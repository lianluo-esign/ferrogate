/**
 * `tenantDatabase()` — the request-path mount of the per-tenant storage
 * topology (one Durable Object per tenant by default; see `./ports.ts`).
 *
 * Position in the ingress chain (`src/index.ts` `GATEWAY_MIDDLEWARE`):
 *
 *   contractAuth → meteringDrain → requestTelemetry → requestLogging →
 *   **tenantDatabase** → rateLimit → … → guardrails → validate → dispatch
 *
 * It must come AFTER `contractAuth`, because the tenant it routes on is the one
 * the credential resolved to (`c.get("auth")`), and a middleware that ran before
 * the guard would route on an unauthenticated guess. It must come BEFORE
 * `rateLimit()`, because admission step 3b — the wallet no-oversell guard —
 * calls {@link tenantDatabaseOf}. Between those two edges its position is free:
 * it does no I/O of its own unless the mode is `"binding_strict"`.
 *
 * ## Why the handle is LAZY by default
 *
 * Under the `durable_object` default, resolving costs NOTHING — the address is
 * `TENANT_DATA.idFromName(tenantId)`, a pure function — so laziness there buys
 * only an object allocation. Under the `binding*` and `rest` modes it still
 * buys a CONTROL-database read, and most gateway operations (`GET /v1/models`,
 * `/healthz`, an inference request whose usage is metered into the CONTROL
 * database) never touch tenant-owned rows. `"binding_strict"` exists for
 * deployments that want the opposite guarantee: no tenant-scoped request is
 * served at all unless its database is routable. There is no eager
 * `durable_object` posture, because there is nothing an eager pass could learn
 * short of issuing a real statement.
 *
 * Laziness is NOT a weakening of fail-closed. The accessor has no code path
 * that returns the shared or control database in place of a tenant's; a caller
 * either gets that tenant's handle or an exception.
 */
import type { TenantDatabaseHandle } from "@ferrogate/storage";
import type { Context, MiddlewareHandler } from "hono";
import { HttpError } from "../middleware/errors.js";
import { type AuthContext, type GatewayEnv, callerScope } from "../ports.js";
import { tenantObjectAddressFor } from "../residency/carrier.js";
import {
  TENANT_DATABASE_UNSCOPED,
  TENANT_DATABASE_VAR,
  type TenancyBindings,
  type TenancyContext,
  type TenantDatabaseAccessor,
  type TenantDatabaseResolver,
  type TenantDatabaseRoutingMode,
} from "./ports.js";
import { parseTenantDatabaseRoutingMode, resolverForEnv } from "./resolver.js";

/** Options. Both exist for tests; production passes neither. */
export interface TenantDatabaseOptions {
  /**
   * Override the resolver factory. Production uses `resolverForEnv`, which
   * reads `GATEWAY_TENANT_DB_ROUTING` + `CONTROL_DB` from the bindings.
   */
  readonly resolver?: (env: TenancyBindings) => TenantDatabaseResolver;
}

/**
 * The accessor parked on the context.
 *
 * `#resolved` memoizes per REQUEST, not per isolate: two handlers in one
 * request share a handle, and two requests never do.
 *
 * ## The resolver is built LAZILY, and that is a deliberate reversal
 *
 * `resolver` is a THUNK, not a resolver. It used to be built eagerly in
 * `tenantDatabase()`, so a misconfigured routing posture — an unparseable var,
 * a `durable_object` deployment with no `TENANT_DATA` stanza — was a 503 on
 * EVERY authenticated request, including the many that never touch tenant data
 * (`GET /v1/models`, `/v1/models/{id}`, any request served entirely out of the
 * catalog). That was defensible while `"off"` was the default and reaching this
 * code at all meant an operator had opted in. Since #819 turned routing on by
 * default it is not: it converts "this Worker has no tenant storage bound" into
 * a total outage rather than a refusal of the operations that actually need it.
 *
 * Deferring loses nothing that mattered. The misconfiguration is still a NAMED
 * 503 with the same code and the same message; it simply arrives at the first
 * request that ASKS for a tenant handle. Nothing degrades, nothing falls back
 * to `env.DB`, and `"binding_strict"` still forces resolution up front — the
 * mode is parsed from the var directly, so the eager posture does not need the
 * router to have been built to be honoured.
 */
class RequestTenantDatabaseAccessor implements TenantDatabaseAccessor {
  #resolved: Promise<TenantDatabaseHandle> | undefined;

  constructor(
    private readonly resolver: () => TenantDatabaseResolver,
    readonly tenantId: string | null,
    readonly mode: TenantDatabaseRoutingMode,
    private readonly address?: import("@ferrogate/storage").TenantObjectAddress,
  ) {}

  handle(): Promise<TenantDatabaseHandle> {
    if (this.tenantId === null) {
      // A platform-operator credential (Rust `CallerScope::PlatformOperator`)
      // is account-global by definition: there is no single tenant whose
      // database it should read, and picking one would be a cross-tenant read.
      // Admin surfaces that need a specific tenant name it in the request and
      // route explicitly through `resolver.forTenant(...)`.
      return Promise.reject(
        new HttpError(
          403,
          TENANT_DATABASE_UNSCOPED,
          "this credential is not confined to a tenant, so it has no tenant database; " +
            "account-global data lives in the CONTROL database",
        ),
      );
    }
    // `resolver()` can THROW (`503 tenant_database_routing_misconfigured`).
    // Wrapped so it rejects the promise instead of throwing synchronously out
    // of `handle()`, because every caller awaits this and a mixed
    // throw/reject surface is how one of them ends up unhandled.
    this.#resolved ??= (async () =>
      this.resolver().forTenant(this.tenantId as string, this.address))();
    return this.#resolved;
  }

  async db(): Promise<D1Database> {
    return (await this.handle()).db;
  }

  control(): D1Database {
    return this.resolver().control();
  }
}

/**
 * The tenant id this credential is confined to, or `null`.
 *
 * `callerScope` is the Rust `AuthContext::caller_scope`: an unclassified
 * credential is a TENANT with the empty-string id, never platform root. The
 * empty string is unforgeable as a real tenant id, so it can never match a
 * `tenant_databases` row — and `EnvBindingTenantDatabaseRouter.forTenant("")`
 * refuses it outright. Either way it cannot be routed anywhere, which is the
 * correct outcome and not something to paper over here.
 */
export function routableTenantId(auth: AuthContext): string | null {
  const scope = callerScope(auth);
  return scope.kind === "platform_operator" ? null : scope.tenantId;
}

/**
 * Mount the per-tenant database resolution on every authenticated request.
 *
 * Anonymous operations (`/healthz`, `/readyz`, `/.well-known/agent.json`) have
 * no `auth`, so nothing is attached and nothing is resolved — asking for a
 * tenant database from one of them is a programming error and
 * {@link tenantDatabaseOf} says so.
 */
export function tenantDatabase(options: TenantDatabaseOptions = {}): MiddlewareHandler<GatewayEnv> {
  const resolverFor = options.resolver ?? resolverForEnv;
  return async (c, next) => {
    const auth = c.get("auth");
    if (auth === null || auth === undefined) {
      await next();
      return;
    }
    const env = c.env as unknown as TenancyBindings;
    // The MODE is read from the var directly, without building a router. That
    // is what lets the accessor report `mode` and honour `eager` while the
    // resolver itself stays unbuilt until something asks for a handle — see
    // `RequestTenantDatabaseAccessor`. An unparseable var has no mode; it is
    // reported as `"off"` HERE and as a 503 the moment a handle is requested,
    // which is the fail-closed pairing: nothing is routed, and nothing is
    // quietly served from the shared database either.
    const mode = parseTenantDatabaseRoutingMode(env.GATEWAY_TENANT_DB_ROUTING) ?? "off";
    const tenantId = routableTenantId(auth);
    const accessor = new RequestTenantDatabaseAccessor(
      () => resolverFor(env),
      tenantId,
      mode,
      tenantObjectAddressFor(c.req.raw),
    );
    (c as unknown as TenancyContext).set(TENANT_DATABASE_VAR, accessor);
    if (mode === "binding_strict" && tenantId !== null) {
      // `"binding_strict"`: prove routability before the request is served, so
      // an un-provisioned tenant is refused at the door instead of half-way
      // through a handler. It is the ONE mode that resolves eagerly, and the
      // check is on the mode rather than on a built resolver's `eager` flag so
      // that reaching it does not itself force the construction the laziness
      // above exists to defer.
      await accessor.handle();
    }
    await next();
  };
}

/**
 * Read the accessor a handler needs, or fail loudly.
 *
 * The throw is the point. If `tenantDatabase()` is not mounted, a call site
 * that wanted tenant-isolated storage gets a 500 that names the missing
 * middleware — it does NOT get `c.env.DB`. That is this repo's recurring defect
 * (an unmounted composition root going unnoticed because the fallback looked
 * fine) turned into an immediate, attributable failure.
 */
export function tenantDatabaseOf(c: Context<GatewayEnv>): TenantDatabaseAccessor {
  const accessor = (c as unknown as TenancyContext).get(TENANT_DATABASE_VAR);
  if (accessor === undefined) {
    throw new HttpError(
      500,
      "internal_error",
      "tenantDatabase() is not mounted on this Worker, so no per-tenant D1 handle is available; " +
        "add it to GATEWAY_MIDDLEWARE in src/index.ts (see src/tenancy/index.ts WIRING)",
    );
  }
  return accessor;
}
