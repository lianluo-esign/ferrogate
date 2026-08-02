/**
 * `tenantDatabase()` — the request-path mount of the per-tenant D1 topology.
 *
 * Position in the ingress chain (Rust order, `src/index.ts` `GATEWAY_MIDDLEWARE`):
 *
 *   contractAuth → meteringDrain → rateLimit → guardrails → **tenantDatabase** → validate → dispatch
 *
 * It must come AFTER `contractAuth`, because the tenant it routes on is the one
 * the credential resolved to (`c.get("auth")`), and a middleware that ran before
 * the guard would route on an unauthenticated guess. Beyond that its position is
 * free: it does no I/O of its own unless the mode is `"binding_strict"`.
 *
 * ## Why the handle is LAZY by default
 *
 * Resolving costs one CONTROL-database read (cached 30 s in-isolate by
 * `EnvBindingTenantDatabaseRouter`). Most gateway operations — `GET /v1/models`,
 * `/healthz`, an inference request whose usage is metered into the CONTROL
 * database — never touch tenant-owned rows, so charging them a registry read
 * would be a pure regression on the hot path. `"binding_strict"` exists for
 * deployments that want the opposite guarantee: no tenant-scoped request is
 * served at all unless its database is routable.
 *
 * Laziness is NOT a weakening of fail-closed. The accessor has no code path
 * that returns the shared or control database in place of a tenant's; a caller
 * either gets that tenant's handle or an exception.
 */
import type { TenantDatabaseHandle } from "@ferrogate/storage";
import type { Context, MiddlewareHandler } from "hono";
import { HttpError } from "../middleware/errors.js";
import { type AuthContext, type GatewayEnv, callerScope } from "../ports.js";
import {
  TENANT_DATABASE_UNSCOPED,
  TENANT_DATABASE_VAR,
  type TenancyBindings,
  type TenancyContext,
  type TenantDatabaseAccessor,
  type TenantDatabaseResolver,
} from "./ports.js";
import { resolverForEnv } from "./resolver.js";

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
 * request share a handle, and two requests never do (the router's own cache is
 * the isolate-level one, and it caches the registry ROW, never a binding).
 */
class RequestTenantDatabaseAccessor implements TenantDatabaseAccessor {
  #resolved: Promise<TenantDatabaseHandle> | undefined;

  constructor(
    private readonly resolver: TenantDatabaseResolver,
    readonly tenantId: string | null,
  ) {}

  get mode() {
    return this.resolver.mode;
  }

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
    this.#resolved ??= this.resolver.forTenant(this.tenantId);
    return this.#resolved;
  }

  async db(): Promise<D1Database> {
    return (await this.handle()).db;
  }

  control(): D1Database {
    return this.resolver.control();
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
    // A misconfigured `GATEWAY_TENANT_DB_ROUTING` throws HERE, on the request,
    // rather than at module scope — a Worker that cannot start is worse than
    // one that answers 503 with a code naming the var.
    const resolver = resolverFor(c.env as unknown as TenancyBindings);
    const tenantId = routableTenantId(auth);
    const accessor = new RequestTenantDatabaseAccessor(resolver, tenantId);
    (c as unknown as TenancyContext).set(TENANT_DATABASE_VAR, accessor);
    if (resolver.eager && tenantId !== null) {
      // `"binding_strict"`: prove routability before the request is served, so
      // an un-provisioned tenant is refused at the door instead of half-way
      // through a handler.
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
