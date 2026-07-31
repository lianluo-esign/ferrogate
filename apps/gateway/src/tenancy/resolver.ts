/**
 * Builds the {@link TenantDatabaseResolver} for a set of Worker bindings.
 *
 * Nothing is re-implemented here. Every mode delegates to a router that already
 * exists, is already tested (152 D1 tests in `packages/storage`) and was, until
 * this file, DEAD — zero importers under any app. This module is the mount, and
 * `test/tenancy/resolver.spec.ts` is the gate that keeps it mounted.
 *
 * Read `./ports.ts` first: it carries the deploy-time-binding constraint, the
 * three strategies, the control/tenant split, and the fail-closed invariant.
 */
import {
  EnvBindingTenantDatabaseRouter,
  NonAtomicD1RestTenantDatabaseRouter,
  SharedDatabaseTenantRouter,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import {
  TENANT_DATABASE_ROUTING_DISABLED,
  TENANT_DATABASE_ROUTING_MISCONFIGURED,
  TENANT_DATABASE_ROUTING_MODES,
  TENANT_DATABASE_UNAVAILABLE,
  type TenancyBindings,
  type TenantDatabaseResolver,
  type TenantDatabaseRoutingMode,
} from "./ports.js";

/**
 * Parse `GATEWAY_TENANT_DB_ROUTING`.
 *
 * An absent/empty value is `"off"` — the shipped default, and the posture every
 * existing deployment is already in. A value that is present but NOT a legal
 * mode returns `undefined`, which the resolver turns into
 * `503 tenant_database_routing_misconfigured`. It deliberately does NOT fall
 * back to `"off"`: an operator who typed `bindng` asked for per-tenant routing
 * and must be told they did not get it, exactly as a malformed
 * `[network_access]` answers `503 network_access_misconfigured` rather than
 * degrading to "no allowlist".
 */
export function parseTenantDatabaseRoutingMode(
  raw: string | undefined,
): TenantDatabaseRoutingMode | undefined {
  const value = (raw ?? "").trim();
  if (value === "") return "off";
  return TENANT_DATABASE_ROUTING_MODES.find((mode) => mode === value);
}

/** Thrown as the uniform gateway envelope; see `middleware/errors.ts`. */
function misconfigured(detail: string): HttpError {
  return new HttpError(503, TENANT_DATABASE_ROUTING_MISCONFIGURED, detail);
}

/**
 * The `"off"` resolver.
 *
 * It is a real object rather than `undefined` so that the failure mode is a
 * NAMED refusal at the point of use instead of an `undefined` that some call
 * site helpfully replaces with `env.DB`. `router` throws for the same reason.
 */
class DisabledTenantDatabaseResolver implements TenantDatabaseResolver {
  readonly mode = "off" as const;
  readonly eager = false;

  get router(): TenantDatabaseRouter {
    throw new HttpError(
      503,
      TENANT_DATABASE_ROUTING_DISABLED,
      "per-tenant D1 routing is not configured on this Worker (GATEWAY_TENANT_DB_ROUTING is unset)",
    );
  }

  control(): D1Database {
    throw new HttpError(
      503,
      TENANT_DATABASE_ROUTING_DISABLED,
      "per-tenant D1 routing is not configured on this Worker (GATEWAY_TENANT_DB_ROUTING is unset)",
    );
  }

  forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    return Promise.reject(
      new HttpError(
        503,
        TENANT_DATABASE_ROUTING_DISABLED,
        [
          `per-tenant D1 routing is not configured on this Worker, so tenant ${tenantId} has no`,
          "database; set GATEWAY_TENANT_DB_ROUTING and provision the tenant. This request is",
          "refused rather than served from the shared database.",
        ].join(" "),
      ),
    );
  }
}

/** Wraps a `@ferrogate/storage` router in the gateway's error envelope. */
class RoutedTenantDatabaseResolver implements TenantDatabaseResolver {
  constructor(
    readonly mode: TenantDatabaseRoutingMode,
    readonly eager: boolean,
    readonly router: TenantDatabaseRouter,
  ) {}

  control(): D1Database {
    return this.router.control();
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    try {
      return await this.router.forTenant(tenantId);
    } catch (error) {
      // Every refusal the router raises — unregistered tenant, registry row
      // with no `binding_name`, a binding name this Worker does not have, a
      // binding that is not a D1 database — arrives here. NONE of them is
      // recovered from: there is no `catch → env.DB`, which is the single line
      // whose absence this whole directory exists to guarantee.
      throw new HttpError(
        503,
        TENANT_DATABASE_UNAVAILABLE,
        `tenant ${tenantId} has no resolvable D1 database: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}

/**
 * Build the resolver for one request's bindings.
 *
 * Pure with respect to the bindings — no caching here; {@link resolverForEnv}
 * memoizes per `env` object, which is what a Worker wants (bindings are
 * per-request objects, and the isolate outlives none of them).
 */
export function createTenantDatabaseResolver(env: TenancyBindings): TenantDatabaseResolver {
  const mode = parseTenantDatabaseRoutingMode(env.GATEWAY_TENANT_DB_ROUTING);
  if (mode === undefined) {
    throw misconfigured(
      `GATEWAY_TENANT_DB_ROUTING = "${env.GATEWAY_TENANT_DB_ROUTING}" is not one of ` +
        `${TENANT_DATABASE_ROUTING_MODES.join(", ")}; refusing to guess a tenant-routing posture`,
    );
  }
  if (mode === "off") return new DisabledTenantDatabaseResolver();

  if (mode === "shared_development") {
    // Named explicitly in the var, or unreachable. `SharedDatabaseTenantRouter`
    // gives NO physical isolation — every tenant shares `env.DB` and only the
    // `tenant_id` column separates them, which is the Postgres-era posture this
    // topology replaces. Legitimate for `wrangler dev --local` and for a
    // genuinely single-tenant self-hosted deployment; nothing else.
    const shared = env.DB;
    if (shared === undefined) {
      throw misconfigured(
        'GATEWAY_TENANT_DB_ROUTING = "shared_development" needs the DB binding, which is not bound',
      );
    }
    return new RoutedTenantDatabaseResolver(mode, false, new SharedDatabaseTenantRouter(shared));
  }

  // Every remaining mode reads the registry out of the CONTROL database.
  const controlDb = env.CONTROL_DB;
  if (controlDb === undefined) {
    throw misconfigured(
      [
        `GATEWAY_TENANT_DB_ROUTING = "${mode}" needs the CONTROL_DB binding (it holds`,
        "tenant_databases, the tenantId -> database registry), which is not bound",
      ].join(" "),
    );
  }

  if (mode === "rest") {
    const accountId = (env.GATEWAY_TENANT_DB_ACCOUNT_ID ?? "").trim();
    const apiToken = (env.GATEWAY_TENANT_DB_API_TOKEN ?? "").trim();
    if (accountId === "" || apiToken === "") {
      throw misconfigured(
        'GATEWAY_TENANT_DB_ROUTING = "rest" needs GATEWAY_TENANT_DB_ACCOUNT_ID and the ' +
          "GATEWAY_TENANT_DB_API_TOKEN secret; refusing to route without them",
      );
    }
    // Reads and single-statement writes only: handles report
    // `supportsAtomicBatch: false`, so `requireAtomicBatch` refuses the wallet
    // reserve, the workflow-budget CAS and the billing-outbox enqueue. See the
    // atomicity table in `@ferrogate/storage`'s `tenant-rest.ts`.
    return new RoutedTenantDatabaseResolver(
      mode,
      false,
      new NonAtomicD1RestTenantDatabaseRouter(controlDb, { accountId, apiToken }),
    );
  }

  // `binding` / `binding_strict` — the strategy to deploy. `env` is passed
  // WHOLE because that is the mechanism: a binding is declared at deploy time
  // and selected at RUNTIME by name (`env[bindingName]`), and the name comes
  // from `tenant_databases.binding_name`.
  return new RoutedTenantDatabaseResolver(
    mode,
    mode === "binding_strict",
    new EnvBindingTenantDatabaseRouter(env as Record<string, unknown>, controlDb),
  );
}

/**
 * Memoized-per-`env` resolver.
 *
 * Same pattern (and same reason) as `meteringBindingsFromEnv` and
 * `assetDepsFromEnv`: the middleware is built ONCE at module scope while
 * bindings exist only per request, so the construction is keyed on the `env`
 * object itself. Nothing is ambient, so nothing leaks between concurrent
 * requests, and the router's 30 s in-isolate registration cache survives for as
 * long as the `env` object does.
 */
const RESOLVER_CACHE = new WeakMap<object, TenantDatabaseResolver>();

export function resolverForEnv(env: TenancyBindings): TenantDatabaseResolver {
  const key = env as unknown as object;
  const cached = RESOLVER_CACHE.get(key);
  if (cached !== undefined) return cached;
  const built = createTenantDatabaseResolver(env);
  RESOLVER_CACHE.set(key, built);
  return built;
}
