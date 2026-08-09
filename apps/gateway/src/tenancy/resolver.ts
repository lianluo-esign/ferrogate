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
  DurableObjectTenantDatabaseRouter,
  EnvBindingTenantDatabaseRouter,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  type TenantObjectAddress,
} from "@ferrogate/storage";
import { controlDatabaseFrom } from "../control-data.js";
import { HttpError } from "../middleware/errors.js";
import {
  TENANT_DATABASE_ROUTING_MISCONFIGURED,
  TENANT_DATABASE_ROUTING_MODES,
  TENANT_DATABASE_UNAVAILABLE,
  type TenancyBindings,
  type TenantDatabaseResolver,
  type TenantDatabaseRoutingMode,
} from "./ports.js";
import { tenantDataNamespace } from "./tenant-data.js";

/**
 * Parse `GATEWAY_TENANT_DB_ROUTING`.
 *
 * An absent/empty value is **`"durable_object"`** — the default since #819.
 * That is a deliberate reversal: it used to be `"off"`, i.e. per-tenant storage
 * was opt-in, which is how the whole `src/tenancy/` directory sat mounted and
 * inert with `tenantDatabaseOf(c)` at zero production call sites. Physical
 * isolation that has to be switched on is not isolation; it is a setting that
 * every deployment forgets. Under `durable_object` the default costs nothing to
 * turn on — no deploy, no provisioning call, no binding budget — so there is no
 * longer a reason for the safe posture to be the opt-in one.
 *
 * Since #821 PR2-delete there is no shared `env.DB` tenant database left to
 * fall back to: the `"off"` and `"shared_development"` modes, both of which
 * read it, are gone. A value that is present but NOT a legal mode (including
 * either of those retired names) returns `undefined`, which the resolver turns
 * into `503 tenant_database_routing_misconfigured`. It deliberately does NOT
 * fall back to the default: an operator who typed `bindng` asked for a specific
 * posture and must be told they did not get it, exactly as a malformed
 * `[network_access]` answers `503 network_access_misconfigured` rather than
 * degrading to "no allowlist".
 */
export function parseTenantDatabaseRoutingMode(
  raw: string | undefined,
): TenantDatabaseRoutingMode | undefined {
  const value = (raw ?? "").trim();
  if (value === "") return "durable_object";
  return TENANT_DATABASE_ROUTING_MODES.find((mode) => mode === value);
}

/** Thrown as the uniform gateway envelope; see `middleware/errors.ts`. */
function misconfigured(detail: string): HttpError {
  return new HttpError(503, TENANT_DATABASE_ROUTING_MISCONFIGURED, detail);
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

  async forTenant(tenantId: string, address?: TenantObjectAddress): Promise<TenantDatabaseHandle> {
    try {
      return await this.router.forTenant(tenantId, address);
    } catch (error) {
      // Every refusal the router raises arrives here. Under the D1 modes those
      // are resolution failures: unregistered tenant, registry row with no
      // `binding_name`, a binding name this Worker does not have, a binding
      // that is not a D1 database. Under `durable_object` resolution reads
      // nothing and cannot fail that way — only a blank tenant id refuses here,
      // and the OBJECT's own refusals (a stub that adopted another tenant, a
      // schema that stopped mid-migration) surface at the first statement
      // instead, wrapped by `DurableObjectD1Database`.
      //
      // NONE of them is recovered from, in either topology: there is no
      // `catch → env.DB`, which is the single line whose absence this whole
      // directory exists to guarantee.
      throw new HttpError(
        503,
        TENANT_DATABASE_UNAVAILABLE,
        `tenant ${tenantId} has no resolvable tenant database: ${
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
  // Every remaining mode needs the CONTROL database. Native-binding modes use
  // `tenant_databases.binding_name` for compatibility routing. For
  // `durable_object` it is NOT a routing table: routing needs nothing, and the
  // binding is required only for `control()` and `provisionedTenants()` — both
  // account-global, neither on a request path. The requirement is kept for that
  // mode anyway, because a gateway with no CONTROL_DB cannot answer the fleet
  // views at all and should say so at configuration time rather than at the
  // first admin fan-out.
  const controlDb = controlDatabaseFrom(env);
  if (controlDb === undefined) {
    throw misconfigured(
      [
        `GATEWAY_TENANT_DB_ROUTING = "${mode}" needs the CONTROL_DB binding (it holds`,
        "tenant_databases and the account-global tables), which is not bound",
      ].join(" "),
    );
  }

  if (mode === "durable_object") {
    // THE DEFAULT. One SQLite-backed Durable Object per tenant, addressed
    // `env.TENANT_DATA.idFromName(tenantId)`.
    //
    // `tenantDataNamespace` is the ONE place the binding is read, and it raises
    // `503 tenant_database_routing_misconfigured` when the stanza is absent —
    // deliberately NOT a fallback to a shared database. Reusing it here rather
    // than reading `env.TENANT_DATA` a second time keeps the refusal, its
    // message and the `env.X` token `test/env-var-drift.test.ts` scans for in a
    // single module.
    //
    // Handles resolve LAZILY (`eager: false`) and that is not the weaker
    // posture it is under `binding`: eager resolution existed to prove a
    // deploy-time binding was really there, and there is nothing left to prove
    // — `idFromName` cannot fail. The only remaining failure is the object's
    // own admission refusal, which is observable at the first statement and
    // nowhere earlier, so an "eager" DO mode would have to issue a real RPC per
    // request to learn anything a lazy one does not.
    //
    // Since #821 PR2-delete the pure DO router is UNCONDITIONAL: the shared
    // `env.DB` tenant database has been retired, so there is no
    // `BackendDispatchingTenantDatabaseRouter` legacy-shared fallback and no
    // pre-cutover source. Every tenant is one Durable Object; there is nowhere
    // else its rows could be.
    const durableObject = new DurableObjectTenantDatabaseRouter(
      tenantDataNamespace(env),
      controlDb,
    );
    return new RoutedTenantDatabaseResolver(mode, false, durableObject);
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
 * requests.
 *
 * What this memoization saves is now smaller than it used to be, and saying so
 * is the point. It used to also keep alive the binding router's 30 s in-isolate
 * REGISTRATION cache; under the `durable_object` default there is no such cache,
 * because there is no registry read to cache — see
 * `DurableObjectTenantDatabaseRouter`. What is left is an object allocation and
 * one `GATEWAY_TENANT_DB_ROUTING` parse per `env`, which is worth keeping and is
 * not worth claiming more for.
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
