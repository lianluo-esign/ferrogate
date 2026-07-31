/**
 * The request-path tenancy seam: authenticated identity → **that tenant's** D1
 * database.
 *
 * ## The user directive this closes, and what was actually true before it
 *
 * The standing directive is "use Cloudflare D1 as the database, **one isolated
 * database per tenant**". Before this module the gateway used a SINGLE shared
 * `env.DB` (+ `env.CONTROL_DB` / `env.BILLING_DB`) for every tenant, and
 * `TenantDatabaseRouter` — implemented and tested in `@ferrogate/storage` —
 * had zero callers. Logical isolation (a `tenant_id` column, filtered in the
 * query) existed and was tested; **physical** isolation did not exist on any
 * deployed path.
 *
 * ## The platform constraint, stated honestly
 *
 * `docs/legacy/inventory-data-billing.md` §1.7 records it as "the biggest
 * architectural open question": **Cloudflare bindings resolve at DEPLOY time.**
 * `env.DB` is handed to the isolate already connected; there is no runtime
 * `openDatabase(uuid)`. So there are exactly three ways to reach tenant X's
 * database, and `@ferrogate/storage`'s `D1_BINDING_STRATEGIES` prices all three:
 *
 * | strategy | how | atomic `batch()` + `RETURNING`? | onboarding |
 * |---|---|---|---|
 * | `native_binding` | one `[[d1_databases]]` stanza per tenant; the CONTROL database's `tenant_databases.binding_name` names it; `env[bindingName]` is an ordinary **runtime** property read over a deploy-time-declared set | **yes** | needs a `wrangler deploy` |
 * | `proxy_service` | a proxy Worker holds the per-tenant bindings behind a `[[services]]` binding (the shape `workers/d1-proxy` had, issue #450) | **yes** | redeploy the proxy, not the gateway |
 * | `rest` | the D1 HTTP query API addressed by RUNTIME `database_uuid` | **NO** — no transaction envelope | a control-database row |
 *
 * The registry is the same in all three: the **CONTROL** database's
 * `tenant_databases` table (`sql/d1-ts/control/0001_init_control.sql`), which is
 * the direct descendant of the Rust `d1_tenant_database` registry document.
 *
 * ### Which operations can and cannot be atomic through the REST path
 *
 * Single statements — including a guarded `UPDATE … WHERE <cas> RETURNING …` —
 * ARE atomic over REST and their `RETURNING` rows do come back. What is
 * impossible is `batch()`: N statements as ONE transaction. That is exactly the
 * primitive the wallet no-oversell reserve (3 statements), the workflow-budget
 * CAS and the billing-outbox enqueue (#150) are built on, so a REST handle
 * reports `supportsAtomicBatch: false` and `requireAtomicBatch` refuses it.
 * This is the reason the Rust tree needed a `d1-proxy` Worker at all.
 *
 * ## FAIL CLOSED — the invariant the whole feature exists for
 *
 * If a tenant's database cannot be resolved, the request ERRORS. It never falls
 * back to `env.DB`, to `env.CONTROL_DB`, or to any other tenant's database. A
 * silent fallback would write tenant A's wallet reservation into the shared
 * database that tenant B also reads — i.e. it would destroy the isolation the
 * DB-per-tenant topology is the entire point of. There is deliberately **no**
 * "default database" option anywhere in this directory, and
 * `test/tenancy/resolver.spec.ts` mutation-proves it.
 *
 * ## The control / tenant split
 *
 * | database | holds | why it cannot be per-tenant |
 * |---|---|---|
 * | **CONTROL** (`env.CONTROL_DB`, `sql/d1-ts/control/`) | `tenants`, `tenant_databases`, `api_key_directory`, `static_api_keys`, `plans`, `quota_policies`, RBAC (`permissions`/`roles`/`tenant_role_bindings`), guardrail policy revisions + bindings, site domains, budget alerts, `billing_events`/`billing_ledger`/`billing_report_outbox` | it is the thing that ANSWERS "which tenant?", so it cannot itself be tenant-routed (the chicken-and-egg §"split rule (b)" in the control migration). Account-global reporting also has to join across tenants |
 * | **TENANT** (one D1 per tenant, `sql/d1-ts/tenant/`) | the full `api_keys` rows, wallets + reservations + settlements, usage/metadata rollups, workflow budgets, `stored_assets` + `asset_channels`, retention, agent schedules + fires, presence, agent cost burn | this is the tenant's own money and content; it is what physical isolation must protect |
 *
 * A credential is resolved to a tenant through the CONTROL `api_key_directory`
 * point lookup (`src/keys/`), and only then is exactly one routed call made.
 * That ordering is load-bearing: the Rust backend authenticated by FANNING OUT
 * the lookup across every tenant database, which is O(tenants) round trips on
 * the inference hot path and is itself a cross-tenant read.
 */
import type { TenantDatabaseHandle, TenantDatabaseRouter } from "@ferrogate/storage";
import type { Context, MiddlewareHandler } from "hono";
import type { GatewayBindings, GatewayEnv, GatewayVariables } from "../ports.js";

// ---------------------------------------------------------------------------
// Routing mode
// ---------------------------------------------------------------------------

/**
 * How this deployment reaches a tenant's database. Read from the
 * `GATEWAY_TENANT_DB_ROUTING` var; see {@link parseTenantDatabaseRoutingMode}.
 *
 * There is no `"fallback"` mode and there never will be — see the FAIL CLOSED
 * section of the file docblock.
 */
export type TenantDatabaseRoutingMode =
  /**
   * DEFAULT. No per-tenant routing is configured. The resolver hands out NO
   * handle at all: a caller that asks for one gets `503
   * tenant_database_routing_disabled`. This is still fail-closed — the absence
   * of a route is an error, not a silent redirection to the shared database —
   * and it is what lets the middleware be mounted before the tenant databases
   * exist without changing the behaviour of any request that does not ask.
   */
  | "off"
  /**
   * `EnvBindingTenantDatabaseRouter` over `env.CONTROL_DB`. Handles are
   * resolved LAZILY, on first use, so an operation that never touches tenant
   * data costs no control-database read.
   */
  | "binding"
  /**
   * `"binding"`, plus EAGER resolution: every tenant-scoped credential must
   * resolve to a routable database before its request is served. The strictest
   * posture — a tenant whose binding has not been deployed cannot reach the
   * data plane at all, rather than failing at the first store call.
   */
  | "binding_strict"
  /**
   * `NonAtomicD1RestTenantDatabaseRouter` over the D1 HTTP query API, addressed
   * by runtime uuid. Read paths and single-statement writes only: every handle
   * reports `supportsAtomicBatch: false`, so `requireAtomicBatch` refuses the
   * money paths. Needs `GATEWAY_TENANT_DB_ACCOUNT_ID` + the
   * `GATEWAY_TENANT_DB_API_TOKEN` secret.
   */
  | "rest"
  /**
   * `SharedDatabaseTenantRouter` over `env.DB` — ONE database for every tenant,
   * i.e. NO physical isolation. `wrangler dev --local` and genuinely
   * single-tenant self-hosted deployments only. It must be named explicitly in
   * the var, so a code search for this string finds every deployment that
   * accepted the tradeoff, and no typo can reach it.
   */
  | "shared_development";

/** Every legal `GATEWAY_TENANT_DB_ROUTING` value, for diagnostics and tests. */
export const TENANT_DATABASE_ROUTING_MODES: readonly TenantDatabaseRoutingMode[] = [
  "off",
  "binding",
  "binding_strict",
  "rest",
  "shared_development",
] as const;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/**
 * The four refusals, all 5xx/4xx and none of them a fallback.
 *
 * `tenant_database_unavailable` is 503 rather than 500 because the cause is
 * always operational — an unprovisioned tenant, a registry row whose binding
 * has not been deployed, a control database that is down — and a client may
 * legitimately retry after the operator acts.
 */
export const TENANT_DATABASE_UNAVAILABLE = "tenant_database_unavailable";
/** Mode is `"off"` and something asked for a tenant handle anyway. */
export const TENANT_DATABASE_ROUTING_DISABLED = "tenant_database_routing_disabled";
/** The var names an unknown mode, or the mode's required binding is absent. */
export const TENANT_DATABASE_ROUTING_MISCONFIGURED = "tenant_database_routing_misconfigured";
/**
 * The credential is not confined to a tenant (a platform-operator key, or one
 * with no tenancy at all), so there is no tenant database to hand it. 403: the
 * caller is authenticated, and this is a scope problem, not an outage.
 */
export const TENANT_DATABASE_UNSCOPED = "tenant_database_unscoped";

// ---------------------------------------------------------------------------
// The seam
// ---------------------------------------------------------------------------

/**
 * The gateway-facing resolver. A thin, typed wrapper over the
 * `@ferrogate/storage` {@link TenantDatabaseRouter} — it exists so the request
 * path depends on one narrow surface, and so `router` stays reachable for the
 * anti-unmount assertion that the storage implementation is the one actually in
 * use.
 */
export interface TenantDatabaseResolver {
  readonly mode: TenantDatabaseRoutingMode;
  /** `true` for `"binding_strict"`: resolve before the request is served. */
  readonly eager: boolean;
  /**
   * The `@ferrogate/storage` router doing the work. Exposed so
   * `test/tenancy/resolver.spec.ts` can assert it IS
   * `EnvBindingTenantDatabaseRouter` — replacing it with a hand-rolled
   * equivalent (this repo's recurring defect) turns that test red.
   */
  readonly router: TenantDatabaseRouter;
  /** The account-global CONTROL database. */
  control(): D1Database;
  /** Resolve one tenant's database, or THROW. Never falls back. */
  forTenant(tenantId: string): Promise<TenantDatabaseHandle>;
}

/**
 * What the middleware parks on the request context. Resolution is deferred to
 * {@link handle} so an operation that never touches tenant data pays nothing —
 * except under `"binding_strict"`, where the middleware forces it up front.
 */
export interface TenantDatabaseAccessor {
  readonly mode: TenantDatabaseRoutingMode;
  /** The caller's tenant, or `null` for a platform-operator credential. */
  readonly tenantId: string | null;
  /**
   * THIS caller's tenant database. Throws (503/403) rather than ever returning
   * the shared or control database.
   */
  handle(): Promise<TenantDatabaseHandle>;
  /** `handle().db`, for call sites that only want the D1 handle. */
  db(): Promise<D1Database>;
  /** The CONTROL database — account-global data only. Throws if unbound. */
  control(): D1Database;
}

// ---------------------------------------------------------------------------
// Bindings + context var
// ---------------------------------------------------------------------------

/**
 * The bindings this directory reads. They are NOT added to
 * `GatewayBindings` in `src/ports.ts` here: that file is the composition
 * root's, and the integrate step owns it. See `WIRING` in `./index.ts`.
 */
export interface TenancyBindings {
  /** One of {@link TENANT_DATABASE_ROUTING_MODES}. Absent ⇒ `"off"`. */
  readonly GATEWAY_TENANT_DB_ROUTING?: string;
  /** Cloudflare account id — `"rest"` mode only. */
  readonly GATEWAY_TENANT_DB_ACCOUNT_ID?: string;
  /** D1-capable API token — `"rest"` mode only. A SECRET, never a var. */
  readonly GATEWAY_TENANT_DB_API_TOKEN?: string;
  /** The CONTROL database holding `tenant_databases`. */
  readonly CONTROL_DB?: D1Database;
  /** The shared database — `"shared_development"` mode only. */
  readonly DB?: D1Database;
  /** Any number of per-tenant `[[d1_databases]]` bindings, by name. */
  readonly [binding: string]: unknown;
}

/** The context variable name. Namespaced so it cannot collide. */
export const TENANT_DATABASE_VAR = "tenantDatabase";

/**
 * Hono generic for this directory: the gateway's own bindings/variables plus
 * the tenancy additions. The exported middleware is still typed
 * `MiddlewareHandler<GatewayEnv>` so it drops into
 * `createGatewayApp({ middleware })` with no change to `src/routes/index.ts`;
 * the widening happens once, inside the middleware.
 */
export type TenancyEnv = {
  Bindings: GatewayBindings & TenancyBindings;
  Variables: GatewayVariables & { [TENANT_DATABASE_VAR]: TenantDatabaseAccessor };
};

/** The context shape after {@link TENANT_DATABASE_VAR} has been set. */
export type TenancyContext = Context<TenancyEnv>;

/** A middleware that is mountable on the app without touching its generics. */
export type TenancyMiddleware = MiddlewareHandler<GatewayEnv>;
