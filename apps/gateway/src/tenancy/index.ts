/**
 * `apps/gateway/src/tenancy` — request-path routing to **one SQLite-backed
 * Durable Object per tenant** (`durable_object`, the default since #819), with
 * the D1-per-tenant modes kept for self-hosted single-tenant deploys.
 *
 * Start at `./ports.ts`: it carries the deploy-time-binding constraint that
 * ruled out D1-per-tenant, the strategies and their atomicity costs, the
 * CONTROL/TENANT split, and the fail-closed invariant. `./resolver.ts` builds
 * the router; `./middleware.ts` mounts it and exposes {@link tenantDatabaseOf}
 * to handlers; `./tenant-data.ts` is the one place `env.TENANT_DATA` is read.
 *
 * Nothing in this directory re-implements routing. Every mode delegates to
 * `@ferrogate/storage` (`DurableObjectTenantDatabaseRouter`,
 * `EnvBindingTenantDatabaseRouter`, `NonAtomicD1RestTenantDatabaseRouter`,
 * `SharedDatabaseTenantRouter`, `ControlDatabaseTenantRegistry`,
 * `requireAtomicBatch`), and `packages/storage/test/mount-inventory.test.ts` is
 * the gate that keeps that true.
 *
 * ===========================================================================
 * WIRING — LANDED, and what each piece is
 * ===========================================================================
 *
 * An earlier revision of this block was a TODO list addressed to an "integrate
 * step" that had not run, and it described a D1 topology this directory no
 * longer defaults to. Both are now false. What is actually deployed:
 *
 * ### 1. `apps/gateway/src/index.ts` — `tenantDatabase()` in `GATEWAY_MIDDLEWARE`
 *
 * Mounted IMMEDIATELY ABOVE `rateLimit()`. The position is load-bearing, not
 * cosmetic: admission step 3b (the wallet no-oversell guard) calls
 * {@link tenantDatabaseOf}, so the accessor has to be on the context before
 * `rateLimit()` runs. It used to be last in the array, back when nothing read a
 * tenant handle at all.
 *
 * ### 2. `apps/gateway/wrangler.toml`
 *
 * ```toml
 * [vars]
 * # durable_object | off | binding | binding_strict | rest | shared_development
 * GATEWAY_TENANT_DB_ROUTING = "durable_object"
 *
 * [[durable_objects.bindings]]
 * name = "TENANT_DATA"
 * class_name = "TenantDataObject"
 *
 * [exports.TenantDataObject]
 * type = "durable-object"
 * storage = "sqlite"                       # IMMUTABLE once deployed
 * ```
 *
 * `CONTROL_DB` is already declared. Under `durable_object` it is NOT a routing
 * table — resolution reads nothing — but `control()` and
 * `provisionedTenants()` still need it, and a DO namespace cannot be
 * enumerated in production.
 *
 * ### 3. `apps/gateway/src/worker.ts`
 *
 * `export { TenantDataObject } from "@ferrogate/storage/durable-objects";` —
 * workerd resolves `class_name` against the ENTRY module's named exports, and
 * `@cloudflare/vitest-pool-workers` does not perform that check, so deleting
 * that line stops the Worker booting while every gateway suite stays green.
 * `apps/gateway/test/wrangler-bindings.test.ts` and
 * `packages/storage/test/mount-inventory.test.ts` are the two gates that fail
 * instead.
 *
 * ### 4. Provisioning — THERE IS NONE
 *
 * This is the difference the topology bought. A tenant's object exists the
 * moment it is addressed: no `wrangler d1 create`, no migration run, no
 * registry INSERT, no redeploy. `TenantDataObject`'s constructor applies
 * `sql/d1-ts/tenant/*.sql` under `blockConcurrencyWhile`, once, gated on its own
 * `storage_schema_migrations` ledger. `tenant_databases` survives as the
 * provisioning/STATE record — who exists, where their data is homed — and is
 * read on admin paths only.
 *
 * The `binding` / `binding_strict` / `rest` modes still need the per-tenant D1
 * work (`wrangler d1 create`, `migrations apply`, a `[[d1_databases]]` stanza
 * whose `binding` matches `tenant_databases.binding_name`, a redeploy, then the
 * registry row). A row without `binding_name` is "provisioned but not yet
 * routable" and is REFUSED, not fallen back.
 * ===========================================================================
 */
export {
  TENANT_DATABASE_ROUTING_DISABLED,
  TENANT_DATABASE_ROUTING_MISCONFIGURED,
  TENANT_DATABASE_ROUTING_MODES,
  TENANT_DATABASE_UNAVAILABLE,
  TENANT_DATABASE_UNSCOPED,
  TENANT_DATABASE_VAR,
} from "./ports.js";
export type {
  TenancyBindings,
  TenancyContext,
  TenancyEnv,
  TenancyMiddleware,
  TenantDatabaseAccessor,
  TenantDatabaseResolver,
  TenantDatabaseRoutingMode,
} from "./ports.js";
export {
  createTenantDatabaseResolver,
  parseTenantDatabaseRoutingMode,
  resolverForEnv,
} from "./resolver.js";
export {
  type TenantDatabaseOptions,
  routableTenantId,
  tenantDatabase,
  tenantDatabaseOf,
} from "./middleware.js";
/**
 * `TenantDataObject` addressing (#822), now WIRED.
 *
 * {@link createTenantDatabaseResolver} calls `tenantDataNamespace(env)` on the
 * `durable_object` branch, which is what keeps `env.TENANT_DATA` read in
 * exactly one place — along with its 503 refusal for an unbound namespace, and
 * the `env.X` token `test/env-var-drift.test.ts` scans for.
 *
 * `tenantDataObjectFor` is the raw stub, and it is NOT what the request path
 * takes: routing goes through the router, which wraps the stub in the
 * `D1Database` facade so the eight tenant-plane modules under
 * `packages/storage/src/d1/` work unchanged. It is exported for maintenance and
 * test paths that want the object itself.
 */
export {
  type TenantDataBindings,
  tenantDataNamespace,
  tenantDataObjectFor,
} from "./tenant-data.js";
