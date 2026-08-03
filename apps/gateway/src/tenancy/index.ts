/**
 * `apps/gateway/src/tenancy` — request-path routing to **one D1 database per
 * tenant**.
 *
 * Start at `./ports.ts`: it carries the deploy-time-binding constraint, the
 * three strategies and their atomicity costs, the CONTROL/TENANT split, and the
 * fail-closed invariant. `./resolver.ts` builds the router; `./middleware.ts`
 * mounts it and exposes {@link tenantDatabaseOf} to handlers.
 *
 * Nothing in this directory re-implements routing. Every mode delegates to
 * `@ferrogate/storage` (`EnvBindingTenantDatabaseRouter`,
 * `NonAtomicD1RestTenantDatabaseRouter`, `SharedDatabaseTenantRouter`,
 * `ControlDatabaseTenantRegistry`, `requireAtomicBatch`), which was fully
 * implemented, 152-D1-test covered, and had ZERO importers under any app before
 * this slice.
 *
 * ===========================================================================
 * WIRING — the exact lines the integrate step must add
 * ===========================================================================
 *
 * The composition root (`src/index.ts`), the entry module (`src/worker.ts`) and
 * `wrangler.toml` all belong to the integrate step, so this slice may not edit
 * them. Three changes, none of which touches a route or a handler:
 *
 * ### 1. `apps/gateway/src/index.ts` — ONE import + ONE array entry
 *
 * ```ts
 * import { tenantDatabase } from "./tenancy/index.js";
 *
 * export const GATEWAY_MIDDLEWARE = [
 *   meteringDrain(usage),
 *   rateLimit(),
 *   guardrails(...),
 *   // Per-tenant D1 (one database per tenant). AFTER contractAuth, because it
 *   // routes on the tenant the credential resolved to. Inert unless
 *   // GATEWAY_TENANT_DB_ROUTING is set; NEVER falls back to the shared DB.
 *   tenantDatabase(),
 * ] as const;
 * ```
 *
 * ### 2. `apps/gateway/wrangler.toml` — the routing var + one stanza per tenant
 *
 * ```toml
 * [vars]
 * # off | binding | binding_strict | rest | shared_development
 * GATEWAY_TENANT_DB_ROUTING = "off"          # flip to "binding" once (3) exists
 * # "rest" mode only; the token is a SECRET (`wrangler secret put`).
 * # GATEWAY_TENANT_DB_ACCOUNT_ID = "<account>"
 *
 * # CONTROL_DB is ALREADY declared and already holds `tenant_databases`.
 *
 * # One per provisioned tenant. `binding` is the string recorded in
 * # tenant_databases.binding_name; the router reads env[binding] at runtime.
 * [[d1_databases]]
 * binding = "TENANT_DB_ACME"
 * database_name = "ferrogate-tenant-acme"
 * database_id = "replace-at-deploy"
 * migrations_dir = "../../sql/d1-ts/tenant"
 * ```
 *
 * No new Durable Object, no new Queue, no `[[services]]`, and no change to
 * `src/worker.ts` — this slice adds no exported class.
 *
 * ### 3. Provisioning (per tenant, once)
 *
 * ```
 * wrangler d1 create ferrogate-tenant-acme
 * wrangler d1 migrations apply ferrogate-tenant-acme          # sql/d1-ts/tenant
 * # add the [[d1_databases]] stanza above, then:
 * wrangler deploy
 * # then record the mapping in the CONTROL database:
 * INSERT INTO tenant_databases
 *   (tenant_id, database_uuid, database_name, binding_name, schema_version,
 *    provisioned_at_unix, updated_at_unix)
 * VALUES ('tenant_acme', '<uuid>', 'ferrogate-tenant-acme', 'TENANT_DB_ACME', 1,
 *         unixepoch(), unixepoch());
 * ```
 *
 * A row without `binding_name` is "provisioned but not yet routable" and is
 * REFUSED, not fallen back — that is deliberate; see `./ports.ts`.
 *
 * ### The gate this wiring owes — LANDED
 *
 * Wiring (1) is in `src/index.ts` (`GATEWAY_MIDDLEWARE`, after `guardrails()`),
 * so the probe in `test/tenancy/mount.spec.ts` is a LIVE `test`, not the
 * `test.todo` an earlier revision of this note asked a future commit to flip:
 * it imports `GATEWAY_MIDDLEWARE` from `src/index.ts` and asserts an
 * unprovisioned tenant is refused rather than served from the shared database.
 * Steps (2) and (3) stay deploy-time work, because a `[[d1_databases]]` stanza
 * per tenant cannot be committed with real ids.
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
 * `TenantDataObject` addressing (#822).
 *
 * Re-exported here, and NOT wired into {@link createTenantDatabaseResolver},
 * because the `durable_object` routing mode needs a `D1Database`-shaped facade
 * over the object's `query`/`batch` RPCs that does not exist yet — see the
 * docblock in `./tenant-data.ts` for why shipping half a router would be worse
 * than shipping none. What exists now is the addressing rule and the two
 * refusals around it, exported so the facade slice imports a reviewed seam
 * instead of writing a second `idFromName` call somewhere else.
 */
export {
  type TenantDataBindings,
  tenantDataNamespace,
  tenantDataObjectFor,
} from "./tenant-data.js";
