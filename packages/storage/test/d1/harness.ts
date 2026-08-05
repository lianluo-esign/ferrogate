/**
 * Shared setup for the D1 suite.
 *
 * Every test file in `test/d1/` applies the REAL migrations from
 * `sql/d1-ts/**` to REAL databases in `workerd`. Nothing here fakes a
 * database, a transaction, or a guard — that is the point of the suite.
 *
 * ## This suite runs TWICE, against two backends
 *
 * `TENANT_BACKEND` is set by the config that booted the run
 * (`vitest.d1.config.ts` → `native_binding`, `vitest.d1do.config.ts` →
 * `durable_object`), and the two factories below are the only place the
 * difference is visible:
 *
 *   * {@link setupTenantRouter} hands back the backend's router;
 *   * {@link tenantDb} hands back one tenant's database for DIRECT seeding and
 *     assertion — the reads a test does to check that the store wrote what it
 *     said it wrote, without going through the store.
 *
 * A test file that reaches past these two — `env.TENANT_DB_A` in the middle of
 * a tenant-plane assertion — would silently assert against an EMPTY D1 database
 * while the store under test wrote into a Durable Object. It would pass, by
 * looking at the wrong place. That is why the tenant-plane files name their
 * database through `tenantDb()` and only the control-plane files (`billing`,
 * `site-domain`, `provider-credential`, `budget-alerts`) address `CONTROL_DB`
 * directly: the control plane is D1 in both legs, deliberately, because those
 * tables do not exist in the tenant schema.
 *
 * {@link setupDatabases} is kept and still returns the BINDING router
 * unconditionally, because `router.test.ts` asserts on that class specifically
 * — its subject is the registry→binding resolution, which the DO topology
 * replaces rather than reimplements.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import type { D1Migration } from "cloudflare:test";
import {
  ControlDatabaseTenantRegistry,
  DurableObjectTenantDatabaseRouter,
  EnvBindingTenantDatabaseRouter,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "../../src/index.js";
// TYPE-ONLY, and it has to stay that way: `src/tenant-data-object.ts` imports
// `DurableObject` from `cloudflare:workers`, which resolves in workerd only. A
// value import here would be fine inside this suite and would break the moment
// anything outside it re-exported the harness.
import type { TenantDataNamespace } from "../../src/tenant-data-object.js";

declare global {
  namespace Cloudflare {
    interface Env {
      CONTROL_DB: D1Database;
      TENANT_DB_A: D1Database;
      TENANT_DB_B: D1Database;
      TENANT_DB_C: D1Database;
      CONTROL_MIGRATIONS: D1Migration[];
      TENANT_MIGRATIONS: D1Migration[];
      /** `"native_binding"` | `"durable_object"`; see the file docblock. */
      TENANT_BACKEND: string;
      /** Present in both legs; only the `durable_object` leg addresses it. */
      TENANT_DATA: TenantDataNamespace;
    }
  }
}

export const TENANT_A = "tenant_a";
export const TENANT_B = "tenant_b";
export const TENANT_C = "tenant_c";

/**
 * Which backend this run is exercising.
 *
 * Defaults to `native_binding` when the binding is absent so that a config
 * which forgot it runs the historical suite rather than exploding — the DO leg
 * is the one that must be asked for explicitly, because it is the new claim.
 */
export const TENANT_BACKEND: "native_binding" | "durable_object" =
  env.TENANT_BACKEND === "durable_object" ? "durable_object" : "native_binding";

/** True on the leg that runs the suite through the `src/tenant-do.ts` facade. */
export const IS_DURABLE_OBJECT_BACKEND = TENANT_BACKEND === "durable_object";

/**
 * Apply both migration sets and register the three tenants in the control
 * database, returning a live BINDING router.
 *
 * `TENANT_C` is registered with `binding_name = null` on purpose: it is the
 * "provisioned but not yet redeployed" case the binding router must refuse
 * rather than silently serve from the control database. Under
 * `durable_object` there is no such state — one namespace binding serves every
 * tenant — so {@link setupTenantRouter}'s DO router resolves `TENANT_C`
 * happily, and `router.test.ts` keeps the refusal pinned where it still holds.
 */
export async function setupDatabases(): Promise<EnvBindingTenantDatabaseRouter> {
  await applyD1Migrations(env.CONTROL_DB, env.CONTROL_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_A, env.TENANT_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_B, env.TENANT_MIGRATIONS);
  await applyD1Migrations(env.TENANT_DB_C, env.TENANT_MIGRATIONS);

  const registry = new ControlDatabaseTenantRegistry(env.CONTROL_DB);
  await registry.upsert(
    {
      tenantId: TENANT_A,
      databaseUuid: "uuid-a",
      databaseName: "ferrogate-tenant-a",
      bindingName: "TENANT_DB_A",
      schemaVersion: 1,
    },
    1_700_000_000,
  );
  await registry.upsert(
    {
      tenantId: TENANT_B,
      databaseUuid: "uuid-b",
      databaseName: "ferrogate-tenant-b",
      bindingName: "TENANT_DB_B",
      schemaVersion: 1,
    },
    1_700_000_000,
  );
  await registry.upsert(
    {
      tenantId: TENANT_C,
      databaseUuid: "uuid-c",
      databaseName: "ferrogate-tenant-c",
      schemaVersion: 1,
    },
    1_700_000_000,
  );

  // `registrationTtlMs: 0` — no in-isolate caching, so a test that changes a
  // registration sees the change immediately. Production keeps the default TTL.
  return new EnvBindingTenantDatabaseRouter(
    env as unknown as Record<string, unknown>,
    env.CONTROL_DB,
    { registrationTtlMs: 0 },
  );
}

/**
 * The router for the backend this run is exercising — the sibling factory.
 *
 * Both legs perform the SAME setup first: the migrations are applied to the D1
 * tenant databases and the registry rows are written either way. Under
 * `durable_object` the registry rows are NOT what routes — since #819 the DO
 * router reads nothing on `forTenant()` — but they are still the only possible
 * answer to `provisionedTenants()`, since a Durable Object namespace cannot be
 * enumerated in production. Applying the tenant migrations to the (now unused)
 * D1 databases is left in place so that the two legs differ in exactly one
 * thing: which database the handle points at.
 */
export async function setupTenantRouter(): Promise<TenantDatabaseRouter> {
  const binding = await setupDatabases();
  if (!IS_DURABLE_OBJECT_BACKEND) return binding;
  // No options: the DO router has no registration cache to disable, because it
  // performs no registration read.
  return new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, env.CONTROL_DB);
}

/**
 * One tenant's database, for the DIRECT reads and seeds a test does around the
 * store under test.
 *
 * Under `native_binding` this is the raw `env.TENANT_DB_*` binding; under
 * `durable_object` it is the facade over that tenant's object. Both are real
 * databases holding the tenant's real rows, which is the only property the
 * assertions need.
 */
export function tenantDb(tenantId: string): D1Database {
  if (IS_DURABLE_OBJECT_BACKEND) {
    return new DurableObjectTenantDatabaseRouter(env.TENANT_DATA, env.CONTROL_DB).databaseFor(
      tenantId,
    );
  }
  switch (tenantId) {
    case TENANT_A:
      return env.TENANT_DB_A;
    case TENANT_B:
      return env.TENANT_DB_B;
    case TENANT_C:
      return env.TENANT_DB_C;
    default:
      throw new Error(
        `tenantDb(${tenantId}): the D1 leg binds databases for ${TENANT_A}, ${TENANT_B} and ` +
          `${TENANT_C} only; a fourth tenant needs a fourth binding in vitest.d1.shared.ts`,
      );
  }
}

/** Truncate every table a D1 test writes, so files/tests do not leak into each other. */
export async function resetTenantData(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM wallet_settlements"),
    db.prepare("DELETE FROM wallet_reservations"),
    db.prepare("DELETE FROM wallets"),
    db.prepare("DELETE FROM workflow_run_budgets"),
    db.prepare("DELETE FROM observed_agent_presence"),
    db.prepare("DELETE FROM agent_cost_burn"),
    db.prepare("DELETE FROM control_plane_replay_floors"),
    db.prepare("DELETE FROM usage_monthly_rollups"),
    db.prepare("DELETE FROM usage_metadata_rollups"),
    db.prepare("DELETE FROM usage_aggregate_rollups"),
    db.prepare("DELETE FROM tenant_contexts"),
    db.prepare("DELETE FROM asset_channels"),
    db.prepare("DELETE FROM stored_assets"),
    db.prepare("DELETE FROM retention_policies"),
    db.prepare("DELETE FROM agent_schedule_fires"),
    db.prepare("DELETE FROM agent_schedules"),
  ]);
}

/** Seed a wallet with `balanceCredits` on `handle`'s database. */
export async function seedWallet(
  handle: TenantDatabaseHandle,
  balanceCredits: number,
  nowUnix = 1_700_000_000,
): Promise<void> {
  await handle.db
    .prepare(
      "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, " +
        "updated_at_unix) VALUES (?, ?, ?, 0, ?, ?) " +
        "ON CONFLICT (id) DO UPDATE SET balance_credits = excluded.balance_credits",
    )
    .bind(handle.tenantId, handle.tenantId, balanceCredits, nowUnix, nowUnix)
    .run();
}
