/**
 * Shared setup for the D1 suite.
 *
 * Every test file in `test/d1/` applies the REAL migrations from
 * `sql/d1-ts/**` to REAL D1 databases in `workerd`. Nothing here fakes a
 * database, a transaction, or a guard — that is the point of the suite.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import type { D1Migration } from "cloudflare:test";
import {
  ControlDatabaseTenantRegistry,
  EnvBindingTenantDatabaseRouter,
  type TenantDatabaseHandle,
} from "../../src/index.js";

declare global {
  namespace Cloudflare {
    interface Env {
      CONTROL_DB: D1Database;
      TENANT_DB_A: D1Database;
      TENANT_DB_B: D1Database;
      TENANT_DB_C: D1Database;
      CONTROL_MIGRATIONS: D1Migration[];
      TENANT_MIGRATIONS: D1Migration[];
    }
  }
}

export const TENANT_A = "tenant_a";
export const TENANT_B = "tenant_b";
export const TENANT_C = "tenant_c";

/**
 * Apply both migration sets and register the three tenants in the control
 * database, returning a live router.
 *
 * `TENANT_C` is registered with `binding_name = null` on purpose: it is the
 * "provisioned but not yet redeployed" case the router must refuse rather than
 * silently serve from the control database.
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

/** Truncate every table a D1 test writes, so files/tests do not leak into each other. */
export async function resetTenantData(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare("DELETE FROM wallet_settlements"),
    db.prepare("DELETE FROM wallet_reservations"),
    db.prepare("DELETE FROM wallets"),
    db.prepare("DELETE FROM workflow_run_budgets"),
    db.prepare("DELETE FROM observed_agent_presence"),
    db.prepare("DELETE FROM agent_cost_burn"),
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
