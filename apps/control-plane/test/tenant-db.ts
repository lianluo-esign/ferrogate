/**
 * Per-tenant D1 test plumbing: REAL tenant databases with the REAL tenant
 * migration applied, and REAL `tenant_databases` registry rows pointing at them.
 *
 * `TENANT_DB_A` / `TENANT_DB_B` are bound by `vitest.config.ts` (see its
 * docblock for why they live there and not in `wrangler.toml`), and
 * `TEST_TENANT_D1_SCHEMA` carries `sql/d1-ts/tenant/` — the same directory
 * `wrangler d1 migrations apply` is pointed at for a tenant database. Nothing
 * here restates a `CREATE TABLE`.
 *
 * Two databases, not one. A cross-tenant assertion against a single shared
 * database is vacuous: it would pass against a router that ignored its argument
 * and handed everybody the same handle, which is exactly the failure the
 * database-per-tenant topology exists to prevent.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import { db } from "./d1.js";

interface TenantD1Bindings {
  readonly TENANT_DB_A: D1Database;
  readonly TENANT_DB_B: D1Database;
  readonly TEST_TENANT_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

export const TENANT_A = "tenant_a";
export const TENANT_B = "tenant_b";
/**
 * Registered in the control database naming a binding this Worker does NOT
 * have, so "provisioned but not yet redeployed" has something real to refuse.
 */
export const TENANT_UNROUTABLE = "tenant_unrouted";

function bindings(): TenantD1Bindings {
  return env as unknown as TenantD1Bindings;
}

export function tenantDbA(): D1Database {
  return bindings().TENANT_DB_A;
}

export function tenantDbB(): D1Database {
  return bindings().TENANT_DB_B;
}

/** Apply `sql/d1-ts/tenant/` to both tenant databases. Call once, in `beforeAll`. */
export async function applyTenantSchema(): Promise<void> {
  const b = bindings();
  await applyD1Migrations(b.TENANT_DB_A, b.TEST_TENANT_D1_SCHEMA);
  await applyD1Migrations(b.TENANT_DB_B, b.TEST_TENANT_D1_SCHEMA);
}

/**
 * Empty the tenant tables this app writes, plus the two CONTROL tables that
 * point into them (`tenant_databases`, `api_key_directory`). Call in
 * `beforeEach` — the pool does not roll D1 writes back and the databases are
 * persisted under `.wrangler/state`, so without this a passing assertion could
 * be a previous test's (or a previous RUN's) leftover row.
 *
 * `api_key_directory` belongs here rather than in `resetD1`: it is the control
 * half of the per-tenant credential dual write, so it is meaningless without the
 * tenant `api_keys` rows this function clears alongside it.
 */
export async function resetTenantD1(): Promise<void> {
  for (const handle of [tenantDbA(), tenantDbB()]) {
    await handle.batch([
      handle.prepare("DELETE FROM api_keys"),
      handle.prepare("DELETE FROM workspaces"),
      handle.prepare("DELETE FROM projects"),
      // The prepaid-money tables. `wallet_settlements` in particular MUST be
      // cleared: it is the idempotency ledger, so a leftover row from a
      // previous test would make a fresh credit report itself as an
      // already-applied replay and move no money — a green assertion built on
      // the previous run's state.
      handle.prepare("DELETE FROM wallet_reservations"),
      handle.prepare("DELETE FROM wallet_settlements"),
      handle.prepare("DELETE FROM wallets"),
      handle.prepare("DELETE FROM payment_methods"),
      handle.prepare("DELETE FROM tenant_resources"),
      handle
        .prepare("DELETE FROM tenant_provisioning_marks WHERE mark = ?")
        .bind("control_plane_resource_backfill_v1"),
      handle
        .prepare("DELETE FROM tenant_provisioning_marks WHERE mark LIKE ?")
        .bind("control_plane_resource_deleted_v1:%"),
    ]);
  }
  await db().batch([
    db().prepare("DELETE FROM tenant_databases"),
    db().prepare("DELETE FROM api_key_directory"),
  ]);
}

/**
 * Register the tenants in the CONTROL database's `tenant_databases` table — the
 * registry `EnvBindingTenantDatabaseRouter` reads.
 *
 * Written with raw SQL rather than through `ControlDatabaseTenantRegistry`
 * deliberately: a fixture built with the code under test cannot show that the
 * code under test reads what is actually in the table.
 */
export async function registerTenantDatabases(): Promise<void> {
  const rows: [string, string, string, string | null][] = [
    [TENANT_A, "uuid-a", "ferrogate-tenant-a", "TENANT_DB_A"],
    [TENANT_B, "uuid-b", "ferrogate-tenant-b", "TENANT_DB_B"],
    // Names a binding that does not exist on this Worker.
    [TENANT_UNROUTABLE, "uuid-x", "ferrogate-tenant-x", "TENANT_DB_NOT_DEPLOYED"],
  ];
  await db().batch(
    rows.map(([tenantId, uuid, name, binding]) =>
      db()
        .prepare(
          `INSERT INTO tenant_databases
             (tenant_id, database_uuid, database_name, binding_name, schema_version,
              migration_state, provisioned_at_unix, updated_at_unix)
           VALUES (?, ?, ?, ?, 1, 'done', 1, 1)`,
        )
        .bind(tenantId, uuid, name, binding),
    ),
  );
}

/** Ids of the rows in a tenant database's `projects` table, ascending. */
export async function projectIds(handle: D1Database): Promise<string[]> {
  const rows = await handle.prepare("SELECT id FROM projects ORDER BY id").all<{ id: string }>();
  return rows.results.map((row) => row.id);
}

/** Ids of the rows in a tenant database's `workspaces` table, ascending. */
export async function workspaceIds(handle: D1Database): Promise<string[]> {
  const rows = await handle.prepare("SELECT id FROM workspaces ORDER BY id").all<{ id: string }>();
  return rows.results.map((row) => row.id);
}

/**
 * Insert a virtual API key row straight into a tenant database.
 *
 * This is the OTHER thing §1.5.7's guard counts. The admin surface DOES mint one
 * now (`src/store/virtual_keys.ts`, driven end to end by
 * `virtual-key-credential.test.ts`), but a fixture built with the code under
 * test cannot show that the reference guard reads what is actually in the table
 * — so the guard's own tests seed the row directly, exactly as `seedD1` does for
 * the document store.
 */
export async function seedVirtualKey(
  handle: D1Database,
  options: { id: string; tenantId: string; projectId: string; workspaceId: string },
): Promise<void> {
  await handle
    .prepare(
      `INSERT INTO api_keys
         (id, workspace_id, tenant_id, project_id, name, key_prefix, key_hash, last4)
       VALUES (?, ?, ?, ?, ?, 'fg_', 'sha256:seed', 'seed')`,
    )
    .bind(options.id, options.workspaceId, options.tenantId, options.projectId, options.id)
    .run();
}
