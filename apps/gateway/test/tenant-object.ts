import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDatabaseHandle } from "@ferrogate/storage";
import type { TenantDataNamespace, TenantDataStatement } from "@ferrogate/storage/durable-objects";

interface TenantObjectBindings {
  readonly CONTROL_DB: D1Database;
  readonly TENANT_DATA: TenantDataNamespace;
}

function bindings(): TenantObjectBindings {
  const value = env as unknown as Partial<TenantObjectBindings>;
  if (value.CONTROL_DB === undefined || value.TENANT_DATA === undefined) {
    throw new Error("gateway tenant fixtures require CONTROL_DB and TENANT_DATA bindings");
  }
  return value as TenantObjectBindings;
}

function router(): DurableObjectTenantDatabaseRouter {
  const value = bindings();
  return new DurableObjectTenantDatabaseRouter(value.TENANT_DATA, value.CONTROL_DB);
}

export function tenantObjectDb(tenantId: string): D1Database {
  return router().databaseFor(tenantId);
}

/**
 * The router itself, for source ports that take a `tenantDatabases` option
 * (post-#863 the tenant object is the authority for `tenant_role_bindings`).
 */
export function tenantObjectRouter(): DurableObjectTenantDatabaseRouter {
  return router();
}

/**
 * The trusted operator projection path. `TenantDataObject` refuses ordinary
 * tenant SQL against `tenant_role_bindings` / `tenant_role_catalog`, so a test
 * seeding (or clearing) durable role grants must go through the same
 * privileged RPC `backfillTenantConfigurationPolicy` uses.
 */
export async function tenantObjectPrivilegedBatch(
  tenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<void> {
  await router().privilegedBatch(tenantId, statements);
}

export async function tenantObjectHandle(tenantId: string): Promise<TenantDatabaseHandle> {
  return router().forTenant(tenantId);
}

export async function resetTenantObjectState(tenantIds: readonly string[]): Promise<void> {
  for (const tenantId of tenantIds) {
    const tenant = tenantObjectDb(tenantId);
    await tenant.batch([
      tenant.prepare("DELETE FROM semantic_cache_policies"),
      tenant.prepare("DELETE FROM delegation_revocations"),
      tenant.prepare("DELETE FROM budget_alert_notifications"),
      tenant.prepare("DELETE FROM tenant_provisioning_marks"),
    ]);
  }
}

/**
 * Roster rows for tenants a single test file invents beyond the
 * `vitest.config.ts` fixtures (which `test/setup-d1.ts` already seeds).
 *
 * Since #820/#824 the `durable_object` default routes through
 * `BackendDispatchingTenantDatabaseRouter` whenever `DB` is bound, and that
 * router reads the `tenant_databases` roster: a tenant with NO row falls to the
 * native-binding arm, whose `not_found` surfaces as a 503 on every
 * authenticated request. Production writes this row at onboarding; ad-hoc test
 * tenants must seed it themselves.
 */
export async function seedTenantRosterRows(tenantIds: readonly string[]): Promise<void> {
  const control = bindings().CONTROL_DB;
  // `migration_state` is stated explicitly: the column's SQL DEFAULT is
  // 'shared' (pre-cutover), which makes the dispatching router take the LEGACY
  // shared-database arm — so a test that seeds the tenant OBJECT would read
  // back nothing. Production's `ControlDatabaseTenantRegistry.upsert` writes
  // 'done' for every durable_object tenant; so does this.
  const seed = control.prepare(
    "INSERT OR IGNORE INTO tenant_databases " +
      "(tenant_id, storage_backend, provisioning_status, migration_state) " +
      "VALUES (?, 'durable_object', 'ready', 'done')",
  );
  await control.batch(tenantIds.map((tenantId) => seed.bind(tenantId)));
}

/** Clear tenant-authoritative billing state between gateway metering tests. */
export async function resetTenantBillingState(tenantIds: readonly string[]): Promise<void> {
  for (const tenantId of tenantIds) {
    const tenant = tenantObjectDb(tenantId);
    await tenant.batch([
      tenant.prepare("DELETE FROM billing_report_outbox"),
      tenant.prepare("DELETE FROM billing_ledger"),
      tenant.prepare("DELETE FROM billing_events"),
      tenant.prepare("DELETE FROM wallet_settlements"),
      tenant.prepare("DELETE FROM wallet_reservations"),
      tenant.prepare("DELETE FROM wallets"),
    ]);
  }
}
