import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDataNamespace, TenantDataStatement } from "@ferrogate/storage/durable-objects";
import { db } from "./d1.js";

interface TenantObjectBindings {
  readonly TENANT_DATA: TenantDataNamespace;
}

function bindings(): TenantObjectBindings {
  const value = env as unknown as Partial<TenantObjectBindings>;
  if (value.TENANT_DATA === undefined) {
    throw new Error("control-plane tenant fixtures require the TENANT_DATA binding");
  }
  return value as TenantObjectBindings;
}

export function tenantObjectRouter(): DurableObjectTenantDatabaseRouter {
  // Zero-D1 S5 (#881): the tenant router reads the `tenant_databases` roster out
  // of the control database, which is now the CONTROL_DATA object facade
  // (`db()`), not the retired `env.DB` control D1.
  return new DurableObjectTenantDatabaseRouter(bindings().TENANT_DATA, db());
}

export function tenantObjectDb(tenantId: string): D1Database {
  return tenantObjectRouter().databaseFor(tenantId);
}

/**
 * The raw stored document of a TENANT-ATTRIBUTED resource, read straight out of
 * the owning tenant's object (`tenant_resources`) — the post-#861/#863
 * authority for tenant-private kinds. The control-table twin (`rawDocument` in
 * `./d1.ts`) keeps serving the UN-ATTRIBUTED platform rows, which stay on
 * control D1.
 */
export async function rawTenantDocument(
  tenantId: string,
  collection: string,
  id: string,
): Promise<Record<string, unknown> | null> {
  const row = await tenantObjectDb(tenantId)
    .prepare(
      "SELECT document_json FROM tenant_resources WHERE resource_kind = ? AND resource_id = ?",
    )
    .bind(collection, id)
    .first<{ document_json: string }>();
  return row === null ? null : (JSON.parse(row.document_json) as Record<string, unknown>);
}

/** The storage revision of a tenant-object row, or `null` when it is gone. */
export async function rawTenantRevision(
  tenantId: string,
  collection: string,
  id: string,
): Promise<number | null> {
  const row = await tenantObjectDb(tenantId)
    .prepare("SELECT revision FROM tenant_resources WHERE resource_kind = ? AND resource_id = ?")
    .bind(collection, id)
    .first<{ revision: number }>();
  return row === null ? null : row.revision;
}

export async function privilegedTenantBatch(
  tenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<void> {
  const router = tenantObjectRouter();
  if (router.privilegedBatch === undefined) {
    throw new Error("control-plane tenant fixtures require the privileged tenant RPC");
  }
  await router.privilegedBatch(tenantId, statements);
}

export async function registerDurableObjectTenant(tenantId: string): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO tenant_databases
         (tenant_id, binding_name, schema_version,
          storage_backend, provisioning_status, migration_state, provisioned_at_unix, updated_at_unix)
       VALUES (?, NULL, 15, 'durable_object', 'ready', 'done', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         binding_name = NULL,
         storage_backend = 'durable_object',
         provisioning_status = 'ready',
         migration_state = 'done',
         schema_version = 15`,
    )
    .bind(tenantId)
    .run();
}

/**
 * Roster rows for a suite's fixture tenants (same shape the gateway's
 * `test/setup-d1.ts` seeds): the platform-operator fan-out reads
 * `tenant_databases`, and in production the onboarding path writes this row the
 * moment a tenant is created — the fixture tenants of `arm()` never onboard, so
 * suites that exercise operator reads over tenant-attributed rows seed the
 * roster here, after `resetD1` wiped it.
 */
export async function registerObjectTenants(tenantIds: readonly string[]): Promise<void> {
  for (const tenantId of tenantIds) await registerDurableObjectTenant(tenantId);
}

export async function seedTenantRoleProjection(
  tenantId: string,
  roleId: string,
  permissionKeys: readonly string[] | string,
  nowUnix = 1,
): Promise<void> {
  const router = tenantObjectRouter();
  if (router.privilegedBatch === undefined) {
    throw new Error("control-plane role fixtures require the privileged tenant RPC");
  }
  const statements: TenantDataStatement[] = [
    {
      sql:
        "INSERT INTO tenant_role_catalog " +
        "(role_id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, '', ?, ?, ?) " +
        "ON CONFLICT(role_id) DO UPDATE SET permission_keys_json = excluded.permission_keys_json, " +
        "updated_at_unix = excluded.updated_at_unix",
      params: [roleId, roleId, roleId, JSON.stringify(permissionKeys), nowUnix, nowUnix],
    },
    {
      sql:
        "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) " +
        "VALUES (?, ?, ?, ?) ON CONFLICT(tenant_id, role_id) DO NOTHING",
      params: [`${tenantId}:${roleId}`, tenantId, roleId, nowUnix],
    },
  ];
  await router.privilegedBatch(tenantId, statements);
}

export async function resetTenantObjectState(tenantIds: readonly string[]): Promise<void> {
  const router = tenantObjectRouter();
  if (router.privilegedBatch === undefined) {
    throw new Error("control-plane tenant cleanup requires the privileged tenant RPC");
  }
  for (const tenantId of tenantIds) {
    const tenant = tenantObjectDb(tenantId);
    await router.privilegedBatch(tenantId, [
      { sql: "DELETE FROM tenant_role_bindings", params: [] },
      { sql: "DELETE FROM tenant_role_catalog", params: [] },
    ]);
    await tenant.batch([
      tenant.prepare("DELETE FROM tenant_provider_credentials"),
      tenant.prepare("DELETE FROM sso_provider_configs"),
      tenant.prepare("DELETE FROM semantic_cache_policies"),
      tenant.prepare("DELETE FROM delegation_revocations"),
      tenant.prepare("DELETE FROM control_plane_replay_floors"),
      tenant.prepare("DELETE FROM budget_alert_notifications"),
      tenant.prepare("DELETE FROM tenant_provisioning_marks"),
    ]);
  }
}
