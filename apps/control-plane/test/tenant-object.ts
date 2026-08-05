import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDataNamespace, TenantDataStatement } from "@ferrogate/storage/durable-objects";
import { db } from "./d1.js";

interface TenantObjectBindings {
  readonly DB: D1Database;
  readonly TENANT_DATA: TenantDataNamespace;
}

function bindings(): TenantObjectBindings {
  const value = env as unknown as Partial<TenantObjectBindings>;
  if (value.DB === undefined || value.TENANT_DATA === undefined) {
    throw new Error("control-plane tenant fixtures require DB and TENANT_DATA bindings");
  }
  return value as TenantObjectBindings;
}

export function tenantObjectRouter(): DurableObjectTenantDatabaseRouter {
  const value = bindings();
  return new DurableObjectTenantDatabaseRouter(value.TENANT_DATA, value.DB);
}

export function tenantObjectDb(tenantId: string): D1Database {
  return tenantObjectRouter().databaseFor(tenantId);
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
         (tenant_id, database_uuid, database_name, binding_name, schema_version,
          storage_backend, provisioning_status, provisioned_at_unix, updated_at_unix)
       VALUES (?, ?, ?, NULL, 15, 'durable_object', 'ready', 1, 1)
       ON CONFLICT (tenant_id) DO UPDATE SET
         binding_name = NULL,
         storage_backend = 'durable_object',
         provisioning_status = 'ready',
         schema_version = 15`,
    )
    .bind(tenantId, `uuid-${tenantId}`, `ferrogate-${tenantId}`)
    .run();
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
