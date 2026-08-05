import { env } from "cloudflare:test";
import {
  DurableObjectTenantDatabaseRouter,
} from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";

interface TenantObjectBindings {
  readonly DB: D1Database;
  readonly TENANT_DATA: TenantDataNamespace;
}

function bindings(): TenantObjectBindings {
  const value = env as unknown as Partial<TenantObjectBindings>;
  if (value.DB === undefined || value.TENANT_DATA === undefined) {
    throw new Error("MCP tenant fixtures require DB and TENANT_DATA bindings");
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

export async function registerDurableObjectTenant(tenantId: string): Promise<void> {
  await bindings()
    .DB.prepare(
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

export function tenantObjectNamespace(): TenantDataNamespace {
  return bindings().TENANT_DATA;
}

/**
 * Inject one local read failure without asking the real object to throw.
 *
 * A rejected `TenantDataObject.query()` is a valid RPC failure, but workerd
 * reports the remote exception as `uncaught` even when the caller converts it
 * into the expected fail-closed 503. Tests that need an unreadable table must
 * therefore reject at this namespace boundary and delegate every other call
 * to the real object. This preserves the production reader path and keeps the
 * test output free of transport-level noise.
 */
export function tenantObjectNamespaceWithQueryFailure(
  namespace: TenantDataNamespace,
  sqlFragment: string,
): TenantDataNamespace {
  return {
    idFromName: (name: string) => namespace.idFromName(name),
    get(id: DurableObjectId) {
      const stub = namespace.get(id) as unknown as {
        query(request: { sql: string; params?: readonly unknown[] }): Promise<unknown>;
        batch(request: unknown): Promise<unknown>;
        privilegedBatch?(request: unknown): Promise<unknown>;
      };
      return {
        query(request: { sql: string; params?: readonly unknown[] }) {
          if (request.sql.includes(sqlFragment)) {
            return Promise.reject(new Error(`tenant object test fault: ${sqlFragment}`));
          }
          return stub.query(request);
        },
        batch: (request: unknown) => stub.batch(request),
        ...(stub.privilegedBatch === undefined
          ? {}
          : { privilegedBatch: (request: unknown) => stub.privilegedBatch?.(request) }),
      };
    },
  } as unknown as TenantDataNamespace;
}

export async function seedTenantRoleProjection(
  tenantId: string,
  roleId: string,
  permissionKeys: readonly string[],
): Promise<void> {
  const router = tenantObjectRouter();
  if (router.privilegedBatch === undefined) {
    throw new Error("MCP role fixtures require the privileged tenant RPC");
  }
  await router.privilegedBatch(tenantId, [
    {
      sql:
        "INSERT INTO tenant_role_catalog " +
        "(role_id, name, slug, description, permission_keys_json, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, '', ?, 1, 1) " +
        "ON CONFLICT(role_id) DO UPDATE SET permission_keys_json = excluded.permission_keys_json, " +
        "updated_at_unix = excluded.updated_at_unix",
      params: [roleId, roleId, roleId, JSON.stringify(permissionKeys)],
    },
    {
      sql:
        "INSERT INTO tenant_role_bindings (id, tenant_id, role_id, created_at_unix) " +
        "VALUES (?, ?, ?, 1) ON CONFLICT(tenant_id, role_id) DO NOTHING",
      params: [`${tenantId}:${roleId}`, tenantId, roleId],
    },
  ]);
}

export async function resetTenantObjectState(tenantIds: readonly string[]): Promise<void> {
  const router = tenantObjectRouter();
  if (router.privilegedBatch === undefined) {
    throw new Error("MCP tenant cleanup requires the privileged tenant RPC");
  }
  for (const tenantId of tenantIds) {
    const tenant = tenantObjectDb(tenantId);
    await router.privilegedBatch(tenantId, [
      { sql: "DELETE FROM tenant_role_bindings", params: [] },
      { sql: "DELETE FROM tenant_role_catalog", params: [] },
    ]);
    await tenant.batch([
      tenant.prepare("DELETE FROM api_keys"),
      tenant.prepare("DELETE FROM usage_monthly_rollups"),
      tenant.prepare("DELETE FROM wallets"),
      tenant.prepare("DELETE FROM wallet_reservations"),
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
