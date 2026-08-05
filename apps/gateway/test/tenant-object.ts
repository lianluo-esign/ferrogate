import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDatabaseHandle } from "@ferrogate/storage";
import type { TenantDataNamespace } from "@ferrogate/storage/durable-objects";

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
