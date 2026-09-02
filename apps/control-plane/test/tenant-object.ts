import { env } from "cloudflare:test";
import { DurableObjectTenantDatabaseRouter } from "@ferrogate/storage";
import type { TenantDataNamespace, TenantDataStatement } from "@ferrogate/storage/durable-objects";
import {
  type BillingEventSeed,
  type RequestLogSeed,
  db,
  platformDb,
  seedBillingEvents,
  seedRequestLogs,
} from "./d1.js";

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

/**
 * Cost evidence seeded WHERE IT LIVES: a tenant-attributed request log goes into
 * that tenant's object (registering it on the roster), an un-attributed one into
 * the platform object — and a billing event follows the request it belongs to.
 *
 * The control `request_logs` / `billing_events` tables are no longer what an
 * operator's cost read joins (that read fans out over the objects), so a
 * fixture that seeded control would test nothing. The owner map is per test:
 * call {@link resetRoutedCostOwners} from `beforeEach`.
 */
const ROUTED_COST_OWNERS = new Map<string, string | null>();

export function resetRoutedCostOwners(): void {
  ROUTED_COST_OWNERS.clear();
}

export async function seedRoutedRequestLogs(
  rows: readonly RequestLogSeed[],
  target?: D1Database,
): Promise<void> {
  for (const row of rows) ROUTED_COST_OWNERS.set(row.requestId, row.tenant ?? null);
  if (target !== undefined) {
    await seedRequestLogs(rows, target);
    return;
  }
  const tenants = new Set(
    rows.map((row) => row.tenant ?? null).filter((tenant): tenant is string => tenant !== null),
  );
  for (const tenantId of tenants) {
    await registerDurableObjectTenant(tenantId);
    await seedRequestLogs(
      rows.filter((row) => (row.tenant ?? null) === tenantId),
      tenantObjectDb(tenantId),
    );
  }
  await seedRequestLogs(
    rows.filter((row) => (row.tenant ?? null) === null),
    platformDb(),
  );
}

export async function seedRoutedBillingEvents(
  rows: readonly BillingEventSeed[],
  target?: D1Database,
  tenantId?: string,
): Promise<void> {
  if (target !== undefined) {
    await seedBillingEvents(rows, target, tenantId);
    return;
  }
  const byOwner = new Map<string | null, BillingEventSeed[]>();
  for (const row of rows) {
    const owner = ROUTED_COST_OWNERS.get(row.requestId) ?? null;
    byOwner.set(owner, [...(byOwner.get(owner) ?? []), row]);
  }
  for (const [owner, events] of byOwner) {
    if (owner === null) await seedBillingEvents(events, platformDb());
    else {
      await registerDurableObjectTenant(owner);
      await seedBillingEvents(events, tenantObjectDb(owner), owner);
    }
  }
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
