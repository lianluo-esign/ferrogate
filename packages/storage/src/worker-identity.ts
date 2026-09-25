import { StorageError } from "./errors.js";
import type { TenantDatabaseRouter } from "./tenant-router.js";

/** Credentials and mutable worker state have exactly one home: the tenant DO. */
export async function readTenantWorkerIdentity(
  router: TenantDatabaseRouter,
  tenantId: string,
  workerId: string,
): Promise<Record<string, unknown> | null> {
  const handle = await router.forTenant(tenantId).catch((error) => {
    if (error instanceof StorageError && error.kind === "not_found") return null;
    throw error;
  });
  if (handle === null) return null;
  const row = await handle.db
    .prepare(
      `SELECT workspace_id,token_id,token_secret,status,identity_json,registered_at_unix
       FROM self_hosted_worker_identities WHERE tenant_id=? AND worker_id=?`,
    )
    .bind(tenantId, workerId)
    .first<{
      workspace_id: string;
      token_id: string;
      token_secret: string;
      status: string;
      identity_json: string;
      registered_at_unix: number;
    }>();
  if (row === null) return null;
  const document: unknown = JSON.parse(row.identity_json);
  if (document === null || typeof document !== "object" || Array.isArray(document)) return null;
  return {
    framework_adapter: "native",
    capabilities: [],
    identity_fingerprint: null,
    identity_expires_at_unix: null,
    ...document,
    tenant_id: tenantId,
    workspace_id: row.workspace_id,
    worker_id: workerId,
    token_id: row.token_id,
    token_secret: row.token_secret,
    active: row.status === "active",
    registered_at_unix: row.registered_at_unix,
  };
}
