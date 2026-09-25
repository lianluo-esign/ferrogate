import type { TenantDatabaseRouter } from "./tenant-router.js";

export const TENANT_CONFIGURATION_BACKFILL_MARK = "tenant_configuration_policy_v1";

/** Retired compatibility export. Runtime callers no longer invoke it.
 * All source reads, copying, cursors and completion writes were removed.
 * Legacy control rows must never restore or override tenant-owned state. */
export async function backfillTenantConfigurationPolicy(
  _controlDb: D1Database,
  _router: TenantDatabaseRouter,
  _tenantId: string,
  _nowUnix?: number,
): Promise<void> {}
