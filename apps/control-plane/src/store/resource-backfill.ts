/** Retired compatibility exports. No runtime path reads legacy control
 * resources, copies them into tenant objects, or writes a backfill cursor. */
export const RESOURCE_BACKFILL_MARK = "control_plane_resource_backfill_v1";
export const RESOURCE_BACKFILL_BATCH_SIZE = 200;
export interface TenantResourceBackfillResult {
  readonly scanned: number;
  readonly copied: number;
}
export async function backfillTenantResourceKinds(
  _controlDb: D1Database,
  _tenantDb: D1Database,
  _tenantId: string,
): Promise<TenantResourceBackfillResult> {
  return { scanned: 0, copied: 0 };
}
