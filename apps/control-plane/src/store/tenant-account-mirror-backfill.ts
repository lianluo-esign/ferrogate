/**
 * One-time backfill of the `tenants.document_json` mirror (#75).
 *
 * The operator `tenant-accounts` LIST is served from the control-DO `tenants`
 * mirror (`split.ts` `#listTenantAccountsMirror`), which reads back the full
 * admin document `projectTenantAccount` now writes into `document_json`. Every
 * write-through from the moment the column ships fills it, but tenants that were
 * provisioned BEFORE the migration have a `tenants` row with `document_json`
 * NULL until their next mutation — and the reader SKIPS NULL rows, so those
 * tenants would silently drop out of the operator list. This pass copies each
 * such tenant's authoritative document from its own object into the mirror once.
 *
 * ## Why the NULL filter IS the idempotency gate (no separate mark)
 *
 * The unit of remaining work is exactly `SELECT id FROM tenants WHERE
 * document_json IS NULL`: a successful backfill sets the column non-NULL, so the
 * row leaves the set permanently and a later tick never re-opens that object.
 * When the set is empty the pass returns `"complete"` having opened ZERO objects
 * — steady state is one indexed control-DO SELECT per eligible tick. This is
 * self-terminating and self-healing without a durable cursor.
 *
 * A `tenants` row whose object has no `tenant-accounts` document (a pathological
 * orphan — no such row is produced by any live path) stays NULL and is
 * re-examined on later ticks. That is bounded by {@link
 * TENANT_ACCOUNT_MIRROR_BACKFILL_BATCH} object opens per eligible tick and never
 * grows, so it is accepted rather than tracked; such a tenant has no document to
 * list anyway.
 *
 * ## Contention
 *
 * Opening up to N objects per tick has the same single-control-DO-thread profile
 * the catalog sweep documents (`scheduled.ts`), so the caller gates this on the
 * same coarse cadence and bounds each tick to a batch. After the fleet converges
 * (a tick or two post-deploy) the pass idles.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { TENANT_RESOURCE_TABLE } from "./d1.js";
import { projectTenantAccount } from "./quota_registry.js";

/** Max objects a single eligible tick opens, so per-tick control-DO load is bounded. */
export const TENANT_ACCOUNT_MIRROR_BACKFILL_BATCH = 50;

export interface TenantAccountMirrorBackfillReport {
  /** `tenants` rows with a NULL `document_json` this tick examined (<= batch). */
  readonly scanned: number;
  /** How many were filled from their object's authoritative document. */
  readonly mirrored: number;
  /** How many object reads/projections failed (retried next eligible tick). */
  readonly failed: number;
  /**
   * `"complete"` when no NULL rows remain (zero objects opened); `null` when a
   * batch was processed and more may remain; `"control_database_unavailable"`
   * when the deployment binds no control DB.
   */
  readonly skipped: null | "complete" | "control_database_unavailable";
}

/**
 * Fill up to a batch of un-mirrored `tenants` rows from each tenant's object.
 * Never throws — a roster or per-tenant failure is folded into the report so the
 * caller (a `scheduled` handler) is not retried into a second execution path.
 */
export async function backfillTenantAccountMirror(
  router: TenantDatabaseRouter,
  controlDatabase: D1Database,
  nowUnix: number,
): Promise<TenantAccountMirrorBackfillReport> {
  let pending: readonly { id: string }[];
  try {
    const rows = await controlDatabase
      .prepare("SELECT id FROM tenants WHERE document_json IS NULL LIMIT ?")
      .bind(TENANT_ACCOUNT_MIRROR_BACKFILL_BATCH)
      .all<{ id: string }>();
    pending = rows.results;
  } catch (error) {
    console.warn("control-plane: tenant-account mirror backfill scan failed", error);
    return { scanned: 0, mirrored: 0, failed: 1, skipped: null };
  }
  if (pending.length === 0) return { scanned: 0, mirrored: 0, failed: 0, skipped: "complete" };

  let mirrored = 0;
  let failed = 0;
  for (const { id } of pending) {
    try {
      const handle = await router.forTenant(id);
      // `tenant-accounts` is id-keyed: the document id IS the tenant id.
      const row = await handle.db
        .prepare(
          `SELECT document_json FROM ${TENANT_RESOURCE_TABLE}
             WHERE resource_kind = 'tenant-accounts' AND resource_id = ?`,
        )
        .bind(id)
        .first<{ document_json: string }>();
      if (row === null) continue; // orphan row with no object document — leave NULL.
      await projectTenantAccount(controlDatabase, JSON.parse(row.document_json), nowUnix);
      mirrored += 1;
    } catch (error) {
      failed += 1;
      console.warn(`control-plane: tenant-account mirror backfill failed for ${id}`, error);
    }
  }
  return { scanned: pending.length, mirrored, failed, skipped: null };
}
