/**
 * `D1RetentionPolicyStore` + `sweepAssetRetention` — the storage and the
 * EXECUTOR for `../retention.ts` (issues #263/#284), on a tenant handle.
 *
 * The planners in `../retention.ts` were already ported, pure and tested; what
 * was missing was that nothing read or wrote `retention_policies` and nothing
 * ever CALLED a planner, so request evidence and R2 asset blobs were append-only
 * forever and a retention contract an operator configured had no effect. The
 * #859 gateway sweep now owns request-log cleanup at the composition root: it
 * deletes the tenant-object authority first and the derived control projection
 * second. This tenant-handle executor remains responsible for asset retention.
 *
 * ## The order of operations is the safety property
 *
 * {@link sweepAssetRetention} deletes the D1 ROW first and the R2 OBJECT second,
 * which is the exact reverse of the publish protocol in `./assets-r2.ts` — and
 * deliberately so. There is no transaction spanning R2 and D1, so one of the two
 * crash windows has to be chosen:
 *
 *   - row first ⇒ a crash leaves an ORPHAN OBJECT. Costs storage; nothing can
 *     name it, so nothing serves it; the next `planBlobGc` sweep reclaims it.
 *   - object first ⇒ a crash leaves a LIVE ROW pointing at bytes that are gone.
 *     Every pull on a published name 404s until someone notices.
 *
 * The first is recoverable and invisible; the second is a published outage. Row
 * first, always.
 *
 * ## Channel pins are re-read, never trusted from the caller
 *
 * The sweep reads the line's `asset_channels` rows itself and feeds them to
 * {@link ../retention.js pinnedVersions}. A caller-supplied pin set is exactly
 * the input that, if stale by one publish, deletes the version `latest` has just
 * been moved onto. The planner is fail-safe on every dimension it can see; the
 * executor's job is to not hand it a lie.
 *
 * ## What is NOT here
 *
 * The `[triggers] crons` handler that CALLS this on a schedule lives on a
 * Worker's composition root (`apps/gateway/src/worker.ts` already exposes a
 * `scheduled` handler for the billing outbox). A `packages/*` library has no
 * entry module and cannot mount itself — see the note on `../retention.ts`.
 */
import { retentionPolicyId } from "../ids.js";
import {
  type BucketObject,
  type RetentionPlan,
  type RetentionPolicy,
  type StoredRetentionPolicy,
  pinnedVersions,
  planBlobGc,
  planVersionRetention,
  retentionPolicyOf,
} from "../retention.js";
import type { TenantDatabaseHandle } from "../tenant-router.js";
import type { D1AssetMetadataStore } from "./assets-d1.js";
import type { R2AssetBlobStore } from "./assets-r2.js";
import { bindOptional, d1Error, optionalNumber } from "./rows.js";

/** The projection order shared by every `retention_policies` read. */
export const RETENTION_POLICY_COLUMNS =
  "id, tenant_id, resource_type, scope, keep_last_n, max_age_secs, min_age_secs, " +
  "created_at_unix, updated_at_unix";

interface RetentionPolicyRow {
  id: string;
  tenant_id: string;
  resource_type: string;
  scope: string;
  keep_last_n: number | null;
  max_age_secs: number | null;
  min_age_secs: number;
  created_at_unix: number;
  updated_at_unix: number;
}

function intoStored(row: RetentionPolicyRow): StoredRetentionPolicy {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    resourceType: row.resource_type,
    scope: row.scope,
    keepLastN: optionalNumber(row.keep_last_n),
    maxAgeSecs: optionalNumber(row.max_age_secs),
    minAgeSecs: Number(row.min_age_secs),
    createdAtUnix: Number(row.created_at_unix),
    updatedAtUnix: Number(row.updated_at_unix),
  };
}

function changes(result: D1Response): number {
  const meta = result.meta as { changes?: number } | undefined;
  return meta?.changes ?? 0;
}

/** The durable `retention_policies` store (Rust `set_retention_limits` + reads). */
export class D1RetentionPolicyStore {
  private readonly db: D1Database;

  constructor(handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  /**
   * Create or replace the rule for one `(tenant, resourceType, scope)`.
   *
   * The id is the deterministic `{tenant}:{resource_type}:{scope}`
   * ({@link ../ids.js retentionPolicyId}), so setting the same triple twice
   * REPLACES rather than accumulating a second contradictory rule that a sweep
   * would then have to break a tie between.
   *
   * `createdAtUnix` is preserved across a replace (`DO UPDATE` does not touch
   * it), so "when did this tenant first configure retention" survives edits.
   */
  async setRetentionPolicy(policy: StoredRetentionPolicy): Promise<void> {
    try {
      await this.db
        .prepare(
          `INSERT INTO retention_policies (${RETENTION_POLICY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET keep_last_n = excluded.keep_last_n, max_age_secs = excluded.max_age_secs, min_age_secs = excluded.min_age_secs, updated_at_unix = excluded.updated_at_unix`,
        )
        .bind(
          retentionPolicyId(policy.tenantId, policy.resourceType, policy.scope),
          policy.tenantId,
          policy.resourceType,
          policy.scope,
          bindOptional(policy.keepLastN),
          bindOptional(policy.maxAgeSecs),
          policy.minAgeSecs,
          policy.createdAtUnix,
          policy.updatedAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("set_retention_policy", error);
    }
  }

  /** The rule for one `(tenant, resourceType, scope)`, or `undefined`. */
  async getRetentionPolicy(
    tenantId: string,
    resourceType: string,
    scope: string,
  ): Promise<StoredRetentionPolicy | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${RETENTION_POLICY_COLUMNS} FROM retention_policies WHERE id = ?`)
        .bind(retentionPolicyId(tenantId, resourceType, scope))
        .first<RetentionPolicyRow>();
      return row === null ? undefined : intoStored(row);
    } catch (error) {
      throw d1Error("get_retention_policy", error);
    }
  }

  /** One tenant's rules, optionally one `resourceType`, ordered like Postgres. */
  async listRetentionPolicies(
    tenantId: string,
    resourceType?: string,
  ): Promise<StoredRetentionPolicy[]> {
    try {
      const statement =
        resourceType === undefined
          ? this.db
              .prepare(
                `SELECT ${RETENTION_POLICY_COLUMNS} FROM retention_policies WHERE tenant_id = ? ORDER BY resource_type ASC, scope ASC`,
              )
              .bind(tenantId)
          : this.db
              .prepare(
                `SELECT ${RETENTION_POLICY_COLUMNS} FROM retention_policies WHERE tenant_id = ? AND resource_type = ? ORDER BY scope ASC`,
              )
              .bind(tenantId, resourceType);
      const rows = await statement.all<RetentionPolicyRow>();
      return rows.results.map(intoStored);
    } catch (error) {
      throw d1Error("list_retention_policies", error);
    }
  }

  /** Drop one rule; `true` when a row was removed. */
  async deleteRetentionPolicy(
    tenantId: string,
    resourceType: string,
    scope: string,
  ): Promise<boolean> {
    try {
      const result = await this.db
        .prepare("DELETE FROM retention_policies WHERE id = ?")
        .bind(retentionPolicyId(tenantId, resourceType, scope))
        .run();
      return changes(result) > 0;
    } catch (error) {
      throw d1Error("delete_retention_policy", error);
    }
  }
}

/** What one asset-line sweep actually did. */
export interface RetentionSweepReport {
  /** The plan the planner produced, verbatim — including an empty one. */
  plan: RetentionPlan;
  /** `stored_assets.id`s whose row was deleted. */
  deletedRowIds: string[];
  /** R2 keys deleted after their row was gone. */
  deletedObjectKeys: string[];
}

/**
 * Apply {@link ../retention.js planVersionRetention} to ONE
 * `{tenant, assetType, name}` line and execute the plan.
 *
 * Returns the plan alongside what was deleted so a caller can log the two and
 * notice a divergence (a target the delete refused). `dryRun` produces the plan
 * and deletes nothing, which is how an operator inspects a rule before arming it
 * — a retention sweep is unrecoverable, so being able to see it first is not a
 * luxury.
 */
export async function sweepAssetRetention(
  assets: D1AssetMetadataStore,
  blobs: R2AssetBlobStore | undefined,
  target: { tenantId: string; assetType: string; name: string },
  policy: RetentionPolicy,
  nowUnix: number,
  options: { dryRun?: boolean } = {},
): Promise<RetentionSweepReport> {
  const all = await assets.listAssets(target.tenantId, target.assetType);
  const line = all.filter((asset) => asset.name === target.name);
  // Re-read the pins rather than trusting a caller: a pin set stale by one
  // publish is exactly what deletes the version `latest` was just moved onto.
  const channels = await assets.listAssetChannels(target.tenantId, target.assetType, target.name);
  const plan = planVersionRetention(line, pinnedVersions(channels), nowUnix, policy);
  if (options.dryRun === true) {
    return { plan, deletedRowIds: [], deletedObjectKeys: [] };
  }

  const deletedRowIds: string[] = [];
  const deletedObjectKeys: string[] = [];
  for (const pruneTarget of plan.targets) {
    // ROW FIRST. A crash here leaves an orphan object, which is invisible and
    // reclaimable; the reverse order leaves a live row pointing at bytes that
    // are gone, which 404s a published name.
    const removed = await assets.deleteAsset(pruneTarget.id);
    if (!removed) continue;
    deletedRowIds.push(pruneTarget.id);
    if (blobs !== undefined && pruneTarget.storageUri !== undefined) {
      await blobs.delete(pruneTarget.storageUri);
      deletedObjectKeys.push(pruneTarget.storageUri);
    }
  }
  return { plan, deletedRowIds, deletedObjectKeys };
}

/**
 * Apply {@link ../retention.js planBlobGc} over one R2 prefix, using the LIVE
 * `storage_uri` set read from D1 as the reference set.
 *
 * The live set is read AFTER the bucket listing on purpose. Reading it first
 * would mean an asset published during the listing has a row the GC never saw,
 * and its freshly written object would look like an orphan; reading it after
 * makes the reference set a superset of what the listing could contain, so a
 * concurrent publish is protected. (`graceSecs` is the second, independent
 * defense: an object younger than the grace window is kept regardless.)
 */
export async function sweepOrphanBlobs(
  handle: TenantDatabaseHandle,
  blobs: R2AssetBlobStore,
  bucketObjects: readonly BucketObject[],
  nowUnix: number,
  graceSecs: number,
): Promise<string[]> {
  let referenced: ReadonlySet<string>;
  try {
    const rows = await handle.db
      .prepare("SELECT storage_uri FROM stored_assets WHERE storage_uri IS NOT NULL")
      .all<{ storage_uri: string }>();
    referenced = new Set(rows.results.map((row) => row.storage_uri));
  } catch (error) {
    throw d1Error("list_referenced_storage_uris", error);
  }
  const orphans = planBlobGc(bucketObjects, referenced, nowUnix, graceSecs);
  for (const key of orphans) await blobs.delete(key);
  return orphans;
}

/** Project a stored rule to the evaluated one the planners take. */
export { retentionPolicyOf };
