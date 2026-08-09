/**
 * The scheduled asset lifecycle sweep. The storage package owns the planner
 * and D1/R2 executor; this module owns tenant enumeration, policy selection,
 * bucket-prefix listing, audit, and gateway metrics.
 */
import {
  type BucketObject,
  D1RetentionPolicyStore,
  R2AssetBlobStore,
  RETENTION_RESOURCE_ASSET,
  RETENTION_SCOPE_DEFAULT,
  D1AssetMetadataStore as StorageD1AssetMetadataStore,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  retentionPolicyOf,
  sweepAssetRetention,
  sweepOrphanBlobs,
} from "@ferrogate/storage";
import { recordAssetLifecycleMetrics } from "../routes/metrics.js";
import { assetAuditSinkFromEnv } from "./d1.js";
import { tenantKeyPrefix } from "./keys.js";

export const DEFAULT_ASSET_RETENTION_ORPHAN_GRACE_SECS = 86400;
const ASSET_RETENTION_ORPHAN_GRACE_ENV = "ASSET_RETENTION_ORPHAN_GRACE_SECS";

function r2BucketFrom(env: unknown): R2Bucket | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const bucket = (env as { ASSETS?: unknown }).ASSETS;
  if (
    typeof bucket !== "object" ||
    bucket === null ||
    typeof (bucket as R2Bucket).list !== "function" ||
    typeof (bucket as R2Bucket).delete !== "function"
  ) {
    return undefined;
  }
  return bucket as R2Bucket;
}

function nonNegativeIntegerFromEnv(env: unknown, name: string, fallback: number): number {
  if (typeof env !== "object" || env === null) return fallback;
  const raw = (env as Record<string, unknown>)[name];
  if (typeof raw !== "string" && typeof raw !== "number") return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : fallback;
}

async function listTenantBucketObjects(bucket: R2Bucket, prefix: string): Promise<BucketObject[]> {
  const objects: BucketObject[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page =
      cursor === undefined ? await bucket.list({ prefix }) : await bucket.list({ prefix, cursor });
    for (const object of page.objects) {
      objects.push({
        key: object.key,
        lastModifiedUnix: Math.floor(object.uploaded.getTime() / 1000),
      });
    }
    if (!page.truncated || page.cursor === undefined || page.cursor === cursor) return objects;
    cursor = page.cursor;
  }
}

function recordPruneAudit(
  sink: ReturnType<typeof assetAuditSinkFromEnv>,
  tenantId: string,
  target: string,
  message: string,
  nowUnix: number,
): void {
  sink?.record({
    action: "asset.retention_prune",
    target,
    outcome: "committed",
    message,
    tenantId,
    requestId: `cron_asset_retention:${tenantId}:${nowUnix}`,
    occurredAtUnix: nowUnix,
  });
}

async function sweepTenant(
  env: Record<string, unknown>,
  router: TenantDatabaseRouter,
  bucket: R2Bucket,
  tenantId: string,
  nowUnix: number,
  orphanGraceSecs: number,
): Promise<void> {
  let scanned = 0;
  let pruned = 0;
  let failed = 0;
  let handle: TenantDatabaseHandle | undefined;
  const audit = assetAuditSinkFromEnv(env);

  try {
    handle = await router.forTenant(tenantId);
    const assets = new StorageD1AssetMetadataStore(handle);
    const blobs = new R2AssetBlobStore(bucket);
    const policies = new D1RetentionPolicyStore(handle);
    const storedPolicies = await policies.listRetentionPolicies(tenantId, RETENTION_RESOURCE_ASSET);
    const policyByScope = new Map(storedPolicies.map((policy) => [policy.scope, policy]));
    const storedAssets = await assets.listAssets(tenantId);
    const lines = new Map<string, { assetType: string; name: string }>();
    for (const asset of storedAssets) {
      const key = `${asset.assetType}\u0000${asset.name}`;
      lines.set(key, { assetType: asset.assetType, name: asset.name });
    }

    for (const line of lines.values()) {
      scanned += 1;
      const storedPolicy =
        policyByScope.get(line.assetType) ?? policyByScope.get(RETENTION_SCOPE_DEFAULT);
      if (storedPolicy === undefined) continue;
      try {
        const report = await sweepAssetRetention(
          assets,
          blobs,
          { tenantId, assetType: line.assetType, name: line.name },
          retentionPolicyOf(storedPolicy),
          nowUnix,
        );
        const deletedRows = report.deletedRowIds.length;
        const deletedObjects = report.deletedObjectKeys.length;
        pruned += deletedRows + deletedObjects;
        if (deletedRows + deletedObjects > 0) {
          recordPruneAudit(
            audit,
            tenantId,
            `${tenantId}:${line.assetType}:${line.name}`,
            `retention pruned ${deletedRows} asset rows and ${deletedObjects} objects`,
            nowUnix,
          );
        }
      } catch (error) {
        failed += 1;
        console.warn(
          `[ferrogate] asset retention sweep failed for ${tenantId}/${line.assetType}/${line.name}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }
  } catch (error) {
    failed += 1;
    console.warn(
      `[ferrogate] asset retention policy sweep failed for ${tenantId}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  if (handle !== undefined) {
    try {
      const blobs = new R2AssetBlobStore(bucket);
      const bucketObjects = await listTenantBucketObjects(bucket, tenantKeyPrefix(tenantId));
      const orphanKeys = await sweepOrphanBlobs(
        handle,
        blobs,
        bucketObjects,
        nowUnix,
        orphanGraceSecs,
      );
      pruned += orphanKeys.length;
      if (orphanKeys.length > 0) {
        recordPruneAudit(
          audit,
          tenantId,
          tenantKeyPrefix(tenantId),
          `orphan GC pruned ${orphanKeys.length} objects`,
          nowUnix,
        );
      }
    } catch (error) {
      failed += 1;
      console.warn(
        `[ferrogate] asset orphan GC failed for ${tenantId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  try {
    await audit?.flush?.();
  } catch (error) {
    failed += 1;
    console.warn(
      `[ferrogate] asset retention audit flush failed for ${tenantId}: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  recordAssetLifecycleMetrics(scanned, pruned, failed);
}

/** Sweep every provisioned tenant without allowing one tenant to stop the fleet. */
export async function sweepAssetRetentionForTenants(
  env: unknown,
  router: TenantDatabaseRouter,
  tenantIds: readonly string[],
  nowUnix = Math.floor(Date.now() / 1000),
): Promise<void> {
  const bucket = r2BucketFrom(env);
  if (bucket === undefined) {
    recordAssetLifecycleMetrics(0, 0, 1);
    console.warn("[ferrogate] asset retention sweep skipped: ASSETS R2 binding is unavailable");
    return;
  }
  const orphanGraceSecs = nonNegativeIntegerFromEnv(
    env,
    ASSET_RETENTION_ORPHAN_GRACE_ENV,
    DEFAULT_ASSET_RETENTION_ORPHAN_GRACE_SECS,
  );
  const bindings = env as Record<string, unknown>;
  for (const tenantId of tenantIds) {
    if (tenantId.trim() === "") continue;
    try {
      await sweepTenant(bindings, router, bucket, tenantId, nowUnix, orphanGraceSecs);
    } catch (error) {
      // The tenant helper is defensive as well; this guard protects the fleet
      // loop if a future change throws outside one of its local stages.
      recordAssetLifecycleMetrics(0, 0, 1);
      console.warn(
        `[ferrogate] asset lifecycle sweep aborted for ${tenantId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}
