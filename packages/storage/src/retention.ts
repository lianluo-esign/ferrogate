/**
 * Asset-version retention + unreferenced-blob GC, and flat operational-log
 * retention (ports `ferrogate-storage::asset_lifecycle`, issues #263/#284).
 *
 * This is the pure, side-effect-free planning core the sweeper applies. The whole
 * engine is FAIL-SAFE: on ANY doubt it KEEPS. Retention never prunes a
 * channel-pinned version or one inside the grace window; GC never deletes a blob a
 * row references, one whose age is unknown, or one inside the grace window.
 *
 * PORT-TODO(P: inventory-data-billing §1.4.6 `retention_policies`) — SHARPENED, and
 * now only ONE leg wide: the CRON TRIGGER.
 *
 * CLOSED in this package: the STORAGE and the EXECUTOR both exist in
 * {@link ./d1/retention-d1.js} — `D1RetentionPolicyStore` reads/writes the
 * `retention_policies` table (Rust `set_retention_limits`), `sweepAssetRetention`
 * feeds {@link planVersionRetention} from real rows and applies the plan
 * ROW-BEFORE-OBJECT, and `sweepOrphanBlobs` feeds {@link planBlobGc} from the
 * live `storage_uri` set. `test/d1/retention-d1.test.ts` pins the delete order
 * and the channel-pin protection.
 *
 * STILL OPEN, and NOT CLOSABLE FROM A LIBRARY PACKAGE: nothing CALLS the sweeper
 * on a schedule. A `packages/*` library has no Worker entry module, no
 * `wrangler.toml`, and therefore no `[triggers] crons` — the schedule can only
 * be declared on a deployable. `apps/gateway/src/worker.ts` already exposes a
 * `scheduled` handler for the billing outbox and is where this hangs off; the
 * exact seam is `sweepAssetRetention(assets, blobs, line, retentionPolicyOf(p),
 * nowUnix)` per policy returned by `listRetentionPolicies`. Until that edit
 * lands, `request_logs`, `audit_events`, `agent_run_events` and R2 asset blobs
 * still grow without bound in a deployed environment, because a sweeper nobody
 * invokes prunes nothing.
 *
 * Also still open and deliberately so: {@link planLogRetention} has no D1
 * executor here. `request_logs` / `audit_events` are CONTROL-database tables and
 * this module's executor is tenant-scoped; deleting from the control database on
 * a tenant's rule is a cross-scope decision that belongs to the control plane,
 * not to a per-tenant sweep.
 */
import type { StoredAsset, StoredAssetChannel } from "./assets.js";

export const RETENTION_RESOURCE_ASSET = "asset";
export const RETENTION_RESOURCE_REQUEST_LOG = "request_logs";
export const RETENTION_RESOURCE_AUDIT_EVENT = "audit_events";
export const RETENTION_SCOPE_DEFAULT = "*";
export const RETENTION_SCOPE_RESPONSE_BODY = "response_body";

/** A durable, generalizable retention rule (#263). */
export interface StoredRetentionPolicy {
  id: string;
  tenantId: string;
  resourceType: string;
  scope: string;
  keepLastN?: number;
  maxAgeSecs?: number;
  minAgeSecs: number;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** The evaluated rule (identity/audit columns stripped). */
export interface RetentionPolicy {
  keepLastN?: number;
  maxAgeSecs?: number;
  minAgeSecs: number;
}

/** Project a stored policy to the evaluated rule (clamps `minAgeSecs` at 0). */
export function retentionPolicyOf(stored: StoredRetentionPolicy): RetentionPolicy {
  return {
    keepLastN: stored.keepLastN,
    maxAgeSecs: stored.maxAgeSecs,
    minAgeSecs: Math.max(stored.minAgeSecs, 0),
  };
}

/** A rule with neither size nor age dimension is inert — the sweeper skips it. */
export function retentionPolicyIsNoop(policy: RetentionPolicy): boolean {
  return policy.keepLastN === undefined && policy.maxAgeSecs === undefined;
}

/** One row selected for pruning, with what the sweeper needs to delete + reconcile. */
export interface RetentionPruneTarget {
  id: string;
  version: string;
  variant: string;
  storageUri?: string;
  sizeBytes: number;
}

export interface RetentionPlan {
  targets: RetentionPruneTarget[];
  freedBytes: number;
}

/**
 * Decide which versions of ONE `{tenant, asset_type, name}` line to prune. A
 * version is retained if ANY hold: channel-pinned; younger than the grace window;
 * within the newest `keepLastN`; or younger than `maxAgeSecs`. Recency is by
 * newest `createdAtUnix` across a version's variant rows.
 */
export function planVersionRetention(
  assets: readonly StoredAsset[],
  pinnedVersionSet: ReadonlySet<string>,
  now: number,
  policy: RetentionPolicy,
): RetentionPlan {
  if (retentionPolicyIsNoop(policy) || assets.length === 0) {
    return { targets: [], freedBytes: 0 };
  }

  const newestCreated = new Map<string, number>();
  for (const asset of assets) {
    const prev = newestCreated.get(asset.version) ?? Number.MIN_SAFE_INTEGER;
    newestCreated.set(asset.version, Math.max(prev, asset.createdAtUnix));
  }

  // Newest first (created desc, then version string desc as a stable tiebreak).
  const versions = [...newestCreated.entries()].sort(
    (a, b) => b[1] - a[1] || (b[0] < a[0] ? -1 : b[0] > a[0] ? 1 : 0),
  );

  const keepLastN = policy.keepLastN;
  const pruneVersions = new Set<string>();
  versions.forEach(([version, created], index) => {
    const age = Math.max(now - created, 0);
    if (age < policy.minAgeSecs) return; // grace window
    if (pinnedVersionSet.has(version)) return; // channel-pinned
    if (keepLastN !== undefined && index < keepLastN) return; // within newest N
    if (policy.maxAgeSecs !== undefined && age <= policy.maxAgeSecs) return; // within max-age
    const beyondKeep = keepLastN !== undefined && index >= keepLastN;
    const olderThanMax = policy.maxAgeSecs !== undefined && age > policy.maxAgeSecs;
    if (beyondKeep || olderThanMax) pruneVersions.add(version);
  });

  const plan: RetentionPlan = { targets: [], freedBytes: 0 };
  for (const asset of assets) {
    if (pruneVersions.has(asset.version)) {
      plan.freedBytes += asset.sizeBytes;
      plan.targets.push({
        id: asset.id,
        version: asset.version,
        variant: asset.variant,
        storageUri: asset.storageUri,
        sizeBytes: asset.sizeBytes,
      });
    }
  }
  return plan;
}

/** One flat operational-log row considered for retention (#284). */
export interface LogRetentionCandidate {
  id: string;
  createdAtUnix: number;
}

/**
 * Decide which flat log rows to prune for ONE tenant (#284). Same fail-safe rules
 * as {@link planVersionRetention} minus channel pins; `minAgeSecs` is the
 * compliance legal floor. Returns the ids to delete.
 */
export function planLogRetention(
  candidates: readonly LogRetentionCandidate[],
  now: number,
  policy: RetentionPolicy,
): string[] {
  if (retentionPolicyIsNoop(policy) || candidates.length === 0) return [];
  const ordered = [...candidates].sort(
    (a, b) => b.createdAtUnix - a.createdAtUnix || (b.id < a.id ? -1 : b.id > a.id ? 1 : 0),
  );
  const keepLastN = policy.keepLastN;
  const prune: string[] = [];
  ordered.forEach((candidate, index) => {
    const age = Math.max(now - candidate.createdAtUnix, 0);
    if (age < policy.minAgeSecs) return;
    if (keepLastN !== undefined && index < keepLastN) return;
    if (policy.maxAgeSecs !== undefined && age <= policy.maxAgeSecs) return;
    const beyondKeep = keepLastN !== undefined && index >= keepLastN;
    const olderThanMax = policy.maxAgeSecs !== undefined && age > policy.maxAgeSecs;
    if (beyondKeep || olderThanMax) prune.push(candidate.id);
  });
  return prune;
}

/** The versions any channel points at, for one asset line's channel rows. */
export function pinnedVersions(channels: readonly StoredAssetChannel[]): Set<string> {
  return new Set(channels.map((c) => c.version));
}

/** A bucket object observed during GC; `lastModifiedUnix <= 0` means unknown ⇒ KEEP. */
export interface BucketObject {
  key: string;
  lastModifiedUnix: number;
}

/**
 * Plan the unreferenced-blob GC. An object is an orphan to delete ONLY when: no
 * row references its key; its age is known (`> 0`); and it is older than
 * `graceSecs`. Anything failing any check is KEPT. Returned keys are sorted+deduped.
 */
export function planBlobGc(
  bucketObjects: readonly BucketObject[],
  referencedKeys: ReadonlySet<string>,
  now: number,
  graceSecs: number,
): string[] {
  const grace = Math.max(graceSecs, 0);
  const orphans = bucketObjects
    .filter((o) => !referencedKeys.has(o.key))
    .filter((o) => o.lastModifiedUnix > 0)
    .filter((o) => Math.max(now - o.lastModifiedUnix, 0) >= grace)
    .map((o) => o.key);
  return [...new Set(orphans)].sort();
}
