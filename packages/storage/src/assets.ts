/**
 * Static assets: trust-screening visibility, the atomic storage-quota admission
 * classifier, channel pointers, and the `pending_scan → visible|quarantined`
 * promotion CAS (ports the asset surface from `ferrogate-storage::lib`, issues
 * #176/#260/#366/#371/#378).
 */
import { StorageError } from "./errors.js";

/**
 * Trust-screening visibility (#366). An unrecognized token fails CLOSED to
 * `quarantined` — an unknown/poisoned/partially-migrated row must never be served.
 */
export type AssetVisibility = "visible" | "pending_scan" | "quarantined";

/** Parse the TEXT column; unknown ⇒ `quarantined` (fail-closed, ports `from_stored`). */
export function assetVisibilityFromStored(raw: string): AssetVisibility {
  if (raw === "visible") return "visible";
  if (raw === "pending_scan") return "pending_scan";
  return "quarantined";
}

/** Only `visible` is downloadable. */
export function assetVisibilityIsDownloadable(v: AssetVisibility): boolean {
  return v === "visible";
}

/** A tenant-scoped static asset row. `content` bytes are inline unless `storageUri` is set. */
export interface StoredAsset {
  id: string;
  tenantId: string;
  projectId?: string;
  assetType: string;
  name: string;
  version: string;
  contentType: string;
  contentHash: string;
  sizeBytes: number;
  /** Inline bytes; empty when `storageUri` holds the real object key. */
  content: Uint8Array;
  storageUri?: string;
  /** Platform/arch variant; empty is the default artifact. Part of the row identity. */
  variant: string;
  yanked: boolean;
  visibility: AssetVisibility;
  createdAtUnix: number;
  updatedAtUnix: number;
}

/** Whether an asset may be resolved/served right now (#366). */
export function assetIsDownloadable(asset: StoredAsset): boolean {
  return assetVisibilityIsDownloadable(asset.visibility);
}

/** A mutable channel pointer (`latest`/`stable`/`canary`/tag) → concrete version (#260). */
export interface StoredAssetChannel {
  id: string;
  tenantId: string;
  assetType: string;
  name: string;
  channel: string;
  version: string;
  updatedAtUnix: number;
}

/** Definitive outcome of an atomic asset-storage quota admission (#371). */
export type AssetQuotaAdmission =
  | { kind: "admitted" }
  | { kind: "already_exists" }
  | { kind: "over_quota"; usedBytes: number; attemptedBytes: number; quotaBytes: number };

/**
 * The single shared admission classifier (ports `classify_asset_quota_admission`)
 * so the backends' truth tables cannot drift. Precedence: an `admitted` insert
 * wins; then an existing id (or a passed quota guard that still didn't insert — a
 * same-id race) is `already_exists`; only a non-existing id whose quota guard
 * FAILED is a definitive `over_quota`.
 */
export function classifyAssetQuotaAdmission(
  inserted: boolean,
  idExists: boolean,
  quotaOk: boolean,
  usedBytes: number,
  attemptedBytes: number,
  quotaBytes: number | undefined,
): AssetQuotaAdmission {
  if (inserted) return { kind: "admitted" };
  if (idExists || quotaOk) return { kind: "already_exists" };
  return {
    kind: "over_quota",
    usedBytes,
    attemptedBytes,
    quotaBytes: quotaBytes ?? Number.MAX_SAFE_INTEGER,
  };
}

/** Terminal target of a scan promotion. */
export type AssetPromotionTarget = "visible" | "quarantined";

/** The durable visibility a promotion target resolves to. */
export function assetPromotionTargetVisibility(target: AssetPromotionTarget): AssetVisibility {
  return target;
}

/** Outcome of the `pending_scan → visible|quarantined` promotion CAS (#378). */
export type AssetVisibilityPromotionOutcome =
  | { kind: "promoted"; to: AssetVisibility }
  | { kind: "not_found" }
  | { kind: "not_pending"; current: AssetVisibility };

/**
 * Pure promotion CAS decision against one asset's current visibility (mirrors the
 * memory backend's `promote_asset_visibility`). The flip is valid ONLY from
 * `pending_scan`; a missing row is `not_found`, a terminal row is `not_pending`
 * (fail-closed — never silently re-promoted).
 */
export function promoteAssetVisibility(
  current: AssetVisibility | undefined,
  target: AssetPromotionTarget,
): AssetVisibilityPromotionOutcome {
  if (current === undefined) return { kind: "not_found" };
  if (current !== "pending_scan") return { kind: "not_pending", current };
  return { kind: "promoted", to: assetPromotionTargetVisibility(target) };
}

/**
 * Outcome of the atomic channel-move coordination mutation (#367).
 *
 * CLOSED — former marker inventory-data-billing §1.4.6 `asset_channels` + §1.2
 * `move_asset_channel_if_resolvable` / `set_asset_version_yank` /
 * `list_withheld_assets` / `delete_asset_channel`. The producer is
 * {@link ./d1/assets-d1.js D1AssetMetadataStore}, the durable metadata twin on a
 * tenant handle. It writes `stored_assets` AND `asset_channels`, and carries the
 * two guards this type exists to express:
 *
 *   - the move resolves the target version and writes the pointer in ONE
 *     `INSERT ... SELECT ... WHERE EXISTS(version) AND NOT EXISTS(yanked variant)
 *     ON CONFLICT (id) DO UPDATE RETURNING` — an empty `RETURNING` set IS
 *     `target_not_resolvable`;
 *   - the yank refuses while a channel still points at the version
 *     ({@link VersionYankOutcome}), closing the same write-skew from the other
 *     side.
 *
 * Before it, `latest`/`stable`/`canary` were resolved at pull time from rows
 * that never persisted, so a published asset was unresolvable on the next
 * request and the yank flag — the kill switch for a bad artifact — could not
 * survive a deploy. {@link ./d1/assets-r2.js R2AssetBlobStore} holds the bytes
 * half; this is the metadata half.
 *
 * STILL OPEN, and OUT OF THIS PACKAGE'S SCOPE: `apps/gateway/src/assets/ports.ts`
 * declares its own `AssetMetadataStore` interface whose only implementation is
 * still `InMemoryAssetMetadataStore`. Constructing a `D1AssetMetadataStore` on
 * the request-path tenant handle and mounting it there is an `apps/gateway`
 * edit; until it lands, the durable store exists but the deployed pull path
 * still resolves channels from an isolate-local map.
 */
export type ChannelMoveOutcome =
  | { kind: "moved"; priorVersion?: string }
  | { kind: "target_not_resolvable" };

/**
 * Outcome of the guarded yank/unyank of every variant row of one version (#367).
 *
 * `referenced_by_channel` is a REFUSAL, not a warning: yanking a version a
 * channel still resolves to would strand that channel on an artifact the
 * operator has just declared unusable, so every subsequent pull would serve the
 * thing being withdrawn. The operator must move the channel first. An UNyank is
 * always safe and never takes this arm — it can only ever make more artifacts
 * resolvable.
 */
export type VersionYankOutcome =
  | { kind: "applied"; variants: number }
  | { kind: "not_found" }
  | { kind: "referenced_by_channel" };

/**
 * Small in-memory asset registry capturing the identity/visibility/channel logic.
 * The quota-admission and yank/channel-move guards run under one serialization
 * point here, mirroring the durable backends' single-statement/locked guards.
 *
 * The R2 move IS ported — see `./d1/assets-r2.js`: `R2AssetBlobStore` holds the
 * artifact bytes and `commitAssetWithBlob` runs the object-then-row commit
 * protocol that the absence of an R2↔D1 transaction forces. This reference
 * store keeps `content` inline ON PURPOSE, because it is the synchronous
 * in-memory twin of the durable pair and holding bytes is how it stays a
 * single-serialization-point specification of the admission guard. It is not
 * the deployed path.
 */
export class MemoryAssetStore {
  private readonly assets = new Map<string, StoredAsset>();

  upsertAsset(asset: StoredAsset): void {
    this.assets.set(asset.id, { ...asset, content: new Uint8Array(asset.content) });
  }

  getAsset(id: string): StoredAsset | undefined {
    const a = this.assets.get(id);
    return a ? { ...a, content: new Uint8Array(a.content) } : undefined;
  }

  deleteAsset(id: string): boolean {
    return this.assets.delete(id);
  }

  /** Cumulative bytes used by one tenant's rows — the live SUM the quota guards. */
  tenantAssetStorageBytesUsed(tenantId: string): number {
    let used = 0;
    for (const a of this.assets.values()) if (a.tenantId === tenantId) used += a.sizeBytes;
    return used;
  }

  /**
   * Atomic create-within-quota (ports `create_asset_within_quota` via the shared
   * classifier): folds the usage read, the quota guard, and the create-if-absent
   * guard into one decision so two different-id commits can't jointly overshoot.
   */
  createAssetWithinQuota(asset: StoredAsset, quotaBytes: number | undefined): AssetQuotaAdmission {
    const idExists = this.assets.has(asset.id);
    if (idExists) return classifyAssetQuotaAdmission(false, true, false, 0, 0, quotaBytes);
    const usedBytes = this.tenantAssetStorageBytesUsed(asset.tenantId);
    const attemptedBytes = asset.sizeBytes;
    const quotaOk = quotaBytes === undefined || usedBytes + attemptedBytes <= quotaBytes;
    if (!quotaOk) {
      return classifyAssetQuotaAdmission(
        false,
        false,
        false,
        usedBytes,
        attemptedBytes,
        quotaBytes,
      );
    }
    this.upsertAsset(asset);
    return classifyAssetQuotaAdmission(true, false, true, usedBytes, attemptedBytes, quotaBytes);
  }

  /** Promote a `pending_scan` row; durable only when the CAS decision says `promoted`. */
  promoteAssetVisibility(
    id: string,
    target: AssetPromotionTarget,
    nowUnix: number,
  ): AssetVisibilityPromotionOutcome {
    const asset = this.assets.get(id);
    const outcome = promoteAssetVisibility(asset?.visibility, target);
    if (outcome.kind === "promoted" && asset) {
      asset.visibility = outcome.to;
      asset.updatedAtUnix = nowUnix;
    }
    return outcome;
  }
}
