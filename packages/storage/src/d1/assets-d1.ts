/**
 * `D1AssetMetadataStore` — the durable metadata twin of `../assets.ts`
 * (issues #176/#260/#366/#367/#371/#378), on a tenant handle.
 *
 * `stored_assets` and `asset_channels` are both TENANT-database tables, so every
 * guard below and every subquery it reads are in ONE database and the atomicity
 * is genuine. Contrast `./usage-d1.ts`, whose claim/accumulate pair straddles
 * control and tenant and therefore cannot be one commit on this platform.
 *
 * ## The three guards, and why each is one statement
 *
 * 1. **Quota admission** (`createAssetWithinQuota`). The usage SUM, the quota
 *    comparison and the insert are one `INSERT ... SELECT ... WHERE <quota>`
 *    with `ON CONFLICT DO NOTHING RETURNING`. Reading the SUM and then
 *    inserting would let two different-id pushes each observe the pre-state and
 *    jointly overshoot the tenant's byte quota. A pre-state read still runs, but
 *    ONLY to LABEL the outcome (`already_exists` vs `over_quota`) — never to
 *    decide it. {@link ../assets.js classifyAssetQuotaAdmission} is the one
 *    shared truth table, so this backend and `MemoryAssetStore` cannot drift.
 *
 * 2. **Channel move** (`moveAssetChannelIfResolvable`, #367). Resolving the
 *    target version and writing the pointer are one statement:
 *    `WHERE EXISTS(<version present>) AND NOT EXISTS(<yanked variant>)`. An
 *    empty `RETURNING` set means the target was not resolvable AT COMMIT TIME.
 *    A resolve-then-write would let a concurrent yank or variant delete land in
 *    the window and strand `latest` on bytes that no longer exist — a 404 on a
 *    name the operator believes is published.
 *
 * 3. **Yank** (`setAssetVersionYank`, #367). The mirror image: the yank applies
 *    only while NO channel points at the version. Together, 2 and 3 close the
 *    write skew from both sides — 2 cannot move onto a yanked version, 3 cannot
 *    yank a version a channel names, and neither can be defeated by interleaving
 *    because in both cases the check and the write are the same statement.
 *
 * ## Why the pre-state reads are in the same `batch()`
 *
 * The labelling reads for 1 and 3 are submitted in the SAME `batch()` as their
 * guard, not before it. A separate read would observe a DIFFERENT snapshot from
 * the one the guard evaluated, so the label could contradict the decision (e.g.
 * report `not_found` for a version another isolate had just created and the
 * guard had just yanked). Inside one batch they are one transaction, so the
 * label describes the state the guard actually acted on.
 *
 * That is also why these operations require `supportsAtomicBatch`: on a REST
 * handle `batch()` is neither one transaction nor able to return `RETURNING`
 * rows, and a guard whose verdict is read from an empty `RETURNING` set would
 * silently read "refused" for every call.
 */
import {
  type AssetPromotionTarget,
  type AssetQuotaAdmission,
  type AssetVisibility,
  type AssetVisibilityPromotionOutcome,
  type ChannelMoveOutcome,
  type StoredAsset,
  type StoredAssetChannel,
  type VersionYankOutcome,
  assetVisibilityFromStored,
  classifyAssetQuotaAdmission,
  promoteAssetVisibility,
} from "../assets.js";
import { StorageError } from "../errors.js";
import { type TenantDatabaseHandle, requireAtomicBatch } from "../tenant-router.js";
import { bindOptional, boolFromSqlite, boolToSqlite, d1Error, optionalText } from "./rows.js";

/**
 * The projection order shared by every `stored_assets` read.
 *
 * `content` is deliberately absent: this rewrite moved the artifact bytes to R2
 * (see `./assets-r2.ts`), so the row carries `content_hash` / `size_bytes` /
 * `storage_uri` only. Every guard here reads exactly those and never the bytes.
 */
export const STORED_ASSET_COLUMNS =
  "id, tenant_id, project_id, asset_type, name, version, content_type, content_hash, " +
  "size_bytes, created_at_unix, updated_at_unix, storage_uri, variant, yanked, visibility";

/** The projection order shared by every `asset_channels` read. */
export const ASSET_CHANNEL_COLUMNS =
  "id, tenant_id, asset_type, name, channel, version, updated_at_unix";

/**
 * The guarded resolvable channel upsert (#367). Exported so the mutation proof
 * in `test/d1/assets-d1.test.ts` can assert the two guard clauses are present in
 * the SQL the store actually runs — an outcome-only test would still pass
 * against a resolve-then-write.
 */
export const MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL = `INSERT INTO asset_channels (${ASSET_CHANNEL_COLUMNS}) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS(SELECT 1 FROM stored_assets              WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?)   AND NOT EXISTS(SELECT 1 FROM stored_assets                  WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?                    AND yanked = 1) ON CONFLICT (id) DO UPDATE SET version = excluded.version, updated_at_unix = excluded.updated_at_unix RETURNING version`;

/**
 * The guarded yank/unyank. The `? = 0` term short-circuits the channel-reference
 * guard for an UNyank, which is always safe: making an artifact resolvable again
 * can never strand a pointer.
 */
export const SET_ASSET_VERSION_YANK_SQL =
  "UPDATE stored_assets SET yanked = ?, updated_at_unix = ? " +
  "WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? " +
  "  AND (? = 0 OR NOT EXISTS(SELECT 1 FROM asset_channels " +
  "       WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?)) " +
  "RETURNING id";

/** The guarded quota-admitting insert (#371). `?` = '' means unlimited. */
export const CREATE_ASSET_WITHIN_QUOTA_SQL = `INSERT INTO stored_assets (${STORED_ASSET_COLUMNS}) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE (? = '' OR        COALESCE((SELECT SUM(size_bytes) FROM stored_assets WHERE tenant_id = ?), 0)          + ? <= ?) ON CONFLICT DO NOTHING RETURNING 1 AS inserted`;

/** The visibility promotion CAS (#378): the `pending_scan` predicate is IN the write. */
export const PROMOTE_ASSET_VISIBILITY_SQL =
  "UPDATE stored_assets SET visibility = ?, updated_at_unix = ? " +
  "WHERE id = ? AND visibility = 'pending_scan' " +
  "RETURNING id";

interface StoredAssetRow {
  id: string;
  tenant_id: string;
  project_id: string | null;
  asset_type: string;
  name: string;
  version: string;
  content_type: string;
  content_hash: string;
  size_bytes: number;
  created_at_unix: number;
  updated_at_unix: number;
  storage_uri: string | null;
  variant: string;
  yanked: number;
  visibility: string;
}

function intoStoredAsset(row: StoredAssetRow): StoredAsset {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    projectId: optionalText(row.project_id),
    assetType: row.asset_type,
    name: row.name,
    version: row.version,
    contentType: row.content_type,
    contentHash: row.content_hash,
    sizeBytes: Number(row.size_bytes),
    // The bytes live in R2 under `storage_uri`; the row never carries them.
    content: new Uint8Array(0),
    storageUri: optionalText(row.storage_uri),
    variant: row.variant,
    yanked: boolFromSqlite(row.yanked),
    // Unknown token ⇒ `quarantined`, never a servable default (#366).
    visibility: assetVisibilityFromStored(row.visibility),
    createdAtUnix: Number(row.created_at_unix),
    updatedAtUnix: Number(row.updated_at_unix),
  };
}

interface AssetChannelRow {
  id: string;
  tenant_id: string;
  asset_type: string;
  name: string;
  channel: string;
  version: string;
  updated_at_unix: number;
}

function intoStoredChannel(row: AssetChannelRow): StoredAssetChannel {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    assetType: row.asset_type,
    name: row.name,
    channel: row.channel,
    version: row.version,
    updatedAtUnix: Number(row.updated_at_unix),
  };
}

function changes(result: D1Response): number {
  const meta = result.meta as { changes?: number } | undefined;
  return meta?.changes ?? 0;
}

/** The 15 positional binds of {@link STORED_ASSET_COLUMNS}, in that exact order. */
function assetInsertBinds(asset: StoredAsset): unknown[] {
  return [
    asset.id,
    asset.tenantId,
    bindOptional(asset.projectId),
    asset.assetType,
    asset.name,
    asset.version,
    asset.contentType,
    asset.contentHash,
    asset.sizeBytes,
    asset.createdAtUnix,
    asset.updatedAtUnix,
    bindOptional(asset.storageUri),
    asset.variant,
    boolToSqlite(asset.yanked),
    asset.visibility,
  ];
}

export class D1AssetMetadataStore {
  private readonly db: D1Database;

  constructor(private readonly handle: TenantDatabaseHandle) {
    this.db = handle.db;
  }

  // --- rows ---------------------------------------------------------------

  /**
   * Create-or-replace one asset row. NOT the publish path — it has no quota
   * guard, so it is for administrative repair and for tests. Publishing goes
   * through {@link createAssetWithinQuota}.
   */
  async upsertAsset(asset: StoredAsset): Promise<void> {
    try {
      await this.db
        .prepare(
          `INSERT INTO stored_assets (${STORED_ASSET_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET content_type = excluded.content_type, content_hash = excluded.content_hash, size_bytes = excluded.size_bytes, updated_at_unix = excluded.updated_at_unix, storage_uri = excluded.storage_uri, yanked = excluded.yanked, visibility = excluded.visibility`,
        )
        .bind(...assetInsertBinds(asset))
        .run();
    } catch (error) {
      throw d1Error("upsert_asset", error);
    }
  }

  /**
   * The publish path (#371): admit an asset only while the tenant's cumulative
   * `size_bytes` plus this artifact fits inside `quotaBytes`.
   *
   * `quotaBytes === undefined` is UNLIMITED and is spelled as the empty-string
   * sentinel in the guard, which short-circuits it — not as a huge number, which
   * would silently become a real cap under saturation.
   *
   * The pre-state read is statement 0 of the SAME batch as the guard, so the
   * label it produces describes the snapshot the guard acted on.
   */
  async createAssetWithinQuota(
    asset: StoredAsset,
    quotaBytes: number | undefined,
  ): Promise<AssetQuotaAdmission> {
    requireAtomicBatch(this.handle, "create_asset_within_quota");
    const quotaParam = quotaBytes === undefined ? "" : quotaBytes;
    try {
      const results = await this.db.batch([
        this.db
          .prepare(
            "SELECT " +
              "(SELECT COUNT(*) FROM stored_assets WHERE id = ?) AS id_exists, " +
              "(SELECT COUNT(*) FROM stored_assets " +
              " WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ? " +
              "   AND variant = ?) AS tuple_exists, " +
              "COALESCE((SELECT SUM(size_bytes) FROM stored_assets WHERE tenant_id = ?), 0) " +
              "  AS used_bytes",
          )
          .bind(
            asset.id,
            asset.tenantId,
            asset.assetType,
            asset.name,
            asset.version,
            asset.variant,
            asset.tenantId,
          ),
        this.db
          .prepare(CREATE_ASSET_WITHIN_QUOTA_SQL)
          .bind(
            ...assetInsertBinds(asset),
            quotaParam,
            asset.tenantId,
            asset.sizeBytes,
            quotaParam,
          ),
      ]);
      const state = (
        results[0] as D1Result<{ id_exists: number; tuple_exists: number; used_bytes: number }>
      ).results[0];
      if (state === undefined) {
        throw StorageError.runtime(
          "create_asset_within_quota pre-state read returned no row; the labelling read must " +
            "always answer, even for a tenant with no assets",
        );
      }
      const inserted = (results[1] as D1Result<{ inserted: number }>).results.length > 0;
      const usedBytes = Math.max(Number(state.used_bytes), 0);
      const idOrTupleExists = Number(state.id_exists) !== 0 || Number(state.tuple_exists) !== 0;
      const quotaOk = quotaBytes === undefined || usedBytes + asset.sizeBytes <= quotaBytes;
      return classifyAssetQuotaAdmission(
        inserted,
        idOrTupleExists,
        quotaOk,
        usedBytes,
        asset.sizeBytes,
        quotaBytes,
      );
    } catch (error) {
      if (error instanceof StorageError) throw error;
      // Defense in depth: a surfaced UNIQUE violation is the `already_exists`
      // loser the guard already models — either unique constraint, id or the
      // (tenant, type, name, version, variant) composite.
      const detail = error instanceof Error ? error.message : String(error);
      if (detail.includes("UNIQUE constraint failed")) return { kind: "already_exists" };
      throw d1Error("create_asset_within_quota", error);
    }
  }

  /** One asset row by id, or `undefined`. */
  async getAsset(id: string): Promise<StoredAsset | undefined> {
    try {
      const row = await this.db
        .prepare(`SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE id = ?`)
        .bind(id)
        .first<StoredAssetRow>();
      return row === null ? undefined : intoStoredAsset(row);
    } catch (error) {
      throw d1Error("get_asset", error);
    }
  }

  /** One tenant's assets, optionally one `assetType`, ordered like Postgres. */
  async listAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    try {
      const statement =
        assetType === undefined
          ? this.db
              .prepare(
                `SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ? ORDER BY asset_type ASC, name ASC, version ASC, variant ASC`,
              )
              .bind(tenantId)
          : this.db
              .prepare(
                `SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ? AND asset_type = ? ORDER BY name ASC, version ASC, variant ASC`,
              )
              .bind(tenantId, assetType);
      const rows = await statement.all<StoredAssetRow>();
      return rows.results.map(intoStoredAsset);
    } catch (error) {
      throw d1Error("list_assets", error);
    }
  }

  /**
   * Everything this tenant holds that is NOT servable — `pending_scan` and
   * `quarantined` (#366). The operator read behind "what is my screening backlog
   * and what did screening reject".
   *
   * The predicate is `visibility <> 'visible'` and NOT an enumeration of the two
   * withheld states, so a row carrying an unrecognized token — the poisoned or
   * partially-migrated case {@link ../assets.js assetVisibilityFromStored} fails
   * closed on — is LISTED rather than invisible to the operator.
   */
  async listWithheldAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    try {
      const statement =
        assetType === undefined
          ? this.db
              .prepare(
                `SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ? AND visibility <> 'visible' ORDER BY asset_type ASC, name ASC, version ASC, variant ASC`,
              )
              .bind(tenantId)
          : this.db
              .prepare(
                `SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ? AND asset_type = ? AND visibility <> 'visible' ORDER BY name ASC, version ASC, variant ASC`,
              )
              .bind(tenantId, assetType);
      const rows = await statement.all<StoredAssetRow>();
      return rows.results.map(intoStoredAsset);
    } catch (error) {
      throw d1Error("list_withheld_assets", error);
    }
  }

  /** The tenant's cumulative asset bytes — the live SUM the quota guard reads. */
  async tenantAssetStorageBytesUsed(tenantId: string): Promise<number> {
    try {
      const row = await this.db
        .prepare(
          "SELECT COALESCE(SUM(size_bytes), 0) AS used_bytes FROM stored_assets " +
            "WHERE tenant_id = ?",
        )
        .bind(tenantId)
        .first<{ used_bytes: number }>();
      return Math.max(Number(row?.used_bytes ?? 0), 0);
    } catch (error) {
      throw d1Error("tenant_asset_storage_bytes_used", error);
    }
  }

  /** Unconditional delete by id. The GUARDED variant is `D1ReferenceGuardedDeletes`. */
  async deleteAsset(id: string): Promise<boolean> {
    try {
      const result = await this.db.prepare("DELETE FROM stored_assets WHERE id = ?").bind(id).run();
      return changes(result) > 0;
    } catch (error) {
      throw d1Error("delete_asset", error);
    }
  }

  /**
   * The trust-screening promotion CAS (#378): flip `pending_scan` to a terminal
   * visibility, and ONLY from `pending_scan`.
   *
   * The predicate is inside the UPDATE, so a second scanner racing the first
   * cannot re-promote a row that has already been decided — an empty
   * `RETURNING` set is the refusal. The follow-up read only labels it
   * (`not_found` vs `not_pending`) via the shared pure rule
   * {@link ../assets.js promoteAssetVisibility}.
   */
  async promoteAssetVisibility(
    id: string,
    target: AssetPromotionTarget,
    nowUnix: number,
  ): Promise<AssetVisibilityPromotionOutcome> {
    try {
      const promoted = await this.db
        .prepare(PROMOTE_ASSET_VISIBILITY_SQL)
        .bind(target, nowUnix, id)
        .run();
      if (changes(promoted) > 0) return { kind: "promoted", to: target };

      const row = await this.db
        .prepare("SELECT visibility FROM stored_assets WHERE id = ?")
        .bind(id)
        .first<{ visibility: string }>();
      const current: AssetVisibility | undefined =
        row === null ? undefined : assetVisibilityFromStored(row.visibility);
      const outcome = promoteAssetVisibility(current, target);
      // The guard already refused, so `promoted` cannot be the honest label: it
      // would mean the row went back to `pending_scan` between the statements.
      return outcome.kind === "promoted"
        ? { kind: "not_pending", current: "pending_scan" }
        : outcome;
    } catch (error) {
      throw d1Error("promote_asset_visibility", error);
    }
  }

  // --- channels -----------------------------------------------------------

  /**
   * Create-or-move a channel pointer WITHOUT the resolvability guard. This is
   * the administrative/repair path (Rust `upsert_asset_channel`); the publish
   * path is {@link moveAssetChannelIfResolvable} and callers should prefer it —
   * this one will happily point `latest` at a version that does not exist.
   */
  async upsertAssetChannel(channel: StoredAssetChannel): Promise<void> {
    try {
      await this.db
        .prepare(
          `INSERT INTO asset_channels (${ASSET_CHANNEL_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET version = excluded.version, updated_at_unix = excluded.updated_at_unix`,
        )
        .bind(
          channel.id,
          channel.tenantId,
          channel.assetType,
          channel.name,
          channel.channel,
          channel.version,
          channel.updatedAtUnix,
        )
        .run();
    } catch (error) {
      throw d1Error("upsert_asset_channel", error);
    }
  }

  /** One `{tenant, assetType, name}`'s channel pointers, ordered by channel. */
  async listAssetChannels(
    tenantId: string,
    assetType: string,
    name: string,
  ): Promise<StoredAssetChannel[]> {
    try {
      const rows = await this.db
        .prepare(
          `SELECT ${ASSET_CHANNEL_COLUMNS} FROM asset_channels WHERE tenant_id = ? AND asset_type = ? AND name = ? ORDER BY channel ASC`,
        )
        .bind(tenantId, assetType, name)
        .all<AssetChannelRow>();
      return rows.results.map(intoStoredChannel);
    } catch (error) {
      throw d1Error("list_asset_channels", error);
    }
  }

  /** Delete one channel pointer by id; `true` when a row was removed. */
  async deleteAssetChannel(id: string): Promise<boolean> {
    try {
      const result = await this.db
        .prepare("DELETE FROM asset_channels WHERE id = ?")
        .bind(id)
        .run();
      return changes(result) > 0;
    } catch (error) {
      throw d1Error("delete_asset_channel", error);
    }
  }

  /**
   * Move a channel to a version ONLY while that version is durably resolvable —
   * present, and with no yanked variant (#367).
   *
   * Two statements in one batch: the prior target (audit evidence, read before
   * the move) and the guarded upsert. An empty `RETURNING` set from the guard is
   * `target_not_resolvable`, decided at commit time, so a concurrent yank or
   * variant delete cannot slip between "resolve" and "write".
   */
  async moveAssetChannelIfResolvable(channel: StoredAssetChannel): Promise<ChannelMoveOutcome> {
    requireAtomicBatch(this.handle, "move_asset_channel_if_resolvable");
    try {
      const results = await this.db.batch([
        this.db.prepare("SELECT version FROM asset_channels WHERE id = ?").bind(channel.id),
        this.db
          .prepare(MOVE_ASSET_CHANNEL_IF_RESOLVABLE_SQL)
          .bind(
            channel.id,
            channel.tenantId,
            channel.assetType,
            channel.name,
            channel.channel,
            channel.version,
            channel.updatedAtUnix,
            channel.tenantId,
            channel.assetType,
            channel.name,
            channel.version,
            channel.tenantId,
            channel.assetType,
            channel.name,
            channel.version,
          ),
      ]);
      const moved = (results[1] as D1Result<{ version: string }>).results.length > 0;
      if (!moved) return { kind: "target_not_resolvable" };
      const prior = (results[0] as D1Result<{ version: string }>).results[0];
      return { kind: "moved", priorVersion: prior?.version };
    } catch (error) {
      throw d1Error("move_asset_channel_if_resolvable", error);
    }
  }

  /**
   * Yank (or unyank) every variant row of one version (#367).
   *
   * A yank is REFUSED while a channel still resolves to the version — the mirror
   * of the move guard. Refusing costs the operator one "move `latest` first"
   * message; permitting it strands the channel on an artifact that has just been
   * declared unusable, and every pull keeps serving it.
   *
   * An unyank skips the guard: it can only ever make more artifacts resolvable.
   *
   * The state read is statement 0 of the SAME batch, so `not_found` and
   * `referenced_by_channel` describe the snapshot the guard acted on rather than
   * a later one.
   */
  async setAssetVersionYank(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
    yanked: boolean,
    nowUnix: number,
  ): Promise<VersionYankOutcome> {
    requireAtomicBatch(this.handle, "set_asset_version_yank");
    const yankFlag = boolToSqlite(yanked);
    try {
      const results = await this.db.batch([
        this.db
          .prepare(
            "SELECT " +
              "(SELECT COUNT(*) FROM stored_assets " +
              " WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) " +
              "  AS variant_count, " +
              "(SELECT COUNT(*) FROM asset_channels " +
              " WHERE tenant_id = ? AND asset_type = ? AND name = ? AND version = ?) " +
              "  AS referenced_count",
          )
          .bind(tenantId, assetType, name, version, tenantId, assetType, name, version),
        this.db
          .prepare(SET_ASSET_VERSION_YANK_SQL)
          .bind(
            yankFlag,
            nowUnix,
            tenantId,
            assetType,
            name,
            version,
            yankFlag,
            tenantId,
            assetType,
            name,
            version,
          ),
      ]);
      const state = (results[0] as D1Result<{ variant_count: number; referenced_count: number }>)
        .results[0];
      if (state === undefined) {
        throw StorageError.runtime(
          "set_asset_version_yank state read returned no row; the labelling read must always " +
            "answer, even for a version that does not exist",
        );
      }
      if (Number(state.variant_count) === 0) return { kind: "not_found" };
      if (yanked && Number(state.referenced_count) > 0) return { kind: "referenced_by_channel" };
      return {
        kind: "applied",
        variants: (results[1] as D1Result<{ id: string }>).results.length,
      };
    } catch (error) {
      if (error instanceof StorageError) throw error;
      throw d1Error("set_asset_version_yank", error);
    }
  }
}
