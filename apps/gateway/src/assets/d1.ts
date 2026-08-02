/**
 * The DURABLE asset registry — `stored_assets` + `asset_channels` on the tenant
 * D1 (`sql/d1-ts/tenant/0001_init_tenant.sql`).
 *
 * ## Why this file exists
 *
 * `InMemoryAssetMetadataStore` (`./ports.ts`) was the ONLY implementation of
 * {@link AssetMetadataStore}, and `assetDepsFromEnv` did not resolve `metadata`
 * at all — so every asset row the gateway wrote lived in one isolate's heap.
 * `docs/rewrite/parity-audit-storage.md` §4.8 states the consequence exactly:
 * `latest`/`stable`/`canary` are resolved at pull time from rows that never
 * persist, so a published asset is unresolvable on the next isolate, and the
 * **yank flag — the kill switch for a bad artifact — cannot survive a deploy.**
 * The bytes half was already durable (`env.ASSETS`, an R2 bucket); only the
 * metadata half was not, which is the worst of the two shapes: the object is
 * really there and nothing can find it, or worse, a version pulled after a yank
 * is served again because the yank was heap state.
 *
 * The tables were already in the deployed migration. Nothing wrote them.
 *
 * ## Every invariant is INSIDE one statement
 *
 * D1 is SQLite: no `SELECT … FOR UPDATE`, and a Worker cannot hold a
 * transaction open across an `await`. So each method that carries a lifecycle
 * invariant (Rust issue #367) puts its predicate in the WRITING statement and
 * reads `RETURNING` to learn whether it fired:
 *
 * | method | guard, in the statement |
 * |---|---|
 * | {@link D1AssetMetadataStore.createAssetWithinQuota} | `WHERE <quota> IS NULL OR (SELECT SUM(size_bytes) …) + <size> <= <quota>` + bare `ON CONFLICT DO NOTHING` |
 * | {@link D1AssetMetadataStore.deleteAssetVariantIfUnreferenced} | `AND (EXISTS <another live variant> OR NOT EXISTS <channel pointing here>)` |
 * | {@link D1AssetMetadataStore.setAssetVersionYank} | `AND (<unyank> OR NOT EXISTS <channel pointing here>)` |
 * | {@link D1AssetMetadataStore.promotePendingAssetVisibility} | `AND visibility = 'pending_scan'` |
 * | {@link D1AssetMetadataStore.moveAssetChannel} | `WHERE EXISTS <visible variant> AND NOT EXISTS <yanked variant>` |
 *
 * An EMPTY `RETURNING` set is the refusal. It is deliberately NOT self-labeling
 * — "nothing was written" cannot distinguish "already existed" from "over
 * quota" — so each method follows an empty result with a **classification
 * read**. That read decides only which error the caller renders; it can never
 * admit anything, so a concurrent write between the guarded statement and the
 * classification can at worst mislabel a refusal, never turn one into a
 * success. That is the same S2 split the wallet reserve uses in
 * `packages/storage/src/d1/wallet-d1.ts`, and it is why the read is AFTER the
 * write rather than before it.
 *
 * ## Which database
 *
 * The tenant one (`env.DB`), because `stored_assets` / `asset_channels` are in
 * the TENANT migration, not the control one — a write against `CONTROL_DB`
 * would fail loudly with `no such table`, which is the split's whole point
 * (`src/tenancy/ports.ts`). Every method still takes `tenantId` and every
 * statement still filters on it: under `GATEWAY_TENANT_DB_ROUTING = "off"`
 * (the committed default) `DB` is one shared tenant database, so the
 * `tenant_id` predicate is the isolation, exactly as it is for `api_keys` in
 * `src/keys/store.ts`. When routing is switched on, `src/tenancy/` hands each
 * request its own physical database and the same predicate is then redundant
 * rather than wrong.
 *
 * ## Relationship to `packages/storage`
 *
 * `packages/storage/src/assets.ts` declares the same DTOs and
 * `ChannelMoveOutcome`. This store is app-local for the same reason
 * `src/metering/d1.ts` and `src/guardrails/d1.ts` are: those seams are already
 * app-local and the asset service's port lives here. See
 * `docs/rewrite/parity-audit-storage.md` §4.11 on the duplication — it closes
 * when the whole durable half of `@ferrogate/storage` is mounted, not before.
 */
import { randomHex128 } from "./hash.js";
import type {
  AssetAuditEvent,
  AssetAuditSink,
  AssetBundleIndexStore,
  AssetMetadataStore,
  AssetQuotaAdmission,
  AssetVisibility,
  AssetVisibilityPromotionOutcome,
  ChannelMoveOutcome,
  StoredAsset,
  StoredAssetChannel,
  StoredBundleFile,
  VariantDeleteOutcome,
  VersionYankOutcome,
} from "./ports.js";

// ---------------------------------------------------------------------------
// The narrow database port
// ---------------------------------------------------------------------------

/** One row, as D1 hands it back. */
type Row = Record<string, unknown>;

/** What a `RETURNING`/`SELECT` statement resolves to. */
export interface AssetQueryResult {
  results?: Row[] | null;
}

export interface AssetStatement {
  bind(...values: unknown[]): AssetStatement;
  all(): Promise<AssetQueryResult>;
}

/**
 * The subset of `D1Database` this store uses. A live binding satisfies it
 * structurally, so nothing is cast at the composition root and nothing wraps
 * the binding. `batch` is required, not optional: {@link
 * D1AssetMetadataStore.moveAssetChannel} needs the prior version and the upsert
 * to be ONE transaction, and a store built on a handle without `batch` would
 * silently lose that atomicity.
 */
export interface AssetDatabase {
  prepare(sql: string): AssetStatement;
  batch(statements: AssetStatement[]): Promise<AssetQueryResult[]>;
}

/** Binding name of the TENANT D1 (see `wrangler.toml`). */
export const TENANT_DATABASE_BINDING = "DB";

export function isAssetDatabase(value: unknown): value is AssetDatabase {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AssetDatabase).prepare === "function" &&
    typeof (value as AssetDatabase).batch === "function"
  );
}

// ---------------------------------------------------------------------------
// SQL — exported so tests pin the statements rather than restate them
// ---------------------------------------------------------------------------

const ASSET_COLUMNS =
  "id, tenant_id, project_id, asset_type, name, version, content_type, content_hash, " +
  "size_bytes, storage_uri, variant, yanked, visibility, created_at_unix, updated_at_unix";

export const ASSET_SELECT_SQL = `SELECT ${ASSET_COLUMNS} FROM stored_assets WHERE id = ?1`;

/** Stable listing order, shared by the plain and the withheld listing. */
const ASSET_ORDER = "asset_type ASC, name ASC, version ASC, variant ASC";

/**
 * `?2 IS NULL` is the "all asset types" arm. Written as a bound predicate
 * rather than two SQL strings so the listing and the filtered listing cannot
 * drift in their ordering or their column set.
 */
export const ASSET_LIST_SQL =
  `SELECT ${ASSET_COLUMNS} FROM stored_assets ` +
  `WHERE tenant_id = ?1 AND (?2 IS NULL OR asset_type = ?2) ORDER BY ${ASSET_ORDER}`;

/** Rust `list_withheld_assets` (#379): anything a read surface will not serve. */
export const ASSET_LIST_WITHHELD_SQL =
  `SELECT ${ASSET_COLUMNS} FROM stored_assets WHERE tenant_id = ?1 ` +
  `AND (?2 IS NULL OR asset_type = ?2) AND visibility <> 'visible' ORDER BY ${ASSET_ORDER}`;

export const ASSET_BYTES_USED_SQL =
  "SELECT COALESCE(SUM(size_bytes), 0) AS used_bytes FROM stored_assets WHERE tenant_id = ?1";

/**
 * The atomic create (#369/#371).
 *
 * `INSERT … SELECT … WHERE <quota predicate>` is what makes the admission a
 * SINGLE statement: the `SUM(size_bytes)` is computed by the same statement
 * that inserts, so two concurrent pushes cannot both observe the same remaining
 * capacity. Splitting this into a read plus an insert is the exact defect the
 * Rust issue closed, and `test/assets/d1.test.ts` proves it by racing 8 pushes
 * against a quota that affords 3.
 *
 * The bare `ON CONFLICT DO NOTHING` (no target) covers BOTH uniqueness rules on
 * the table — the `id` primary key and `UNIQUE (tenant_id, asset_type, name,
 * version, variant)` — so a republish is a refusal, never a rewrite of a
 * published artifact's hash or bytes. The `WHERE` clause is also what makes the
 * upsert unambiguous to SQLite's parser when the values come from a `SELECT`.
 */
export const ASSET_CREATE_WITHIN_QUOTA_SQL =
  "INSERT INTO stored_assets " +
  "(id, tenant_id, project_id, asset_type, name, version, content_type, content_hash, " +
  "size_bytes, storage_uri, variant, yanked, visibility, created_at_unix, updated_at_unix) " +
  "SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15 " +
  "WHERE ?16 IS NULL " +
  "OR (SELECT COALESCE(SUM(size_bytes), 0) FROM stored_assets WHERE tenant_id = ?2) + ?9 <= ?16 " +
  "ON CONFLICT DO NOTHING " +
  "RETURNING id";

/** Classification-only: which of the two refusals was it? */
export const ASSET_CONFLICT_PROBE_SQL =
  "SELECT id FROM stored_assets " +
  "WHERE id = ?1 " +
  "OR (tenant_id = ?2 AND asset_type = ?3 AND name = ?4 AND version = ?5 AND variant = ?6)";

/**
 * §1.5.7's third reference-guarded delete (`delete_asset_variant_if_unreferenced`).
 *
 * The guard is INSIDE the DELETE, so the check-then-delete window does not
 * exist: a channel move that lands between a hypothetical check and the delete
 * cannot strand the channel, because there is no between. Admitted when either
 * ANOTHER live (non-yanked) variant of the same logical version survives the
 * delete, OR no channel points at that version at all.
 */
export const ASSET_VARIANT_DELETE_SQL =
  "DELETE FROM stored_assets WHERE id = ?1 AND (" +
  "EXISTS (SELECT 1 FROM stored_assets other WHERE other.tenant_id = ?2 " +
  "AND other.asset_type = ?3 AND other.name = ?4 AND other.version = ?5 " +
  "AND other.id <> ?1 AND other.yanked = 0) " +
  "OR NOT EXISTS (SELECT 1 FROM asset_channels WHERE tenant_id = ?2 " +
  "AND asset_type = ?3 AND name = ?4 AND version = ?5)) " +
  "RETURNING id";

export const ASSET_EXISTS_SQL = "SELECT id FROM stored_assets WHERE id = ?1";

export const ASSET_VERSION_EXISTS_SQL =
  "SELECT id FROM stored_assets " +
  "WHERE tenant_id = ?1 AND asset_type = ?2 AND name = ?3 AND version = ?4";

/**
 * Yank/unyank every variant row of one logical version (#367).
 *
 * `?5 = 0 OR NOT EXISTS (…)`: an UNYANK only ever makes a version MORE
 * resolvable, so it can never strand a channel and is unconditional. A YANK is
 * fail-closed while a channel still points at the version — refusing is what
 * keeps the "a channel never points at a yanked version" invariant true from
 * both directions.
 */
export const ASSET_VERSION_YANK_SQL =
  "UPDATE stored_assets SET yanked = ?5, updated_at_unix = ?6 " +
  "WHERE tenant_id = ?1 AND asset_type = ?2 AND name = ?3 AND version = ?4 " +
  "AND (?5 = 0 OR NOT EXISTS (SELECT 1 FROM asset_channels " +
  "WHERE tenant_id = ?1 AND asset_type = ?2 AND name = ?3 AND version = ?4)) " +
  "RETURNING id";

/** The fail-closed `pending_scan -> visible|quarantined` CAS (#378). */
export const ASSET_PROMOTE_VISIBILITY_SQL =
  "UPDATE stored_assets SET visibility = ?2, updated_at_unix = ?3 " +
  "WHERE id = ?1 AND visibility = 'pending_scan' " +
  "RETURNING id";

export const ASSET_VISIBILITY_PROBE_SQL = "SELECT visibility FROM stored_assets WHERE id = ?1";

const CHANNEL_COLUMNS = "id, tenant_id, asset_type, name, channel, version, updated_at_unix";

/** Stable listing order for channel pointers. */
const CHANNEL_ORDER = "channel ASC";

export const CHANNEL_LIST_SQL =
  `SELECT ${CHANNEL_COLUMNS} FROM asset_channels ` +
  `WHERE tenant_id = ?1 AND asset_type = ?2 AND name = ?3 ORDER BY ${CHANNEL_ORDER}`;

export const CHANNEL_PRIOR_SQL = "SELECT version FROM asset_channels WHERE id = ?1";

/**
 * The atomic channel move (#367): durable ONLY if the target resolves at write
 * time.
 *
 * `EXISTS (… visibility = 'visible' AND yanked = 0)` is "at least one variant
 * a read surface would actually serve"; `NOT EXISTS (… yanked = 1)` is "no
 * variant of this version is yanked". Together they are the in-memory oracle's
 * `rows.length > 0 && rows.every(not yanked) && rows.some(downloadable)`. The
 * `visible` clause is a deliberate fail-closed tightening over the Rust
 * `channel_target_is_resolvable` (presence + not yanked): moving `latest` onto
 * a `pending_scan`/`quarantined` version would publish a pointer to something
 * every read surface withholds (#366).
 */
export const CHANNEL_MOVE_SQL =
  "INSERT INTO asset_channels " +
  "(id, tenant_id, asset_type, name, channel, version, updated_at_unix) " +
  "SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 " +
  "WHERE EXISTS (SELECT 1 FROM stored_assets WHERE tenant_id = ?2 AND asset_type = ?3 " +
  "AND name = ?4 AND version = ?6 AND visibility = 'visible' AND yanked = 0) " +
  "AND NOT EXISTS (SELECT 1 FROM stored_assets WHERE tenant_id = ?2 AND asset_type = ?3 " +
  "AND name = ?4 AND version = ?6 AND yanked = 1) " +
  "ON CONFLICT (id) DO UPDATE SET version = excluded.version, " +
  "updated_at_unix = excluded.updated_at_unix " +
  "RETURNING id";

export const CHANNEL_DELETE_SQL = "DELETE FROM asset_channels WHERE id = ?1 RETURNING id";

// ---------------------------------------------------------------------------
// Row mapping
// ---------------------------------------------------------------------------

function rowsOf(result: AssetQueryResult): Row[] {
  return result.results ?? [];
}

function text(value: unknown): string {
  return typeof value === "string" ? value : String(value ?? "");
}

function integer(value: unknown): number {
  return typeof value === "number" ? value : Number(value ?? 0);
}

/**
 * SQLite has no boolean type, so `yanked` is stored `0`/`1`. Anything other
 * than a truthy integer/`true` reads as NOT yanked — which is the fail-OPEN
 * direction for a flag whose job is to WITHHOLD, so it is pinned by a test
 * rather than left to inference: a legacy `NULL` must not read as "yanked" and
 * quietly 404 a live asset, and a `1` must never read as "not yanked".
 */
function boolFromSqlite(value: unknown): boolean {
  return value === 1 || value === true || value === "1";
}

/**
 * `visibility` is a free `TEXT` column in the migration (no CHECK), so an
 * unknown token has to mean something. It reads as `quarantined`: the ONE value
 * that withholds the row from every read surface. Fail-closed, matching the
 * screening default in `./ports.ts` — a row the gateway cannot classify is not
 * a row it will serve.
 */
function visibilityFromSqlite(value: unknown): AssetVisibility {
  const raw = text(value);
  return raw === "visible" || raw === "pending_scan" ? raw : "quarantined";
}

function assetFromRow(row: Row): StoredAsset {
  const projectId = row.project_id;
  return {
    id: text(row.id),
    tenant_id: text(row.tenant_id),
    ...(projectId === null || projectId === undefined ? {} : { project_id: text(projectId) }),
    asset_type: text(row.asset_type),
    name: text(row.name),
    version: text(row.version),
    content_type: text(row.content_type),
    content_hash: text(row.content_hash),
    size_bytes: integer(row.size_bytes),
    storage_uri: text(row.storage_uri),
    variant: text(row.variant),
    yanked: boolFromSqlite(row.yanked),
    visibility: visibilityFromSqlite(row.visibility),
    created_at_unix: integer(row.created_at_unix),
    updated_at_unix: integer(row.updated_at_unix),
  };
}

function channelFromRow(row: Row): StoredAssetChannel {
  return {
    id: text(row.id),
    tenant_id: text(row.tenant_id),
    asset_type: text(row.asset_type),
    name: text(row.name),
    channel: text(row.channel),
    version: text(row.version),
    updated_at_unix: integer(row.updated_at_unix),
  };
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/**
 * The durable {@link AssetMetadataStore}. Answers exactly the outcomes
 * `InMemoryAssetMetadataStore` answers — `test/assets/d1.test.ts` runs both
 * through one shared conformance body so the two cannot drift, which is the
 * only reason the in-memory one is still safe to keep as a local-dev default.
 */
export class D1AssetMetadataStore implements AssetMetadataStore {
  constructor(private readonly db: AssetDatabase) {}

  async getAsset(id: string): Promise<StoredAsset | null> {
    const rows = rowsOf(await this.db.prepare(ASSET_SELECT_SQL).bind(id).all());
    const row = rows[0];
    return row === undefined ? null : assetFromRow(row);
  }

  async listAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    const rows = rowsOf(
      await this.db
        .prepare(ASSET_LIST_SQL)
        .bind(tenantId, assetType ?? null)
        .all(),
    );
    return rows.map(assetFromRow);
  }

  async listWithheldAssets(tenantId: string, assetType?: string): Promise<StoredAsset[]> {
    const rows = rowsOf(
      await this.db
        .prepare(ASSET_LIST_WITHHELD_SQL)
        .bind(tenantId, assetType ?? null)
        .all(),
    );
    return rows.map(assetFromRow);
  }

  async tenantAssetStorageBytesUsed(tenantId: string): Promise<number> {
    const rows = rowsOf(await this.db.prepare(ASSET_BYTES_USED_SQL).bind(tenantId).all());
    return integer(rows[0]?.used_bytes);
  }

  async createAssetWithinQuota(
    asset: StoredAsset,
    quotaBytes: number | undefined,
  ): Promise<AssetQuotaAdmission> {
    const admitted = rowsOf(
      await this.db
        .prepare(ASSET_CREATE_WITHIN_QUOTA_SQL)
        .bind(
          asset.id,
          asset.tenant_id,
          asset.project_id ?? null,
          asset.asset_type,
          asset.name,
          asset.version,
          asset.content_type,
          asset.content_hash,
          asset.size_bytes,
          asset.storage_uri,
          asset.variant,
          asset.yanked ? 1 : 0,
          asset.visibility,
          asset.created_at_unix,
          asset.updated_at_unix,
          quotaBytes ?? null,
        )
        .all(),
    );
    if (admitted.length > 0) return { kind: "admitted" };

    // Empty `RETURNING` = refused. Classify (see the module docstring: this
    // read decides the label only, it can never admit).
    const conflicting = rowsOf(
      await this.db
        .prepare(ASSET_CONFLICT_PROBE_SQL)
        .bind(asset.id, asset.tenant_id, asset.asset_type, asset.name, asset.version, asset.variant)
        .all(),
    );
    if (conflicting.length > 0) return { kind: "already_exists" };
    return {
      kind: "over_quota",
      used_bytes: await this.tenantAssetStorageBytesUsed(asset.tenant_id),
      attempted_bytes: asset.size_bytes,
      // Unreachable with an unbounded quota: `?16 IS NULL` admits, so the only
      // way to arrive here with `quotaBytes === undefined` would be a conflict,
      // which the probe above already returned.
      quota_bytes: quotaBytes ?? 0,
    };
  }

  async deleteAssetVariantIfUnreferenced(
    id: string,
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
  ): Promise<VariantDeleteOutcome> {
    const deleted = rowsOf(
      await this.db
        .prepare(ASSET_VARIANT_DELETE_SQL)
        .bind(id, tenantId, assetType, name, version)
        .all(),
    );
    if (deleted.length > 0) return { kind: "deleted" };
    const present = rowsOf(await this.db.prepare(ASSET_EXISTS_SQL).bind(id).all());
    return present.length > 0 ? { kind: "blocked_by_channel" } : { kind: "not_found" };
  }

  async setAssetVersionYank(
    tenantId: string,
    assetType: string,
    name: string,
    version: string,
    yanked: boolean,
    nowUnix: number,
  ): Promise<VersionYankOutcome> {
    const applied = rowsOf(
      await this.db
        .prepare(ASSET_VERSION_YANK_SQL)
        .bind(tenantId, assetType, name, version, yanked ? 1 : 0, nowUnix)
        .all(),
    );
    if (applied.length > 0) return { kind: "applied", variants: applied.length };
    const present = rowsOf(
      await this.db
        .prepare(ASSET_VERSION_EXISTS_SQL)
        .bind(tenantId, assetType, name, version)
        .all(),
    );
    return present.length > 0 ? { kind: "referenced_by_channel" } : { kind: "not_found" };
  }

  async promotePendingAssetVisibility(
    id: string,
    to: Exclude<AssetVisibility, "pending_scan">,
    nowUnix: number,
  ): Promise<AssetVisibilityPromotionOutcome> {
    const promoted = rowsOf(
      await this.db.prepare(ASSET_PROMOTE_VISIBILITY_SQL).bind(id, to, nowUnix).all(),
    );
    if (promoted.length > 0) return { kind: "promoted", to };
    const rows = rowsOf(await this.db.prepare(ASSET_VISIBILITY_PROBE_SQL).bind(id).all());
    const row = rows[0];
    if (row === undefined) return { kind: "not_found" };
    return { kind: "not_pending", current: visibilityFromSqlite(row.visibility) };
  }

  async listAssetChannels(
    tenantId: string,
    assetType: string,
    name: string,
  ): Promise<StoredAssetChannel[]> {
    const rows = rowsOf(
      await this.db.prepare(CHANNEL_LIST_SQL).bind(tenantId, assetType, name).all(),
    );
    return rows.map(channelFromRow);
  }

  async moveAssetChannel(
    tenantId: string,
    assetType: string,
    name: string,
    channel: string,
    version: string,
    nowUnix: number,
  ): Promise<ChannelMoveOutcome> {
    const id = `${tenantId}:${assetType}:${name}:${channel}`;
    // ONE transaction. `prior_version` is part of the move's answer, so reading
    // it in a separate round trip would let a concurrent move report a version
    // that was never this move's predecessor.
    const [prior, moved] = await this.db.batch([
      this.db.prepare(CHANNEL_PRIOR_SQL).bind(id),
      this.db
        .prepare(CHANNEL_MOVE_SQL)
        .bind(id, tenantId, assetType, name, channel, version, nowUnix),
    ]);
    if (rowsOf(moved ?? {}).length === 0) return { kind: "target_not_resolvable" };
    const priorRow = rowsOf(prior ?? {})[0];
    return {
      kind: "moved",
      prior_version: priorRow === undefined ? undefined : text(priorRow.version),
    };
  }

  async deleteAssetChannel(id: string): Promise<boolean> {
    const deleted = rowsOf(await this.db.prepare(CHANNEL_DELETE_SQL).bind(id).all());
    return deleted.length > 0;
  }
}

/**
 * Bindings → the durable registry. `undefined` when `DB` is unbound, so
 * `buildAssetService` falls back to the in-isolate store for local dev.
 */
export function assetMetadataStoreFromEnv(env: Record<string, unknown>): AssetMetadataStore | null {
  const db = env[TENANT_DATABASE_BINDING];
  return isAssetDatabase(db) ? new D1AssetMetadataStore(db) : null;
}

// ---------------------------------------------------------------------------
// The durable static_site bundle index — `asset_bundle_files` (#736)
// ---------------------------------------------------------------------------

const BUNDLE_FILE_COLUMNS =
  "asset_id, tenant_id, path, storage_uri, content_type, content_hash, size_bytes, created_at_unix";

/**
 * `ON CONFLICT … DO UPDATE`, not `DO NOTHING`.
 *
 * The only way a row can already exist for `(asset_id, path)` is a RETRIED
 * expansion of the same version — the version row is created before expansion
 * and `stored_assets` immutability refuses a second, different publish under
 * that id. So the retry's values are the authority, and `DO NOTHING` would
 * leave the index pointing at the FIRST attempt's object keys while the version
 * row and the reclamation pass both believe in the second attempt's.
 */
export const BUNDLE_FILE_UPSERT_SQL =
  `INSERT INTO asset_bundle_files (${BUNDLE_FILE_COLUMNS}) ` +
  "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) " +
  "ON CONFLICT (asset_id, path) DO UPDATE SET " +
  "storage_uri = excluded.storage_uri, content_type = excluded.content_type, " +
  "content_hash = excluded.content_hash, size_bytes = excluded.size_bytes, " +
  "created_at_unix = excluded.created_at_unix";

export const BUNDLE_FILE_SELECT_SQL = `SELECT ${BUNDLE_FILE_COLUMNS} FROM asset_bundle_files WHERE asset_id = ?1 AND path = ?2`;

export const BUNDLE_FILE_LIST_SQL = `SELECT ${BUNDLE_FILE_COLUMNS} FROM asset_bundle_files WHERE asset_id = ?1 ORDER BY path`;

/**
 * `RETURNING` on the delete, so the caller learns which OBJECTS it now owns the
 * reclamation of. A separate select-then-delete would let a concurrent retry
 * slip a row in between and strand its bytes with nothing referencing them.
 */
export const BUNDLE_FILE_DELETE_SQL = `DELETE FROM asset_bundle_files WHERE asset_id = ?1 RETURNING ${BUNDLE_FILE_COLUMNS}`;

function bundleFileFromRow(row: Row): StoredBundleFile {
  return {
    asset_id: text(row.asset_id),
    tenant_id: text(row.tenant_id),
    path: text(row.path),
    storage_uri: text(row.storage_uri),
    content_type: text(row.content_type),
    content_hash: text(row.content_hash),
    size_bytes: integer(row.size_bytes),
    created_at_unix: integer(row.created_at_unix),
  };
}

/**
 * The durable {@link AssetBundleIndexStore}.
 *
 * The whole index of one bundle is written in ONE `batch`, which D1 runs as a
 * single transaction. That is not an optimization: it is what makes "the index
 * is durable" a single observable event, so the CAS that follows it can be the
 * only thing standing between a partial expansion and a `visible` version.
 */
export class D1AssetBundleIndexStore implements AssetBundleIndexStore {
  constructor(private readonly db: AssetDatabase) {}

  async putBundleFiles(files: readonly StoredBundleFile[]): Promise<void> {
    if (files.length === 0) return;
    await this.db.batch(
      files.map((file) =>
        this.db
          .prepare(BUNDLE_FILE_UPSERT_SQL)
          .bind(
            file.asset_id,
            file.tenant_id,
            file.path,
            file.storage_uri,
            file.content_type,
            file.content_hash,
            file.size_bytes,
            file.created_at_unix,
          ),
      ),
    );
  }

  async getBundleFile(assetId: string, path: string): Promise<StoredBundleFile | null> {
    const rows = rowsOf(await this.db.prepare(BUNDLE_FILE_SELECT_SQL).bind(assetId, path).all());
    const row = rows[0];
    return row === undefined ? null : bundleFileFromRow(row);
  }

  async listBundleFiles(assetId: string): Promise<StoredBundleFile[]> {
    return rowsOf(await this.db.prepare(BUNDLE_FILE_LIST_SQL).bind(assetId).all()).map(
      bundleFileFromRow,
    );
  }

  async deleteBundleFiles(assetId: string): Promise<StoredBundleFile[]> {
    return rowsOf(await this.db.prepare(BUNDLE_FILE_DELETE_SQL).bind(assetId).all()).map(
      bundleFileFromRow,
    );
  }
}

/** `null` when `DB` is absent — same fallback rule as the metadata store. */
export function assetBundleIndexStoreFromEnv(
  env: Record<string, unknown>,
): AssetBundleIndexStore | null {
  const db = env[TENANT_DATABASE_BINDING];
  return isAssetDatabase(db) ? new D1AssetBundleIndexStore(db) : null;
}

// ---------------------------------------------------------------------------
// The durable audit sink — `audit_events` on the CONTROL D1
// ---------------------------------------------------------------------------

/**
 * Binding name of the CONTROL D1. `audit_events` lives in
 * `sql/d1-ts/control/`, NOT the tenant migration — an account-global admin
 * surface has to answer "who yanked this artifact" across every tenant, which
 * a per-tenant database cannot. Same reason `src/guardrails/d1.ts` reads it.
 */
export const CONTROL_DATABASE_BINDING_FOR_AUDIT = "CONTROL_DB";

/**
 * `id` is generated at RECORD time, not at flush time, so a retried flush is
 * idempotent against `ON CONFLICT DO NOTHING` — an audit trail that
 * double-counts a yank is as misleading as one that misses it.
 */
export const AUDIT_EVENT_INSERT_SQL =
  "INSERT INTO audit_events (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json) " +
  "VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING";

/**
 * The evidence read behind `listWithheldAssets` (#379).
 *
 * Newest-first so the caller can keep the FIRST row it sees per target and
 * ignore the rest — the same "latest wins" rule the in-memory sink applies.
 * Bounded, because the withheld listing is a UI surface and an unbounded scan
 * of an append-only table is a slow query that gets slower forever (there is
 * still nothing pruning this table — see the retention note in the class).
 */
export const AUDIT_SCREENING_EVIDENCE_SQL =
  "SELECT audit_json FROM audit_events WHERE tenant = ?1 " +
  "ORDER BY occurred_at_unix DESC LIMIT ?2";

/** How many recent rows the evidence read scans. */
export const AUDIT_EVIDENCE_SCAN_LIMIT = 500;

/**
 * The durable {@link AssetAuditSink}.
 *
 * ## Why it buffers
 *
 * `AssetAuditSink.record` is synchronous at 24 call sites, several of them
 * inside `return fail(...)` expressions. Making it async would have meant
 * threading `await` through every refusal path in `service.ts` and letting a
 * D1 hiccup change the STATUS the caller receives. So `record` appends to
 * `#pending` and {@link flush} commits the lot in ONE `batch()` — one round
 * trip per request instead of one per event, and either all of a request's
 * audit rows land or none do.
 *
 * ## Why it is NOT keyed per request
 *
 * The sink is built once per `env` and shared by every concurrent request in
 * the isolate, exactly like the asset service that holds it. `flush` therefore
 * DRAINS `#pending` (splice, not read-then-clear-later) before its first
 * `await`: a concurrent request's `record` lands in the fresh array and is
 * committed by its own flush. Two requests may each commit a superset of their
 * own rows, never a subset — an audit row can be written early, never dropped.
 *
 * ## Retention
 *
 * `audit_events` is append-only on this platform and NOTHING prunes it — see
 * `docs/rewrite/parity-audit-storage.md` §4.6 (`planLogRetention` is ported,
 * pure and tested in `packages/storage`, and has no executor). That is why the
 * evidence read is `LIMIT`-bounded rather than a full scan.
 */
export class D1AssetAuditSink implements AssetAuditSink {
  #pending: { id: string; event: AssetAuditEvent }[] = [];

  constructor(
    private readonly db: AssetDatabase,
    private readonly fallback: AssetAuditSink | undefined = undefined,
  ) {}

  record(event: AssetAuditEvent): void {
    this.#pending.push({ id: `aud_${randomHex128()}`, event });
    this.fallback?.record(event);
  }

  async flush(): Promise<void> {
    const draining = this.#pending;
    if (draining.length === 0) return;
    this.#pending = [];
    await this.db.batch(
      draining.map(({ id, event }) =>
        this.db.prepare(AUDIT_EVENT_INSERT_SQL).bind(
          id,
          event.requestId,
          event.agentRunId ?? null,
          event.tenantId,
          event.occurredAtUnix,
          JSON.stringify({
            action: event.action,
            target: event.target,
            outcome: event.outcome,
            message: event.message,
          }),
        ),
      ),
    );
  }

  /**
   * The #379 correlation, read back from D1 so it survives the isolate that
   * produced it — which is the entire point: a push is screened in one isolate
   * and the withheld listing is served by another, so the in-memory sink
   * answered `undefined` for essentially every real request.
   */
  async screeningEvidence(tenantId: string): Promise<Map<string, string>> {
    const rows = rowsOf(
      await this.db
        .prepare(AUDIT_SCREENING_EVIDENCE_SQL)
        .bind(tenantId, AUDIT_EVIDENCE_SCAN_LIMIT)
        .all(),
    );
    const evidence = new Map<string, string>();
    for (const row of rows) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(text(row.audit_json));
      } catch {
        // A malformed row must not poison the listing; it just carries no
        // evidence, which is the same answer as an absent row.
        continue;
      }
      if (typeof parsed !== "object" || parsed === null) continue;
      const detail = parsed as Record<string, unknown>;
      if (detail.action !== "asset.push" || detail.outcome !== "committed") continue;
      const target = text(detail.target);
      // Newest-first, so the first row seen for a target IS the latest.
      if (target === "" || evidence.has(target)) continue;
      evidence.set(target, text(detail.message));
    }
    return evidence;
  }
}

/**
 * Bindings → the durable audit sink. `null` when `CONTROL_DB` is unbound, so
 * `buildAssetService` keeps the bounded in-memory sink for local dev.
 */
export function assetAuditSinkFromEnv(env: Record<string, unknown>): AssetAuditSink | null {
  const db = env[CONTROL_DATABASE_BINDING_FOR_AUDIT];
  return isAssetDatabase(db) ? new D1AssetAuditSink(db) : null;
}
