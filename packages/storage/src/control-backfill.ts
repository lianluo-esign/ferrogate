/**
 * The audited, idempotent CONTROL D1 → `ControlDataObject` backfill (Zero-D1
 * S5, issue #881).
 *
 * The control plane is a SINGLETON: unlike a tenant migration there is no
 * per-row ownership to resolve — every control row belongs to the one object.
 * So this is a whole-database copy rather than a tenant-scoped fan-out, and the
 * only per-table metadata it needs is a stable key for deterministic
 * pagination and a receipt.
 *
 * Three properties the issue demands, held by construction:
 *
 *  - **Idempotent by primary key.** By default every write is `INSERT OR
 *    IGNORE`, so a row whose key already exists at the destination is skipped.
 *    Re-running copies zero rows and the per-table row counts are unchanged — the
 *    property the companion test proves by running the copy twice. The optional
 *    `overwrite` mode ({@link ControlBackfillOptions}) instead upserts, so a
 *    destination row that has diverged from the source is reconciled rather than
 *    left stale — the cut-over parity gate needs this because the destination
 *    object self-seeds a few rows on first wake (see {@link copyStatementSql}).
 *  - **Re-runnable in either direction.** The copier is backend-agnostic: it
 *    takes two `D1Database` handles (a real D1 binding and the object facade
 *    from `controlDataObjectDatabase` are both `D1Database`-shaped), so
 *    `backfillControlData(a, b)` and `backfillControlData(b, a)` are the two
 *    directions the design's rollback note relies on.
 *  - **Per-table row-count + checksum verification.** After the copy every
 *    table gets a {@link ControlTableReceipt} on BOTH sides. The checksum is a
 *    deterministic SHA-256 chain folded over the primary-key-ordered pages in a
 *    SINGLE STREAMING PASS (peak memory is one page, not the whole table), each
 *    page hashed with the tenant backfill's type-preserving row checksum. Both
 *    backends read the same key order in the same page size, so a silent
 *    divergence is a reported mismatch rather than a lost row — and a
 *    high-volume append table (request_logs, audit_events, billing_ledger, the
 *    usage rollups) is verified without materialising millions of rows.
 *
 * SECURITY: the table and key-column names are a FROZEN static allow-list. A
 * table name reaches a SQL string only after it has been selected from this
 * manifest; it is never taken from a database row, a `sqlite_master` scan, or an
 * operator request. Column names copied for a row come from `PRAGMA table_info`
 * of the source table (the database's own schema, not row data) and are each
 * re-validated against the identifier grammar before they are interpolated.
 */

import {
  type CanonicalRow,
  type TenantTableReceipt,
  type TenantTableReceiptComparison,
  checksumRows,
  compareTableReceipts,
} from "./tenant-backfill.js";

// ---------------------------------------------------------------------------
// Static control-table manifest
// ---------------------------------------------------------------------------

const SAFE_IDENTIFIER = /^[a-z][a-z0-9_]*$/;

function assertSafeIdentifier(identifier: string, kind: string): void {
  if (!SAFE_IDENTIFIER.test(identifier)) {
    throw new Error(`unsafe control backfill ${kind} identifier: ${identifier}`);
  }
}

export interface ControlBackfillTable {
  readonly name: string;
  /** Stable ordering columns (the table's primary key) for pagination + receipts. */
  readonly keyColumns: readonly string[];
}

function table(name: string, keyColumns: readonly string[]): ControlBackfillTable {
  assertSafeIdentifier(name, "table");
  if (keyColumns.length === 0) {
    throw new Error(`control backfill table ${name} needs at least one key column`);
  }
  for (const column of keyColumns) assertSafeIdentifier(column, "key column");
  return Object.freeze({ name, keyColumns: Object.freeze([...keyColumns]) });
}

/**
 * Every live control table, keyed by its primary key, in FOREIGN-KEY DEPENDENCY
 * order: a parent table always precedes any table that references it.
 *
 * The order is load-bearing, not cosmetic. `ControlDataObject`'s SQLite storage
 * enforces foreign keys (they are on by default and cannot be disabled inside a
 * transaction), and `INSERT OR IGNORE` suppresses only UNIQUE/PK/NOT NULL/CHECK
 * conflicts — NOT foreign-key failures. So a child row copied before its parent
 * exists aborts the whole backfill with `FOREIGN KEY constraint failed`. The two
 * dependencies in the control schema are therefore ordered by hand:
 *   - `platform_catalog_offerings` (FK → `platform_catalog_models` and
 *     `platform_provider_channels`, migration 0025) follows both parents;
 *   - `guardrail_check_evaluations` (FK → `guardrail_evaluations(projection_key)`,
 *     migration 0015) follows its parent.
 * Every other table is otherwise in `sqlite_master` name order.
 *
 * Derived from the full `sql/d1-ts/control/*.sql` apply — including the
 * `*_legacy` tables that migration `0016` renamed and left in place as
 * tenant-configuration backfill sources — and pinned exactly against the live
 * object schema by `test/do/control-backfill.test.ts`, so a new control
 * migration that adds or renames a table turns that test red until this list is
 * regenerated. The two migration ledgers
 * ({@link CONTROL_BACKFILL_EXCLUDED_TABLES}) are deliberately absent.
 */
export const CONTROL_BACKFILL_TABLES: readonly ControlBackfillTable[] = Object.freeze([
  table("admin_user_refresh_tokens", ["id"]),
  table("admin_user_tenant_memberships", ["id"]),
  table("admin_users", ["id"]),
  table("agent_run_events", ["projection_key"]),
  table("agent_runs", ["projection_key"]),
  table("agent_worker_instances", ["id"]),
  table("api_key_directory", ["key_hash"]),
  table("audit_events", ["projection_key"]),
  table("billing_events", ["billing_event_id"]),
  table("billing_ledger", ["id"]),
  table("billing_report_outbox", ["id"]),
  table("budget_alert_notifications_legacy", ["id"]),
  table("control_plane_replay_floors_legacy", ["tenant_id", "deployment_id"]),
  table("control_plane_resources", ["resource_kind", "resource_id"]),
  table("delegation_revocations_legacy", ["tenant", "subject"]),
  table("experiment_shadow_legs", ["projection_key"]),
  // Parent before child: guardrail_check_evaluations FK → guardrail_evaluations
  // (projection_key), migration 0015.
  table("guardrail_evaluations", ["projection_key"]),
  table("guardrail_check_evaluations", ["projection_key"]),
  table("guardrail_policy_bindings", ["policy_id"]),
  table("guardrail_policy_revisions", ["policy_id", "revision"]),
  table("managed_worker_isolation_evidence", ["projection_key"]),
  table("managed_worker_isolation_policies", ["session_id"]),
  table("managed_worker_isolation_selections", ["session_id"]),
  table("managed_worker_lifecycle_events", ["id"]),
  table("managed_worker_sessions", ["id"]),
  table("managed_worker_templates", ["id"]),
  table("observed_agent_presence", ["projection_key"]),
  table("online_eval_leg_quality", [
    "tenant",
    "criterion_id",
    "judge_model",
    "logical_model",
    "provider",
    "provider_model",
  ]),
  table("online_eval_regressions", ["projection_key"]),
  table("online_eval_scores", ["projection_key"]),
  table("permissions", ["id"]),
  table("plans", ["id"]),
  // Announcements (公告), migration 0030. `platform_announcements` and its
  // single-row revision stamp have no FK, so placement is free.
  table("platform_announcements", ["id"]),
  table("platform_announcement_revisions", ["id"]),
  // Billing groups (分组), migration 0028. `platform_billing_groups` and its
  // single-row revision stamp have no FK; the provider junction below FK →
  // BOTH platform_billing_groups AND platform_provider_channels, so it is
  // ordered after both parents (see the junction entry further down).
  table("platform_billing_groups", ["id"]),
  table("platform_billing_group_revisions", ["id"]),
  // Parents before child: platform_catalog_offerings FK → platform_catalog_models
  // AND platform_provider_channels, migration 0025.
  table("platform_catalog_models", ["id"]),
  // Public baseline prices (migration 0034). Offerings may bind this id, so
  // copy the price registry before the configured routes that consume it.
  table("platform_model_prices", ["id"]),
  table("platform_provider_channels", ["id"]),
  // FK → platform_billing_groups (above) AND platform_provider_channels (above),
  // migration 0028 — so the junction copies after both its parents.
  table("platform_billing_group_providers", ["group_id", "provider_id"]),
  table("platform_catalog_offerings", ["id"]),
  table("platform_catalog_revisions", ["id"]),
  table("quota_policies", ["id"]),
  table("request_logs", ["projection_key"]),
  table("roles", ["id"]),
  table("self_hosted_run_dispatches", ["dispatch_id"]),
  table("self_hosted_worker_artifacts", ["id"]),
  table("self_hosted_worker_checkpoints", ["id"]),
  table("self_hosted_worker_heartbeats", ["id"]),
  table("self_hosted_worker_registrations", ["id"]),
  table("self_hosted_worker_telemetry_events", ["id"]),
  table("semantic_cache_policies_legacy", ["scope_type", "scope_id"]),
  // Shared-config push watermark (#948), migration 0029. No FK; one row per
  // shared-config domain. Net-new and control-owned, so it has no legacy D1
  // source rows to copy — but the manifest-parity guard still requires every
  // live control table to be classified here or in the excluded ledgers.
  table("shared_config_push_state", ["domain"]),
  table("siem_export_cursors", ["sink_id", "stream"]),
  table("site_domain_verifications", ["tenant_id", "hostname"]),
  table("site_domains", ["hostname"]),
  table("spend_anomaly_episodes", ["projection_key"]),
  table("spend_anomaly_runs", ["window_start_unix"]),
  table("spend_throttles", ["scope_type", "scope_id"]),
  table("sso_pending_flows", ["state"]),
  table("sso_provider_configs_legacy", ["tenant_id"]),
  table("static_api_keys", ["key_hash"]),
  table("tenant_agent_cost_rollups", ["tenant_id", "agent_key", "period"]),
  table("tenant_asset_rollups", ["tenant_id"]),
  table("tenant_databases", ["tenant_id"]),
  table("tenant_provider_credentials_legacy", ["tenant_id", "alias"]),
  table("tenant_role_bindings_legacy", ["id"]),
  table("tenant_spend_rollups", ["tenant_id", "period"]),
  table("tenants", ["id"]),
  table("usage_aggregate_rollups", ["projection_key"]),
  table("usage_metadata_rollups", ["projection_key"]),
  table("usage_monthly_rollups", ["projection_key"]),
]);

/** A descriptive alias so call sites read naturally without a second copy. */
export const CONTROL_BACKFILL_TABLE_MANIFEST = CONTROL_BACKFILL_TABLES;

/**
 * The two bookkeeping ledgers the backfill never copies. `storage_schema_
 * migrations` is the D1 applier's ledger and `control_schema_applied` is the
 * `ControlDataObject`'s NAME-keyed ledger; the object rebuilds its own on first
 * wake, so copying either is at best redundant and at worst confuses the
 * applier about what it has run.
 */
export const CONTROL_BACKFILL_EXCLUDED_TABLES: readonly string[] = Object.freeze([
  "storage_schema_migrations",
  "control_schema_applied",
]);

// ---------------------------------------------------------------------------
// Copy + verify
// ---------------------------------------------------------------------------

export type ControlTableReceipt = TenantTableReceipt;
export type ControlTableReceiptComparison = TenantTableReceiptComparison;

export interface ControlBackfillOptions {
  /** Rows read per page and statements per destination batch. */
  readonly pageSize?: number;
  /**
   * When true, a destination row that already exists with the same primary key
   * is UPDATED to the source's values (a true `ON CONFLICT … DO UPDATE` upsert)
   * rather than skipped. Default false = the historic additive `INSERT OR
   * IGNORE`, which is safe only for an EMPTY destination.
   *
   * The cut-over needs the upsert because the destination `ControlDataObject` is
   * never empty when it is backfilled: it applies the same control migrations on
   * first wake, and a few of those SEED or bump rows (`plans` 'free' in 0001;
   * the `platform_billing_group_revisions` counter in 0032/0033) with
   * migration-time values the live D1 has since evolved. `INSERT OR IGNORE` can
   * never heal a same-key/different-value row, so it pins the parity gate open on
   * exactly those tables; the upsert reconciles them. See {@link copyStatementSql}.
   */
  readonly overwrite?: boolean;
}

export interface ControlBackfillTableResult {
  readonly table: string;
  /** Rows read from the source table. */
  readonly sourceRows: number;
  /**
   * Rows written at the destination — inserts, plus in-place updates when
   * `overwrite` is set. `0` on an idempotent `INSERT OR IGNORE` re-run.
   */
  readonly copied: number;
}

export interface ControlBackfillReport {
  readonly tables: readonly ControlBackfillTableResult[];
  /** Manifest tables absent from the source database, skipped rather than failed. */
  readonly skipped: readonly string[];
  readonly source: readonly ControlTableReceipt[];
  readonly destination: readonly ControlTableReceipt[];
  readonly comparison: ControlTableReceiptComparison;
  /** True iff every copied table's receipts match on both sides. */
  readonly ok: boolean;
}

const DEFAULT_PAGE_SIZE = 100;

function assertPositivePageSize(pageSize: number): number {
  if (!Number.isInteger(pageSize) || pageSize < 1) {
    throw new Error(`control backfill page size must be a positive integer, got ${pageSize}`);
  }
  return pageSize;
}

async function tableExists(db: D1Database, name: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(name)
    .first<{ present: number }>();
  return row !== null;
}

/** Column names of a table, in schema (`cid`) order, each re-validated. */
async function tableColumns(db: D1Database, name: string): Promise<string[]> {
  // `name` is already a validated manifest identifier; interpolation is safe and
  // PRAGMA does not accept a bound parameter for the table name.
  const { results } = await db.prepare(`PRAGMA table_info(${name})`).all<{ name: string }>();
  const columns = results.map((row) => row.name);
  if (columns.length === 0) {
    throw new Error(`control backfill found no columns for table ${name}`);
  }
  for (const column of columns) assertSafeIdentifier(column, "column");
  return columns;
}

function orderByClause(keyColumns: readonly string[]): string {
  return keyColumns.map((column) => `"${column}"`).join(", ");
}

function columnList(columns: readonly string[]): string {
  return columns.map((column) => `"${column}"`).join(", ");
}

/** Read one page of a table, ordered by its key, as canonical rows. */
async function readPage(
  db: D1Database,
  name: string,
  columns: readonly string[],
  keyColumns: readonly string[],
  pageSize: number,
  offset: number,
): Promise<CanonicalRow[]> {
  const { results } = await db
    .prepare(
      `SELECT ${columnList(columns)} FROM ${name} ` +
        `ORDER BY ${orderByClause(keyColumns)} LIMIT ? OFFSET ?`,
    )
    .bind(pageSize, offset)
    .all<Record<string, unknown>>();
  return results;
}

/**
 * The per-row write statement for one table.
 *
 * Default (`overwrite` false) is `INSERT OR IGNORE`: additive and idempotent by
 * primary key — the historic behavior, safe for an EMPTY destination.
 *
 * `overwrite` true switches to a true upsert: `INSERT … ON CONFLICT (<pk>) DO
 * UPDATE SET <non-key col> = excluded.<col>, …`. This is an in-place UPDATE that
 * touches no child rows — deliberately NOT `INSERT OR REPLACE`, whose delete+insert
 * would cascade through `ON DELETE` foreign keys. It is needed because the
 * destination `ControlDataObject` self-seeds a handful of rows on first wake
 * (`plans` 'free' in migration 0001; the `platform_billing_group_revisions`
 * counter in 0032/0033) whose migration-time values the live D1 has since
 * evolved — a same-key/different-value divergence `INSERT OR IGNORE` can never
 * reconcile. A table whose every column is a key column has nothing to update, so
 * it degrades to `ON CONFLICT DO NOTHING` — identical to the ignore path.
 */
function copyStatementSql(
  spec: ControlBackfillTable,
  columns: readonly string[],
  overwrite: boolean,
): string {
  const placeholders = columns.map(() => "?").join(", ");
  const columnsSql = columnList(columns);
  const insertHead = `INSERT INTO ${spec.name} (${columnsSql}) VALUES (${placeholders})`;
  if (!overwrite) {
    return `INSERT OR IGNORE INTO ${spec.name} (${columnsSql}) VALUES (${placeholders})`;
  }
  const keyColumns = new Set(spec.keyColumns);
  const setColumns = columns.filter((column) => !keyColumns.has(column));
  const conflictTarget = orderByClause(spec.keyColumns);
  if (setColumns.length === 0) {
    return `${insertHead} ON CONFLICT (${conflictTarget}) DO NOTHING`;
  }
  const assignments = setColumns.map((column) => `"${column}" = excluded."${column}"`).join(", ");
  return `${insertHead} ON CONFLICT (${conflictTarget}) DO UPDATE SET ${assignments}`;
}

/** Copy one table's rows page by page — additive by default, upsert when `overwrite`. */
async function copyTable(
  source: D1Database,
  destination: D1Database,
  spec: ControlBackfillTable,
  pageSize: number,
  overwrite: boolean,
): Promise<ControlBackfillTableResult> {
  const columns = await tableColumns(source, spec.name);
  const insertSql = copyStatementSql(spec, columns, overwrite);
  let sourceRows = 0;
  let copied = 0;
  for (let offset = 0; ; offset += pageSize) {
    const page = await readPage(source, spec.name, columns, spec.keyColumns, pageSize, offset);
    if (page.length === 0) break;
    sourceRows += page.length;
    const statements = page.map((row) =>
      destination.prepare(insertSql).bind(...columns.map((column) => row[column] ?? null)),
    );
    const results = await destination.batch(statements);
    for (const result of results) copied += result.meta?.changes ?? 0;
    if (page.length < pageSize) break;
  }
  return { table: spec.name, sourceRows, copied };
}

/** Rows read per page when computing a receipt; fixed so both backends chain identically. */
const RECEIPT_PAGE_SIZE = 500;

/** SHA-256 of a UTF-8 string, lower-case hex. */
async function sha256Hex(input: string): Promise<string> {
  const runtimeCrypto = (
    globalThis as unknown as {
      crypto?: { subtle: { digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer> } };
    }
  ).crypto;
  if (runtimeCrypto === undefined) {
    throw new Error("Web Crypto is required for control backfill receipts");
  }
  const digest = await runtimeCrypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/**
 * A row-count + checksum receipt for one table, or `undefined` if it is absent.
 *
 * The checksum is computed in a SINGLE STREAMING PASS: each primary-key-ordered
 * page is hashed with the tenant backfill's type-preserving row checksum, then
 * folded into a rolling SHA-256 chain. Peak memory is one {@link RECEIPT_PAGE_SIZE}
 * page rather than the whole table, so an unbounded append table (request_logs,
 * audit_events, billing_ledger, the usage rollups) is verified without
 * materialising millions of rows in the Worker heap. Because both backends read
 * the same key order in the same page size, the chain is deterministic and a
 * genuine divergence — a changed value that leaves the row count unchanged
 * included — is a reported mismatch.
 */
async function tableReceipt(
  db: D1Database,
  spec: ControlBackfillTable,
): Promise<ControlTableReceipt | undefined> {
  if (!(await tableExists(db, spec.name))) return undefined;
  const columns = await tableColumns(db, spec.name);
  let rowCount = 0;
  let chain = await sha256Hex(`ferrogate-control-backfill-receipt-v1:${spec.name}`);
  for (let offset = 0; ; offset += RECEIPT_PAGE_SIZE) {
    const page = await readPage(db, spec.name, columns, spec.keyColumns, RECEIPT_PAGE_SIZE, offset);
    if (page.length === 0) break;
    rowCount += page.length;
    const pageChecksum = await checksumRows(page, columns);
    chain = await sha256Hex(`${chain}|${offset}:${pageChecksum}`);
    if (page.length < RECEIPT_PAGE_SIZE) break;
  }
  return { table: spec.name, rowCount, checksum: chain };
}

/** Receipts for every manifest table present in a database, in manifest order. */
export async function controlBackfillReceipts(
  db: D1Database,
  tables: readonly ControlBackfillTable[] = CONTROL_BACKFILL_TABLES,
): Promise<ControlTableReceipt[]> {
  const receipts: ControlTableReceipt[] = [];
  for (const spec of tables) {
    const receipt = await tableReceipt(db, spec);
    if (receipt !== undefined) receipts.push(receipt);
  }
  return receipts;
}

/**
 * Copy the whole CONTROL database from `source` into `destination`, then verify.
 *
 * Tables absent from the source are recorded in `skipped` rather than failing,
 * so a source that predates a migration still completes AND still passes: the
 * verification is scoped to the tables that were actually present at the source,
 * so a manifest table the source lacks (which the freshly-migrated destination
 * has as an empty table) is NOT spuriously reported as `missing_source`. A table
 * that exists at the source but NOT the destination is still in that scope, so
 * it surfaces as a `missing_destination` mismatch. `ok` is the single boolean a
 * caller gates the cut-over on.
 */
export async function backfillControlData(
  source: D1Database,
  destination: D1Database,
  options: ControlBackfillOptions = {},
): Promise<ControlBackfillReport> {
  const pageSize = assertPositivePageSize(options.pageSize ?? DEFAULT_PAGE_SIZE);
  const overwrite = options.overwrite ?? false;
  const tables: ControlBackfillTableResult[] = [];
  const skipped: string[] = [];
  const presentTables: ControlBackfillTable[] = [];
  for (const spec of CONTROL_BACKFILL_TABLES) {
    if (!(await tableExists(source, spec.name))) {
      skipped.push(spec.name);
      continue;
    }
    presentTables.push(spec);
    tables.push(await copyTable(source, destination, spec, pageSize, overwrite));
  }
  // Verify only the tables the source actually had. A manifest table the source
  // predates is excluded from BOTH receipts, so it cannot become a spurious
  // `missing_source`; a source-present table missing at the destination is still
  // in scope and still surfaces as `missing_destination`.
  const sourceReceipts = await controlBackfillReceipts(source, presentTables);
  const destinationReceipts = await controlBackfillReceipts(destination, presentTables);
  const comparison = compareTableReceipts(sourceReceipts, destinationReceipts);
  return {
    tables,
    skipped,
    source: sourceReceipts,
    destination: destinationReceipts,
    comparison,
    ok: comparison.ok,
  };
}
