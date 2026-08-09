/**
 * Operator-controlled migration from the legacy shared tenant D1 into one
 * tenant Durable Object (#824).
 *
 * The control database is the durable coordinator. The shared D1 fence is the
 * write-side guard, and the object migration RPC is the only destination write
 * capability while the source is frozen. Every page is idempotent and records
 * its keyset cursor before the next page is attempted, so a Worker restart can
 * resume without guessing which rows were committed.
 */
import {
  TENANT_BACKFILL_TABLES,
  TENANT_JURISDICTIONS,
  TENANT_LOCATION_HINTS,
  type TenantBackfillTable,
  type TenantDataStatement,
  type TenantDataValue,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
  type TenantJurisdiction,
  type TenantLocationHint,
  type TenantMigrationMode,
  type TenantMigrationState,
  type TenantMigrationStatus,
  type TenantObjectAddress,
  type TenantTableReceipt,
  assertTenantMigrationTransition,
  checksumRows,
  compareTableReceipts,
  tenantJurisdictionForResidencyRegions,
} from "@ferrogate/storage";
import type { StoreRecord } from "../ports.js";
import { runControlPlaneMutationWithAudit } from "./d1.js";

const DEFAULT_PAGE_SIZE = 100;
const MAX_PAGE_SIZE = 500;
const DEFAULT_RETENTION_SECONDS = 30 * 24 * 60 * 60;
const MIGRATION_COLLECTION = "tenant_data_migrations";

export type TenantBackfillAction =
  | "start"
  | "resume"
  | "verify"
  | "cutover"
  | "rollback"
  | "status";

export interface TenantBackfillOptions {
  readonly controlDatabase: D1Database;
  readonly legacyTenantDatabase: D1Database;
  /** Must be the direct Durable Object router, not the state-dispatching router. */
  readonly destinationRouter: TenantDatabaseRouter;
  readonly tenantId: string;
  readonly action: TenantBackfillAction;
  /** Observed from tenant traffic; the migration job's own location is invalid. */
  readonly locationHint?: TenantLocationHint;
  readonly requestId?: string | null;
  readonly nowUnix?: number;
  readonly pageSize?: number;
  readonly retentionSeconds?: number;
}

export interface TenantBackfillResult {
  readonly object: "tenant_storage_migration";
  readonly tenant_id: string;
  readonly action: TenantBackfillAction;
  readonly migration_state: TenantMigrationState;
  readonly migration_epoch: number;
  readonly migration_frozen_at_unix: number | null;
  readonly migration_cutover_at_unix: number | null;
  readonly migration_retention_until_unix: number | null;
  readonly progress: TenantBackfillProgress;
  readonly receipt: TenantBackfillReceipt;
  readonly object_status: TenantMigrationStatus | null;
}

export class TenantBackfillError extends Error {
  override readonly name = "TenantBackfillError";

  constructor(
    readonly statusCode: 400 | 404 | 409 | 503,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

interface TenantBackfillRow {
  readonly tenant_id: string;
  readonly storage_backend: string | null;
  readonly binding_name: string | null;
  readonly location_hint: string | null;
  readonly location_hint_source: string | null;
  readonly location_hint_recorded_at_unix: number | null;
  readonly jurisdiction: string | null;
  readonly migration_state: string;
  readonly migration_epoch: number;
  readonly migration_frozen_at_unix: number | null;
  readonly migration_cutover_at_unix: number | null;
  readonly migration_retention_until_unix: number | null;
  readonly migration_last_error: string | null;
  readonly migration_receipt_json: string;
  readonly migration_progress_json: string;
}

export interface TenantBackfillProgress {
  readonly version: 1;
  readonly table_index: number;
  readonly cursor: readonly TenantDataValue[] | null;
  readonly copied_rows: number;
}

export interface TenantBackfillReceipt {
  readonly version: 1;
  readonly source: readonly TenantTableReceipt[];
  readonly destination: readonly TenantTableReceipt[];
  readonly object_write_epoch: number | null;
  readonly verified_at_unix: number | null;
}

interface MigrationDestination {
  forTenant(tenantId: string, address?: TenantObjectAddress): Promise<TenantDatabaseHandle>;
  migrationImport(
    tenantId: string,
    epoch: number,
    statements: readonly TenantDataStatement[],
    address?: TenantObjectAddress,
  ): Promise<void>;
  setMigrationMode(
    tenantId: string,
    mode: TenantMigrationMode,
    epoch: number,
    address?: TenantObjectAddress,
  ): Promise<TenantMigrationStatus>;
  migrationStatus(tenantId: string, address?: TenantObjectAddress): Promise<TenantMigrationStatus>;
}

const ROW_COLUMNS = [
  "tenant_id",
  "storage_backend",
  "binding_name",
  "location_hint",
  "location_hint_source",
  "location_hint_recorded_at_unix",
  "jurisdiction",
  "migration_state",
  "migration_epoch",
  "migration_frozen_at_unix",
  "migration_cutover_at_unix",
  "migration_retention_until_unix",
  "migration_last_error",
  "migration_receipt_json",
  "migration_progress_json",
].join(", ");

function asMigrationDestination(router: TenantDatabaseRouter): MigrationDestination {
  const candidate = router as TenantDatabaseRouter &
    Partial<Pick<MigrationDestination, "migrationImport" | "setMigrationMode" | "migrationStatus">>;
  if (
    typeof candidate.migrationImport !== "function" ||
    typeof candidate.setMigrationMode !== "function" ||
    typeof candidate.migrationStatus !== "function"
  ) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_unavailable",
      "the destination router does not expose the trusted Durable Object migration RPCs",
    );
  }
  return candidate as MigrationDestination;
}

function quotedIdentifier(value: string): string {
  if (!/^[a-z][a-z0-9_]*$/.test(value)) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      `unsafe identifier ${value}`,
    );
  }
  return `"${value}"`;
}

function tableName(table: TenantBackfillTable): string {
  return quotedIdentifier(table.name);
}

/**
 * D1 decodes SQLite INTEGER values as JS numbers. Select numeric values as
 * decimal text so an int64 wallet amount never crosses the 2^53 boundary as a
 * lossy double; BLOB and TEXT values keep their native D1 representation.
 */
function selectedColumn(alias: string, column: string): string {
  const reference = `${alias}.${quotedIdentifier(column)}`;
  return [
    `CASE typeof(${reference})`,
    `WHEN 'integer' THEN CAST(${reference} AS TEXT)`,
    `WHEN 'real' THEN CAST(${reference} AS TEXT)`,
    `ELSE ${reference}`,
    `END AS ${quotedIdentifier(column)}`,
  ].join(" ");
}

function parseState(value: string): TenantMigrationState {
  if (
    value !== "shared" &&
    value !== "copying" &&
    value !== "verifying" &&
    value !== "cut" &&
    value !== "done"
  ) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      `unknown migration state ${value}`,
    );
  }
  return value;
}

function parseProgress(value: string): TenantBackfillProgress {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration progress is invalid JSON",
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration progress is not an object",
    );
  }
  const candidate = parsed as Record<string, unknown>;
  if (Object.keys(candidate).length === 0) return emptyProgress();
  const tableIndex = candidate.table_index;
  const copiedRows = candidate.copied_rows;
  const cursor = candidate.cursor;
  if (
    candidate.version !== 1 ||
    typeof tableIndex !== "number" ||
    !Number.isSafeInteger(tableIndex) ||
    tableIndex < 0 ||
    typeof copiedRows !== "number" ||
    !Number.isSafeInteger(copiedRows) ||
    copiedRows < 0 ||
    (cursor !== null &&
      (!Array.isArray(cursor) ||
        cursor.some(
          (value) =>
            value !== null &&
            typeof value !== "string" &&
            typeof value !== "number" &&
            !(value instanceof ArrayBuffer),
        )))
  ) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration progress has invalid fields",
    );
  }
  return {
    version: 1,
    table_index: tableIndex,
    cursor: cursor as readonly TenantDataValue[] | null,
    copied_rows: copiedRows,
  };
}

function parseReceipt(value: string): TenantBackfillReceipt {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration receipt is invalid JSON",
    );
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration receipt is not an object",
    );
  }
  const candidate = parsed as Record<string, unknown>;
  if (Object.keys(candidate).length === 0) return emptyReceipt();
  if (
    candidate.version !== 1 ||
    !Array.isArray(candidate.source) ||
    !Array.isArray(candidate.destination) ||
    (candidate.object_write_epoch !== null && typeof candidate.object_write_epoch !== "number") ||
    (candidate.verified_at_unix !== null && typeof candidate.verified_at_unix !== "number")
  ) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      "migration receipt has invalid fields",
    );
  }
  const receipt = (items: unknown[]): TenantTableReceipt[] =>
    items.map((item) => {
      if (item === null || typeof item !== "object" || Array.isArray(item)) {
        throw new TenantBackfillError(
          503,
          "tenant_storage_migration_schema_error",
          "migration receipt table is invalid",
        );
      }
      const row = item as Record<string, unknown>;
      if (
        typeof row.table !== "string" ||
        typeof row.rowCount !== "number" ||
        !Number.isSafeInteger(row.rowCount) ||
        row.rowCount < 0 ||
        typeof row.checksum !== "string"
      ) {
        throw new TenantBackfillError(
          503,
          "tenant_storage_migration_schema_error",
          "migration receipt table fields are invalid",
        );
      }
      return { table: row.table, rowCount: row.rowCount, checksum: row.checksum };
    });
  return {
    version: 1,
    source: receipt(candidate.source),
    destination: receipt(candidate.destination),
    object_write_epoch: candidate.object_write_epoch as number | null,
    verified_at_unix: candidate.verified_at_unix as number | null,
  };
}

function emptyProgress(): TenantBackfillProgress {
  return { version: 1, table_index: 0, cursor: null, copied_rows: 0 };
}

function emptyReceipt(): TenantBackfillReceipt {
  return {
    version: 1,
    source: [],
    destination: [],
    object_write_epoch: null,
    verified_at_unix: null,
  };
}

async function readRow(db: D1Database, tenantId: string): Promise<TenantBackfillRow> {
  const row = await db
    .prepare(`SELECT ${ROW_COLUMNS} FROM tenant_databases WHERE tenant_id = ?`)
    .bind(tenantId)
    .first<TenantBackfillRow>();
  if (row === null) {
    throw new TenantBackfillError(
      404,
      "tenant_not_found",
      `tenant ${tenantId} is not registered in tenant_databases`,
    );
  }
  return row;
}

function requireBackfillLocationHint(value: TenantLocationHint | undefined): TenantLocationHint {
  if (value === undefined || !TENANT_LOCATION_HINTS.includes(value)) {
    throw new TenantBackfillError(
      400,
      "tenant_storage_migration_location_hint_required",
      "tenant storage backfill requires a location_hint observed from the tenant's traffic; the control-plane job location is not a valid substitute",
    );
  }
  return value;
}

function parseBackfillJurisdiction(value: string | null): TenantJurisdiction | undefined {
  if (value === null) return undefined;
  if (TENANT_JURISDICTIONS.includes(value as TenantJurisdiction))
    return value as TenantJurisdiction;
  throw new TenantBackfillError(
    503,
    "tenant_storage_migration_schema_error",
    `tenant row contains unsupported jurisdiction ${value}`,
  );
}

async function policyJurisdiction(
  db: D1Database,
  tenantId: string,
): Promise<TenantJurisdiction | undefined> {
  try {
    const row = await db
      .prepare(
        "SELECT residency_regions_json FROM quota_policies " +
          "WHERE scope_type = 'tenant' AND scope_id = ?",
      )
      .bind(tenantId)
      .first<{ residency_regions_json: string | null }>();
    if (row?.residency_regions_json === null || row?.residency_regions_json === undefined)
      return undefined;
    const parsed: unknown = JSON.parse(row.residency_regions_json);
    if (!Array.isArray(parsed)) return undefined;
    const regions = parsed.filter((entry): entry is string => typeof entry === "string");
    return tenantJurisdictionForResidencyRegions(regions);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    if (/no such (table|column):/i.test(detail)) return undefined;
    if (error instanceof SyntaxError) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        "tenant residency policy is invalid JSON",
      );
    }
    throw error;
  }
}

async function addressForBackfill(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
): Promise<{ readonly row: TenantBackfillRow; readonly address: TenantObjectAddress }> {
  const locationHint = requireBackfillLocationHint(options.locationHint);
  if (row.location_hint !== null && row.location_hint !== locationHint) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_location_conflict",
      `tenant ${row.tenant_id} is already recorded at location_hint ${row.location_hint}; changing the first placement decision requires a data migration`,
    );
  }
  if (
    row.location_hint !== null &&
    !TENANT_LOCATION_HINTS.includes(row.location_hint as TenantLocationHint)
  ) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      `tenant row contains unsupported location_hint ${row.location_hint}`,
    );
  }
  const policy = await policyJurisdiction(options.controlDatabase, row.tenant_id);
  const recorded = parseBackfillJurisdiction(row.jurisdiction);
  if (recorded !== undefined && policy !== undefined && recorded !== policy) {
    throw new TenantBackfillError(
      409,
      "tenant_jurisdiction_migration_required",
      `tenant ${row.tenant_id} records jurisdiction ${recorded}, but its residency policy requires ${policy}; changing the jurisdiction is part of the object address and requires a data migration`,
    );
  }
  const jurisdiction = recorded ?? policy;
  if (
    row.location_hint === null ||
    row.location_hint_source === null ||
    row.location_hint_recorded_at_unix === null ||
    (row.jurisdiction === null && jurisdiction !== undefined)
  ) {
    await options.controlDatabase
      .prepare(
        `UPDATE tenant_databases SET
           location_hint = COALESCE(location_hint, ?),
           location_hint_source = COALESCE(location_hint_source, ?),
           location_hint_recorded_at_unix = COALESCE(location_hint_recorded_at_unix, ?),
           jurisdiction = COALESCE(jurisdiction, ?),
           updated_at_unix = unixepoch()
         WHERE tenant_id = ?`,
      )
      .bind(
        locationHint,
        "backfill:observed tenant traffic",
        options.nowUnix ?? Math.floor(Date.now() / 1000),
        jurisdiction ?? null,
        row.tenant_id,
      )
      .run();
  }
  const refreshed = await readRow(options.controlDatabase, row.tenant_id);
  const refreshedJurisdiction = parseBackfillJurisdiction(refreshed.jurisdiction);
  return {
    row: refreshed,
    address: {
      locationHint,
      ...(refreshedJurisdiction === undefined ? {} : { jurisdiction: refreshedJurisdiction }),
    },
  };
}

function objectAddressForRow(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
): TenantObjectAddress {
  const locationHint = requireBackfillLocationHint(options.locationHint);
  if (row.location_hint !== locationHint) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_location_conflict",
      `tenant ${row.tenant_id} has no matching recorded location_hint for this backfill`,
    );
  }
  const jurisdiction = parseBackfillJurisdiction(row.jurisdiction);
  return {
    locationHint,
    ...(jurisdiction === undefined ? {} : { jurisdiction }),
  };
}

function decodeRow(row: TenantBackfillRow): {
  readonly state: TenantMigrationState;
  readonly progress: TenantBackfillProgress;
  readonly receipt: TenantBackfillReceipt;
} {
  return {
    state: parseState(row.migration_state),
    progress: parseProgress(row.migration_progress_json),
    receipt: parseReceipt(row.migration_receipt_json),
  };
}

async function transitionWithAudit(
  db: D1Database,
  row: TenantBackfillRow,
  to: TenantMigrationState,
  epoch: number,
  requestId: string | null | undefined,
  nowUnix: number,
  fields: Readonly<Record<string, string | number | null>> = {},
): Promise<TenantBackfillRow> {
  const from = parseState(row.migration_state);
  assertTenantMigrationTransition(from, to);
  const assignments = ["migration_state = ?", "migration_epoch = ?"];
  const values: Array<string | number | null> = [to, epoch];
  for (const [column, value] of Object.entries(fields)) {
    if (
      !/^(storage_backend|binding_name|migration_frozen_at_unix|migration_cutover_at_unix|migration_retention_until_unix|migration_last_error|migration_receipt_json|migration_progress_json)$/.test(
        column,
      )
    ) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        `unsafe migration column ${column}`,
      );
    }
    assignments.push(`${column} = ?`);
    values.push(value);
  }
  values.push(row.tenant_id, from, row.migration_epoch);
  const record: StoreRecord = {
    id: `${row.tenant_id}:${epoch}:${to}`,
    tenant_id: row.tenant_id,
    from_state: from,
    to_state: to,
    migration_epoch: epoch,
  };
  const changed = await runControlPlaneMutationWithAudit(
    db,
    () =>
      db
        .prepare(
          `UPDATE tenant_databases SET ${assignments.join(", ")}, updated_at_unix = unixepoch()
           WHERE tenant_id = ? AND migration_state = ? AND migration_epoch = ?`,
        )
        .bind(...values),
    {
      action: "merge",
      collection: MIGRATION_COLLECTION,
      record,
      revision: epoch,
      scope: { kind: "platform_operator" },
      requestId,
      newId: () => `tenant-storage-migration:${row.tenant_id}:${epoch}:${from}:${to}`,
      now: () => nowUnix,
      auditJson: JSON.stringify({
        object: "tenant_storage_migration",
        action: "transition",
        tenant_id: row.tenant_id,
        from,
        to,
        migration_epoch: epoch,
      }),
    },
  );
  if (!changed) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_conflict",
      "tenant migration state changed; retry the operation",
    );
  }
  return readRow(db, row.tenant_id);
}

async function recordError(db: D1Database, row: TenantBackfillRow, error: unknown): Promise<void> {
  const message = error instanceof Error ? error.message : String(error);
  await db
    .prepare(
      `UPDATE tenant_databases SET migration_last_error = ?, updated_at_unix = unixepoch()
       WHERE tenant_id = ? AND migration_state = ? AND migration_epoch = ?`,
    )
    .bind(message.slice(0, 4000), row.tenant_id, row.migration_state, row.migration_epoch)
    .run();
}

async function freezeSource(
  db: D1Database,
  tenantId: string,
  epoch: number,
  nowUnix: number,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO tenant_write_fences (tenant_id, migration_epoch, mode, updated_at_unix)
       VALUES (?, ?, 'frozen', ?)
       ON CONFLICT (tenant_id) DO UPDATE SET
         migration_epoch = excluded.migration_epoch,
         mode = 'frozen',
         updated_at_unix = excluded.updated_at_unix`,
    )
    .bind(tenantId, epoch, nowUnix)
    .run();
}

async function openSource(
  db: D1Database,
  tenantId: string,
  epoch: number,
  nowUnix: number,
): Promise<void> {
  await db
    .prepare(
      `UPDATE tenant_write_fences SET mode = 'open', updated_at_unix = ?
       WHERE tenant_id = ? AND migration_epoch = ?`,
    )
    .bind(nowUnix, tenantId, epoch)
    .run();
}

async function readColumns(db: D1Database, table: TenantBackfillTable): Promise<string[]> {
  const result = await db.prepare(`PRAGMA table_info(${tableName(table)})`).all<{ name: string }>();
  const columns = result.results.map((row) => row.name);
  if (columns.length === 0) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      `table ${table.name} is missing from a tenant database`,
    );
  }
  if (new Set(columns).size !== columns.length) {
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_schema_error",
      `table ${table.name} has duplicate columns`,
    );
  }
  for (const key of table.keyColumns) {
    if (!columns.includes(key)) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        `table ${table.name} is missing key column ${key}`,
      );
    }
  }
  return columns;
}

function pageQuery(
  table: TenantBackfillTable,
  columns: readonly string[],
  tenantId: string,
  cursor: readonly TenantDataValue[] | null,
  pageSize: number,
): { readonly sql: string; readonly params: unknown[] } {
  const select = columns.map((column) => selectedColumn("t", column)).join(", ");
  const order = table.keyColumns.map((column) => `t.${quotedIdentifier(column)}`).join(", ");
  const params: unknown[] = Array.from({ length: table.ownership.parameterCount }, () => tenantId);
  let cursorPredicate = "";
  if (cursor !== null) {
    if (cursor.length !== table.keyColumns.length) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        `cursor for ${table.name} has the wrong arity`,
      );
    }
    const terms: string[] = [];
    for (let index = 0; index < table.keyColumns.length; index += 1) {
      const equal = table.keyColumns
        .slice(0, index)
        .map((column) => `t.${quotedIdentifier(column)} = ?`)
        .join(" AND ");
      terms.push(
        `(${equal}${equal === "" ? "" : " AND "}t.${quotedIdentifier(table.keyColumns[index] as string)} > ?)`,
      );
      params.push(...cursor.slice(0, index), cursor[index] as TenantDataValue);
    }
    cursorPredicate = ` AND (${terms.join(" OR ")})`;
  }
  params.push(pageSize);
  return {
    sql: `SELECT ${select} FROM ${tableName(table)} AS t WHERE (${table.ownership.whereSql})${cursorPredicate} ORDER BY ${order} LIMIT ?`,
    params,
  };
}

function toTenantValue(value: unknown, table: string, column: string): TenantDataValue {
  if (value === null || typeof value === "string" || typeof value === "number") return value;
  if (typeof value === "bigint") return value.toString(10);
  if (value instanceof ArrayBuffer) return value;
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
  }
  throw new TenantBackfillError(
    503,
    "tenant_storage_migration_value_error",
    `unsupported value in ${table}.${column}`,
  );
}

function importStatements(
  table: TenantBackfillTable,
  columns: readonly string[],
  rows: readonly Record<string, unknown>[],
): TenantDataStatement[] {
  const names = columns.map(quotedIdentifier).join(", ");
  const placeholders = columns.map(() => "?").join(", ");
  const sql = `INSERT INTO ${tableName(table)} (${names}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;
  return rows.map((row) => ({
    sql,
    params: columns.map((column) => {
      if (!Object.prototype.hasOwnProperty.call(row, column)) {
        throw new TenantBackfillError(
          503,
          "tenant_storage_migration_value_error",
          `source row for ${table.name} is missing ${column}`,
        );
      }
      return toTenantValue(row[column], table.name, column);
    }),
  }));
}

async function saveProgress(
  db: D1Database,
  row: TenantBackfillRow,
  progress: TenantBackfillProgress,
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE tenant_databases SET migration_progress_json = ?, migration_last_error = NULL, updated_at_unix = unixepoch()
       WHERE tenant_id = ? AND migration_state = 'copying' AND migration_epoch = ?`,
    )
    .bind(JSON.stringify(progress), row.tenant_id, row.migration_epoch)
    .run();
  if ((result.meta.changes ?? 0) !== 1) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_conflict",
      "migration progress could not be recorded; retry",
    );
  }
}

async function copyTables(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
  destination: MigrationDestination,
  progress: TenantBackfillProgress,
  pageSize: number,
): Promise<void> {
  const address = objectAddressForRow(options, row);
  const handle = await destination.forTenant(options.tenantId, address);
  const destinationDb = handle.db;
  let current = progress;
  for (
    let tableIndex = current.table_index;
    tableIndex < TENANT_BACKFILL_TABLES.length;
    tableIndex += 1
  ) {
    const table = TENANT_BACKFILL_TABLES[tableIndex] as TenantBackfillTable;
    if (table.ownership.kind === "unresolved") {
      const count = await options.legacyTenantDatabase
        .prepare(`SELECT COUNT(*) AS count FROM ${tableName(table)}`)
        .first<{ count: number }>();
      if ((count?.count ?? 0) !== 0) {
        throw new TenantBackfillError(
          409,
          "tenant_storage_migration_unowned_rows",
          `table ${table.name} contains rows without a safe tenant ownership predicate`,
        );
      }
      current = {
        version: 1,
        table_index: tableIndex + 1,
        cursor: null,
        copied_rows: current.copied_rows,
      };
      await saveProgress(options.controlDatabase, row, current);
      continue;
    }

    const sourceColumns = await readColumns(options.legacyTenantDatabase, table);
    const destinationColumns = await readColumns(destinationDb, table);
    if (sourceColumns.join("\u0000") !== destinationColumns.join("\u0000")) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        `source and destination schemas differ for ${table.name}`,
      );
    }
    let cursor = tableIndex === current.table_index ? current.cursor : null;
    let copied = tableIndex === current.table_index ? current.copied_rows : 0;
    for (;;) {
      const page = pageQuery(table, sourceColumns, options.tenantId, cursor, pageSize);
      const sourceRows = (
        await options.legacyTenantDatabase
          .prepare(page.sql)
          .bind(...page.params)
          .all<Record<string, unknown>>()
      ).results;
      if (sourceRows.length === 0) break;
      await destination.migrationImport(
        options.tenantId,
        row.migration_epoch,
        importStatements(table, sourceColumns, sourceRows),
        address,
      );
      const last = sourceRows[sourceRows.length - 1] as Record<string, unknown>;
      cursor = table.keyColumns.map((column) => toTenantValue(last[column], table.name, column));
      copied += sourceRows.length;
      current = { version: 1, table_index: tableIndex, cursor, copied_rows: copied };
      await saveProgress(options.controlDatabase, row, current);
      if (sourceRows.length < pageSize) break;
    }
    current = { version: 1, table_index: tableIndex + 1, cursor: null, copied_rows: copied };
    await saveProgress(options.controlDatabase, row, current);
  }
}

async function receiptForTable(
  db: D1Database,
  table: TenantBackfillTable,
  tenantId: string,
  columns: readonly string[],
): Promise<TenantTableReceipt> {
  if (table.ownership.kind === "unresolved") {
    const count = await db
      .prepare(`SELECT COUNT(*) AS count FROM ${tableName(table)}`)
      .first<{ count: number }>();
    if ((count?.count ?? 0) !== 0) {
      throw new TenantBackfillError(
        409,
        "tenant_storage_migration_unowned_rows",
        `table ${table.name} contains rows without a safe tenant ownership predicate`,
      );
    }
    return { table: table.name, rowCount: 0, checksum: await checksumRows([], columns) };
  }
  const select = columns.map((column) => selectedColumn("t", column)).join(", ");
  const params = Array.from({ length: table.ownership.parameterCount }, () => tenantId);
  const rows = (
    await db
      .prepare(`SELECT ${select} FROM ${tableName(table)} AS t WHERE (${table.ownership.whereSql})`)
      .bind(...params)
      .all<Record<string, unknown>>()
  ).results;
  return { table: table.name, rowCount: rows.length, checksum: await checksumRows(rows, columns) };
}

async function verifyTables(
  options: TenantBackfillOptions,
  destination: MigrationDestination,
): Promise<{
  readonly source: TenantTableReceipt[];
  readonly destination: TenantTableReceipt[];
  readonly objectWriteEpoch: number;
}> {
  const row = await readRow(options.controlDatabase, options.tenantId);
  const address = objectAddressForRow(options, row);
  const handle = await destination.forTenant(options.tenantId, address);
  const source: TenantTableReceipt[] = [];
  const target: TenantTableReceipt[] = [];
  for (const table of TENANT_BACKFILL_TABLES) {
    const sourceColumns = await readColumns(options.legacyTenantDatabase, table);
    const destinationColumns = await readColumns(handle.db, table);
    if (sourceColumns.join("\u0000") !== destinationColumns.join("\u0000")) {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_schema_error",
        `source and destination schemas differ for ${table.name}`,
      );
    }
    source.push(
      await receiptForTable(options.legacyTenantDatabase, table, options.tenantId, sourceColumns),
    );
    target.push(await receiptForTable(handle.db, table, options.tenantId, destinationColumns));
  }
  const status = await destination.migrationStatus(options.tenantId, address);
  const comparison = compareTableReceipts(source, target);
  if (!comparison.ok) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_verification_failed",
      JSON.stringify(comparison.mismatches),
    );
  }
  return { source, destination: target, objectWriteEpoch: status.writeEpoch };
}

async function assertSourceReceiptUnchanged(
  options: TenantBackfillOptions,
  expected: readonly TenantTableReceipt[],
): Promise<void> {
  const current: TenantTableReceipt[] = [];
  for (const table of TENANT_BACKFILL_TABLES) {
    const columns = await readColumns(options.legacyTenantDatabase, table);
    current.push(
      await receiptForTable(options.legacyTenantDatabase, table, options.tenantId, columns),
    );
  }
  const comparison = compareTableReceipts(expected, current);
  if (!comparison.ok) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_source_changed",
      JSON.stringify(comparison.mismatches),
    );
  }
}

async function startMigration(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
  destination: MigrationDestination,
  nowUnix: number,
): Promise<TenantBackfillRow> {
  const address = objectAddressForRow(options, row);
  const decoded = decodeRow(row);
  if (decoded.state !== "shared") return row;
  const epoch = row.migration_epoch === 0 ? 1 : row.migration_epoch;
  const objectStatus = await destination.migrationStatus(options.tenantId, address);
  const adoptingFreshObject =
    objectStatus.mode === "done" && objectStatus.epoch === 0 && epoch === 1;
  if (
    (!adoptingFreshObject && objectStatus.epoch !== epoch) ||
    (objectStatus.epoch === epoch && (objectStatus.mode === "cut" || objectStatus.mode === "done"))
  ) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_state_conflict",
      `control row is shared@${row.migration_epoch}, but the Durable Object is ${objectStatus.mode}@${objectStatus.epoch}`,
    );
  }
  await freezeSource(options.legacyTenantDatabase, options.tenantId, epoch, nowUnix);
  if (adoptingFreshObject)
    await destination.setMigrationMode(options.tenantId, "shared", epoch, address);
  if (objectStatus.mode === "done" || objectStatus.mode === "shared") {
    await destination.setMigrationMode(options.tenantId, "copying", epoch, address);
  }
  return transitionWithAudit(
    options.controlDatabase,
    row,
    "copying",
    epoch,
    options.requestId,
    nowUnix,
    {
      migration_frozen_at_unix: row.migration_frozen_at_unix ?? nowUnix,
      migration_last_error: null,
      migration_progress_json: JSON.stringify(emptyProgress()),
      migration_receipt_json: JSON.stringify(emptyReceipt()),
    },
  );
}

async function verifyMigration(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
  destination: MigrationDestination,
  nowUnix: number,
): Promise<TenantBackfillRow> {
  const address = objectAddressForRow(options, row);
  const decoded = decodeRow(row);
  let current = row;
  if (decoded.state === "copying") {
    await copyTables(
      options,
      row,
      destination,
      decoded.progress,
      normalizePageSize(options.pageSize),
    );
    const objectStatus = await destination.setMigrationMode(
      options.tenantId,
      "verifying",
      row.migration_epoch,
      address,
    );
    if (objectStatus.mode !== "verifying") {
      throw new TenantBackfillError(
        503,
        "tenant_storage_migration_unavailable",
        "Durable Object did not enter verifying mode",
      );
    }
    current = await transitionWithAudit(
      options.controlDatabase,
      row,
      "verifying",
      row.migration_epoch,
      options.requestId,
      nowUnix,
      {
        migration_last_error: null,
      },
    );
  }
  const verified = await verifyTables(options, destination);
  const receipt: TenantBackfillReceipt = {
    version: 1,
    source: verified.source,
    destination: verified.destination,
    object_write_epoch: verified.objectWriteEpoch,
    verified_at_unix: nowUnix,
  };
  await options.controlDatabase
    .prepare(
      `UPDATE tenant_databases SET migration_receipt_json = ?, migration_last_error = NULL, updated_at_unix = ?
       WHERE tenant_id = ? AND migration_state = 'verifying' AND migration_epoch = ?`,
    )
    .bind(JSON.stringify(receipt), nowUnix, options.tenantId, current.migration_epoch)
    .run();
  return readRow(options.controlDatabase, options.tenantId);
}

async function cutoverMigration(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
  destination: MigrationDestination,
  nowUnix: number,
): Promise<TenantBackfillRow> {
  const address = objectAddressForRow(options, row);
  const decoded = decodeRow(row);
  if (decoded.receipt.object_write_epoch === null) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_not_verified",
      "cutover requires a completed verification receipt",
    );
  }

  if (decoded.state === "cut") {
    const status = await destination.migrationStatus(options.tenantId, address);
    if (status.mode !== "cut" && status.mode !== "done") {
      throw new TenantBackfillError(
        409,
        "tenant_storage_migration_state_conflict",
        `control row is cut, but the Durable Object is ${status.mode}`,
      );
    }
    if (status.mode === "cut")
      await destination.setMigrationMode(options.tenantId, "done", row.migration_epoch, address);
    return transitionWithAudit(
      options.controlDatabase,
      row,
      "done",
      row.migration_epoch,
      options.requestId,
      nowUnix,
      {
        migration_last_error: null,
      },
    );
  }

  if (decoded.state !== "verifying") {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_not_ready",
      `cutover requires verifying state, found ${decoded.state}`,
    );
  }

  await assertSourceReceiptUnchanged(options, decoded.receipt.source);
  const status = await destination.migrationStatus(options.tenantId, address);
  if (status.mode === "cut" || status.mode === "done") {
    const current = await transitionWithAudit(
      options.controlDatabase,
      row,
      "cut",
      row.migration_epoch,
      options.requestId,
      nowUnix,
      {
        storage_backend: "durable_object",
        migration_cutover_at_unix: row.migration_cutover_at_unix ?? nowUnix,
        migration_retention_until_unix:
          row.migration_retention_until_unix ??
          nowUnix + (options.retentionSeconds ?? DEFAULT_RETENTION_SECONDS),
        migration_last_error: null,
      },
    );
    return cutoverMigration(options, current, destination, nowUnix);
  }
  if (status.mode !== "verifying" || status.writeEpoch !== decoded.receipt.object_write_epoch) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_write_detected",
      "the Durable Object changed after verification; re-run verify",
    );
  }
  await destination.setMigrationMode(options.tenantId, "cut", row.migration_epoch, address);
  const retention = nowUnix + (options.retentionSeconds ?? DEFAULT_RETENTION_SECONDS);
  const current = await transitionWithAudit(
    options.controlDatabase,
    row,
    "cut",
    row.migration_epoch,
    options.requestId,
    nowUnix,
    {
      storage_backend: "durable_object",
      migration_cutover_at_unix: nowUnix,
      migration_retention_until_unix: retention,
      migration_last_error: null,
    },
  );
  return cutoverMigration(options, current, destination, nowUnix);
}

async function rollbackMigration(
  options: TenantBackfillOptions,
  row: TenantBackfillRow,
  destination: MigrationDestination,
  nowUnix: number,
): Promise<TenantBackfillRow> {
  const address = objectAddressForRow(options, row);
  const decoded = decodeRow(row);
  if (decoded.state === "shared") {
    if (
      row.migration_epoch === 0 ||
      row.migration_frozen_at_unix === null ||
      row.storage_backend !== "native_binding"
    ) {
      throw new TenantBackfillError(
        409,
        "tenant_storage_migration_not_cutover",
        "rollback requires a completed cutover or an interrupted rollback",
      );
    }
    const status = await destination.migrationStatus(options.tenantId, address);
    if (status.mode !== "shared" || status.epoch !== row.migration_epoch) {
      throw new TenantBackfillError(
        409,
        "tenant_storage_migration_state_conflict",
        `control row is shared@${row.migration_epoch}, but the Durable Object is ${status.mode}@${status.epoch}`,
      );
    }
    await openSource(
      options.legacyTenantDatabase,
      options.tenantId,
      row.migration_epoch - 1,
      nowUnix,
    );
    return row;
  }
  if (decoded.state !== "cut" && decoded.state !== "done") {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_not_cutover",
      `rollback requires cut or done state, found ${decoded.state}`,
    );
  }
  if (row.migration_retention_until_unix !== null && nowUnix > row.migration_retention_until_unix) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_retention_expired",
      "rollback retention has expired; the shared source is no longer a rollback target",
    );
  }
  if (decoded.receipt.object_write_epoch === null) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_not_verified",
      "rollback requires the verification receipt",
    );
  }
  const status = await destination.migrationStatus(options.tenantId, address);
  if (status.writeEpoch !== decoded.receipt.object_write_epoch) {
    throw new TenantBackfillError(
      409,
      "tenant_storage_migration_write_detected",
      "rollback refused because the Durable Object has accepted writes after cutover",
    );
  }
  const nextEpoch = row.migration_epoch + 1;
  await destination.setMigrationMode(options.tenantId, "shared", nextEpoch, address);
  const current = await transitionWithAudit(
    options.controlDatabase,
    row,
    "shared",
    nextEpoch,
    options.requestId,
    nowUnix,
    {
      storage_backend: "native_binding",
      migration_cutover_at_unix: null,
      migration_last_error: null,
      migration_progress_json: JSON.stringify(emptyProgress()),
      migration_receipt_json: JSON.stringify(emptyReceipt()),
    },
  );
  await openSource(options.legacyTenantDatabase, options.tenantId, nextEpoch - 1, nowUnix);
  return current;
}

function normalizePageSize(value: number | undefined): number {
  if (value === undefined) return DEFAULT_PAGE_SIZE;
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_PAGE_SIZE) {
    throw new TenantBackfillError(
      400,
      "invalid_page_size",
      `page_size must be an integer between 1 and ${MAX_PAGE_SIZE}`,
    );
  }
  return value;
}

function result(
  action: TenantBackfillAction,
  row: TenantBackfillRow,
  objectStatus: TenantMigrationStatus | null,
): TenantBackfillResult {
  const decoded = decodeRow(row);
  return {
    object: "tenant_storage_migration",
    tenant_id: row.tenant_id,
    action,
    migration_state: decoded.state,
    migration_epoch: row.migration_epoch,
    migration_frozen_at_unix: row.migration_frozen_at_unix,
    migration_cutover_at_unix: row.migration_cutover_at_unix,
    migration_retention_until_unix: row.migration_retention_until_unix,
    progress: decoded.progress,
    receipt: decoded.receipt,
    object_status: objectStatus,
  };
}

/** Execute one explicit operator action; no request path invokes this implicitly. */
export async function runTenantStorageMigration(
  options: TenantBackfillOptions,
): Promise<TenantBackfillResult> {
  if (options.tenantId.trim() === "") {
    throw new TenantBackfillError(404, "tenant_not_found", "tenant_id must not be empty");
  }
  requireBackfillLocationHint(options.locationHint);
  const nowUnix = options.nowUnix ?? Math.floor(Date.now() / 1000);
  let row = await readRow(options.controlDatabase, options.tenantId);
  const placement = await addressForBackfill(options, row);
  row = placement.row;
  const destination = asMigrationDestination(options.destinationRouter);
  try {
    if (options.action === "status") {
      return result(
        options.action,
        row,
        await destination.migrationStatus(options.tenantId, placement.address),
      );
    }
    if (options.action === "start") {
      row = await startMigration(options, row, destination, nowUnix);
      return result(
        options.action,
        row,
        await destination.migrationStatus(options.tenantId, placement.address),
      );
    }
    if (options.action === "resume") {
      if (parseState(row.migration_state) === "shared")
        row = await startMigration(options, row, destination, nowUnix);
      const state = parseState(row.migration_state);
      if (state === "copying") {
        row = await verifyMigration(options, row, destination, nowUnix);
      }
      if (parseState(row.migration_state) === "verifying") {
        const objectStatus = await destination.migrationStatus(options.tenantId, placement.address);
        row =
          objectStatus.mode === "cut" || objectStatus.mode === "done"
            ? await cutoverMigration(options, row, destination, nowUnix)
            : await verifyMigration(options, row, destination, nowUnix);
      }
      if (parseState(row.migration_state) === "cut")
        row = await cutoverMigration(options, row, destination, nowUnix);
      return result(
        options.action,
        row,
        await destination.migrationStatus(options.tenantId, placement.address),
      );
    }
    if (options.action === "verify") {
      if (parseState(row.migration_state) === "shared")
        row = await startMigration(options, row, destination, nowUnix);
      row = await verifyMigration(options, row, destination, nowUnix);
      return result(
        options.action,
        row,
        await destination.migrationStatus(options.tenantId, placement.address),
      );
    }
    if (options.action === "cutover") {
      row = await cutoverMigration(options, row, destination, nowUnix);
      return result(
        options.action,
        row,
        await destination.migrationStatus(options.tenantId, placement.address),
      );
    }
    row = await rollbackMigration(options, row, destination, nowUnix);
    return result(
      options.action,
      row,
      await destination.migrationStatus(options.tenantId, placement.address),
    );
  } catch (error) {
    await recordError(options.controlDatabase, row, error).catch(() => undefined);
    if (error instanceof TenantBackfillError) throw error;
    throw new TenantBackfillError(
      503,
      "tenant_storage_migration_failed",
      error instanceof Error ? error.message : String(error),
    );
  }
}
