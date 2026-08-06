/**
 * `TenantDataObject` — a SQLite-backed Durable Object that **is** one tenant's
 * database (issue #822, `docs/design/per-tenant-durable-object-storage-2026-08.md`).
 *
 * ## Why this is the default tenant data plane
 *
 * A native D1 binding is retained for explicit single-tenant and self-hosted
 * compatibility, but it requires deploy-time binding configuration. The
 * Durable Object namespace is addressed at runtime by tenant id, has no
 * per-tenant deploy step, and provides the transaction boundary required by
 * the money paths.
 *
 * A SQLite-backed Durable Object carries its own embedded database.
 * `env.TENANT_DATA.idFromName(tenantId)` addresses a tenant's database at
 * RUNTIME — unlimited instances, no deploy, 10 GB each — and
 * `ctx.storage.transactionSync()` is a real SQLite transaction that rolls back
 * on throw, which keeps every tenant-local guarded write atomic.
 *
 * ## This is the fleet's FIRST `ctx.storage.sql` user — read this before editing
 *
 * The repo already ships eight `new_sqlite_classes` DO classes, but every one of
 * them uses the KEY-VALUE storage API (`ctx.storage.get/put/list`) on top of the
 * SQLite backend. `new_sqlite_classes` selects the storage BACKEND, not the SQL
 * API. So the wrangler discipline, the `src/worker.ts` re-export rule and the
 * test harness shape are all proven in-repo, and the SQL API is not. The
 * platform rules this file is written against, verified against Cloudflare's
 * docs on 2026-08-04 and re-verified empirically under this repo's workerd:
 *
 *  1. `ctx.storage.sql.exec(query, ...bindings)` is **synchronous** and returns
 *     a cursor. Bindings apply only to the LAST statement of a multi-statement
 *     string — which is why {@link sqlStatements} splits and the applier loops,
 *     rather than handing a whole file to one `exec()`.
 *  2. A cursor held across an `await` has no isolation guarantee: it may observe
 *     rows from a transaction that later rolls back. **Every cursor in this file
 *     is drained with `.toArray()` in the same synchronous stretch that opened
 *     it**, and no `await` appears inside any `transactionSync` callback.
 *  3. `exec()` cannot run `BEGIN`/`SAVEPOINT`. `transactionSync(cb)` is the only
 *     transaction, and `cb` must be non-async and must not return a Promise.
 *  4. `ctx.blockConcurrencyWhile(cb)` delivers no RPC until `cb` settles, which
 *     is how a request is kept from observing a half-migrated database.
 *
 * ## What this object deliberately does NOT do
 *
 * It exposes `query` / `batch` / schema and schedule-alarm RPCs. The
 * `D1Database`-shaped facade that lets the 14 modules under `src/d1/` port
 * unchanged (`prepare().bind().first()/all()/run()`, `meta.changes`, the
 * `durable_object` `TenantDatabaseSource`) is a separate slice; this one
 * establishes the object, its schema and its isolation guard.
 *
 * There is no `fetch()` surface: every method is RPC over the binding, so the
 * object is not addressable from the internet.
 */
import { DurableObject } from "cloudflare:workers";
import { AUDIT_CHAIN_GENESIS_HASH, auditChainKey, auditRowHash } from "./audit-chain.js";
import {
  type TenantScheduleAlarmMessage,
  decodeTenantScheduleAlarm,
  encodeTenantScheduleAlarm,
  tenantScheduleAlarmMessage,
} from "./tenant-schedule-alarm.js";
import {
  TENANT_MIGRATIONS,
  TENANT_SCHEMA_VERSION,
  type TenantMigration,
} from "./tenant-schema-sql.js";

/**
 * The value domain SQLite accepts and returns through `sql.exec`.
 *
 * Narrower than it looks and deliberately so: it excludes `boolean`, `bigint`
 * and `undefined`. The repo already normalizes at the edge — `boolToSqlite()`
 * and `bindOptional()` in `src/d1/rows.ts` — and credit columns that can exceed
 * 2^53 cross as decimal STRINGS via `bindCredits()` / `creditsFromText()`
 * (`src/credits.ts`), because `bind(<bigint>)` throws and the `number` form
 * drifts. Widening this type would quietly re-open that decode.
 */
export type TenantDataValue = ArrayBuffer | string | number | null;

/** One statement and its positional bindings, forwarded to `sql.exec` verbatim. */
export interface TenantDataStatement {
  readonly sql: string;
  /**
   * Bindings, forwarded UNCHANGED and in order.
   *
   * Never renumbered and never counted: `apps/gateway/src/assets/d1.ts` alone
   * uses 106 ordinal placeholders with REUSE (`?2` three times, `?9` and `?16`
   * twice in one statement), so any transform that derives arity by counting
   * `?` characters breaks a live money path.
   */
  readonly params?: readonly TenantDataValue[];
}

/** An RPC carrying the caller's tenant id — see {@link TenantDataObject.query}. */
export interface TenantDataQueryRequest extends TenantDataStatement {
  /** The tenant this caller believes it is addressing. Checked, not trusted. */
  readonly tenantId: string;
}

/** A control-plane operator read, kept off the tenant-facing D1 facade. */
export interface TenantDataOperatorQueryRequest extends TenantDataStatement {
  readonly tenantId: string;
  /** Stable id used to make the audit append safe to retry. */
  readonly auditId: string;
  readonly requestId: string;
  /** Operator identity, never a bearer secret. */
  readonly operator: string;
  readonly occurredAtUnix: number;
}

export interface TenantDataOperatorQueryResult extends TenantDataResult {
  readonly rowCount: number;
  readonly auditId: string;
}

/** One resumable page of the object export. The format is deliberately JSONL. */
export interface TenantDataExportPageRequest {
  readonly tenantId: string;
  readonly exportId: string;
  readonly cursor: string | null;
  readonly pageSize: number;
  readonly auditId: string;
  readonly requestId: string;
  readonly operator: string;
  readonly occurredAtUnix: number;
}

export interface TenantDataExportPageResult {
  readonly exportId: string;
  readonly jsonl: string;
  readonly rowCount: number;
  readonly nextCursor: string | null;
  readonly done: boolean;
  readonly auditId: string;
}

/** A point-in-time restore scheduled for the object's next session. */
export interface TenantDataRestoreRequest {
  readonly tenantId: string;
  readonly bookmark?: string;
  readonly timestampUnix?: number;
  readonly auditId: string;
  readonly requestId: string;
  readonly operator: string;
  readonly occurredAtUnix: number;
}

export interface TenantDataRestoreResult {
  readonly bookmark: string;
  readonly auditId: string;
  readonly scheduled: true;
}

/** An RPC carrying the caller's tenant id — see {@link TenantDataObject.batch}. */
export interface TenantDataBatchRequest {
  readonly tenantId: string;
  readonly statements: readonly TenantDataStatement[];
}

/**
 * The persisted mode of the tenant migration gate.
 *
 * `done` is the compatibility default for objects created before this gate was
 * deployed. A migration caller must explicitly move an object to `shared`
 * before it can use the frozen import path.
 */
export type TenantMigrationMode = "shared" | "copying" | "verifying" | "cut" | "done";

/** Trusted control-plane request to advance the object-side migration gate. */
export interface TenantMigrationModeRequest {
  readonly tenantId: string;
  readonly mode: TenantMigrationMode;
  /** Monotonic migration generation; retries with the same generation are idempotent. */
  readonly epoch: number;
}

/** Tenant admission for a migration status read. */
export interface TenantMigrationStatusRequest {
  readonly tenantId: string;
}

/** Trusted, migration-only batch import while the object is frozen. */
export interface TenantMigrationImportRequest extends TenantDataBatchRequest {
  /** Must equal the currently persisted migration epoch. */
  readonly epoch: number;
}

/** Object-side migration state used by cutover and rollback orchestration. */
export interface TenantMigrationStatus {
  readonly tenantId: string;
  readonly mode: TenantMigrationMode;
  readonly epoch: number;
  /** Increases before every accepted tenant-data write attempt. */
  readonly writeEpoch: number;
}

/** One tenant-authoritative append to the tamper-evident audit chain. */
export interface TenantAuditAppendRequest {
  readonly tenantId: string;
  readonly id: string;
  readonly requestId: string;
  readonly agentRunId: string | null;
  readonly occurredAtUnix: number;
  readonly auditJson: string;
}

/** The complete row returned after the object assigned its chain position. */
export interface TenantAuditAppendResult {
  readonly id: string;
  readonly requestId: string;
  readonly agentRunId: string | null;
  readonly tenant: string;
  readonly occurredAtUnix: number;
  readonly auditJson: string;
  readonly chainKey: string;
  readonly seq: number;
  readonly prevHash: string;
  readonly rowHash: string;
}

/** One statement's outcome. Every field is structured-cloneable. */
export interface TenantDataResult {
  /**
   * The rows the statement produced, always a real array — `[]` for a write with
   * no `RETURNING`, never `undefined`. Seventeen call sites under `src/d1/`
   * index `.results` with no guard, so `undefined` there is a TypeError on a
   * money path rather than a missing row.
   */
  readonly results: Record<string, TenantDataValue>[];
  /**
   * Rows this statement inserted/updated/deleted — the `D1Result.meta.changes`
   * equivalent, and the ONLY meta field anything in this repo reads.
   *
   * It is measured as a `total_changes()` DELTA around the statement, not read
   * from `SqlStorageCursor`. The cursor exposes `rowsWritten`, which counts
   * INDEX row writes too, so a row touching three indexes reports 4. Five
   * `changes()` helpers in `src/d1/` treat `changes > 0` as "the guarded write
   * fired" — an overreported value publishes an unscanned asset
   * (`assets-d1.ts:418`), skips a schedule fire forever
   * (`agent-schedule-d1.ts:342`) and reports deletions that never happened
   * (`references-d1.ts`). `changes()` alone is also wrong here: it retains the
   * previous write's count across a SELECT, so a read would inherit it. The
   * delta is 0 for a read, which is what D1 reports.
   */
  readonly changes: number;
  /** Rows the statement read; billing-shaped diagnostics, nothing branches on it. */
  readonly rowsRead: number;
  /**
   * Rows WRITTEN, straight off the cursor — the `D1Result.meta.rows_written`
   * equivalent, and deliberately NOT the same number as {@link changes}.
   *
   * The cursor counts INDEX row writes as well as table rows, so a row landing
   * in a table with three indexes reports 4 here and 1 in `changes`. Both are
   * true and neither substitutes for the other: D1 bills on `rows_written` and
   * the guarded-write CAS branches on `changes`. Reporting one under the other's
   * name would either bill wrong or publish an unscanned asset.
   */
  readonly rowsWritten: number;
  /**
   * `last_insert_rowid()` AFTER the statement — `D1Result.meta.last_row_id`.
   *
   * Read from the connection, not from the statement, so a statement that
   * inserted nothing reports whatever the previous INSERT on this object left
   * behind. That is exactly D1's behaviour (its `last_row_id` is a connection
   * property too), and it is why nothing in this repo reads it: grepping
   * `last_row_id|lastRowId|lastInsertRowid` over non-test source returns zero
   * hits. It is carried anyway because `D1Meta.last_row_id` is non-optional, and
   * a synthesized `0` there would be a lie a future caller could believe.
   */
  readonly lastRowId: number;
  /**
   * The object's SQLite database size in bytes after the statement —
   * `D1Result.meta.size_after`. `ctx.storage.sql.databaseSize`, verbatim.
   *
   * Also unread by anything in this repo, and also carried rather than
   * zero-filled: it is the one meta field that maps onto the 10 GB per-object
   * ceiling, so an operator asking "how close is this tenant to the limit"
   * should get a real answer rather than a placeholder.
   */
  readonly databaseSize: number;
}

/** What {@link TenantDataObject.schemaVersion} answers. */
export interface TenantSchemaStatus {
  /** The tenant id this object adopted, or `null` before its first RPC. */
  readonly tenantId: string | null;
  /** Highest version in `storage_schema_migrations`; `0` on a virgin object. */
  readonly version: number;
  /** The version {@link TENANT_MIGRATIONS} would bring it to. */
  readonly latest: number;
  /**
   * Migration NAMES applied during THIS wake — empty on every wake after the
   * first, which is the observable form of "an already-current object does a
   * version read and nothing more". Asserting on this rather than on wall time
   * is what makes the no-rerun claim a real test instead of a timing guess.
   */
  readonly appliedThisWake: readonly string[];
  /** Set when the schema apply failed; every other RPC refuses while it is set. */
  readonly failure: string | null;
}

/** A tenant-local schedule deadline retained beside the multiplexed native alarm. */
export interface TenantScheduleAlarmRequest {
  /** The tenant this object must already hold or adopt. */
  readonly tenantId: string;
  /** Unix seconds; the native Durable Object alarm is armed in milliseconds. */
  readonly scheduledAtUnix: number;
}

/** Clear the current tenant object's schedule alarm. */
export interface TenantScheduleAlarmClearRequest {
  readonly tenantId: string;
}

/** The tenant-local deadline for the periodic control-D1 aggregate push. */
export interface TenantAggregateFlushAlarmRequest {
  /** The tenant this object must already hold or adopt. */
  readonly tenantId: string;
  /** Unix seconds; the native Durable Object alarm is armed in milliseconds. */
  readonly scheduledAtUnix: number;
}

export const TENANT_AGGREGATE_FLUSH_KIND = "tenant-aggregate-flush-alarm" as const;
export const TENANT_AGGREGATE_FLUSH_VERSION = 1 as const;

export interface TenantAggregateFlushAlarmMessage {
  readonly kind: typeof TENANT_AGGREGATE_FLUSH_KIND;
  readonly version: typeof TENANT_AGGREGATE_FLUSH_VERSION;
  readonly tenant_id: string;
  readonly scheduled_at_unix: number;
}

/** Storage key for the adopted tenant id. See {@link TenantDataObject.query}. */
const TENANT_ID_KEY = "tenant_data:tenant_id";

/** Persisted migration gate and rollback witness. Kept in KV to avoid schema drift. */
const TENANT_MIGRATION_STATE_KEY = "tenant_data:migration_state";

interface PersistedTenantMigrationState {
  readonly mode: TenantMigrationMode;
  readonly epoch: number;
  readonly writeEpoch: number;
}

const DEFAULT_TENANT_MIGRATION_STATE: PersistedTenantMigrationState = {
  mode: "done",
  epoch: 0,
  writeEpoch: 0,
};

const TENANT_MIGRATION_MODES: readonly TenantMigrationMode[] = [
  "shared",
  "copying",
  "verifying",
  "cut",
  "done",
];

const FROZEN_TENANT_MIGRATION_MODES: readonly TenantMigrationMode[] = [
  "shared",
  "copying",
  "verifying",
  // The control registry switches routing to the object at `cut`, but the
  // object must remain read-only until the control row reaches `done`.
  "cut",
];

/** The validated schedule payload retained until the native alarm fires. */
const SCHEDULE_ALARM_KEY = "tenant_data:schedule_alarm";

/** The validated aggregate-flush payload retained until the native alarm fires. */
const AGGREGATE_FLUSH_ALARM_KEY = "tenant_data:aggregate_flush_alarm";

/**
 * One flush per minute is a deliberate cost/freshness tradeoff: one billed
 * native-alarm write per flush keeps the admin money view bounded to one minute
 * of staleness without turning every tenant write into a billed alarm write.
 */
export const TENANT_AGGREGATE_FLUSH_INTERVAL_SECONDS = 60;

interface TenantScheduleAlarmQueue {
  send(body: unknown): Promise<unknown>;
}

function scheduleAlarmQueueFrom(env: unknown): TenantScheduleAlarmQueue | null {
  if (typeof env !== "object" || env === null) return null;
  const queue = (env as { SCHEDULE_ALARMS?: unknown }).SCHEDULE_ALARMS;
  if (typeof queue !== "object" || queue === null) return null;
  const send = (queue as { send?: unknown }).send;
  return typeof send === "function" ? (queue as TenantScheduleAlarmQueue) : null;
}

/**
 * Symbol-keyed so it is a testable/internal seam without becoming a string RPC
 * method. Cloudflare RPC only addresses string properties; the alarm entrypoint
 * is the only production caller.
 */
export const TENANT_SCHEDULE_ALARM_CALLBACK = Symbol("TenantDataObject.scheduleAlarmCallback");

export type TenantScheduleAlarmCallback = (message: TenantScheduleAlarmMessage) => Promise<void>;

/** Internal alarm seam; production reads the tenant SQLite and pushes to D1. */
export const TENANT_AGGREGATE_FLUSH_CALLBACK = Symbol("TenantDataObject.aggregateFlushCallback");

export type TenantAggregateFlushAlarmCallback = (
  message: TenantAggregateFlushAlarmMessage,
) => Promise<void>;

function tenantAggregateFlushAlarmMessage(
  tenantId: string,
  scheduledAtUnix: number,
): TenantAggregateFlushAlarmMessage {
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new Error(`${REFUSAL}: aggregate flush alarm requires a non-empty tenant id`);
  }
  if (!Number.isSafeInteger(scheduledAtUnix) || scheduledAtUnix < 0) {
    throw new Error(`${REFUSAL}: aggregate flush alarm requires a non-negative safe timestamp`);
  }
  return {
    kind: TENANT_AGGREGATE_FLUSH_KIND,
    version: TENANT_AGGREGATE_FLUSH_VERSION,
    tenant_id: tenantId.trim(),
    scheduled_at_unix: scheduledAtUnix,
  };
}

function decodeTenantAggregateFlushAlarm(raw: unknown): TenantAggregateFlushAlarmMessage {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${REFUSAL}: aggregate flush alarm payload must be an object`);
  }
  const record = raw as Record<string, unknown>;
  if (record.kind !== TENANT_AGGREGATE_FLUSH_KIND) {
    throw new Error(`${REFUSAL}: aggregate flush alarm kind is invalid`);
  }
  if (record.version !== TENANT_AGGREGATE_FLUSH_VERSION) {
    throw new Error(`${REFUSAL}: aggregate flush alarm version is unsupported`);
  }
  return tenantAggregateFlushAlarmMessage(
    record.tenant_id as string,
    record.scheduled_at_unix as number,
  );
}

function controlDatabaseFromEnv(env: unknown): D1Database | null {
  if (typeof env !== "object" || env === null) return null;
  const candidate = (env as { CONTROL_DB?: unknown }).CONTROL_DB;
  if (typeof candidate !== "object" || candidate === null) return null;
  return typeof (candidate as { prepare?: unknown }).prepare === "function"
    ? (candidate as D1Database)
    : null;
}

/**
 * A witness table from `0001_init_tenant.sql`, used to catch a ledger that
 * disagrees with the database it claims to describe. See `#assertLedgerHonest`.
 */
const WITNESS_TABLE = "projects";

/** Prefix on every refusal this object raises, so a caller can recognise one. */
const REFUSAL = "tenant_data_object";

/**
 * Role bindings and their local catalog are an operator projection. Letting a
 * tenant-facing SQL caller write either half would allow it to manufacture its
 * own permission grant, so those writes require the separate privileged RPC.
 */
const PRIVILEGED_WRITE_TABLES = ["tenant_role_bindings", "tenant_role_catalog"] as const;

function stripSqlCommentsAndStrings(sql: string): string {
  let output = "";
  let mode: "normal" | "line_comment" | "block_comment" | "string" = "normal";

  for (let index = 0; index < sql.length; index += 1) {
    const current = sql[index];
    const next = sql[index + 1];
    if (mode === "line_comment") {
      if (current === "\n") {
        output += current;
        mode = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (mode === "block_comment") {
      if (current === "*" && next === "/") {
        output += "  ";
        index += 1;
        mode = "normal";
      } else {
        output += " ";
      }
      continue;
    }
    if (mode === "string") {
      if (current === "'") {
        if (next === "'") {
          output += "  ";
          index += 1;
        } else {
          output += " ";
          mode = "normal";
        }
      } else {
        output += " ";
      }
      continue;
    }
    if (current === "-" && next === "-") {
      output += "  ";
      index += 1;
      mode = "line_comment";
    } else if (current === "/" && next === "*") {
      output += "  ";
      index += 1;
      mode = "block_comment";
    } else if (current === "'") {
      output += " ";
      mode = "string";
    } else {
      output += current;
    }
  }
  return output;
}

function requiresPrivilegedWrite(sql: string): string | null {
  // This is deliberately conservative. Tokenising after a stateful pass that
  // removes comments and string literals catches CTEs, `UPDATE OR REPLACE`,
  // schema-qualified names, and trigger bodies without trying to implement
  // SQLite's grammar here. The state machine matters: `--` and `/*` inside a
  // legal string must not hide SQL that follows that string.
  const tokens = sqlTokens(sql);
  if (
    !["insert", "replace", "update", "delete", "create", "alter", "drop", "truncate"].some((verb) =>
      tokens.has(verb),
    )
  ) {
    return null;
  }
  for (const table of PRIVILEGED_WRITE_TABLES) {
    if (tokens.has(table)) return table;
  }
  return null;
}

function sqlTokens(sql: string): Set<string> {
  const normalized = stripSqlCommentsAndStrings(sql);
  return new Set(
    (normalized.match(/[A-Za-z_][A-Za-z0-9_$]*/g) ?? []).map((token) => token.toLowerCase()),
  );
}

/**
 * Conservative SQL write detection. The object owns its schema, so DDL and
 * connection-level write pragmas are writes for the migration gate too. A
 * token pass catches CTEs and trigger bodies without trusting a caller's first
 * keyword.
 */
function isSqlWrite(sql: string): boolean {
  const normalized = stripSqlCommentsAndStrings(sql).trim().toLowerCase();
  if (
    /^pragma\s+(?:main\.)?(?:table_info|index_info|index_list|foreign_key_list)\s*\(/.test(
      normalized,
    )
  ) {
    return false;
  }
  const tokens = sqlTokens(sql);
  return [
    "insert",
    "replace",
    "update",
    "delete",
    "create",
    "alter",
    "drop",
    "truncate",
    "vacuum",
    "reindex",
    "analyze",
    "attach",
    "detach",
    "pragma",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "release",
  ].some((verb) => tokens.has(verb));
}

const OPERATOR_EXPORT_MAX_PAGE_SIZE = 32;
const OPERATOR_EXPORT_INTERNAL_TABLES = new Set(["audit_events", "storage_schema_migrations"]);
const OPERATOR_READ_WRITE_OPCODES = new Set([
  "Clear",
  "CreateBtree",
  "Delete",
  "Destroy",
  "DropIndex",
  "DropTable",
  "DropTrigger",
  "Insert",
  "Reindex",
  "Update",
  "Vacuum",
  "VUpdate",
]);
type SqlLexMode =
  | "normal"
  | "single"
  | "double"
  | "backtick"
  | "bracket"
  | "line_comment"
  | "block_comment";

/**
 * Return whether the suffix contains SQL rather than whitespace/comments.
 * This is used only after a semicolon, where a second quoted literal is still
 * content and must not be mistaken for a harmless trailing comment.
 */
function hasSqlContent(sql: string): boolean {
  let mode: "normal" | "line_comment" | "block_comment" = "normal";
  for (let index = 0; index < sql.length; index += 1) {
    const current = sql[index];
    const next = sql[index + 1];
    if (mode === "line_comment") {
      if (current === "\n") mode = "normal";
      continue;
    }
    if (mode === "block_comment") {
      if (current === "*" && next === "/") {
        index += 1;
        mode = "normal";
      }
      continue;
    }
    if (current === "-" && next === "-") {
      index += 1;
      mode = "line_comment";
      continue;
    }
    if (current === "/" && next === "*") {
      index += 1;
      mode = "block_comment";
      continue;
    }
    if (current !== undefined && !/\s/.test(current)) return true;
  }
  return false;
}

/** Strip one trailing terminator while refusing every second statement. */
function oneSqlStatement(sql: string): string {
  let mode: SqlLexMode = "normal";
  for (let index = 0; index < sql.length; index += 1) {
    const current = sql[index];
    const next = sql[index + 1];
    if (mode === "line_comment") {
      if (current === "\n") mode = "normal";
      continue;
    }
    if (mode === "block_comment") {
      if (current === "*" && next === "/") {
        index += 1;
        mode = "normal";
      }
      continue;
    }
    if (mode === "single") {
      if (current === "'" && next === "'") {
        index += 1;
      } else if (current === "'") {
        mode = "normal";
      }
      continue;
    }
    if (mode === "double") {
      if (current === '"' && next === '"') {
        index += 1;
      } else if (current === '"') {
        mode = "normal";
      }
      continue;
    }
    if (mode === "backtick") {
      if (current === "`" && next === "`") {
        index += 1;
      } else if (current === "`") {
        mode = "normal";
      }
      continue;
    }
    if (mode === "bracket") {
      if (current === "]") mode = "normal";
      continue;
    }
    if (current === "-" && next === "-") {
      index += 1;
      mode = "line_comment";
    } else if (current === "/" && next === "*") {
      index += 1;
      mode = "block_comment";
    } else if (current === "'") {
      mode = "single";
    } else if (current === '"') {
      mode = "double";
    } else if (current === "`") {
      mode = "backtick";
    } else if (current === "[") {
      mode = "bracket";
    } else if (current === ";") {
      if (hasSqlContent(sql.slice(index + 1))) {
        throw new Error(`${REFUSAL}: operator query must contain exactly one SQL statement`);
      }
      return sql.slice(0, index);
    }
  }
  return sql;
}

/** Read the first executable keyword without trusting its textual position. */
function firstSqlKeyword(sql: string): string | null {
  let mode: SqlLexMode = "normal";
  for (let index = 0; index < sql.length; index += 1) {
    const current = sql[index];
    const next = sql[index + 1];
    if (mode === "line_comment") {
      if (current === "\n") mode = "normal";
      continue;
    }
    if (mode === "block_comment") {
      if (current === "*" && next === "/") {
        index += 1;
        mode = "normal";
      }
      continue;
    }
    if (mode === "single") {
      if (current === "'" && next === "'") index += 1;
      else if (current === "'") mode = "normal";
      continue;
    }
    if (mode === "double") {
      if (current === '"' && next === '"') index += 1;
      else if (current === '"') mode = "normal";
      continue;
    }
    if (mode === "backtick") {
      if (current === "`" && next === "`") index += 1;
      else if (current === "`") mode = "normal";
      continue;
    }
    if (mode === "bracket") {
      if (current === "]") mode = "normal";
      continue;
    }
    if (current === "-" && next === "-") {
      index += 1;
      mode = "line_comment";
      continue;
    }
    if (current === "/" && next === "*") {
      index += 1;
      mode = "block_comment";
      continue;
    }
    if (current === "'") {
      mode = "single";
      continue;
    }
    if (current === '"') {
      mode = "double";
      continue;
    }
    if (current === "`") {
      mode = "backtick";
      continue;
    }
    if (current === "[") {
      mode = "bracket";
      continue;
    }
    if (current !== undefined && /[A-Za-z_]/.test(current)) {
      let end = index + 1;
      while (end < sql.length && /[A-Za-z0-9_$]/.test(sql[end] ?? "")) end += 1;
      return sql.slice(index, end).toLowerCase();
    }
    if (current !== undefined && !/\s/.test(current)) return null;
  }
  return null;
}

/**
 * Validate at SQLite parse level, then reject the VM opcodes that write.
 * Prefix checks are intentionally absent: comments, CTEs and a second
 * statement all change what the first word means. `EXPLAIN` parses the exact
 * statement without executing it, and the cursor is drained before this
 * synchronous validator returns.
 */
function validateReadOnlySelect(sql: SqlStorage, statement: TenantDataStatement): string {
  if (typeof statement.sql !== "string" || statement.sql.trim() === "") {
    throw new Error(`${REFUSAL}: operator query requires one read-only SELECT statement`);
  }
  const single = oneSqlStatement(statement.sql);
  const keyword = firstSqlKeyword(single);
  if (keyword !== "select" && keyword !== "with") {
    throw new Error(`${REFUSAL}: operator query requires one read-only SELECT statement`);
  }

  let explainRows: { opcode?: string }[];
  try {
    explainRows = sql
      .exec<{ opcode?: string }>(`EXPLAIN ${single}`, ...(statement.params ?? []))
      .toArray();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`${REFUSAL}: operator query was rejected at SQL parse level: ${detail}`);
  }
  const writeOpcode = explainRows.find((row) =>
    OPERATOR_READ_WRITE_OPCODES.has(String(row.opcode ?? "")),
  );
  if (writeOpcode !== undefined) {
    throw new Error(
      `${REFUSAL}: operator query must be one read-only SELECT statement; ` +
        `SQLite parsed a ${String(writeOpcode.opcode)} write opcode`,
    );
  }
  return single;
}

interface OperatorExportCursor {
  readonly table: string;
  readonly rowid: number;
}

function quoteSqlIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function decodeOperatorExportCursor(value: string | null): OperatorExportCursor | null {
  if (value === null) return null;
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (
      typeof parsed.table !== "string" ||
      parsed.table.trim() === "" ||
      typeof parsed.rowid !== "number" ||
      !Number.isSafeInteger(parsed.rowid) ||
      parsed.rowid < 0
    ) {
      throw new Error("invalid cursor fields");
    }
    return { table: parsed.table, rowid: parsed.rowid };
  } catch {
    throw new Error(`${REFUSAL}: operator export cursor is invalid`);
  }
}

function encodeOperatorExportCursor(cursor: OperatorExportCursor): string {
  return JSON.stringify(cursor);
}

function encodeExportValue(value: TenantDataValue): unknown {
  if (value instanceof ArrayBuffer) {
    const bytes = new Uint8Array(value);
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return { type: "base64", data: btoa(binary) };
  }
  return value;
}

function isTenantMigrationMode(value: unknown): value is TenantMigrationMode {
  return typeof value === "string" && TENANT_MIGRATION_MODES.includes(value as TenantMigrationMode);
}

function isFrozenTenantMigrationMode(mode: TenantMigrationMode): boolean {
  return FROZEN_TENANT_MIGRATION_MODES.includes(mode);
}

function migrationTransitionAllowed(
  current: PersistedTenantMigrationState,
  next: TenantMigrationMode,
): boolean {
  if (current.mode === next) return true;
  // An object that predates the gate starts in compatibility `done@0`; the
  // first migration may claim it explicitly. A later `done` object may also
  // be reopened only through the trusted control-plane rollback path; the
  // control database supplies the retention and write-epoch checks.
  if (current.mode === "done" && next === "shared") return true;
  if (current.mode === "shared") return next === "copying";
  if (current.mode === "copying") return next === "verifying";
  if (current.mode === "verifying") return next === "cut";
  if (current.mode === "cut") return next === "done" || next === "shared";
  return false;
}

function decodeTenantMigrationState(value: unknown): PersistedTenantMigrationState {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${REFUSAL}: persisted migration state is not an object`);
  }
  const candidate = value as Record<string, unknown>;
  if (!isTenantMigrationMode(candidate.mode)) {
    throw new Error(`${REFUSAL}: persisted migration state has an unknown mode`);
  }
  if (
    typeof candidate.epoch !== "number" ||
    !Number.isSafeInteger(candidate.epoch) ||
    candidate.epoch < 0
  ) {
    throw new Error(`${REFUSAL}: persisted migration state has an invalid epoch`);
  }
  if (
    typeof candidate.writeEpoch !== "number" ||
    !Number.isSafeInteger(candidate.writeEpoch) ||
    candidate.writeEpoch < 0
  ) {
    throw new Error(`${REFUSAL}: persisted migration state has an invalid write epoch`);
  }
  return {
    mode: candidate.mode,
    epoch: candidate.epoch,
    writeEpoch: candidate.writeEpoch,
  };
}

/**
 * Split a migration file into single statements.
 *
 * A near-copy of the splitter in `apps/gateway/test/setup-d1.ts:70` (and its
 * four duplicates); it lives here rather than being imported because that one
 * is under a `test/` tree and this one ships. The reasoning is carried across
 * with it, because it is the only thing standing between this function and a
 * future trigger body:
 *
 *  * **Comment stripping must come first.** `0001_init_tenant.sql` has 18
 *    comment lines containing a `;` mid-prose, and the TWENTY files have 36
 *    between them (18 in 0001, 1 in 0003, 5 in 0005, 3 in 0008, 2 in 0009,
 *    1 in 0011, 1 in 0012, 1 in 0013, 1 in 0015, 1 in 0016 and 2 in 0017) —
 *    36, not 18,
 *    is the number that bounds this function's exposure. Splitting before
 *    stripping cuts statements in half at every one of them.
 *
 *    These numbers are a MEASUREMENT and they have gone stale before: the
 *    census was not always re-run when a migration landed. `test/do/tenant-
 *    data-object.test.ts` now recomputes every count in this docblock from the
 *    real files and asserts them, so the next migration reddens a test instead
 *    of quietly falsifying a safety argument.
 *  * The filter is line-granular after `trimStart()`, which is what makes it
 *    lossless over `0005_responses_conversations.sql` — that file indents `--`
 *    comments BETWEEN columns, and a filter anchored at column 0 would corrupt
 *    the table.
 *  * Trigger bodies are kept as one statement. Their `BEGIN` block contains
 *    statement terminators by design; splitting those terminators would leave
 *    the object with a permanently failed schema migration. The current SQL
 *    convention puts `END;` on its own line, which is enforced by the parser
 *    below rather than assumed by the caller.
 *
 * Splitting is mandatory, not stylistic: `sql.exec` applies bindings only to the
 * LAST statement of a multi-statement string, so handing a whole file to one
 * `exec()` would make the first parameterized backfill migration bind against
 * the wrong statement, silently. Splitting first makes that invariant free.
 */
export function sqlStatements(migration: string): string[] {
  const lines = migration.split("\n").filter((line) => !line.trimStart().startsWith("--"));
  const statements: string[] = [];
  let current: string[] = [];
  let inTrigger = false;

  const flush = (keepTerminator = false) => {
    let statement = current.join("\n").trim();
    if (!keepTerminator) statement = statement.replace(/;\s*$/, "");
    if (statement !== "") statements.push(statement);
    current = [];
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "") {
      if (current.length > 0) current.push(line);
      continue;
    }
    current.push(line);
    if (!inTrigger && /^CREATE\s+(?:TEMP\s+)?TRIGGER\b/i.test(current.join("\n"))) {
      inTrigger = true;
    }
    if (inTrigger) {
      if (/(?:^|\s)END;\s*$/i.test(trimmed)) {
        inTrigger = false;
        flush(true);
      }
      continue;
    }
    if (trimmed.endsWith(";")) flush();
  }
  if (inTrigger)
    throw new Error("tenant schema migration has an unterminated CREATE TRIGGER block");
  flush();
  return statements;
}

/**
 * One tenant's database. Addressed `env.TENANT_DATA.idFromName(tenantId)`.
 *
 * Reachable only through the binding; there is no `fetch()`.
 */
export class TenantDataObject extends DurableObject {
  /**
   * `this.ctx` is typed as the base class's state; this is the same handle,
   * narrowed once so the SQL API is reachable without a cast at every use.
   */
  readonly #state: DurableObjectState;
  #tenantId: string | null = null;
  #appliedThisWake: string[] = [];
  #failure: string | null = null;
  #migrationState: PersistedTenantMigrationState = DEFAULT_TENANT_MIGRATION_STATE;
  readonly #scheduleAlarmQueue: TenantScheduleAlarmQueue | null;
  readonly #controlDatabase: D1Database | null;
  readonly [TENANT_SCHEDULE_ALARM_CALLBACK]: TenantScheduleAlarmCallback = async (message) => {
    if (this.#scheduleAlarmQueue === null) {
      throw new Error(`${REFUSAL}: SCHEDULE_ALARMS is not bound; retaining the alarm for retry`);
    }
    await this.#scheduleAlarmQueue.send(encodeTenantScheduleAlarm(message));
  };
  readonly [TENANT_AGGREGATE_FLUSH_CALLBACK]: TenantAggregateFlushAlarmCallback = async () => {
    await this.#flushAggregates(Math.floor(Date.now() / 1000));
  };

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx as never, env as never);
    this.#state = ctx;
    this.#scheduleAlarmQueue = scheduleAlarmQueueFrom(env);
    this.#controlDatabase = controlDatabaseFromEnv(env);
    // `blockConcurrencyWhile` is the lock, and it is the whole reason a request
    // cannot observe a half-migrated database: no RPC is delivered until this
    // settles. An EVICTED instance re-runs it on the next wake, so the version
    // gate inside `#migrate` is what keeps that from re-applying 183 statements
    // on every cold start of every tenant.
    ctx.blockConcurrencyWhile(async () => {
      this.#tenantId = (await ctx.storage.get<string>(TENANT_ID_KEY)) ?? null;
      try {
        this.#migrationState = this.#loadMigrationState();
        this.#migrate();
      } catch (error) {
        // Caught, NOT swallowed. Throwing out of `blockConcurrencyWhile` aborts
        // the object, which fails closed but with an opaque error that names
        // neither the tenant nor the version. Recording it here and refusing
        // every RPC with the message below is the same refusal, legibly: the
        // operator is told which version the schema stopped at.
        this.#failure = error instanceof Error ? error.message : String(error);
      }
    });
  }

  /**
   * The migration set. Overridable so a test can drive a schema that FAILS —
   * a method rather than a field because subclass field initializers run after
   * `super()`, i.e. after the constructor has already migrated.
   */
  protected migrations(): readonly TenantMigration[] {
    return TENANT_MIGRATIONS;
  }

  /** The version {@link migrations} brings the database to. */
  protected latestVersion(): number {
    const list = this.migrations();
    return list[list.length - 1]?.version ?? TENANT_SCHEMA_VERSION;
  }

  // -------------------------------------------------------------------------
  // RPC surface
  // -------------------------------------------------------------------------

  /**
   * Run one statement.
   *
   * `tenantId` is the cross-tenant guard, not a routing hint: the object adopts
   * the FIRST id it is addressed with and refuses every later id that differs.
   * `idFromName` is one-way, so an object cannot derive its own tenant from its
   * id; without this, a resolver bug that computed the wrong name would silently
   * read and write another tenant's ledger, and every row would look correct
   * because the physical database really is the one the id named.
   */
  async query(request: TenantDataQueryRequest): Promise<TenantDataResult> {
    await this.#admit(request.tenantId);
    this.#refuseMigrationWrite(request.sql, "query");
    this.#refuseUnprivilegedWrite(request.sql);
    await this.#ensureFlushAlarm();
    this.#recordWriteAttempt(isSqlWrite(request.sql));
    // One statement is still a transaction: `changes` is measured as a
    // `total_changes()` delta, and a delta straddling a commit boundary could
    // be polluted by another statement. `transactionSync` also gives a bare
    // `query()` the same rollback-on-throw semantics `batch()` has.
    return this.#state.storage.transactionSync(() => this.#exec(request));
  }

  /**
   * Platform-operator-only read path. The control plane is the authorization
   * boundary; this RPC is intentionally absent from the D1 facade exposed to
   * tenant-facing code. The audit append reuses the same tamper-evident chain
   * as every other object audit event.
   */
  async operatorQuery(
    request: TenantDataOperatorQueryRequest,
  ): Promise<TenantDataOperatorQueryResult> {
    await this.#admit(request.tenantId);
    this.#validateOperatorAuditRequest(request);
    const parsedSql = validateReadOnlySelect(this.#state.storage.sql, request);
    const result = this.#state.storage.transactionSync(() =>
      this.#exec({ sql: parsedSql, params: request.params }),
    );
    await this.#appendOperatorAudit(request, {
      object: "tenant_data_operator",
      operation: "query",
      operator: request.operator,
      tenant_id: request.tenantId,
      statement: request.sql,
      row_count: result.results.length,
    });
    return {
      ...result,
      rowCount: result.results.length,
      auditId: request.auditId,
    };
  }

  /**
   * Return one bounded JSONL page. Each row query uses a keyset cursor and
   * `LIMIT 1`, so the object never materializes a tenant table. The cursor is
   * drained synchronously before the next query or any later await: holding a
   * `ctx.storage.sql` cursor across an await has no isolation guarantee.
   * Resumable pages are chosen over a raised CPU limit so an export survives an
   * object that grows and can be retried after a request deadline.
   */
  async operatorExportPage(
    request: TenantDataExportPageRequest,
  ): Promise<TenantDataExportPageResult> {
    await this.#admit(request.tenantId);
    this.#validateOperatorAuditRequest(request);
    if (
      !Number.isSafeInteger(request.pageSize) ||
      request.pageSize < 1 ||
      request.pageSize > OPERATOR_EXPORT_MAX_PAGE_SIZE
    ) {
      throw new Error(
        `${REFUSAL}: operator export page size must be between 1 and ${OPERATOR_EXPORT_MAX_PAGE_SIZE}`,
      );
    }
    if (typeof request.exportId !== "string" || request.exportId.trim() === "") {
      throw new Error(`${REFUSAL}: operator export requires a non-empty export id`);
    }

    const page = this.#operatorExportPageSync(request);
    await this.#appendOperatorAudit(request, {
      object: "tenant_data_operator",
      operation: "export_page",
      operator: request.operator,
      tenant_id: request.tenantId,
      export_id: request.exportId,
      cursor: request.cursor,
      format: "jsonl",
      row_count: page.rowCount,
    });
    return {
      ...page,
      exportId: request.exportId,
      auditId: request.auditId,
    };
  }

  /**
   * Schedule a retained bookmark on the next object session. Cloudflare's
   * restore API is deliberately asynchronous at the session boundary: the
   * current invocation records the request, and the next session opens at the
   * selected bookmark. A timestamp is resolved by the platform's bookmark
   * index; a missing/expired result is a refusal, never a fabricated restore.
   */
  async operatorRestore(request: TenantDataRestoreRequest): Promise<TenantDataRestoreResult> {
    await this.#admit(request.tenantId);
    this.#validateOperatorAuditRequest(request);
    const suppliedBookmark = typeof request.bookmark === "string" ? request.bookmark.trim() : "";
    let bookmark = suppliedBookmark;
    if (bookmark === "") {
      if (
        request.timestampUnix === undefined ||
        !Number.isSafeInteger(request.timestampUnix) ||
        request.timestampUnix < 0
      ) {
        throw new Error(`${REFUSAL}: restore requires a bookmark or a non-negative timestamp`);
      }
      try {
        bookmark = await this.#state.storage.getBookmarkForTime(
          new Date(request.timestampUnix * 1000),
        );
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          `${REFUSAL}: no usable bookmark for tenant ${request.tenantId} at ${request.timestampUnix}: ${detail}`,
        );
      }
    }
    if (bookmark === "") {
      throw new Error(`${REFUSAL}: no usable bookmark for tenant ${request.tenantId}`);
    }
    try {
      await this.#state.storage.onNextSessionRestoreBookmark(bookmark);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`${REFUSAL}: no usable bookmark for tenant ${request.tenantId}: ${detail}`);
    }

    await this.#appendOperatorAudit(request, {
      object: "tenant_data_operator",
      operation: "restore",
      operator: request.operator,
      tenant_id: request.tenantId,
      bookmark,
      timestamp_unix: request.timestampUnix ?? null,
      status: "scheduled_next_session",
    });
    return { bookmark, auditId: request.auditId, scheduled: true };
  }

  /**
   * Run N statements as ONE transaction. This is the entire point of the object.
   *
   * Every statement runs inside a single `transactionSync`, so a throw anywhere
   * rolls back everything before it. That is what restores
   * `supportsAtomicBatch: true` to the 13 `requireAtomicBatch()` money paths
   * that require a transaction — the no-oversell wallet reserve, the
   * workflow-budget debit, the asset quota admission.
   *
   * Exactly one result per submitted statement, in order. `wallet-d1.ts:377`
   * and `billing-d1.ts:182` both check the length and refuse a short response,
   * because a short batch makes every settle look like a replay and nothing is
   * ever billed.
   */
  async batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]> {
    await this.#admit(request.tenantId);
    for (const statement of request.statements) {
      this.#refuseMigrationWrite(statement.sql, "batch");
      this.#refuseUnprivilegedWrite(statement.sql);
    }
    await this.#ensureFlushAlarm();
    this.#recordWriteAttempt(request.statements.some((statement) => isSqlWrite(statement.sql)));
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) {
        results.push(this.#exec(statement));
      }
      return results;
    });
  }

  /**
   * Internal operator path for projections that must be written atomically.
   * The binding is private to Worker-to-Worker bindings; ordinary tenant
   * callers only receive `query` and `batch` through the D1 facade.
   */
  async privilegedBatch(request: TenantDataBatchRequest): Promise<TenantDataResult[]> {
    await this.#admit(request.tenantId);
    for (const statement of request.statements) {
      this.#refuseMigrationWrite(statement.sql, "privilegedBatch");
    }
    await this.#ensureFlushAlarm();
    this.#recordWriteAttempt(request.statements.some((statement) => isSqlWrite(statement.sql)));
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) results.push(this.#exec(statement));
      return results;
    });
  }

  /**
   * Trusted migration import path. It is deliberately separate from
   * `privilegedBatch`: the latter is a normal operator projection path and is
   * frozen with all other ordinary writes, while this path is the only write
   * capability available during `copying`/`verifying`.
   */
  async migrationImport(request: TenantMigrationImportRequest): Promise<TenantDataResult[]> {
    await this.#admit(request.tenantId);
    this.#assertMigrationImport(request.epoch);
    this.#recordWriteAttempt(request.statements.some((statement) => isSqlWrite(statement.sql)));
    return this.#state.storage.transactionSync(() => {
      const results: TenantDataResult[] = [];
      for (const statement of request.statements) results.push(this.#exec(statement));
      return results;
    });
  }

  /** Set the persisted mode/generation through the trusted migration seam. */
  async setMigrationMode(request: TenantMigrationModeRequest): Promise<TenantMigrationStatus> {
    await this.#admit(request.tenantId);
    if (!isTenantMigrationMode(request.mode)) {
      throw new Error(`${REFUSAL}: unknown migration mode ${String(request.mode)}`);
    }
    if (!Number.isSafeInteger(request.epoch) || request.epoch < 0) {
      throw new Error(`${REFUSAL}: migration epoch must be a non-negative safe integer`);
    }
    const current = this.#migrationState;
    if (request.epoch < current.epoch) {
      throw new Error(
        `${REFUSAL}: stale migration epoch ${request.epoch}; current epoch is ${current.epoch}`,
      );
    }
    if (!migrationTransitionAllowed(current, request.mode)) {
      throw new Error(
        `${REFUSAL}: migration transition ${current.mode} -> ${request.mode} is not allowed`,
      );
    }
    if (request.mode === current.mode && request.epoch === current.epoch) {
      return this.#migrationStatus(request.tenantId);
    }
    const next: PersistedTenantMigrationState = {
      mode: request.mode,
      epoch: request.epoch,
      writeEpoch: current.writeEpoch,
    };
    this.#state.storage.kv.put(TENANT_MIGRATION_STATE_KEY, next);
    this.#migrationState = next;
    return this.#migrationStatus(request.tenantId);
  }

  /** Read mode and write epoch for cutover/rollback checks. */
  async migrationStatus(request: TenantMigrationStatusRequest): Promise<TenantMigrationStatus> {
    await this.#admit(request.tenantId);
    return this.#migrationStatus(request.tenantId);
  }

  /**
   * Append one tenant audit row with its chain position assigned by the object.
   *
   * The hash calculation is asynchronous Web Crypto, while SQLite's
   * `transactionSync()` callback must be synchronous. `blockConcurrencyWhile`
   * closes that gap: it keeps every other RPC out while the head is read, the
   * digest is computed, and the checked insert commits. The transaction still
   * re-reads the head before inserting, so the serialization assumption is
   * explicit rather than hidden in the caller.
   */
  async appendAudit(request: TenantAuditAppendRequest): Promise<TenantAuditAppendResult> {
    await this.#admit(request.tenantId);
    if (request.tenantId.trim() === "" || request.tenantId !== request.tenantId.trim()) {
      throw new Error(`${REFUSAL}: audit append requires a normalized tenant id`);
    }
    if (request.occurredAtUnix < 0 || !Number.isSafeInteger(request.occurredAtUnix)) {
      throw new Error(`${REFUSAL}: audit append requires a non-negative integer timestamp`);
    }
    const tenant = request.tenantId;
    const chainKey = auditChainKey(tenant);
    this.#refuseMigrationWrite("INSERT INTO audit_events", "audit append");
    this.#recordWriteAttempt(true);

    return this.#state.blockConcurrencyWhile(async () => {
      const existing = this.#state.storage.sql
        .exec<{
          id: string;
          request_id: string;
          agent_run_id: string | null;
          tenant: string;
          occurred_at_unix: number;
          audit_json: string;
          chain_key: string;
          seq: number;
          prev_hash: string;
          row_hash: string;
        }>(
          "SELECT id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json, " +
            "chain_key, seq, prev_hash, row_hash FROM audit_events WHERE id = ?",
          request.id,
        )
        .toArray()[0];
      if (existing !== undefined) {
        if (
          existing.request_id !== request.requestId ||
          existing.agent_run_id !== request.agentRunId ||
          existing.tenant !== tenant ||
          existing.occurred_at_unix !== request.occurredAtUnix ||
          existing.audit_json !== request.auditJson
        ) {
          throw new Error(`${REFUSAL}: audit append idempotency conflict for ${request.id}`);
        }
        return {
          id: existing.id,
          requestId: existing.request_id,
          agentRunId: existing.agent_run_id,
          tenant: existing.tenant,
          occurredAtUnix: existing.occurred_at_unix,
          auditJson: existing.audit_json,
          chainKey: existing.chain_key,
          seq: existing.seq,
          prevHash: existing.prev_hash,
          rowHash: existing.row_hash,
        };
      }
      const head = this.#auditHead(chainKey);
      const seq = head === null ? 1 : head.seq + 1;
      const prevHash = head?.rowHash ?? AUDIT_CHAIN_GENESIS_HASH;
      const rowHash = await auditRowHash({
        chain_key: chainKey,
        seq,
        prev_hash: prevHash,
        id: request.id,
        request_id: request.requestId,
        agent_run_id: request.agentRunId,
        tenant,
        occurred_at_unix: request.occurredAtUnix,
        audit_json: request.auditJson,
      });

      return this.#state.storage.transactionSync(() => {
        const current = this.#auditHead(chainKey);
        if (current?.seq !== head?.seq || current?.rowHash !== head?.rowHash) {
          throw new Error(`${REFUSAL}: audit chain head changed while appending`);
        }
        this.#state.storage.sql
          .exec(
            "INSERT INTO audit_events " +
              "(id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json, " +
              "chain_key, seq, prev_hash, row_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            request.id,
            request.requestId,
            request.agentRunId,
            tenant,
            request.occurredAtUnix,
            request.auditJson,
            chainKey,
            seq,
            prevHash,
            rowHash,
          )
          .toArray();
        return {
          id: request.id,
          requestId: request.requestId,
          agentRunId: request.agentRunId,
          tenant,
          occurredAtUnix: request.occurredAtUnix,
          auditJson: request.auditJson,
          chainKey,
          seq,
          prevHash,
          rowHash,
        };
      });
    });
  }

  /**
   * The schema state. Callable even while the object is refusing, because the
   * version it stopped at is the one thing an operator needs from a broken
   * tenant — and the only way to see it without a query path.
   */
  async schemaVersion(): Promise<TenantSchemaStatus> {
    return {
      tenantId: this.#tenantId,
      version: this.#appliedVersion(),
      latest: this.latestVersion(),
      appliedThisWake: [...this.#appliedThisWake],
      failure: this.#failure,
    };
  }

  /** Re-arm the native deadline to the earlier retained schedule or flush. */
  async #rearmNativeAlarm(): Promise<void> {
    const scheduleRaw = await this.#state.storage.get<unknown>(SCHEDULE_ALARM_KEY);
    const flushRaw = await this.#state.storage.get<unknown>(AGGREGATE_FLUSH_ALARM_KEY);
    const schedule = scheduleRaw === undefined ? null : decodeTenantScheduleAlarm(scheduleRaw);
    const flush = flushRaw === undefined ? null : decodeTenantAggregateFlushAlarm(flushRaw);
    for (const message of [schedule, flush]) {
      if (message !== null && this.#tenantId !== message.tenant_id) {
        throw new Error(
          `${REFUSAL}: alarm names tenant ${message.tenant_id}, but this object holds ${
            this.#tenantId ?? "no tenant"
          }; refusing`,
        );
      }
    }
    const deadlines = [schedule?.scheduled_at_unix, flush?.scheduled_at_unix].filter(
      (deadline): deadline is number => deadline !== undefined,
    );
    const currentAlarm = await this.#state.storage.getAlarm();
    if (deadlines.length === 0) {
      if (currentAlarm !== null) await this.#state.storage.deleteAlarm();
      return;
    }
    const nextAlarm = Math.min(...deadlines) * 1000;
    // Alarm writes are billed storage writes. A normal tenant RPC often calls
    // this method while the same flush deadline is already armed, so avoid
    // rewriting an identical native deadline.
    if (currentAlarm !== nextAlarm) await this.#state.storage.setAlarm(nextAlarm);
  }

  /** Arm the periodic push once a tenant has made its first ordinary RPC. */
  async #ensureFlushAlarm(): Promise<void> {
    if (this.#controlDatabase === null || this.#tenantId === null) return;
    await this.#state.blockConcurrencyWhile(async () => {
      const raw = await this.#state.storage.get<unknown>(AGGREGATE_FLUSH_ALARM_KEY);
      if (raw === undefined) {
        await this.#state.storage.put(
          AGGREGATE_FLUSH_ALARM_KEY,
          tenantAggregateFlushAlarmMessage(
            this.#tenantId as string,
            Math.floor(Date.now() / 1000) + TENANT_AGGREGATE_FLUSH_INTERVAL_SECONDS,
          ),
        );
      } else {
        const message = decodeTenantAggregateFlushAlarm(raw);
        if (message.tenant_id !== this.#tenantId) {
          throw new Error(
            `${REFUSAL}: aggregate flush alarm names tenant ${message.tenant_id}, but this object holds ${this.#tenantId}; refusing`,
          );
        }
      }
      await this.#rearmNativeAlarm();
    });
  }

  /** Push the current tenant-owned counters as replacements, never deltas. */
  async #flushAggregates(asOfUnix: number): Promise<void> {
    if (this.#controlDatabase === null) {
      throw new Error(`${REFUSAL}: CONTROL_DB is not bound; retaining aggregate flush alarm`);
    }
    const tenantId = this.#tenantId;
    if (tenantId === null) {
      throw new Error(`${REFUSAL}: aggregate flush requires an admitted tenant`);
    }

    // Retirement removes the roster row before the retained object is erased.
    // Treat that row as the flush lease: once it is gone, remove this object's
    // pending flush payload and do not recreate projections for a tenant that
    // no longer appears in any fleet enumeration.
    const roster = await this.#controlDatabase
      .prepare("SELECT tenant_id FROM tenant_databases WHERE tenant_id = ?")
      .bind(tenantId)
      .first<{ tenant_id: string }>();
    if (roster === null) {
      await this.#state.storage.delete(AGGREGATE_FLUSH_ALARM_KEY);
      return;
    }

    // Drain every cursor before the first D1 await. The object SQLite read is
    // the authority; D1 receives a replacement snapshot and is never queried
    // as a shortcut back into another tenant's database.
    const agentRows = this.#state.storage.sql
      .exec<{
        tenant_id: string;
        agent_key: string;
        period: string;
        accumulated_usd: number;
        first_seen_unix: number;
        updated_at_unix: number;
      }>(
        "SELECT tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix " +
          "FROM agent_cost_burn WHERE tenant_id = ? ORDER BY period ASC, agent_key ASC",
        tenantId,
      )
      .toArray();
    const assetTotals = this.#state.storage.sql
      .exec<{ asset_count: number; asset_bytes: number }>(
        "SELECT count(*) AS asset_count, COALESCE(sum(size_bytes), 0) AS asset_bytes " +
          "FROM stored_assets WHERE tenant_id = ?",
        tenantId,
      )
      .toArray()[0] ?? { asset_count: 0, asset_bytes: 0 };
    const channelTotals = this.#state.storage.sql
      .exec<{ channel_count: number }>(
        "SELECT count(*) AS channel_count FROM asset_channels WHERE tenant_id = ?",
        tenantId,
      )
      .toArray()[0] ?? { channel_count: 0 };

    const spendByPeriod = new Map<string, number>();
    for (const row of agentRows) {
      spendByPeriod.set(row.period, (spendByPeriod.get(row.period) ?? 0) + row.accumulated_usd);
    }
    const statements: D1PreparedStatement[] = [
      this.#controlDatabase
        .prepare("DELETE FROM tenant_agent_cost_rollups WHERE tenant_id = ?")
        .bind(tenantId),
      this.#controlDatabase
        .prepare("DELETE FROM tenant_spend_rollups WHERE tenant_id = ?")
        .bind(tenantId),
      this.#controlDatabase
        .prepare(
          `INSERT INTO tenant_asset_rollups
             (tenant_id, asset_count, asset_bytes, channel_count, as_of_unix)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (tenant_id) DO UPDATE SET
             asset_count = excluded.asset_count,
             asset_bytes = excluded.asset_bytes,
             channel_count = excluded.channel_count,
             as_of_unix = excluded.as_of_unix`,
        )
        .bind(
          tenantId,
          assetTotals.asset_count,
          assetTotals.asset_bytes,
          channelTotals.channel_count,
          asOfUnix,
        ),
    ];
    for (const row of agentRows) {
      statements.push(
        this.#controlDatabase
          .prepare(
            `INSERT INTO tenant_agent_cost_rollups
               (tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix, as_of_unix)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            row.tenant_id,
            row.agent_key,
            row.period,
            row.accumulated_usd,
            row.first_seen_unix,
            row.updated_at_unix,
            asOfUnix,
          ),
      );
    }
    for (const [period, accumulatedUsd] of spendByPeriod) {
      statements.push(
        this.#controlDatabase
          .prepare(
            `INSERT INTO tenant_spend_rollups
               (tenant_id, period, accumulated_usd, as_of_unix)
             VALUES (?, ?, ?, ?)`,
          )
          .bind(tenantId, period, accumulatedUsd, asOfUnix),
      );
    }
    await this.#controlDatabase.batch(statements);
  }

  /**
   * Arm the one native alarm owned by this tenant object.
   *
   * Cloudflare permits one alarm deadline per object. The schedule and flush
   * payloads therefore live in separate durable keys, while this method always
   * arms the earlier deadline and preserves the later one.
   */
  async setScheduleAlarm(request: TenantScheduleAlarmRequest): Promise<void> {
    const message = tenantScheduleAlarmMessage(request.tenantId, request.scheduledAtUnix);
    await this.#admit(message.tenant_id);
    this.#refuseMigrationStorageWrite("set schedule alarm");
    this.#recordWriteAttempt(true);
    await this.#state.blockConcurrencyWhile(async () => {
      // Keep the payload durable before arming the deadline. If the alarm
      // write fails, a retry still has a complete message to deliver.
      await this.#state.storage.put(SCHEDULE_ALARM_KEY, message);
      await this.#rearmNativeAlarm();
    });
  }

  /** Clear the current schedule alarm and its tenant-local callback payload. */
  async clearScheduleAlarm(request: TenantScheduleAlarmClearRequest): Promise<void> {
    const tenantId = tenantScheduleAlarmMessage(request.tenantId, 0).tenant_id;
    await this.#admit(tenantId);
    this.#refuseMigrationStorageWrite("clear schedule alarm");
    this.#recordWriteAttempt(true);
    await this.#state.blockConcurrencyWhile(async () => {
      await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
      await this.#rearmNativeAlarm();
    });
  }

  /** Internal operator/test seam for arming a flush at a deterministic time. */
  async setAggregateFlushAlarm(request: TenantAggregateFlushAlarmRequest): Promise<void> {
    const message = tenantAggregateFlushAlarmMessage(request.tenantId, request.scheduledAtUnix);
    await this.#admit(message.tenant_id);
    this.#refuseMigrationStorageWrite("set aggregate flush alarm");
    this.#recordWriteAttempt(true);
    await this.#state.blockConcurrencyWhile(async () => {
      await this.#state.storage.put(AGGREGATE_FLUSH_ALARM_KEY, message);
      await this.#rearmNativeAlarm();
    });
  }

  /**
   * Recompute the deadline from rows in this object, while no other object RPC
   * can interleave. The caller never supplies a schedule snapshot, so a late
   * rearm cannot clear or replace an alarm written by a newer schedule update.
   */
  async rearmScheduleAlarm(request: TenantScheduleAlarmClearRequest): Promise<void> {
    const tenantId = tenantScheduleAlarmMessage(request.tenantId, 0).tenant_id;
    await this.#admit(tenantId);
    this.#refuseMigrationStorageWrite("rearm schedule alarm");
    this.#recordWriteAttempt(true);
    await this.#state.blockConcurrencyWhile(async () => {
      let earliest: number | undefined;
      const rows = this.#state.storage.sql
        .exec<{ enabled: number; next_fire_at_unix: number | null }>(
          "SELECT enabled, next_fire_at_unix FROM agent_schedules WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL ORDER BY next_fire_at_unix ASC LIMIT 1",
        )
        .toArray();
      const candidate = rows[0]?.next_fire_at_unix;
      if (typeof candidate === "number" && Number.isSafeInteger(candidate)) {
        earliest = candidate;
      }

      if (earliest === undefined) {
        await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
      } else {
        const message = tenantScheduleAlarmMessage(tenantId, earliest);
        // Retain the payload before arming the native alarm. If setAlarm fails,
        // the caller receives the failure and can retry without losing intent.
        await this.#state.storage.put(SCHEDULE_ALARM_KEY, message);
      }
      await this.#rearmNativeAlarm();
    });
  }

  /**
   * Native Durable Object alarm entrypoint.
   *
   * The callback is symbol-keyed rather than a public string method, so a
   * binding caller cannot invoke a queue-like operation with caller-supplied
   * tenant data. Production sends the validated payload to `SCHEDULE_ALARMS`;
   * a missing binding throws and leaves the payload retained for retry.
   */
  override async alarm(): Promise<void> {
    await this.#state.blockConcurrencyWhile(async () => {
      const nowUnix = Math.floor(Date.now() / 1000);
      const scheduleRaw = await this.#state.storage.get<unknown>(SCHEDULE_ALARM_KEY);
      const flushRaw = await this.#state.storage.get<unknown>(AGGREGATE_FLUSH_ALARM_KEY);
      const schedule = scheduleRaw === undefined ? null : decodeTenantScheduleAlarm(scheduleRaw);
      const flush = flushRaw === undefined ? null : decodeTenantAggregateFlushAlarm(flushRaw);
      const earliest = Math.min(
        ...(schedule === null ? [] : [schedule.scheduled_at_unix]),
        ...(flush === null ? [] : [flush.scheduled_at_unix]),
      );
      for (const message of [schedule, flush]) {
        if (message !== null && this.#tenantId !== message.tenant_id) {
          throw new Error(
            `${REFUSAL}: alarm names tenant ${message.tenant_id}, but this object holds ${
              this.#tenantId ?? "no tenant"
            }; refusing`,
          );
        }
      }
      // The platform invokes alarm() for the native deadline, so the earliest
      // retained payload is due even when a deterministic workerd test invokes
      // the entrypoint before wall clock time reaches that deadline. A later
      // payload is due only when its own deadline has also elapsed.
      if (
        schedule !== null &&
        (schedule.scheduled_at_unix <= nowUnix || schedule.scheduled_at_unix === earliest)
      ) {
        await this[TENANT_SCHEDULE_ALARM_CALLBACK](schedule);
        await this.#state.storage.delete(SCHEDULE_ALARM_KEY);
      }
      if (
        flush !== null &&
        (flush.scheduled_at_unix <= nowUnix || flush.scheduled_at_unix === earliest)
      ) {
        await this[TENANT_AGGREGATE_FLUSH_CALLBACK](flush);
        if ((await this.#state.storage.get(AGGREGATE_FLUSH_ALARM_KEY)) !== undefined) {
          await this.#state.storage.put(
            AGGREGATE_FLUSH_ALARM_KEY,
            tenantAggregateFlushAlarmMessage(
              this.#tenantId as string,
              nowUnix + TENANT_AGGREGATE_FLUSH_INTERVAL_SECONDS,
            ),
          );
        }
      }
      await this.#rearmNativeAlarm();
    });
  }

  #validateOperatorAuditRequest(request: {
    readonly auditId: string;
    readonly requestId: string;
    readonly operator: string;
    readonly occurredAtUnix: number;
  }): void {
    for (const [name, value] of [
      ["audit id", request.auditId],
      ["request id", request.requestId],
      ["operator", request.operator],
    ] as const) {
      if (typeof value !== "string" || value.trim() === "") {
        throw new Error(`${REFUSAL}: operator audit requires a non-empty ${name}`);
      }
    }
    if (request.occurredAtUnix < 0 || !Number.isSafeInteger(request.occurredAtUnix)) {
      throw new Error(`${REFUSAL}: operator audit requires a non-negative integer timestamp`);
    }
  }

  async #appendOperatorAudit(
    request: {
      readonly tenantId: string;
      readonly auditId: string;
      readonly requestId: string;
      readonly operator: string;
      readonly occurredAtUnix: number;
    },
    detail: Record<string, unknown>,
  ): Promise<TenantAuditAppendResult> {
    return this.appendAudit({
      tenantId: request.tenantId,
      id: request.auditId,
      requestId: request.requestId,
      agentRunId: null,
      occurredAtUnix: request.occurredAtUnix,
      auditJson: JSON.stringify(detail),
    });
  }

  #operatorExportPageSync(
    request: TenantDataExportPageRequest,
  ): Omit<TenantDataExportPageResult, "exportId" | "auditId"> {
    const sql = this.#state.storage.sql;
    const tables = sql
      .exec<{ name: string; sql: string | null }>(
        "SELECT name, sql FROM sqlite_master " +
          "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' " +
          "ORDER BY name",
      )
      .toArray()
      .filter((table) => !OPERATOR_EXPORT_INTERNAL_TABLES.has(table.name));
    const cursor = decodeOperatorExportCursor(request.cursor);
    let tableIndex = 0;
    let rowid: number | null = null;
    if (cursor !== null) {
      tableIndex = tables.findIndex((table) => table.name === cursor.table);
      if (tableIndex < 0) {
        throw new Error(`${REFUSAL}: operator export cursor names an unknown table`);
      }
      rowid = cursor.rowid;
    }

    const lines: string[] = [];
    let rowCount = 0;
    while (tableIndex < tables.length) {
      const table = tables[tableIndex];
      if (table === undefined) break;
      const tableName = table.name;
      const columns = sql
        .exec<{
          name: string;
          type: string;
          notnull: number;
          dflt_value: string | null;
          pk: number;
        }>(`PRAGMA table_info(${quoteSqlIdentifier(tableName)})`)
        .toArray();
      lines.push(
        JSON.stringify({
          kind: "schema",
          table: tableName,
          sql: table.sql,
          columns,
        }),
      );

      while (rowCount < request.pageSize) {
        // LIMIT 1 keeps the JS heap bounded even when one tenant row is large.
        // The cursor is fully drained before this loop can await through the
        // caller, because `toArray()` completes before any page is returned.
        const rows = sql
          .exec<Record<string, TenantDataValue>>(
            `SELECT rowid AS "__ferrogate_rowid", * FROM ${quoteSqlIdentifier(tableName)} WHERE rowid > ? ORDER BY rowid LIMIT 1`,
            rowid ?? 0,
          )
          .toArray();
        const row = rows[0];
        if (row === undefined) {
          tableIndex += 1;
          rowid = null;
          break;
        }
        const rawRowid = row.__ferrogate_rowid;
        if (typeof rawRowid !== "number" || !Number.isSafeInteger(rawRowid)) {
          throw new Error(`${REFUSAL}: operator export encountered an invalid rowid`);
        }
        const values: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(row)) {
          if (key !== "__ferrogate_rowid") values[key] = encodeExportValue(value);
        }
        lines.push(JSON.stringify({ kind: "row", table: tableName, rowid: rawRowid, values }));
        rowCount += 1;
        rowid = rawRowid;
        if (rowCount === request.pageSize) {
          return {
            jsonl: `${lines.join("\n")}\n`,
            rowCount,
            nextCursor: encodeOperatorExportCursor({ table: tableName, rowid: rawRowid }),
            done: false,
          };
        }
      }
    }

    return {
      jsonl: lines.length === 0 ? "" : `${lines.join("\n")}\n`,
      rowCount,
      nextCursor: null,
      done: true,
    };
  }

  // -------------------------------------------------------------------------
  // Admission
  // -------------------------------------------------------------------------

  /** Refuse a failed schema, a blank tenant id, or another tenant's id. */
  async #admit(tenantId: string): Promise<void> {
    if (this.#failure !== null) {
      throw new Error(`${REFUSAL}: ${this.#failure}`);
    }
    // Blank is refused rather than adopted. `middleware.ts:108` returns `""`
    // (never `null`) for an unclassified credential precisely so that it
    // matches nothing; adopting it here would turn the unforgeable id into a
    // shared object every unclassified caller lands in.
    //
    // The `typeof` arm is not redundant with the parameter type: this value
    // arrived over an RPC boundary as a structured clone, so the declared type
    // is the CALLER's promise, not a checked fact. A guard whose whole job is
    // to be unbypassable does not take a caller's word for its own input.
    if (typeof tenantId !== "string" || tenantId.trim() === "") {
      throw new Error(`${REFUSAL}: an RPC arrived with an empty tenant id; refusing`);
    }
    if (this.#tenantId === null) {
      // Adopt, under the lock. `blockConcurrencyWhile` is what stops two
      // concurrent first RPCs from each seeing `null` and adopting different
      // ids — the in-memory assignment alone would be safe only up to the
      // first `await`, and the `put` is one.
      await this.#state.blockConcurrencyWhile(async () => {
        if (this.#tenantId !== null) return;
        await this.#state.storage.put(TENANT_ID_KEY, tenantId);
        this.#tenantId = tenantId;
      });
    }
    if (this.#tenantId !== tenantId) {
      throw new Error(
        `${REFUSAL}: this object holds tenant ${this.#tenantId} and was addressed as ` +
          `${tenantId}; refusing rather than serving one tenant's data to another`,
      );
    }
  }

  #loadMigrationState(): PersistedTenantMigrationState {
    const stored = this.#state.storage.kv.get<unknown>(TENANT_MIGRATION_STATE_KEY);
    if (stored === undefined) {
      const initial = { ...DEFAULT_TENANT_MIGRATION_STATE };
      this.#state.storage.kv.put(TENANT_MIGRATION_STATE_KEY, initial);
      return initial;
    }
    return decodeTenantMigrationState(stored);
  }

  #migrationStatus(tenantId: string): TenantMigrationStatus {
    return {
      tenantId,
      mode: this.#migrationState.mode,
      epoch: this.#migrationState.epoch,
      writeEpoch: this.#migrationState.writeEpoch,
    };
  }

  #refuseMigrationWrite(sql: string, operation: string): void {
    if (!isSqlWrite(sql) || !isFrozenTenantMigrationMode(this.#migrationState.mode)) return;
    throw new Error(
      `${REFUSAL}: ${operation} writes are frozen in migration mode ` +
        `${this.#migrationState.mode}@${this.#migrationState.epoch}; use migrationImport`,
    );
  }

  #refuseMigrationStorageWrite(operation: string): void {
    if (!isFrozenTenantMigrationMode(this.#migrationState.mode)) return;
    throw new Error(
      `${REFUSAL}: ${operation} writes are frozen in migration mode ` +
        `${this.#migrationState.mode}@${this.#migrationState.epoch}; resume after cutover`,
    );
  }

  #assertMigrationImport(epoch: number): void {
    if (!Number.isSafeInteger(epoch) || epoch < 0) {
      throw new Error(`${REFUSAL}: migration import epoch must be a non-negative safe integer`);
    }
    if (epoch !== this.#migrationState.epoch) {
      throw new Error(
        `${REFUSAL}: migration import epoch ${epoch} does not match current epoch ` +
          `${this.#migrationState.epoch}`,
      );
    }
    if (this.#migrationState.mode !== "copying" && this.#migrationState.mode !== "verifying") {
      throw new Error(
        `${REFUSAL}: migration import is only allowed in copying/verifying, current mode is ${this.#migrationState.mode}`,
      );
    }
  }

  /**
   * Persist a write witness before running the SQL transaction. A failed SQL
   * transaction may advance the witness, but can never make it lag a committed
   * object write; rollback therefore fails closed instead of losing an object
   * mutation because the KV write happened after SQLite committed.
   */
  #recordWriteAttempt(willWrite: boolean): void {
    if (!willWrite) return;
    if (this.#migrationState.writeEpoch === Number.MAX_SAFE_INTEGER) {
      throw new Error(`${REFUSAL}: migration write epoch exhausted; refusing further writes`);
    }
    const next: PersistedTenantMigrationState = {
      mode: this.#migrationState.mode,
      epoch: this.#migrationState.epoch,
      writeEpoch: this.#migrationState.writeEpoch + 1,
    };
    this.#state.storage.kv.put(TENANT_MIGRATION_STATE_KEY, next);
    this.#migrationState = next;
  }

  #refuseUnprivilegedWrite(sql: string): void {
    const table = requiresPrivilegedWrite(sql);
    if (table === null) return;
    throw new Error(
      `${REFUSAL}: writes to ${table} require the privileged operator RPC; refusing ordinary tenant SQL`,
    );
  }

  // -------------------------------------------------------------------------
  // Execution
  // -------------------------------------------------------------------------

  /**
   * Run one statement and materialize its result.
   *
   * SYNCHRONOUS and called only from inside a `transactionSync` callback, which
   * is what makes the cursor drain safe: `.toArray()` happens in the same
   * synchronous stretch as the `exec()`, so no cursor is ever held across an
   * `await` where it could observe rows a rollback later removes.
   */
  #exec(statement: TenantDataStatement): TenantDataResult {
    const sql = this.#state.storage.sql;
    const before = connectionCounters(sql).changes;
    const cursor = sql.exec<Record<string, TenantDataValue>>(
      statement.sql,
      ...(statement.params ?? []),
    );
    // Drained BEFORE `rowsRead`/`rowsWritten` are read: the cursor's counters
    // are only final once it has been consumed.
    const results = cursor.toArray();
    const rowsRead = cursor.rowsRead;
    const rowsWritten = cursor.rowsWritten;
    // ONE trailing read for both connection-level counters. `total_changes()`
    // and `last_insert_rowid()` are both properties of the connection rather
    // than of the cursor, and reading them in a single `exec` keeps them from
    // straddling a statement that a future edit might insert between them.
    const after = connectionCounters(sql);
    return {
      results,
      changes: after.changes - before,
      rowsRead,
      rowsWritten,
      lastRowId: after.lastRowId,
      databaseSize: sql.databaseSize,
    };
  }

  // -------------------------------------------------------------------------
  // Schema migration
  // -------------------------------------------------------------------------

  /**
   * Bring the database to {@link latestVersion}. Synchronous throughout.
   *
   * The version gate is the first thing that happens, because this runs on every
   * cold start of every tenant object: an already-current tenant pays one
   * `sqlite_master` probe and one `MAX(version)` read and returns, instead of
   * re-running the 183 statements of the twenty files — 71 `CREATE TABLE IF
   * NOT EXISTS`, 89 `CREATE INDEX`, 6 `CREATE UNIQUE INDEX`, 10 `ALTER TABLE … ADD
   * COLUMN`, 6 ledger `INSERT` statements and one `DROP TABLE`. (Counted,
   * not estimated — and counted by a
   * TEST since #831's review: an earlier draft said "26 `CREATE INDEX`", and the
   * whole census then went stale again the moment `0013_guardrail_evaluations.sql`
   * landed. `test/do/tenant-data-object.test.ts` re-derives these five numbers
   * from `sql/d1-ts/tenant/` and asserts them. The ten ALTERs are the half that
   * matters — the CREATEs are idempotent by construction and the ALTERs are not,
   * so the gate is load-bearing rather than an optimisation.)
   */
  #migrate(): void {
    const applied = this.#appliedVersion();
    this.#assertLedgerHonest(applied);
    const pending = this.migrations().filter((migration) => migration.version > applied);
    if (pending.length === 0) return;

    for (const migration of pending) {
      try {
        // ONE transaction per FILE: the file's DDL and the ledger row that
        // records it commit or roll back together. That is strictly stronger
        // than what `wrangler d1 migrations apply` gives a D1 tenant, and it is
        // what makes the four ALTER-only migrations safe to gate on the version
        // number alone — SQLite has no `ADD COLUMN IF NOT EXISTS`, so a second
        // apply throws `duplicate column name`, and the only way that can
        // happen here is a ledger row that committed without its DDL, which
        // this transaction makes impossible.
        //
        // Note what is deliberately NOT done: `apps/gateway/test/setup-d1.ts`
        // wraps its ALTERs in a catch that swallows `duplicate column name`.
        // Copying that here would be a bug, not a convenience — inside a
        // transaction, catch-and-continue is exactly how a real error becomes a
        // half-applied schema that reports success.
        this.#state.storage.transactionSync(() => {
          for (const statement of sqlStatements(migration.sql)) {
            this.#state.storage.sql.exec(statement);
          }
          // Recorded LAST and inside the same transaction. `0001` already ends
          // with its own `INSERT OR IGNORE … VALUES (1, '0001_init_tenant')`;
          // `INSERT OR IGNORE` here makes this a no-op for that file rather
          // than a PRIMARY KEY conflict, and supplies the rows for 0002..0008,
          // which record nothing of their own. In D1 that ledger is vestigial
          // (only version 1 is ever written, and `wrangler`'s own
          // `d1_migrations` table does the real bookkeeping); inside a DO there
          // is no wrangler and no `d1_migrations`, so this IS the ledger.
          this.#state.storage.sql.exec(
            "INSERT OR IGNORE INTO storage_schema_migrations (version, name) VALUES (?, ?)",
            migration.version,
            migration.name,
          );
        });
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
          `schema migration stopped at version ${migration.version} (${migration.name}); ` +
            `the database is still at version ${this.#appliedVersion()} and this tenant is ` +
            `refusing every query. cause: ${detail}`,
        );
      }
      this.#appliedThisWake.push(migration.name);
    }
  }

  /** Highest recorded version; `0` when the ledger table does not exist yet. */
  #appliedVersion(): number {
    if (!this.#tableExists("storage_schema_migrations")) return 0;
    const rows = this.#state.storage.sql
      .exec<{ version: number | null }>(
        "SELECT MAX(version) AS version FROM storage_schema_migrations",
      )
      .toArray();
    const version = rows[0]?.version;
    return typeof version === "number" ? version : 0;
  }

  /**
   * Refuse a ledger that claims a schema the database does not have.
   *
   * The version row says what the applier BELIEVES; `sqlite_master` says what
   * the database IS. They can only disagree if a ledger row committed without
   * its DDL, which the per-file transaction above is designed to prevent — so
   * this check should never fire. It is here because the consequence of
   * proceeding on a disagreement is a tenant serving queries against a schema
   * that is missing tables, and failing closed on an impossible state costs one
   * `sqlite_master` probe per cold start.
   */
  #assertLedgerHonest(applied: number): void {
    if (applied >= 1 && !this.#tableExists(WITNESS_TABLE)) {
      throw new Error(
        [
          `schema ledger claims version ${applied} but table ${WITNESS_TABLE} is absent;`,
          "the migration ledger and the database disagree, so this tenant is refusing",
          "every query rather than serving an incomplete schema",
        ].join(" "),
      );
    }
  }

  #tableExists(name: string): boolean {
    return (
      this.#state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
          name,
        )
        .toArray().length > 0
    );
  }

  #auditHead(chainKey: string): { readonly seq: number; readonly rowHash: string } | null {
    const rows = this.#state.storage.sql
      .exec<{ seq: number; row_hash: string }>(
        "SELECT seq, row_hash FROM audit_events WHERE chain_key = ? ORDER BY seq DESC LIMIT 1",
        chainKey,
      )
      .toArray();
    const row = rows[0];
    return row === undefined ? null : { seq: row.seq, rowHash: row.row_hash };
  }
}

/**
 * The two CONNECTION-level counters `#exec` needs: `total_changes()` (rows
 * changed since the connection opened) and `last_insert_rowid()`.
 *
 * A free function so both reads in `#exec` are provably the same query, and one
 * `exec` for the pair so a future edit cannot slip a statement between them and
 * silently attribute one statement's rowid to another's change count. The
 * cursor is drained immediately, in the caller's synchronous stretch.
 *
 * Reading these is itself a `SELECT`, which changes neither counter — that is
 * what makes the before/after delta in `#exec` attributable to the caller's
 * statement alone.
 *
 * Exported for `control-data-object.ts`, whose `#exec` makes the identical
 * delta measurement over its own storage handle.
 */
export function connectionCounters(sql: SqlStorage): { changes: number; lastRowId: number } {
  const rows = sql
    .exec<{ n: number; r: number }>("SELECT total_changes() AS n, last_insert_rowid() AS r")
    .toArray();
  const row = rows[0];
  return { changes: row?.n ?? 0, lastRowId: row?.r ?? 0 };
}

/** The `[[durable_objects.bindings]]` namespace type for `env.TENANT_DATA`. */
export type TenantDataNamespace = DurableObjectNamespace<TenantDataObject>;
