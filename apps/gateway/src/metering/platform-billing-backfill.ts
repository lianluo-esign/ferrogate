/**
 * Copy the control projection's UNATTRIBUTED (`tenant_id IS NULL`) billing rows
 * into the authoritative `PlatformDataObject` (Zero-D1 Plan B) — the metering
 * sibling of `apps/control-plane/src/store/platform_request_log_backfill.ts`.
 *
 * G1's dual-write (`sink.ts` `#deliverOnce`) already lands EVERY NEW
 * unattributed settlement's `billing_events` + `billing_ledger` rows in the
 * platform object. This is the one-time copy of the rows written to CONTROL
 * *before* that dual-write existed — the historical backup the operator asked
 * for ("对旧的d1需要备份数据到新的do当中"). Removing the control D1 must not
 * strand them: an unattributed charge has no roster tenant, so no tenant
 * fan-out reader can ever reach it.
 *
 * ## Why this runs on the Cron, not a reader
 *
 * The request-log backfill is triggered inline before an operator list is
 * served and throws a retryable 503 while incomplete, because a reader must not
 * present a partial view. Billing reader cutover is DEFERRED (the polaris
 * system owns it later), so this is a pure WRITE-side migration with no reader
 * to hang off. It therefore runs as a bounded, resumable leg of
 * `gatewayScheduled` — the same place the retention sweeps run, the one context
 * that holds both bindings and has no request to serve — and NEVER throws.
 *
 * ## Idempotent and cutover-safe
 *
 * The control settlement path still dual-writes to BOTH stores in this slice
 * (G2, which stops the control write, is a later slice), so every control
 * `tenant_id IS NULL` row is a legitimate platform row forever — there is no
 * "post-cutover" control row to guard against here. Each copy is `ON CONFLICT
 * DO NOTHING` on the primary key (reusing the EXACT control insert statements
 * the dual-write binds), so a row the dual-write already placed is a no-op and
 * a re-drained tick cannot double-write. Progress lives in the object's
 * `platform_backfill_marks` (0002), one mark per table, so a tick that hits its
 * page budget resumes from the cursor on the next tick, and a completed mark
 * short-circuits before any control read — the steady-state cost is two small
 * object SELECTs per tick and zero control reads.
 *
 * ## The cursor is index-aligned
 *
 * Control carries `idx_control_billing_events_tenant
 * (tenant_id, occurred_at_unix, request_id, provider_attempt_index)` and
 * `idx_control_billing_ledger_tenant (tenant_id, created_at_unix, id)`
 * (`0020_billing_compatibility_columns.sql`). With `tenant_id` fixed to `NULL`
 * the remaining columns are the cursor, so each page seeks the index instead of
 * scanning the whole (large) billing table for the small unattributed subset —
 * the D1-read cost this whole migration exists to cut. `(request_id,
 * provider_attempt_index)` and `id` are unique tails, so the lexicographic
 * cursor never skips or repeats a boundary row. The predicate is spelled out
 * (`a > ? OR (a = ? AND b > ?) …`) rather than as a row-value tuple so it does
 * not depend on any row-value support beyond plain comparisons.
 */
import { BILLING_EVENT_INSERT_SQL, BILLING_LEDGER_INSERT_SQL } from "./d1.js";

// NO OUTBOX HISTORICAL BACKFILL, by design. This leg copies only the append-only
// evidence (`billing_events` + `billing_ledger`). The `billing_report_outbox` is
// ephemeral, mutable DELIVERY-INTENT (reschedule / dead-letter / reap), not
// append-only evidence: copying live or already-drained control outbox rows into
// the platform object would manufacture DOUBLE-PUBLISHES, since the platform
// `sweepPlatform` recovery drain would then re-deliver a charge control already
// reported. New unattributed intents land in the platform outbox through the
// request-path shadow (`sink.ts` `#deliverOnce`) and are reaped in the same pass;
// dead-letters stay on control this slice as a deferred reader concern (polaris).

/** The `GATEWAY_PLATFORM_BILLING_BACKFILL = "on"` gate — defaults OFF. */
export const PLATFORM_BILLING_BACKFILL_FLAG = "GATEWAY_PLATFORM_BILLING_BACKFILL";

/** The object-local markers for the one-time control→object copy, one per table. */
export const PLATFORM_BILLING_EVENTS_BACKFILL_MARK = "platform_billing_events_backfill_v1";
export const PLATFORM_BILLING_LEDGER_BACKFILL_MARK = "platform_billing_ledger_backfill_v1";

/** Keep each cross-store copy bounded; the marker makes the loop resumable. */
const PAGE_SIZE = 100;
const MAX_PAGES_PER_TICK = 16;

/** One table's copy specification. */
interface BackfillSpec {
  readonly mark: string;
  readonly sourceTable: string;
  /** Columns SELECTed from control, in the INSERT's bind order. */
  readonly selectColumns: readonly string[];
  /** The lexicographic cursor columns (a unique tail), in ORDER BY order. */
  readonly cursorColumns: readonly string[];
  /** The control-variant `ON CONFLICT DO NOTHING` insert (reused verbatim). */
  readonly insertSql: string;
}

const EVENTS_SPEC: BackfillSpec = {
  mark: PLATFORM_BILLING_EVENTS_BACKFILL_MARK,
  sourceTable: "billing_events",
  selectColumns: [
    "billing_event_id",
    "request_id",
    "provider_attempt_index",
    "occurred_at_unix",
    "event_json",
  ],
  cursorColumns: ["occurred_at_unix", "request_id", "provider_attempt_index"],
  insertSql: BILLING_EVENT_INSERT_SQL,
};

const LEDGER_SPEC: BackfillSpec = {
  mark: PLATFORM_BILLING_LEDGER_BACKFILL_MARK,
  sourceTable: "billing_ledger",
  selectColumns: [
    "id",
    "organization_id",
    "project_id",
    "api_key_id",
    "created_at_unix",
    "entry_json",
  ],
  cursorColumns: ["created_at_unix", "id"],
  insertSql: BILLING_LEDGER_INSERT_SQL,
};

type TableOutcome = "skipped" | "complete" | "in_progress";

export interface PlatformBillingBackfillSummary {
  events: TableOutcome;
  ledger: TableOutcome;
  copied: number;
}

interface BackfillMark {
  readonly state: "in_progress" | "complete";
  readonly cursor: readonly unknown[] | null;
  readonly rows: number;
}

function parseMark(detail: string | null | undefined): BackfillMark | undefined {
  if (detail === undefined || detail === null || detail.trim() === "") return undefined;
  try {
    const value: unknown = JSON.parse(detail);
    if (typeof value !== "object" || value === null) return undefined;
    const candidate = value as Record<string, unknown>;
    if (candidate.state !== "in_progress" && candidate.state !== "complete") return undefined;
    return {
      state: candidate.state,
      cursor: Array.isArray(candidate.cursor) ? candidate.cursor : null,
      rows: typeof candidate.rows === "number" ? candidate.rows : 0,
    };
  } catch {
    return undefined;
  }
}

async function readMark(platformDb: D1Database, mark: string): Promise<BackfillMark | undefined> {
  const row = await platformDb
    .prepare("SELECT detail FROM platform_backfill_marks WHERE mark = ?")
    .bind(mark)
    .first<{ detail: string | null }>();
  return parseMark(row?.detail);
}

function markDetail(state: BackfillMark["state"], cursor: readonly unknown[] | null, rows: number): string {
  return JSON.stringify({ version: 1, state, cursor, rows });
}

/**
 * The lexicographic "strictly after `cursor`" predicate, spelled out so it uses
 * only plain column comparisons. For cursor columns `[a, b, c]` and values
 * `[x, y, z]` it emits `(a > x) OR (a = x AND b > y) OR (a = x AND b = y AND c > z)`.
 */
function cursorPredicate(
  columns: readonly string[],
  cursor: readonly unknown[] | null,
): { sql: string; values: unknown[] } {
  if (cursor === null || cursor.length !== columns.length) {
    return { sql: "tenant_id IS NULL", values: [] };
  }
  const terms: string[] = [];
  const values: unknown[] = [];
  for (let i = 0; i < columns.length; i += 1) {
    const clause: string[] = [];
    for (let j = 0; j < i; j += 1) {
      clause.push(`${columns[j]} = ?`);
      values.push(cursor[j]);
    }
    clause.push(`${columns[i]} > ?`);
    values.push(cursor[i]);
    terms.push(`(${clause.join(" AND ")})`);
  }
  return { sql: `tenant_id IS NULL AND (${terms.join(" OR ")})`, values };
}

async function selectPage(
  controlDb: D1Database,
  spec: BackfillSpec,
  cursor: readonly unknown[] | null,
): Promise<Record<string, unknown>[]> {
  const predicate = cursorPredicate(spec.cursorColumns, cursor);
  const orderBy = spec.cursorColumns.map((c) => `${c} ASC`).join(", ");
  const rows = await controlDb
    .prepare(
      `SELECT ${spec.selectColumns.join(", ")}
         FROM ${spec.sourceTable}
        WHERE ${predicate.sql}
        ORDER BY ${orderBy}
        LIMIT ?`,
    )
    .bind(...predicate.values, PAGE_SIZE)
    .all<Record<string, unknown>>();
  return rows.results;
}

async function runBackfillTable(
  controlDb: D1Database,
  platformDb: D1Database,
  spec: BackfillSpec,
  nowUnix: number,
): Promise<{ outcome: TableOutcome; copied: number }> {
  const existing = await readMark(platformDb, spec.mark);
  if (existing?.state === "complete") return { outcome: "complete", copied: 0 };

  let cursor: readonly unknown[] | null = existing?.cursor ?? null;
  let total = existing?.rows ?? 0;
  let copiedThisTick = 0;
  const insert = platformDb.prepare(spec.insertSql);
  // The upsert refuses to reopen a mark another tick already completed.
  const markUpsert = platformDb.prepare(
    `INSERT INTO platform_backfill_marks (mark, detail, applied_at_unix)
       VALUES (?, ?, ?)
       ON CONFLICT (mark) DO UPDATE SET
         detail = excluded.detail,
         applied_at_unix = excluded.applied_at_unix
       WHERE platform_backfill_marks.detail NOT LIKE '%"state":"complete"%'`,
  );

  for (let page = 0; page < MAX_PAGES_PER_TICK; page += 1) {
    const rows = await selectPage(controlDb, spec, cursor);
    const complete = rows.length < PAGE_SIZE;
    const nextCursor =
      rows.length === 0
        ? cursor
        : spec.cursorColumns.map((c) => (rows[rows.length - 1] as Record<string, unknown>)[c]);
    total += rows.length;
    copiedThisTick += rows.length;

    // One atomic batch: the row inserts land iff the advanced mark lands, so a
    // failed batch leaves the mark at the previous cursor and the tick resumes
    // there. The mark write is LAST for readability; D1 batches are transactional.
    const statements: D1PreparedStatement[] = rows.map((row) =>
      insert.bind(...spec.selectColumns.map((c) => (row as Record<string, unknown>)[c] ?? null)),
    );
    statements.push(
      markUpsert.bind(
        spec.mark,
        markDetail(complete ? "complete" : "in_progress", nextCursor, total),
        nowUnix,
      ),
    );
    await platformDb.batch(statements);

    if (complete) return { outcome: "complete", copied: copiedThisTick };
    cursor = nextCursor;
  }
  return { outcome: "in_progress", copied: copiedThisTick };
}

/**
 * Resumably copy the control projection's unattributed billing into the
 * platform object. NEVER throws — a backfill outage must not take the
 * billing-outbox recovery sweep on the same tick down with it.
 *
 * Early-returns when the gate is off, when there is no control DB to copy FROM
 * (memory posture) or no platform object to copy TO (unbound `PLATFORM_DATA`).
 */
export async function sweepPlatformBillingBackfill(
  env: unknown,
  controlDb: D1Database | null | undefined,
  platformDb: D1Database | null | undefined,
  nowUnix: number,
): Promise<PlatformBillingBackfillSummary> {
  const summary: PlatformBillingBackfillSummary = {
    events: "skipped",
    ledger: "skipped",
    copied: 0,
  };
  const flag = (env as Record<string, unknown> | null | undefined)?.[PLATFORM_BILLING_BACKFILL_FLAG];
  if (flag !== "on") return summary;
  if (controlDb == null || platformDb == null) return summary;

  for (const spec of [EVENTS_SPEC, LEDGER_SPEC] as const) {
    try {
      const { outcome, copied } = await runBackfillTable(controlDb, platformDb, spec, nowUnix);
      summary.copied += copied;
      if (spec === EVENTS_SPEC) summary.events = outcome;
      else summary.ledger = outcome;
    } catch (error) {
      console.warn(
        `[ferrogate] platform billing backfill (${spec.sourceTable}) failed; control projection is unaffected: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return summary;
}
