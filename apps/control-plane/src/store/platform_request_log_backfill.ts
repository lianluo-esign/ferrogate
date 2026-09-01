/**
 * Move platform/unattributed request logs out of the control projection and into
 * the authoritative `PlatformDataObject` before an operator list/export is served
 * (Zero-D1 Plan B).
 *
 * The request-log sibling of `platform_guardrail_evidence_backfill.ts`. Same
 * shape, same marker discipline, one structural difference: `request_logs` is a
 * SINGLE table with no child `checks` rows, so this is a one-table copy rather
 * than a parent+child one. G1's dual-write (`apps/gateway/src/requestlog/`)
 * already lands NEW unattributed rows in the platform object, so this is the
 * one-time copy of the rows written to CONTROL before that dual-write existed.
 * `INSERT OR IGNORE` on the `request_id` primary key makes a row the dual-write
 * already placed a no-op, so the copy is idempotent even where the two overlap.
 *
 * ## The predicate is `(tenant IS NULL OR tenant = '')`, not `IS NULL` alone
 *
 * The gateway writes an unattributed row's `tenant` as `NULL` when the caller's
 * `organizationId` is absent and as `''` when it is the empty string
 * (`requestlog/d1.ts`'s `bindOptional` passes `''` through). The retention sweep
 * (`sweepUnscopedProjection`) already treats BOTH as platform, so this copy must
 * too or it would strand the empty-string rows in control forever. The
 * destination is normalized to `NULL` — the object's single canonical "no owner"
 * value, matching what G1's `platformRequestLogStatements` writes — so the object
 * never carries a mix of `NULL` and `''`.
 *
 * ## `guardrail_verdict` is COALESCEd to `'not_screened'`
 *
 * The control projection's `guardrail_verdict` is nullable; the platform table
 * declares it `NOT NULL DEFAULT 'not_screened'` (matching the tenant table). A
 * legacy control row that predates guardrail screening has `NULL` there, so the
 * copy substitutes the same default the table would apply on an omitted column —
 * a `NULL` insert would otherwise fail the NOT NULL constraint and strand that
 * row in control forever.
 *
 * ## The marker lives in the object, keyed by `mark` alone
 *
 * The platform singleton has no tenant id, so it cannot use the tenant bridge's
 * `tenant_provisioning_marks` (keyed by `tenant_id`). It keeps the SAME JSON
 * `detail` shape in `platform_backfill_marks` (0002) keyed by `mark`, under a
 * mark distinct from the guardrail copy's. A completed mark makes later
 * control-projection lag invisible to the backfill, and the conditional
 * claim/update prevents an old in-flight call from reopening a finished copy and
 * dragging a post-cutover control row into the authority.
 */
import { HttpError } from "../middleware/errors.js";

/** The object-local marker for the one-time control→platform-object copy. */
export const PLATFORM_REQUEST_LOG_BACKFILL_MARK = "platform_request_log_backfill_v1";

/** Both `NULL` and `''` are platform/unattributed — see the module docblock. */
const UNATTRIBUTED_PREDICATE = "(tenant IS NULL OR tenant = '')";

/** Keep each cross-store copy bounded; the marker makes the loop resumable. */
const PAGE_SIZE = 100;
const MAX_PAGES_PER_READ = 16;

/**
 * The control columns read, `projection_key` first (the cursor) followed by the
 * 29 data columns the platform table carries, in the platform table's own order.
 */
const CONTROL_REQUEST_LOG_COLUMNS =
  "projection_key, request_id, trace_id, agent_run_id, delegation_chain, delegation_root, " +
  "experiment_id, experiment_arm, routing_decision, tenant, project, workspace, api_key_id, " +
  "route, provider, logical_model, provider_model, status_code, error_code, cache_status, " +
  "latency_ms, prompt_tokens, completion_tokens, total_tokens, guardrail_verdict, " +
  "guardrail_policy_id, streamed, started_at_unix, completed_at_unix, request_json";

interface ControlRequestLogRow {
  readonly projection_key: string;
  readonly request_id: string;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly delegation_chain: string | null;
  readonly delegation_root: string | null;
  readonly experiment_id: string | null;
  readonly experiment_arm: string | null;
  readonly routing_decision: string | null;
  readonly tenant: string | null;
  readonly project: string | null;
  readonly workspace: string | null;
  readonly api_key_id: string | null;
  readonly route: string | null;
  readonly provider: string | null;
  readonly logical_model: string | null;
  readonly provider_model: string | null;
  readonly status_code: number | null;
  readonly error_code: string | null;
  readonly cache_status: string | null;
  readonly latency_ms: number | null;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly guardrail_verdict: string | null;
  readonly guardrail_policy_id: string | null;
  readonly streamed: number | null;
  readonly started_at_unix: number;
  readonly completed_at_unix: number | null;
  readonly request_json: string;
}

interface BackfillMark {
  readonly state: "in_progress" | "complete";
  readonly cursor: string | null;
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
      cursor: typeof candidate.cursor === "string" ? candidate.cursor : null,
      rows: typeof candidate.rows === "number" ? candidate.rows : 0,
    };
  } catch {
    return undefined;
  }
}

async function readMark(platformDb: D1Database): Promise<BackfillMark | undefined> {
  const row = await platformDb
    .prepare("SELECT detail FROM platform_backfill_marks WHERE mark = ?")
    .bind(PLATFORM_REQUEST_LOG_BACKFILL_MARK)
    .first<{ detail: string | null }>();
  return parseMark(row?.detail);
}

async function requestLogPage(
  controlDb: D1Database,
  cursor: string | null,
): Promise<ControlRequestLogRow[]> {
  const predicate =
    cursor === null ? UNATTRIBUTED_PREDICATE : `${UNATTRIBUTED_PREDICATE} AND projection_key > ?`;
  const values = cursor === null ? [PAGE_SIZE] : [cursor, PAGE_SIZE];
  const rows = await controlDb
    .prepare(
      `SELECT ${CONTROL_REQUEST_LOG_COLUMNS}
         FROM request_logs
        WHERE ${predicate}
        ORDER BY projection_key ASC
        LIMIT ?`,
    )
    .bind(...values)
    .all<ControlRequestLogRow>();
  return rows.results;
}

function markDetail(state: BackfillMark["state"], cursor: string | null, rows: number): string {
  return JSON.stringify({ version: 1, state, cursor, rows });
}

/**
 * Ensure the control projection's platform/unattributed request logs have been
 * copied into the platform object.
 *
 * Refuses to serve a partial copy: if there is more than the bounded work one
 * request completes, the progress mark is durable and the caller gets a
 * retryable 503, exactly like the guardrail sibling. `INSERT OR IGNORE`
 * preserves live object writes that race the copy, and the conditional mark
 * update stops an old in-flight call from reopening a completed backfill.
 *
 * Early-returns when either side is absent: no control DB means nothing to copy
 * FROM (the memory posture), and no platform object means nowhere to copy TO
 * (the leg is skipped and the operator read falls back to its tenant union).
 */
export async function ensurePlatformRequestLogBackfill(
  controlDb: D1Database | null,
  platformDb: D1Database | null,
): Promise<void> {
  if (controlDb === null || platformDb === null) return;

  const existing = await readMark(platformDb);
  if (existing?.state === "complete") return;

  let cursor = existing?.cursor ?? null;
  let copied = existing?.rows ?? 0;

  for (let pageNumber = 0; pageNumber < MAX_PAGES_PER_READ; pageNumber += 1) {
    const rows = await requestLogPage(controlDb, cursor);
    const nextCursor = rows.at(-1)?.projection_key ?? cursor;
    copied += rows.length;
    const complete = rows.length < PAGE_SIZE;

    // Claim the marker in the SAME transaction as the page writes. Every data
    // insert below also checks this row, so an older call that read the page
    // before another call completed the backfill becomes a no-op rather than
    // copying a later projection row into an already-authoritative object.
    const claimStatement = platformDb
      .prepare(
        `INSERT OR IGNORE INTO platform_backfill_marks (mark, detail, applied_at_unix)
         VALUES (?, ?, ?)`,
      )
      .bind(
        PLATFORM_REQUEST_LOG_BACKFILL_MARK,
        markDetail("in_progress", cursor, copied),
        Math.floor(Date.now() / 1000),
      );
    // The platform object has no `projection_key` column: the single object makes
    // `request_id` unique on its own. `tenant` is normalized to NULL (see the
    // module docblock) rather than carried through as `''`, and a legacy
    // `NULL` `guardrail_verdict` takes the table's `'not_screened'` default.
    const insertStatement = platformDb.prepare(
      `INSERT OR IGNORE INTO request_logs
         (request_id, trace_id, agent_run_id, delegation_chain, delegation_root,
          experiment_id, experiment_arm, routing_decision, tenant, project, workspace,
          api_key_id, route, provider, logical_model, provider_model, status_code,
          error_code, cache_status, latency_ms, prompt_tokens, completion_tokens,
          total_tokens, guardrail_verdict, guardrail_policy_id, streamed,
          started_at_unix, completed_at_unix, request_json)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM platform_backfill_marks
           WHERE mark = ? AND detail NOT LIKE '%"state":"complete"%'
        )`,
    );
    const statements: D1PreparedStatement[] = [claimStatement];
    for (const row of rows) {
      statements.push(
        insertStatement.bind(
          row.request_id,
          row.trace_id ?? null,
          row.agent_run_id ?? null,
          row.delegation_chain ?? null,
          row.delegation_root ?? null,
          row.experiment_id ?? null,
          row.experiment_arm ?? null,
          row.routing_decision ?? null,
          null,
          row.project ?? null,
          row.workspace ?? null,
          row.api_key_id ?? null,
          row.route ?? null,
          row.provider ?? null,
          row.logical_model ?? null,
          row.provider_model ?? null,
          row.status_code ?? null,
          row.error_code ?? null,
          row.cache_status ?? null,
          row.latency_ms ?? null,
          row.prompt_tokens ?? null,
          row.completion_tokens ?? null,
          row.total_tokens ?? null,
          row.guardrail_verdict ?? "not_screened",
          row.guardrail_policy_id ?? null,
          row.streamed ?? 0,
          row.started_at_unix,
          row.completed_at_unix ?? null,
          row.request_json,
          PLATFORM_REQUEST_LOG_BACKFILL_MARK,
        ),
      );
    }

    statements.push(
      platformDb
        .prepare(
          `INSERT INTO platform_backfill_marks (mark, detail, applied_at_unix)
           VALUES (?, ?, ?)
           ON CONFLICT (mark) DO UPDATE SET
             detail = excluded.detail,
             applied_at_unix = excluded.applied_at_unix
           WHERE platform_backfill_marks.detail NOT LIKE '%"state":"complete"%'`,
        )
        .bind(
          PLATFORM_REQUEST_LOG_BACKFILL_MARK,
          markDetail(complete ? "complete" : "in_progress", nextCursor, copied),
          Math.floor(Date.now() / 1000),
        ),
    );
    await platformDb.batch(statements);

    if (complete) return;
    cursor = nextCursor;
  }

  throw new HttpError(
    503,
    "platform_request_log_backfill_incomplete",
    "platform request-log backfill is still in progress; retry",
  );
}
