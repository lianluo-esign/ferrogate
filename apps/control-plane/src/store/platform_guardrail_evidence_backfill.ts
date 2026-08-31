/**
 * Move platform/unattributed guardrail evidence out of the control projection
 * and into the authoritative `PlatformDataObject` before an operator read is
 * served (Zero-D1 Plan B).
 *
 * The platform sibling of `guardrail_evidence_backfill.ts`. That bridge copies
 * ONE tenant's qualified projection into its TenantDataObject; this one copies
 * the un-attributed rows — the ones no roster tenant owns and no fan-out reader
 * can reach — into the single platform object. G1's dual-write already lands
 * NEW unattributed evidence in the object, so this is the one-time copy of the
 * rows written to control BEFORE that dual-write existed. `INSERT OR IGNORE` on
 * the `id` primary key makes a row the dual-write already placed a no-op, so the
 * copy is idempotent even where the two overlap.
 *
 * ## The predicate is `(tenant IS NULL OR tenant = '')`, not `IS NULL` alone
 *
 * The gateway writes an unattributed row's `tenant` as `NULL` when the caller's
 * `organizationId` is absent and as `''` when it is the empty string
 * (`evidence-d1.ts`'s `bindOptional` passes `''` through). The retention sweep
 * (`sweepUnscopedProjection`) already treats BOTH as platform, so this copy must
 * too or it would strand the empty-string rows in control forever. The
 * destination is normalized to `NULL` — the object's single canonical "no owner"
 * value, matching what G1's `platformGuardrailEvidenceStatements` writes — so the
 * object never carries a mix of `NULL` and `''`.
 *
 * ## The marker lives in the object, keyed by `mark` alone
 *
 * The platform singleton has no tenant id, so it cannot use the tenant bridge's
 * `tenant_provisioning_marks` (keyed by `tenant_id`). It keeps the SAME JSON
 * `detail` shape in `platform_backfill_marks` keyed by `mark`. A completed mark
 * makes later control-projection lag invisible to the backfill, and the
 * conditional claim/update prevents an old in-flight call from reopening a
 * finished copy and dragging a post-cutover control row into the authority.
 */
import { HttpError } from "../middleware/errors.js";

/** The object-local marker for the one-time control→platform-object copy. */
export const PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK = "platform_evidence_backfill_v1";

/** Both `NULL` and `''` are platform/unattributed — see the module docblock. */
const UNATTRIBUTED_PREDICATE = "(tenant IS NULL OR tenant = '')";

/** Keep each cross-store copy bounded; the marker makes the loop resumable. */
const PAGE_SIZE = 100;
const MAX_PAGES_PER_READ = 16;

const CONTROL_EVALUATION_COLUMNS =
  "projection_key, id, request_id, trace_id, agent_run_id, subject_id, tenant, " +
  "scope_type, scope_id, target, protocol, stage, mode, policy_id, policy_revision, " +
  "verdict, action, enforcement_status, latency_ms, finding_count, input_fingerprint, " +
  "action_fingerprint, occurred_at_unix, evaluation_json";

interface ControlEvaluationRow {
  readonly projection_key: string;
  readonly id: string;
  readonly request_id: string;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly subject_id: string | null;
  readonly tenant: string | null;
  readonly scope_type: string;
  readonly scope_id: string | null;
  readonly target: string;
  readonly protocol: string;
  readonly stage: string;
  readonly mode: string;
  readonly policy_id: string;
  readonly policy_revision: number;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly latency_ms: number;
  readonly finding_count: number;
  readonly input_fingerprint: string;
  readonly action_fingerprint: string | null;
  readonly occurred_at_unix: number;
  readonly evaluation_json: string;
}

interface ControlCheckRow {
  readonly id: string;
  readonly evaluation_projection_key: string;
  readonly evaluation_id: string;
  readonly check_id: string;
  readonly detector_id: string;
  readonly detector_version: string;
  readonly config_digest: string;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly error_kind: string | null;
  readonly check_json: string;
}

interface BackfillMark {
  readonly state: "in_progress" | "complete";
  readonly cursor: string | null;
  readonly evaluations: number;
  readonly checks: number;
}

function placeholders(count: number): string {
  return new Array(count).fill("?").join(", ");
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
      evaluations: typeof candidate.evaluations === "number" ? candidate.evaluations : 0,
      checks: typeof candidate.checks === "number" ? candidate.checks : 0,
    };
  } catch {
    return undefined;
  }
}

async function readMark(platformDb: D1Database): Promise<BackfillMark | undefined> {
  const row = await platformDb
    .prepare("SELECT detail FROM platform_backfill_marks WHERE mark = ?")
    .bind(PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK)
    .first<{ detail: string | null }>();
  return parseMark(row?.detail);
}

async function evaluationPage(
  controlDb: D1Database,
  cursor: string | null,
): Promise<ControlEvaluationRow[]> {
  const predicate =
    cursor === null ? UNATTRIBUTED_PREDICATE : `${UNATTRIBUTED_PREDICATE} AND projection_key > ?`;
  const values = cursor === null ? [PAGE_SIZE] : [cursor, PAGE_SIZE];
  const rows = await controlDb
    .prepare(
      `SELECT ${CONTROL_EVALUATION_COLUMNS}
         FROM guardrail_evaluations
        WHERE ${predicate}
        ORDER BY projection_key ASC
        LIMIT ?`,
    )
    .bind(...values)
    .all<ControlEvaluationRow>();
  return rows.results;
}

async function checksFor(
  controlDb: D1Database,
  evaluations: readonly ControlEvaluationRow[],
): Promise<ControlCheckRow[]> {
  if (evaluations.length === 0) return [];
  const keys = evaluations.map((row) => row.projection_key);
  const rows = await controlDb
    .prepare(
      `SELECT id, evaluation_projection_key, evaluation_id, check_id,
              detector_id, detector_version, config_digest, verdict, action,
              enforcement_status, error_kind, check_json
         FROM guardrail_check_evaluations
        WHERE ${UNATTRIBUTED_PREDICATE}
          AND evaluation_projection_key IN (${placeholders(keys.length)})
        ORDER BY evaluation_projection_key ASC, check_id ASC`,
    )
    .bind(...keys)
    .all<ControlCheckRow>();
  return rows.results;
}

function markDetail(
  state: BackfillMark["state"],
  cursor: string | null,
  evaluations: number,
  checks: number,
): string {
  return JSON.stringify({ version: 1, state, cursor, evaluations, checks });
}

/**
 * Ensure the control projection's platform/unattributed guardrail evidence has
 * been copied into the platform object.
 *
 * Refuses to serve a partial copy: if there is more than the bounded work one
 * request completes, the progress mark is durable and the caller gets a
 * retryable 503, exactly like the tenant bridge. `INSERT OR IGNORE` preserves
 * live object writes that race the copy, and the conditional mark update stops
 * an old in-flight call from reopening a completed backfill.
 *
 * Early-returns when either side is absent: no control DB means nothing to copy
 * FROM (the memory posture), and no platform object means nowhere to copy TO
 * (the leg is skipped and the operator read falls back to its tenant union).
 */
export async function ensurePlatformGuardrailEvidenceBackfill(
  controlDb: D1Database | null,
  platformDb: D1Database | null,
): Promise<void> {
  if (controlDb === null || platformDb === null) return;

  const existing = await readMark(platformDb);
  if (existing?.state === "complete") return;

  let cursor = existing?.cursor ?? null;
  let evaluations = existing?.evaluations ?? 0;
  let checks = existing?.checks ?? 0;

  for (let pageNumber = 0; pageNumber < MAX_PAGES_PER_READ; pageNumber += 1) {
    const evaluationRows = await evaluationPage(controlDb, cursor);
    const checkRows = await checksFor(controlDb, evaluationRows);
    const nextCursor = evaluationRows.at(-1)?.projection_key ?? cursor;
    evaluations += evaluationRows.length;
    checks += checkRows.length;
    const complete = evaluationRows.length < PAGE_SIZE;

    // Claim the marker in the SAME transaction as the page writes. Every data
    // insert below also checks this row, so an older call that read the page
    // before another call completed the backfill becomes a no-op rather than
    // copying a later projection row into an already-authoritative object.
    const claimDetail = markDetail("in_progress", cursor, evaluations, checks);
    const claimStatement = platformDb
      .prepare(
        `INSERT OR IGNORE INTO platform_backfill_marks (mark, detail, applied_at_unix)
         VALUES (?, ?, ?)`,
      )
      .bind(PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK, claimDetail, Math.floor(Date.now() / 1000));
    // The platform object has no `projection_key` column: the single object
    // makes `id` unique on its own. `tenant` is normalized to NULL (see the
    // module docblock) rather than carried through as `''`.
    const parentStatement = platformDb.prepare(
      `INSERT OR IGNORE INTO guardrail_evaluations
         (id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type, scope_id,
          target, protocol, stage, mode, policy_id, policy_revision, verdict, action,
          enforcement_status, latency_ms, finding_count, input_fingerprint,
          action_fingerprint, occurred_at_unix, evaluation_json)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM platform_backfill_marks
           WHERE mark = ? AND detail NOT LIKE '%"state":"complete"%'
        )`,
    );
    const childStatement = platformDb.prepare(
      `INSERT OR IGNORE INTO guardrail_check_evaluations
         (id, evaluation_id, tenant, check_id, detector_id, detector_version,
          config_digest, verdict, action, enforcement_status, error_kind, check_json)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM platform_backfill_marks
           WHERE mark = ? AND detail NOT LIKE '%"state":"complete"%'
        )`,
    );
    const statements: D1PreparedStatement[] = [];
    statements.push(claimStatement);
    for (const row of evaluationRows) {
      statements.push(
        parentStatement.bind(
          row.id,
          row.request_id,
          row.trace_id ?? null,
          row.agent_run_id ?? null,
          row.subject_id ?? null,
          null,
          row.scope_type,
          row.scope_id ?? null,
          row.target,
          row.protocol,
          row.stage,
          row.mode,
          row.policy_id,
          row.policy_revision,
          row.verdict,
          row.action,
          row.enforcement_status,
          row.latency_ms,
          row.finding_count,
          row.input_fingerprint,
          row.action_fingerprint ?? null,
          row.occurred_at_unix,
          row.evaluation_json,
          PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK,
        ),
      );
    }
    for (const row of checkRows) {
      statements.push(
        childStatement.bind(
          row.id,
          row.evaluation_id,
          null,
          row.check_id,
          row.detector_id,
          row.detector_version,
          row.config_digest,
          row.verdict,
          row.action,
          row.enforcement_status,
          row.error_kind ?? null,
          row.check_json,
          PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK,
        ),
      );
    }

    const detail = markDetail(
      complete ? "complete" : "in_progress",
      nextCursor,
      evaluations,
      checks,
    );
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
        .bind(PLATFORM_GUARDRAIL_EVIDENCE_BACKFILL_MARK, detail, Math.floor(Date.now() / 1000)),
    );
    await platformDb.batch(statements);

    if (complete) return;
    cursor = nextCursor;
  }

  throw new HttpError(
    503,
    "platform_guardrail_evidence_backfill_incomplete",
    "platform guardrail evidence backfill is still in progress; retry",
  );
}
