/**
 * Move tenant-attributed guardrail evidence written before #860 into the
 * authoritative TenantDataObject before a tenant-scoped read is served.
 *
 * The SQL migration can rebuild CONTROL tables, but it cannot write across the
 * CONTROL D1 and a Durable Object. This worker-side step is therefore the
 * cutover bridge: it reads only the tenant's qualified projection, writes the
 * object with INSERT-OR-IGNORE semantics, and records progress in the object.
 * A completed mark makes later projection lag invisible to the backfill.
 */
import type { TenantDatabaseRouter } from "@ferrogate/storage";
import { HttpError } from "../middleware/errors.js";
import { tenantEvidenceDatabaseFor } from "./tenancy.js";

/** The object-local marker for the one-time pre-#860 copy. */
export const GUARDRAIL_EVIDENCE_BACKFILL_MARK = "guardrail_evidence_backfill_v1";

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
  readonly tenant: string | null;
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

async function readMark(db: D1Database, tenantId: string): Promise<BackfillMark | undefined> {
  const row = await db
    .prepare("SELECT detail FROM tenant_provisioning_marks WHERE tenant_id = ? AND mark = ?")
    .bind(tenantId, GUARDRAIL_EVIDENCE_BACKFILL_MARK)
    .first<{ detail: string | null }>();
  return parseMark(row?.detail);
}

async function evaluationPage(
  controlDb: D1Database,
  tenantId: string,
  cursor: string | null,
): Promise<ControlEvaluationRow[]> {
  const predicate = cursor === null ? "tenant = ?" : "tenant = ? AND projection_key > ?";
  const values = cursor === null ? [tenantId, PAGE_SIZE] : [tenantId, cursor, PAGE_SIZE];
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
  tenantId: string,
  evaluations: readonly ControlEvaluationRow[],
): Promise<ControlCheckRow[]> {
  if (evaluations.length === 0) return [];
  const keys = evaluations.map((row) => row.projection_key);
  const rows = await controlDb
    .prepare(
      `SELECT id, evaluation_projection_key, evaluation_id, tenant, check_id,
              detector_id, detector_version, config_digest, verdict, action,
              enforcement_status, error_kind, check_json
         FROM guardrail_check_evaluations
        WHERE tenant = ? AND evaluation_projection_key IN (${placeholders(keys.length)})
        ORDER BY evaluation_projection_key ASC, check_id ASC`,
    )
    .bind(tenantId, ...keys)
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
 * Ensure one tenant's old CONTROL projection has been copied into its object.
 *
 * The function refuses to serve a partial copy: if a tenant has more than the
 * bounded work completed in one request, the progress mark is durable and the
 * caller gets a retryable 503. INSERT-OR-IGNORE preserves live object writes
 * that race the migration, while the conditional mark update prevents an old
 * in-flight call from reopening a completed backfill and copying later
 * projection lag into the authority.
 */
export async function ensureTenantGuardrailEvidenceBackfill(
  controlDb: D1Database | null,
  router: TenantDatabaseRouter,
  tenantId: string,
): Promise<void> {
  if (controlDb === null) return;
  const normalizedTenantId = tenantId.trim();
  if (normalizedTenantId === "") return;

  const tenantDb = await tenantEvidenceDatabaseFor(router, normalizedTenantId);
  const existing = await readMark(tenantDb, normalizedTenantId);
  if (existing?.state === "complete") return;

  let cursor = existing?.cursor ?? null;
  let evaluations = existing?.evaluations ?? 0;
  let checks = existing?.checks ?? 0;

  for (let pageNumber = 0; pageNumber < MAX_PAGES_PER_READ; pageNumber += 1) {
    const evaluationRows = await evaluationPage(controlDb, normalizedTenantId, cursor);
    const checkRows = await checksFor(controlDb, normalizedTenantId, evaluationRows);
    const nextCursor = evaluationRows.at(-1)?.projection_key ?? cursor;
    evaluations += evaluationRows.length;
    checks += checkRows.length;
    const complete = evaluationRows.length < PAGE_SIZE;

    // Claim the marker in the SAME transaction as the page writes. Every data
    // insert below also checks this row, so an older call that read the page
    // before another call completed the backfill becomes a no-op rather than
    // copying a later projection row into an already-authoritative object.
    const claimDetail = markDetail("in_progress", cursor, evaluations, checks);
    const claimStatement = tenantDb
      .prepare(
        `INSERT OR IGNORE INTO tenant_provisioning_marks
           (tenant_id, mark, detail, applied_at_unix)
         VALUES (?, ?, ?, ?)`,
      )
      .bind(
        normalizedTenantId,
        GUARDRAIL_EVIDENCE_BACKFILL_MARK,
        claimDetail,
        Math.floor(Date.now() / 1000),
      );
    const parentStatement = tenantDb.prepare(
      `INSERT OR IGNORE INTO guardrail_evaluations
         (id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type, scope_id,
          target, protocol, stage, mode, policy_id, policy_revision, verdict, action,
          enforcement_status, latency_ms, finding_count, input_fingerprint,
          action_fingerprint, occurred_at_unix, evaluation_json)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM tenant_provisioning_marks
           WHERE tenant_id = ? AND mark = ? AND detail NOT LIKE '%"state":"complete"%'
        )`,
    );
    const childStatement = tenantDb.prepare(
      `INSERT OR IGNORE INTO guardrail_check_evaluations
         (id, evaluation_id, tenant, check_id, detector_id, detector_version,
          config_digest, verdict, action, enforcement_status, error_kind, check_json)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM tenant_provisioning_marks
           WHERE tenant_id = ? AND mark = ? AND detail NOT LIKE '%"state":"complete"%'
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
          normalizedTenantId,
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
          normalizedTenantId,
          GUARDRAIL_EVIDENCE_BACKFILL_MARK,
        ),
      );
    }
    for (const row of checkRows) {
      statements.push(
        childStatement.bind(
          row.id,
          row.evaluation_id,
          normalizedTenantId,
          row.check_id,
          row.detector_id,
          row.detector_version,
          row.config_digest,
          row.verdict,
          row.action,
          row.enforcement_status,
          row.error_kind ?? null,
          row.check_json,
          normalizedTenantId,
          GUARDRAIL_EVIDENCE_BACKFILL_MARK,
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
      tenantDb
        .prepare(
          `INSERT INTO tenant_provisioning_marks
             (tenant_id, mark, detail, applied_at_unix)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (tenant_id, mark) DO UPDATE SET
             detail = excluded.detail,
             applied_at_unix = excluded.applied_at_unix
           WHERE tenant_provisioning_marks.detail NOT LIKE '%"state":"complete"%'`,
        )
        .bind(
          normalizedTenantId,
          GUARDRAIL_EVIDENCE_BACKFILL_MARK,
          detail,
          Math.floor(Date.now() / 1000),
        ),
    );
    await tenantDb.batch(statements);

    if (complete) return;
    cursor = nextCursor;
  }

  throw new HttpError(
    503,
    "guardrail_evidence_backfill_incomplete",
    `tenant ${normalizedTenantId} guardrail evidence backfill is still in progress; retry`,
  );
}
