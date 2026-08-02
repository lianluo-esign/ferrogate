/**
 * Policy-driven retention for guardrail evidence (#665) — the answer to "and
 * then it grows forever", which is the other half of turning on an append-only
 * evidence table.
 *
 * ## Why this reuses #664's policy rather than declaring its own vars
 *
 * `REQUEST_LOG_RETENTION_DAYS` / `REQUEST_LOG_RETENTION_POLICIES` already
 * express, per tenant, how long this deployment keeps the record of what the
 * gateway DID. A guardrail evaluation is a row of exactly that record — it is
 * joined to a request log by `request_id` and read through the same
 * investigation view — so giving it a second, independently-set window would
 * create a state nobody wants and everybody would eventually reach: a request
 * log whose screening evidence has been deleted, or screening evidence for a
 * request that no longer exists. An investigation that can only half-answer is
 * the failure this issue exists to fix.
 *
 * Adding vars is also not free in this tree: the env-var drift gates pin the
 * declared set exactly, and two knobs that must be kept equal are a worse
 * operator surface than one.
 *
 * If a later slice genuinely needs to diverge (a jurisdiction that requires
 * screening evidence longer than traffic logs), the split belongs in
 * `requestlog/retention.ts::RequestLogRetentionScope` as a per-table override,
 * not in a parallel copy of the parser.
 *
 * ## `ON DELETE CASCADE` does the child rows
 *
 * `guardrail_check_evaluations.evaluation_id` is declared
 * `REFERENCES guardrail_evaluations(id) ON DELETE CASCADE`, so deleting the
 * parent takes its checks with it. The sweep therefore issues ONE delete per
 * doomed evaluation and cannot leave an orphaned check row — evidence pointing
 * at a decision that no longer exists, which is worse than no row at all.
 *
 * D1 enables foreign keys by default, but a database that somehow does not
 * would silently accumulate orphans; the child sweep below is issued
 * unconditionally for that reason and is a no-op when the cascade already ran.
 */
import { type LogRetentionCandidate, planLogRetention } from "@ferrogate/storage";
import {
  REQUEST_LOG_SWEEP_MAX_ROWS,
  type RequestLogRetentionScope,
  type RequestLogSweepResult,
  requestLogRetentionFromEnv,
} from "../requestlog/retention.js";
import {
  GUARDRAIL_CHECK_TABLE,
  GUARDRAIL_EVALUATION_TABLE,
  type GuardrailEvidenceDatabase,
} from "./evidence-d1.js";

interface CandidateRow {
  readonly id: string;
  readonly occurred_at_unix: number;
}

/**
 * Apply one scope's rule to `guardrail_evaluations`.
 *
 * The candidate window is the OLDEST rows in the scope, because those are the
 * only ones an age rule can select; ascending order means the sweep does useful
 * work on its first tick against a large table instead of paging through rows
 * it will certainly keep.
 *
 * A tenant-scoped rule uses STRICT equality, so the fleet default — and only
 * the fleet default — governs the un-attributed (platform) rows. An operator
 * who narrows one tenant's window must not thereby narrow everyone's.
 *
 * Never throws: a retention failure is an unpruned table, which is safe.
 */
export async function sweepGuardrailEvidenceRetention(
  db: GuardrailEvidenceDatabase,
  scope: RequestLogRetentionScope,
  nowUnix: number,
  maxRows: number = REQUEST_LOG_SWEEP_MAX_ROWS,
): Promise<RequestLogSweepResult> {
  const fence = scope.tenantId === undefined ? "" : " WHERE tenant = ?";
  const params = scope.tenantId === undefined ? [] : [scope.tenantId];

  let rows: CandidateRow[];
  try {
    const result = (await db
      .prepare(
        `SELECT id, occurred_at_unix FROM ${GUARDRAIL_EVALUATION_TABLE}${fence}
          ORDER BY occurred_at_unix ASC LIMIT ?`,
      )
      .bind(...params, maxRows)
      .all()) as { results?: CandidateRow[] };
    rows = result.results ?? [];
  } catch {
    return { scanned: 0, pruned: 0 };
  }

  const candidates: LogRetentionCandidate[] = rows.map((row) => ({
    id: row.id,
    createdAtUnix: row.occurred_at_unix,
  }));
  // The PLANNER is reused rather than restated as a SQL predicate. Its
  // semantics — fail-safe KEEP on any doubt, `minAgeSecs` as an absolute floor,
  // an inert policy pruning nothing — are the contract, and re-deriving them in
  // a `DELETE ... WHERE occurred_at_unix < ?` here is how the two would come to
  // disagree about a boundary case that only shows up as missing evidence.
  const doomed = planLogRetention(candidates, nowUnix, scope.policy);
  if (doomed.length === 0) return { scanned: rows.length, pruned: 0 };

  try {
    const parents = db.prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE} WHERE id = ?`);
    const children = db.prepare(`DELETE FROM ${GUARDRAIL_CHECK_TABLE} WHERE evaluation_id = ?`);
    // Children first, then parents: with the cascade on, the second delete is a
    // no-op; without it, this is what stops the orphans. Doing it in the other
    // order would leave a window in which the checks are unreachable.
    await db.batch([
      ...doomed.map((id) => children.bind(id)),
      ...doomed.map((id) => parents.bind(id)),
    ]);
  } catch {
    return { scanned: rows.length, pruned: 0 };
  }
  return { scanned: rows.length, pruned: doomed.length };
}

/**
 * Every configured scope, swept once. The `scheduled` handler's entry point.
 *
 * With no vars configured this resolves to zero scopes and returns without
 * touching the database — an operator who has not opted into retention keeps
 * everything, which is the only safe default for evidence.
 */
export async function sweepGuardrailEvidence(
  db: GuardrailEvidenceDatabase,
  env: unknown,
  nowUnix: number,
): Promise<RequestLogSweepResult> {
  let scanned = 0;
  let pruned = 0;
  for (const scope of requestLogRetentionFromEnv(env)) {
    const result = await sweepGuardrailEvidenceRetention(db, scope, nowUnix);
    scanned += result.scanned;
    pruned += result.pruned;
  }
  return { scanned, pruned };
}
