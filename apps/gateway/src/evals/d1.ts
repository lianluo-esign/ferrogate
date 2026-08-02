/**
 * `online_eval_scores` and `online_eval_regressions` in the CONTROL database.
 *
 * The tables are defined by `sql/d1-ts/control/0009_online_eval.sql`.
 * `apps/gateway` is the only writer (the queue consumer and the cron sweep);
 * nothing reads them from an admin route yet — see `./index.ts` for why that is
 * deliberate rather than forgotten.
 *
 * ============================================================================
 * THE JOIN THIS SCHEMA EXISTS TO MAKE POSSIBLE
 * ============================================================================
 *
 * "Did quality move WITH cost" is the only question anyone actually asks, and it
 * needs both numbers on one axis. #677 files per-request cost in
 * `billing_events` keyed by `request_id`, with tenant/project/key/model/tag/agent
 * run as grouping columns; this table files a score under the SAME `request_id`
 * with the SAME grouping columns. So:
 *
 * ```sql
 * -- mean score and total cost per model, for one tenant, one criterion, one day
 * SELECT s.logical_model,
 *        AVG(s.score)          AS mean_score,
 *        COUNT(*)              AS scored_requests,
 *        SUM(b.cost_usd)       AS cost_usd
 *   FROM online_eval_scores s
 *   JOIN billing_events    b ON b.request_id = s.request_id
 *  WHERE s.tenant = ?1 AND s.criterion_id = ?2
 *    AND s.scored_at_unix >= ?3
 *  GROUP BY s.logical_model;
 * ```
 *
 * Both tables live in the CONTROL database for the reason
 * `0004_guardrail_evaluations.sql` sets out at length: D1 has no read spanning
 * two databases, so a score in the tenant database and a charge in the control
 * one would make exactly this join unimplementable.
 *
 * ### And the denormalised columns are not redundant
 *
 * `logical_model` is also on the request log and on the billing event. It is
 * repeated here because the aggregate above must be answerable WITHOUT a join —
 * a trend query that has to join two large tables to group by model is the one
 * that gets turned off when the table grows. The cost of the duplication is that
 * a score row records the model as it was AT SCORING TIME, which is what a
 * point-in-time measurement wants anyway.
 */
import type { OnlineEvalScoreRecord } from "./record.js";

export const ONLINE_EVAL_SCORE_TABLE = "online_eval_scores";
export const ONLINE_EVAL_REGRESSION_TABLE = "online_eval_regressions";

/**
 * The score upsert.
 *
 * `ON CONFLICT (request_id, criterion_id)` is what makes Queues' at-least-once
 * redelivery safe: a redelivered sample is re-judged (the judge is not free, but
 * it is bounded by `max_retries`) and its scores REPLACE the earlier ones for
 * the same request and criterion rather than doubling the sample. Doubling would
 * be the dangerous failure — a mean computed over duplicated rows silently
 * over-weights whichever requests happened to be redelivered.
 *
 * The updated columns are assigned from `excluded` rather than COALESCEd,
 * unlike `request_logs`: a score row is written whole by one leg, so a later
 * write is a re-judgement and not a partial contribution.
 */
export const ONLINE_EVAL_SCORE_UPSERT_SQL = `INSERT INTO ${ONLINE_EVAL_SCORE_TABLE} (
  request_id, criterion_id, tenant, project, workspace, api_key_id, agent_run_id,
  operation_id, provider, logical_model, provider_model,
  sampling_key, sampling_unit, sample_rate,
  judge_model, score, rationale,
  prompt_truncated, completion_truncated, scored_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (request_id, criterion_id) DO UPDATE SET
  score = excluded.score,
  rationale = excluded.rationale,
  judge_model = excluded.judge_model,
  scored_at_unix = excluded.scored_at_unix`;

/** Bind order for {@link ONLINE_EVAL_SCORE_UPSERT_SQL}. */
export function onlineEvalScoreBindings(record: OnlineEvalScoreRecord): unknown[] {
  return [
    record.requestId,
    record.criterionId,
    record.tenantId,
    record.projectId ?? null,
    record.workspaceId ?? null,
    record.apiKeyId ?? null,
    record.agentRunId ?? null,
    record.operationId ?? null,
    record.provider ?? null,
    record.logicalModel ?? null,
    record.providerModel ?? null,
    record.samplingKey,
    record.samplingUnit,
    record.sampleRate,
    record.judgeModel,
    record.score,
    record.rationale ?? null,
    record.promptTruncated ? 1 : 0,
    record.completionTruncated ? 1 : 0,
    record.scoredAtUnix,
  ];
}

/** The `D1Database` subset the writers need. A live binding fits. */
export interface OnlineEvalScoreDatabase {
  prepare(query: string): {
    bind(...values: unknown[]): {
      run(): Promise<unknown>;
      all(): Promise<unknown>;
      first<T = Record<string, unknown>>(): Promise<T | null>;
    };
  };
  batch(statements: unknown[]): Promise<unknown[]>;
}

/**
 * Persist a batch of scores in ONE D1 round trip.
 *
 * REJECTS on failure, deliberately and unlike most of this slice: the caller is
 * the queue consumer, whose retry ladder needs a rejection to arm. A batch fails
 * whole, which is what makes redelivery safe against the upsert above.
 */
export async function writeOnlineEvalScores(
  db: OnlineEvalScoreDatabase,
  records: readonly OnlineEvalScoreRecord[],
): Promise<void> {
  if (records.length === 0) return;
  const statement = db.prepare(ONLINE_EVAL_SCORE_UPSERT_SQL);
  await db.batch(records.map((record) => statement.bind(...onlineEvalScoreBindings(record))));
}

/** `env.CONTROL_DB` (or its `BILLING_DB` alias), when it really is a D1 binding. */
export function onlineEvalDatabaseFrom(env: unknown): OnlineEvalScoreDatabase | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const bindings = env as { CONTROL_DB?: unknown; BILLING_DB?: unknown };
  for (const candidate of [bindings.CONTROL_DB, bindings.BILLING_DB]) {
    if (
      typeof candidate === "object" &&
      candidate !== null &&
      typeof (candidate as OnlineEvalScoreDatabase).prepare === "function" &&
      typeof (candidate as OnlineEvalScoreDatabase).batch === "function"
    ) {
      return candidate as OnlineEvalScoreDatabase;
    }
  }
  return undefined;
}

/**
 * The two-window aggregate the regression sweep reads.
 *
 * One statement, both windows, grouped by the axes a comparison is legitimate
 * along — tenant, criterion, judge model and logical model (see `./policy.ts`
 * on why crossing a judge or a criterion invalidates the comparison). The
 * windows are half-open and disjoint, so no score is counted on both sides.
 */
export const ONLINE_EVAL_WINDOW_AGGREGATE_SQL = `SELECT
  tenant, criterion_id, judge_model, logical_model,
  SUM(CASE WHEN scored_at_unix >= ?3 THEN score ELSE 0 END)  AS recent_total,
  SUM(CASE WHEN scored_at_unix >= ?3 THEN 1 ELSE 0 END)      AS recent_count,
  SUM(CASE WHEN scored_at_unix <  ?3 THEN score ELSE 0 END)  AS baseline_total,
  SUM(CASE WHEN scored_at_unix <  ?3 THEN 1 ELSE 0 END)      AS baseline_count
FROM ${ONLINE_EVAL_SCORE_TABLE}
WHERE tenant = ?1 AND scored_at_unix >= ?2
GROUP BY tenant, criterion_id, judge_model, logical_model`;

/**
 * The regression CLAIM — the dedupe that stops one sustained regression from
 * alerting on every cron tick for a week.
 *
 * `INSERT … ON CONFLICT DO NOTHING RETURNING request_key` is the same arbiter
 * `D1BudgetAlertStore.claimBudgetAlertNotification` uses, and for the same
 * reason: a Worker isolate does not outlive its request, so "check then insert"
 * has a window in which two scheduled invocations both alert. Making the INSERT
 * the arbiter removes it — SQLite evaluates the conflict inside the statement's
 * own implicit transaction.
 */
export const ONLINE_EVAL_REGRESSION_CLAIM_SQL = `INSERT INTO ${ONLINE_EVAL_REGRESSION_TABLE} (
  claim_key, tenant, criterion_id, judge_model, logical_model,
  baseline_mean, baseline_count, recent_mean, recent_count, drop_amount, detected_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (claim_key) DO NOTHING
RETURNING claim_key`;
