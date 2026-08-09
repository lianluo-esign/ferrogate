/**
 * `online_eval_scores` and `online_eval_regressions` in the tenant object and
 * their CONTROL-D1 fleet projections.
 *
 * The tenant tables are defined by `sql/d1-ts/tenant/0018_usage_evaluation_audit.sql`;
 * matching control projections remain in `sql/d1-ts/control/0017_*` and
 * `0018_*`. `apps/gateway` is the only producer (the queue consumer and the
 * cron sweep); admin report reads remain projection-backed until their bounded
 * fleet-read contract is implemented.
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
 * Tenant-attributed rows live in the owning object. The control projection keeps
 * the existing fleet join available; tenant authority is never recovered from
 * that projection when the object cannot be reached.
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

import { controlDatabaseFrom } from "../control-data.js";
import { evidenceProjectionKey, requestLogTenantDatabaseFrom } from "../requestlog/d1.js";
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
const ONLINE_EVAL_SCORE_UPDATE_SET = `DO UPDATE SET
  score = excluded.score,
  rationale = excluded.rationale,
  judge_model = excluded.judge_model,
  scored_at_unix = excluded.scored_at_unix`;

/** The single-tenant authoritative write. */
export const TENANT_ONLINE_EVAL_SCORE_UPSERT_SQL = `INSERT INTO ${ONLINE_EVAL_SCORE_TABLE} (
  request_id, criterion_id, tenant, project, workspace, api_key_id, agent_run_id,
  operation_id, provider, logical_model, provider_model,
  experiment_id, experiment_arm,
  sampling_key, sampling_unit, sample_rate,
  judge_model, score, rationale,
  prompt_truncated, completion_truncated, scored_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (request_id, criterion_id) ${ONLINE_EVAL_SCORE_UPDATE_SET}`;

/** Control-D1 compatibility projection, keyed by tenant plus logical score id. */
export const ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL = `INSERT INTO ${ONLINE_EVAL_SCORE_TABLE} (
  projection_key, request_id, criterion_id, tenant, project, workspace, api_key_id, agent_run_id,
  operation_id, provider, logical_model, provider_model,
  experiment_id, experiment_arm,
  sampling_key, sampling_unit, sample_rate,
  judge_model, score, rationale,
  prompt_truncated, completion_truncated, scored_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) ${ONLINE_EVAL_SCORE_UPDATE_SET}`;

/**
 * Kept as the public legacy name for callers that explicitly inject the
 * control database. Production object writes use the tenant-specific constant
 * above; a control write must include the projection key.
 */
export const ONLINE_EVAL_SCORE_UPSERT_SQL = ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL;

/** Bind order for the tenant-object score upsert. */
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
    record.experimentId ?? null,
    record.experimentArm ?? null,
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

/** Bind order for the control-D1 projection upsert. */
export function onlineEvalScoreProjectionBindings(record: OnlineEvalScoreRecord): unknown[] {
  return [
    evidenceProjectionKey(record.tenantId, `${record.requestId}:${record.criterionId}`),
    ...onlineEvalScoreBindings(record),
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
  const statement = db.prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL);
  await db.batch(
    records.map((record) => statement.bind(...onlineEvalScoreProjectionBindings(record))),
  );
}

/** Resolve one tenant's authoritative score database when the object binding exists. */
export function onlineEvalTenantDatabaseFrom(
  env: unknown,
  tenantId: string,
): OnlineEvalScoreDatabase | undefined {
  if (tenantId.trim() === "") return undefined;
  if (typeof env !== "object" || env === null) return undefined;
  if ((env as { TENANT_DATA?: unknown }).TENANT_DATA === undefined) return undefined;
  return requestLogTenantDatabaseFrom(env, tenantId) as OnlineEvalScoreDatabase | undefined;
}

/** Write a same-tenant score batch to its object-authoritative table. */
export async function writeTenantOnlineEvalScores(
  db: OnlineEvalScoreDatabase,
  records: readonly OnlineEvalScoreRecord[],
): Promise<void> {
  if (records.length === 0) return;
  const statement = db.prepare(TENANT_ONLINE_EVAL_SCORE_UPSERT_SQL);
  await db.batch(records.map((record) => statement.bind(...onlineEvalScoreBindings(record))));
}

/** Write the retry-safe control projection for a score batch. */
export async function writeOnlineEvalScoreProjections(
  db: OnlineEvalScoreDatabase,
  records: readonly OnlineEvalScoreRecord[],
): Promise<void> {
  if (records.length === 0) return;
  const statement = db.prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL);
  await db.batch(
    records.map((record) => statement.bind(...onlineEvalScoreProjectionBindings(record))),
  );
}

/** The CONTROL database facade, when it really is a D1 binding. */
export function onlineEvalDatabaseFrom(env: unknown): OnlineEvalScoreDatabase | undefined {
  const candidate = controlDatabaseFrom(env);
  if (
    typeof candidate === "object" &&
    candidate !== null &&
    typeof (candidate as OnlineEvalScoreDatabase).prepare === "function" &&
    typeof (candidate as OnlineEvalScoreDatabase).batch === "function"
  ) {
    return candidate as unknown as OnlineEvalScoreDatabase;
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

/** The same claim inside one tenant object. */
export const TENANT_ONLINE_EVAL_REGRESSION_CLAIM_SQL = ONLINE_EVAL_REGRESSION_CLAIM_SQL;

/** Control-D1 projection for a tenant-authoritative regression claim. */
export const ONLINE_EVAL_REGRESSION_PROJECTION_SQL = `INSERT INTO ${ONLINE_EVAL_REGRESSION_TABLE} (
  projection_key, claim_key, tenant, criterion_id, judge_model, logical_model,
  baseline_mean, baseline_count, recent_mean, recent_count, drop_amount, detected_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  claim_key = excluded.claim_key,
  tenant = excluded.tenant,
  criterion_id = excluded.criterion_id,
  judge_model = excluded.judge_model,
  logical_model = excluded.logical_model,
  baseline_mean = excluded.baseline_mean,
  baseline_count = excluded.baseline_count,
  recent_mean = excluded.recent_mean,
  recent_count = excluded.recent_count,
  drop_amount = excluded.drop_amount,
  detected_at_unix = excluded.detected_at_unix`;

export function onlineEvalRegressionBindings(regression: {
  claimKey: string;
  tenantId: string;
  criterionId: string;
  judgeModel: string;
  logicalModel?: string | undefined;
  baselineMean: number;
  baselineCount: number;
  recentMean: number;
  recentCount: number;
  dropAmount: number;
  detectedAtUnix: number;
}): unknown[] {
  return [
    regression.claimKey,
    regression.tenantId,
    regression.criterionId,
    regression.judgeModel,
    regression.logicalModel ?? null,
    regression.baselineMean,
    regression.baselineCount,
    regression.recentMean,
    regression.recentCount,
    regression.dropAmount,
    regression.detectedAtUnix,
  ];
}
