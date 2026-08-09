/**
 * "Regressions are alertable" — the detector, the claim that makes it fire once,
 * and an explicit statement of what this signal is worth.
 *
 * ============================================================================
 * WHAT IS COMPARED, AND WHY ONLY THAT
 * ============================================================================
 *
 * The instrument supports exactly one inference (`./policy.ts`): two populations
 * scored by the SAME judge under the SAME criterion can be compared to each
 * other. So the detector compares a RECENT window against a BASELINE window,
 * grouped by `(tenant, criterion, judge_model, logical_model)` — and by nothing
 * coarser. Averaging across criteria would average two different questions;
 * across judges, two different instruments; across models, the very thing a
 * rollout is trying to isolate.
 *
 * A drop is reported when all three hold:
 *
 *  1. both windows have at least `regressionMinSamples` scores. A judge is noisy
 *     per item, so a mean over five samples moves 0.2 on its own;
 *  2. the recent mean is at least `regressionDrop` BELOW the baseline mean;
 *  3. the group exists in both windows — a model that only appeared recently has
 *     no baseline, and calling that a regression would page someone every time a
 *     new model was added.
 *
 * ## What this is NOT
 *
 * It is not a significance test. A t-test would need per-window variance, which
 * the aggregate does not carry, and would suggest a rigour this measurement does
 * not have — the judge's own bias is not sampling noise and does not shrink with
 * n. The threshold is a blunt instrument, deliberately: it says "the mean of a
 * proxy moved by more than you said you cared about", and the honest operator
 * action is to LOOK, using the request ids in `online_eval_scores`, not to roll
 * back automatically.
 *
 * ============================================================================
 * "ALERTABLE" MEANS A CLAIMED ROW PLUS A METRIC SERIES — NOT A WEBHOOK
 * ============================================================================
 *
 * A detected regression is recorded twice: a durable, deduplicated row in
 * `online_eval_regressions` (queryable, with the numbers that produced it) and
 * one Analytics Engine point (`ferrogate.online_eval.regression`) an operator
 * alerts on from whatever they already watch.
 *
 * There is deliberately NO webhook delivery in this slice. Sending one needs a
 * signing secret and an alert-channel decision, and the only existing channel is
 * `BILLING_ALERTS_WEBHOOK_*` — a billing-scoped credential whose receiver
 * authenticates budget notifications. Borrowing it for a quality signal would
 * mean a quality alert that a finance receiver believes is a budget alert, and
 * shipping an UNSIGNED webhook instead would be worse. The row and the series
 * are what an operator can act on today; the channel is a decision this issue
 * does not settle.
 *
 * ## The claim, and why the INSERT is the arbiter
 *
 * A sustained regression is present on every cron tick for as long as it lasts.
 * `claim_key` is `{tenant}:{criterion}:{judge}:{model}:{windowStartUnix}`, and
 * the insert is `ON CONFLICT DO NOTHING RETURNING claim_key` — so the second
 * detection in the same window inserts nothing, returns nothing, and emits
 * nothing. Same arbiter, same reasoning as `budget-alerts.ts`: a Worker isolate
 * does not outlive its invocation, so "check then insert" has a window in which
 * two scheduled runs both alert.
 */

import { evidenceProjectionKey } from "../requestlog/d1.js";
import {
  ONLINE_EVAL_REGRESSION_CLAIM_SQL,
  ONLINE_EVAL_REGRESSION_PROJECTION_SQL,
  ONLINE_EVAL_SCORE_TABLE,
  ONLINE_EVAL_WINDOW_AGGREGATE_SQL,
  type OnlineEvalScoreDatabase,
  TENANT_ONLINE_EVAL_REGRESSION_CLAIM_SQL,
  onlineEvalDatabaseFrom,
  onlineEvalRegressionBindings,
  onlineEvalTenantDatabaseFrom,
} from "./d1.js";
import { refreshOnlineEvalLegQuality } from "./leg-quality.js";
import { ONLINE_EVAL_REGRESSION_METRIC, publishOnlineEvalScorePoints } from "./metrics.js";
import type { OnlineEvalPolicy } from "./policy.js";
import { type OnlineEvalBindings, onlineEvalPolicySourceFromEnv } from "./source.js";

/** Windows. Long baseline, short recent — a rollout shows up within a day. */
export const RECENT_WINDOW_SECONDS = 24 * 60 * 60;
export const BASELINE_WINDOW_SECONDS = 7 * 24 * 60 * 60;

/** One `(tenant, criterion, judge, model)` group, both windows. */
export interface OnlineEvalWindowAggregate {
  readonly tenantId: string;
  readonly criterionId: string;
  readonly judgeModel: string;
  readonly logicalModel?: string | undefined;
  readonly recentTotal: number;
  readonly recentCount: number;
  readonly baselineTotal: number;
  readonly baselineCount: number;
}

/** A detected drop, with the numbers that produced it. */
export interface OnlineEvalRegression {
  readonly tenantId: string;
  readonly criterionId: string;
  readonly judgeModel: string;
  readonly logicalModel?: string | undefined;
  readonly baselineMean: number;
  readonly baselineCount: number;
  readonly recentMean: number;
  readonly recentCount: number;
  readonly dropAmount: number;
}

/**
 * The pure detector. No I/O, so the three rules above are directly assertable
 * and a change to any of them is a failing test rather than a judgement call
 * buried in a query.
 */
export function detectOnlineEvalRegressions(
  aggregates: readonly OnlineEvalWindowAggregate[],
  policy: Pick<OnlineEvalPolicy, "regressionDrop" | "regressionMinSamples">,
): OnlineEvalRegression[] {
  const found: OnlineEvalRegression[] = [];
  for (const aggregate of aggregates) {
    if (
      aggregate.recentCount < policy.regressionMinSamples ||
      aggregate.baselineCount < policy.regressionMinSamples
    ) {
      continue;
    }
    const recentMean = aggregate.recentTotal / aggregate.recentCount;
    const baselineMean = aggregate.baselineTotal / aggregate.baselineCount;
    const dropAmount = baselineMean - recentMean;
    if (dropAmount < policy.regressionDrop) continue;
    found.push({
      tenantId: aggregate.tenantId,
      criterionId: aggregate.criterionId,
      judgeModel: aggregate.judgeModel,
      logicalModel: aggregate.logicalModel,
      baselineMean,
      baselineCount: aggregate.baselineCount,
      recentMean,
      recentCount: aggregate.recentCount,
      dropAmount,
    });
  }
  return found;
}

/** `{tenant}:{criterion}:{judge}:{model}:{windowStart}` — see the module docs. */
export function regressionClaimKey(
  regression: OnlineEvalRegression,
  windowStartUnix: number,
): string {
  return [
    regression.tenantId,
    regression.criterionId,
    regression.judgeModel,
    regression.logicalModel ?? "-",
    String(windowStartUnix),
  ].join(":");
}

function numberColumn(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function stringColumn(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Read both windows for one tenant in one statement. */
export async function onlineEvalWindowAggregates(
  db: OnlineEvalScoreDatabase,
  tenantId: string,
  nowUnix: number,
): Promise<OnlineEvalWindowAggregate[]> {
  const recentStart = nowUnix - RECENT_WINDOW_SECONDS;
  const baselineStart = nowUnix - BASELINE_WINDOW_SECONDS;
  const result = (await db
    .prepare(ONLINE_EVAL_WINDOW_AGGREGATE_SQL)
    .bind(tenantId, baselineStart, recentStart)
    .all()) as { results?: Record<string, unknown>[] } | undefined;
  const rows = result?.results ?? [];
  return rows.map((row) => ({
    tenantId,
    criterionId: String(row.criterion_id ?? ""),
    judgeModel: String(row.judge_model ?? ""),
    logicalModel: stringColumn(row.logical_model),
    recentTotal: numberColumn(row.recent_total),
    recentCount: numberColumn(row.recent_count),
    baselineTotal: numberColumn(row.baseline_total),
    baselineCount: numberColumn(row.baseline_count),
  }));
}

export interface OnlineEvalSweepResult {
  readonly detected: number;
  /** Detections that WON the claim — i.e. that were newly recorded. */
  readonly claimed: number;
}

/**
 * The cron leg for ONE tenant: aggregate, detect, claim, emit.
 *
 * NEVER throws. It runs from `gatewayScheduled`, beside the billing-outbox
 * sweep, and a quality-measurement failure must not take money recovery down
 * with it — the same rule `gatewayRequestLogRetention` follows.
 */
export async function sweepOnlineEvalRegressions(
  env: unknown,
  tenantId: string,
  policy: Pick<OnlineEvalPolicy, "regressionDrop" | "regressionMinSamples">,
  nowUnix: number,
  database: (env: unknown) => OnlineEvalScoreDatabase | undefined = onlineEvalDatabaseFrom,
  tenantDatabase: (
    env: unknown,
    tenantId: string,
  ) => OnlineEvalScoreDatabase | undefined = onlineEvalTenantDatabaseFrom,
): Promise<OnlineEvalSweepResult> {
  const db = database(env);
  if (db === undefined) return { detected: 0, claimed: 0 };

  const authoritative = tenantDatabase(env, tenantId);
  // The default deployment is object-first. An absent object binding is a
  // storage misconfiguration, not permission to read the old shared table.
  // Explicit database injection remains the compatibility/test seam.
  if (database === onlineEvalDatabaseFrom && authoritative === undefined) {
    return { detected: 0, claimed: 0 };
  }
  const source = authoritative ?? db;

  let regressions: OnlineEvalRegression[];
  try {
    const aggregates = await onlineEvalWindowAggregates(source, tenantId, nowUnix);
    regressions = detectOnlineEvalRegressions(aggregates, policy);
  } catch {
    return { detected: 0, claimed: 0 };
  }
  if (regressions.length === 0) return { detected: 0, claimed: 0 };

  const windowStartUnix = nowUnix - RECENT_WINDOW_SECONDS;
  const claimed: OnlineEvalRegression[] = [];
  for (const regression of regressions) {
    try {
      const claimKey = regressionClaimKey(regression, windowStartUnix);
      const bindings = onlineEvalRegressionBindings({
        claimKey,
        tenantId: regression.tenantId,
        criterionId: regression.criterionId,
        judgeModel: regression.judgeModel,
        logicalModel: regression.logicalModel,
        baselineMean: regression.baselineMean,
        baselineCount: regression.baselineCount,
        recentMean: regression.recentMean,
        recentCount: regression.recentCount,
        dropAmount: regression.dropAmount,
        detectedAtUnix: nowUnix,
      });
      const row = await source
        .prepare(
          authoritative === undefined
            ? ONLINE_EVAL_REGRESSION_CLAIM_SQL
            : TENANT_ONLINE_EVAL_REGRESSION_CLAIM_SQL,
        )
        .bind(...bindings)
        .first();
      // `null` = the conflict arm fired: somebody already alerted for this
      // group in this window. Not an error, and deliberately not re-emitted.
      if (row !== null && row !== undefined) claimed.push(regression);

      if (authoritative !== undefined) {
        // The object claim is the arbiter. Project even when the object claim
        // already existed, so a retry after a projection-only failure repairs
        // control D1 without emitting a second alert.
        await db
          .prepare(ONLINE_EVAL_REGRESSION_PROJECTION_SQL)
          .bind(evidenceProjectionKey(regression.tenantId, claimKey), ...bindings)
          .run();
      }
    } catch {
      // A claim that could not be written is a claim not taken; the next tick
      // tries again. Never a throw — see the function docs.
    }
  }

  if (claimed.length > 0) {
    await publishOnlineEvalScorePoints(
      env,
      claimed.map((regression) => ({
        name: ONLINE_EVAL_REGRESSION_METRIC,
        description: "A judge-score mean fell below its baseline by the tenant's threshold.",
        // The DROP is the measurement, so an alert threshold in the metric
        // store reads the same number the tenant configured.
        value: regression.dropAmount,
        timeUnixMs: nowUnix * 1000,
        attributes: [
          { key: "tenant", value: regression.tenantId },
          { key: "criterion", value: regression.criterionId },
          { key: "judge_model", value: regression.judgeModel },
          ...(regression.logicalModel === undefined
            ? []
            : [{ key: "logical_model", value: regression.logicalModel }]),
        ],
      })),
    );
  }

  return { detected: regressions.length, claimed: claimed.length };
}

/**
 * Which tenants have been scored recently enough to be worth comparing.
 *
 * Read from the SCORES rather than from the policy table on purpose: a tenant
 * that opted in last week and has since been switched off still has a week of
 * scores whose regression is real, and a tenant that opted in five minutes ago
 * has nothing to compare yet. The `LIMIT` is a bound on one cron tick's work,
 * not a correctness boundary — the next tick sees the same set.
 */
export const ONLINE_EVAL_ACTIVE_TENANTS_SQL = `SELECT DISTINCT tenant
FROM ${ONLINE_EVAL_SCORE_TABLE}
WHERE scored_at_unix >= ?1
LIMIT 200`;

/**
 * The whole cron leg: every tenant with recent scores, under that tenant's own
 * thresholds.
 *
 * NEVER throws — it is called from `gatewayScheduled`, beside the billing-outbox
 * sweep, and a quality measurement must never be able to take money recovery
 * down with it.
 *
 * A tenant whose policy cannot be READ is skipped rather than swept under a
 * default threshold: `regressionDrop` is the number that decides whether an
 * operator is told, and applying a fleet default to a tenant who chose a
 * different one would alert on the wrong evidence.
 */
export async function sweepAllOnlineEvalRegressions(
  env: unknown,
  nowUnix: number,
  database: (env: unknown) => OnlineEvalScoreDatabase | undefined = onlineEvalDatabaseFrom,
  tenantDatabase: (
    env: unknown,
    tenantId: string,
  ) => OnlineEvalScoreDatabase | undefined = onlineEvalTenantDatabaseFrom,
): Promise<OnlineEvalSweepResult> {
  const db = database(env);
  if (db === undefined) return { detected: 0, claimed: 0 };

  let tenants: string[];
  try {
    const result = (await db
      .prepare(ONLINE_EVAL_ACTIVE_TENANTS_SQL)
      .bind(nowUnix - BASELINE_WINDOW_SECONDS)
      .all()) as { results?: Record<string, unknown>[] } | undefined;
    tenants = (result?.results ?? [])
      .map((row) => row.tenant)
      .filter((tenant): tenant is string => typeof tenant === "string" && tenant !== "");
  } catch {
    // A schema that predates `0009_online_eval.sql`, or a D1 blip. Nothing to
    // sweep and nothing to report.
    return { detected: 0, claimed: 0 };
  }

  const policies = onlineEvalPolicySourceFromEnv(env as OnlineEvalBindings);
  let detected = 0;
  let claimed = 0;
  for (const tenantId of tenants) {
    const resolved = await policies.policyFor(tenantId).catch(() => undefined);
    if (resolved === undefined || !resolved.ok || resolved.policy === null) continue;
    const result = await sweepOnlineEvalRegressions(
      env,
      tenantId,
      resolved.policy,
      nowUnix,
      database,
      tenantDatabase,
    );
    detected += result.detected;
    claimed += result.claimed;
    // #894 — the same tick refreshes the per-LEG projection the router reads.
    // Here as well as in the queue consumer because the consumer only fires when
    // a tenant is being scored, and a leg whose scores all aged out of the
    // window would otherwise keep its last value until the next sample arrived.
    // `refreshOnlineEvalLegQuality` never throws; the `catch` is depth, not a
    // second failure mode.
    await refreshOnlineEvalLegQuality(env, tenantId, nowUnix, database, tenantDatabase).catch(
      () => 0,
    );
  }
  return { detected, claimed };
}
