import {
  type ArmOperationalAggregate,
  type ArmScoreAggregate,
  type ExperimentArm,
  compareExperimentQuality,
  summariseArmOperations,
} from "@ferrogate/routing";
/**
 * Contract group `admin_experiment` (2 operations) — OUTCOME METRICS FOR CANARY
 * AND SHADOW SPLITS (#693).
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES
 * ============================================================================
 *
 * `packages/routing` has split traffic since #276 and the product measured no
 * outcome, so "is the canary better" was a guess about everything except price.
 * The gateway half of #693 fixed the writing: `request_logs` now carries
 * `experiment_id` / `experiment_arm`, `experiment_shadow_legs` records the arm
 * that has no request log, and `online_eval_scores` carries the arm too. This
 * is the reading — and reading is where the honesty is either enforced or lost.
 *
 * ============================================================================
 * THE COMPARISON IS NOT MADE HERE, AND THAT IS THE POINT
 * ============================================================================
 *
 * Every quality verdict on this surface comes out of
 * `@ferrogate/routing::compareExperimentQuality`, which is pure, is unit-tested
 * against textbook values, and REFUSES in three separate ways:
 *
 *  1. arms scored by a different judge or under a different criterion are not
 *     subtracted — there is no code path that subtracts them, because the
 *     comparator only pairs arms inside one `(judge_model, criterion_id)` group
 *     and reports the rest as `incomparable`;
 *  2. below the sample floor the MEANS ARE ABSENT from the result, so this
 *     route physically cannot serialize a number computed from two requests;
 *  3. a difference the spread does not support comes back as
 *     `no_measured_difference` rather than as a winner.
 *
 * This module's whole job on the quality side is to produce the SQL grouping
 * that makes (1) checkable — `GROUP BY judge_model, criterion_id,
 * experiment_arm`, never a pre-averaged `mean_score` per arm — and to hand the
 * aggregates over. A route that computed its own means would be a second
 * implementation of the rules, and the second implementation is the one that
 * eventually forgets a refusal.
 *
 * ============================================================================
 * THE FENCE
 * ============================================================================
 *
 * `request_logs`, `online_eval_scores` and `experiment_shadow_legs` all carry
 * the AUTHENTICATED tenant, so all three are fenced with strict equality and
 * none of them is ever reached through another table's key. `billing_events`
 * has NO tenant column — its rows are keyed by `request_id` — so, exactly as
 * `admin_cost_record.ts` argues, it is never the driving side: it is reached
 * only through a join on a `request_id` the fence has already cleared.
 *
 * A `NULL` tenant matches nobody. An un-attributed request is a
 * platform-operator call, and an experiment report names a customer's models,
 * their spend and their measured quality — the most identity-dense document
 * this product publishes after a cost record.
 *
 * ============================================================================
 * WHY THERE IS NO `experiments` TABLE
 * ============================================================================
 *
 * An experiment is not a resource an operator creates. It is the SPLIT that a
 * model's `[[models]].canary` / `.shadow` config already declares, and its id is
 * a fingerprint of the three routes involved (`experimentIdFor`). A registry
 * table would be a second declaration of the same thing, able to drift from the
 * config that actually routes traffic — and an experiment that a report knows
 * about but the router does not is worse than no report. So the experiment list
 * is DISCOVERED from the observations, which means it lists exactly the splits
 * that really served traffic in the window.
 */
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { BILLING_EVENT_TABLE, REQUEST_LOG_TABLE } from "../store/d1.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

const EXPERIMENT_OBJECT = "experiment";
const EXPERIMENT_REPORT_OBJECT = "experiment_report";

/** `experiment_shadow_legs` — the shadow arm's own evidence table (#693). */
const SHADOW_LEG_TABLE = "experiment_shadow_legs";
/** `online_eval_scores` — #692's judge scores, now arm-tagged. */
const EVAL_SCORE_TABLE = "online_eval_scores";

/**
 * How far back a report looks when the caller does not say.
 *
 * Thirty days rather than "everything": an experiment's arms must be compared
 * over a window in which the same thing was being compared, and pooling a year
 * of traffic across every config change the operator made in it produces a
 * difference that is mostly the config changes. The bound is a default, not a
 * cap — `?since=` moves it — but a report with no window at all is the shape
 * that gets read as a result.
 */
const DEFAULT_WINDOW_SECONDS = 30 * 24 * 60 * 60;

/**
 * The default minimum scored samples per arm before any mean is reported.
 *
 * There is no universally right value; it depends on the effect size the
 * operator cares about and on the judge's noise floor. Thirty is the
 * conventional floor below which a t-interval on a bounded score is wide enough
 * to be useless, and it is overridable per request — but it is never ZERO, and
 * the comparator has no default of its own precisely so that the choice is
 * always made somewhere a reader can see it.
 */
const DEFAULT_MIN_SAMPLES = 30;

/** Two-sided significance level. Overridable, floored and capped below. */
const DEFAULT_ALPHA = 0.05;

/**
 * The tenant fence.
 *
 * Stated separately from `admin_cost_record.ts::costRecordTenantFence` for the
 * reason that file gives about ITS siblings: these predicates read independent
 * facts, and folding them into one helper would make a later divergence look
 * like a typo rather than a decision.
 */
function tenantFence(scope: CallerScope, column: string): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: `${column} = ?`, params: [scope.tenantId] };
}

function whereFrom(clauses: readonly string[]): string {
  const kept = clauses.filter((clause) => clause !== "");
  return kept.length === 0 ? "" : `WHERE ${kept.join(" AND ")}`;
}

/**
 * The SERVED arms' operational totals, from `request_logs` joined to
 * `billing_events`.
 *
 * The failure predicate is the request LOG's — `status_code >= 400 OR
 * error_code IS NOT NULL` — and not the circuit breaker's: a provider that
 * answers 400 to a body it dislikes failed the caller, even though the breaker
 * deliberately ignores it when deciding whether to shed traffic.
 *
 * Cost is `SUM(json_extract(event_json, '$.cost_usd'))` over the request's
 * billing events, i.e. the SAME documents `D1LedgerStore.record` wrote in the
 * same batch as the `billing_ledger` row. No third figure for the same money —
 * see `admin_cost_record.ts` on why a `cost_records` table would be a
 * reconciliation problem rather than a feature.
 */
const SERVED_ARM_AGGREGATE_SQL = (fence: string) => `SELECT
  rl.experiment_id                                    AS experiment_id,
  rl.experiment_arm                                   AS arm,
  MAX(rl.logical_model)                               AS logical_model,
  COUNT(*)                                            AS requests,
  SUM(CASE WHEN rl.status_code >= 400 OR rl.error_code IS NOT NULL THEN 1 ELSE 0 END)
                                                      AS failures,
  SUM(COALESCE(rl.latency_ms, 0))                     AS latency_total_ms,
  COALESCE(SUM(cost.cost_usd), 0)                     AS cost_usd_total,
  MIN(rl.started_at_unix)                             AS first_seen_unix,
  MAX(rl.started_at_unix)                             AS last_seen_unix
FROM ${REQUEST_LOG_TABLE} rl
LEFT JOIN (
  SELECT request_id, SUM(json_extract(event_json, '$.cost_usd')) AS cost_usd
    FROM ${BILLING_EVENT_TABLE}
   GROUP BY request_id
) cost ON cost.request_id = rl.request_id
${whereFrom(["rl.experiment_id IS NOT NULL", "rl.started_at_unix >= ?", fence])}
GROUP BY rl.experiment_id, rl.experiment_arm`;

/**
 * The SHADOW arm's operational totals, from its own table.
 *
 * A separate statement rather than a `UNION` with the one above, deliberately:
 * the two arms live in different tables because a mirror is not a client
 * request, and a `UNION` would have to invent a common column list that hides
 * exactly that difference. Two reads, one shape, assembled in TypeScript where
 * the difference stays visible.
 *
 * `cost_usd` here is the OPERATOR's cost. Nobody is billed for it — see
 * `armChargedTo` — and the report says so on every shadow arm.
 */
const SHADOW_ARM_AGGREGATE_SQL = (fence: string) => `SELECT
  experiment_id,
  MAX(logical_model)                                  AS logical_model,
  COUNT(*)                                            AS requests,
  SUM(CASE WHEN status_code >= 400 OR error_code IS NOT NULL THEN 1 ELSE 0 END)
                                                      AS failures,
  SUM(COALESCE(latency_ms, 0))                        AS latency_total_ms,
  COALESCE(SUM(cost_usd), 0)                          AS cost_usd_total,
  MIN(observed_at_unix)                               AS first_seen_unix,
  MAX(observed_at_unix)                               AS last_seen_unix
FROM ${SHADOW_LEG_TABLE}
${whereFrom(["observed_at_unix >= ?", fence])}
GROUP BY experiment_id`;

/**
 * The QUALITY aggregate — and the grouping IS the enforcement.
 *
 * `GROUP BY judge_model, criterion_id, experiment_arm` returns Σx and Σx² per
 * arm per instrument. Two arms scored by different judges land in different
 * groups, so `compareExperimentQuality` has no pair to subtract and reports
 * them incomparable. A query that returned `AVG(score)` per arm would have
 * thrown that information away at the database, and no amount of care in the
 * TypeScript could have recovered it.
 */
const QUALITY_AGGREGATE_SQL = (fence: string) => `SELECT
  experiment_arm            AS arm,
  judge_model               AS judge_model,
  criterion_id              AS criterion_id,
  COUNT(*)                  AS n,
  SUM(score)                AS total,
  SUM(score * score)        AS total_squares
FROM ${EVAL_SCORE_TABLE}
${whereFrom(["experiment_id = ?", "experiment_arm IS NOT NULL", "scored_at_unix >= ?", fence])}
GROUP BY experiment_arm, judge_model, criterion_id`;

interface ArmRow {
  readonly experiment_id: string;
  readonly arm?: string | null;
  readonly logical_model: string | null;
  readonly requests: number;
  readonly failures: number;
  readonly latency_total_ms: number;
  readonly cost_usd_total: number;
  readonly first_seen_unix: number;
  readonly last_seen_unix: number;
}

interface QualityRow {
  readonly arm: string;
  readonly judge_model: string;
  readonly criterion_id: string;
  readonly n: number;
  readonly total: number;
  readonly total_squares: number;
}

/** A D1 binding, narrowed to what this module issues. */
interface Database {
  prepare(query: string): {
    bind(...values: unknown[]): { all<T>(): Promise<{ results: T[] }> };
    all<T>(): Promise<{ results: T[] }>;
  };
}

function isArm(value: unknown): value is ExperimentArm {
  return value === "control" || value === "canary" || value === "shadow";
}

/** One experiment's arms, gathered from both operational tables. */
interface ExperimentObservations {
  readonly experimentId: string;
  logicalModel: string | null;
  firstSeenUnix: number;
  lastSeenUnix: number;
  readonly arms: Map<ExperimentArm, ArmOperationalAggregate>;
}

async function experimentObservations(
  db: Database,
  scope: CallerScope,
  sinceUnix: number,
): Promise<Map<string, ExperimentObservations>> {
  const servedFence = tenantFence(scope, "rl.tenant");
  const shadowFence = tenantFence(scope, "tenant");

  const [served, shadow] = await Promise.all([
    db
      .prepare(SERVED_ARM_AGGREGATE_SQL(servedFence.sql))
      .bind(sinceUnix, ...servedFence.params)
      .all<ArmRow>(),
    db
      .prepare(SHADOW_ARM_AGGREGATE_SQL(shadowFence.sql))
      .bind(sinceUnix, ...shadowFence.params)
      .all<ArmRow>(),
  ]);

  const byExperiment = new Map<string, ExperimentObservations>();
  const absorb = (row: ArmRow, arm: ExperimentArm): void => {
    const existing = byExperiment.get(row.experiment_id) ?? {
      experimentId: row.experiment_id,
      logicalModel: row.logical_model,
      firstSeenUnix: row.first_seen_unix,
      lastSeenUnix: row.last_seen_unix,
      arms: new Map<ExperimentArm, ArmOperationalAggregate>(),
    };
    existing.logicalModel = existing.logicalModel ?? row.logical_model;
    existing.firstSeenUnix = Math.min(existing.firstSeenUnix, row.first_seen_unix);
    existing.lastSeenUnix = Math.max(existing.lastSeenUnix, row.last_seen_unix);
    existing.arms.set(arm, {
      arm,
      requests: row.requests,
      failures: row.failures,
      latencyTotalMs: row.latency_total_ms,
      costUsdTotal: row.cost_usd_total,
    });
    byExperiment.set(row.experiment_id, existing);
  };

  for (const row of served.results) {
    // A row whose arm is not one of the three is DROPPED rather than defaulted
    // to `control`. The gateway only ever writes the three, so an unknown value
    // is a schema drift or a hand-edited row, and folding it into the control
    // arm would silently move somebody else's traffic into the baseline the
    // variant is judged against.
    if (isArm(row.arm)) absorb(row, row.arm);
  }
  for (const row of shadow.results) absorb(row, "shadow");
  return byExperiment;
}

/** The operational half of a report, as a document. */
function armDocuments(observations: ExperimentObservations): StoreRecord[] {
  return summariseArmOperations([...observations.arms.values()]).map((summary) => ({
    object: "experiment_arm",
    arm: summary.arm,
    requests: summary.requests,
    failures: summary.failures,
    error_rate: summary.errorRate ?? null,
    mean_latency_ms: summary.meanLatencyMs ?? null,
    cost_usd: summary.costUsd,
    // Both structural, from the arm. A shadow arm's response was never
    // delivered and its provider spend is the OPERATOR's cost of taking a
    // measurement — the customer neither saw the answer nor asked for the
    // second provider. Surfacing it per arm is what stops "shadow costs $X"
    // being read as "the customer was billed $X".
    delivered: summary.delivered,
    charged_to: summary.chargedTo,
  })) as unknown as StoreRecord[];
}

function experimentDocument(observations: ExperimentObservations): StoreRecord {
  return {
    object: EXPERIMENT_OBJECT,
    id: observations.experimentId,
    logical_model: observations.logicalModel,
    first_seen_unix: observations.firstSeenUnix,
    last_seen_unix: observations.lastSeenUnix,
    arms: armDocuments(observations),
  } as unknown as StoreRecord;
}

/** `?since=` as an absolute unix second, defaulting to the window above. */
function sinceFrom(url: URL, nowUnix: number): number {
  const raw = url.searchParams.get("since");
  if (raw === null || raw.trim() === "") return nowUnix - DEFAULT_WINDOW_SECONDS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new HttpError(400, "invalid_request", "`since` must be a unix timestamp in seconds");
  }
  return Math.floor(parsed);
}

function positiveIntegerParam(url: URL, name: string, fallback: number): number {
  const raw = url.searchParams.get(name);
  if (raw === null || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new HttpError(400, "invalid_request", `\`${name}\` must be a positive integer`);
  }
  return parsed;
}

function alphaFrom(url: URL): number {
  const raw = url.searchParams.get("alpha");
  if (raw === null || raw.trim() === "") return DEFAULT_ALPHA;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed >= 1) {
    throw new HttpError(400, "invalid_request", "`alpha` must be a number in (0, 1)");
  }
  return parsed;
}

function noDatabase(): never {
  // Not an empty list. A deployment with no control database has no evidence
  // tables and no gateway writing them, so "no experiments" would be a claim
  // this instance cannot support — and the operator would read it as "the
  // canary produced no traffic".
  throw new HttpError(
    503,
    "control_database_unavailable",
    "experiment reporting requires the control database",
  );
}

/** `GET /admin/v1/experiments` — the splits that really served traffic. */
function listExperimentsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const db = deps.controlDatabase as Database | null;
    if (db === null) noDatabase();

    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const sinceUnix = sinceFrom(url, Math.floor(Date.now() / 1000));

    const observations = await experimentObservations(db, scopeOf(c), sinceUnix);
    // Newest activity first: the split an operator is about to make a decision
    // about is the one that served traffic most recently.
    const all = [...observations.values()].sort((a, b) => b.lastSeenUnix - a.lastSeenUnix);
    const page = all.slice(query.offset, query.offset + query.limit).map(experimentDocument);
    return json(c, 200, adminListPaginated(page, all.length, query.offset, query.limit));
  };
}

/**
 * `GET /admin/v1/experiments/{experiment_id}` — the arms, and the verdict.
 *
 * `?variant=canary|shadow` chooses WHICH variant is compared against the
 * control, and it is a parameter rather than "whatever is not the control"
 * because a model can carry a canary AND a shadow at once: pooling them would
 * compare the control against a mixture of two different variants. Absent, it
 * defaults to whichever variant arm actually has observations, and refuses when
 * both do — a report that silently picked one would be a rollout decision taken
 * on the operator's behalf.
 */
function getExperimentHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const db = deps.controlDatabase as Database | null;
    if (db === null) noDatabase();

    const experimentId = c.req.param("experiment_id") ?? "";
    const url = new URL(c.req.url);
    const sinceUnix = sinceFrom(url, Math.floor(Date.now() / 1000));
    const minSamples = positiveIntegerParam(url, "min_samples", DEFAULT_MIN_SAMPLES);
    const alpha = alphaFrom(url);
    const scope = scopeOf(c);

    const observations = (await experimentObservations(db, scope, sinceUnix)).get(experimentId);
    if (observations === undefined) {
      throw new HttpError(404, "not_found", `unknown experiment ${experimentId}`);
    }

    const variant = variantArmFor(url, observations);

    const scoreFence = tenantFence(scope, "tenant");
    const scores = await db
      .prepare(QUALITY_AGGREGATE_SQL(scoreFence.sql))
      .bind(experimentId, sinceUnix, ...scoreFence.params)
      .all<QualityRow>();

    const aggregates: ArmScoreAggregate[] = [];
    for (const row of scores.results) {
      if (!isArm(row.arm)) continue;
      aggregates.push({
        arm: row.arm,
        judgeModel: row.judge_model,
        criterionId: row.criterion_id,
        count: row.n,
        total: row.total,
        totalSquares: row.total_squares,
      });
    }

    // THE comparison, made by the pure comparator and never here.
    const quality = compareExperimentQuality(variant, aggregates, { minSamples, alpha });

    return json(c, 200, {
      object: EXPERIMENT_REPORT_OBJECT,
      id: experimentId,
      logical_model: observations.logicalModel,
      variant_arm: variant,
      since_unix: sinceUnix,
      min_samples: minSamples,
      alpha,
      arms: armDocuments(observations),
      quality: {
        object: "experiment_quality",
        // Hoisted out of the cell list so a surface cannot render the report
        // without them: they say "your arms were measured with different
        // instruments", which is the one thing that invalidates the whole
        // comparison rather than one row of it.
        judge_mismatch: quality.judgeMismatch,
        criterion_mismatch: quality.criterionMismatch,
        comparisons: quality.cells.map((cell) => ({
          criterion_id: cell.criterionId,
          judge_model: cell.judgeModel,
          verdict: cell.verdict,
          min_samples: cell.minSamples,
          control: qualitySideDocument(cell.control),
          variant: qualitySideDocument(cell.variant),
          // ABSENT, not null, under `insufficient_samples`: the comparator
          // omits them, and this route preserves the omission so a client
          // cannot render a number that was never computed.
          ...(cell.difference === undefined ? {} : { difference: cell.difference }),
          ...(cell.pValue === undefined ? {} : { p_value: cell.pValue }),
        })),
        incomparable: quality.incomparable.map((cell) => ({
          criterion_id: cell.criterionId,
          judge_model: cell.judgeModel,
          reason: cell.reason,
          scored_arms: cell.scoredArms,
          detail: cell.detail,
        })),
      },
    });
  };
}

function qualitySideDocument(side: {
  arm: ExperimentArm;
  count: number;
  mean?: number | undefined;
  stdDev?: number | undefined;
}): Record<string, unknown> {
  return {
    arm: side.arm,
    count: side.count,
    ...(side.mean === undefined ? {} : { mean: side.mean }),
    ...(side.stdDev === undefined ? {} : { std_dev: side.stdDev }),
  };
}

/**
 * Which variant this report compares against the control.
 *
 * Explicit `?variant=` wins. With neither variant arm observed there is nothing
 * to compare and the request is refused rather than answered with an empty
 * comparison, because "no difference found" and "there is no variant" read
 * identically on a dashboard and mean opposite things.
 */
function variantArmFor(url: URL, observations: ExperimentObservations): ExperimentArm {
  const requested = url.searchParams.get("variant");
  if (requested !== null && requested.trim() !== "") {
    if (requested !== "canary" && requested !== "shadow") {
      throw new HttpError(400, "invalid_request", "`variant` must be 'canary' or 'shadow'");
    }
    return requested;
  }
  const hasCanary = observations.arms.has("canary");
  const hasShadow = observations.arms.has("shadow");
  if (hasCanary && hasShadow) {
    throw new HttpError(
      400,
      "invalid_request",
      "this experiment has both a canary and a shadow arm; name one with `variant`",
    );
  }
  if (hasCanary) return "canary";
  if (hasShadow) return "shadow";
  throw new HttpError(
    409,
    "no_variant_arm",
    `experiment ${observations.experimentId} has no variant arm in this window`,
  );
}

export const adminExperimentRoutes: GroupModule = crudGroup(
  "admin_experiment",
  [readOnlyCollection("experiments", EXPERIMENT_OBJECT)],
  {
    listAdminExperiments: listExperimentsHandler(),
    getAdminExperiment: getExperimentHandler(),
  },
);
