/**
 * The per-PROVIDER-LEG quality aggregate the router can rank candidates with
 * (#894), and the pure RELATIVE comparator that reads it.
 *
 * ============================================================================
 * WHY A SECOND AGGREGATE EXISTED TO BE WRITTEN
 * ============================================================================
 *
 * `./d1.ts::ONLINE_EVAL_WINDOW_AGGREGATE_SQL` groups by
 * `(tenant, criterion_id, judge_model, logical_model)`. Every candidate in one
 * failover ladder shares its `logical_model` — that is what a ladder IS — so
 * that aggregate has exactly one row per ladder and cannot say which LEG of the
 * ladder scored better. It answers "did this model regress against itself last
 * week", which is the question `./regression.ts` asks and a complete answer to
 * it. It cannot answer "is `openai-eu/gpt-4o-mini` scoring below
 * `azure-eu/gpt-4o-mini` for this tenant", which is the question a router
 * choosing between them has to ask.
 *
 * So this module groups one axis finer: the ladder (`logical_model`) AND the leg
 * inside it (`provider`, `provider_model`). The raw score rows have carried both
 * columns since `0009_online_eval.sql`; nothing was reading them.
 *
 * ============================================================================
 * THE SEMANTICS ARE RELATIVE, AND THIS FILE MAY NOT WEAKEN THAT
 * ============================================================================
 *
 * From `./policy.ts:20-46`, which is the authority on what a judge score means:
 *
 *   > It does NOT support, and an operator must not act as if it does:
 *   > **an absolute claim.** "Our quality is 0.82" is meaningless: judges are
 *   > biased, they systematically prefer longer answers, answers in their own
 *   > family's style, and answers that agree with the prompt's framing.
 *
 * There is therefore NO threshold in this file that a mean is compared against.
 * The only verdict it can reach is the DIFFERENCE one:
 *
 *   > candidate X's mean is at least `regressionDrop` BELOW the best mean in the
 *   > same ladder, under the SAME judge and the SAME criterion, with at least
 *   > `regressionMinSamples` scores on BOTH sides.
 *
 * That is the same shape, the same two knobs and the same guard ORDER as
 * `./regression.ts::detectOnlineEvalRegressions` — deliberately, so that the
 * "how much is a real difference" decision is made once, by the tenant, in one
 * pair of columns, rather than twice with two answers. The only thing swapped is
 * what the candidate is compared TO: a time window there, a sibling leg here.
 *
 * A leg with too few samples is `no_signal`, and `no_signal` is NOT "fine". The
 * three-armed verdict exists precisely so a caller cannot spell "we have not
 * measured this leg" and "this leg measured well" the same way — a two-armed
 * boolean would make a never-routed-to candidate indistinguishable from a good
 * one, which is the exact reading that would promote it.
 *
 * ============================================================================
 * WHERE THE ROWS COME FROM, AND WHY NOT FROM THE REQUEST PATH
 * ============================================================================
 *
 * `refreshOnlineEvalLegQuality` runs from the QUEUE CONSUMER (right after a
 * tenant's scores are written) and from the CRON sweep. Neither is on a client's
 * request. The request path only ever READS the projected rows, through the
 * peek/warm memo in `./quality-source.ts`, and never awaits a read at all — see
 * that file, and `inference/strategy.ts` on why ordering is pure.
 *
 * The recompute reads the tenant object's authoritative scores and REPLACES the
 * control projection's rows for that tenant. Nothing accumulates, so a
 * redelivered queue batch and a double cron tick are both no-ops rather than
 * double counts.
 */
import {
  ONLINE_EVAL_SCORE_TABLE,
  type OnlineEvalScoreDatabase,
  onlineEvalDatabaseFrom,
  onlineEvalTenantDatabaseFrom,
} from "./d1.js";
import type { OnlineEvalPolicy } from "./policy.js";
import { SHADOW_EVAL_ARM } from "./shadow-leg.js";

export const ONLINE_EVAL_LEG_QUALITY_TABLE = "online_eval_leg_quality";

/**
 * How far back the leg aggregate looks.
 *
 * The same seven days `./regression.ts::BASELINE_WINDOW_SECONDS` uses, and NOT
 * the 24h recent window: a non-primary candidate only accumulates scores from
 * shadow coverage, which is a sampled fraction of a sampled fraction, so a
 * 24h window would leave every candidate below `regressionMinSamples` forever
 * and the whole signal would be `no_signal` by construction.
 */
export const LEG_QUALITY_WINDOW_SECONDS = 7 * 24 * 60 * 60;

/** One `(criterion, judge, ladder, leg)` cell of one tenant's window. */
export interface OnlineEvalLegAggregate {
  readonly tenantId: string;
  readonly criterionId: string;
  readonly judgeModel: string;
  readonly logicalModel: string;
  readonly provider: string;
  readonly providerModel: string;
  readonly scoreTotal: number;
  readonly scoreCount: number;
}

/**
 * The finer GROUP BY, in one statement.
 *
 * `provider`, `logical_model` and `provider_model` are nullable columns on the
 * score table (a sample whose route could not be attributed writes NULL), and a
 * NULL grouping key is not a leg anybody can route to — so they are excluded in
 * the WHERE rather than grouped as a phantom row.
 *
 * ## Why the `shadow` arm is excluded, and only that arm
 *
 * `./shadow-leg.ts::shadowArmSampleFrom` files an EXPERIMENT mirror's score
 * under the served request's `logical_model` — the same ladder — with the
 * mirror's own `(provider, provider_model)`. But
 * `inference/candidates.ts::servableCandidates` strips every route carrying
 * `shadowPercent` from the ladder, so that provider can NEVER serve a client.
 * Leaving it in would let an unroutable leg DEFINE the `best` bar in
 * {@link legQualityVerdicts} and demote a servable sibling that is inside the
 * tenant's own `regressionDrop` of the best ROUTABLE leg — i.e. on a gap the
 * tenant has declared is not real. The `coverage` arm is deliberately KEPT: a
 * covered leg is a servable candidate of this ladder, and buying its score is
 * the whole point of #894.
 */
export const ONLINE_EVAL_LEG_WINDOW_AGGREGATE_SQL = `SELECT
  criterion_id, judge_model, logical_model, provider, provider_model,
  SUM(score) AS score_total,
  COUNT(*)   AS score_count
FROM ${ONLINE_EVAL_SCORE_TABLE}
WHERE tenant = ?1 AND scored_at_unix >= ?2
  AND provider IS NOT NULL AND provider <> ''
  AND provider_model IS NOT NULL AND provider_model <> ''
  AND logical_model IS NOT NULL AND logical_model <> ''
  AND (experiment_arm IS NULL OR experiment_arm <> '${SHADOW_EVAL_ARM}')
GROUP BY criterion_id, judge_model, logical_model, provider, provider_model`;

/** Replace, never accumulate — see the module docs on redelivery. */
export const ONLINE_EVAL_LEG_QUALITY_UPSERT_SQL = `INSERT INTO ${ONLINE_EVAL_LEG_QUALITY_TABLE} (
  tenant, criterion_id, judge_model, logical_model, provider, provider_model,
  score_total, score_count, window_start_unix, as_of_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (tenant, criterion_id, judge_model, logical_model, provider, provider_model)
DO UPDATE SET
  score_total = excluded.score_total,
  score_count = excluded.score_count,
  window_start_unix = excluded.window_start_unix,
  as_of_unix = excluded.as_of_unix`;

/**
 * Drop the cells this refresh did not rewrite.
 *
 * A group whose scores have all aged out of the window produces no row above,
 * so without this the last value it ever had would sit in the table for ever
 * and a leg that stopped being measured would keep steering the router on a
 * number nobody can reproduce.
 */
export const ONLINE_EVAL_LEG_QUALITY_PRUNE_SQL = `DELETE FROM ${ONLINE_EVAL_LEG_QUALITY_TABLE}
WHERE tenant = ?1 AND as_of_unix < ?2`;

/** One tenant's whole projected aggregate. Read by the router's warm half. */
export const ONLINE_EVAL_LEG_QUALITY_SELECT_SQL = `SELECT
  criterion_id, judge_model, logical_model, provider, provider_model,
  score_total, score_count
FROM ${ONLINE_EVAL_LEG_QUALITY_TABLE}
WHERE tenant = ?1`;

function numberColumn(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function rowToAggregate(tenantId: string, row: Record<string, unknown>): OnlineEvalLegAggregate {
  return {
    tenantId,
    criterionId: String(row.criterion_id ?? ""),
    judgeModel: String(row.judge_model ?? ""),
    logicalModel: String(row.logical_model ?? ""),
    provider: String(row.provider ?? ""),
    providerModel: String(row.provider_model ?? ""),
    scoreTotal: numberColumn(row.score_total),
    scoreCount: numberColumn(row.score_count),
  };
}

/** Recompute one tenant's per-leg window from the SCORES. */
export async function onlineEvalLegAggregates(
  db: OnlineEvalScoreDatabase,
  tenantId: string,
  nowUnix: number,
): Promise<OnlineEvalLegAggregate[]> {
  const windowStart = nowUnix - LEG_QUALITY_WINDOW_SECONDS;
  const result = (await db
    .prepare(ONLINE_EVAL_LEG_WINDOW_AGGREGATE_SQL)
    .bind(tenantId, windowStart)
    .all()) as { results?: Record<string, unknown>[] } | undefined;
  return (result?.results ?? []).map((row) => rowToAggregate(tenantId, row));
}

/** Read one tenant's PROJECTED aggregate back. */
export async function readOnlineEvalLegQuality(
  db: OnlineEvalScoreDatabase,
  tenantId: string,
): Promise<OnlineEvalLegAggregate[]> {
  const result = (await db.prepare(ONLINE_EVAL_LEG_QUALITY_SELECT_SQL).bind(tenantId).all()) as
    | { results?: Record<string, unknown>[] }
    | undefined;
  return (result?.results ?? []).map((row) => rowToAggregate(tenantId, row));
}

/** Bind order for {@link ONLINE_EVAL_LEG_QUALITY_UPSERT_SQL}. */
export function onlineEvalLegQualityBindings(
  aggregate: OnlineEvalLegAggregate,
  windowStartUnix: number,
  asOfUnix: number,
): unknown[] {
  return [
    aggregate.tenantId,
    aggregate.criterionId,
    aggregate.judgeModel,
    aggregate.logicalModel,
    aggregate.provider,
    aggregate.providerModel,
    aggregate.scoreTotal,
    aggregate.scoreCount,
    windowStartUnix,
    asOfUnix,
  ];
}

/**
 * Write one tenant's recomputed cells and prune the ones that aged out.
 *
 * `tenantId` is a PARAMETER rather than read off `aggregates[0]`, and the prune
 * is UNCONDITIONAL. An empty recompute is not "nothing to do": it is the exact
 * state the prune exists for — every score of every leg has aged out of the
 * seven-day window, so without a prune the last cell the tenant ever had would
 * sit in the table for ever and keep steering the router on a number nobody can
 * reproduce, and no other path recovers it (`./regression.ts`'s cron sweep only
 * iterates tenants that HAVE scores in the window, which is precisely not this
 * tenant). Deriving the tenant from the first aggregate made the empty case
 * unreachable, which is how it was missed.
 */
export async function writeOnlineEvalLegQuality(
  db: OnlineEvalScoreDatabase,
  tenantId: string,
  aggregates: readonly OnlineEvalLegAggregate[],
  nowUnix: number,
): Promise<void> {
  const windowStartUnix = nowUnix - LEG_QUALITY_WINDOW_SECONDS;
  const upsert = db.prepare(ONLINE_EVAL_LEG_QUALITY_UPSERT_SQL);
  const statements = aggregates.map((aggregate) =>
    upsert.bind(...onlineEvalLegQualityBindings(aggregate, windowStartUnix, nowUnix)),
  );
  // The tenant fence is the bound `tenant` on every row; the prune is bound to
  // the same tenant, so one tenant's refresh can never remove another's cells.
  statements.push(db.prepare(ONLINE_EVAL_LEG_QUALITY_PRUNE_SQL).bind(tenantId, nowUnix));
  await db.batch(statements);
}

/**
 * Recompute + project one tenant, OFF the request path.
 *
 * NEVER throws, and returns the number of cells written. The callers are the
 * queue consumer (after the scores are durable — a refresh failure must not
 * cost a score that has already been paid for) and the cron sweep (beside the
 * billing outbox, where a quality projection may not take money recovery down).
 *
 * Object-first, with the same rule and the same seam as
 * `./regression.ts::sweepOnlineEvalRegressions`: an absent tenant-object binding
 * under the DEFAULT resolvers is a storage misconfiguration, not permission to
 * aggregate the shared control table as if it were authority.
 */
export async function refreshOnlineEvalLegQuality(
  env: unknown,
  tenantId: string,
  nowUnix: number,
  database: (env: unknown) => OnlineEvalScoreDatabase | undefined = onlineEvalDatabaseFrom,
  tenantDatabase: (
    env: unknown,
    tenantId: string,
  ) => OnlineEvalScoreDatabase | undefined = onlineEvalTenantDatabaseFrom,
): Promise<number> {
  const projection = database(env);
  if (projection === undefined) return 0;

  const authoritative = tenantDatabase(env, tenantId);
  if (database === onlineEvalDatabaseFrom && authoritative === undefined) return 0;
  // Single source of truth (Track A): `online_eval_leg_quality` is a
  // fully-recomputed projection of `online_eval_scores`, which is authoritative
  // in the tenant object. The projection is written to that SAME object and
  // nowhere else — the shared-control mirror is retired, so there is no second
  // copy to drift and no dual-write to reconcile. Under the DEFAULT resolvers
  // `authoritative` IS the tenant object (the guard above already refused the
  // absent-binding case); the `?? projection` fallback exists only for tests
  // that inject a single db to drive the real recompute/upsert/prune SQL.
  const target = authoritative ?? projection;

  try {
    const aggregates = await onlineEvalLegAggregates(target, tenantId, nowUnix);
    await writeOnlineEvalLegQuality(target, tenantId, aggregates, nowUnix);
    return aggregates.length;
  } catch {
    // A schema that predates this migration, or a D1 blip. The next queue batch
    // or cron tick recomputes the same window from the same scores.
    return 0;
  }
}

// ---------------------------------------------------------------------------
// The pure comparator
// ---------------------------------------------------------------------------

/**
 * What the router is told about ONE leg.
 *
 * Three arms rather than a boolean, for the reason in the module docs: a
 * two-armed answer cannot distinguish "not measured" from "measured well", and
 * the un-measured candidate is exactly the one a cost-driven router wants to
 * promote.
 */
export type LegQualityVerdict =
  | {
      /** Fewer than `regressionMinSamples` on this leg, or on every comparator. */
      readonly kind: "no_signal";
    }
  | {
      /** Measured against a comparable sibling and NOT below it by `regressionDrop`. */
      readonly kind: "comparable";
      readonly scoreCount: number;
    }
  | {
      readonly kind: "lagging";
      /** `bestMean - legMean`, always `>= regressionDrop`. */
      readonly dropAmount: number;
      readonly criterionId: string;
      readonly judgeModel: string;
      readonly scoreCount: number;
      /** The leg it lost to — never a floor, always another leg of this ladder. */
      readonly bestProvider: string;
      readonly bestProviderModel: string;
      readonly bestScoreCount: number;
    };

/** `no_signal`, named once so a caller can compare against it by identity. */
export const NO_LEG_QUALITY_SIGNAL: LegQualityVerdict = { kind: "no_signal" };

/** `${logicalModel}\u0000${provider}\u0000${providerModel}` — the leg's key. */
export function legQualityKey(
  logicalModel: string,
  provider: string,
  providerModel: string,
): string {
  return `${logicalModel}\u0000${provider}\u0000${providerModel}`;
}

interface LadderCell {
  readonly aggregate: OnlineEvalLegAggregate;
  readonly mean: number;
}

/**
 * The comparator, PURE and total.
 *
 * Same guard order as `./regression.ts::detectOnlineEvalRegressions`:
 *
 *  1. the leg itself needs `regressionMinSamples` scores;
 *  2. so does the leg it is compared against — "≥ N on BOTH sides";
 *  3. only then is `bestMean - legMean >= regressionDrop` a lag.
 *
 * A leg that lags under ANY one `(criterion, judge)` group is reported lagging.
 * The criteria are separate questions the tenant wrote separately, so scoring
 * well on one does not answer another, and averaging them would average two
 * instruments — the thing `./policy.ts` forbids.
 */
export function legQualityVerdicts(
  aggregates: readonly OnlineEvalLegAggregate[],
  policy: Pick<OnlineEvalPolicy, "regressionDrop" | "regressionMinSamples">,
): Map<string, LegQualityVerdict> {
  const groups = new Map<string, LadderCell[]>();
  for (const aggregate of aggregates) {
    if (aggregate.scoreCount <= 0) continue;
    const groupKey = `${aggregate.logicalModel}\u0000${aggregate.criterionId}\u0000${aggregate.judgeModel}`;
    const cells = groups.get(groupKey) ?? [];
    cells.push({ aggregate, mean: aggregate.scoreTotal / aggregate.scoreCount });
    groups.set(groupKey, cells);
  }

  const verdicts = new Map<string, LegQualityVerdict>();
  for (const cells of groups.values()) {
    // Only a leg with enough samples may DEFINE the bar. A four-sample leg that
    // happened to score 1.0 must not make every sibling look like a regression.
    const eligible = cells.filter(
      (cell) => cell.aggregate.scoreCount >= policy.regressionMinSamples,
    );
    if (eligible.length === 0) continue;
    let best = eligible[0] as LadderCell;
    for (const cell of eligible) if (cell.mean > best.mean) best = cell;

    for (const cell of eligible) {
      const key = legQualityKey(
        cell.aggregate.logicalModel,
        cell.aggregate.provider,
        cell.aggregate.providerModel,
      );
      const dropAmount = best.mean - cell.mean;
      const lagging = dropAmount >= policy.regressionDrop;
      const existing = verdicts.get(key);
      if (!lagging) {
        // A `lagging` already recorded under another criterion wins: the OR in
        // the docblock. Only upgrade `undefined`/`no_signal` to `comparable`.
        if (existing === undefined || existing.kind === "no_signal") {
          verdicts.set(key, { kind: "comparable", scoreCount: cell.aggregate.scoreCount });
        }
        continue;
      }
      if (existing?.kind === "lagging" && existing.dropAmount >= dropAmount) continue;
      verdicts.set(key, {
        kind: "lagging",
        dropAmount,
        criterionId: cell.aggregate.criterionId,
        judgeModel: cell.aggregate.judgeModel,
        scoreCount: cell.aggregate.scoreCount,
        bestProvider: best.aggregate.provider,
        bestProviderModel: best.aggregate.providerModel,
        bestScoreCount: best.aggregate.scoreCount,
      });
    }
  }
  return verdicts;
}
