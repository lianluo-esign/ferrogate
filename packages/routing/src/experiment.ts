/**
 * Experiment identity and the comparison of two arms' OUTCOMES (issue #693).
 *
 * `./rollout.ts` is the split: a sticky canary percentage and a budgeted shadow
 * mirror. This module is the other half — what the split is called, which arm
 * served a request, and the only comparison the data actually supports.
 *
 * It lives beside the split rather than in the app that reports it, because the
 * writer (`apps/gateway`) and the reader (`apps/control-plane`) must agree
 * exactly on the experiment id: an id computed one way in the gateway and
 * another way in the reporting surface would file two halves of one experiment
 * under two names and report neither.
 *
 * ============================================================================
 * WHAT AN EXPERIMENT NUMBER MEANS — AND WHAT IT CANNOT MEAN
 * ============================================================================
 *
 * The quality half of this comparison is built on #692's online-evaluation
 * scores, and inherits that slice's governing honesty verbatim
 * (`apps/gateway/src/evals/policy.ts` states it at length). A score row means
 * exactly:
 *
 *   > judge X, shown this exchange and asked criterion Y, answered Z at time T.
 *
 * That supports ONE class of inference: a RELATIVE comparison between two
 * populations scored by the SAME judge under the SAME criterion. Not an
 * absolute claim, not a comparison across judges or re-worded criteria, not a
 * per-request verdict.
 *
 * An experiment IS exactly that relative comparison, which is why outcome
 * metrics became cheap the day online evaluation landed and were not
 * implementable before it. But "same judge, same criterion" is a precondition a
 * report can violate without anything looking wrong: two arms scored by
 * different judges produce two perfectly good means, and subtracting them
 * produces a perfectly plausible number that measures the difference between
 * two INSTRUMENTS rather than between two models.
 *
 * So the precondition is enforced STRUCTURALLY here rather than documented:
 * {@link compareExperimentQuality} groups by `(judgeModel, criterionId)` and
 * only ever pairs arms WITHIN one group. Arms that do not share a group cannot
 * be subtracted, because there is no code path that subtracts them — they come
 * back as {@link ExperimentIncomparableCell}, which carries no difference and
 * no means. An operator sees "these arms were scored differently", not a
 * number.
 *
 * ============================================================================
 * THE THREE REFUSALS
 * ============================================================================
 *
 *  1. **Different judge or different criterion ⇒ incomparable.** Above.
 *  2. **Too few samples ⇒ no number at all.** Below `minSamples` in EITHER arm
 *     the verdict is `insufficient_samples` and the means are omitted from the
 *     result object entirely. Reporting counts without means is deliberate: the
 *     count is what tells an operator to wait, and a mean over two samples on a
 *     screen will be acted on however carefully it is captioned.
 *  3. **A difference the spread does not support ⇒ `no_measured_difference`.**
 *     Welch's unequal-variance t-test at `alpha`. The means ARE shown here,
 *     because the sample is adequate and the honest statement is "we measured
 *     both and cannot distinguish them" — which is itself a rollout decision.
 *
 * None of the three is a warning flag on an otherwise-numeric result. Each one
 * changes the SHAPE of what comes back, so a consumer that ignores it has
 * nothing to render.
 */
import { fnv1a64 } from "./fnv.js";

/**
 * Which leg of a split produced an observation.
 *
 * `control` — the route the model would have used with no split at all.
 * `canary` — the variant route, promoted for the sticky subset of callers
 *   `canarySelected` picks. Fully served: the client sees this response.
 * `shadow` — the mirror. Dispatched, measured, and DISCARDED; no client ever
 *   sees it. See {@link armChargedTo} for what that means for the invoice.
 */
export type ExperimentArm = "control" | "canary" | "shadow";

/** Every arm, in report order (control first — it is what the rest is against). */
export const EXPERIMENT_ARMS: readonly ExperimentArm[] = ["control", "canary", "shadow"];

/** Whether an arm's response was delivered to the caller. */
export function armDelivered(arm: ExperimentArm): boolean {
  return arm !== "shadow";
}

/**
 * WHO PAYS for an arm's provider spend.
 *
 * A `control` or `canary` response was served: the caller made a request, got
 * an answer, and is charged for it exactly as they would be with no experiment
 * running. `apps/gateway/src/inference/handlers.ts` meters that response once,
 * from the attempt that produced it.
 *
 * A `shadow` response was never delivered. The customer did not ask for a
 * second provider, could not see the answer, and cannot use it — so the tokens
 * are the OPERATOR's cost of taking a measurement, and
 * `apps/gateway/src/inference/shadow.ts` structurally cannot bill them: it has
 * no code path to `deps.usage.record`, to the ledger, to the billing outbox or
 * to the TPM governor. The provider still invoices the operator for those
 * tokens; that is the price of the experiment and it belongs on the operator's
 * side of the ledger.
 *
 * This is a FUNCTION OF THE ARM rather than a field on an observation, so a
 * writer cannot record a shadow leg as tenant-charged, and a report cannot show
 * shadow spend as if it landed on the customer's invoice.
 */
export function armChargedTo(arm: ExperimentArm): "tenant" | "operator" {
  return arm === "shadow" ? "operator" : "tenant";
}

/** The provider-side identity of one route, as an experiment names it. */
export interface ExperimentRouteIdentity {
  readonly provider: string;
  readonly providerModel: string;
}

/**
 * The split an experiment id is computed from.
 *
 * The CONTROL is included on purpose. Moving the primary route changes what the
 * variant is being compared against, so it must start a new experiment — the
 * same discipline #692 applies to a renamed criterion, and for the same reason:
 * pooling a population measured against one baseline with one measured against
 * another produces a difference that is partly a baseline change and entirely
 * uninterpretable.
 *
 * The PERCENTAGES are deliberately NOT included. Raising a canary from 5% to
 * 25% changes how fast the sample accumulates; it does not change what is being
 * compared, and restarting the experiment on every ramp step would guarantee
 * that no experiment ever reaches a significant sample.
 */
export interface ExperimentSplitSpec {
  readonly logicalModel: string;
  readonly control: ExperimentRouteIdentity;
  readonly canary?: ExperimentRouteIdentity | undefined;
  readonly shadow?: ExperimentRouteIdentity | undefined;
}

const UTF8 = new TextEncoder();

function routeToken(route: ExperimentRouteIdentity | undefined): string {
  return route === undefined ? "-" : `${route.provider}:${route.providerModel}`;
}

/**
 * The stable id for a split, or `null` when there is no split to identify.
 *
 * A model with no canary and no shadow is not an experiment: nothing is being
 * compared to anything, and minting an id for it would fill the reporting
 * surface with single-arm "experiments" an operator has to learn to ignore.
 *
 * The id is a hash rather than a readable composite because it is a GROUPING
 * KEY stored on every observation row and every score row of an experiment;
 * `exp_openai:gpt-4o-mini|anthropic:claude-3-5-haiku|-` would be that string on
 * millions of rows, and a provider or model name containing the separator would
 * make two different splits collide. The inputs are also reported alongside the
 * id by the reader, so the hash is never the only record of what was compared.
 */
export function experimentIdFor(spec: ExperimentSplitSpec): string | null {
  if (spec.canary === undefined && spec.shadow === undefined) return null;
  const canonical = [
    "v1",
    spec.logicalModel,
    routeToken(spec.control),
    routeToken(spec.canary),
    routeToken(spec.shadow),
  ].join(" ");
  return `exp_${fnv1a64(UTF8.encode(canonical)).toString(16).padStart(16, "0")}`;
}

// ---------------------------------------------------------------------------
// The OPERATIONAL half — cost, latency, error rate
// ---------------------------------------------------------------------------

/** Raw per-arm totals, as an aggregate query returns them. */
export interface ArmOperationalAggregate {
  readonly arm: ExperimentArm;
  /** Legs observed for this arm in the window. */
  readonly requests: number;
  /**
   * Legs that failed. The classification is the request LOG's
   * (`status_code >= 400 || error_code is not null`), not the circuit breaker's
   * — a provider that answers 400 to a body it dislikes failed the caller even
   * though the breaker deliberately ignores it.
   */
  readonly failures: number;
  readonly latencyTotalMs: number;
  readonly costUsdTotal: number;
}

/** One arm's operational outcome, ready to report. */
export interface ArmOperationalSummary {
  readonly arm: ExperimentArm;
  readonly requests: number;
  readonly failures: number;
  /** `undefined` for an arm that served nothing — 0/0 is not 0. */
  readonly errorRate?: number | undefined;
  readonly meanLatencyMs?: number | undefined;
  readonly costUsd: number;
  /** Structural, from the arm. See {@link armDelivered}. */
  readonly delivered: boolean;
  /** Structural, from the arm. See {@link armChargedTo}. */
  readonly chargedTo: "tenant" | "operator";
}

/**
 * Turn per-arm totals into the reported outcome.
 *
 * The one judgement here is that an arm with zero requests has NO error rate
 * and NO mean latency, rather than zero. An arm that has served nothing yet is
 * the normal state of a canary in its first minutes, and rendering it as "0%
 * errors, 0 ms" is how a split that is not actually receiving traffic gets
 * promoted.
 */
export function summariseArmOperations(
  aggregates: readonly ArmOperationalAggregate[],
): ArmOperationalSummary[] {
  return aggregates.map((aggregate) => {
    const { arm, requests, failures, latencyTotalMs, costUsdTotal } = aggregate;
    return {
      arm,
      requests,
      failures,
      ...(requests > 0 ? { errorRate: failures / requests } : {}),
      ...(requests > 0 ? { meanLatencyMs: latencyTotalMs / requests } : {}),
      costUsd: costUsdTotal,
      delivered: armDelivered(arm),
      chargedTo: armChargedTo(arm),
    };
  });
}

// ---------------------------------------------------------------------------
// The QUALITY half — the comparison the honesty rules constrain
// ---------------------------------------------------------------------------

/**
 * One arm's scores under ONE `(judgeModel, criterionId)`, as sufficient
 * statistics.
 *
 * `total` and `totalSquares` rather than a list of scores: the aggregate is
 * produced by a `GROUP BY` in SQLite over a table that grows with traffic, and
 * a comparison that had to stream every score into the isolate would be the
 * first thing switched off. Σx and Σx² are all Welch's test needs.
 *
 * Carrying `judgeModel` and `criterionId` on the row rather than on the call is
 * what makes the precondition enforceable: the grouping is DATA, so a mismatch
 * is detectable, and a caller cannot assert "these were all judge A" the way it
 * could if the judge were a parameter.
 */
export interface ArmScoreAggregate {
  readonly arm: ExperimentArm;
  readonly judgeModel: string;
  readonly criterionId: string;
  readonly count: number;
  /** Σ score over the arm's scored samples. */
  readonly total: number;
  /** Σ score². Needed for the sample variance the significance test runs on. */
  readonly totalSquares: number;
}

/** What a comparison concluded. */
export type ExperimentQualityVerdict =
  /** The variant scored higher, by more than the spread can explain. */
  | "variant_better"
  /** The control scored higher, by more than the spread can explain. */
  | "control_better"
  /** Both arms adequately sampled; the difference is not distinguishable. */
  | "no_measured_difference"
  /** Below the sample floor in at least one arm. NO means are reported. */
  | "insufficient_samples";

/** One arm's side of a comparison. */
export interface ArmQualitySide {
  readonly arm: ExperimentArm;
  readonly count: number;
  /**
   * Present ONLY when the cell cleared the sample floor. Omitted — not zeroed,
   * not nulled — so a consumer rendering `insufficient_samples` has no number
   * available to render.
   */
  readonly mean?: number | undefined;
  readonly stdDev?: number | undefined;
}

/** A comparable `(judge, criterion)` cell: both arms scored the same way. */
export interface ExperimentQualityCell {
  readonly criterionId: string;
  readonly judgeModel: string;
  readonly control: ArmQualitySide;
  readonly variant: ArmQualitySide;
  readonly verdict: ExperimentQualityVerdict;
  /** `variant.mean - control.mean`. Absent under `insufficient_samples`. */
  readonly difference?: number | undefined;
  /** Two-sided Welch p-value. Absent under `insufficient_samples`. */
  readonly pValue?: number | undefined;
  /** The floor this cell was held to, so the refusal is self-explaining. */
  readonly minSamples: number;
}

/**
 * A `(judge, criterion)` cell only ONE arm was scored under.
 *
 * This is the shape a violated precondition takes. It deliberately carries no
 * mean and no difference: there is nothing legitimate to compute, and a field
 * that could hold a number would eventually hold one.
 */
export interface ExperimentIncomparableCell {
  readonly criterionId: string;
  readonly judgeModel: string;
  readonly reason: "control_arm_not_scored" | "variant_arm_not_scored";
  /** The arms that DO have scores here, so the mismatch is diagnosable. */
  readonly scoredArms: readonly ExperimentArm[];
  readonly detail: string;
}

/** The whole quality comparison for one experiment. */
export interface ExperimentQualityReport {
  readonly cells: readonly ExperimentQualityCell[];
  readonly incomparable: readonly ExperimentIncomparableCell[];
  /**
   * True when the two arms were scored under criteria that do not both appear
   * on both sides — the loud "your arms were measured with different
   * questions" signal, hoisted out of `incomparable` so a surface cannot show
   * the report without it.
   */
  readonly criterionMismatch: boolean;
  /** The same, for the judge model. */
  readonly judgeMismatch: boolean;
}

export interface ExperimentQualityOptions {
  /**
   * Minimum scored samples in BOTH arms before any mean is reported.
   *
   * There is no defensible universal value — it depends on the effect size an
   * operator cares about and on the judge's noise floor, which depends on the
   * tenant's criteria wording. So it is a required parameter rather than a
   * constant with a comment: a default here would be a decision taken on behalf
   * of every deployment by whoever typed it first.
   */
  readonly minSamples: number;
  /** Two-sided significance level, e.g. `0.05`. */
  readonly alpha: number;
}

function cellKey(judgeModel: string, criterionId: string): string {
  return `${judgeModel} ${criterionId}`;
}

/** Sample mean and sample standard deviation from the sufficient statistics. */
function moments(aggregate: ArmScoreAggregate): { mean: number; stdDev: number } {
  const mean = aggregate.total / aggregate.count;
  if (aggregate.count < 2) return { mean, stdDev: 0 };
  // s² = (Σx² − n·x̄²) / (n − 1). Clamped at zero: with identical scores the
  // two terms cancel and floating-point can leave a tiny negative, whose square
  // root would be NaN and would poison every downstream comparison.
  const variance = Math.max(
    (aggregate.totalSquares - aggregate.count * mean * mean) / (aggregate.count - 1),
    0,
  );
  return { mean, stdDev: Math.sqrt(variance) };
}

/**
 * Compare a variant arm against the control, one `(judge, criterion)` at a time.
 *
 * `variantArm` is a parameter rather than "whatever is not the control" because
 * a model can carry a canary AND a shadow at once, and pooling them would
 * compare the control against a mixture of two different variants. A caller
 * asks about one variant; the other arm's rows are ignored, not merged.
 *
 * PURE: no I/O, no clock, no randomness. The aggregates come from one SQL
 * `GROUP BY` in `apps/control-plane`, and every refusal above is decided here
 * so the reporting route cannot decide it differently.
 */
export function compareExperimentQuality(
  variantArm: ExperimentArm,
  aggregates: readonly ArmScoreAggregate[],
  options: ExperimentQualityOptions,
): ExperimentQualityReport {
  const groups = new Map<
    string,
    {
      judgeModel: string;
      criterionId: string;
      control?: ArmScoreAggregate;
      variant?: ArmScoreAggregate;
      scoredArms: Set<ExperimentArm>;
    }
  >();

  for (const aggregate of aggregates) {
    if (aggregate.count <= 0) continue;
    const key = cellKey(aggregate.judgeModel, aggregate.criterionId);
    const group = groups.get(key) ?? {
      judgeModel: aggregate.judgeModel,
      criterionId: aggregate.criterionId,
      scoredArms: new Set<ExperimentArm>(),
    };
    group.scoredArms.add(aggregate.arm);
    if (aggregate.arm === "control") group.control = aggregate;
    else if (aggregate.arm === variantArm) group.variant = aggregate;
    groups.set(key, group);
  }

  const cells: ExperimentQualityCell[] = [];
  const incomparable: ExperimentIncomparableCell[] = [];
  const judges = new Set<string>();
  const criteria = new Set<string>();
  const pairedJudges = new Set<string>();
  const pairedCriteria = new Set<string>();

  for (const group of groups.values()) {
    judges.add(group.judgeModel);
    criteria.add(group.criterionId);
    const { control, variant } = group;

    if (control === undefined || variant === undefined) {
      // The precondition is violated for this cell. There is no arithmetic to
      // do; the only useful output is which arm is missing and what WAS scored.
      incomparable.push({
        criterionId: group.criterionId,
        judgeModel: group.judgeModel,
        reason: control === undefined ? "control_arm_not_scored" : "variant_arm_not_scored",
        scoredArms: [...group.scoredArms],
        detail:
          control === undefined
            ? `no control-arm scores under judge '${group.judgeModel}' for criterion '${group.criterionId}'`
            : `no ${variantArm}-arm scores under judge '${group.judgeModel}' for criterion '${group.criterionId}'`,
      });
      continue;
    }

    pairedJudges.add(group.judgeModel);
    pairedCriteria.add(group.criterionId);

    if (control.count < options.minSamples || variant.count < options.minSamples) {
      cells.push({
        criterionId: group.criterionId,
        judgeModel: group.judgeModel,
        control: { arm: "control", count: control.count },
        variant: { arm: variantArm, count: variant.count },
        verdict: "insufficient_samples",
        minSamples: options.minSamples,
      });
      continue;
    }

    const controlMoments = moments(control);
    const variantMoments = moments(variant);
    const difference = variantMoments.mean - controlMoments.mean;
    const pValue = welchTwoSidedP(
      controlMoments,
      control.count,
      variantMoments,
      variant.count,
      difference,
    );
    const significant = pValue <= options.alpha;

    cells.push({
      criterionId: group.criterionId,
      judgeModel: group.judgeModel,
      control: { arm: "control", count: control.count, ...controlMoments },
      variant: { arm: variantArm, count: variant.count, ...variantMoments },
      verdict: !significant
        ? "no_measured_difference"
        : difference > 0
          ? "variant_better"
          : "control_better",
      difference,
      pValue,
      minSamples: options.minSamples,
    });
  }

  return {
    cells,
    incomparable,
    // A mismatch is "some judge/criterion carried scores from only one arm".
    // Computed from the group sets rather than from `incomparable.length` so
    // the two cannot drift apart if the incomparable shape ever changes.
    judgeMismatch: judges.size > pairedJudges.size,
    criterionMismatch: criteria.size > pairedCriteria.size,
  };
}

/**
 * Two-sided p-value for Welch's unequal-variance t-test.
 *
 * Welch rather than Student because the two arms are different models: there is
 * no reason to assume they have the same score variance, and pooling variances
 * that differ inflates significance for the smaller arm — which is always the
 * canary, i.e. exactly the arm a false "better" would promote.
 *
 * The degenerate case is handled explicitly rather than left to produce `NaN`:
 * with zero variance on both sides the standard error is zero, and `t` is
 * ±Infinity or `0/0`. Identical means ⇒ p = 1 (nothing to distinguish);
 * different means with zero observed spread ⇒ p = 0. The second is the honest
 * reading of "every sample in arm A scored 0.8 and every sample in arm B scored
 * 0.6", though it is also a good reason to look at the judge.
 */
function welchTwoSidedP(
  control: { mean: number; stdDev: number },
  controlCount: number,
  variant: { mean: number; stdDev: number },
  variantCount: number,
  difference: number,
): number {
  const controlVarOverN = (control.stdDev * control.stdDev) / controlCount;
  const variantVarOverN = (variant.stdDev * variant.stdDev) / variantCount;
  const standardError = Math.sqrt(controlVarOverN + variantVarOverN);
  if (!(standardError > 0)) {
    return difference === 0 ? 1 : 0;
  }
  const t = difference / standardError;
  const numerator = (controlVarOverN + variantVarOverN) ** 2;
  const denominator =
    (controlVarOverN * controlVarOverN) / (controlCount - 1) +
    (variantVarOverN * variantVarOverN) / (variantCount - 1);
  const df = denominator > 0 ? numerator / denominator : controlCount + variantCount - 2;
  return studentTTwoSidedP(Math.abs(t), df);
}

/**
 * `P(|T_df| >= t)` via the regularized incomplete beta function.
 *
 * The identity is the standard one: for `t >= 0` and `df > 0`,
 * `P(|T| >= t) = I_x(df/2, 1/2)` with `x = df / (df + t²)`.
 *
 * Implemented rather than approximated by a normal because these samples are
 * small on purpose — an experiment is interesting long before it has thousands
 * of scores per arm, and the normal approximation is anti-conservative exactly
 * there, which would call canaries "better" on samples that do not support it.
 */
function studentTTwoSidedP(t: number, df: number): number {
  if (!Number.isFinite(t)) return 0;
  if (!(df > 0)) return 1;
  const x = df / (df + t * t);
  return clampProbability(regularizedIncompleteBeta(x, df / 2, 0.5));
}

function clampProbability(value: number): number {
  if (!Number.isFinite(value)) return 1;
  return Math.min(Math.max(value, 0), 1);
}

/** Lanczos approximation of `ln Γ(z)` — the beta function's normaliser. */
function logGamma(z: number): number {
  const coefficients = [
    676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059,
    12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
  ];
  if (z < 0.5) {
    // Reflection, so the series is only ever evaluated where it converges.
    return Math.log(Math.PI / Math.sin(Math.PI * z)) - logGamma(1 - z);
  }
  const shifted = z - 1;
  let series = 0.99999999999980993;
  for (let index = 0; index < coefficients.length; index += 1) {
    series += (coefficients[index] as number) / (shifted + index + 1);
  }
  const tail = shifted + coefficients.length - 0.5;
  return 0.5 * Math.log(2 * Math.PI) + (shifted + 0.5) * Math.log(tail) - tail + Math.log(series);
}

/**
 * `I_x(a, b)` — the regularized incomplete beta function, by the modified
 * Lentz continued fraction with the standard symmetry swap.
 *
 * The swap (`x > (a+1)/(a+b+2)` ⇒ evaluate the complement) is what keeps the
 * fraction in its fast-converging region; without it the tail this test lives
 * in converges slowly enough to matter.
 */
function regularizedIncompleteBeta(x: number, a: number, b: number): number {
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const front = Math.exp(
    logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log(1 - x),
  );
  if (x > (a + 1) / (a + b + 2)) {
    return 1 - regularizedIncompleteBeta(1 - x, b, a);
  }
  return (front * betaContinuedFraction(x, a, b)) / a;
}

/** The continued fraction of `I_x(a, b)`, evaluated by Lentz's method. */
function betaContinuedFraction(x: number, a: number, b: number): number {
  const tiny = 1e-30;
  const epsilon = 1e-12;
  let c = 1;
  let d = 1 - ((a + b) * x) / (a + 1);
  if (Math.abs(d) < tiny) d = tiny;
  d = 1 / d;
  let result = d;

  for (let m = 1; m <= 300; m += 1) {
    const evenNumerator = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m));
    d = 1 + evenNumerator * d;
    if (Math.abs(d) < tiny) d = tiny;
    c = 1 + evenNumerator / c;
    if (Math.abs(c) < tiny) c = tiny;
    d = 1 / d;
    result *= d * c;

    const oddNumerator = (-(a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1));
    d = 1 + oddNumerator * d;
    if (Math.abs(d) < tiny) d = tiny;
    c = 1 + oddNumerator / c;
    if (Math.abs(c) < tiny) c = tiny;
    d = 1 / d;
    const delta = d * c;
    result *= delta;

    if (Math.abs(delta - 1) < epsilon) break;
  }
  return result;
}
