/**
 * THE DETECTOR (#697) — pure arithmetic, no I/O, no clock, no bindings.
 *
 * Everything that decides whether an operator gets woken up lives in this file
 * and is a total function of its arguments, so the interesting cases (a bursty
 * tenant, a sparse one, a brand-new one, a growing one) are unit tests rather
 * than fixture archaeology. `./pass.ts` is the part that reads D1 and sends
 * webhooks and holds no judgement of its own.
 *
 * ============================================================================
 * WHAT AN ANOMALY IS HERE, AND WHY NOT A THRESHOLD
 * ============================================================================
 *
 * A threshold on absolute spend fires for every growing customer and is ignored
 * within a week; that is the instrument the tree already had (#170's
 * `alert_threshold_pcts` on month-to-date spend) and the one the issue says is
 * wrong. Two signals replace it, kept separate because they have different
 * blind spots and different tuning:
 *
 * ## 1. `burn_rate_spike` — deviation from the scope's OWN baseline
 *
 * Compare the spend in the last CLOSED window against the same scope's
 * preceding `baselineWindows` windows. Three bars must ALL be cleared, and the
 * threshold is their `max`:
 *
 * | bar      | value                          | the false positive it exists to stop |
 * |----------|--------------------------------|--------------------------------------|
 * | `ratio`  | `median * ratio`               | ordinary variance around a stable rate |
 * | `robust` | `median + 3 * 1.4826 * MAD`    | a tenant whose normal IS spiky — its MAD is large, so its bar is high |
 * | `floor`  | `minWindowUsd`                 | $0.02 -> $0.80 is a 40x spike and is nobody's incident |
 *
 * **Median and MAD, never mean and standard deviation.** One previous spike
 * inflates the mean AND the standard deviation, so a z-score detector both
 * misses the second occurrence of a repeating problem and is dragged around by
 * the first. The median has a 50% breakdown point: half the baseline can be
 * garbage before it moves. `1.4826` is the standard consistency constant that
 * makes MAD comparable to a standard deviation for normally-distributed data —
 * spend is NOT normally distributed, which is exactly why the constant is used
 * as a scale hint and the `ratio` bar, not the robust bar, is the knob an
 * operator turns.
 *
 * WHAT IT CANNOT CATCH, and this is the honest part:
 *
 *  - **A runaway that predates the baseline.** It becomes the baseline.
 *    Deviation-from-self is structurally blind to a level shift older than its
 *    lookback. `forecast_overrun` is the only backstop, and only for a scope
 *    with a budget.
 *  - **A slow creep.** 5% a day never deviates from its own recent past by
 *    enough to bind, and lands the same bill a month later.
 *  - **A burst shorter than the window.** A $400 minute in an idle hour is
 *    caught as a $400 hour; a $400 minute inside a $2,000 hour is not
 *    distinguishable from the hour.
 *  - **Anything at all for a scope below the cold-start gates.** That is
 *    deliberate silence, not an oversight — see below.
 *
 * ## 2. `forecast_overrun` — the current rate does not fit the budget
 *
 * Project month-to-date spend to the end of the billing period at the rate
 * observed in that same closed window, and fire when the projection exceeds
 * `monthly_budget_usd`. This is the leg that works from a tenant's FIRST HOUR,
 * because it is anchored on a number the operator set rather than on history
 * that does not exist yet — which is the deliberate answer to cold start.
 *
 * It is a LINEAR EXTRAPOLATION OF ONE WINDOW, not a model. It claims "the
 * current rate does not fit the budget" and nothing else; it does not predict
 * spend, and it is wrong whenever the rate changes, which for agent traffic is
 * most of the time. That is acceptable because the claim it makes is still
 * true and still actionable when the rate later falls — "at this rate you
 * overrun" was a fact about that rate.
 *
 * The guard that keeps it from being absurd is {@link SpendAnomalyTuning.forecastMinPct}:
 * month-to-date spend must already be a few percent of the budget before the
 * projection is allowed to speak. Without it the first expensive request of a
 * billing period extrapolates to a number with no information in it.
 *
 * ============================================================================
 * COLD START AND SPARSITY — DECIDED, NOT LEFT TO THE ARITHMETIC
 * ============================================================================
 *
 * A brand-new tenant is the case a naive implementation gets loudest and most
 * wrong: with no history the baseline is empty, `median` is 0, `MAD` is 0,
 * every bar collapses to 0 and the first dollar is an infinite deviation. Three
 * gates decide it instead:
 *
 *  1. `observedWindows >= minBaselineWindows` (default 12 of 24) — otherwise
 *     {@link SpendAnomalyOutcome} is `insufficient_baseline` and the burn-rate
 *     leg is SILENT.
 *  2. `activeWindows >= minActiveWindows` (default 6) — the sparsity gate. A
 *     tenant with three requests a day has ~3 non-zero hours in 24 and no
 *     distribution at all; it is silent for the same reason.
 *  3. `observedUsd >= minWindowUsd` (default $1) — the absolute floor, applied
 *     as the third bar so it also survives a baseline that is legitimately
 *     tiny.
 *
 * A zero-spend window DOES count as an observation (bar 1) and does NOT count
 * as active (bar 2). "This tenant spent nothing that hour" is a real fact about
 * the shape of their traffic and dropping it would make an idle tenant look
 * denser than it is; but a baseline of mostly zeroes is not a distribution and
 * bar 2 is what says so.
 *
 * Nothing here fabricates a fleet-wide default baseline for a new tenant. A
 * borrowed baseline would produce alerts about a distribution the tenant never
 * had, which is the same class of error as #692's proxy metric: a number
 * presented as one thing that is actually another.
 */

/** The two signals. Kept apart everywhere; never merged into one "anomaly". */
export const SPEND_ANOMALY_SIGNALS = ["burn_rate_spike", "forecast_overrun"] as const;
export type SpendAnomalySignal = (typeof SPEND_ANOMALY_SIGNALS)[number];

/** Ordered worst-last, so `SEVERITY_RANK` can compare them. */
export const SPEND_ANOMALY_SEVERITIES = ["warning", "critical"] as const;
export type SpendAnomalySeverity = (typeof SPEND_ANOMALY_SEVERITIES)[number];

export const SEVERITY_RANK: Readonly<Record<SpendAnomalySeverity, number>> = {
  warning: 1,
  critical: 2,
};

/** Which of the three bars was the binding one. */
export type SpendAnomalyBound = "ratio" | "robust" | "floor" | "forecast";

/**
 * Every knob, resolved. `./policy.ts` builds one of these from a
 * `quota_policies` row plus the defaults below; nothing in this file reads a
 * default, so a test can state a world exactly.
 */
export interface SpendAnomalyTuning {
  readonly enabled: boolean;
  readonly baselineWindows: number;
  readonly minBaselineWindows: number;
  readonly minActiveWindows: number;
  readonly minWindowUsd: number;
  readonly ratio: number;
  readonly criticalRatio: number;
  readonly cooldownSecs: number;
  readonly forecastMinPct: number;
  readonly autoThrottleRpm?: number | undefined;
  readonly throttleTtlSecs: number;
}

/**
 * The shipped defaults.
 *
 * Chosen to be QUIET. Every one of them can only be relaxed by an operator who
 * has decided they want more alerts; the failure mode of a too-quiet detector
 * is a missed incident the invoice still catches, and the failure mode of a
 * too-loud one is a muted channel that also loses the next real incident.
 */
export const SPEND_ANOMALY_DEFAULTS: SpendAnomalyTuning = {
  enabled: true,
  baselineWindows: 24,
  minBaselineWindows: 12,
  minActiveWindows: 6,
  minWindowUsd: 1,
  ratio: 4,
  criticalRatio: 10,
  cooldownSecs: 21_600,
  forecastMinPct: 5,
  autoThrottleRpm: undefined,
  throttleTtlSecs: 3_600,
};

/**
 * The width of a detection window, in seconds. A FLEET constant, not a knob.
 *
 * `./source.ts` buckets the whole fleet's spend with ONE `GROUP BY` at this
 * width, which is what makes it affordable to watch every tenant by default.
 * A per-scope width would need one bucket query, one window alignment and one
 * `spend_anomaly_runs` claim key per distinct width, so it is not a column an
 * operator can set — and the previous attempt at making it one is the defect
 * this constant replaces: `spend_anomaly_window_secs` was read into the tuning
 * and then used ONLY as the divisor of the forecast projection, so an operator
 * who "narrowed the window" got the same hourly observation divided by ten
 * minutes. A flat $1/hour tenant, $25 month-to-date against a $400 budget,
 * projected to $2,173 and pulled its own auto-throttle. The projection now
 * scales by {@link SpendAnomalyInput.observedWindowSecs} — the width the sum
 * was actually taken over, and the same number written to
 * `spend_anomaly_episodes.window_secs`.
 */
export const SPEND_ANOMALY_WINDOW_SECS = 3_600;

/**
 * The widest baseline an operator may ask for: one week of hourly windows.
 *
 * `./pass.ts` fetches buckets back to the WIDEST baseline any policy configured,
 * so this is the bound on how far a single typo can make the fleet pass scan.
 * A value above it falls back to the default, exactly as a negative one does.
 */
export const SPEND_ANOMALY_MAX_BASELINE_WINDOWS = 168;

/**
 * The robust-bar multiplier, deliberately NOT a tuning column.
 *
 * Three scaled MADs is the conventional robust analogue of "3 sigma". It is
 * fixed because two sensitivity knobs pointing at the same decision is how a
 * detector becomes untunable: an operator turning `ratio` down and wondering
 * why nothing changed (because the robust bar was binding) is a worse
 * experience than one knob that always moves the answer. `boundBy` on every
 * episode is what tells them which bar bound, so the fixed one is never
 * invisible.
 */
export const ROBUST_BAR_SIGMAS = 3;

/** MAD -> standard-deviation-comparable scale, for normal data. */
export const MAD_TO_SIGMA = 1.4826;

/** One closed window of observed spend for one scope. */
export interface SpendWindow {
  readonly startUnix: number;
  readonly costUsd: number;
}

/** Everything the detector knows about one scope at one tick. */
export interface SpendAnomalyInput {
  readonly scopeType: "tenant";
  readonly scopeId: string;
  /** The closed window under evaluation. */
  readonly windowStartUnix: number;
  readonly observedUsd: number;
  /**
   * The width, in seconds, of the window `observedUsd` was SUMMED over.
   *
   * Supplied by the caller rather than taken from the tuning, because it is a
   * property of the MEASUREMENT and not a preference: `./pass.ts` buckets with
   * one fleet-wide `GROUP BY`, and the projection below multiplies by
   * "remaining period / this", so any other number silently rescales a real
   * observation. It is the same number written to
   * `spend_anomaly_episodes.window_secs`, which is what lets a test recompute
   * the projection from the episode row and catch the two drifting apart.
   */
  readonly observedWindowSecs: number;
  /**
   * The `baselineWindows` windows immediately before it, oldest first, with
   * zero-spend windows PRESENT as zeroes — see the module docblock. Windows
   * before the scope's first observed traffic are absent, not zero.
   */
  readonly baseline: readonly number[];
  /** Month-to-date PRICED spend including the window under evaluation. */
  readonly periodSpendUsd: number;
  /** `quota_policies.monthly_budget_usd`, or `undefined` when unset. */
  readonly budgetUsd?: number | undefined;
  /**
   * Seconds left in the billing period after the window under evaluation.
   *
   * Supplied rather than derived, because "the billing period" is a UTC
   * calendar month here (`periodMonthFromUnix`) and re-deriving it inside a
   * pure function would put a second, subtly different calendar in the tree.
   * Zero on the last second of a month, which correctly makes the projection
   * equal to month-to-date spend.
   */
  readonly periodRemainingSecs: number;
  readonly tuning: SpendAnomalyTuning;
}

/** Why the burn-rate leg said nothing, when it said nothing. */
export type SpendAnomalyOutcome =
  | "detected"
  | "disabled"
  | "insufficient_baseline"
  | "too_sparse"
  | "below_threshold";

export interface BurnRateDecision {
  readonly outcome: SpendAnomalyOutcome;
  readonly observedUsd: number;
  readonly baselineUsd: number;
  readonly thresholdUsd: number;
  readonly boundBy: SpendAnomalyBound;
  readonly severity?: SpendAnomalySeverity | undefined;
  readonly observedWindows: number;
  readonly activeWindows: number;
  /** `observedUsd / baselineUsd`, or `null` when the baseline is zero. */
  readonly ratio: number | null;
}

export interface ForecastDecision {
  readonly outcome: "detected" | "disabled" | "no_budget" | "too_early" | "within_budget";
  readonly projectedUsd: number;
  readonly periodSpendUsd: number;
  readonly budgetUsd: number | null;
  readonly severity?: SpendAnomalySeverity | undefined;
  /** Hours until the budget is exhausted at the observed rate, when it is. */
  readonly hoursToExhaustion: number | null;
}

// ---------------------------------------------------------------------------
// Robust statistics
// ---------------------------------------------------------------------------

/**
 * The median of a copy, ascending. Even-length takes the mean of the two middle
 * values — the conventional definition, and the one that keeps the median of
 * `[0, 0, 4, 4]` at 2 rather than silently preferring the low side and making
 * every bar half as high as intended.
 */
export function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = sorted.length >> 1;
  if (sorted.length % 2 === 1) return sorted[middle] as number;
  return ((sorted[middle - 1] as number) + (sorted[middle] as number)) / 2;
}

/** Median absolute deviation from the median. Zero for a constant series. */
export function medianAbsoluteDeviation(values: readonly number[], centre: number): number {
  if (values.length === 0) return 0;
  return median(values.map((value) => Math.abs(value - centre)));
}

// ---------------------------------------------------------------------------
// The burn-rate leg
// ---------------------------------------------------------------------------

/**
 * Evaluate one scope's last closed window against its own baseline.
 *
 * Reads NOTHING it was not given, and returns a decision that names its own
 * evidence — `baselineUsd`, `thresholdUsd`, `boundBy`, `observedWindows`,
 * `activeWindows` — because an alert whose derivation cannot be reconstructed
 * is one an operator can neither trust nor tune, and an untunable alert gets
 * muted.
 */
export function evaluateBurnRate(input: SpendAnomalyInput): BurnRateDecision {
  const { tuning, baseline, observedUsd } = input;
  const observedWindows = baseline.length;
  const activeWindows = baseline.filter((value) => value > 0).length;
  const centre = median(baseline);
  const mad = medianAbsoluteDeviation(baseline, centre);

  const silent = (outcome: SpendAnomalyOutcome, thresholdUsd = 0): BurnRateDecision => ({
    outcome,
    observedUsd,
    baselineUsd: centre,
    thresholdUsd,
    boundBy: "floor",
    observedWindows,
    activeWindows,
    ratio: centre > 0 ? observedUsd / centre : null,
  });

  if (!tuning.enabled) return silent("disabled");
  // COLD START. Not "assume zero" — see the module docblock.
  if (observedWindows < tuning.minBaselineWindows) return silent("insufficient_baseline");
  // SPARSITY. A baseline of mostly zeroes is not a distribution.
  if (activeWindows < tuning.minActiveWindows) return silent("too_sparse");

  // Three bars, each stopping a different false positive; the threshold is the
  // strictest of them, so a window has to clear all three.
  const ratioBar = centre * tuning.ratio;
  const robustBar = centre + ROBUST_BAR_SIGMAS * MAD_TO_SIGMA * mad;
  const floorBar = tuning.minWindowUsd;
  const bars: [SpendAnomalyBound, number][] = [
    ["ratio", ratioBar],
    ["robust", robustBar],
    ["floor", floorBar],
  ];
  // `reduce` rather than `Math.max` so the WINNING bar's name survives; ties go
  // to the earlier entry, which puts the operator's own knob ahead of the fixed
  // robust bar in the explanation when both agree.
  const [boundBy, thresholdUsd] = bars.reduce((best, candidate) =>
    candidate[1] > best[1] ? candidate : best,
  );

  if (!(observedUsd > thresholdUsd)) {
    return {
      outcome: "below_threshold",
      observedUsd,
      baselineUsd: centre,
      thresholdUsd,
      boundBy,
      observedWindows,
      activeWindows,
      ratio: centre > 0 ? observedUsd / centre : null,
    };
  }

  // Severity escalates on the RATIO bar only. The robust bar is a noise floor,
  // not a measure of how bad something is: a tenant with a huge MAD can clear a
  // very high robust bar with an unremarkable multiple of its own median, and
  // calling that critical would page on ordinary burstiness.
  //
  // `centre === 0` cannot reach here (it would force `ratioBar = 0`, so `floor`
  // would bind and `activeWindows >= minActiveWindows` would still have had to
  // hold) — but the guard stays, because a future tuning change that lets it
  // through must not silently produce `Infinity > criticalRatio` and page.
  const observedRatio = centre > 0 ? observedUsd / centre : null;
  const severity: SpendAnomalySeverity =
    observedRatio !== null && observedRatio >= tuning.criticalRatio ? "critical" : "warning";

  return {
    outcome: "detected",
    observedUsd,
    baselineUsd: centre,
    thresholdUsd,
    boundBy,
    severity,
    observedWindows,
    activeWindows,
    ratio: observedRatio,
  };
}

// ---------------------------------------------------------------------------
// The forecast leg
// ---------------------------------------------------------------------------

/**
 * Project month-to-date spend to the end of the billing period at the rate
 * observed in the last closed window, and compare it against the budget.
 *
 * ## The projection, spelt out
 *
 * ```
 *   remainingSecs = periodSecs * (1 - elapsedFraction)
 *   projected     = periodSpendUsd + observedUsd * (remainingSecs / observedWindowSecs)
 * ```
 *
 * `observedWindowSecs` is the width `observedUsd` was measured over, and it is
 * the ONLY window this arithmetic may use. See {@link SPEND_ANOMALY_WINDOW_SECS}.
 *
 * i.e. "keep spending exactly what you spent in the last hour, every hour,
 * until the period ends". Deliberately NOT the month-to-date AVERAGE rate: the
 * average is dominated by history and is at its most reassuring precisely when
 * a runaway has just started, which is the case this whole slice exists for.
 * The cost of that choice is that the projection is jumpy, and the cost is paid
 * by the cooldown rather than by smoothing — smoothing would reintroduce the
 * lag the average has.
 *
 * ## The guards
 *
 *  - No `budgetUsd` -> `no_budget`. There is nothing to overrun, and inventing
 *    a budget for a tenant would be alerting on a number they never set.
 *  - Month-to-date below `forecastMinPct` of the budget -> `too_early`. The
 *    first expensive request of a period otherwise extrapolates to a figure
 *    with no information in it.
 *  - `severity` is `critical` when the projection is at least twice the budget,
 *    or when the budget would be exhausted within a day at this rate — "you
 *    will overrun by 3%" and "you will burn the month by Thursday" are not the
 *    same page.
 */
export function evaluateForecast(input: SpendAnomalyInput): ForecastDecision {
  const { tuning, budgetUsd, periodSpendUsd, observedUsd } = input;
  const base = {
    projectedUsd: periodSpendUsd,
    periodSpendUsd,
    budgetUsd: budgetUsd ?? null,
    hoursToExhaustion: null,
  };
  if (!tuning.enabled) return { ...base, outcome: "disabled" };
  if (budgetUsd === undefined || !(budgetUsd > 0)) return { ...base, outcome: "no_budget" };
  if (periodSpendUsd < (budgetUsd * tuning.forecastMinPct) / 100) {
    return { ...base, outcome: "too_early" };
  }

  // Clamped at zero: a negative remainder (a clock skew, a period boundary
  // crossed mid-pass) would project spend DOWNWARD and turn an overrun into
  // silence, which is exactly the wrong direction for a failure to take.
  //
  // `observedWindowSecs`, NOT a tuning value: `observedUsd` is a sum over a
  // window of that width, so this ratio is "how many more windows like the one
  // I measured fit in the rest of the period". Dividing by anything else
  // fabricates a rate — see {@link SPEND_ANOMALY_WINDOW_SECS}.
  const remainingWindows = Math.max(input.periodRemainingSecs, 0) / input.observedWindowSecs;
  const projectedUsd = periodSpendUsd + observedUsd * remainingWindows;

  const burnRatePerHour = (observedUsd * 3_600) / input.observedWindowSecs;
  const hoursToExhaustion =
    burnRatePerHour > 0 ? Math.max(budgetUsd - periodSpendUsd, 0) / burnRatePerHour : null;

  if (!(projectedUsd > budgetUsd)) {
    return { ...base, outcome: "within_budget", projectedUsd, hoursToExhaustion };
  }

  const severity: SpendAnomalySeverity =
    projectedUsd >= budgetUsd * 2 || (hoursToExhaustion !== null && hoursToExhaustion <= 24)
      ? "critical"
      : "warning";

  return {
    ...base,
    outcome: "detected",
    projectedUsd,
    severity,
    hoursToExhaustion,
  };
}
