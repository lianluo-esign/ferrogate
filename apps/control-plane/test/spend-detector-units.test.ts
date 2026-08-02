/**
 * THE DETECTOR'S ARITHMETIC (#697), as pure unit tests.
 *
 * `test/spend-anomaly.test.ts` drives the whole thing through the real cron
 * tick against real D1. This file is the other half: the decisions themselves,
 * where a case can be stated in three lines instead of seeded as a day of
 * traffic.
 *
 * ## Most of it pins what the detector CANNOT do
 *
 * `src/finops/detector.ts` and `sql/d1-ts/control/0010_spend_anomaly.sql` both
 * claim, in prose, that this detector is blind to a runaway that predates its
 * baseline, to a slow creep, and to a burst shorter than its window. Those
 * claims are the honest part of the feature and they are what stops an operator
 * buying the wrong instrument — so they are ASSERTED here rather than left as
 * comments that a later change could quietly falsify. A limitation nothing
 * tests is a limitation that becomes a surprise.
 */
import { describe, expect, it } from "vitest";
import {
  SPEND_ANOMALY_DEFAULTS,
  type SpendAnomalyInput,
  type SpendAnomalyTuning,
  evaluateBurnRate,
  evaluateForecast,
  median,
  medianAbsoluteDeviation,
} from "../src/finops/detector.js";

const HOUR = 3_600;

function input(over: Partial<SpendAnomalyInput> = {}): SpendAnomalyInput {
  return {
    scopeType: "tenant",
    scopeId: "t",
    windowStartUnix: 0,
    observedUsd: 0,
    baseline: [],
    periodSpendUsd: 0,
    periodRemainingSecs: 15 * 24 * HOUR,
    tuning: SPEND_ANOMALY_DEFAULTS,
    ...over,
  };
}

function tuned(over: Partial<SpendAnomalyTuning>): SpendAnomalyTuning {
  return { ...SPEND_ANOMALY_DEFAULTS, ...over };
}

/** A flat baseline of `usd` across `n` windows. */
const flat = (usd: number, n = 24): number[] => Array.from({ length: n }, () => usd);

describe("robust statistics", () => {
  it("takes the mean of the two middle values on an even-length series", () => {
    // Not the low side. Preferring it would make every ratio bar derived from
    // an even baseline lower than intended, i.e. the detector louder than its
    // configuration says.
    expect(median([0, 0, 4, 4])).toBe(2);
    expect(median([1, 2, 3])).toBe(2);
    expect(median([])).toBe(0);
  });

  it("is unmoved by an outlier that would drag a mean", () => {
    const series = [...flat(2, 23), 200];
    expect(median(series)).toBe(2);
    expect(medianAbsoluteDeviation(series, 2)).toBe(0);
    // The mean of the same series is 10.25 — a 5x difference, and the whole
    // reason the baseline is not a mean.
    expect(series.reduce((a, b) => a + b, 0) / series.length).toBeCloseTo(10.25, 2);
  });
});

describe("the three bars", () => {
  it("reports WHICH bar bound, so a false positive has a knob attached", () => {
    // Flat $2 baseline: ratio bar $8, robust bar $2 (MAD is 0), floor $1.
    const ratioBound = evaluateBurnRate(input({ observedUsd: 80, baseline: flat(2) }));
    expect(ratioBound.outcome).toBe("detected");
    expect(ratioBound.boundBy).toBe("ratio");
    expect(ratioBound.thresholdUsd).toBeCloseTo(8, 6);

    // A tenant whose normal IS spiky: alternating $1/$40. Its MAD is large, so
    // the robust bar is far above 4x the median and a $60 hour says nothing.
    const spiky = Array.from({ length: 24 }, (_, i) => (i % 2 === 0 ? 1 : 40));
    const bursty = evaluateBurnRate(input({ observedUsd: 60, baseline: spiky }));
    expect(bursty.outcome).toBe("below_threshold");
    expect(bursty.boundBy).toBe("robust");

    // Pennies: the floor is the binding bar and a 40x spike is silent.
    const pennies = evaluateBurnRate(input({ observedUsd: 0.8, baseline: flat(0.02) }));
    expect(pennies.outcome).toBe("below_threshold");
    expect(pennies.boundBy).toBe("floor");
  });

  it("escalates on the RATIO, not on the robust bar", () => {
    // A high MAD can be cleared by an unremarkable multiple of the median, and
    // paging `critical` for ordinary burstiness is how a channel gets muted.
    const warning = evaluateBurnRate(input({ observedUsd: 12, baseline: flat(2) }));
    expect(warning.severity).toBe("warning");
    const critical = evaluateBurnRate(input({ observedUsd: 25, baseline: flat(2) }));
    expect(critical.severity).toBe("critical");
  });
});

describe("cold start and sparsity are DECIDED, not left to the arithmetic", () => {
  it("is silent with too little history, rather than dividing by a zero median", () => {
    const decision = evaluateBurnRate(input({ observedUsd: 500, baseline: flat(1, 3) }));
    expect(decision.outcome).toBe("insufficient_baseline");
    expect(decision.severity).toBeUndefined();
  });

  it("is silent for a baseline that is mostly zeroes", () => {
    // 24 observed windows, 3 of them non-zero: the count gate passes and the
    // SPARSITY gate is what catches it. Without the second gate the median is 0,
    // the MAD is 0, every bar collapses to 0 and this fires forever.
    const sparse = [...flat(0, 21), 0.4, 0.4, 0.4];
    const decision = evaluateBurnRate(input({ observedUsd: 12, baseline: sparse }));
    expect(decision.outcome).toBe("too_sparse");
    expect(decision.baselineUsd).toBe(0);
    expect(decision.activeWindows).toBe(3);
  });

  it("counts a zero-spend window as OBSERVED but not as ACTIVE", () => {
    const decision = evaluateBurnRate(
      input({ observedUsd: 12, baseline: [...flat(0, 18), ...flat(3, 6)] }),
    );
    expect(decision.observedWindows).toBe(24);
    expect(decision.activeWindows).toBe(6);
  });

  it("honours an operator who explicitly accepts the noise", () => {
    // `min_active_windows = 0` is a real configuration, and `nonNegativeInt` in
    // `policy.ts` exists so it is not collapsed into the default.
    const sparse = [...flat(0, 21), 0.4, 0.4, 40];
    const decision = evaluateBurnRate(
      input({ observedUsd: 60, baseline: sparse, tuning: tuned({ minActiveWindows: 0 }) }),
    );
    expect(decision.outcome).toBe("detected");
  });
});

describe("what this detector CANNOT catch — asserted, not just documented", () => {
  it("is blind to a runaway that was already running when the baseline was taken", () => {
    // The loop has been burning $80/hour for over a day. That IS the baseline
    // now, so deviation-from-self says nothing — structurally, not by accident.
    const decision = evaluateBurnRate(input({ observedUsd: 80, baseline: flat(80) }));
    expect(decision.outcome).toBe("below_threshold");

    // …and the forecast leg is the ONLY backstop, which is why it exists.
    const forecast = evaluateForecast(
      input({ observedUsd: 80, periodSpendUsd: 2_000, budgetUsd: 5_000 }),
    );
    expect(forecast.outcome).toBe("detected");
  });

  it("is blind to a slow creep", () => {
    // 5% per window, compounding: 24 windows later the rate has more than
    // tripled, and no single window ever deviates from its own recent past.
    const creep = Array.from({ length: 24 }, (_, i) => 2 * 1.05 ** i);
    const observed = 2 * 1.05 ** 24;
    expect(evaluateBurnRate(input({ observedUsd: observed, baseline: creep })).outcome).toBe(
      "below_threshold",
    );
  });

  it("cannot see a burst shorter than the window inside a busy one", () => {
    // $400 spent in one minute of a $2,000 hour is $2,400 for that hour, which
    // is 1.2x a $2,000 baseline and nothing at all to the ratio bar.
    const decision = evaluateBurnRate(input({ observedUsd: 2_400, baseline: flat(2_000) }));
    expect(decision.outcome).toBe("below_threshold");
  });

  it("says nothing when a tenant opted out", () => {
    const decision = evaluateBurnRate(
      input({ observedUsd: 80, baseline: flat(2), tuning: tuned({ enabled: false }) }),
    );
    expect(decision.outcome).toBe("disabled");
  });
});

describe("the forecast leg", () => {
  it("projects the CURRENT rate, not the month-to-date average", () => {
    // Half a month gone, $100 spent, and the last hour was $50. The average
    // rate says "on track"; the current rate says "you will spend $18,100".
    // The average is at its most reassuring exactly when a runaway has just
    // started, which is the case this whole slice exists for.
    const decision = evaluateForecast(
      input({
        observedUsd: 50,
        periodSpendUsd: 100,
        budgetUsd: 1_000,
        periodRemainingSecs: 15 * 24 * HOUR,
      }),
    );
    expect(decision.outcome).toBe("detected");
    expect(decision.projectedUsd).toBeCloseTo(100 + 50 * 360, 6);
    expect(decision.severity).toBe("critical");
  });

  it("refuses to speak about the first expensive request of a period", () => {
    // $40 against a $100,000 budget projects to a large number with no
    // information in it — the "your $3 lunch projects to $90,000/year" error.
    const decision = evaluateForecast(
      input({ observedUsd: 40, periodSpendUsd: 40, budgetUsd: 100_000 }),
    );
    expect(decision.outcome).toBe("too_early");
  });

  it("has nothing to say without a budget", () => {
    const decision = evaluateForecast(input({ observedUsd: 500, periodSpendUsd: 5_000 }));
    expect(decision.outcome).toBe("no_budget");
    expect(decision.budgetUsd).toBeNull();
  });

  it("never projects DOWNWARD when the period boundary is already past", () => {
    // A clock skew or a boundary crossed mid-pass must not turn an overrun into
    // silence — the clamp is the difference between a late alert and none.
    const decision = evaluateForecast(
      input({
        observedUsd: 500,
        periodSpendUsd: 900,
        budgetUsd: 1_000,
        periodRemainingSecs: -100_000,
      }),
    );
    expect(decision.projectedUsd).toBe(900);
    expect(decision.outcome).toBe("within_budget");
  });

  it("warns rather than pages on a modest overrun far from exhaustion", () => {
    // "You will overrun by 3%" and "you burn the month by Thursday" are not the
    // same page.
    const decision = evaluateForecast(
      input({
        observedUsd: 1,
        periodSpendUsd: 900,
        budgetUsd: 1_000,
        periodRemainingSecs: 15 * 24 * HOUR,
      }),
    );
    expect(decision.outcome).toBe("detected");
    expect(decision.severity).toBe("warning");
    expect(decision.hoursToExhaustion).toBeCloseTo(100, 6);
  });
});
