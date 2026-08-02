/**
 * The EXPERIMENT half of the rollout primitive (#693): arm identity, and the
 * comparison of two arms' outcomes.
 *
 * ## What is actually being held here
 *
 * `rollout.ts` splits traffic. Nothing in this repository could say whether the
 * split was any GOOD, and the reason is that a quality comparison is only valid
 * under conditions a report can silently violate:
 *
 *  1. both arms scored by the SAME judge under the SAME criterion;
 *  2. enough samples in BOTH arms for a mean to mean anything;
 *  3. a difference large enough, relative to the spread, to be believed.
 *
 * Every case below exists because breaking one of those three produces a
 * plausible number that an operator would act on. The dangerous failure is not
 * an error — it is a green dashboard reading "canary +0.14" computed by
 * averaging two different instruments.
 */
import { describe, expect, it } from "vitest";
import {
  type ArmScoreAggregate,
  compareExperimentQuality,
  experimentIdFor,
  summariseArmOperations,
} from "../src/experiment.js";

const CONTROL = { provider: "openai", providerModel: "gpt-4o-mini" };
const CANARY = { provider: "anthropic", providerModel: "claude-3-5-haiku" };

/**
 * `n` scores whose mean is `mean` and whose sample variance is `variance`,
 * expressed as the three sufficient statistics the aggregate carries. Built
 * arithmetically rather than from a list so a case can ask for a spread
 * directly.
 */
function aggregate(
  arm: ArmScoreAggregate["arm"],
  options: {
    n: number;
    mean: number;
    variance?: number;
    judgeModel?: string;
    criterionId?: string;
  },
): ArmScoreAggregate {
  const { n, mean } = options;
  const variance = options.variance ?? 0;
  // Σx² = (n-1)·s² + n·x̄²  — the inverse of the sample-variance formula.
  const totalSquares = (n - 1) * variance + n * mean * mean;
  return {
    arm,
    judgeModel: options.judgeModel ?? "judge-a",
    criterionId: options.criterionId ?? "helpfulness",
    count: n,
    total: n * mean,
    totalSquares,
  };
}

describe("experimentIdFor", () => {
  it("is stable for the same split and different for a different variant", () => {
    const a = experimentIdFor({
      logicalModel: "gpt-4o-mini",
      control: CONTROL,
      canary: CANARY,
    });
    const again = experimentIdFor({
      logicalModel: "gpt-4o-mini",
      control: CONTROL,
      canary: CANARY,
    });
    const moved = experimentIdFor({
      logicalModel: "gpt-4o-mini",
      control: CONTROL,
      canary: { provider: "anthropic", providerModel: "claude-3-5-sonnet" },
    });
    expect(a).not.toBeNull();
    expect(again).toBe(a);
    expect(moved).not.toBe(a);
  });

  it("changes when the CONTROL moves, so the old population is never pooled with the new", () => {
    const before = experimentIdFor({
      logicalModel: "gpt-4o-mini",
      control: CONTROL,
      canary: CANARY,
    });
    const after = experimentIdFor({
      logicalModel: "gpt-4o-mini",
      control: { provider: "openai", providerModel: "gpt-4o" },
      canary: CANARY,
    });
    expect(after).not.toBe(before);
  });

  it("is null when no variant is declared — a model with no split is not an experiment", () => {
    expect(experimentIdFor({ logicalModel: "gpt-4o-mini", control: CONTROL })).toBeNull();
  });
});

describe("compareExperimentQuality", () => {
  it("REFUSES to compare arms scored by different judges", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 200, mean: 0.7, variance: 0.04, judgeModel: "judge-a" }),
        aggregate("canary", { n: 200, mean: 0.9, variance: 0.04, judgeModel: "judge-b" }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );

    // No comparable cell at all — and both one-sided cells are reported as
    // incomparable rather than dropped, so the surface can SAY why.
    expect(report.cells).toHaveLength(0);
    expect(report.incomparable).toHaveLength(2);
    expect(report.incomparable.map((cell) => cell.reason).sort()).toEqual([
      "control_arm_not_scored",
      "variant_arm_not_scored",
    ]);
    expect(report.judgeMismatch).toBe(true);
    // And nothing anywhere in the report carries a difference.
    expect(JSON.stringify(report)).not.toContain("difference");
  });

  it("REFUSES to compare arms scored under different criteria", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 200, mean: 0.7, variance: 0.04, criterionId: "helpfulness" }),
        aggregate("canary", { n: 200, mean: 0.9, variance: 0.04, criterionId: "helpfulnes" }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    expect(report.cells).toHaveLength(0);
    expect(report.incomparable).toHaveLength(2);
    expect(report.criterionMismatch).toBe(true);
  });

  it("compares within a shared (judge, criterion) and refuses the unshared one in the SAME input", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 200, mean: 0.7, variance: 0.04, criterionId: "helpfulness" }),
        aggregate("canary", { n: 200, mean: 0.9, variance: 0.04, criterionId: "helpfulness" }),
        aggregate("control", { n: 200, mean: 0.5, variance: 0.04, criterionId: "tone" }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    expect(report.cells.map((cell) => cell.criterionId)).toEqual(["helpfulness"]);
    expect(report.incomparable.map((cell) => cell.criterionId)).toEqual(["tone"]);
  });

  it("reports NO NUMBER when either arm is below the sample floor", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 400, mean: 0.7, variance: 0.04 }),
        aggregate("canary", { n: 2, mean: 0.95, variance: 0.04 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );

    expect(report.cells).toHaveLength(1);
    const cell = report.cells[0];
    expect(cell?.verdict).toBe("insufficient_samples");
    // Sample sizes ARE reported — that is what tells the operator to wait.
    expect(cell?.control.count).toBe(400);
    expect(cell?.variant.count).toBe(2);
    // The MEANS are not, on either side. A UI cannot render "0.95 vs 0.70" from
    // this object, which is the point: two requests per arm is not a result,
    // and a number on a screen will be acted on however it is captioned.
    expect(cell?.control.mean).toBeUndefined();
    expect(cell?.variant.mean).toBeUndefined();
    expect(cell?.difference).toBeUndefined();
    expect(cell?.pValue).toBeUndefined();
  });

  it("calls a large, low-variance improvement for the variant", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 300, mean: 0.6, variance: 0.02 }),
        aggregate("canary", { n: 300, mean: 0.78, variance: 0.02 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    const cell = report.cells[0];
    expect(cell?.verdict).toBe("variant_better");
    expect(cell?.difference).toBeCloseTo(0.18, 6);
    expect(cell?.pValue).toBeLessThan(0.001);
  });

  it("calls a large, low-variance regression for the control", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 300, mean: 0.78, variance: 0.02 }),
        aggregate("canary", { n: 300, mean: 0.6, variance: 0.02 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    expect(report.cells[0]?.verdict).toBe("control_better");
  });

  it("refuses to call a difference that the spread does not support", () => {
    // Same 0.03 gap, variance an order of magnitude wider than the low-variance
    // case above. Above the sample floor on both sides, so the means ARE shown
    // — but the verdict says the data does not support acting on them.
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 40, mean: 0.6, variance: 0.09 }),
        aggregate("canary", { n: 40, mean: 0.63, variance: 0.09 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    const cell = report.cells[0];
    expect(cell?.verdict).toBe("no_measured_difference");
    expect(cell?.control.mean).toBeCloseTo(0.6, 6);
    expect(cell?.pValue).toBeGreaterThan(0.05);
  });

  it("does not call a zero-variance tie a win in either direction", () => {
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 50, mean: 0.8, variance: 0 }),
        aggregate("canary", { n: 50, mean: 0.8, variance: 0 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    expect(report.cells[0]?.verdict).toBe("no_measured_difference");
  });

  it("compares the SHADOW arm against the control on the same terms", () => {
    const report = compareExperimentQuality(
      "shadow",
      [
        aggregate("control", { n: 300, mean: 0.6, variance: 0.02 }),
        aggregate("shadow", { n: 300, mean: 0.78, variance: 0.02 }),
        // A canary arm in the same table must not be mistaken for the variant
        // under comparison, nor pooled into the control.
        aggregate("canary", { n: 300, mean: 0.1, variance: 0.02 }),
      ],
      { minSamples: 30, alpha: 0.05 },
    );
    expect(report.cells).toHaveLength(1);
    expect(report.cells[0]?.variant.arm).toBe("shadow");
    expect(report.cells[0]?.verdict).toBe("variant_better");
    expect(report.cells[0]?.difference).toBeCloseTo(0.18, 6);
  });

  it("holds the t-test against a textbook two-sample value", () => {
    // Welch's t for x̄=0.5,s²=0.01,n=25 vs x̄=0.6,s²=0.01,n=25:
    //   se = sqrt(0.01/25 + 0.01/25) = 0.0282842712...
    //   t  = 0.1 / se = 3.5355339...   df = 48
    // Two-sided p for |t|=3.5355 at df=48 is ~0.00092.
    const report = compareExperimentQuality(
      "canary",
      [
        aggregate("control", { n: 25, mean: 0.5, variance: 0.01 }),
        aggregate("canary", { n: 25, mean: 0.6, variance: 0.01 }),
      ],
      { minSamples: 10, alpha: 0.05 },
    );
    expect(report.cells[0]?.pValue).toBeCloseTo(0.00092, 4);
  });
});

describe("summariseArmOperations", () => {
  it("charges a served arm to the tenant and a shadow arm to the operator", () => {
    const summaries = summariseArmOperations([
      {
        arm: "control",
        requests: 100,
        failures: 3,
        latencyTotalMs: 120_000,
        costUsdTotal: 1.5,
      },
      { arm: "canary", requests: 10, failures: 1, latencyTotalMs: 9_000, costUsdTotal: 0.2 },
      { arm: "shadow", requests: 10, failures: 0, latencyTotalMs: 7_000, costUsdTotal: 0.25 },
    ]);

    const byArm = new Map(summaries.map((summary) => [summary.arm, summary]));
    expect(byArm.get("control")?.chargedTo).toBe("tenant");
    expect(byArm.get("canary")?.chargedTo).toBe("tenant");
    // The customer never saw the shadow response and never asked for the second
    // provider. Billing them for the operator's measurement would be charging
    // for an experiment they did not run.
    expect(byArm.get("shadow")?.chargedTo).toBe("operator");
    expect(byArm.get("shadow")?.delivered).toBe(false);
    expect(byArm.get("control")?.delivered).toBe(true);

    expect(byArm.get("control")?.errorRate).toBeCloseTo(0.03, 6);
    expect(byArm.get("control")?.meanLatencyMs).toBeCloseTo(1200, 6);
    expect(byArm.get("canary")?.costUsd).toBeCloseTo(0.2, 6);
  });

  it("reports no rate and no mean latency for an arm with no requests", () => {
    const [summary] = summariseArmOperations([
      { arm: "canary", requests: 0, failures: 0, latencyTotalMs: 0, costUsdTotal: 0 },
    ]);
    expect(summary?.requests).toBe(0);
    // 0/0 is not 0. An arm that served nothing has no error rate, and printing
    // "0% errors" for it reads as a healthy arm.
    expect(summary?.errorRate).toBeUndefined();
    expect(summary?.meanLatencyMs).toBeUndefined();
  });
});
