/**
 * REGRESSION DETECTION (#692) — the three rules, and the claim that makes a
 * sustained regression alert once instead of every cron tick.
 *
 * The sweep half runs against the REAL control D1 with the REAL migration, so
 * the aggregate SQL, the window boundaries and the `ON CONFLICT DO NOTHING`
 * arbiter are exercised by SQLite rather than asserted against a double.
 *
 * ## MUTATION LOG
 *
 * | mutation (in `src/`)                                        | red |
 * |---------------------------------------------------------------|-----|
 * | `regression.ts`: drop the `regressionMinSamples` guard         | `does not believe a drop measured on a handful of scores` |
 * | `regression.ts`: `dropAmount < drop` → `dropAmount <= drop`… nothing; `> 0` | `ignores a fall smaller than the tenant's threshold` |
 * | `d1.ts`: `ON CONFLICT (claim_key) DO NOTHING` removed          | `claims a regression once per window` (the second sweep claimed again) |
 */
import { beforeEach, describe, expect, it } from "vitest";

import {
  ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL,
  type OnlineEvalWindowAggregate,
  RECENT_WINDOW_SECONDS,
  detectOnlineEvalRegressions,
  onlineEvalScoreProjectionBindings,
  sweepOnlineEvalRegressions,
} from "../../src/evals/index.js";
import { controlDb, resetOnlineEvalTables, storedRegressions } from "./harness.js";

const POLICY = { regressionDrop: 0.1, regressionMinSamples: 20 };

function aggregate(overrides: Partial<OnlineEvalWindowAggregate> = {}): OnlineEvalWindowAggregate {
  return {
    tenantId: "tenant_a",
    criterionId: "answer_relevance",
    judgeModel: "judge-model",
    logicalModel: "gpt-4o-mini",
    // 0.9 mean over 40 scores, then 0.6 over 40 — a real drop.
    baselineTotal: 36,
    baselineCount: 40,
    recentTotal: 24,
    recentCount: 40,
    ...overrides,
  };
}

describe("the detector believes only what the instrument supports", () => {
  it("reports a drop past the tenant's threshold with the numbers behind it", () => {
    expect(detectOnlineEvalRegressions([aggregate()], POLICY)).toEqual([
      {
        tenantId: "tenant_a",
        criterionId: "answer_relevance",
        judgeModel: "judge-model",
        logicalModel: "gpt-4o-mini",
        baselineMean: 0.9,
        baselineCount: 40,
        recentMean: 0.6,
        recentCount: 40,
        dropAmount: expect.closeTo(0.3, 10) as unknown as number,
      },
    ]);
  });

  it("ignores a fall smaller than the tenant's threshold", () => {
    // 0.9 → 0.85 is a 0.05 fall against a 0.1 threshold.
    const small = aggregate({ recentTotal: 34, recentCount: 40 });
    expect(detectOnlineEvalRegressions([small], POLICY)).toEqual([]);
  });

  it("does not believe a drop measured on a handful of scores", () => {
    // A judge is noisy per item: a mean over five samples moves 0.2 on its own,
    // so without this guard every quiet tenant would alert constantly.
    const thin = aggregate({ recentTotal: 1, recentCount: 2 });
    expect(detectOnlineEvalRegressions([thin], POLICY)).toEqual([]);
  });

  it("says nothing about a group with no baseline", () => {
    // A model that only appeared in the recent window has nothing to be
    // compared against; calling that a regression would page someone every
    // time a new model was added.
    const fresh = aggregate({ baselineTotal: 0, baselineCount: 0 });
    expect(detectOnlineEvalRegressions([fresh], POLICY)).toEqual([]);
  });

  it("never compares across judges or criteria", () => {
    // Two groups that differ only by judge; one regressed and one did not. A
    // detector that pooled them would report neither, or both, depending on
    // the arithmetic — and both answers would be wrong.
    const regressed = aggregate({ judgeModel: "judge-a" });
    const steady = aggregate({ judgeModel: "judge-b", recentTotal: 36, recentCount: 40 });
    const found = detectOnlineEvalRegressions([regressed, steady], POLICY);
    expect(found.map((r) => r.judgeModel)).toEqual(["judge-a"]);
  });
});

const NOW_UNIX = 1_800_000_000;

/** Insert `count` scores at `atUnix` with the given score value. */
async function seedScores(count: number, score: number, atUnix: number): Promise<void> {
  const db = controlDb();
  const statement = db.prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL);
  await db.batch(
    Array.from({ length: count }, (_, index) =>
      statement.bind(
        ...onlineEvalScoreProjectionBindings({
          requestId: `fg-${atUnix}-${index}`,
          tenantId: "tenant_a",
          criterionId: "answer_relevance",
          score,
          judgeModel: "judge-model",
          logicalModel: "gpt-4o-mini",
          samplingKey: `fg-${atUnix}-${index}`,
          samplingUnit: "request",
          sampleRate: 1,
          promptTruncated: false,
          completionTruncated: false,
          scoredAtUnix: atUnix,
        }),
      ),
    ),
  );
}

beforeEach(async () => {
  await resetOnlineEvalTables();
});

describe("the sweep, against the real schema", () => {
  it("records a regression once per window, with its evidence", async () => {
    // Baseline: 40 scores of 0.9, three days ago. Recent: 40 of 0.6, an hour
    // ago. The window split is the sweep's, not the test's.
    await seedScores(40, 0.9, NOW_UNIX - 3 * 24 * 60 * 60);
    await seedScores(40, 0.6, NOW_UNIX - 3600);

    const first = await sweepOnlineEvalRegressions(
      {},
      "tenant_a",
      POLICY,
      NOW_UNIX,
      () => controlDb() as never,
    );
    expect(first).toEqual({ detected: 1, claimed: 1 });

    const rows = await storedRegressions();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      tenant: "tenant_a",
      criterion_id: "answer_relevance",
      judge_model: "judge-model",
      logical_model: "gpt-4o-mini",
      baseline_count: 40,
      recent_count: 40,
    });
    expect(Number(rows[0]?.["drop_amount"])).toBeCloseTo(0.3, 6);
    expect(String(rows[0]?.["claim_key"])).toContain(String(NOW_UNIX - RECENT_WINDOW_SECONDS));

    // The SECOND sweep sees the same regression — it has not gone away — and
    // must not record it again. Without the claim an operator gets one alert
    // per cron tick for as long as the regression lasts.
    const second = await sweepOnlineEvalRegressions(
      {},
      "tenant_a",
      POLICY,
      NOW_UNIX,
      () => controlDb() as never,
    );
    expect(second).toEqual({ detected: 1, claimed: 0 });
    expect(await storedRegressions()).toHaveLength(1);
  });

  it("records nothing when quality held", async () => {
    await seedScores(40, 0.9, NOW_UNIX - 3 * 24 * 60 * 60);
    await seedScores(40, 0.88, NOW_UNIX - 3600);

    const result = await sweepOnlineEvalRegressions(
      {},
      "tenant_a",
      POLICY,
      NOW_UNIX,
      () => controlDb() as never,
    );

    expect(result).toEqual({ detected: 0, claimed: 0 });
    expect(await storedRegressions()).toEqual([]);
  });

  it("does not read another tenant's scores", async () => {
    await seedScores(40, 0.9, NOW_UNIX - 3 * 24 * 60 * 60);
    await seedScores(40, 0.6, NOW_UNIX - 3600);

    const result = await sweepOnlineEvalRegressions(
      {},
      "tenant_b",
      POLICY,
      NOW_UNIX,
      () => controlDb() as never,
    );

    expect(result).toEqual({ detected: 0, claimed: 0 });
  });
});
