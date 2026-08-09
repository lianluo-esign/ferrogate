/**
 * #894 — the per-PROVIDER-LEG quality aggregate, its RELATIVE comparator, and
 * the memo the router reads it through.
 *
 * The aggregate half runs against the REAL control D1 with the REAL migration
 * (`sql/d1-ts/control/0026_online_eval_leg_quality.sql`), so the finer `GROUP
 * BY`, the upsert's conflict target and the prune are exercised by SQLite rather
 * than asserted against a double. The router half runs in the gateway isolate
 * and asserts the thing the issue actually asks for: after a warm, the answer is
 * available SYNCHRONOUSLY.
 *
 * ## MUTATION LOG
 *
 * Every row below was applied to the tree, run, and reverted.
 *
 * | mutation (in `src/`)                                                        | red |
 * |------------------------------------------------------------------------------|-----|
 * | `leg-quality.ts`: `GROUP BY … provider, provider_model` → the old ladder-only grouping | `separates the two provider legs of one logical model` (1 row instead of 2) |
 * | `leg-quality.ts`: `scoreCount >= regressionMinSamples` → `> 0`                 | `is silent about a leg with too few samples` |
 * | `leg-quality.ts`: `dropAmount >= regressionDrop` → `dropAmount > 0`            | `says nothing when the legs are within the tenant's threshold` |
 * | `quality-source.ts`: cache the resolution unconditionally (drop `if (resolved.ok)`) | `never caches a failure` |
 * | `strategy.ts`: `demoteLaggingLegs` returns `ordered` unchanged                 | `moves a lagging leg behind its comparable sibling` |
 */
import { beforeEach, describe, expect, it } from "vitest";
import { controlNamespace } from "../support/control-namespace.js";

import {
  DEFAULT_REGRESSION_DROP,
  DEFAULT_REGRESSION_MIN_SAMPLES,
  LEG_QUALITY_WINDOW_SECONDS,
  ONLINE_EVAL_LEG_QUALITY_TABLE,
  ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL,
  type OnlineEvalLegAggregate,
  type OnlineEvalPolicySource,
  cachedOnlineEvalLegQualitySource,
  d1OnlineEvalLegQualitySource,
  legQualityKey,
  legQualityVerdicts,
  onlineEvalLegAggregates,
  onlineEvalScoreProjectionBindings,
  readOnlineEvalLegQuality,
  refreshOnlineEvalLegQuality,
  routingQualityPortFor,
  routingQualityPortFrom,
  sweepAllOnlineEvalRegressions,
  writeOnlineEvalLegQuality,
} from "../../src/evals/index.js";
import type { PhysicalRoute } from "../../src/inference/ports.js";
import { NO_ROUTING_QUALITY, orderCandidatesByStrategy } from "../../src/inference/strategy.js";
import { controlDb, resetOnlineEvalTables } from "./harness.js";

const TENANT = "tenant_a";
const NOW_UNIX = 1_800_000_000;
const POLICY = {
  regressionDrop: DEFAULT_REGRESSION_DROP,
  regressionMinSamples: DEFAULT_REGRESSION_MIN_SAMPLES,
};

/** The `GATEWAY_ONLINE_EVAL_POLICIES` wire row for {@link TENANT}. */
const OPT_IN_ROW = {
  enabled: true,
  sample_rate: 1,
  judge_model: "judge-model",
  criteria: [{ id: "grounded", definition: "grounded?" }],
} as const;

function aggregate(overrides: Partial<OnlineEvalLegAggregate> = {}): OnlineEvalLegAggregate {
  return {
    tenantId: TENANT,
    criterionId: "grounded",
    judgeModel: "judge-model",
    logicalModel: "split-model",
    provider: "openai-main",
    providerModel: "gpt-4o-mini",
    scoreTotal: 18,
    scoreCount: 20,
    ...overrides,
  };
}

/** Seed `count` scores for one LEG of one ladder. */
async function seedLeg(input: {
  readonly provider: string;
  readonly providerModel: string;
  readonly count: number;
  readonly score: number;
  readonly atUnix?: number;
  readonly criterionId?: string;
  /** `undefined` = the SERVED arm; `"coverage"` / `"shadow"` are the mirrors. */
  readonly arm?: string;
}): Promise<void> {
  const db = controlDb();
  const statement = db.prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL);
  const atUnix = input.atUnix ?? NOW_UNIX - 3600;
  const criterionId = input.criterionId ?? "grounded";
  await db.batch(
    Array.from({ length: input.count }, (_, index) =>
      statement.bind(
        ...onlineEvalScoreProjectionBindings({
          requestId: `fg-${input.provider}-${criterionId}-${atUnix}-${index}`,
          tenantId: TENANT,
          criterionId,
          score: input.score,
          judgeModel: "judge-model",
          provider: input.provider,
          logicalModel: "split-model",
          providerModel: input.providerModel,
          ...(input.arm === undefined ? {} : { experimentArm: input.arm }),
          samplingKey: `fg-${input.provider}-${index}`,
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

/** `legQualityKey`'s spelling, so a test never hand-rolls the NUL separator. */
function key(
  provider: string,
  providerModel = "gpt-4o-mini",
  logicalModel = "split-model",
): string {
  return legQualityKey(logicalModel, provider, providerModel);
}

async function storedLegQuality(): Promise<Record<string, unknown>[]> {
  const result = await controlDb()
    .prepare(`SELECT * FROM ${ONLINE_EVAL_LEG_QUALITY_TABLE} ORDER BY provider, criterion_id`)
    .all();
  return result.results as Record<string, unknown>[];
}

beforeEach(async () => {
  await resetOnlineEvalTables();
  await controlDb().prepare(`DELETE FROM ${ONLINE_EVAL_LEG_QUALITY_TABLE}`).run();
});

// ---------------------------------------------------------------------------
// The aggregate, against the real schema
// ---------------------------------------------------------------------------

describe("the per-leg aggregate, against the real schema", () => {
  it("separates the two provider legs of one logical model", async () => {
    // THE DEFECT THIS FILE EXISTS FOR. `ONLINE_EVAL_WINDOW_AGGREGATE_SQL` groups
    // by `logical_model`, which both of these share, so it produces ONE row and
    // the router cannot tell the legs apart.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await seedLeg({ provider: "azure-eu", providerModel: "gpt-4o-mini", count: 20, score: 0.5 });

    const rows = await onlineEvalLegAggregates(controlDb(), TENANT, NOW_UNIX);
    expect(rows).toHaveLength(2);
    const byProvider = new Map(rows.map((row) => [row.provider, row]));
    expect(byProvider.get("openai-main")?.scoreCount).toBe(20);
    expect(byProvider.get("openai-main")?.scoreTotal).toBeCloseTo(18, 6);
    expect(byProvider.get("azure-eu")?.scoreCount).toBe(20);
    expect(byProvider.get("azure-eu")?.scoreTotal).toBeCloseTo(10, 6);
    // Both legs are the SAME ladder — that is what makes them comparable at all.
    expect(new Set(rows.map((row) => row.logicalModel))).toEqual(new Set(["split-model"]));
  });

  it("excludes a score whose leg cannot be identified", async () => {
    // A row with no provider is not a leg anybody can route to, and grouping it
    // as a phantom `NULL` leg would give the router a candidate that does not
    // exist.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 5, score: 0.9 });
    const db = controlDb();
    await db
      .prepare(ONLINE_EVAL_SCORE_PROJECTION_UPSERT_SQL)
      .bind(
        ...onlineEvalScoreProjectionBindings({
          requestId: "fg-unattributed",
          tenantId: TENANT,
          criterionId: "grounded",
          score: 0.1,
          judgeModel: "judge-model",
          samplingKey: "fg-unattributed",
          samplingUnit: "request",
          sampleRate: 1,
          promptTruncated: false,
          completionTruncated: false,
          scoredAtUnix: NOW_UNIX - 3600,
        }),
      )
      .run();

    const rows = await onlineEvalLegAggregates(controlDb(), TENANT, NOW_UNIX);
    expect(rows.map((row) => row.provider)).toEqual(["openai-main"]);
  });

  it("ignores scores older than the window", async () => {
    await seedLeg({
      provider: "openai-main",
      providerModel: "gpt-4o-mini",
      count: 20,
      score: 0.9,
      atUnix: NOW_UNIX - LEG_QUALITY_WINDOW_SECONDS - 1,
    });
    expect(await onlineEvalLegAggregates(controlDb(), TENANT, NOW_UNIX)).toEqual([]);
  });

  it("replaces rather than accumulates when a batch is redelivered", async () => {
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    const refresh = (): Promise<number> =>
      refreshOnlineEvalLegQuality(
        {},
        TENANT,
        NOW_UNIX,
        () => controlDb() as never,
        () => undefined,
      );

    expect(await refresh()).toBe(1);
    expect(await refresh()).toBe(1);

    const rows = await storedLegQuality();
    // A second refresh that ACCUMULATED would show 40 here, and every mean the
    // router reads would be computed over doubled rows.
    expect(rows).toHaveLength(1);
    expect(rows[0]?.score_count).toBe(20);
    expect(rows[0]?.score_total).toBeCloseTo(18, 6);
  });

  it("prunes a cell whose scores have all aged out, beside a live one", async () => {
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await writeOnlineEvalLegQuality(
      controlDb(),
      TENANT,
      await onlineEvalLegAggregates(controlDb(), TENANT, NOW_UNIX),
      NOW_UNIX,
    );
    expect(await storedLegQuality()).toHaveLength(1);

    // A week later the scores are outside the window, so the recompute produces
    // nothing for `openai-main` — and the stale cell must go rather than steer
    // the router for ever on a number nobody can reproduce.
    const later = NOW_UNIX + LEG_QUALITY_WINDOW_SECONDS + 10;
    await writeOnlineEvalLegQuality(
      controlDb(),
      TENANT,
      [aggregate({ provider: "azure-eu" })],
      later,
    );
    expect((await storedLegQuality()).map((row) => row.provider)).toEqual(["azure-eu"]);
  });

  it("prunes the LAST cell when the tenant's whole aggregate ages out", async () => {
    // THE CASE THE TEST ABOVE CANNOT REACH, and the one that matters most: a
    // tenant who turned evaluation off or went quiet. The recompute is EMPTY,
    // so a prune appended only `if (aggregates.length > 0)` never runs and the
    // last value the leg ever had keeps its `lagging` verdict for ever —
    // `d1OnlineEvalLegQualitySource` would serve it to the router indefinitely,
    // and `sweepAllOnlineEvalRegressions` cannot recover it because
    // `ONLINE_EVAL_ACTIVE_TENANTS_SQL` only returns tenants that HAVE scores in
    // the window, i.e. precisely not this one.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    const refresh = (atUnix: number): Promise<number> =>
      refreshOnlineEvalLegQuality(
        {},
        TENANT,
        atUnix,
        () => controlDb() as never,
        () => undefined,
      );
    expect(await refresh(NOW_UNIX)).toBe(1);
    expect(await storedLegQuality()).toHaveLength(1);

    const later = NOW_UNIX + LEG_QUALITY_WINDOW_SECONDS + 10;
    expect(await onlineEvalLegAggregates(controlDb(), TENANT, later)).toEqual([]);
    expect(await refresh(later)).toBe(0);
    expect(await storedLegQuality()).toEqual([]);
  });

  it("prunes only the refreshing tenant's cells", async () => {
    // ANTI-VACUITY for the unconditional prune: it is bound to the tenant being
    // refreshed, so an empty recompute for one tenant may not wipe another's.
    await writeOnlineEvalLegQuality(controlDb(), TENANT, [aggregate()], NOW_UNIX);
    await writeOnlineEvalLegQuality(
      controlDb(),
      "tenant_b",
      [aggregate({ tenantId: "tenant_b", provider: "azure-eu" })],
      NOW_UNIX,
    );
    expect(await storedLegQuality()).toHaveLength(2);

    const later = NOW_UNIX + LEG_QUALITY_WINDOW_SECONDS + 10;
    await writeOnlineEvalLegQuality(controlDb(), TENANT, [], later);
    expect(await readOnlineEvalLegQuality(controlDb(), TENANT)).toEqual([]);
    expect(await readOnlineEvalLegQuality(controlDb(), "tenant_b")).toHaveLength(1);
  });

  it("keeps a COVERAGE score in the ladder aggregate and drops a SHADOW one", async () => {
    // `servableCandidates` strips every `shadowPercent` route from the ladder,
    // so an experiment's shadow provider can never serve — but
    // `shadowArmSampleFrom` files its score under the SAME `logical_model`. If
    // it were aggregated it could DEFINE the `best` bar and demote a servable
    // sibling on a gap the tenant's own `regressionDrop` says is not real.
    // Coverage is the opposite: a covered leg IS a servable candidate.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await seedLeg({
      provider: "azure-eu",
      providerModel: "gpt-4o-mini",
      count: 20,
      score: 0.85,
      arm: "coverage",
    });
    await seedLeg({
      provider: "anthropic-us",
      providerModel: "claude",
      count: 20,
      score: 1,
      arm: "shadow",
    });

    const rows = await onlineEvalLegAggregates(controlDb(), TENANT, NOW_UNIX);
    expect(rows.map((row) => row.provider).sort()).toEqual(["azure-eu", "openai-main"]);

    // The consequence the exclusion exists for. Best ROUTABLE leg is 0.90, so
    // `azure-eu`'s 0.85 is a 0.05 gap — inside the tenant's 0.10 threshold.
    const verdicts = legQualityVerdicts(rows, POLICY);
    expect(verdicts.get(key("azure-eu"))).toEqual({ kind: "comparable", scoreCount: 20 });
    // ANTI-VACUITY: the SAME comparator, handed the unroutable shadow cell as
    // well, DOES demote it (1.00 - 0.85 >= 0.10) — so the `comparable` above is
    // the SQL filter doing its job, not a comparator that cannot say `lagging`.
    const withShadow = legQualityVerdicts(
      [
        ...rows,
        // 1.00 against azure-eu's 0.85 — a 0.15 gap, clear of the 0.10
        // threshold and of float noise in the SQL-computed SUM.
        aggregate({
          provider: "anthropic-us",
          providerModel: "claude",
          scoreTotal: 20,
          scoreCount: 20,
        }),
      ],
      POLICY,
    );
    expect(withShadow.get(key("azure-eu"))).toMatchObject({
      kind: "lagging",
      bestProvider: "anthropic-us",
    });
  });

  it("is populated by the CRON sweep, not only by a direct call", async () => {
    // The off-request-path hook `regression.ts::sweepAllOnlineEvalRegressions`
    // makes on every tick. Without it, a tenant whose queue batches have gone
    // quiet keeps whatever the projection last held, and every deployment where
    // the consumer hook regressed would still look green.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await seedLeg({ provider: "azure-eu", providerModel: "gpt-4o-mini", count: 20, score: 0.5 });
    expect(await storedLegQuality()).toEqual([]);

    await sweepAllOnlineEvalRegressions(
      { GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([{ tenant_id: TENANT, ...OPT_IN_ROW }]) },
      NOW_UNIX,
      () => controlDb() as never,
      () => controlDb() as never,
    );

    const rows = await storedLegQuality();
    expect(rows.map((row) => row.provider)).toEqual(["azure-eu", "openai-main"]);
    // And it is the ROUTER-readable projection, under this tenant.
    expect(await readOnlineEvalLegQuality(controlDb(), TENANT)).toHaveLength(2);
  });

  it("refuses to aggregate the shared table when the tenant object is absent", async () => {
    // The object-first rule `regression.ts` states: an absent `TENANT_DATA`
    // binding is a storage misconfiguration, not permission to read the control
    // projection as if it were authority.
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    expect(await refreshOnlineEvalLegQuality({ CONTROL_DB: controlDb() }, TENANT, NOW_UNIX)).toBe(
      0,
    );
    expect(await storedLegQuality()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The comparator — RELATIVE, never a floor
// ---------------------------------------------------------------------------

describe("the comparator compares legs to each other, never to a number", () => {
  it("calls a leg lagging only against the ladder's best under the same judge and criterion", () => {
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "openai-main", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "azure-eu", scoreTotal: 10, scoreCount: 20 }),
      ],
      POLICY,
    );
    expect(verdicts.get("split-model\u0000openai-main\u0000gpt-4o-mini")).toEqual({
      kind: "comparable",
      scoreCount: 20,
    });
    expect(verdicts.get("split-model\u0000azure-eu\u0000gpt-4o-mini")).toMatchObject({
      kind: "lagging",
      dropAmount: expect.closeTo(0.4, 10) as unknown as number,
      bestProvider: "openai-main",
      bestScoreCount: 20,
    });
  });

  it("is silent about a leg with too few samples", () => {
    // 19 against `DEFAULT_REGRESSION_MIN_SAMPLES = 20`, and a mean of 0.1 —
    // catastrophically below its sibling. It is STILL `no_signal`: the guard is
    // on the sample count, not on the number.
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "openai-main", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "azure-eu", scoreTotal: 1.9, scoreCount: 19 }),
      ],
      POLICY,
    );
    expect(verdicts.has("split-model\u0000azure-eu\u0000gpt-4o-mini")).toBe(false);
    // ANTI-VACUITY: the same helper, one more sample, produces a real signal —
    // so "no signal" above is the guard firing and not the reader being broken.
    const withOneMore = legQualityVerdicts(
      [
        aggregate({ provider: "openai-main", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "azure-eu", scoreTotal: 2, scoreCount: 20 }),
      ],
      POLICY,
    );
    expect(withOneMore.get("split-model\u0000azure-eu\u0000gpt-4o-mini")).toMatchObject({
      kind: "lagging",
    });
  });

  it("will not let a thin leg define the bar for its siblings", () => {
    // A 3-sample leg that happened to score 1.0 must not make a well-measured
    // 0.85 leg look like a regression.
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "lucky", scoreTotal: 3, scoreCount: 3 }),
        aggregate({ provider: "steady", scoreTotal: 17, scoreCount: 20 }),
      ],
      POLICY,
    );
    expect(verdicts.get("split-model\u0000steady\u0000gpt-4o-mini")).toEqual({
      kind: "comparable",
      scoreCount: 20,
    });
  });

  it("says nothing when the legs are within the tenant's threshold", () => {
    // 0.90 vs 0.85 is a 0.05 gap against a 0.1 threshold.
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "openai-main", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "azure-eu", scoreTotal: 17, scoreCount: 20 }),
      ],
      POLICY,
    );
    expect(verdicts.get("split-model\u0000azure-eu\u0000gpt-4o-mini")).toEqual({
      kind: "comparable",
      scoreCount: 20,
    });
  });

  it("never compares across judges, criteria or ladders", () => {
    // Three pairs that each differ on exactly one grouping axis. If any axis
    // were pooled, the 0.1-scoring leg would drag a 0.9 leg into `lagging`.
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "a", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "b", judgeModel: "other-judge", scoreTotal: 2, scoreCount: 20 }),
        aggregate({ provider: "c", criterionId: "other-criterion", scoreTotal: 2, scoreCount: 20 }),
        aggregate({ provider: "d", logicalModel: "other-model", scoreTotal: 2, scoreCount: 20 }),
      ],
      POLICY,
    );
    // Each cell is alone in its group, so each is its own best and nothing lags.
    for (const verdict of verdicts.values()) expect(verdict.kind).toBe("comparable");
  });

  it("reports a leg that lags under ANY one criterion", () => {
    const verdicts = legQualityVerdicts(
      [
        aggregate({ provider: "best", criterionId: "grounded", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "mixed", criterionId: "grounded", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "best", criterionId: "concise", scoreTotal: 18, scoreCount: 20 }),
        aggregate({ provider: "mixed", criterionId: "concise", scoreTotal: 4, scoreCount: 20 }),
      ],
      POLICY,
    );
    expect(verdicts.get("split-model\u0000mixed\u0000gpt-4o-mini")).toMatchObject({
      kind: "lagging",
      criterionId: "concise",
    });
  });
});

// ---------------------------------------------------------------------------
// The router-consumable memo
// ---------------------------------------------------------------------------

function policySource(
  answer: () => Promise<
    | { ok: true; policy: null | (typeof POLICY & Record<string, unknown>) }
    | { ok: false; detail: string }
  >,
): OnlineEvalPolicySource {
  return {
    policyFor: async () => (await answer()) as never,
    peek: () => undefined,
  };
}

const OPT_IN = {
  enabled: true,
  sampleRate: 1,
  samplingUnit: "request",
  judgeModel: "judge-model",
  criteria: [{ id: "grounded", definition: "grounded?" }],
  coveragePercent: 0,
  ...POLICY,
} as const;

describe("the router-consumable read", () => {
  it("answers peek only after the async read warmed it", async () => {
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await seedLeg({ provider: "azure-eu", providerModel: "gpt-4o-mini", count: 20, score: 0.5 });
    await refreshOnlineEvalLegQuality(
      {},
      TENANT,
      NOW_UNIX,
      () => controlDb() as never,
      () => undefined,
    );

    const source = cachedOnlineEvalLegQualitySource(
      d1OnlineEvalLegQualitySource(
        controlDb() as never,
        policySource(async () => ({ ok: true, policy: OPT_IN as never })),
      ),
    );

    // COLD. This is the state every isolate starts in, and the router must get
    // an answer without doing I/O — so `undefined`, never a blocking read.
    expect(source.peek(TENANT)).toBeUndefined();

    await source.qualityFor(TENANT);

    // WARM, and SYNCHRONOUS: no await on this expression.
    const peeked = source.peek(TENANT);
    expect(peeked?.ok).toBe(true);
    if (peeked === undefined || !peeked.ok) throw new Error("expected a warm snapshot");
    expect(peeked.quality.verdictFor("split-model", "azure-eu", "gpt-4o-mini")).toMatchObject({
      kind: "lagging",
      bestProvider: "openai-main",
    });
    expect(peeked.quality.verdictFor("split-model", "openai-main", "gpt-4o-mini").kind).toBe(
      "comparable",
    );
    // A leg nobody has measured is `no_signal`, not `comparable`.
    expect(peeked.quality.verdictFor("split-model", "never-routed", "x").kind).toBe("no_signal");
  });

  it("never caches a failure", async () => {
    let attempts = 0;
    const source = cachedOnlineEvalLegQualitySource(
      d1OnlineEvalLegQualitySource(
        controlDb() as never,
        policySource(async () => {
          attempts += 1;
          return attempts === 1
            ? { ok: false, detail: "blip" }
            : { ok: true, policy: OPT_IN as never };
        }),
      ),
    );

    expect((await source.qualityFor(TENANT)).ok).toBe(false);
    // A cached failure would read as `no_signal` for every leg — i.e. as "these
    // legs are fine" — for the whole TTL.
    expect(source.peek(TENANT)).toBeUndefined();
    expect((await source.qualityFor(TENANT)).ok).toBe(true);
    expect(attempts).toBe(2);
  });

  it("fences one tenant's snapshot from another's", async () => {
    await seedLeg({ provider: "openai-main", providerModel: "gpt-4o-mini", count: 20, score: 0.9 });
    await seedLeg({ provider: "azure-eu", providerModel: "gpt-4o-mini", count: 20, score: 0.5 });
    await refreshOnlineEvalLegQuality(
      {},
      TENANT,
      NOW_UNIX,
      () => controlDb() as never,
      () => undefined,
    );

    const source = cachedOnlineEvalLegQualitySource(
      d1OnlineEvalLegQualitySource(
        controlDb() as never,
        policySource(async () => ({ ok: true, policy: OPT_IN as never })),
      ),
    );
    await source.qualityFor("tenant_b");
    const peeked = source.peek("tenant_b");
    if (peeked === undefined || !peeked.ok) throw new Error("expected a warm snapshot");
    // `tenant_a`'s rows exist, and are `tenant_a`'s.
    expect(peeked.quality.verdictFor("split-model", "azure-eu", "gpt-4o-mini").kind).toBe(
      "no_signal",
    );
    expect(await readOnlineEvalLegQuality(controlDb(), TENANT)).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// The hot path stays synchronous
// ---------------------------------------------------------------------------

function route(overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
  return {
    logicalModel: "split-model",
    provider: "openai-main",
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: "https://api.example/v1/",
    apiKey: "sk-test",
    enabled: true,
    priority: 0,
    ...overrides,
  } as PhysicalRoute;
}

describe("the routing hot path reads the memo and nothing else", () => {
  it("moves a lagging leg behind its comparable sibling", () => {
    const good = route({ provider: "openai-main", priority: 1 });
    const bad = route({ provider: "azure-eu", priority: 0 });
    const quality = {
      lags: (candidate: PhysicalRoute) => candidate.provider === "azure-eu",
    };

    // `priority` alone puts `azure-eu` first. WITHOUT the quality input that is
    // still the answer, which is the pre-#894 behaviour.
    expect(
      orderCandidatesByStrategy([bad, good], "lowest_cost", {}).map((r) => r.provider),
    ).toEqual(["azure-eu", "openai-main"]);
    expect(
      orderCandidatesByStrategy([bad, good], "lowest_cost", { quality }).map((r) => r.provider),
    ).toEqual(["openai-main", "azure-eu"]);
  });

  it("never drops a route, even when every leg lags", () => {
    const legs = [route({ provider: "a" }), route({ provider: "b" })];
    const ordered = orderCandidatesByStrategy(legs, "lowest_cost", {
      quality: { lags: () => true },
    });
    // A quality signal is a noisy proxy; it may reorder a ladder and must never
    // be able to remove the leg that would have served the request.
    expect(ordered).toHaveLength(2);
    expect(new Set(ordered.map((r) => r.provider))).toEqual(new Set(["a", "b"]));
  });

  it("gives a deployment with no evaluation storage the named empty port", () => {
    // `NO_ROUTING_QUALITY` is the one value `defaults.ts` can hand the router
    // when nothing durable is bound, and naming it is only worth anything if
    // something reaches it: an unconfigured env must resolve to it BY IDENTITY,
    // and it must answer "no quality input" rather than "every leg is fine".
    expect(routingQualityPortFor({} as never)).toBe(NO_ROUTING_QUALITY);
    expect(NO_ROUTING_QUALITY.ladderQuality(TENANT, "split-model")).toBeUndefined();
    // ANTI-VACUITY: a CONFIGURED env does not get it.
    expect(routingQualityPortFor({ CONTROL_DATA: controlNamespace() } as never)).not.toBe(
      NO_ROUTING_QUALITY,
    );
  });

  it("asks the port synchronously and never awaits storage", () => {
    // The port `handlers.ts::planUpstream` holds. If any implementation of it
    // ever returned a promise — i.e. if somebody "fixed" the cold-memo case by
    // reading D1 — this assertion is what fails, because `planUpstream` has no
    // `await` to give it and the ladder would be ordered by a `Promise` object.
    let calls = 0;
    const port = routingQualityPortFrom({
      qualityFor: async () => {
        throw new Error("the routing path must never call qualityFor");
      },
      peek: () => {
        calls += 1;
        return undefined;
      },
    });
    const resolved = port.ladderQuality(TENANT, "split-model");
    expect(resolved).toBeUndefined();
    expect(calls).toBe(1);
    // And a warm port answers a PLAIN object, not a thenable.
    const warm = routingQualityPortFrom({
      qualityFor: async () => ({
        ok: true,
        quality: { verdictFor: () => ({ kind: "no_signal" }), costQualityRouting: false },
      }),
      peek: () => ({
        ok: true,
        quality: {
          verdictFor: () => ({
            kind: "lagging" as const,
            dropAmount: 0.4,
            criterionId: "grounded",
            judgeModel: "judge-model",
            scoreCount: 20,
            bestProvider: "openai-main",
            bestProviderModel: "gpt-4o-mini",
            bestScoreCount: 20,
          }),
          costQualityRouting: false,
        },
      }),
    }).ladderQuality(TENANT, "split-model");
    expect(warm).toBeDefined();
    expect((warm as { then?: unknown }).then).toBeUndefined();
    expect(warm?.lags(route({ provider: "azure-eu" }))).toBe(true);
  });
});
