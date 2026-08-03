/**
 * THE READ half of experiment outcome metrics (#693), through the exported
 * Worker against a REAL D1 binding.
 *
 * ## What this file is FOR
 *
 * Not "the endpoint returns 200". The reason this surface is dangerous is that
 * a quality comparison is only valid under conditions a report can violate
 * without anything looking wrong, and the whole value of #693 is that it
 * refuses instead. So every case below drives one of the refusals with rows
 * that would produce a plausible, confident, WRONG number under a naive
 * implementation:
 *
 *  - two arms scored by DIFFERENT JUDGES, whose means differ by 0.20;
 *  - two arms scored under DIFFERENT CRITERIA, likewise;
 *  - a variant arm with TWO SAMPLES and a spectacular mean;
 *  - two adequately-sampled arms whose difference is inside the noise.
 *
 * In each case the assertion is not only on the verdict but on the ABSENCE of a
 * number in the response body — because a caption is not a control and a field
 * that exists will eventually be rendered.
 *
 * ## What is real, and what is a fixture
 *
 * Real: the exported control-plane Worker (`SELF`), the auth guard, the RBAC
 * chain, the contract router, the real `DB` binding with the DEPLOYED migration
 * set, and the pure comparator in `@ferrogate/routing`.
 *
 * Fixtures: the rows. The WRITER is `apps/gateway` — a different Worker with a
 * different `wrangler.toml`, unreachable from this suite — and it is held end
 * to end by `apps/gateway/test/experiments/{attribution,scored-arms}.test.ts`,
 * which drive real requests and assert against these same columns. The two
 * halves meet at `sql/d1-ts/control/0011_experiment_outcomes.sql`, which both
 * suites apply from the deployed migration directory rather than from a copy,
 * so a column rename breaks both. This is the same seam and the same argument
 * `test/request-logs-read.test.ts` states for #664.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1, seedBillingEvents, seedRequestLogs } from "./d1.js";
import { BASE, arm as armWorld, bearer, tenantKey } from "./harness.js";

const KEY = "cp_exp_reader";
const TENANT = "tenant_a";
const EXPERIMENT = "exp_00000000deadbeef";
const OTHER_EXPERIMENT = "exp_00000000feedface";
const NOW = 1_800_000_000;

interface ArmDocument {
  arm: string;
  requests: number;
  failures: number;
  error_rate: number | null;
  mean_latency_ms: number | null;
  cost_usd: number;
  delivered: boolean;
  charged_to: string;
}

interface ReportBody {
  object: string;
  id: string;
  variant_arm: string;
  min_samples: number;
  arms: ArmDocument[];
  quality: {
    judge_mismatch: boolean;
    criterion_mismatch: boolean;
    comparisons: {
      criterion_id: string;
      judge_model: string;
      verdict: string;
      control: { arm: string; count: number; mean?: number };
      variant: { arm: string; count: number; mean?: number };
      difference?: number;
      p_value?: number;
    }[];
    incomparable: { criterion_id: string; judge_model: string; reason: string }[];
  };
}

/** `n` served requests on one arm, all successful unless `failures` says so. */
async function seedServedArm(options: {
  experimentId?: string;
  arm: "control" | "canary";
  count: number;
  failures?: number;
  latencyMs: number;
  costUsdEach: number;
  prefix: string;
}): Promise<void> {
  const experimentId = options.experimentId ?? EXPERIMENT;
  const failures = options.failures ?? 0;
  const logs = [];
  const events = [];
  for (let index = 0; index < options.count; index += 1) {
    const requestId = `${options.prefix}-${index}`;
    const failed = index < failures;
    logs.push({
      requestId,
      tenant: TENANT,
      startedAtUnix: NOW - 60,
      statusCode: failed ? 502 : 200,
      latencyMs: options.latencyMs,
      logicalModel: "split-model",
      provider: options.arm === "canary" ? "anthropic-canary" : "openai-main",
    });
    events.push({
      id: `be-${requestId}`,
      requestId,
      occurredAtUnix: NOW - 60,
      event: { cost_usd: options.costUsdEach },
    });
  }
  await seedRequestLogs(logs);
  await seedBillingEvents(events);
  // The arm columns are not in `seedRequestLogs`' insert list (it predates
  // #693), so they are set here. Deliberately a separate UPDATE rather than a
  // widened shared helper: every other suite that uses that helper asserts on
  // rows with NO experiment, and quietly giving them one would change what
  // those tests mean.
  await db()
    .prepare(
      "UPDATE request_logs SET experiment_id = ?, experiment_arm = ? WHERE request_id LIKE ?",
    )
    .bind(experimentId, options.arm, `${options.prefix}-%`)
    .run();
}

/** Shadow legs — the arm with no request log. */
async function seedShadowLegs(options: {
  count: number;
  failures?: number;
  latencyMs: number;
  costUsdEach: number;
}): Promise<void> {
  const failures = options.failures ?? 0;
  const statements = [];
  for (let index = 0; index < options.count; index += 1) {
    const failed = index < failures;
    statements.push(
      db()
        .prepare(
          `INSERT INTO experiment_shadow_legs
             (leg_id, client_request_id, experiment_id, tenant, logical_model, provider,
              provider_model, status_code, error_code, latency_ms, cost_usd, observed_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          `shadow-${index}~shadow`,
          `shadow-${index}`,
          EXPERIMENT,
          TENANT,
          "split-model",
          "mirror-provider",
          "mirror-physical",
          failed ? null : 200,
          failed ? "provider_dispatch_error" : null,
          options.latencyMs,
          failed ? null : options.costUsdEach,
          NOW - 60,
        ),
    );
  }
  if (statements.length > 0) await db().batch(statements);
}

/**
 * `n` scores for one arm under one instrument.
 *
 * The scores ALTERNATE around `mean` by `spread`, so the sample variance is a
 * real number rather than zero — a zero-variance fixture would make every
 * significance assertion below vacuous, since any non-zero difference is then
 * infinitely significant.
 */
async function seedScores(options: {
  arm: string;
  count: number;
  mean: number;
  spread: number;
  judgeModel?: string;
  criterionId?: string;
  tenant?: string;
  /**
   * The `request_id` these scores are filed under.
   *
   * The shadow arm's rows are filed under the LEG id — `{clientRequestId}~shadow`
   * — because `online_eval_scores` is keyed by `(request_id, criterion_id)` and
   * a shadow score filed under the client's own id would OVERWRITE the served
   * arm's score for the same criterion. `apps/gateway/src/evals/shadow-leg.ts`
   * derives it, and `apps/gateway/test/experiments/shadow-scored.test.ts` holds
   * the derivation end to end; this parameter is what lets the fixtures here
   * carry the same shape the writer really produces.
   */
  requestIdFor?: (index: number) => string;
}): Promise<void> {
  const judgeModel = options.judgeModel ?? "judge-a";
  const criterionId = options.criterionId ?? "helpfulness";
  const statements = [];
  for (let index = 0; index < options.count; index += 1) {
    const score = options.mean + (index % 2 === 0 ? options.spread : -options.spread);
    statements.push(
      db()
        .prepare(
          `INSERT INTO online_eval_scores
             (request_id, criterion_id, tenant, sampling_key, sampling_unit, sample_rate,
              judge_model, score, scored_at_unix, experiment_id, experiment_arm)
           VALUES (?, ?, ?, ?, 'request', 1, ?, ?, ?, ?, ?)`,
        )
        .bind(
          options.requestIdFor?.(index) ??
            `score-${options.arm}-${judgeModel}-${criterionId}-${index}`,
          criterionId,
          options.tenant ?? TENANT,
          `sk-${index}`,
          judgeModel,
          score,
          NOW - 60,
          EXPERIMENT,
          options.arm,
        ),
    );
  }
  if (statements.length > 0) await db().batch(statements);
}

async function report(query = ""): Promise<ReportBody> {
  const response = await SELF.fetch(`${BASE}/admin/v1/experiments/${EXPERIMENT}${query}`, {
    headers: bearer(KEY),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as ReportBody;
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await db().batch([
    db().prepare("DELETE FROM experiment_shadow_legs"),
    db().prepare("DELETE FROM online_eval_scores"),
  ]);
  armWorld({ store: "d1", nativeKeys: [tenantKey(KEY, TENANT, ["admin.read"])] });
});

describe("the operational half", () => {
  it("reports each arm's requests, error rate, latency and cost — and who is charged", async () => {
    await seedServedArm({
      arm: "control",
      count: 10,
      failures: 1,
      latencyMs: 100,
      costUsdEach: 0.01,
      prefix: "ctl",
    });
    await seedServedArm({
      arm: "canary",
      count: 4,
      latencyMs: 50,
      costUsdEach: 0.02,
      prefix: "can",
    });
    await seedShadowLegs({ count: 4, latencyMs: 70, costUsdEach: 0.03 });

    const body = await report("?since=0&variant=canary");
    const byArm = new Map(body.arms.map((entry) => [entry.arm, entry]));

    expect(byArm.get("control")?.requests).toBe(10);
    expect(byArm.get("control")?.error_rate).toBeCloseTo(0.1, 6);
    expect(byArm.get("control")?.mean_latency_ms).toBeCloseTo(100, 6);
    expect(byArm.get("control")?.cost_usd).toBeCloseTo(0.1, 6);
    expect(byArm.get("control")?.charged_to).toBe("tenant");

    expect(byArm.get("canary")?.requests).toBe(4);
    expect(byArm.get("canary")?.cost_usd).toBeCloseTo(0.08, 6);

    // THE shadow decision, visible on the wire. The customer never saw these
    // responses and never asked for the second provider, so the spend is the
    // OPERATOR's cost of running the experiment.
    expect(byArm.get("shadow")?.requests).toBe(4);
    expect(byArm.get("shadow")?.delivered).toBe(false);
    expect(byArm.get("shadow")?.charged_to).toBe("operator");
    expect(byArm.get("shadow")?.cost_usd).toBeCloseTo(0.12, 6);
  });

  it("fences to the caller's tenant", async () => {
    await seedServedArm({
      arm: "control",
      count: 5,
      latencyMs: 10,
      costUsdEach: 0,
      prefix: "ctl",
    });
    await db().prepare("UPDATE request_logs SET tenant = 'tenant_b'").run();

    const response = await SELF.fetch(`${BASE}/admin/v1/experiments?since=0`, {
      headers: bearer(KEY),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: unknown[]; total: number };
    // An experiment report names a customer's models, their spend and their
    // measured quality. Another tenant's split must not even be discoverable.
    expect(body.data).toHaveLength(0);
    expect(body.total).toBe(0);
  });
});

describe("the quality half REFUSES rather than reporting a plausible number", () => {
  beforeEach(async () => {
    await seedServedArm({
      arm: "control",
      count: 200,
      latencyMs: 100,
      costUsdEach: 0,
      prefix: "ctl",
    });
    await seedServedArm({
      arm: "canary",
      count: 200,
      latencyMs: 90,
      costUsdEach: 0,
      prefix: "can",
    });
  });

  it("will not compare arms scored by DIFFERENT JUDGES", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.1, judgeModel: "judge-a" });
    await seedScores({ arm: "canary", count: 100, mean: 0.8, spread: 0.1, judgeModel: "judge-b" });

    const body = await report("?since=0&variant=canary");

    // A naive report would say "canary +0.20". That number measures the
    // difference between two JUDGES, not between two models.
    expect(body.quality.comparisons).toHaveLength(0);
    expect(body.quality.judge_mismatch).toBe(true);
    expect(body.quality.incomparable.map((cell) => cell.reason).sort()).toEqual([
      "control_arm_not_scored",
      "variant_arm_not_scored",
    ]);
    // And there is no difference ANYWHERE in the payload to render.
    expect(JSON.stringify(body.quality)).not.toContain("difference");
  });

  it("will not compare arms scored under DIFFERENT CRITERIA", async () => {
    await seedScores({
      arm: "control",
      count: 100,
      mean: 0.6,
      spread: 0.1,
      criterionId: "helpfulness",
    });
    await seedScores({
      arm: "canary",
      count: 100,
      mean: 0.8,
      spread: 0.1,
      // One character different: a re-worded criterion is a different
      // instrument, and #692 makes renaming one start a new series on purpose.
      criterionId: "helpfulnes",
    });

    const body = await report("?since=0&variant=canary");
    expect(body.quality.comparisons).toHaveLength(0);
    expect(body.quality.criterion_mismatch).toBe(true);
    expect(JSON.stringify(body.quality)).not.toContain("difference");
  });

  it("reports NO MEAN when the variant arm is too small", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.1 });
    // Two requests per arm is not a result.
    await seedScores({ arm: "canary", count: 2, mean: 0.95, spread: 0.01 });

    const body = await report("?since=0&variant=canary");
    expect(body.quality.comparisons).toHaveLength(1);
    const cell = body.quality.comparisons[0];
    expect(cell?.verdict).toBe("insufficient_samples");
    // The counts ARE reported: that is what tells an operator to wait.
    expect(cell?.control.count).toBe(100);
    expect(cell?.variant.count).toBe(2);
    // The means are not, on either side, and neither is the difference. A
    // client cannot render "0.95 vs 0.60" from this body however it captions it.
    expect(cell?.control.mean).toBeUndefined();
    expect(cell?.variant.mean).toBeUndefined();
    expect(cell?.difference).toBeUndefined();
    expect(cell?.p_value).toBeUndefined();
  });

  it("will not call a difference the spread does not support", async () => {
    // Both arms adequately sampled, means 0.02 apart, spread ±0.30.
    await seedScores({ arm: "control", count: 40, mean: 0.6, spread: 0.3 });
    await seedScores({ arm: "canary", count: 40, mean: 0.62, spread: 0.3 });

    const body = await report("?since=0&variant=canary");
    const cell = body.quality.comparisons[0];
    expect(cell?.verdict).toBe("no_measured_difference");
    // Here the means ARE shown — the sample is adequate and "we measured both
    // and cannot distinguish them" is itself a rollout decision.
    expect(cell?.control.mean).toBeCloseTo(0.6, 6);
    expect(cell?.p_value).toBeGreaterThan(0.05);
  });

  it("calls a real, well-sampled improvement for the variant", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.05 });
    await seedScores({ arm: "canary", count: 100, mean: 0.8, spread: 0.05 });

    const body = await report("?since=0&variant=canary");
    const cell = body.quality.comparisons[0];
    expect(cell?.verdict).toBe("variant_better");
    expect(cell?.difference).toBeCloseTo(0.2, 6);
    expect(cell?.judge_model).toBe("judge-a");
    expect(cell?.criterion_id).toBe("helpfulness");
  });
});

/**
 * THE SHADOW ARM'S QUALITY NUMBER (#693, second cut).
 *
 * Until the gateway could score the mirrored response, a control+shadow
 * experiment came back with `comparisons: []` and one
 * `variant_arm_not_scored` cell — every operational number and no answer to
 * "was the variant better", which is the only question a shadow experiment
 * exists to ask. The rows below are the shape
 * `apps/gateway/src/evals/shadow-leg.ts` really writes: filed under the LEG id,
 * carrying `experiment_arm = 'shadow'`, and — this is the part that makes the
 * comparison legitimate — carrying the SAME judge and the SAME criterion as the
 * control arm, because the sampler derives the shadow sample from the served
 * one rather than resolving a policy a second time.
 */
describe("the SHADOW arm is comparable, under exactly the same rule as the canary", () => {
  beforeEach(async () => {
    await seedServedArm({
      arm: "control",
      count: 200,
      latencyMs: 100,
      costUsdEach: 0,
      prefix: "ctl",
    });
    await seedShadowLegs({ count: 200, latencyMs: 120, costUsdEach: 0.001 });
  });

  it("compares a scored shadow arm against the control and reaches a verdict", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.05 });
    await seedScores({
      arm: "shadow",
      count: 100,
      mean: 0.8,
      spread: 0.05,
      // Filed under the leg id the gateway derives, exactly as the writer does.
      requestIdFor: (index) => `shadow-${index}~shadow`,
    });

    // NO `?variant=`: with only a control and a shadow observed there is one
    // variant, and the report picks it rather than refusing.
    const body = await report("?since=0");
    expect(body.variant_arm).toBe("shadow");

    // THE ASSERTION THIS BLOCK EXISTS FOR — a real verdict where the surface
    // could previously only answer "variant_arm_not_scored".
    expect(body.quality.incomparable).toHaveLength(0);
    expect(body.quality.comparisons).toHaveLength(1);
    const cell = body.quality.comparisons[0];
    expect(cell?.verdict).toBe("variant_better");
    expect(cell?.variant.arm).toBe("shadow");
    expect(cell?.difference).toBeCloseTo(0.2, 6);
    expect(cell?.judge_model).toBe("judge-a");
    expect(cell?.criterion_id).toBe("helpfulness");

    // And the operational half is still the shadow arm's: nobody was served it
    // and nobody was billed for it.
    const shadowArm = body.arms.find((entry) => entry.arm === "shadow");
    expect(shadowArm?.delivered).toBe(false);
    expect(shadowArm?.charged_to).toBe("operator");
  });

  it("still REFUSES a shadow arm scored by a different judge", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.05 });
    await seedScores({
      arm: "shadow",
      count: 100,
      mean: 0.8,
      spread: 0.05,
      judgeModel: "judge-b",
      requestIdFor: (index) => `shadow-${index}~shadow`,
    });

    const body = await report("?since=0");
    // The shadow path acquired no looser rule of its own. A naive report would
    // say "shadow +0.20", which measures the difference between two JUDGES.
    expect(body.quality.comparisons).toHaveLength(0);
    expect(body.quality.judge_mismatch).toBe(true);
    expect(body.quality.incomparable.map((cell) => cell.reason).sort()).toEqual([
      "control_arm_not_scored",
      "variant_arm_not_scored",
    ]);
    expect(JSON.stringify(body.quality)).not.toContain("difference");
  });

  it("still REFUSES a shadow arm scored under a different criterion", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.05 });
    await seedScores({
      arm: "shadow",
      count: 100,
      mean: 0.8,
      spread: 0.05,
      criterionId: "helpfulnes",
      requestIdFor: (index) => `shadow-${index}~shadow`,
    });

    const body = await report("?since=0");
    expect(body.quality.comparisons).toHaveLength(0);
    expect(body.quality.criterion_mismatch).toBe(true);
    expect(JSON.stringify(body.quality)).not.toContain("difference");
  });

  it("still reports NO MEAN when the shadow arm is below the sample floor", async () => {
    await seedScores({ arm: "control", count: 100, mean: 0.6, spread: 0.05 });
    await seedScores({
      arm: "shadow",
      count: 2,
      mean: 0.95,
      spread: 0.01,
      requestIdFor: (index) => `shadow-${index}~shadow`,
    });

    const body = await report("?since=0");
    const cell = body.quality.comparisons[0];
    expect(cell?.verdict).toBe("insufficient_samples");
    expect(cell?.variant.count).toBe(2);
    expect(cell?.variant.mean).toBeUndefined();
    expect(cell?.difference).toBeUndefined();
  });
});

describe("the variant is never chosen on the operator's behalf", () => {
  it("refuses when the experiment has both a canary and a shadow arm", async () => {
    await seedServedArm({
      arm: "control",
      count: 5,
      latencyMs: 10,
      costUsdEach: 0,
      prefix: "ctl",
    });
    await seedServedArm({
      arm: "canary",
      count: 5,
      latencyMs: 10,
      costUsdEach: 0,
      prefix: "can",
    });
    await seedShadowLegs({ count: 5, latencyMs: 10, costUsdEach: 0 });

    const response = await SELF.fetch(`${BASE}/admin/v1/experiments/${EXPERIMENT}?since=0`, {
      headers: bearer(KEY),
    });
    // Picking one silently would be a rollout decision taken by the reporting
    // surface, and the caller would never know which comparison they read.
    expect(response.status).toBe(400);
  });

  it("404s an experiment nothing observed", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/experiments/${OTHER_EXPERIMENT}?since=0`, {
      headers: bearer(KEY),
    });
    expect(response.status).toBe(404);
  });
});
