/**
 * The SAMPLER (#692) — who gets evaluated, how that is decided, and the two
 * ways a wrong sampler makes the resulting numbers meaningless.
 *
 * Every case names the mutation it holds. A sampler is the classic module whose
 * tests pass while the control is absent: "some requests were scored" is true
 * of a random sampler, of an always-on sampler, and of one that ignores the
 * tenant's opt-in entirely.
 */
import { describe, expect, it } from "vitest";

import {
  ONLINE_EVAL_SAMPLING_SALT,
  type OnlineEvalPolicy,
  onlineEvalSamplingDecision,
  parseOnlineEvalPolicyRow,
  sampleBucket,
} from "../../src/evals/index.js";

const CRITERIA = [{ id: "answer_relevance", definition: "Does the answer address the question?" }];

function policy(overrides: Partial<OnlineEvalPolicy> = {}): OnlineEvalPolicy {
  return {
    enabled: true,
    sampleRate: 0.5,
    samplingUnit: "request",
    judgeModel: "judge-model",
    criteria: CRITERIA,
    regressionDrop: 0.1,
    regressionMinSamples: 20,
    coveragePercent: 0,
    costQualityRouting: false,
    ...overrides,
  };
}

describe("the bucket is deterministic, uniform-ish, and salted", () => {
  it("gives the same key the same bucket every time", () => {
    // MUTATION: make `sampleBucket` return `Math.random()` and this goes red.
    // A per-request random sampler cannot compare a conversation against
    // itself, which is the entire point of the `conversation` unit.
    const first = sampleBucket("req_1");
    expect(sampleBucket("req_1")).toBe(first);
    expect(first).toBeGreaterThanOrEqual(0);
    expect(first).toBeLessThan(1);
  });

  it("does not select the same population as an unsalted hash would", () => {
    // The salt is why the online-eval sample is not the SAME 5% of traffic the
    // shadow-mirror sampler picks. Without it, two hash samplers over one key
    // are perfectly correlated and every measured request is also a mirrored
    // one — a biased sample presented as a random one.
    expect(ONLINE_EVAL_SAMPLING_SALT).not.toBe("");
    const salted = sampleBucket("req_1");
    const unsalted = sampleBucket("req_1", "");
    expect(salted).not.toBe(unsalted);
  });

  it("spreads keys across the unit interval", () => {
    const buckets = Array.from({ length: 2000 }, (_, i) => sampleBucket(`req_${i}`));
    const below = buckets.filter((b) => b < 0.25).length;
    // A hash that collapsed to a constant (or to the low bits of the counter)
    // would fail this; 2000 samples put the 25% quartile well inside ±5 points.
    expect(below / buckets.length).toBeGreaterThan(0.2);
    expect(below / buckets.length).toBeLessThan(0.3);
  });
});

describe("sampling is per-tenant OPT-IN", () => {
  it("refuses to sample a tenant with no policy at all", () => {
    // MUTATION: default `policy === null` to an enabled policy and this goes
    // red. Evaluating a customer's traffic without their say-so copies their
    // prompts to a judge model they never agreed to.
    expect(
      onlineEvalSamplingDecision({ policy: null, residency: null, requestId: "req_1" }),
    ).toEqual({ sampled: false, reason: "not_opted_in" });
  });

  it("refuses to sample a tenant whose policy is switched off", () => {
    expect(
      onlineEvalSamplingDecision({
        policy: policy({ enabled: false }),
        residency: null,
        requestId: "req_1",
      }),
    ).toEqual({ sampled: false, reason: "not_opted_in" });
  });

  it("refuses to sample a policy that names no criteria", () => {
    // A score with no stated criterion is a number nobody can interpret.
    expect(
      onlineEvalSamplingDecision({
        policy: policy({ criteria: [] }),
        residency: null,
        requestId: "req_1",
      }),
    ).toEqual({ sampled: false, reason: "no_criteria" });
  });
});

describe("a zero-data-retention tenant is never silently sampled", () => {
  it("skips a ZDR tenant even when its own policy asks to be sampled", () => {
    // MUTATION: delete the ZDR arm from `onlineEvalSamplingDecision` and this
    // goes red. Evaluating a prompt means COPYING it to a judge model and
    // storing a derived record; a tenant that bought zero data retention (#681)
    // must not have that happen because a second control was switched on.
    //
    // The refusal is a DISTINCT reason, not a silent `not_in_sample`, so an
    // operator who sees no scores can tell the difference between "the sampler
    // is working and this tenant is excluded" and "the sampler is broken".
    const decision = onlineEvalSamplingDecision({
      policy: policy({ sampleRate: 1 }),
      residency: {
        regionGated: false,
        allowedRegions: [],
        requireZeroDataRetention: true,
        logResidency: "unconstrained",
      },
      requestId: "req_1",
    });
    expect(decision).toEqual({ sampled: false, reason: "zero_data_retention" });
  });

  it("still samples a region-gated tenant that did NOT require ZDR", () => {
    // Region gating alone does not forbid evaluation — it constrains WHERE the
    // judge may run, which the consumer enforces per judge route. Refusing here
    // would make the region policy a silent opt-out from a control the tenant
    // asked for.
    const decision = onlineEvalSamplingDecision({
      policy: policy({ sampleRate: 1 }),
      residency: {
        regionGated: true,
        allowedRegions: ["eu-west-1"],
        requireZeroDataRetention: false,
        logResidency: "in_region",
      },
      requestId: "req_1",
    });
    expect(decision.sampled).toBe(true);
  });
});

describe("the sampling UNIT decides what a score can be compared against", () => {
  it("samples a whole conversation or none of it", () => {
    // MUTATION: make the conversation unit fall back to the request id and this
    // goes red. Two turns of one conversation landing on opposite sides of the
    // sample is what makes "did this conversation get worse" unanswerable.
    const withUnit = (requestId: string) =>
      onlineEvalSamplingDecision({
        policy: policy({ samplingUnit: "conversation", sampleRate: 0.5 }),
        residency: null,
        requestId,
        conversationKey: "conv_stable",
      });

    const turns = ["req_1", "req_2", "req_3", "req_4"].map(withUnit);
    const sampled = turns.filter((t) => t.sampled).length;
    expect(sampled === 0 || sampled === turns.length).toBe(true);
    for (const turn of turns) {
      if (turn.sampled) expect(turn.samplingKey).toBe("conv_stable");
    }
  });

  it("never samples a conversation-unit request with no conversation to key on", () => {
    // The same rule `inference/shadow.ts` applies to an identity-less caller: a
    // per-request decision under a conversation policy would sample a random
    // slice of every conversation rather than a stable slice of conversations.
    expect(
      onlineEvalSamplingDecision({
        policy: policy({ samplingUnit: "conversation", sampleRate: 1 }),
        residency: null,
        requestId: "req_1",
      }),
    ).toEqual({ sampled: false, reason: "no_conversation_key" });
  });

  it("keys the request unit on the request id", () => {
    const decision = onlineEvalSamplingDecision({
      policy: policy({ sampleRate: 1 }),
      residency: null,
      requestId: "req_7",
      conversationKey: "conv_stable",
    });
    expect(decision).toEqual({
      sampled: true,
      samplingKey: "req_7",
      rate: 1,
      unit: "request",
    });
  });
});

describe("the rate is honoured in both directions", () => {
  it("samples nothing at rate 0 and everything at rate 1", () => {
    const at = (rate: number) =>
      ["a", "b", "c", "d", "e", "f", "g", "h"].filter(
        (id) =>
          onlineEvalSamplingDecision({
            policy: policy({ sampleRate: rate }),
            residency: null,
            requestId: id,
          }).sampled,
      ).length;
    expect(at(0)).toBe(0);
    expect(at(1)).toBe(8);
  });

  it("lands within a few points of the configured fraction", () => {
    // MUTATION: compare `bucket <= rate` against a constant, or drop the
    // comparison entirely, and this goes red in one direction or the other.
    const ids = Array.from({ length: 4000 }, (_, i) => `req_${i}`);
    const sampled = ids.filter(
      (id) =>
        onlineEvalSamplingDecision({
          policy: policy({ sampleRate: 0.1 }),
          residency: null,
          requestId: id,
        }).sampled,
    ).length;
    expect(sampled / ids.length).toBeGreaterThan(0.08);
    expect(sampled / ids.length).toBeLessThan(0.12);
  });
});

describe("the policy row parser fails CLOSED", () => {
  it("reads a row that opts in", () => {
    expect(
      parseOnlineEvalPolicyRow({
        enabled: 1,
        sampleRate: "0.25",
        samplingUnit: "conversation",
        judgeModel: "judge-model",
        criteria: [{ id: "grounded", definition: "Is it supported by the context?" }],
      }),
    ).toEqual({
      ok: true,
      policy: {
        enabled: true,
        sampleRate: 0.25,
        samplingUnit: "conversation",
        judgeModel: "judge-model",
        criteria: [{ id: "grounded", definition: "Is it supported by the context?" }],
        regressionDrop: 0.1,
        regressionMinSamples: 20,
        // #894 — candidate coverage defaults OFF for a tenant that opted into
        // measurement: mirroring to a second provider is a strictly larger
        // consent than sampling. See `evals/policy.ts`.
        coveragePercent: 0,
        // #699 — the cost/quality dial likewise defaults OFF: acting on the
        // signal is a strictly larger consent than measuring it.
        costQualityRouting: false,
      },
    });
  });

  it("reads an absent row as 'this tenant did not opt in'", () => {
    expect(parseOnlineEvalPolicyRow({})).toEqual({ ok: true, policy: null });
  });

  it("refuses a row that opts in without naming a judge model", () => {
    // Not "sample anyway and pick a judge": the judge model IS the measuring
    // instrument, and choosing one for the tenant would make the score's
    // meaning depend on a default nobody agreed to.
    const parsed = parseOnlineEvalPolicyRow({
      enabled: 1,
      sampleRate: 0.5,
      criteria: [{ id: "grounded", definition: "supported?" }],
    });
    expect(parsed.ok).toBe(false);
  });

  it("refuses a rate outside [0, 1]", () => {
    expect(
      parseOnlineEvalPolicyRow({
        enabled: 1,
        sampleRate: 42,
        judgeModel: "judge-model",
        criteria: CRITERIA,
      }).ok,
    ).toBe(false);
  });

  it("refuses a criterion with no definition", () => {
    expect(
      parseOnlineEvalPolicyRow({
        enabled: 1,
        sampleRate: 0.5,
        judgeModel: "judge-model",
        criteria: [{ id: "grounded" }],
      }).ok,
    ).toBe(false);
  });
});
