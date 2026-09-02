/**
 * #894 — CANDIDATE COVERAGE: a score lands on a candidate that never served.
 *
 * ## The gap this file closes
 *
 * `online_eval_scores` only ever held rows for legs that SERVED, plus the shadow
 * arm an EXPERIMENT declared (#693). A cheap candidate sitting behind a healthy
 * primary is never routed to, so it accumulates no scores, so the per-leg
 * aggregate in `evals/leg-quality.ts` reports `no_signal` for it for ever — and
 * a router asked to promote it has nothing to go on. This drives the whole
 * DEPLOYED chain and asserts a score row for a leg the client was never served
 * by, and then that the per-leg aggregate can see both legs.
 *
 * ## What is real
 *
 * The deployed middleware chain (`GATEWAY_MIDDLEWARE`), the real sampler, the
 * real mirror dispatch, the real queue wire, the DEPLOYED queue entry point
 * (`gatewayQueue`), the real judge dispatch with only the outbound `fetch`
 * intercepted, and the real `CONTROL_DB` with the committed migrations. Nothing
 * here seeds a score row.
 *
 * ## MUTATION LOG
 *
 * Every row below was applied to the tree, run, and reverted.
 *
 * | mutation (in `src/`)                                                       | red |
 * |-------------------------------------------------------------------------------|-----|
 * | `handlers.ts::dispatchCandidates`: never spawn the coverage mirror              | `scores a candidate the client was never served by` |
 * | `middleware.ts`: `requestCoverageEval(raw, policy.coveragePercent)` → `(raw, 0)` | `scores a candidate the client was never served by` |
 * | `shadow.ts::coverageMirrorFor`: `candidates.slice(1)` → `slice(0)` (cover the PRIMARY) | `scores a candidate the client was never served by` |
 * | `shadow.ts::coverageMirrorFor`: BOTH the `coveragePercent > 0` guard removed AND `shadowSampled(…, 100)` | `spends nothing for a tenant that did not ask for coverage` |
 *
 * The last row is deliberate: the money guarantee is held by TWO independent
 * guards (the explicit zero check and the per-request sampler, which never
 * selects at 0%), so removing either one alone leaves the test green. That is
 * belt and braces on the one behaviour in this slice that spends the tenant's
 * money, not a vacuous assertion — removing both together turns it red.
 *
 * The selector's own refusals — the credential's provider allowlist, the
 * residency re-check, the budget key and the rotation — are held by
 * `test/inference/coverage-mirror.test.ts`, which can build the ladders this
 * end-to-end harness cannot.
 */
import { createExecutionContext, env as poolEnv, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OnlineEvalSample } from "../../src/evals/index.js";
import {
  coverageArmSampleFrom,
  onlineEvalLegAggregates,
  readOnlineEvalLegQuality,
  shadowArmSampleFrom,
} from "../../src/evals/index.js";
import { GATEWAY_MIDDLEWARE, gatewayQueue } from "../../src/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { controlNamespace } from "../support/control-namespace.js";
import { tenantObjectDb } from "../tenant-object.js";
import { controlDb, resetOnlineEvalTables, storedTenantScores } from "./harness.js";

const BASE = "https://gw.test";
const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

const KEYS = [
  {
    key: "fg_coverage_eval",
    id: "key_coverage_eval",
    tenant_id: "tenant_optin",
    project_id: "project_cov",
    scopes: ["chat.completions"],
  },
];

/** The leg that always serves: lowest priority number, healthy, first. */
const PRIMARY: PhysicalRoute = {
  logicalModel: "ladder-model",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.primary.example/v1/",
  apiKey: "sk-primary",
  enabled: true,
  priority: 0,
};

/**
 * The leg the client is NEVER served by.
 *
 * A perfectly ordinary SERVABLE fallback candidate — no `shadowPercent`, no
 * canary, nothing that would make `shadowMirrorFor` pick it up. That is the
 * whole point: this is the population #693's mirror could not reach.
 */
const FALLBACK: PhysicalRoute = {
  logicalModel: "ladder-model",
  provider: "azure-eu",
  providerModel: "gpt-4o-mini-azure",
  providerKind: "openai",
  baseUrl: "https://api.fallback.example/v1/",
  apiKey: "sk-fallback",
  enabled: true,
  priority: 10,
};

const JUDGE_PROVIDERS = [
  {
    name: "openai-judge",
    kind: "openai",
    base_url: "https://judge.test/v1",
    api_key_var: "JUDGE_API_KEY",
  },
];
const JUDGE_MODELS = [
  { name: "judge-model", provider: "openai-judge", provider_model: "gpt-4o-mini" },
];

function optIn(coveragePercent?: number): Record<string, unknown> {
  return {
    tenant_id: "tenant_optin",
    enabled: true,
    sample_rate: 1,
    judge_model: "judge-model",
    criteria: CRITERIA,
    ...(coveragePercent === undefined ? {} : { coverage_percent: coveragePercent }),
  };
}

interface QueueDouble {
  send(body: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>): Promise<void>;
}

function recordingQueue(): { queue: QueueDouble; bodies: Record<string, unknown>[] } {
  const bodies: Record<string, unknown>[] = [];
  return {
    bodies,
    queue: {
      async send(body: unknown): Promise<void> {
        bodies.push(body as Record<string, unknown>);
      },
      async sendBatch(messages: Iterable<{ body: unknown }>): Promise<void> {
        for (const message of messages) bodies.push(message.body as Record<string, unknown>);
      },
    },
  };
}

function countingRequestIds(prefix: string): RequestIdFactory {
  let n = 0;
  return {
    next: (): string => {
      n += 1;
      return `${prefix}-${n}`;
    },
  };
}

const PRIMARY_ANSWER = "Paris is the capital.";
const FALLBACK_ANSWER = "The capital of France is Paris, population about 2.1 million.";

function ladderProvider(): ProviderInterceptor {
  return interceptProviderFetch((request) => {
    const host = new URL(request.url).host;
    const covered = host.startsWith("api.fallback");
    return providerJson({
      id: covered ? "chatcmpl-fallback" : "chatcmpl-primary",
      object: "chat.completion",
      model: "ladder-model",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: covered ? FALLBACK_ANSWER : PRIMARY_ANSWER },
        },
      ],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    });
  });
}

/** A judge that scores the covered leg's phrasing higher. */
function judgeProvider(): ProviderInterceptor {
  return interceptProviderFetch((request) => {
    const asked = JSON.stringify(request.body ?? {});
    const score = asked.includes("2.1 million") ? 0.9 : 0.4;
    return providerJson({
      id: "chatcmpl-judge",
      object: "chat.completion",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: JSON.stringify({
              scores: [{ criterion: "grounded", score, reason: "judged" }],
            }),
          },
        },
      ],
    });
  });
}

interface Harness {
  call(): Promise<{ response: Response }>;
}

function gateway(bindings: Record<string, unknown>, prefix: string): Harness {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([PRIMARY, FALLBACK]),
        requestIds: countingRequestIds(prefix),
      }),
    ],
    middleware: GATEWAY_MIDDLEWARE,
  });

  return {
    async call(): Promise<{ response: Response }> {
      const context = createExecutionContext();
      const request = new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: {
          authorization: "Bearer fg_coverage_eval",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model: "ladder-model",
          messages: [{ role: "user", content: "what is the capital of France?" }],
        }),
      });
      const response = await app.fetch(request, bindings, context);
      await waitOnExecutionContext(context);
      // The deferred eval half awaits the coverage mirror, which is itself
      // deferred — the same two-phase drain `shadow-scored.test.ts` uses.
      await new Promise((resolve) => setTimeout(resolve, 25));
      await waitOnExecutionContext(context);
      return { response };
    },
  };
}

function gatewayEnv(queue: QueueDouble, policy: Record<string, unknown>): Record<string, unknown> {
  return {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([policy]),
    ONLINE_EVAL: queue,
    AI: (poolEnv as unknown as Record<string, unknown>).AI,
  };
}

let provider: ProviderInterceptor | undefined;

beforeEach(async () => {
  await resetOnlineEvalTables();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

describe("candidate coverage buys a score for a leg that never served", () => {
  it("scores a candidate the client was never served by", async () => {
    provider = ladderProvider();
    const recorder = recordingQueue();
    const h = gateway(gatewayEnv(recorder.queue, optIn(100)), "fg-cov");

    const { response } = await h.call();
    expect(response.status, await response.clone().text()).toBe(200);
    // The CLIENT is still served by the primary. Coverage may not change what
    // anybody is answered with.
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-primary");

    expect(recorder.bodies).toHaveLength(2);
    const served = recorder.bodies.find((body) => body.experiment_arm === undefined);
    const coverage = recorder.bodies.find((body) => body.experiment_arm === "coverage");
    expect(served, "no served-arm sample").toBeDefined();
    expect(coverage, "no coverage sample — the fallback candidate has no score").toBeDefined();
    if (served === undefined || coverage === undefined) return;

    // The coverage sample is a sample OF THE COVERED LEG: its provider, its
    // model, its answer.
    expect(coverage.provider).toBe("azure-eu");
    expect(coverage.provider_model).toBe("gpt-4o-mini-azure");
    expect(coverage.completion).toBe(FALLBACK_ANSWER);
    expect(served.provider).toBe("openai-main");
    expect(served.completion).toBe(PRIMARY_ANSWER);

    // The leg id encodes the covered candidate, so two coverage legs on one
    // request cannot collide on `(request_id, criterion_id)`.
    expect(coverage.request_id).toBe(
      `${String(served.request_id)}~coverage~azure-eu:gpt-4o-mini-azure`,
    );

    // ONE INSTRUMENT, two populations — inherited by value from the served
    // sample, never re-resolved.
    expect(coverage.judge_model).toBe(served.judge_model);
    expect(coverage.criteria).toEqual(served.criteria);
    expect(coverage.prompt).toBe(served.prompt);
    expect(coverage.sampling_key).toBe(served.sampling_key);
    expect(coverage.sample_rate).toBe(served.sample_rate);
    expect(coverage.tenant_id).toBe("tenant_optin");
    // And it belongs to NO experiment: `admin_experiment.ts` groups on
    // `experiment_arm`, and a coverage row inside a real experiment's
    // comparison would be a phantom third arm.
    expect(coverage.experiment_id).toBeUndefined();

    // Now the DEPLOYED consumer, on the bytes the DEPLOYED producer emitted.
    provider.restore();
    provider = judgeProvider();
    await gatewayQueue(
      {
        queue: "ferrogate-online-eval",
        messages: recorder.bodies.map((body, index) => ({
          id: `m${index}`,
          body,
          ack: () => undefined,
          retry: () => undefined,
        })),
      } as never,
      {
        CONTROL_DB: controlDb(),
        CONTROL_DATA: controlNamespace(),
        TENANT_DATA: (poolEnv as unknown as Record<string, unknown>).TENANT_DATA,
        GATEWAY_PROVIDERS: JSON.stringify(JUDGE_PROVIDERS),
        GATEWAY_MODELS: JSON.stringify(JUDGE_MODELS),
        JUDGE_API_KEY: "sk-judge",
      } as never,
    );

    const rows = await storedTenantScores("tenant_optin");
    expect(rows).toHaveLength(2);
    const providers = rows.map((row) => row.provider).sort();
    // THE ASSERTION THIS FILE EXISTS FOR: `azure-eu` has a score, and no client
    // was ever routed to it.
    expect(providers).toEqual(["azure-eu", "openai-main"]);
    expect(rows.find((row) => row.provider === "azure-eu")?.experiment_arm).toBe("coverage");

    // And the per-leg aggregate can now see BOTH legs of the one ladder — which
    // is the thing the router consumes.
    // The recompute reads `online_eval_scores` from the store that now owns them
    // — the tenant object (`projectToControl: false`), not the control mirror.
    const aggregates = await onlineEvalLegAggregates(
      tenantObjectDb("tenant_optin"),
      "tenant_optin",
      Math.floor(Date.now() / 1000),
    );
    expect(aggregates.map((row) => row.provider).sort()).toEqual(["azure-eu", "openai-main"]);
    expect(new Set(aggregates.map((row) => row.logicalModel))).toEqual(new Set(["ladder-model"]));

    // THE CONSUMER HOOK. `consumeOnlineEvalBatch` PROJECTS the aggregate after
    // the scores are durable, and this is the only place that call is driven
    // from the deployed entry point. Without it the table stays empty in every
    // deployment, every leg reads `no_signal`, and the whole slice is a no-op
    // with a green suite — so this reads the PROJECTION, not the recompute. The
    // projection is single-source now: written to the tenant object that owns
    // the scores it derives from, never a control mirror.
    const projected = await readOnlineEvalLegQuality(tenantObjectDb("tenant_optin"), "tenant_optin");
    expect(projected.map((row) => row.provider).sort()).toEqual(["azure-eu", "openai-main"]);
    expect(projected.every((row) => row.scoreCount > 0)).toBe(true);
  });

  it("files the coverage sample under NO experiment, even inside a real one", async () => {
    // ANTI-VACUITY for the `experiment_id` assertion above, which passes in that
    // test whether or not the code drops the field: its served sample carries no
    // experiment, so `undefined` is trivially true. Here the SERVED sample does
    // carry one, so the assertion can only pass if `coverageArmSampleFrom`
    // actually strips it — the defect its docblock names (a coverage row read by
    // the experiment comparator as a phantom third arm).
    const served: OnlineEvalSample = {
      requestId: "fg-served",
      tenantId: "tenant_optin",
      prompt: "what is the capital of France?",
      completion: PRIMARY_ANSWER,
      judgeModel: "judge-model",
      criteria: CRITERIA,
      samplingKey: "fg-served",
      samplingUnit: "request" as const,
      sampleRate: 1,
      promptTruncated: false,
      completionTruncated: false,
      sampledAtUnix: 1_800_000_000,
      provider: "openai-main",
      logicalModel: "ladder-model",
      providerModel: "gpt-4o-mini-2024-07-18",
      experimentId: "exp_live",
      experimentArm: "control",
    };
    const leg = {
      legId: "fg-served~coverage~azure-eu:gpt-4o-mini-azure",
      logicalModel: "ladder-model",
      provider: "azure-eu",
      providerModel: "gpt-4o-mini-azure",
      body: Promise.resolve(undefined),
    };
    const body = JSON.stringify({
      choices: [{ index: 0, message: { role: "assistant", content: FALLBACK_ANSWER } }],
    });

    const sample = coverageArmSampleFrom(served, leg, body);
    expect(sample).toBeDefined();
    expect(sample?.experimentId).toBeUndefined();
    expect(Object.hasOwn(sample as object, "experimentId")).toBe(false);
    expect(sample?.experimentArm).toBe("coverage");
    expect(sample?.provider).toBe("azure-eu");
    // ANTI-VACUITY for THIS test: the shadow constructor over the same served
    // sample DOES carry an experiment id, so the `undefined` above is the
    // coverage constructor stripping it, not a served fixture that never had one.
    expect(served.experimentId).toBe("exp_live");
    expect(
      shadowArmSampleFrom(served, { ...leg, experimentId: "exp_live" }, body)?.experimentId,
    ).toBe("exp_live");
  });

  it("spends nothing for a tenant that did not ask for coverage", async () => {
    // ANTI-VACUITY for the test above, and the money guarantee: `coverage_percent`
    // absent is the DEFAULT for every tenant, including one already opted into
    // evaluation. Exactly one sample, and no second provider was dialled.
    provider = ladderProvider();
    const recorder = recordingQueue();
    const h = gateway(gatewayEnv(recorder.queue, optIn()), "fg-nocov");

    const { response } = await h.call();
    expect(response.status).toBe(200);
    expect(recorder.bodies).toHaveLength(1);
    expect(recorder.bodies[0]?.provider).toBe("openai-main");
    expect(
      provider.requests.some((call) => new URL(call.url).host.startsWith("api.fallback")),
      "a tenant that did not opt into coverage must not have a second provider dialled",
    ).toBe(false);
  });
});
