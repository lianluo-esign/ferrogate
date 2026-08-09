/**
 * THE SHADOW ARM CARRIES AN EVAL SCORE (#693, closing the last Done-when).
 *
 * ## The gap this file closes
 *
 * `attribution.test.ts` proves the shadow arm reaches `experiment_shadow_legs`
 * — cost, latency, error rate. `scored-arms.test.ts` proves the CANARY arm
 * reaches `online_eval_scores`. Between them the shadow arm had every
 * operational number and no quality number, so `compareExperimentQuality` on a
 * control+shadow split could only ever answer `variant_arm_not_scored`: an
 * operator running a shadow experiment learned what the variant COST and never
 * whether it was BETTER, which is the only question the feature exists for.
 *
 * The mirror's response is discarded by design (`inference/shadow.ts` lists the
 * five mechanisms). Scoring it therefore means RETAINING it exactly as long as
 * it takes to build one eval sample, and only for a request the tenant's own
 * eval policy already authorised content capture on.
 *
 * ## The comparability rule is INHERITED, never re-decided
 *
 * The shadow sample is derived from the SERVED sample object
 * (`evals/shadow-leg.ts::shadowArmSampleFrom`), so `judge_model`, `criteria`,
 * `sampling_key`, `sample_rate` and the prompt are the SAME VALUES, not a second
 * resolution that could disagree. That is what the assertions below check
 * directly: two rows, one instrument. If the shadow path ever grew its own
 * policy lookup, these would still be two scores — and
 * `compareExperimentQuality` would silently start comparing two instruments.
 *
 * ## What is real
 *
 * The deployed middleware chain (`GATEWAY_MIDDLEWARE`), the real sampler, the
 * real shadow dispatch, the real queue wire, the DEPLOYED queue entry point
 * (`gatewayQueue`), the real judge dispatch with only the outbound `fetch`
 * intercepted, and the real `CONTROL_DB` with the committed migrations. Nothing
 * here seeds a score row.
 */
import { createExecutionContext, env as poolEnv, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { shadowEvalLegFor } from "../../src/evals/index.js";
import { GATEWAY_MIDDLEWARE, gatewayQueue } from "../../src/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { controlDb, resetOnlineEvalTables, storedScores } from "../evals/harness.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { controlNamespace } from "../support/control-namespace.js";
import { applyControlMigrations } from "./harness.js";

const BASE = "https://gw.test";

const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

const KEYS = [
  {
    key: "fg_shadow_eval",
    id: "key_shadow_eval",
    tenant_id: "tenant_optin",
    project_id: "project_exp",
    scopes: ["chat.completions"],
  },
];

/** The primary — the CONTROL arm, and the only arm a client ever sees. */
const PRIMARY: PhysicalRoute = {
  logicalModel: "split-model",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.primary.example/v1/",
  apiKey: "sk-primary",
  enabled: true,
  priority: 0,
  region: "eu-west-1",
  zeroDataRetention: true,
};

/** The mirror. Never servable; `servableCandidates` strips it. */
const SHADOW: PhysicalRoute = {
  logicalModel: "split-model",
  provider: "mirror-provider",
  providerModel: "mirror-physical",
  providerKind: "openai",
  baseUrl: "https://api.mirror.example/v1/",
  apiKey: "sk-mirror",
  enabled: true,
  priority: 20,
  shadowPercent: 100,
  region: "eu-west-1",
  zeroDataRetention: true,
};

/** The judge's own route, resolved from the deployed `GATEWAY_MODELS` var. */
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

const OPT_IN = {
  tenant_id: "tenant_optin",
  enabled: true,
  sample_rate: 1,
  judge_model: "judge-model",
  criteria: CRITERIA,
};

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

/** Distinct ids per request: the score table's PK is `(request_id, criterion)`. */
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
const MIRROR_ANSWER = "The capital of France is Paris, population about 2.1 million.";

/** One completion body per upstream host, so the two arms are distinguishable. */
function splitProvider(): ProviderInterceptor {
  return interceptProviderFetch((request) => {
    const host = new URL(request.url).host;
    const mirrored = host.startsWith("api.mirror");
    return providerJson({
      id: mirrored ? "chatcmpl-mirror" : "chatcmpl-primary",
      object: "chat.completion",
      model: "split-model",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: mirrored ? MIRROR_ANSWER : PRIMARY_ANSWER },
        },
      ],
      usage: mirrored
        ? { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 }
        : { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    });
  });
}

/** A judge that answers the rubric, scoring the MIRROR's answer higher. */
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

/**
 * Has `promise` already settled?
 *
 * Raced against a real timer rather than against a resolved promise: microtask
 * ordering inside `Promise.race` is subtle enough that a same-tick race would
 * be a coin flip, and a flaky liveness assertion is worse than none.
 */
async function hasSettled(promise: Promise<unknown>): Promise<boolean> {
  return Promise.race([
    promise.then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 50)),
  ]);
}

interface Harness {
  /** Drive one request through the deployed chain and drain `waitUntil`. */
  call(): Promise<{ response: Response; request: Request }>;
}

function gateway(
  routes: readonly PhysicalRoute[],
  bindings: Record<string, unknown>,
  prefix: string,
): Harness {
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([...routes]),
        requestIds: countingRequestIds(prefix),
      }),
    ],
    // THE DEPLOYED CHAIN, in the deployed order — `residency()` immediately
    // ahead of `onlineEvaluation()` is the edge the ZDR refusal below rides on.
    middleware: GATEWAY_MIDDLEWARE,
  });

  return {
    async call(): Promise<{ response: Response; request: Request }> {
      const context = createExecutionContext();
      const request = new Request(`${BASE}/v1/chat/completions`, {
        method: "POST",
        headers: {
          authorization: "Bearer fg_shadow_eval",
          "content-type": "application/json",
        },
        body: JSON.stringify({
          model: "split-model",
          messages: [{ role: "user", content: "what is the capital of France?" }],
        }),
      });
      const response = await app.fetch(request, bindings, context);
      await waitOnExecutionContext(context);
      // The deferred eval half awaits the mirror, which is itself deferred.
      await new Promise((resolve) => setTimeout(resolve, 25));
      await waitOnExecutionContext(context);
      return { response, request };
    },
  };
}

function gatewayEnv(
  queue: QueueDouble,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([OPT_IN]),
    ONLINE_EVAL: queue,
    AI: (poolEnv as unknown as Record<string, unknown>).AI,
    ...extra,
  };
}

let provider: ProviderInterceptor | undefined;

beforeEach(async () => {
  await applyControlMigrations();
  await resetOnlineEvalTables();
});

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

describe("a control+shadow split scores BOTH arms under one instrument", () => {
  it("files the mirror's own answer as `shadow` beside the served answer as `control`", async () => {
    provider = splitProvider();

    const recorder = recordingQueue();
    const env = gatewayEnv(recorder.queue);
    const h = gateway([PRIMARY, SHADOW], env, "fg-shadoweval");

    // ONE request. `GATEWAY_ONLINE_EVAL_POLICIES` is a VAR-backed source, so
    // `peek()` is warm on the first call (`evals/source.ts`) and there is no
    // cold-isolate request to burn.
    const { response } = await h.call();
    expect(response.status, await response.clone().text()).toBe(200);
    // The client got the PRIMARY's answer. Retaining the mirror for scoring must
    // not become a sixth way to break that guarantee.
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-primary");

    // Exactly two samples from that ONE request: the served arm and the mirror.
    expect(recorder.bodies).toHaveLength(2);
    const control = recorder.bodies.find((body) => body.experiment_arm === "control");
    const shadow = recorder.bodies.find((body) => body.experiment_arm === "shadow");
    expect(control, "no control-arm sample").toBeDefined();
    expect(shadow, "no shadow-arm sample — the shadow arm carries no eval score").toBeDefined();
    if (control === undefined || shadow === undefined) return;

    // The shadow sample is a sample OF THE MIRROR: its provider, its model, its
    // answer. A sample carrying the primary's completion under the shadow label
    // would be worse than no shadow score at all.
    expect(shadow.provider).toBe("mirror-provider");
    expect(shadow.provider_model).toBe("mirror-physical");
    expect(shadow.completion).toBe(MIRROR_ANSWER);
    expect(control.completion).toBe(PRIMARY_ANSWER);

    // Filed under the LEG id — derived from the id the client was told, so the
    // shadow score joins `experiment_shadow_legs` and cannot collide with the
    // served arm's score for the same request.
    expect(shadow.request_id).toBe(`${String(control.request_id)}~shadow`);

    // THE COMPARABILITY PRECONDITION, on the wire. Same judge, same criteria,
    // same prompt, same experiment — one instrument, two populations.
    expect(shadow.judge_model).toBe(control.judge_model);
    expect(shadow.criteria).toEqual(control.criteria);
    expect(shadow.prompt).toBe(control.prompt);
    expect(shadow.experiment_id).toBe(control.experiment_id);
    expect(shadow.sampling_key).toBe(control.sampling_key);
    expect(shadow.sample_rate).toBe(control.sample_rate);
    expect(shadow.tenant_id).toBe("tenant_optin");

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

    const rows = await storedScores();
    expect(rows).toHaveLength(2);
    const arms = rows.map((row) => row.experiment_arm).sort();
    // THE ASSERTION THIS FILE EXISTS FOR. Without a `shadow` row here the
    // comparator has one population and can only answer `variant_arm_not_scored`.
    expect(arms).toEqual(["control", "shadow"]);

    // And both rows are the same instrument, so `compareExperimentQuality` has a
    // pair to subtract rather than two incomparable cells.
    expect(new Set(rows.map((row) => row.judge_model))).toEqual(new Set(["judge-model"]));
    expect(new Set(rows.map((row) => row.criterion_id))).toEqual(new Set(["grounded"]));
    expect(new Set(rows.map((row) => row.experiment_id))).toHaveProperty("size", 1);

    // The judge really was shown the mirror's answer: it scores anything
    // containing the mirror's phrasing higher, so a shadow row that had been
    // built from the primary's completion would carry 0.4 here.
    const shadowRow = rows.find((row) => row.experiment_arm === "shadow");
    expect(shadowRow?.score).toBeCloseTo(0.9, 6);
    expect(rows.find((row) => row.experiment_arm === "control")?.score).toBeCloseTo(0.4, 6);
  });
});

describe("#681 governs the eval leg, not just the mirror", () => {
  it("never shadow-SCORES a region-pinned tenant, while still scoring its control arm", async () => {
    provider = splitProvider();

    const recorder = recordingQueue();
    const env = gatewayEnv(recorder.queue, {
      // The tenant is pinned to `eu-west-1`. The primary declares it; the
      // mirror does not.
      GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
        { tenant_id: "tenant_optin", residency_regions: ["eu-west-1"] },
      ]),
    });
    const h = gateway([PRIMARY, { ...SHADOW, region: "us-east-1" }], env, "fg-shadowregion");

    const { response } = await h.call();
    expect(response.status, await response.clone().text()).toBe(200);

    // The mirror never left the region — so there is no third copy of the
    // prompt, and nothing to score.
    expect(
      provider.requests.filter((request) => new URL(request.url).host.startsWith("api.mirror")),
    ).toHaveLength(0);

    // The tenant's OWN arm is still measured. A residency refusal that silently
    // switched the whole feature off for a governed tenant would be a different
    // and worse bug than the one it prevents.
    expect(recorder.bodies).toHaveLength(1);
    expect(recorder.bodies[0]?.experiment_arm).toBe("control");
    expect(recorder.bodies.some((body) => body.experiment_arm === "shadow")).toBe(false);
  });

  it("never copies a ZERO-DATA-RETENTION tenant's exchange to a judge, on either arm", async () => {
    provider = splitProvider();

    const recorder = recordingQueue();
    const env = gatewayEnv(recorder.queue, {
      // ZDR, and BOTH routes assert zero data retention — so the mirror itself
      // is compliant and really does run. What must not happen is the mirrored
      // exchange being copied to a judge and a derived row written for it.
      GATEWAY_RESIDENCY_POLICIES: JSON.stringify([
        { tenant_id: "tenant_optin", require_zero_data_retention: true },
      ]),
    });
    const h = gateway([PRIMARY, SHADOW], env, "fg-shadowzdr");

    const { response, request } = await h.call();
    expect(response.status, await response.clone().text()).toBe(200);

    // The mirror DID run — this is not a test of "nothing happened".
    expect(
      provider.requests.filter((r) => new URL(r.url).host.startsWith("api.mirror")).length,
    ).toBeGreaterThan(0);

    // And not one exchange was enqueued for judging, on either arm.
    expect(recorder.bodies).toHaveLength(0);

    // THE RETENTION GATE ITSELF, not just its downstream effect. Nothing about
    // the mirrored response was held for this request at all: the sampler never
    // asked, so `route-module.ts` published no leg and `runShadowMirror` read
    // the body for its token counts and dropped it. A ZDR tenant's third copy
    // of the prompt never becomes a fourth thing waiting to be scored.
    expect(shadowEvalLegFor(request)).toBeUndefined();
  });
});

describe("the shadow arm is held to the SAME evaluability rule as the served arm", () => {
  it("scores no shadow sample when the mirror did not answer 200, and still settles", async () => {
    provider = interceptProviderFetch((request) => {
      if (new URL(request.url).host.startsWith("api.mirror")) {
        // A NON-200 whose body a judge could perfectly well be shown. That is
        // the case worth pinning: refusing on the STATUS is what stops an arm's
        // mean being dragged down whenever the mirrored provider has a bad hour
        // — a reliability problem read as a quality regression. A refusal shaped
        // so that the extractor happened to fail would prove nothing.
        return new Response(
          JSON.stringify({
            id: "chatcmpl-mirror-degraded",
            object: "chat.completion",
            choices: [
              { index: 0, message: { role: "assistant", content: "I cannot help right now." } },
            ],
          }),
          { status: 503, headers: { "content-type": "application/json" } },
        );
      }
      return providerJson({
        id: "chatcmpl-primary",
        object: "chat.completion",
        model: "split-model",
        choices: [{ index: 0, message: { role: "assistant", content: PRIMARY_ANSWER } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      });
    });

    const recorder = recordingQueue();
    const h = gateway([PRIMARY, SHADOW], gatewayEnv(recorder.queue), "fg-shadow503");

    const { response, request } = await h.call();
    expect(response.status, await response.clone().text()).toBe(200);

    // The mirror ran and failed — its operational failure is still the shadow
    // arm's, and `experiment_shadow_legs` records it (see `attribution.test.ts`).
    expect(
      provider.requests.filter((r) => new URL(r.url).host.startsWith("api.mirror")).length,
    ).toBeGreaterThan(0);

    // But no quality row is fabricated from a degraded provider's answer.
    expect(recorder.bodies).toHaveLength(1);
    expect(recorder.bodies[0]?.experiment_arm).toBe("control");

    // AND the leg still SETTLED. This is the half that has no visible symptom:
    // the sampler awaits `leg.body` from inside `ctx.waitUntil`, so a path that
    // declines to score and forgets to settle leaves that wait pending until
    // the platform kills the isolate — on every mirrored request that took it.
    const leg = shadowEvalLegFor(request);
    expect(leg, "the sampler asked for retention, so a leg must be published").toBeDefined();
    expect(leg === undefined ? undefined : await hasSettled(leg.body)).toBe(true);
  });
});
