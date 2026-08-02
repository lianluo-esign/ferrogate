/**
 * ONLINE-EVALUATION SAMPLING (#692), driven through the DEPLOYED middleware
 * chain.
 *
 * ## Why this file composes `GATEWAY_MIDDLEWARE`
 *
 * The same reason `test/attribution/enforcement.test.ts` gives: the property
 * being claimed — "a sampled request is captured and queued, and an unsampled
 * one is not" — belongs to the chain the Worker actually runs, not to a
 * middleware that exists in `src/` and is mounted nowhere. Deleting
 * `onlineEvaluation(onlineEvals)` from the composition root must be RED here,
 * and it is (see the mutation log below).
 *
 * Only the route module (an in-memory model resolver + a deterministic
 * request-id factory), the outbound provider `fetch`, and the `ONLINE_EVAL`
 * Queue binding are doubles. The policy source, the sampler, the capture and
 * the sink are the shipped ones.
 *
 * ## MUTATION LOG — what was broken, and what went red
 *
 * | mutation (in `src/`)                                              | red |
 * |--------------------------------------------------------------------|-----|
 * | `index.ts`: `onlineEvaluation(onlineEvals)` unmounted               | 4 of the cases here + 2 in `mount.test.ts` |
 * | `policy.ts`: BOTH ZDR arms deleted (the plan's and the decision's)   | `never samples a zero-data-retention tenant, even one that opted in` |
 * | `policy.ts`: `policy === null` defaults to an enabled policy         | `queues nothing for a tenant with no policy` + `queues nothing when NO tenant has a policy at all` |
 * | `middleware.ts`: the capture is `await`ed instead of deferred        | `serves normally when the queue never settles` (timed out) + `answers the client before the sample is enqueued` |
 *
 * One recorded NON-result, because it is the kind of thing this repository
 * insists be said out loud: deleting ONE of the two ZDR arms leaves this file
 * green, because `onlineEvalCapturePlan` delegates its final answer to
 * `onlineEvalSamplingDecision`, which checks ZDR again. The exclusion is held
 * twice on purpose; the mutation that proves the property therefore has to
 * remove both, and it does.
 *
 * Likewise, dropping the `evaluableResponse` guard alone does NOT turn this
 * file red — a streamed body is not JSON, so the capture fails one step later
 * and nothing is queued either way. The guard is held instead by
 * `test/evals/skip-reasons.test.ts`, which asserts the REASON, and that file
 * does go red.
 */
import { env as poolEnv } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";

import { ONLINE_EVAL_SAMPLE_OBJECT, onlineEvalSampleFromWire } from "../../src/evals/index.js";
import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
  providerSse,
} from "../inference/provider-mock.js";

const BASE = "https://gw.test";

/**
 * The served route ASSERTS zero data retention.
 *
 * Load-bearing for the ZDR case, and the reason it is not the shared fixture:
 * with an unasserted route, `residency()` refuses a ZDR tenant's request with
 * `403` and nothing would be sampled because nothing was SERVED — the
 * assertion would pass for the wrong reason. Asserting ZDR on the route makes
 * the request succeed, so "no sample was queued" can only be the sampler's own
 * exclusion.
 */
const ZDR_ROUTE: PhysicalRoute = { ...OPENAI_ROUTE, zeroDataRetention: true };

const KEYS = [
  { key: "fg_optin", id: "key_optin", tenant_id: "tenant_optin", project_id: "project_1" },
  { key: "fg_plain", id: "key_plain", tenant_id: "tenant_plain", project_id: "project_2" },
  { key: "fg_zdr", id: "key_zdr", tenant_id: "tenant_zdr", project_id: "project_3" },
];

const CRITERIA = [
  { id: "answer_relevance", definition: "Does the answer address the question asked?" },
];

function incrementingRequestIds(): RequestIdFactory {
  let next = 0;
  return {
    next: (): string => {
      next += 1;
      return `fg-${next.toString(16).padStart(16, "0")}`;
    },
  };
}

/** A Queue producer double that records bodies and can be made to hang. */
function recordingQueue(options: { readonly hang?: boolean } = {}) {
  const bodies: unknown[] = [];
  let sentAt = -1;
  let tick = 0;
  const queue = {
    async send(body: unknown): Promise<void> {
      bodies.push(body);
      tick += 1;
      sentAt = tick;
      if (options.hang === true) {
        // Never settles. A middleware that awaited this before returning would
        // hang the client's response, which is exactly the property under test.
        await new Promise<void>(() => {});
      }
    },
    async sendBatch(): Promise<void> {},
  };
  return {
    queue,
    bodies,
    get sentAt(): number {
      return sentAt;
    },
    mark(): number {
      tick += 1;
      return tick;
    },
  };
}

interface EvalPolicyVar {
  readonly tenant_id: string;
  readonly enabled: boolean;
  readonly sample_rate: number;
  readonly sampling_unit?: "request" | "conversation";
  readonly judge_model: string;
  readonly criteria: readonly { id: string; definition: string }[];
}

interface Harness {
  readonly queue: ReturnType<typeof recordingQueue>;
  call(key: string, body: unknown, headers?: Record<string, string>): Promise<Response>;
}

function gateway(
  options: {
    readonly policies?: readonly EvalPolicyVar[];
    readonly residency?: readonly Record<string, unknown>[];
    readonly route?: PhysicalRoute;
    readonly hang?: boolean;
    readonly withQueue?: boolean;
  } = {},
): Harness {
  const queue = recordingQueue({ hang: options.hang === true });
  const env: Record<string, unknown> = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    ...(options.policies === undefined
      ? {}
      : { GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify(options.policies) }),
    ...(options.residency === undefined
      ? {}
      : { GATEWAY_RESIDENCY_POLICIES: JSON.stringify(options.residency) }),
    ...(options.withQueue === false ? {} : { ONLINE_EVAL: queue.queue }),
    // The pool's real AI binding is irrelevant here but keeps `env` shaped like
    // the deployed one for anything that probes it.
    AI: (poolEnv as unknown as Record<string, unknown>)["AI"],
  };

  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([options.route ?? OPENAI_ROUTE]),
        requestIds: incrementingRequestIds(),
      }),
    ],
    // THE LINE UNDER TEST: the deployed chain, in the deployed order.
    middleware: GATEWAY_MIDDLEWARE,
  });

  return {
    queue,
    call: async (key, body, headers = {}) =>
      app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${key}`,
            "content-type": "application/json",
            ...headers,
          },
          body: JSON.stringify(body),
        },
        env,
      ),
  };
}

function chat(content = "what is the capital of France?", extra: Record<string, unknown> = {}) {
  return {
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are terse." },
      { role: "user", content },
    ],
    ...extra,
  };
}

let provider: ProviderInterceptor | undefined;

function upstreamAnswers(text = "Paris."): ProviderInterceptor {
  provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      model: "gpt-4o-mini",
      choices: [{ index: 0, message: { role: "assistant", content: text } }],
      usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
    }),
  );
  return provider;
}

function upstreamStreams(): ProviderInterceptor {
  provider = interceptProviderFetch(() =>
    providerSse([
      'data: {"id":"1","object":"chat.completion.chunk","choices":[{"delta":{"content":"Paris."}}]}',
      "data: [DONE]",
    ]),
  );
  return provider;
}

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

/**
 * Let the deferred half run.
 *
 * `app.request()` creates no `ExecutionContext`, so the capture runs as a
 * detached promise (the same shape `ctx.waitUntil` gives it in production). A
 * macrotask turn is enough for the clone reads and the enqueue; the NEGATIVE
 * assertions use the same wait, so "nothing was queued" is measured after the
 * same amount of time in which a positive case would have queued.
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 25));
}

const OPT_IN: EvalPolicyVar = {
  tenant_id: "tenant_optin",
  enabled: true,
  sample_rate: 1,
  judge_model: "judge-model",
  criteria: CRITERIA,
};

describe("an opted-in tenant's traffic is sampled and queued", () => {
  it("captures the exchange with the attribution a cost row can be joined on", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN] });

    const response = await h.call("fg_optin", chat());
    expect(response.status).toBe(200);
    await settle();

    expect(h.queue.bodies).toHaveLength(1);
    const wire = h.queue.bodies[0] as Record<string, unknown>;
    expect(wire["object"]).toBe(ONLINE_EVAL_SAMPLE_OBJECT);

    const sample = onlineEvalSampleFromWire(wire);
    if (sample === undefined) throw new Error("the queued body did not decode as a sample");

    // The join key: the id the CLIENT was told, which is what #664's request
    // log and #677's cost record are both filed under.
    expect(sample.requestId).toBe(response.headers.get("x-request-id"));
    expect(sample.tenantId).toBe("tenant_optin");
    expect(sample.projectId).toBe("project_1");
    expect(sample.apiKeyId).toBe("key_optin");
    expect(sample.logicalModel).toBe("gpt-4o-mini");
    expect(sample.providerModel).toBe("gpt-4o-mini-2024-07-18");
    expect(sample.operationId).toBe("createChatCompletion");

    // The content actually reached the judge's envelope — roles kept, both
    // sides present. Without this the pipeline could queue an empty sample and
    // every later assertion would still pass.
    expect(sample.prompt).toContain("system: You are terse.");
    expect(sample.prompt).toContain("user: what is the capital of France?");
    expect(sample.completion).toBe("Paris.");
    expect(sample.judgeModel).toBe("judge-model");
    expect(sample.criteria).toEqual(CRITERIA);
    expect(sample.sampleRate).toBe(1);
  });

  it("keys a conversation-unit sample on the conversation, not the request", async () => {
    upstreamAnswers();
    const h = gateway({
      policies: [{ ...OPT_IN, sampling_unit: "conversation" }],
    });

    await h.call("fg_optin", chat(), { "x-ferrogate-conversation-id": "conv-42" });
    await h.call("fg_optin", chat("and of Spain?"), {
      "x-ferrogate-conversation-id": "conv-42",
    });
    await settle();

    const samples = h.queue.bodies.map((body) => onlineEvalSampleFromWire(body));
    expect(samples).toHaveLength(2);
    for (const sample of samples) {
      expect(sample?.samplingUnit).toBe("conversation");
      // Both turns share the bucket key, which is what makes "did THIS
      // conversation get worse" a `GROUP BY` rather than a reconstruction.
      expect(sample?.samplingKey).toBe("conv-42");
    }
  });
});

describe("nobody is sampled who did not ask", () => {
  it("queues nothing for a tenant with no policy", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN] });

    const response = await h.call("fg_plain", chat());
    expect(response.status).toBe(200);
    await settle();

    expect(h.queue.bodies).toEqual([]);
  });

  it("queues nothing when NO tenant has a policy at all", async () => {
    upstreamAnswers();
    const h = gateway();

    expect((await h.call("fg_optin", chat())).status).toBe(200);
    await settle();

    expect(h.queue.bodies).toEqual([]);
  });

  it("never samples a zero-data-retention tenant, even one that opted in", async () => {
    // The route asserts ZDR, so the request is SERVED (a refusal would make
    // this pass for the wrong reason) — and still nothing is copied anywhere.
    upstreamAnswers();
    const h = gateway({
      route: ZDR_ROUTE,
      policies: [{ ...OPT_IN, tenant_id: "tenant_zdr" }],
      residency: [{ tenant_id: "tenant_zdr", require_zero_data_retention: true }],
    });

    const response = await h.call("fg_zdr", chat());
    expect(response.status).toBe(200);
    await settle();

    expect(h.queue.bodies).toEqual([]);
  });
});

describe("what cannot be judged is not queued", () => {
  it("does not sample a streamed response", async () => {
    upstreamStreams();
    const h = gateway({ policies: [OPT_IN] });

    const response = await h.call("fg_optin", chat("stream please", { stream: true }));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    await response.text();
    await settle();

    expect(h.queue.bodies).toEqual([]);
  });

  it("does not sample a refused request", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN] });

    // An unknown model is refused before any provider is dialled; there is no
    // answer to judge, and scoring error envelopes would drag every mean down
    // whenever an upstream had a bad hour.
    const response = await h.call("fg_optin", { model: "nope", messages: [] });
    expect(response.status).toBeGreaterThanOrEqual(400);
    await settle();

    expect(h.queue.bodies).toEqual([]);
  });
});

describe("the caller's latency is untouched", () => {
  it("answers the client before the sample is enqueued", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN] });

    const response = await h.call("fg_optin", chat());
    const answeredAt = h.queue.mark();
    expect(response.status).toBe(200);
    // The body is fully readable at this point — nothing is holding it.
    expect(await response.json()).toMatchObject({ object: "chat.completion" });
    await settle();

    expect(h.queue.bodies).toHaveLength(1);
    // The enqueue happened STRICTLY after the response was in the caller's
    // hands. `await`ing the sink before `next()` returns turns this red.
    expect(h.queue.sentAt).toBeGreaterThan(answeredAt);
  });

  it("serves normally when the queue never settles", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN], hang: true });

    const response = await h.call("fg_optin", chat());

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ object: "chat.completion" });
  });

  it("serves normally when no evaluation queue is bound at all", async () => {
    upstreamAnswers();
    const h = gateway({ policies: [OPT_IN], withQueue: false });

    const response = await h.call("fg_optin", chat());

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ object: "chat.completion" });
  });
});
