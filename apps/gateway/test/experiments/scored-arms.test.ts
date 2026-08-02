/**
 * THE ARM REACHES THE SCORE (#693, on top of #692).
 *
 * ## Why this file exists separately from `attribution.test.ts`
 *
 * That file proves the arm reaches `request_logs`, which is the OPERATIONAL
 * half — cost, latency, error rate. This one proves it reaches
 * `online_eval_scores`, which is the QUALITY half, and quality is the half the
 * issue is actually about: an operator can already see that a canary is cheaper
 * or faster, and cannot see whether it is WORSE.
 *
 * The comparison the score table supports is narrow and the narrowness is the
 * whole value (`apps/gateway/src/evals/policy.ts` states it in full): a score
 * row means "judge X, shown this exchange and asked criterion Y, answered Z",
 * which licenses a RELATIVE comparison between two populations scored by the
 * SAME judge under the SAME criterion and nothing else. `experiment_arm` is the
 * third grouping key that turns one tenant's scores into "this arm's against
 * that arm's" — and without it landing on the row, the comparison in
 * `@ferrogate/routing::compareExperimentQuality` has nothing to group.
 *
 * ## What is real
 *
 * The deployed middleware chain (`GATEWAY_MIDDLEWARE`), the real sampler, the
 * real queue wire, the DEPLOYED queue entry point (`gatewayQueue`), the real
 * judge dispatch through `dispatcherFromEnv` with only the outbound `fetch`
 * intercepted, and the real `CONTROL_DB` with the committed migrations. The
 * score rows are read straight back out of the table.
 *
 * Nothing here seeds a score. The row an assertion reads was written by the
 * real consumer from the bytes the real producer emitted.
 */
import { env as poolEnv } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { GATEWAY_MIDDLEWARE, gatewayQueue } from "../../src/index.js";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { controlDb, resetOnlineEvalTables, storedScores } from "../evals/harness.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import { applyControlMigrations } from "./harness.js";

const BASE = "https://gw.test";

const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

const KEYS = [
  {
    key: "fg_exp_eval",
    id: "key_exp_eval",
    tenant_id: "tenant_optin",
    project_id: "project_exp",
    scopes: ["chat.completions"],
  },
];

/** The primary — the CONTROL arm. */
const PRIMARY: PhysicalRoute = {
  logicalModel: "split-model",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.primary.example/v1/",
  apiKey: "sk-primary",
  enabled: true,
  priority: 0,
};

/** The canary at 100%, declared at a LOWER priority so only `applyCanary` promotes it. */
const CANARY: PhysicalRoute = {
  logicalModel: "split-model",
  provider: "anthropic-canary",
  providerModel: "claude-canary-physical",
  providerKind: "openai",
  baseUrl: "https://api.canary.example/v1/",
  apiKey: "sk-canary",
  enabled: true,
  priority: 10,
  canaryPercent: 100,
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

/**
 * A Queue producer double that records the wire bodies the sampler emits.
 *
 * BOTH `send` and `sendBatch`, because `evals/sink.ts::onlineEvalQueueFrom`
 * checks the SHAPE of the binding and answers `undefined` for anything missing
 * either — a deliberate guard there, and a silent "nothing was sampled" here if
 * the double does not satisfy it.
 */
interface QueueDouble {
  send(body: unknown): Promise<void>;
  sendBatch(messages: Iterable<{ body: unknown }>): Promise<void>;
}

function recordingQueue(): { queue: QueueDouble; bodies: unknown[] } {
  const bodies: unknown[] = [];
  return {
    bodies,
    queue: {
      async send(body: unknown): Promise<void> {
        bodies.push(body);
      },
      async sendBatch(messages: Iterable<{ body: unknown }>): Promise<void> {
        for (const message of messages) bodies.push(message.body);
      },
    },
  };
}

function gatewayEnv(queue: QueueDouble): Record<string, unknown> {
  return {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify(KEYS),
    GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([OPT_IN]),
    ONLINE_EVAL: queue,
    AI: (poolEnv as unknown as Record<string, unknown>)["AI"],
  };
}

function chatBody(): unknown {
  return {
    model: "split-model",
    messages: [{ role: "user", content: "what is the capital of France?" }],
  };
}

/**
 * Let the deferred half run.
 *
 * `app.request()` creates no `ExecutionContext`, so the capture runs as a
 * detached promise — the same shape `ctx.waitUntil` gives it in production.
 */
async function settle(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 25));
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

describe("a sampled canary response is scored AS the canary arm", () => {
  it("carries the arm from the response path through the queue onto the score row", async () => {
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-canary",
        object: "chat.completion",
        model: "split-model",
        choices: [{ index: 0, message: { role: "assistant", content: "Paris." } }],
        usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      }),
    );

    const recorder = recordingQueue();
    const { app } = createGatewayApp({
      modules: [inferenceRouteModule({ models: new InMemoryModelResolver([PRIMARY, CANARY]) })],
      // THE DEPLOYED CHAIN, in the deployed order.
      middleware: GATEWAY_MIDDLEWARE,
    });

    // ONE `env` object for both calls, deliberately: the policy source is
    // memoized by a `WeakMap` KEYED ON `env`, so a fresh object per request
    // would hand every request a cold memo and nothing would ever be sampled.
    // That is the deployed shape too — a Worker's `env` is one object.
    const env = gatewayEnv(recorder.queue);

    // TWO requests: the sampler's `peek()` answers only from the isolate memo,
    // so the FIRST request through a cold isolate warms it and is not captured
    // (`evals/middleware.ts` documents the trade at length). Asserting on the
    // second is asserting on the steady state, not working around a bug.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const response = await app.request(
        `${BASE}/v1/chat/completions`,
        {
          method: "POST",
          headers: {
            authorization: "Bearer fg_exp_eval",
            "content-type": "application/json",
          },
          body: JSON.stringify(chatBody()),
        },
        env,
      );
      expect(response.status, await response.clone().text()).toBe(200);
      await settle();
    }

    expect(recorder.bodies.length).toBeGreaterThan(0);
    const wire = recorder.bodies[recorder.bodies.length - 1] as Record<string, unknown>;

    // The sample really is of the CANARY's response — the physical model proves
    // the rollout ran, so the arm below is not a constant.
    expect(wire["provider"]).toBe("anthropic-canary");
    expect(wire["provider_model"]).toBe("claude-canary-physical");
    expect(wire["experiment_arm"]).toBe("canary");
    expect(typeof wire["experiment_id"]).toBe("string");

    // Now the DEPLOYED consumer, on the bytes the DEPLOYED producer emitted.
    provider.restore();
    provider = interceptProviderFetch(() =>
      providerJson({
        id: "chatcmpl-judge",
        object: "chat.completion",
        choices: [
          {
            index: 0,
            message: {
              role: "assistant",
              content: JSON.stringify({
                scores: [{ criterion: "grounded", score: 0.9, reason: "Correct." }],
              }),
            },
          },
        ],
      }),
    );

    await gatewayQueue(
      {
        queue: "ferrogate-online-eval",
        messages: [{ id: "m1", body: wire, ack: () => undefined, retry: () => undefined }],
      } as never,
      {
        CONTROL_DB: controlDb(),
        GATEWAY_PROVIDERS: JSON.stringify(JUDGE_PROVIDERS),
        GATEWAY_MODELS: JSON.stringify(JUDGE_MODELS),
        JUDGE_API_KEY: "sk-judge",
      } as never,
    );

    const scores = await storedScores();
    expect(scores).toHaveLength(1);
    const row = scores[0] as Record<string, unknown>;

    // THE ASSERTION THIS FILE EXISTS FOR. Without the arm on the score row,
    // `compareExperimentQuality` has one undifferentiated population and can
    // only ever answer "incomparable" — i.e. the whole quality half of the
    // issue is inert.
    expect(row["experiment_arm"]).toBe("canary");
    expect(row["experiment_id"]).toBe(wire["experiment_id"]);

    // And the two axes a comparison may NOT cross are on the same row, which is
    // what lets the grouped read pair arms only within one instrument.
    expect(row["judge_model"]).toBe("judge-model");
    expect(row["criterion_id"]).toBe("grounded");
  });
});
