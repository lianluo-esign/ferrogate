/**
 * ARM ATTRIBUTION, end to end on real bindings (#693).
 *
 * ## The defect
 *
 * `packages/routing` has split traffic since #276 — `applyCanary` promotes a
 * sticky percentage of callers onto a variant route, `shadowMirrorFor` mirrors a
 * budgeted fraction to a second provider — and NOTHING recorded which arm
 * served a request. `request_logs` carried tenant, model, latency, status and
 * tokens for every request and no column said "this one was the canary"; the
 * shadow leg produced no durable record at all, so an entire arm's cost,
 * latency and error rate were invisible by construction.
 *
 * Every downstream number therefore existed and could not be grouped: #677's
 * per-request cost, #664's latency, #692's eval scores. "Is the canary better"
 * was unanswerable from data the product already held.
 *
 * ## What is real here
 *
 * The composed gateway (`createGatewayApp`), the contract router, the auth
 * guard, the whole middleware chain, the inference dispatch path, the real
 * `CONTROL_DB` D1 binding with the committed migrations, and an
 * `ExecutionContext` from `cloudflare:test` so `waitUntil` is the real one. The
 * ONLY thing intercepted is the outbound provider `fetch`.
 *
 * Nothing here seeds a row. Every row an assertion finds was written by a real
 * HTTP request flowing through the real chain.
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { experimentIdFor } from "@ferrogate/routing";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import {
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogging,
} from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
} from "../inference/provider-mock.js";
import {
  applyControlMigrations,
  resetExperimentTables,
  storedRequestLogs,
  storedShadowLegs,
} from "./harness.js";

const BASE = "https://gw.test";
const AUTHED = { authorization: "Bearer fg_exp_tenant", "content-type": "application/json" };

const EXP_TENANT_KEY = JSON.stringify([
  {
    key: "fg_exp_tenant",
    id: "key_exp_tenant",
    tenant_id: "tenant_a",
    project_id: "project_exp",
    scopes: ["chat.completions", "messages.create", "models.read"],
  },
]);

/** The primary route — the CONTROL arm. */
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

/**
 * The canary at 100%, declared at a LOWER priority than the primary so nothing
 * but `applyCanary` can promote it — the same construction
 * `test/inference/reliability.test.ts` uses, and what makes a green assertion
 * mean the rollout ran rather than that the ladder happened to order this first.
 */
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
  inputPricePer1m: 1_000_000,
  outputPricePer1m: 2_000_000,
};

/** A model with no split at all — the control for this whole suite. */
const UNSPLIT: PhysicalRoute = {
  logicalModel: "plain-model",
  provider: "openai-main",
  providerModel: "gpt-4o-mini-2024-07-18",
  providerKind: "openai",
  baseUrl: "https://api.primary.example/v1/",
  apiKey: "sk-primary",
  enabled: true,
};

function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

interface Harness {
  call(path: string, init: RequestInit): Promise<Response>;
  settle(): Promise<void>;
}

function gateway(routes: readonly PhysicalRoute[], requestId: string): Harness {
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    // No `REQUEST_LOG` queue producer, so the sink takes its DIRECT-D1 arm —
    // the `wrangler dev --local` posture, and the one whose rows this suite
    // reads back out of the real `CONTROL_DB`.
    REQUEST_LOG: undefined,
    GATEWAY_NATIVE_API_KEYS: EXP_TENANT_KEY,
  };
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([...routes]),
        requestIds: fixedRequestIds(requestId),
      }),
    ],
    middleware: [requestLogging(createRequestLogSink(requestLogBindingsFromEnv))],
  });

  let context: ExecutionContext | undefined;
  return {
    async call(path, init): Promise<Response> {
      context = createExecutionContext();
      return app.fetch(new Request(`${BASE}${path}`, init), bindings, context);
    },
    async settle(): Promise<void> {
      if (context !== undefined) await waitOnExecutionContext(context);
    },
  };
}

function chatBody(model: string): string {
  return JSON.stringify({ model, messages: [{ role: "user", content: "hi" }] });
}

const COMPLETION = {
  id: "chatcmpl-1",
  object: "chat.completion",
  model: "split-model",
  choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

let provider: ProviderInterceptor | undefined;

beforeAll(applyControlMigrations);
beforeEach(resetExperimentTables);
afterEach(() => {
  provider?.restore();
  provider = undefined;
});

describe("the served arm is recorded on the request log", () => {
  it("labels a canary-served request `canary` under the split's experiment id", async () => {
    expect(await storedRequestLogs()).toHaveLength(0);

    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const h = gateway([PRIMARY, CANARY, SHADOW], "fg-canary-1");
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody("split-model"),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await h.settle();

    const rows = await storedRequestLogs();
    expect(rows).toHaveLength(1);
    const row = rows[0] as NonNullable<(typeof rows)[0]>;

    // The canary really did serve it — the physical model proves the rollout
    // ran, so the arm label below is not a constant.
    expect(row.provider).toBe("anthropic-canary");
    expect(row.provider_model).toBe("claude-canary-physical");
    expect(row.experiment_arm).toBe("canary");

    // And the id is the one `packages/routing` computes from the split, which
    // is what makes the gateway's writes and the control plane's reads land on
    // the same experiment.
    expect(row.experiment_id).toBe(
      experimentIdFor({
        logicalModel: "split-model",
        control: { provider: "openai-main", providerModel: "gpt-4o-mini-2024-07-18" },
        canary: { provider: "anthropic-canary", providerModel: "claude-canary-physical" },
        shadow: { provider: "mirror-provider", providerModel: "mirror-physical" },
      }),
    );
  });

  it("labels a primary-served request `control` under the SAME experiment id", async () => {
    // Canary at 0% — the split still exists (so the experiment still exists),
    // but this caller is not in it. Same experiment id: the control arm of an
    // experiment is filed under the experiment, or the two arms could never be
    // compared.
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const h = gateway([PRIMARY, { ...CANARY, canaryPercent: 0 }, SHADOW], "fg-control-1");
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody("split-model"),
    });
    expect(response.status).toBe(200);
    await h.settle();

    const row = (await storedRequestLogs())[0] as NonNullable<
      Awaited<ReturnType<typeof storedRequestLogs>>[0]
    >;
    expect(row.provider).toBe("openai-main");
    expect(row.experiment_arm).toBe("control");
    expect(row.experiment_id).toBe(
      experimentIdFor({
        logicalModel: "split-model",
        control: { provider: "openai-main", providerModel: "gpt-4o-mini-2024-07-18" },
        canary: { provider: "anthropic-canary", providerModel: "claude-canary-physical" },
        shadow: { provider: "mirror-provider", providerModel: "mirror-physical" },
      }),
    );
  });

  it("leaves both columns NULL for a model that is not split", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const h = gateway([UNSPLIT], "fg-plain-1");
    expect(
      (
        await h.call("/v1/chat/completions", {
          method: "POST",
          headers: AUTHED,
          body: chatBody("plain-model"),
        })
      ).status,
    ).toBe(200);
    await h.settle();

    const row = (await storedRequestLogs())[0] as NonNullable<
      Awaited<ReturnType<typeof storedRequestLogs>>[0]
    >;
    // A model with no variant is not an experiment. Minting an id for it would
    // fill the reporting surface with single-arm "experiments".
    expect(row.experiment_id).toBeNull();
    expect(row.experiment_arm).toBeNull();
  });
});

describe("the shadow arm is recorded even though nobody was served it", () => {
  it("writes one leg row with the mirror's own latency, status, tokens and OPERATOR cost", async () => {
    expect(await storedShadowLegs()).toHaveLength(0);

    provider = interceptProviderFetch((request) => {
      const host = new URL(request.url).host;
      return providerJson({
        ...COMPLETION,
        id: host.startsWith("api.mirror") ? "chatcmpl-mirror" : "chatcmpl-primary",
        usage: host.startsWith("api.mirror")
          ? { prompt_tokens: 20, completion_tokens: 10, total_tokens: 30 }
          : { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
      });
    });
    const h = gateway([PRIMARY, SHADOW], "fg-shadow-1");
    const response = await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody("split-model"),
    });
    expect(response.status).toBe(200);
    // The client got the PRIMARY's answer; the mirror is discarded. That is the
    // guarantee `inference/shadow.ts` exists to hold, and it is asserted here
    // because everything below adds a new consumer of the mirrored response.
    expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-primary");
    await h.settle();

    const legs = await storedShadowLegs();
    expect(legs).toHaveLength(1);
    const leg = legs[0] as NonNullable<(typeof legs)[0]>;

    expect(leg.client_request_id).toBe("fg-shadow-1");
    expect(leg.leg_id).toBe("fg-shadow-1~shadow");
    expect(leg.tenant).toBe("tenant_a");
    expect(leg.provider).toBe("mirror-provider");
    expect(leg.provider_model).toBe("mirror-physical");
    expect(leg.status_code).toBe(200);
    expect(leg.error_code).toBeNull();
    expect(leg.latency_ms).toBeGreaterThanOrEqual(0);

    // The MIRROR's own tokens, not the primary's — an arm measured with the
    // other arm's numbers is worse than an unmeasured arm.
    expect(leg.prompt_tokens).toBe(20);
    expect(leg.completion_tokens).toBe(10);

    // Priced from the shadow route's OWN registry rates: 20 in @ $1/token-1M +
    // 10 out @ $2/token-1M = 20 + 20 = 40.
    expect(leg.cost_usd).toBeCloseTo(40, 6);

    // And the leg is filed under the same experiment the served arm is.
    expect(leg.experiment_id).toBe(
      experimentIdFor({
        logicalModel: "split-model",
        control: { provider: "openai-main", providerModel: "gpt-4o-mini-2024-07-18" },
        shadow: { provider: "mirror-provider", providerModel: "mirror-physical" },
      }),
    );
  });

  it("records a leg the mirror could not complete, rather than dropping the arm's failures", async () => {
    provider = interceptProviderFetch((request) => {
      if (new URL(request.url).host.startsWith("api.mirror")) {
        throw new Error("mirror unreachable");
      }
      return providerJson(COMPLETION);
    });
    const h = gateway([PRIMARY, SHADOW], "fg-shadow-fail");
    expect(
      (
        await h.call("/v1/chat/completions", {
          method: "POST",
          headers: AUTHED,
          body: chatBody("split-model"),
        })
      ).status,
      // The client is untouched by a mirror failure. Five mechanisms in
      // `shadow.ts` guarantee it and the new writer must not become a sixth
      // way to break it.
    ).toBe(200);
    await h.settle();

    const legs = await storedShadowLegs();
    expect(legs).toHaveLength(1);
    const leg = legs[0] as NonNullable<(typeof legs)[0]>;
    expect(leg.status_code).toBeNull();
    // An arm whose failures are invisible looks healthier than the arm it is
    // being compared against — which is the direction that promotes a bad
    // variant.
    expect(leg.error_code).toBe("provider_dispatch_error");
    expect(leg.cost_usd).toBeNull();
  });

  it("records the mirror's NON-200 status on the leg, not just a null-with-error-code", async () => {
    // The second half of #692's honesty rule, asserted DIRECTLY rather than by
    // shared code path. The tests above cover the two ends — a 200 leg and a
    // leg the mirror never completed (`status_code` NULL, `error_code` set) —
    // and left the middle uncovered: a mirror that DID answer, with a failure
    // status. That is the case where "not scored" and "not recorded" are
    // easiest to confuse, because `runShadowMirror` only hands the body to the
    // judge on a 200. The failure must still land in the arm's error rate.
    provider = interceptProviderFetch((request) =>
      new URL(request.url).host.startsWith("api.mirror")
        ? providerJson({ error: { message: "upstream is down", type: "server_error" } }, 503)
        : providerJson(COMPLETION),
    );
    const h = gateway([PRIMARY, SHADOW], "fg-shadow-503");
    expect(
      (
        await h.call("/v1/chat/completions", {
          method: "POST",
          headers: AUTHED,
          body: chatBody("split-model"),
        })
      ).status,
    ).toBe(200);
    await h.settle();

    const legs = await storedShadowLegs();
    expect(legs).toHaveLength(1);
    const leg = legs[0] as NonNullable<(typeof legs)[0]>;

    expect(leg.leg_id).toBe("fg-shadow-503~shadow");
    expect(leg.client_request_id).toBe("fg-shadow-503");
    // The whole point: a real provider status, persisted. `toBeNull()` here
    // would mean the arm's 503s were indistinguishable from its unreachable
    // dispatches, and `toBe(200)` would mean they were invisible altogether.
    expect(leg.status_code).toBe(503);
    // NOT an `error_code`: the mirror was reached and answered. Conflating the
    // two would make a provider outage look like an adapter or budget refusal.
    expect(leg.error_code).toBeNull();
    // Still filed under the same experiment as the served arm, so the failure
    // is grouped with the successes it has to be compared against.
    expect(leg.experiment_id).toBe(
      experimentIdFor({
        logicalModel: "split-model",
        control: { provider: "openai-main", providerModel: "gpt-4o-mini-2024-07-18" },
        shadow: { provider: "mirror-provider", providerModel: "mirror-physical" },
      }),
    );
  });

  it("writes no leg row when nothing was mirrored", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const h = gateway([PRIMARY, { ...SHADOW, shadowPercent: 0 }], "fg-shadow-off");
    await h.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody("split-model"),
    });
    await h.settle();
    expect(await storedShadowLegs()).toHaveLength(0);
  });
});
