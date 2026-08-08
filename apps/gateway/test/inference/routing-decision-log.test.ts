/**
 * #699 — the cost/quality dial's decision is EXPLAINABLE in the request log.
 *
 * ## What is real here
 *
 * The composed gateway (`createGatewayApp`), the contract router, the auth
 * guard, the whole middleware chain, the inference dispatch path, the real
 * `CONTROL_DB` D1 binding with the committed migrations (so the new
 * `request_logs.routing_decision` column is the one production gets), and a real
 * `ExecutionContext`. The ONLY seam replaced is `deps.routingQuality`, injected
 * as a WARM dial-on snapshot over the REAL `routingQualityPortFrom` /
 * `tenantLegQualityFrom(legQualityVerdicts(...))` — the same objects
 * `quality-source.ts` builds from D1 — so nothing here doubles the comparator or
 * the router. Only the outbound provider `fetch` is intercepted.
 *
 * The row an assertion reads was written by a real HTTP request flowing through
 * the real chain, then read back out of the real `CONTROL_DB`.
 *
 * ## MUTATION LOG (applied to `src/`, run, reverted)
 *
 * The assertion reads the `routing_decision` COLUMN (via `SELECT *`), which is
 * populated from `record.routingDecision` through the d1 binding — NOT from the
 * `request_json` blob — so the load-bearing mutations are the ones on that path:
 *
 * | mutation                                                                       | red |
 * |--------------------------------------------------------------------------------|-----|
 * | `handlers.ts`: gate out the `routingDecision` contribution to `inferenceLog`    | `records the applied decision, with the filtered leg named` (verified) |
 * | `middleware.ts`: drop `routingDecision: facts.routingDecision`                  | `records the applied decision, with the filtered leg named` |
 * | `d1.ts`: drop `routing_decision` from the upsert columns/bindings              | `records the applied decision, with the filtered leg named` |
 */
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type OnlineEvalLegAggregate,
  legQualityVerdicts,
  routingQualityPortFrom,
  tenantLegQualityFrom,
} from "../../src/evals/index.js";
import type { PhysicalRoute, RequestIdFactory } from "../../src/inference/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import type { RoutingQualityPort } from "../../src/inference/strategy.js";
import {
  createRequestLogSink,
  requestLogBindingsFromEnv,
  requestLogging,
} from "../../src/requestlog/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import {
  applyControlMigrations,
  resetExperimentTables,
  storedRequestLogs,
} from "../experiments/harness.js";
import { type ProviderInterceptor, interceptProviderFetch, providerJson } from "./provider-mock.js";

const BASE = "https://gw.test";
const TENANT = "tenant_cq";
const MODEL = "cq-model";
const POLICY = { regressionDrop: 0.1, regressionMinSamples: 20 };

const TENANT_KEY = JSON.stringify([
  {
    key: "fg_cq_tenant",
    id: "key_cq_tenant",
    tenant_id: TENANT,
    project_id: "project_cq",
    scopes: ["chat.completions", "models.read"],
  },
]);
const AUTHED = { authorization: "Bearer fg_cq_tenant", "content-type": "application/json" };

function route(provider: string, overrides: Partial<PhysicalRoute> = {}): PhysicalRoute {
  return {
    logicalModel: MODEL,
    provider,
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: `https://${provider}.example/v1/`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

function cell(provider: string, mean: number): OnlineEvalLegAggregate {
  return {
    tenantId: TENANT,
    criterionId: "grounded",
    judgeModel: "judge-model",
    logicalModel: MODEL,
    provider,
    providerModel: "gpt-4o-mini",
    scoreTotal: mean * 20,
    scoreCount: 20,
  };
}

/** A warm, DIAL-ON quality port over the real comparator. */
function warmDialPort(aggregates: readonly OnlineEvalLegAggregate[]): RoutingQualityPort {
  const quality = tenantLegQualityFrom(legQualityVerdicts(aggregates, POLICY), true);
  return routingQualityPortFrom({
    qualityFor: async () => ({ ok: true, quality }),
    peek: (tenantId: string) => (tenantId === TENANT ? { ok: true, quality } : undefined),
  });
}

function fixedRequestIds(id: string): RequestIdFactory {
  return { next: (): string => id };
}

interface Harness {
  call(path: string, init: RequestInit): Promise<Response>;
  settle(): Promise<void>;
}

function gateway(
  routes: readonly PhysicalRoute[],
  requestId: string,
  routingQuality: RoutingQualityPort,
): Harness {
  const bindings: Record<string, unknown> = {
    ...(env as unknown as Record<string, unknown>),
    REQUEST_LOG: undefined,
    GATEWAY_NATIVE_API_KEYS: TENANT_KEY,
  };
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([...routes]),
        requestIds: fixedRequestIds(requestId),
        routingQuality,
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

function chatBody(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({ model: MODEL, messages: [{ role: "user", content: "hi" }], ...extra });
}

/**
 * Read THIS request's log row by the fixed id it was issued under, rather than
 * assuming "the only row in the table".
 *
 * `storedRequestLogs()` returns the whole shared `CONTROL_DB.request_logs`, and
 * a batched/full gateway run can schedule another test file into the same
 * workerd isolate, whose write can land between this test's `beforeEach` reset
 * and its read — the same shared-isolate class as the pre-existing
 * `catalog.test.ts` pool flake. A `SELECT *`-then-`rows[0]` read would then
 * inflate the count or return a foreign decision string. Keying on the request
 * id this test alone controls (`fg-cq-*`, verified unique across the suite)
 * makes the assertion depend only on the row this request wrote, so a
 * concurrent row can neither be counted nor read in its place.
 */
async function decisionFor(requestId: string): Promise<string | null> {
  const rows = (await storedRequestLogs()).filter((row) => row.request_id === requestId);
  expect(rows, `exactly one request_logs row for ${requestId}`).toHaveLength(1);
  return (rows[0] as unknown as { routing_decision: string | null }).routing_decision;
}

const COMPLETION = {
  id: "chatcmpl-cq",
  object: "chat.completion",
  model: MODEL,
  choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

let provider: ProviderInterceptor | undefined;

beforeAll(applyControlMigrations);
beforeEach(resetExperimentTables);
afterEach(() => {
  provider?.restore();
  provider = undefined;
});

describe("the cost/quality dial writes an explainable decision to the request log", () => {
  it("records the applied decision, with the filtered leg named", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    // `cheap` lags and is cheapest; `good` is comparable and pricier.
    const routes = [
      route("cheap", { priority: 0, inputPricePer1m: 1, outputPricePer1m: 1 }),
      route("good", { priority: 1, inputPricePer1m: 100, outputPricePer1m: 100 }),
    ];
    const gw = gateway(
      routes,
      "fg-cq-applied",
      warmDialPort([cell("good", 0.9), cell("cheap", 0.5)]),
    );

    const response = await gw.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await gw.settle();

    const decision = await decisionFor("fg-cq-applied");
    expect(decision).toBe(
      "cost_quality task=easy(short_single_turn) applied=true eligible=good/gpt-4o-mini filtered=cheap/gpt-4o-mini",
    );
  });

  it("records a hard task as inspected-but-not-acted-on", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const routes = [
      route("cheap", { priority: 0, inputPricePer1m: 1, outputPricePer1m: 1 }),
      route("good", { priority: 1, inputPricePer1m: 100, outputPricePer1m: 100 }),
    ];
    const gw = gateway(routes, "fg-cq-hard", warmDialPort([cell("good", 0.9), cell("cheap", 0.9)]));

    const response = await gw.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody({ tools: [{ type: "function", function: { name: "f" } }] }),
    });
    expect(response.status, await response.clone().text()).toBe(200);
    await gw.settle();

    const decision = await decisionFor("fg-cq-hard");
    expect(decision).toContain("task=hard(tools_requested)");
    expect(decision).toContain("applied=false");
    expect(decision).toContain("note=hard_task_kept_ladder");
  });

  it("writes NO routing decision when the tenant did not opt the dial in", async () => {
    provider = interceptProviderFetch(() => providerJson(COMPLETION));
    const routes = [
      route("cheap", { priority: 0, inputPricePer1m: 1, outputPricePer1m: 1 }),
      route("good", { priority: 1, inputPricePer1m: 100, outputPricePer1m: 100 }),
    ];
    // Dial OFF: `tenantLegQualityFrom(..., false)` via the plain (no-second-arg) build.
    const off = routingQualityPortFrom({
      qualityFor: async () => ({
        ok: true,
        quality: tenantLegQualityFrom(
          legQualityVerdicts([cell("good", 0.9), cell("cheap", 0.5)], POLICY),
        ),
      }),
      peek: (tenantId: string) =>
        tenantId === TENANT
          ? {
              ok: true,
              quality: tenantLegQualityFrom(
                legQualityVerdicts([cell("good", 0.9), cell("cheap", 0.5)], POLICY),
              ),
            }
          : undefined,
    });
    const gw = gateway(routes, "fg-cq-off", off);

    const response = await gw.call("/v1/chat/completions", {
      method: "POST",
      headers: AUTHED,
      body: chatBody(),
    });
    expect(response.status).toBe(200);
    await gw.settle();

    const decision = await decisionFor("fg-cq-off");
    // The byte-identical-when-off guarantee reaches the log too: no column value.
    expect(decision).toBeNull();
  });
});
