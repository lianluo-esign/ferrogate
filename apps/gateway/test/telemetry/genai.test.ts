/**
 * ANTI-UNMOUNT for the OpenTelemetry **GenAI semantic conventions** (#669).
 *
 * ## What this file is a gate on
 *
 * Before #669 every FerroGate span carried only `ferrogate.*` attributes:
 * `request_id`, `route`, `path`, `status_code`. Datadog, Grafana, Langfuse and
 * Arize all key their LLM views off `gen_ai.*`, so a customer pointing any of
 * them at FerroGate saw a generic HTTP span with no model, no provider and no
 * token counts, and had to write a translator before the gateway told them
 * anything.
 *
 * Emitting the attributes is not the hard part — CARRYING them from the place
 * the gateway knows them (the inference handler, which holds the served route
 * and the provider's usage frame) to the place the span is built (the telemetry
 * middleware, an outer Hono layer that sees only a `Response`) is. So every
 * assertion here goes through `SELF.fetch` against the real deployed Worker —
 * `src/worker.ts` → `createGatewayApp` → the mounted inference module → the
 * stubbed provider → `ctx.waitUntil` → the collector service binding. A unit
 * test that constructed the emitter itself would stay green with that carriage
 * severed, which is exactly the defect class this repo keeps shipping.
 *
 * The collector is a RECORDING `[[services]]` binding, so what is asserted is
 * the byte-level OTLP request `apps/telemetry` would parse.
 *
 * ## Spec revision
 *
 * OpenTelemetry semantic conventions **v1.43.0** — the GenAI group now lives in
 * `open-telemetry/semantic-conventions-genai` (`docs/gen-ai/`), which carries no
 * tag of its own yet, so v1.43.0 of the parent repo is the last numbered
 * revision that contains these definitions. See `packages/observability/src/genai.ts`.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

const BASE = "https://gw.test";
const UPSTREAM_HOST = "api.genai-probe.example";

// `kind: "openai"` is the FerroGate provider kind; the semconv value it maps to
// is `openai`. `provider_model` differs from the logical name on purpose: that
// is what makes `gen_ai.request.model` vs `gen_ai.response.model` a real
// assertion rather than the same string twice.
const PROVIDERS = JSON.stringify([
  { name: "probe", kind: "openai", base_url: `https://${UPSTREAM_HOST}/v1` },
]);
const MODELS = JSON.stringify([
  { name: "genai-probe", provider: "probe", provider_model: "probe-physical" },
]);
const KEYS = JSON.stringify([
  { key: "fg_genai", id: "key_genai", tenant_id: "tenant_a", scopes: [] },
]);

interface CollectedOtlp {
  readonly path: string;
  readonly body: Record<string, unknown>;
}

const collected: CollectedOtlp[] = [];

const COLLECTOR = {
  async fetch(request: Request): Promise<Response> {
    collected.push({
      path: new URL(request.url).pathname,
      body: (await request.json()) as Record<string, unknown>,
    });
    return new Response(JSON.stringify({ partialSuccess: {} }), { status: 200 });
  },
};

const OVERRIDES: Record<string, unknown> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  TELEMETRY_COLLECTOR: COLLECTOR,
  TELEMETRY_TOKEN: "collector-secret",
  // Left unset deliberately: the DEFAULT profile must already be dual, because
  // a default that dropped `ferrogate.*` would break every existing dashboard
  // on the deploy that shipped this. The "legacy half survives" case below is
  // an assertion about the default, not about a var this file sets.
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  // Before the first `SELF.fetch`: `telemetryFromEnv` memoizes the resolved
  // emitter on the `env` object.
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

/**
 * Answer the probe provider with a usage frame; everything else falls through.
 *
 * `delayMs` exists for the duration case: an instantaneous stub can produce a
 * ZERO-millisecond request, and `0 / 1000 === 0` makes a seconds-vs-milliseconds
 * bug invisible. A deliberate upstream delay puts a measurable number on both
 * sides of the comparison.
 */
function stubUpstream(delayMs = 0): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes(UPSTREAM_HOST)) {
      return await original(input as RequestInfo, init);
    }
    if (delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    return new Response(
      JSON.stringify({
        id: "chatcmpl-probe",
        object: "chat.completion",
        model: "probe-physical",
        choices: [
          { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
        ],
        // Distinct prompt/completion counts: equal ones would let an
        // input/output mix-up pass.
        usage: { prompt_tokens: 17, completion_tokens: 5, total_tokens: 22 },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

async function chat(body?: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_genai", "content-type": "application/json" },
    body: JSON.stringify(
      body ?? { model: "genai-probe", messages: [{ role: "user", content: "hello" }] },
    ),
  });
}

/** The emission rides `ctx.waitUntil`, so it lands after the response. */
async function waitForCollected(count: number): Promise<void> {
  for (let i = 0; i < 300; i += 1) {
    if (collected.length >= count) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(
    `timed out waiting for ${count} OTLP request(s); the deployed Worker emitted ${collected.length}`,
  );
}

interface WireSpan {
  readonly name: string;
  readonly attributes: { key: string; value: { stringValue: string } }[];
}

function spanAttributes(): Record<string, string> {
  const traces = collected.find((entry) => entry.path === "/v1/traces")?.body as
    | { resourceSpans: [{ scopeSpans: [{ spans: WireSpan[] }] }] }
    | undefined;
  const span = traces?.resourceSpans[0]?.scopeSpans[0]?.spans[0];
  if (span === undefined) throw new Error("no span in the collected trace batch");
  return Object.fromEntries(
    span.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
  );
}

interface WireHistogramPoint {
  readonly sum?: number;
  readonly count?: string | number;
  readonly attributes: { key: string; value: { stringValue: string } }[];
}

interface WireMetric {
  readonly name: string;
  readonly unit?: string;
  readonly histogram?: { dataPoints: WireHistogramPoint[] };
  readonly sum?: { dataPoints: { asDouble: number }[] };
}

function wireMetrics(): WireMetric[] {
  const metrics = collected.find((entry) => entry.path === "/v1/metrics")?.body as
    | { resourceMetrics: [{ scopeMetrics: [{ metrics: WireMetric[] }] }] }
    | undefined;
  return metrics?.resourceMetrics[0]?.scopeMetrics[0]?.metrics ?? [];
}

/** The attribute bag of one histogram point, flattened. */
function pointAttributes(point: WireHistogramPoint): Record<string, string> {
  return Object.fromEntries(
    point.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
  );
}

let restore: (() => void) | undefined;

afterEach(() => {
  restore?.();
  restore = undefined;
  collected.length = 0;
});

describe("the deployed Worker emits OTel GenAI semantic conventions", () => {
  it("stamps gen_ai.* on the request span for a served inference call", async () => {
    restore = stubUpstream();
    const response = await chat();
    expect(response.status).toBe(200);
    await waitForCollected(2);

    const attributes = spanAttributes();

    // `gen_ai.provider.name` is the current spelling (semconv v1.43.0);
    // `gen_ai.system` is its deprecated predecessor and is emitted TOO, because
    // that is still what shipped Datadog/Langfuse mappings read today.
    expect(attributes["gen_ai.provider.name"]).toBe("openai");
    expect(attributes["gen_ai.system"]).toBe("openai");
    // `chat` is the well-known operation value for a chat-completions call.
    expect(attributes["gen_ai.operation.name"]).toBe("chat");
    // The name the CALLER asked for vs the physical model the route served —
    // two different strings, so a collapse of one onto the other is caught.
    expect(attributes["gen_ai.request.model"]).toBe("genai-probe");
    expect(attributes["gen_ai.response.model"]).toBe("probe-physical");
    // Straight off the provider's usage frame, not an estimate.
    expect(attributes["gen_ai.usage.input_tokens"]).toBe("17");
    expect(attributes["gen_ai.usage.output_tokens"]).toBe("5");
  });

  it("keeps the ferrogate.* attributes alongside them by DEFAULT", async () => {
    // Dual emission is the whole reason #669 is safe to deploy: an operator who
    // upgrades without touching a var must not lose a dashboard. If this case
    // ever needs a var set to pass, the default has regressed.
    restore = stubUpstream();
    const response = await chat();
    const servedRequestId = response.headers.get("x-request-id");
    await waitForCollected(2);

    const attributes = spanAttributes();
    expect(attributes.route).toBe("createChatCompletion");
    expect(attributes.path).toBe("/v1/chat/completions");
    expect(attributes.status_code).toBe("200");
    expect(attributes.request_id).toBe(servedRequestId);
    // And the span NAME is unchanged, which is what a saved Grafana query
    // filters on. The semconv `{operation} {model}` name is available behind
    // the `genai` profile; it is not forced on an existing deployment.
    const traces = collected.find((entry) => entry.path === "/v1/traces")?.body as {
      resourceSpans: [{ scopeSpans: [{ spans: WireSpan[] }] }];
    };
    expect(traces.resourceSpans[0].scopeSpans[0].spans[0]?.name).toBe("ferrogate.gateway.request");
  });

  it("emits gen_ai.client.token.usage as an input/output histogram", async () => {
    restore = stubUpstream();
    expect((await chat()).status).toBe(200);
    await waitForCollected(2);

    const metric = wireMetrics().find((m) => m.name === "gen_ai.client.token.usage");
    expect(metric).toBeDefined();
    expect(metric?.unit).toBe("{token}");

    const points = metric?.histogram?.dataPoints ?? [];
    const byType = new Map(
      points.map((point) => [pointAttributes(point)["gen_ai.token.type"], point]),
    );
    expect(byType.get("input")?.sum).toBe(17);
    expect(byType.get("output")?.sum).toBe(5);

    // `gen_ai.operation.name`, `gen_ai.provider.name` and `gen_ai.token.type`
    // are REQUIRED on this metric; `gen_ai.request.model` is conditionally
    // required and we always have it.
    const input = byType.get("input");
    expect(input).toBeDefined();
    const attributes = pointAttributes(input as WireHistogramPoint);
    expect(attributes["gen_ai.operation.name"]).toBe("chat");
    expect(attributes["gen_ai.provider.name"]).toBe("openai");
    expect(attributes["gen_ai.request.model"]).toBe("genai-probe");
    expect(attributes["gen_ai.response.model"]).toBe("probe-physical");
  });

  it("emits gen_ai.client.operation.duration in SECONDS, not milliseconds", async () => {
    // The 1000x unit error is the specific defect this case is built to catch,
    // and catching it needs an ANCHOR rather than a plausibility bound: the
    // gateway's own span already publishes the same interval in NANOSECONDS
    // (`startTimeUnixNano`/`endTimeUnixNano`), computed from the same two
    // `Date.now()` reads, so the metric must equal it exactly after conversion.
    // A bound like "less than 10" is useless here — a stubbed request takes a
    // few milliseconds, and `3` passes such a bound whether it means 3 seconds
    // or 3 milliseconds.
    const DELAY_MS = 25;
    restore = stubUpstream(DELAY_MS);
    expect((await chat()).status).toBe(200);
    await waitForCollected(2);

    const traces = collected.find((entry) => entry.path === "/v1/traces")?.body as {
      resourceSpans: [
        {
          scopeSpans: [{ spans: { startTimeUnixNano: string; endTimeUnixNano: string }[] }];
        },
      ];
    };
    const span = traces.resourceSpans[0].scopeSpans[0].spans[0] as {
      startTimeUnixNano: string;
      endTimeUnixNano: string;
    };
    const spanSeconds =
      (Number(span.endTimeUnixNano) - Number(span.startTimeUnixNano)) / 1_000_000_000;
    // The delay makes the interval unambiguously non-zero, so the equality
    // below cannot be satisfied by `0 === 0`.
    expect(spanSeconds).toBeGreaterThanOrEqual(DELAY_MS / 1000);

    const metric = wireMetrics().find((m) => m.name === "gen_ai.client.operation.duration");
    expect(metric).toBeDefined();
    expect(metric?.unit).toBe("s");
    const point = metric?.histogram?.dataPoints[0];
    expect(point).toBeDefined();
    expect(point?.sum).toBeCloseTo(spanSeconds, 6);

    const attributes = pointAttributes(point as WireHistogramPoint);
    expect(attributes["gen_ai.operation.name"]).toBe("chat");
    expect(attributes["gen_ai.provider.name"]).toBe("openai");
  });

  it("does NOT invent gen_ai.* for a request that reached no model", async () => {
    // `/v1/tools` is not an inference operation; a span for it carrying
    // `gen_ai.request.model: ""` would poison every model-grouped panel with an
    // empty series. Absent is the only correct answer.
    const response = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { authorization: "Bearer fg_genai" },
    });
    expect(response.status).toBe(501);
    await waitForCollected(2);

    const attributes = spanAttributes();
    expect(attributes.route).toBe("listTools");
    expect(attributes["gen_ai.operation.name"]).toBeUndefined();
    expect(attributes["gen_ai.request.model"]).toBeUndefined();
    expect(attributes["gen_ai.system"]).toBeUndefined();
    expect(wireMetrics().some((m) => m.name.startsWith("gen_ai."))).toBe(false);
  });
});
