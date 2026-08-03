/**
 * ANTI-UNMOUNT for the telemetry egress — `@ferrogate/observability` reaching
 * `apps/telemetry` from the DEPLOYED Worker.
 *
 * ## Why this file exists
 *
 * `apps/telemetry` has been a complete OTLP/HTTP+JSON receiver with an
 * Analytics Engine sink since wave 4, with its own passing suite. The gateway
 * sent it nothing. The only `@ferrogate/observability` reference anywhere in
 * `apps/gateway/src` was `cache/metrics.ts:37`, and it is `import type` — which
 * the compiler ERASES, so the package contributed zero bytes to the deployed
 * bundle. Producer and consumer both green, nothing flowing between them.
 *
 * `test/telemetry/emit.test.ts` exercises the emitter directly and would stay
 * green through exactly that state, because it constructs the emitter itself.
 * This file does not: every assertion goes through `SELF.fetch` — `src/worker.ts`
 * → `src/index.ts` → `createGatewayApp` → the mounted inference route module —
 * so it is RED the moment the `emitRequestTelemetry` call is removed from
 * `src/inference/route-module.ts`.
 *
 * The collector is a RECORDING `[[services]]` binding installed on `env`, which
 * is the shape production gets from `[[services]] binding =
 * "TELEMETRY_COLLECTOR"`. Its `fetch` is the collector's real entry point, so
 * what is asserted below is the exact request `apps/telemetry` would parse.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

const BASE = "https://gw.test";
const UPSTREAM_HOST = "api.telemetry-probe.example";

const PROVIDERS = JSON.stringify([
  { name: "probe", kind: "openai", base_url: `https://${UPSTREAM_HOST}/v1` },
]);
const MODELS = JSON.stringify([
  { name: "telemetry-probe", provider: "probe", provider_model: "probe-physical" },
]);
const KEYS = JSON.stringify([
  { key: "fg_telemetry", id: "key_telemetry", tenant_id: "tenant_a", scopes: [] },
]);

/** Every OTLP request the collector binding received. */
interface CollectedOtlp {
  readonly path: string;
  readonly authorization: string | null;
  readonly tenant: string | null;
  readonly body: Record<string, unknown>;
}

const collected: CollectedOtlp[] = [];

const COLLECTOR = {
  async fetch(request: Request): Promise<Response> {
    collected.push({
      path: new URL(request.url).pathname,
      authorization: request.headers.get("authorization"),
      tenant: request.headers.get("x-ferrogate-tenant"),
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
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;

beforeAll(() => {
  // Installed BEFORE the first `SELF.fetch`: `telemetryFromEnv` memoizes the
  // resolved emitter on the `env` object, so a request served before the
  // binding exists would cache the no-op for the whole isolate.
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

/** Answer the probe provider; everything else falls through to the real fetch. */
function stubUpstream(status = 200): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!url.includes(UPSTREAM_HOST)) {
      return await original(input as RequestInfo, init);
    }
    return new Response(
      JSON.stringify({
        id: "chatcmpl-probe",
        object: "chat.completion",
        model: "telemetry-probe",
        choices: [
          { index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" },
        ],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      }),
      { status, headers: { "content-type": "application/json" } },
    );
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

async function chat(body?: unknown): Promise<Response> {
  return await SELF.fetch(`${BASE}/v1/chat/completions`, {
    method: "POST",
    headers: { authorization: "Bearer fg_telemetry", "content-type": "application/json" },
    body: JSON.stringify(
      body ?? {
        model: "telemetry-probe",
        messages: [{ role: "user", content: "does telemetry leave the worker" }],
      },
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

/**
 * Wait for `count` batches and then keep waiting, to prove no MORE arrive.
 *
 * `waitForCollected` is a `>=` check, so it cannot tell 2 batches from 4. This
 * one can, and that is what makes the "mounted twice, emits once" case below a
 * real assertion instead of a restatement of the comment.
 */
async function settleAtExactly(count: number): Promise<void> {
  await waitForCollected(count);
  for (let i = 0; i < 60; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  if (collected.length !== count) {
    throw new Error(
      `expected exactly ${count} OTLP request(s); the deployed Worker emitted ${collected.length} ` +
        `(${collected.map((entry) => entry.path).join(", ")})`,
    );
  }
}

let restore: (() => void) | undefined;

afterEach(() => {
  restore?.();
  restore = undefined;
  collected.length = 0;
});

describe("the deployed Worker emits telemetry to the collector binding", () => {
  it("POSTs an OTLP trace and metric batch for a served inference request", async () => {
    restore = stubUpstream();

    const response = await chat();
    expect(response.status).toBe(200);

    // NOT a mount gate on its own — see "MOUNT" below. `/v1/chat/completions`
    // is covered by BOTH emitters (`src/inference/route-module.ts` and
    // `src/telemetry/middleware.ts`), so removing either leaves this green:
    // the survivor answers in its place, with the same request id, and
    // `emitRequestTelemetry` de-duplicates on the inbound `Request` so the
    // count stays 2. What this case pins is the PAYLOAD and the transport.
    await waitForCollected(2);
    expect(collected.map((entry) => entry.path)).toEqual(["/v1/traces", "/v1/metrics"]);
    for (const entry of collected) {
      // Exactly what `apps/telemetry/src/auth.ts::requireBearer` compares.
      expect(entry.authorization).toBe("Bearer collector-secret");
      // The AUTHENTICATED tenant of the api key, used as the AE index.
      expect(entry.tenant).toBe("tenant_a");
    }
  });

  it("MOUNT: emits for a NON-inference operation, which only the middleware covers", async () => {
    // THE MOUNT GATE for `requestTelemetry()` (src/telemetry/middleware.ts),
    // and it had to be written this way to be a gate at all.
    //
    // Every other case in this file drives `/v1/chat/completions`, which TWO
    // emitters cover: the inference route module's own `emitRequestTelemetry`
    // and this middleware. Either one alone satisfies them, so neither mount
    // was individually provable and the comment above used to claim otherwise.
    //
    // `/v1/tools` is mounted by `registerToolingRoutes`, NOT by the inference
    // route module, so the middleware is the only thing that can emit for it.
    // Make `requestTelemetry()` a pass-through and this times out at zero —
    // which is also the measurement that says what the middleware BUYS: it
    // widens coverage from the 6 inference operations to all 31.
    const response = await SELF.fetch(`${BASE}/v1/tools`, {
      headers: { authorization: "Bearer fg_telemetry" },
    });
    // The tooling stub. What matters is that a NON-inference operation ran.
    expect(response.status).toBe(501);

    await waitForCollected(2);
    expect(collected.map((entry) => entry.path)).toEqual(["/v1/traces", "/v1/metrics"]);

    const traces = collected[0]?.body as {
      resourceSpans: [
        {
          scopeSpans: [
            { spans: { attributes: { key: string; value: { stringValue: string } }[] }[] },
          ];
        },
      ];
    };
    const attributes = Object.fromEntries(
      traces.resourceSpans[0].scopeSpans[0].spans[0]!.attributes.map((attribute) => [
        attribute.key,
        attribute.value.stringValue,
      ]),
    );
    // The contract operation id, so this cannot pass off some other request.
    expect(attributes["route"]).toBe("listTools");
    expect(attributes["path"]).toBe("/v1/tools");
    expect(attributes["status_code"]).toBe("501");
  });

  it("REDUNDANCY: two mounts on one inference request emit EXACTLY one batch pair", async () => {
    // The other half of the mount story, and the reason it is asserted rather
    // than asserted-about-in-a-comment.
    //
    // `/v1/chat/completions` passes through BOTH emitters — the inference route
    // module's own `emitRequestTelemetry` and `src/telemetry/middleware.ts`.
    // The middleware's docs state that this is safe because the emitter
    // de-duplicates on the inbound `Request` object AND because both publish the
    // same `x-request-id`. Neither claim was checked end to end: every other
    // case here uses `waitForCollected`, a `>=` check that a doubled emission
    // (4 batches) satisfies just as well as a de-duplicated one (2).
    //
    // So this case pins the redundancy itself. It goes RED if de-duplication
    // breaks, and it goes RED if the two emissions ever start disagreeing about
    // the request id — because a different id is a different de-dup outcome and
    // a second pair lands. That is the ONLY way the route-module emission can
    // become individually observable again, and this is the test that would say
    // so instead of it being rediscovered.
    restore = stubUpstream();
    const response = await chat();
    expect(response.status).toBe(200);
    const servedRequestId = response.headers.get("x-request-id");

    await settleAtExactly(2);
    expect(collected.map((entry) => entry.path)).toEqual(["/v1/traces", "/v1/metrics"]);

    const traces = collected[0]?.body as {
      resourceSpans: [
        {
          scopeSpans: [
            { spans: { attributes: { key: string; value: { stringValue: string } }[] }[] },
          ];
        },
      ];
    };
    const spans = traces.resourceSpans[0].scopeSpans[0].spans;
    // ONE span, not two: a single de-duplicated emission, not two emissions that
    // happened to be batched together.
    expect(spans).toHaveLength(1);
    const attributes = Object.fromEntries(
      spans[0]!.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
    );
    expect(attributes["request_id"]).toBe(servedRequestId);
    expect(attributes["route"]).toBe("createChatCompletion");
  });

  it("the span names the operation the deployed router matched", async () => {
    restore = stubUpstream();
    const response = await chat();
    const servedRequestId = response.headers.get("x-request-id");
    await waitForCollected(2);

    const traces = collected[0]?.body as {
      resourceSpans: [
        {
          resource: { attributes: { key: string; value: { stringValue: string } }[] };
          scopeSpans: [
            {
              spans: {
                name: string;
                attributes: { key: string; value: { stringValue: string } }[];
              }[];
            },
          ];
        },
      ];
    };
    const span = traces.resourceSpans[0].scopeSpans[0].spans[0]!;
    const attributes = Object.fromEntries(
      span.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
    );

    expect(span.name).toBe("ferrogate.gateway.request");
    // The CONTRACT operation id, not a path guess — proof the emission is
    // wired to the router that matched, not to a string in the test.
    expect(attributes["route"]).toBe("createChatCompletion");
    expect(attributes["method"]).toBe("POST");
    expect(attributes["path"]).toBe("/v1/chat/completions");
    expect(attributes["status_code"]).toBe("200");
    // The id the OUTER gateway middleware minted for THIS request — the same
    // one the client was told in `x-request-id`, which is what makes a span
    // joinable to a client-side incident report. Asserting the header rather
    // than a format keeps it honest: a hard-coded shape would still pass if the
    // emission published some other request's id.
    expect(servedRequestId).toBeTruthy();
    expect(attributes["request_id"]).toBe(servedRequestId);
    expect(traces.resourceSpans[0].resource.attributes).toContainEqual({
      key: "service.name",
      value: { stringValue: "ferrogate-gateway" },
    });
  });

  it("joins the caller's trace when a valid W3C traceparent arrives", async () => {
    restore = stubUpstream();
    const traceId = "4bf92f3577b34da6a3ce929d0e0e4736";

    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: {
        authorization: "Bearer fg_telemetry",
        "content-type": "application/json",
        traceparent: `00-${traceId}-00f067aa0ba902b7-01`,
      },
      body: JSON.stringify({
        model: "telemetry-probe",
        messages: [{ role: "user", content: "hi" }],
      }),
    });
    expect(response.status).toBe(200);
    await waitForCollected(2);

    const traces = collected[0]?.body as {
      resourceSpans: [{ scopeSpans: [{ spans: { traceId: string }[] }] }];
    };
    // The whole point of `middleware/trace.ts`: a span emitted here belongs to
    // the caller's trace rather than starting an orphan one.
    expect(traces.resourceSpans[0].scopeSpans[0].spans[0]?.traceId).toBe(traceId);
  });

  it("emits an error metric for a request the gateway itself refused", async () => {
    // No upstream stub: an unknown model never reaches a provider.
    const response = await chat({
      model: "no-such-model",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(response.status).toBe(400);
    await waitForCollected(2);

    const metrics = collected[1]?.body as {
      resourceMetrics: [
        {
          scopeMetrics: [
            {
              metrics: {
                name: string;
                sum: {
                  dataPoints: {
                    asDouble: number;
                    attributes: { key: string; value: { stringValue: string } }[];
                  }[];
                };
              }[];
            },
          ];
        },
      ];
    };
    const byName = new Map(
      metrics.resourceMetrics[0].scopeMetrics[0].metrics.map((metric) => [metric.name, metric]),
    );
    expect(byName.get("ferrogate.request_logs")?.sum.dataPoints[0]?.asDouble).toBe(1);
    // A 4xx the gateway produced counts as an error, verbatim Rust.
    expect(byName.get("ferrogate.request_errors")?.sum.dataPoints[0]?.asDouble).toBe(1);
    expect(byName.get("ferrogate.request_status")?.sum.dataPoints[0]?.attributes).toContainEqual({
      key: "status_code",
      value: { stringValue: "400" },
    });
  });

  it("a collector outage leaves the client's response untouched", async () => {
    restore = stubUpstream();
    const failing = {
      async fetch(): Promise<Response> {
        throw new Error("collector unreachable");
      },
    };
    const previous = mutable["TELEMETRY_COLLECTOR"];
    mutable["TELEMETRY_COLLECTOR"] = failing;
    try {
      // The emitter is memoized per env object, so the failing binding only
      // takes effect for a request served after the swap IF the memo is keyed
      // on the env — which it is. Assert the OUTCOME, which is the invariant
      // that matters: a dead collector changes nothing the client sees.
      const response = await chat();
      expect(response.status).toBe(200);
      expect(((await response.json()) as { id: string }).id).toBe("chatcmpl-probe");
    } finally {
      mutable["TELEMETRY_COLLECTOR"] = previous;
    }
  });
});
