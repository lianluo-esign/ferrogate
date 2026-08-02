/**
 * The telemetry EGRESS unit surface: transport selection, the OTLP payload
 * shape, and the two rules the module exists to keep.
 *
 * The MOUNT gate — "the deployed Worker actually emits" — is
 * `test/telemetry/mount.test.ts`, driven through `SELF.fetch`. This file is the
 * behaviour BEHIND that mount, which a mount gate alone would not pin: which
 * binding wins, what a rotated token does, whether an outage is really a no-op.
 */
import { GATEWAY_REQUEST_SPAN } from "@ferrogate/observability";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_TELEMETRY_SERVICE_NAME,
  NO_TELEMETRY,
  SERVICE_BINDING_ORIGIN,
  emitRequestTelemetry,
  snapshotFor,
  spanFor,
  telemetryEmitterFor,
  telemetryFromEnv,
  telemetryIds,
} from "../../src/telemetry/index.js";
import type { RequestTelemetry } from "../../src/telemetry/index.js";

const TELEMETRY: RequestTelemetry = {
  requestId: "fg-000000000000002a",
  traceId: "fg-000000000000002a",
  method: "POST",
  path: "/v1/chat/completions",
  route: "createChatCompletion",
  statusCode: 200,
  startedAtMs: 1_700_000_000_000,
  endedAtMs: 1_700_000_000_120,
  tenantId: "tenant_a",
};

interface Collected {
  readonly url: string;
  readonly method: string;
  readonly authorization: string | null;
  readonly tenant: string | null;
  readonly contentType: string | null;
  readonly body: Record<string, unknown>;
}

/** A stand-in for the `[[services]]` binding to `apps/telemetry`. */
function recordingService(status = 200): {
  readonly received: Collected[];
  fetch(request: Request): Promise<Response>;
} {
  const received: Collected[] = [];
  return {
    received,
    async fetch(request: Request): Promise<Response> {
      received.push({
        url: request.url,
        method: request.method,
        authorization: request.headers.get("authorization"),
        tenant: request.headers.get("x-ferrogate-tenant"),
        contentType: request.headers.get("content-type"),
        body: (await request.json()) as Record<string, unknown>,
      });
      return new Response(JSON.stringify({ partialSuccess: {} }), { status });
    },
  };
}

// ---------------------------------------------------------------------------
// Transport selection
// ---------------------------------------------------------------------------

describe("telemetryEmitterFor picks a transport", () => {
  it("is a no-op when nothing is configured", () => {
    const emitter = telemetryEmitterFor({});
    expect(emitter.enabled).toBe(false);
    expect(emitter.transport).toBe("none");
    expect(emitter).toBe(NO_TELEMETRY);
  });

  it("is a no-op with an endpoint but no token", () => {
    // The collector answers 401 to an unauthenticated ingest, so emitting
    // would buy a guaranteed rejected round trip on every single request.
    expect(telemetryEmitterFor({ TELEMETRY_ENDPOINT: "https://c.test" }).enabled).toBe(false);
  });

  it("is a no-op with a token but no destination", () => {
    expect(telemetryEmitterFor({ TELEMETRY_TOKEN: "tok" }).enabled).toBe(false);
  });

  it("prefers the service binding over the HTTPS endpoint", () => {
    const emitter = telemetryEmitterFor({
      TELEMETRY_COLLECTOR: recordingService(),
      TELEMETRY_ENDPOINT: "https://public.test",
      TELEMETRY_TOKEN: "tok",
    });
    expect(emitter.transport).toBe("service");
  });

  it("falls back to HTTPS when only the endpoint is configured", () => {
    const emitter = telemetryEmitterFor({
      TELEMETRY_ENDPOINT: "https://public.test",
      TELEMETRY_TOKEN: "tok",
    });
    expect(emitter.transport).toBe("https");
  });

  it("refuses to put a bearer token on a non-loopback plaintext endpoint", () => {
    // `CloudflareBackend.validate()` returns `InsecureEndpoint`; a config
    // mistake in OBSERVABILITY degrades to silence, never to a throw on the
    // inference path — and never to a leaked credential.
    expect(
      telemetryEmitterFor({ TELEMETRY_ENDPOINT: "http://public.test", TELEMETRY_TOKEN: "t" })
        .enabled,
    ).toBe(false);
    // Loopback stays usable so `wrangler dev` can drive a local collector.
    expect(
      telemetryEmitterFor({ TELEMETRY_ENDPOINT: "http://localhost:8788", TELEMETRY_TOKEN: "t" })
        .enabled,
    ).toBe(true);
  });

  it("memoizes the emitter on the env object", () => {
    const env = { TELEMETRY_ENDPOINT: "https://c.test", TELEMETRY_TOKEN: "tok" };
    expect(telemetryFromEnv(env)).toBe(telemetryFromEnv(env));
    // A DIFFERENT env (a different request's bindings) gets its own emitter,
    // so nothing is shared between two concurrent requests.
    expect(telemetryFromEnv(env)).not.toBe(
      telemetryFromEnv({ TELEMETRY_ENDPOINT: "https://c.test", TELEMETRY_TOKEN: "tok" }),
    );
  });
});

// ---------------------------------------------------------------------------
// The payload apps/telemetry receives
// ---------------------------------------------------------------------------

describe("the emitted payload is the OTLP apps/telemetry ingests", () => {
  it("POSTs a trace and a metric batch through the service binding", async () => {
    const service = recordingService();
    const emitter = telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "collector-secret",
    });
    await emitter.emit(TELEMETRY);

    expect(service.received.map((r) => new URL(r.url).pathname)).toEqual([
      "/v1/traces",
      "/v1/metrics",
    ]);
    for (const request of service.received) {
      expect(request.method).toBe("POST");
      expect(request.contentType).toBe("application/json");
      // The exact credential `apps/telemetry/src/auth.ts::requireBearer` wants.
      expect(request.authorization).toBe("Bearer collector-secret");
      // The Analytics Engine INDEX; the collector needs one per data point.
      expect(request.tenant).toBe("tenant_a");
      expect(new URL(request.url).origin).toBe(SERVICE_BINDING_ORIGIN);
    }
  });

  it("emits a ferrogate.gateway.request span carrying every template field", async () => {
    const service = recordingService();
    await telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "tok",
    }).emit(TELEMETRY);

    const traces = service.received[0]?.body as {
      resourceSpans: [
        {
          resource: { attributes: { key: string; value: { stringValue: string } }[] };
          scopeSpans: [{ spans: Record<string, unknown>[] }];
        },
      ];
    };
    const resource = traces.resourceSpans[0].resource.attributes;
    expect(resource).toContainEqual({
      key: "service.name",
      value: { stringValue: DEFAULT_TELEMETRY_SERVICE_NAME },
    });

    const span = traces.resourceSpans[0].scopeSpans[0].spans[0] as {
      name: string;
      traceId: string;
      spanId: string;
      attributes: { key: string; value: { stringValue: string } }[];
    };
    expect(span.name).toBe("ferrogate.gateway.request");
    // Read off the template rather than typed out, so a field added to
    // `@ferrogate/observability`'s canonical span fails here instead of
    // silently going unemitted.
    expect(span.attributes.map((a) => a.key)).toEqual([...GATEWAY_REQUEST_SPAN.fields]);
    expect(
      Object.fromEntries(span.attributes.map((a) => [a.key, a.value.stringValue])),
    ).toMatchObject({
      request_id: "fg-000000000000002a",
      method: "POST",
      path: "/v1/chat/completions",
      route: "createChatCompletion",
      status_code: "200",
    });
    // `apps/telemetry`'s `spanSchema` requires both ids and would SKIP the
    // record without them.
    expect(span.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(span.spanId).toMatch(/^[0-9a-f]{16}$/);
  });

  it("adopts a real W3C trace id verbatim, and hashes the gateway's own", async () => {
    const w3c = "4bf92f3577b34da6a3ce929d0e0e4736";
    const adopted = await telemetryIds({ ...TELEMETRY, traceId: w3c });
    // Verbatim: this span JOINS the caller's existing trace.
    expect(adopted.traceId).toBe(w3c);

    const minted = await telemetryIds(TELEMETRY);
    expect(minted.traceId).toMatch(/^[0-9a-f]{32}$/);
    expect(minted.traceId).not.toBe(w3c);
    // Deterministic — the same request always lands on the same trace...
    expect((await telemetryIds(TELEMETRY)).traceId).toBe(minted.traceId);
    // ...and two different requests do not collapse onto one.
    expect((await telemetryIds({ ...TELEMETRY, traceId: "fg-0000000000000042" })).traceId).not.toBe(
      minted.traceId,
    );
  });

  it("emits a per-request metric DELTA, not a cumulative snapshot", async () => {
    const service = recordingService();
    await telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "tok",
    }).emit({ ...TELEMETRY, statusCode: 503 });

    const metrics = service.received[1]?.body as {
      resourceMetrics: [{ scopeMetrics: [{ metrics: Record<string, unknown>[] }] }];
    };
    const byName = new Map(
      metrics.resourceMetrics[0].scopeMetrics[0].metrics.map((metric) => [
        metric["name"] as string,
        metric,
      ]),
    );
    const value = (name: string): number =>
      (byName.get(name) as { sum: { dataPoints: [{ asDouble: number }] } }).sum.dataPoints[0]
        .asDouble;

    // ONE request, ONE error — the delta this request contributed. See the
    // temporality PORT-TODO in `src/telemetry/emit.ts`: a Worker has no process
    // to accumulate in, so per-request deltas summed by Analytics Engine are
    // the platform-shaped answer.
    expect(value("ferrogate.request_logs")).toBe(1);
    expect(value("ferrogate.request_errors")).toBe(1);
    expect(value("ferrogate.request_status")).toBe(1);
    const status = byName.get("ferrogate.request_status") as {
      sum: { dataPoints: [{ attributes: { key: string; value: { stringValue: string } }[] }] };
    };
    expect(status.sum.dataPoints[0].attributes).toContainEqual({
      key: "status_code",
      value: { stringValue: "503" },
    });
  });

  it("counts a 2xx as a request but not as an error", () => {
    expect(snapshotFor(TELEMETRY, "svc").requestErrorTotal).toBe(0);
    expect(snapshotFor(TELEMETRY, "svc").requestLogTotal).toBe(1);
    // Rust: "structured request logs with errors or 4xx/5xx statuses" — a
    // gateway-produced 400 is an error too, which is what makes the ratio
    // actionable.
    expect(snapshotFor({ ...TELEMETRY, statusCode: 400 }, "svc").requestErrorTotal).toBe(1);
  });

  it("honours TELEMETRY_SIGNALS", async () => {
    const service = recordingService();
    await telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "tok",
      TELEMETRY_SIGNALS: "trace",
    }).emit(TELEMETRY);
    expect(service.received.map((r) => new URL(r.url).pathname)).toEqual(["/v1/traces"]);
  });

  it("stamps a configured service name onto the resource", async () => {
    const service = recordingService();
    await telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "tok",
      TELEMETRY_SERVICE_NAME: "gateway-eu",
    }).emit(TELEMETRY);
    const traces = service.received[0]?.body as {
      resourceSpans: [{ resource: { attributes: { key: string; value: unknown }[] } }];
    };
    expect(traces.resourceSpans[0].resource.attributes).toContainEqual({
      key: "service.name",
      value: { stringValue: "gateway-eu" },
    });
  });

  it("builds the span from wall-clock bounds in nanoseconds", async () => {
    const ids = await telemetryIds(TELEMETRY);
    const span = spanFor(TELEMETRY, ids);
    expect(span.endTimeUnixNano - span.startTimeUnixNano).toBe(120_000_000);
  });
});

// ---------------------------------------------------------------------------
// #669 — TELEMETRY_ATTRIBUTE_PROFILE
// ---------------------------------------------------------------------------

/**
 * The profile is resolved ONCE per env inside `telemetryEmitterFor` and the
 * emitter is memoized on the env object, so a profile cannot be varied within
 * one isolate through `SELF.fetch`. That is why the three profiles are pinned
 * here — each with its own `env` — while
 * `apps/gateway/test/telemetry/genai.test.ts` proves the DEFAULT one end to
 * end through the deployed Worker.
 */
describe("TELEMETRY_ATTRIBUTE_PROFILE selects the attribute vocabulary", () => {
  const WITH_GENAI: RequestTelemetry = {
    ...TELEMETRY,
    genai: {
      operationName: "chat",
      providerName: "anthropic",
      requestModel: "claude-sonnet",
      responseModel: "claude-sonnet-4-20250514",
      inputTokens: 11,
      outputTokens: 3,
      durationSeconds: 0.12,
    },
  };

  async function emitted(profile: string | undefined): Promise<{
    readonly spanName: string;
    readonly attributes: Record<string, string>;
    readonly metricNames: string[];
  }> {
    const service = recordingService();
    await telemetryEmitterFor({
      TELEMETRY_COLLECTOR: service,
      TELEMETRY_TOKEN: "tok",
      ...(profile === undefined ? {} : { TELEMETRY_ATTRIBUTE_PROFILE: profile }),
    }).emit(WITH_GENAI);
    const traces = service.received[0]?.body as {
      resourceSpans: [
        {
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
    const span = traces.resourceSpans[0].scopeSpans[0].spans[0] as {
      name: string;
      attributes: { key: string; value: { stringValue: string } }[];
    };
    const metrics = service.received[1]?.body as {
      resourceMetrics: [{ scopeMetrics: [{ metrics: { name: string }[] }] }];
    };
    return {
      spanName: span.name,
      attributes: Object.fromEntries(
        span.attributes.map((attribute) => [attribute.key, attribute.value.stringValue]),
      ),
      metricNames: metrics.resourceMetrics[0].scopeMetrics[0].metrics.map((m) => m.name),
    };
  }

  it("emits BOTH vocabularies when the var is absent", async () => {
    const wire = await emitted(undefined);
    expect(wire.attributes["route"]).toBe("createChatCompletion");
    expect(wire.attributes["gen_ai.request.model"]).toBe("claude-sonnet");
    // The legacy span NAME survives the default, because that is what a saved
    // dashboard query filters on.
    expect(wire.spanName).toBe("ferrogate.gateway.request");
    expect(wire.metricNames).toContain("gen_ai.client.token.usage");
    expect(wire.metricNames).toContain("ferrogate.request_logs");
  });

  it("drops the ferrogate.* half and takes the semconv span name under `genai`", async () => {
    const wire = await emitted("genai");
    expect(wire.attributes["route"]).toBeUndefined();
    expect(wire.attributes["request_id"]).toBeUndefined();
    expect(wire.attributes["gen_ai.operation.name"]).toBe("chat");
    expect(wire.attributes["gen_ai.system"]).toBe("anthropic");
    expect(wire.spanName).toBe("chat claude-sonnet");
    expect(wire.metricNames).toContain("gen_ai.client.token.usage");
    // The request/status COUNTERS are not the AI half and are not dropped:
    // narrowing the attribute vocabulary must not take out an operator's HTTP
    // error-rate panel.
    expect(wire.metricNames).toContain("ferrogate.request_logs");
  });

  it("reproduces the exact pre-#669 wire under `ferrogate`", async () => {
    const wire = await emitted("ferrogate");
    expect(wire.spanName).toBe("ferrogate.gateway.request");
    expect(wire.attributes["route"]).toBe("createChatCompletion");
    expect(Object.keys(wire.attributes).some((key) => key.startsWith("gen_ai."))).toBe(false);
    expect(wire.metricNames.some((name) => name.startsWith("gen_ai."))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A telemetry outage is a NO-OP for the request
// ---------------------------------------------------------------------------

describe("a telemetry outage never reaches the request", () => {
  it("swallows a collector that throws", async () => {
    const env = {
      TELEMETRY_COLLECTOR: {
        fetch(): Promise<Response> {
          throw new Error("collector is down");
        },
      },
      TELEMETRY_TOKEN: "tok",
    };
    // `emitRequestTelemetry` is synchronous and must not throw...
    expect(() =>
      emitRequestTelemetry(env, undefined, new Request("https://gw.test/x"), TELEMETRY),
    ).not.toThrow();
    // ...and the deferred work must not reject either, or `waitUntil` would
    // log a Worker exception on a request that succeeded.
    await expect(telemetryFromEnv(env).emit(TELEMETRY)).rejects.toThrow();
  });

  it("swallows a collector that answers 500", async () => {
    const service = recordingService(500);
    const env = { TELEMETRY_COLLECTOR: service, TELEMETRY_TOKEN: "tok" };
    const captured: Promise<unknown>[] = [];
    emitRequestTelemetry(
      env,
      { waitUntil: (work) => captured.push(work) },
      new Request("https://gw.test/x"),
      TELEMETRY,
    );
    await expect(Promise.all(captured)).resolves.toBeDefined();
    expect(service.received).toHaveLength(2);
  });

  it("swallows a waitUntil on an already-finalized context", () => {
    const env = { TELEMETRY_COLLECTOR: recordingService(), TELEMETRY_TOKEN: "tok" };
    expect(() =>
      emitRequestTelemetry(
        env,
        {
          waitUntil(): void {
            throw new Error("The script will never generate a response.");
          },
        },
        new Request("https://gw.test/x"),
        TELEMETRY,
      ),
    ).not.toThrow();
  });

  it("emits nothing at all when no collector is configured", () => {
    const captured: Promise<unknown>[] = [];
    emitRequestTelemetry(
      {},
      { waitUntil: (work) => captured.push(work) },
      new Request("https://gw.test/x"),
      TELEMETRY,
    );
    // Not even a deferred no-op promise: an unconfigured gateway does no work.
    expect(captured).toHaveLength(0);
  });

  it("emits ONCE per inbound Request even when mounted twice", async () => {
    const service = recordingService();
    const env = { TELEMETRY_COLLECTOR: service, TELEMETRY_TOKEN: "tok" };
    const request = new Request("https://gw.test/v1/chat/completions");
    const captured: Promise<unknown>[] = [];
    const ctx = { waitUntil: (work: Promise<unknown>) => captured.push(work) };

    // The route-module mount AND the app-wide middleware mount, on one request.
    emitRequestTelemetry(env, ctx, request, TELEMETRY);
    emitRequestTelemetry(env, ctx, request, TELEMETRY);
    await Promise.all(captured);

    // Two spans/metrics would DOUBLE every inference request's counters.
    expect(service.received.map((r) => new URL(r.url).pathname)).toEqual([
      "/v1/traces",
      "/v1/metrics",
    ]);
  });
});
