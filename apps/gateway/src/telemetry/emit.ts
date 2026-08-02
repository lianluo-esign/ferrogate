/**
 * Telemetry EGRESS — the gateway's request path → `apps/telemetry`.
 *
 * `@ferrogate/observability` builds OTLP/HTTP+JSON requests and, by contract,
 * never sends them. This module is the sender, and it is the ONLY thing in
 * `apps/gateway/src` that constructs a `CloudflareBackend`, an `OtlpSpanRecord`
 * or a `GatewayMetricsSnapshot` for delivery.
 *
 * ## THE TWO RULES A TELEMETRY PATH MUST NOT BREAK
 *
 * ### It must never delay the client's response
 *
 * {@link emitRequestTelemetry} returns `void` SYNCHRONOUSLY and hands the work
 * to `ctx.waitUntil`, which is the Workers primitive for "keep the isolate
 * alive past the flushed response without holding the response". Nothing on the
 * request path awaits the collector: the OTLP body is serialized inside the
 * deferred task, not before it, so even the `JSON.stringify` of a large
 * snapshot happens after the client has been answered.
 *
 * ### A telemetry outage must be a NO-OP for the request
 *
 * Every failure mode is swallowed inside {@link deliver}: an unreachable
 * collector, a 401 from a rotated token, a 500, a `waitUntil` on an already
 * finalized context, and a serialization failure. `emitRequestTelemetry` is
 * additionally wrapped, so even a synchronous throw while BUILDING the payload
 * cannot reach the handler. A collector that is down costs the gateway a
 * pending promise and nothing else.
 *
 * ## Transport
 *
 * Two arms, preferring the one that never leaves Cloudflare:
 *
 *  1. `TELEMETRY_COLLECTOR` service binding → `apps/telemetry` directly. No
 *     DNS, no TLS handshake, no public hop for the bearer token.
 *  2. `TELEMETRY_ENDPOINT` + `TELEMETRY_TOKEN` → ordinary `fetch`, for a
 *     collector on another account or a local `wrangler dev` one.
 *
 * With neither configured the emitter is {@link NO_TELEMETRY} and every emit is
 * a no-op — the Rust posture for an empty `[observability] exporters` table.
 *
 * ## PORT-TODO(L: inventory-data-billing §4.5, `packages/observability/src/prometheus.ts`)
 *
 * The one thing that genuinely does not port is metric ACCUMULATION. Rust holds
 * a process-lifetime counter bag and an exporter reads a CUMULATIVE snapshot
 * off it every few seconds; a Worker has no process to hold one in, and a
 * module-scope bag would be per-isolate (wrong) and lost on eviction (worse).
 *
 * So what leaves here is a per-request DELTA — `requestLogTotal: 1` and one
 * `requestStatusTotals` entry — carried in the envelope
 * `buildOtlpMetricsRequest` produces, which hard-codes
 * `aggregationTemporality: 2` (CUMULATIVE). That label is inaccurate for these
 * points and is stated rather than hidden: the field is written by
 * `packages/observability`, which this slice does not own, and the DESTINATION
 * makes it harmless — `apps/telemetry` writes each point to Analytics Engine,
 * whose query model is `SUM(double1)` over a time window, i.e. exactly the
 * delta reading. A Prometheus-scraping deployment would read these wrongly, and
 * that is the same gap `prometheus.ts` already marks: the renderer exists, the
 * accumulator it renders from cannot. `test/telemetry/emit.test.ts` pins the
 * delta shape so a future accumulator changes a failing test rather than
 * silently double-counting.
 */
import {
  CloudflareBackend,
  GATEWAY_REQUEST_SPAN,
  ObservabilitySignal,
  TelemetryAttributeProfile,
  defaultGatewayMetricsSnapshot,
  genAiSpanAttributes,
  genAiSpanName,
  otlpAttribute,
  profileEmitsFerrogate,
  profileEmitsGenAi,
  telemetryAttributeProfile,
} from "@ferrogate/observability";
import type {
  GatewayMetricsSnapshot,
  OtlpAttribute,
  OtlpHttpRequest,
  OtlpSpanRecord,
} from "@ferrogate/observability";
import {
  DEFAULT_TELEMETRY_SERVICE_NAME,
  SERVICE_BINDING_ORIGIN,
  type GatewayTelemetryBindings,
  type RequestTelemetry,
  type TelemetryEmitter,
  type TelemetryService,
} from "./ports.js";

/** The emitter for a gateway with no telemetry destination configured. */
export const NO_TELEMETRY: TelemetryEmitter = {
  enabled: false,
  transport: "none",
  async emit(): Promise<void> {
    // No destination: nothing to build, nothing to send, nothing to fail.
  },
};

/** Parse `TELEMETRY_SIGNALS` (`"metric,trace"`); absent/blank ⇒ all signals. */
function signalsFromVar(raw: string | undefined): ObservabilitySignal[] | null {
  if (raw === undefined || raw.trim() === "") {
    return null;
  }
  const wanted: ObservabilitySignal[] = [];
  for (const token of raw.split(",")) {
    switch (token.trim().toLowerCase()) {
      case "metric":
      case "metrics":
        wanted.push(ObservabilitySignal.Metric);
        break;
      case "trace":
      case "traces":
        wanted.push(ObservabilitySignal.Trace);
        break;
      case "log":
      case "logs":
        wanted.push(ObservabilitySignal.Log);
        break;
      default:
        // An unknown token is ignored rather than fatal: a typo must not take
        // the data plane down, and it cannot widen anything.
        break;
    }
  }
  return wanted;
}

/** True for an object that quacks like a `[[services]]` binding. */
function isService(value: unknown): value is TelemetryService {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as TelemetryService).fetch === "function"
  );
}

/**
 * Build the emitter for a Worker `env`.
 *
 * Both arms need `TELEMETRY_TOKEN`: the collector answers 401 to an
 * unauthenticated ingest (`apps/telemetry/src/auth.ts`), so emitting without
 * one would buy a guaranteed rejected round trip per request. A misconfigured
 * backend — `CloudflareBackend.validate()` returning an error, e.g. a bearer
 * token aimed at a non-loopback `http://` endpoint — degrades to
 * {@link NO_TELEMETRY} rather than throwing, because a config mistake in
 * OBSERVABILITY must never take INFERENCE down.
 */
export function telemetryEmitterFor(env: GatewayTelemetryBindings): TelemetryEmitter {
  const token = env.TELEMETRY_TOKEN;
  if (typeof token !== "string" || token.trim() === "") {
    return NO_TELEMETRY;
  }

  const service = isService(env.TELEMETRY_COLLECTOR) ? env.TELEMETRY_COLLECTOR : undefined;
  const endpoint =
    service !== undefined
      ? SERVICE_BINDING_ORIGIN
      : typeof env.TELEMETRY_ENDPOINT === "string" && env.TELEMETRY_ENDPOINT.trim() !== ""
        ? env.TELEMETRY_ENDPOINT.trim()
        : undefined;
  if (endpoint === undefined) {
    return NO_TELEMETRY;
  }

  const serviceName =
    typeof env.TELEMETRY_SERVICE_NAME === "string" && env.TELEMETRY_SERVICE_NAME.trim() !== ""
      ? env.TELEMETRY_SERVICE_NAME.trim()
      : DEFAULT_TELEMETRY_SERVICE_NAME;

  const backend = new CloudflareBackend(endpoint, token);
  const signals = signalsFromVar(env.TELEMETRY_SIGNALS);
  if (signals !== null) {
    backend.withSignals(signals);
  }
  if (backend.validate() !== null) {
    return NO_TELEMETRY;
  }

  // #669. Resolved ONCE here rather than per emission, alongside the signal
  // set, because it is deployment configuration and not per-request state.
  const profile = telemetryAttributeProfile(env.TELEMETRY_ATTRIBUTE_PROFILE);

  return {
    enabled: true,
    transport: service !== undefined ? "service" : "https",
    async emit(telemetry: RequestTelemetry): Promise<void> {
      // The tenant becomes the collector's Analytics Engine index; it needs
      // *some* value, and `CloudflareBackend` is the thing that carries it.
      backend.withDefaultTenant(telemetry.tenantId);
      const ids = await telemetryIds(telemetry);
      const requests: (OtlpHttpRequest | null)[] = [
        backend.tracesRequest(serviceName, [spanFor(telemetry, ids, profile)]),
        backend.metricsRequest(snapshotFor(telemetry, serviceName, profile)),
      ];
      for (const request of requests) {
        if (request !== null) {
          await send(service, request);
        }
      }
    },
  };
}

/** OTLP ids for one request: 32 hex trace, 16 hex span. */
export interface TelemetryIds {
  readonly traceId: string;
  readonly spanId: string;
}

/**
 * Normalize the gateway's correlation id into OTLP's hex id space.
 *
 * `middleware/trace.ts` yields EITHER an adopted 32-hex W3C trace id (a valid
 * OTLP trace id, used verbatim so a span emitted here joins the caller's
 * existing trace) OR the gateway's own `fg-<16 hex>` request id, which is not
 * hex at all. `apps/telemetry`'s `spanSchema` requires both ids, and a
 * fabricated constant would collapse every uncorrelated request onto one trace.
 *
 * So a non-conforming id is HASHED: SHA-256, first 16 bytes as the trace id and
 * the first 8 bytes of a `:span`-suffixed digest as the span id. Deterministic
 * (the same request id always maps to the same trace), collision-resistant, and
 * it never invents a correlation that did not exist.
 */
export async function telemetryIds(telemetry: RequestTelemetry): Promise<TelemetryIds> {
  const traceId = /^[0-9a-f]{32}$/.test(telemetry.traceId)
    ? telemetry.traceId
    : await hashHex(telemetry.traceId, 16);
  const spanId = await hashHex(`${telemetry.requestId}:span`, 8);
  return { traceId, spanId };
}

async function hashHex(value: string, bytes: number): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  const view = new Uint8Array(digest).subarray(0, bytes);
  let hex = "";
  for (const byte of view) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * `GATEWAY_REQUEST_SPAN` as an OTLP span record, in whichever attribute
 * vocabulary the deployment publishes (#669).
 *
 * The `ferrogate.*` attribute keys are read OFF the template rather than typed
 * out, so a field added to `@ferrogate/observability`'s canonical span is a
 * compile-time — and test-time — obligation here instead of silent drift.
 *
 * ## The span NAME is not changed by the default profile, on purpose
 *
 * The convention asks for `{gen_ai.operation.name} {gen_ai.request.model}`, and
 * a deployment gets exactly that under the `genai` profile. Under `dual` — the
 * default — the name stays `ferrogate.gateway.request`, because a span name is
 * what a saved Grafana/Datadog query filters on and renaming it on upgrade
 * would break every existing dashboard, which is the one thing #669 says not to
 * do. The `gen_ai.*` ATTRIBUTES are what Datadog, Langfuse and Arize key their
 * LLM views off, and those arrive under `dual` too, so the recognition the
 * issue asks for does not depend on the rename.
 */
export function spanFor(
  telemetry: RequestTelemetry,
  ids: TelemetryIds,
  profile: TelemetryAttributeProfile = TelemetryAttributeProfile.Dual,
): OtlpSpanRecord {
  const values: Record<string, string> = {
    request_id: telemetry.requestId,
    trace_id: ids.traceId,
    method: telemetry.method,
    path: telemetry.path,
    route: telemetry.route,
    status_code: String(telemetry.statusCode),
  };
  const attributes: OtlpAttribute[] = [];
  if (profileEmitsFerrogate(profile)) {
    attributes.push(
      ...GATEWAY_REQUEST_SPAN.fields.map((field) => otlpAttribute(field, values[field] ?? "")),
    );
  }
  const genai = profileEmitsGenAi(profile) ? telemetry.genai : undefined;
  if (genai !== undefined) {
    attributes.push(...genAiSpanAttributes(genai));
  }

  // The semconv name is only taken when the legacy half is GONE. Under `dual`
  // both vocabularies are present and the legacy name is the compatible one;
  // under `ferrogate` there is no GenAI invocation to name it after anyway.
  const name =
    genai !== undefined && !profileEmitsFerrogate(profile)
      ? genAiSpanName(genai)
      : GATEWAY_REQUEST_SPAN.name;

  const MS_TO_NS = 1_000_000;
  return {
    traceId: ids.traceId,
    spanId: ids.spanId,
    name,
    startTimeUnixNano: telemetry.startedAtMs * MS_TO_NS,
    endTimeUnixNano: telemetry.endedAtMs * MS_TO_NS,
    attributes,
  };
}

/**
 * The per-request metric DELTA (see the temporality PORT-TODO in the module
 * docs).
 *
 * `requestErrorTotal` follows the Rust definition verbatim — "structured
 * request logs with errors or 4xx/5xx statuses" — so a 4xx the gateway itself
 * produced (a `model_not_found`, a `scope_denied`) counts as an error, which is
 * what makes the ratio actionable.
 *
 * `genAiInvocations` carries at most ONE entry — this is a per-request
 * snapshot, not an accumulator — and is empty for every request that reached no
 * model. The `ferrogate.*` counters are unaffected by the profile: they are the
 * request/status series the gateway has always published for all 33 operations,
 * not the AI-specific half #669 is about, and suppressing them for a deployment
 * that opted into `genai` would take out its HTTP error-rate panel too.
 */
export function snapshotFor(
  telemetry: RequestTelemetry,
  serviceName: string,
  profile: TelemetryAttributeProfile = TelemetryAttributeProfile.Dual,
): GatewayMetricsSnapshot {
  const genai = profileEmitsGenAi(profile) ? telemetry.genai : undefined;
  return {
    ...defaultGatewayMetricsSnapshot(),
    serviceName,
    requestLogTotal: 1,
    requestErrorTotal: telemetry.statusCode >= 400 ? 1 : 0,
    requestStatusTotals: [{ statusCode: telemetry.statusCode, count: 1 }],
    genAiInvocations: genai === undefined ? [] : [genai],
  };
}

/** Ship one built OTLP request down whichever transport is configured. */
async function send(service: TelemetryService | undefined, built: OtlpHttpRequest): Promise<void> {
  const headers = new Headers({ "content-type": built.contentType });
  for (const [name, value] of built.headers) {
    headers.set(name, value);
  }
  const request = new Request(built.url, {
    method: built.method,
    headers,
    body: built.body,
  });
  const response =
    service !== undefined ? await service.fetch(request) : await globalThis.fetch(request);
  // The body is drained so the connection is not left half-read. The STATUS is
  // deliberately not acted on: a rejected batch is telemetry lost, never a
  // request failed.
  await response.body?.cancel();
}

/**
 * FIRE THE EMISSION. Synchronous, non-throwing, never awaited by a handler.
 *
 * The `WeakSet` keyed on the inbound `Request` makes a second call for the same
 * request a no-op. That is not defensive coding: this is mounted today inside
 * `inference/route-module.ts` (the nine inference operations), and the
 * integrate step is expected to ALSO mount it app-wide in `GATEWAY_MIDDLEWARE`
 * so the other 25 operations are covered — see the WIRING block in
 * `./index.ts`. Without the guard that second mount would double every
 * inference request's metrics.
 */
const EMITTED = new WeakSet<Request>();

export function emitRequestTelemetry(
  env: unknown,
  ctx: { waitUntil(work: Promise<unknown>): void } | undefined,
  request: Request,
  telemetry: RequestTelemetry,
): void {
  try {
    if (EMITTED.has(request)) {
      return;
    }
    const emitter = telemetryFromEnv(env);
    if (!emitter.enabled) {
      return;
    }
    EMITTED.add(request);
    const work = deliver(emitter, telemetry);
    if (ctx === undefined) {
      // No `ExecutionContext` (a unit test driving `app.request`). `deliver`
      // never rejects, so a detached promise cannot become an unhandled
      // rejection; the shape — not awaited — is the same.
      void work;
      return;
    }
    ctx.waitUntil(work);
  } catch {
    // `ctx.waitUntil` throws on an already-finalized context, and reading a
    // hostile `env` could throw too. Neither may reach the client.
  }
}

/** Build + send, swallowing everything. NEVER REJECTS. */
async function deliver(emitter: TelemetryEmitter, telemetry: RequestTelemetry): Promise<void> {
  try {
    await emitter.emit(telemetry);
  } catch {
    // A telemetry outage is a no-op for the request. See the module docs.
  }
}

/**
 * The emitter for a Worker `env`, memoized ON the env object.
 *
 * Bindings are per request while the backend is cheap-but-not-free to build
 * (`CloudflareBackend.validate()` parses the endpoint). Memoizing on the env
 * object rather than in a module-scope slot is the same rule the rest of this
 * app follows: workerd hands each request its own `env`, so nothing can leak
 * between two concurrent requests.
 */
const BY_ENV = new WeakMap<object, TelemetryEmitter>();

export function telemetryFromEnv(env: unknown): TelemetryEmitter {
  if (typeof env !== "object" || env === null) {
    return NO_TELEMETRY;
  }
  const cached = BY_ENV.get(env);
  if (cached !== undefined) {
    return cached;
  }
  const built = telemetryEmitterFor(env as GatewayTelemetryBindings);
  BY_ENV.set(env, built);
  return built;
}
