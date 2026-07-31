/**
 * The gateway's telemetry EGRESS seam — bindings in, OTLP out.
 *
 * `@ferrogate/observability` is an I/O-free crate by design: its backends BUILD
 * OTLP/HTTP+JSON requests and never send them (`CloudflareBackend` returns an
 * `OtlpHttpRequest`, it does not `fetch` one). Something has to own the send,
 * and until this directory existed nothing did — `grep -rn
 * '@ferrogate/observability' apps/gateway/src` returned three docstring
 * mentions and one TYPE-ONLY import in `cache/metrics.ts`. The deployed Worker
 * emitted no metric, no span and no log to anything, while `apps/telemetry`
 * shipped a complete OTLP receiver with an Analytics Engine sink and received
 * nothing from the data plane.
 *
 * This module is the vocabulary; `./emit.ts` is the send.
 */

/**
 * The service binding shape — `apps/telemetry`'s Worker, reachable without
 * leaving Cloudflare's network.
 *
 * A service binding is preferred over an HTTPS hop for three reasons that all
 * matter on the request path: it costs no DNS/TLS handshake, it never leaves
 * the colo, and it cannot be intercepted, so the bearer token never crosses a
 * public network. The URL still carries the OTLP path (`/v1/metrics`,
 * `/v1/traces`) because that is how the collector routes; the HOST in it is
 * synthetic and ignored by the binding.
 */
export interface TelemetryService {
  fetch(request: Request): Promise<Response>;
}

/**
 * Bindings and vars the gateway's telemetry egress reads. Every one is
 * OPTIONAL: an unconfigured gateway emits nothing, which is exactly the Rust
 * posture (`[observability] exporters` empty ⇒ no exporter is built).
 */
export interface GatewayTelemetryBindings {
  /**
   * `[[services]] binding = "TELEMETRY_COLLECTOR"` → the `ferrogate-telemetry`
   * Worker. The PREFERRED transport; see {@link TelemetryService}.
   */
  readonly TELEMETRY_COLLECTOR?: TelemetryService | undefined;
  /**
   * Absolute base URL of the collector, used when no service binding exists
   * (a collector deployed on another account, or `wrangler dev` against a
   * locally-running `apps/telemetry`). `https://`, or `http://` to loopback
   * only — `CloudflareBackend.validate()` refuses to put a bearer token on any
   * other plaintext endpoint, and this module honours that answer.
   */
  readonly TELEMETRY_ENDPOINT?: string | undefined;
  /**
   * The collector's `COLLECTOR_TOKEN`. A SECRET (`wrangler secret put`), never
   * a plaintext var. Without it nothing is emitted: the collector answers 401
   * to an unauthenticated ingest, so emitting anyway would be a guaranteed
   * round trip to a rejection on every single request.
   */
  readonly TELEMETRY_TOKEN?: string | undefined;
  /**
   * `resource.service.name` on every emitted record. Defaults to
   * {@link DEFAULT_TELEMETRY_SERVICE_NAME}.
   */
  readonly TELEMETRY_SERVICE_NAME?: string | undefined;
  /**
   * Comma-separated subset of `metric,trace,log` to emit. Absent ⇒ all of them,
   * matching `CloudflareBackend`'s default `ALL_SIGNALS`.
   */
  readonly TELEMETRY_SIGNALS?: string | undefined;
  readonly [binding: string]: unknown;
}

/** `resource.service.name` when `TELEMETRY_SERVICE_NAME` is unset. */
export const DEFAULT_TELEMETRY_SERVICE_NAME = "ferrogate-gateway";

/**
 * The synthetic origin used when the transport is a SERVICE BINDING.
 *
 * A service binding routes by BINDING, not by hostname, so the authority is
 * never resolved — but `buildOtlp*Request` still needs a syntactically valid
 * absolute URL to append `/v1/traces` to, and `CloudflareBackend.validate()`
 * refuses a bearer token on a non-https endpoint. `https://` on an unresolvable
 * `.internal` host satisfies both without implying a real destination.
 */
export const SERVICE_BINDING_ORIGIN = "https://telemetry.ferrogate.internal";

/**
 * One request's worth of telemetry — the fields of
 * `@ferrogate/observability`'s {@link GATEWAY_REQUEST_SPAN} template, plus the
 * wall-clock bounds a span needs.
 *
 * There is deliberately no free-form attribute bag. `GATEWAY_REQUEST_SPAN`
 * names six fields and issue #500 is the reason the metric labels are
 * low-cardinality; an open map here would be the obvious place for a caller to
 * put a request id, a user id, or a prompt.
 */
export interface RequestTelemetry {
  /** Gateway request id (`x-request-id`). */
  readonly requestId: string;
  /**
   * The trace id the request is correlated under — the caller's adopted W3C
   * trace id when `middleware/trace.ts` accepted a `traceparent`, else the
   * request id. Normalized to 32 hex characters by `./emit.ts`.
   */
  readonly traceId: string;
  readonly method: string;
  readonly path: string;
  /** Contract `operation_id`, which is the gateway's own route label. */
  readonly route: string;
  readonly statusCode: number;
  /** `Date.now()` before the handler ran. */
  readonly startedAtMs: number;
  /** `Date.now()` once the response object existed. */
  readonly endedAtMs: number;
  /**
   * Authenticated tenant, used as the collector's Analytics Engine INDEX. Never
   * a client-declared value — `apps/telemetry` falls back to `unknown` rather
   * than trusting one.
   */
  readonly tenantId?: string | undefined;
}

/**
 * The send port. `emit` MUST NOT throw and MUST NOT be awaited by the request
 * path — see `./emit.ts` for how both are enforced.
 */
export interface TelemetryEmitter {
  /** `true` when this emitter has a destination; `false` for the no-op. */
  readonly enabled: boolean;
  /** Identifies the transport in a test assertion (`service` | `https` | `none`). */
  readonly transport: "service" | "https" | "none";
  emit(telemetry: RequestTelemetry): Promise<void>;
}
