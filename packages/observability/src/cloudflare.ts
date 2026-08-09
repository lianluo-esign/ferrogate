/**
 * Cloudflare telemetry backend: OTLP/HTTP+JSON to the FerroGate
 * `telemetry-collector` Worker (#520). Clean-room port of
 * `ferrogate-observability::cloudflare`.
 *
 * Cloudflare exposes no observability ingest endpoint (no OTLP receiver, no
 * Workers Logs write API; Analytics Engine's `writeDataPoint()` is a *binding*,
 * not HTTP). The collector Worker is the ingest endpoint we deploy; it fans out
 * to Analytics Engine + Workers Logs over bindings. OTLP/JSON is used so CF's
 * native Worker OTLP export and FerroGate telemetry line up in one store.
 *
 * The in-Worker collapse IS ported — `./analytics-engine.ts`'s
 * `AnalyticsEngineSink` holds the dataset binding and calls `writeDataPoint()`
 * directly, with no collector hop and no HTTP. It is a SEPARATE type rather
 * than another `TelemetryBackend` because that contract is "build a request,
 * do not send it", and an AE write has no URL, method, body, or response;
 * forcing it into `OtlpHttpRequest` would misdescribe the platform. A
 * deployment picks one: `CloudflareBackend` when telemetry must leave the
 * Worker as OTLP (the container-side shape, ported faithfully here), the AE
 * sink when the gateway holds the binding itself.
 */

import { ALL_SIGNALS, type TelemetryBackend } from "./backend.js";
import { ObservabilityConfigError, ObservabilitySignal } from "./config.js";
import type { GatewayMetricsSnapshot } from "./metrics.js";
import {
  buildOtlpGaugeMetricsRequest,
  buildOtlpLogsRequest,
  buildOtlpMetricsRequest,
  buildOtlpTracesRequest,
} from "./otlp.js";
import type { OtlpGaugePoint, OtlpHttpRequest, OtlpLogRecord, OtlpSpanRecord } from "./otlp.js";

/**
 * Header carrying the fallback tenant for records that have no tenant
 * attribute. Analytics Engine requires exactly one `index` per data point and
 * the collector uses the tenant as that index, so it needs *some* value.
 */
export const TENANT_HEADER = "x-ferrogate-tenant";

const BACKEND_NAME = "cloudflare";

/** Ships telemetry to the FerroGate collector Worker on Cloudflare. */
export class CloudflareBackend implements TelemetryBackend {
  private readonly collectorEndpoint_: string;
  private readonly token: string;
  private defaultTenant_?: string;
  private signals: ObservabilitySignal[];

  constructor(collectorEndpoint: string, token: string) {
    this.collectorEndpoint_ = collectorEndpoint;
    this.token = token;
    this.defaultTenant_ = undefined;
    this.signals = [...ALL_SIGNALS];
  }

  withDefaultTenant(tenant: string | undefined): this {
    this.defaultTenant_ = tenant !== undefined && tenant.trim() !== "" ? tenant : undefined;
    return this;
  }

  withSignals(signals: ObservabilitySignal[]): this {
    this.signals = signals;
    return this;
  }

  collectorEndpoint(): string {
    return this.collectorEndpoint_;
  }

  defaultTenant(): string | undefined {
    return this.defaultTenant_;
  }

  private headers(): Array<[string, string]> {
    const headers: Array<[string, string]> = [["Authorization", `Bearer ${this.token}`]];
    if (this.defaultTenant_ !== undefined) {
      headers.push([TENANT_HEADER, this.defaultTenant_]);
    }
    return headers;
  }

  private authorize(request: OtlpHttpRequest): OtlpHttpRequest {
    request.headers.push(...this.headers());
    return request;
  }

  name(): string {
    return BACKEND_NAME;
  }

  supports(signal: ObservabilitySignal): boolean {
    return this.signals.includes(signal);
  }

  metricsRequest(snapshot: GatewayMetricsSnapshot): OtlpHttpRequest | null {
    if (!this.supports(ObservabilitySignal.Metric)) {
      return null;
    }
    return this.authorize(buildOtlpMetricsRequest(this.collectorEndpoint_, snapshot));
  }

  /**
   * The METRIC signal again, for measurements whose series is data rather than
   * a field on {@link GatewayMetricsSnapshot} — an online-evaluation score is
   * named by a tenant's own criterion id (#692).
   *
   * It honours the same `supports(Metric)` gate as {@link metricsRequest}, so a
   * deployment that exported only traces does not start receiving metrics
   * through a second door, and it returns `null` for an empty batch the way
   * {@link tracesRequest} does — an OTLP envelope with no data points is a
   * round trip that carries nothing.
   */
  gaugeMetricsRequest(
    serviceName: string,
    points: readonly OtlpGaugePoint[],
  ): OtlpHttpRequest | null {
    if (points.length === 0 || !this.supports(ObservabilitySignal.Metric)) {
      return null;
    }
    return this.authorize(
      buildOtlpGaugeMetricsRequest(this.collectorEndpoint_, serviceName, points),
    );
  }

  tracesRequest(serviceName: string, spans: readonly OtlpSpanRecord[]): OtlpHttpRequest | null {
    if (spans.length === 0 || !this.supports(ObservabilitySignal.Trace)) {
      return null;
    }
    return this.authorize(buildOtlpTracesRequest(this.collectorEndpoint_, serviceName, spans));
  }

  logsRequest(serviceName: string, logs: readonly OtlpLogRecord[]): OtlpHttpRequest | null {
    if (logs.length === 0 || !this.supports(ObservabilitySignal.Log)) {
      return null;
    }
    return this.authorize(buildOtlpLogsRequest(this.collectorEndpoint_, serviceName, logs));
  }

  validate(): ObservabilityConfigError | null {
    // Endpoint scheme/emptiness, via the shared builder checks.
    try {
      buildOtlpTracesRequest(this.collectorEndpoint_, "ferrogate", []);
    } catch (error) {
      return error as ObservabilityConfigError;
    }

    if (this.token.trim() === "") {
      return new ObservabilityConfigError("MissingCredential", {
        exporter: BACKEND_NAME,
      });
    }

    // A bearer token on a plaintext connection is a credential disclosure, so
    // http:// is refused — except to loopback, which keeps `wrangler dev`
    // usable for local collector work.
    if (!endpointProtectsCredentials(this.collectorEndpoint_)) {
      return new ObservabilityConfigError("InsecureEndpoint", {
        exporter: BACKEND_NAME,
        endpoint: this.collectorEndpoint_,
      });
    }

    // The send path refuses CR/LF at send time; catching it here turns a silent
    // every-5s export failure into a startup error.
    for (const [name, value] of this.headers()) {
      if (containsCrlf(name) || containsCrlf(value)) {
        return new ObservabilityConfigError("InvalidCredential", {
          exporter: BACKEND_NAME,
        });
      }
    }

    return null;
  }

  /** Redacted debug string — never leaks the bearer token into logs. */
  redactedDebug(): string {
    const tenant =
      this.defaultTenant_ === undefined ? "undefined" : JSON.stringify(this.defaultTenant_);
    return `CloudflareBackend { collectorEndpoint: ${JSON.stringify(
      this.collectorEndpoint_,
    )}, token: "<redacted>", defaultTenant: ${tenant}, signals: [${this.signals.join(", ")}] }`;
  }

  toString(): string {
    return this.redactedDebug();
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.redactedDebug();
  }
}

function containsCrlf(value: string): boolean {
  return value.includes("\r") || value.includes("\n");
}

/**
 * True when a bearer credential can be sent to `endpoint` without exposing it:
 * any https endpoint, or plaintext http to loopback only (which keeps
 * `wrangler dev` usable for local collector work). Public so config validation
 * uses the same rule the backend enforces at export time.
 */
export function endpointProtectsCredentials(endpoint: string): boolean {
  const trimmed = endpoint.trim();
  if (trimmed.startsWith("https://")) {
    return true;
  }
  if (!trimmed.startsWith("http://")) {
    return false;
  }
  const rest = trimmed.slice("http://".length);
  // Drop path/query/fragment, then any userinfo, leaving `host[:port]`.
  const authority = splitFirst(rest, ["/", "?", "#"]);
  const atIdx = authority.lastIndexOf("@");
  const hostPort = atIdx >= 0 ? authority.slice(atIdx + 1) : authority;
  let host: string;
  if (hostPort.startsWith("[")) {
    // Bracketed IPv6 literal, e.g. `[::1]:8787`.
    host = hostPort.slice(1).split("]")[0] ?? "";
  } else {
    host = hostPort.split(":")[0] ?? "";
  }
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function splitFirst(value: string, delimiters: string[]): string {
  let cut = value.length;
  for (const delimiter of delimiters) {
    const idx = value.indexOf(delimiter);
    if (idx >= 0 && idx < cut) {
      cut = idx;
    }
  }
  return value.slice(0, cut);
}
