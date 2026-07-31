/**
 * `AnalyticsEngineSink` — the IN-WORKER telemetry destination (inventory §4.5).
 *
 * ## What this closes
 *
 * `CloudflareBackend` (`./cloudflare.ts`) ports the container-side shape:
 * build an OTLP/JSON request, hand it to a caller that POSTs it to the
 * `telemetry-collector` Worker, which then fans out to Analytics Engine over a
 * binding. Inside a Worker that hop is unnecessary — the gateway can hold the
 * Analytics Engine binding itself and call `writeDataPoint()` directly.
 *
 * This module is that direct sink. It is deliberately NOT a
 * {@link ../backend.js TelemetryBackend}: that contract's whole shape is
 * "build a request, do not send it", and an Analytics Engine write is not a
 * request — it has no URL, no method, no body, and no response. Forcing it into
 * `OtlpHttpRequest` would be a lie about what the platform does. Both live side
 * by side, and a deployment picks one.
 *
 * ## The hard limits are enforced here, on purpose
 *
 * Analytics Engine silently DROPS a data point that violates its per-point
 * limits — no throw, no error, no counter. A metrics pipeline that quietly
 * stops recording is worse than one that fails, so {@link writeDataPoint}
 * validates before writing and reports the violation instead:
 *
 *  - exactly ONE index (AE requires it, and it is what the dataset is sharded
 *    and sampled by); its UTF-8 length must be ≤ 96 bytes;
 *  - at most 20 blobs and at most 20 doubles;
 *  - at most 5120 bytes of blobs in total.
 *
 * `indexes[0]` is the TENANT for every point this module writes, matching what
 * the collector Worker used the `x-ferrogate-tenant` header for.
 */
import { ObservabilityConfigError } from "./config.js";
import type { GatewayMetricsSnapshot } from "./metrics.js";
import type { OtlpAttribute, OtlpLogRecord, OtlpSpanRecord } from "./otlp.js";

/** Max `indexes[0]` length in UTF-8 bytes. */
export const AE_MAX_INDEX_BYTES = 96;
/** Max `blobs` entries per data point. */
export const AE_MAX_BLOBS = 20;
/** Max `doubles` entries per data point. */
export const AE_MAX_DOUBLES = 20;
/** Max total `blobs` payload per data point, in UTF-8 bytes. */
export const AE_MAX_BLOB_BYTES = 5120;

/** One Analytics Engine data point. */
export interface AnalyticsEngineDataPoint {
  indexes: [string];
  blobs?: string[];
  doubles?: number[];
}

/**
 * The `[[analytics_engine_datasets]]` binding surface this sink needs.
 *
 * Declared structurally rather than imported so this module stays usable from a
 * non-Worker context (the CLI's `status` command) and so a test can supply a
 * recorder — see the note in `test/analytics-engine.test.ts` about why a
 * recorder is the right instrument for THIS code and a fake D1 would not be.
 */
export interface AnalyticsEngineDatasetBinding {
  writeDataPoint(event: AnalyticsEngineDataPoint): void;
}

const UTF8 = new TextEncoder();

/**
 * OTLP attributes are a `(key, value)` LIST, not a map, so the per-record
 * tenant has to be looked up rather than indexed. First match wins, matching
 * how an OTLP consumer reads a duplicated key.
 */
function attributeValue(
  attributes: readonly OtlpAttribute[] | undefined,
  key: string,
): string | undefined {
  return attributes?.find((a) => a.key === key)?.value;
}

function byteLength(value: string): number {
  return UTF8.encode(value).length;
}

/**
 * Validate one data point against the Analytics Engine per-point limits.
 * Returns `null` when it is writable, otherwise the reason it would be dropped.
 */
export function analyticsEngineDataPointViolation(
  point: AnalyticsEngineDataPoint,
): string | null {
  if (point.indexes.length !== 1) {
    return `analytics engine requires exactly 1 index, got ${point.indexes.length}`;
  }
  const index = point.indexes[0];
  if (index === "") {
    return "analytics engine index must not be empty";
  }
  const indexBytes = byteLength(index);
  if (indexBytes > AE_MAX_INDEX_BYTES) {
    return `analytics engine index is ${indexBytes} bytes, over the ${AE_MAX_INDEX_BYTES}-byte limit`;
  }
  const blobs = point.blobs ?? [];
  if (blobs.length > AE_MAX_BLOBS) {
    return `analytics engine accepts at most ${AE_MAX_BLOBS} blobs, got ${blobs.length}`;
  }
  const doubles = point.doubles ?? [];
  if (doubles.length > AE_MAX_DOUBLES) {
    return `analytics engine accepts at most ${AE_MAX_DOUBLES} doubles, got ${doubles.length}`;
  }
  const blobBytes = blobs.reduce((total, blob) => total + byteLength(blob), 0);
  if (blobBytes > AE_MAX_BLOB_BYTES) {
    return `analytics engine blobs total ${blobBytes} bytes, over the ${AE_MAX_BLOB_BYTES}-byte limit`;
  }
  if (doubles.some((d) => !Number.isFinite(d))) {
    return "analytics engine doubles must be finite numbers";
  }
  return null;
}

/** A data point the sink refused to write, and why. */
export interface DroppedDataPoint {
  reason: string;
  point: AnalyticsEngineDataPoint;
}

const BACKEND_NAME = "analytics_engine";

/**
 * Writes FerroGate telemetry straight to an Analytics Engine dataset binding.
 *
 * Every `write*` method returns the data points it REFUSED, so a caller can
 * surface them (a log line, a counter) rather than losing them the way a bare
 * `writeDataPoint()` would.
 */
export class AnalyticsEngineSink {
  #dropped: DroppedDataPoint[] = [];

  constructor(
    private readonly dataset: AnalyticsEngineDatasetBinding,
    /** Fallback index for records carrying no tenant attribute. */
    private readonly defaultTenant: string,
  ) {}

  name(): string {
    return BACKEND_NAME;
  }

  /**
   * Fails fast at startup on a default tenant AE would reject as an index.
   *
   * `MissingCredential` / `InvalidCredential` are reused rather than a new
   * error kind: the tenant IS the credential-shaped required field for this
   * backend (AE demands exactly one index per point and the tenant is it), and
   * the existing taxonomy is what the CLI status output already renders.
   */
  validate(): ObservabilityConfigError | null {
    if (this.defaultTenant.trim() === "") {
      return new ObservabilityConfigError("MissingCredential", { exporter: BACKEND_NAME });
    }
    if (byteLength(this.defaultTenant) > AE_MAX_INDEX_BYTES) {
      return new ObservabilityConfigError("InvalidCredential", { exporter: BACKEND_NAME });
    }
    return null;
  }

  /** Data points refused so far, in write order. */
  dropped(): readonly DroppedDataPoint[] {
    return this.#dropped;
  }

  /** Clear the dropped-point buffer (after a caller has reported them). */
  clearDropped(): void {
    this.#dropped = [];
  }

  /** Write one point, or record why it was refused. Returns whether it was written. */
  writeDataPoint(point: AnalyticsEngineDataPoint): boolean {
    const violation = analyticsEngineDataPointViolation(point);
    if (violation !== null) {
      this.#dropped.push({ reason: violation, point });
      return false;
    }
    this.dataset.writeDataPoint(point);
    return true;
  }

  #index(tenant: string | undefined): string {
    return tenant !== undefined && tenant.trim() !== "" ? tenant : this.defaultTenant;
  }

  /**
   * One data point per snapshot, carrying the scalar gateway totals.
   *
   * Deliberately NOT one point per counter: AE bills and samples per data
   * point, and the totals are read together. The high-cardinality per-model /
   * per-method breakdowns get their own points below, where the cardinality is
   * the whole reason to keep them separate.
   */
  writeMetrics(snapshot: GatewayMetricsSnapshot, tenant?: string): number {
    let written = 0;
    if (
      this.writeDataPoint({
        indexes: [this.#index(tenant)],
        blobs: ["gateway_totals", snapshot.serviceName],
        doubles: [
          snapshot.requestLogTotal,
          snapshot.requestErrorTotal,
          snapshot.billingEventTotal,
          snapshot.tokenTotals.promptTokens,
          snapshot.tokenTotals.completionTokens,
          snapshot.tokenTotals.totalTokens,
        ],
      })
    ) {
      written += 1;
    }
    for (const model of snapshot.modelProviderTotals) {
      if (
        this.writeDataPoint({
          indexes: [this.#index(tenant)],
          blobs: ["model_provider", snapshot.serviceName, model.logicalModel, model.provider],
          doubles: [model.requests, model.totalTokens],
        })
      ) {
        written += 1;
      }
    }
    return written;
  }

  /** One data point per span. */
  writeSpans(serviceName: string, spans: readonly OtlpSpanRecord[], tenant?: string): number {
    let written = 0;
    for (const span of spans) {
      if (
        this.writeDataPoint({
          indexes: [this.#index(attributeValue(span.attributes, "tenant") ?? tenant)],
          blobs: ["span", serviceName, span.name, span.traceId, span.spanId],
          doubles: [span.startTimeUnixNano / 1e6, span.endTimeUnixNano / 1e6],
        })
      ) {
        written += 1;
      }
    }
    return written;
  }

  /** One data point per log record. */
  writeLogs(serviceName: string, logs: readonly OtlpLogRecord[], tenant?: string): number {
    let written = 0;
    for (const log of logs) {
      if (
        this.writeDataPoint({
          indexes: [this.#index(attributeValue(log.attributes, "tenant") ?? tenant)],
          blobs: ["log", serviceName, log.severityText, log.body],
          doubles: [log.timeUnixNano / 1e6],
        })
      ) {
        written += 1;
      }
    }
    return written;
  }
}
