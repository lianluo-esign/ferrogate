import {
  AE_MAX_DOUBLES,
  AE_MAX_WRITES_PER_INVOCATION,
  type ClampedBlobs,
  clampBlobs,
  clampDoubles,
  clampIndex,
} from "./limits.js";
/**
 * The telemetry **sink port** and its Cloudflare Analytics Engine adapter.
 *
 * Cloudflare exposes no observability *ingest* endpoint anywhere on the
 * platform (`docs/legacy/inventory-data-billing.md` §4.4): there is no OTLP
 * receiver, no Workers Logs write API, and Analytics Engine's
 * `writeDataPoint()` is a Worker **binding** whose only HTTP API is the SQL
 * *read* API. That is the whole reason this Worker exists — it is the ingest
 * endpoint we deploy, and the binding is the write path.
 *
 * Because a binding cannot be observed from inside the Worker that holds it,
 * the write path is narrowed to {@link TelemetrySink}: one method, one data
 * point. {@link AnalyticsEngineSink} is the deployed implementation;
 * {@link RecordingTelemetrySink} is the same port backed by an array so the
 * whole pipeline is assertable with no live dataset.
 */
import type { ParsedLogRecord, ParsedMetricPoint, ParsedSpan } from "./otlp.js";

/** A data point in the exact shape `AnalyticsEngineDataset.writeDataPoint()` takes. */
export interface TelemetryDataPoint {
  /** EXACTLY one entry: the tenant id, clamped to 96 bytes. */
  readonly indexes: readonly string[];
  readonly blobs: readonly string[];
  readonly doubles: readonly number[];
}

/**
 * The narrow write port. `write` is fire-and-forget by contract (Analytics
 * Engine's binding is synchronous and unacknowledged) and MAY throw; the caller
 * — {@link SinkWriter} — is what turns a throw into a counted drop.
 */
export interface TelemetrySink {
  /** Identifies the implementation in the ingest summary log line. */
  readonly name: string;
  write(point: TelemetryDataPoint): void;
}

/**
 * The slice of `AnalyticsEngineDataset` this Worker uses. Declared locally so
 * the adapter can be exercised against a stub, and so `src/` does not depend on
 * the ambient Workers types for its own contract.
 */
export interface AnalyticsEngineLike {
  writeDataPoint(point: {
    indexes?: string[];
    blobs?: string[];
    doubles?: number[];
  }): void;
}

/** The deployed sink: one OTLP record → one Analytics Engine data point. */
export class AnalyticsEngineSink implements TelemetrySink {
  readonly name = "analytics_engine";

  constructor(private readonly dataset: AnalyticsEngineLike) {}

  write(point: TelemetryDataPoint): void {
    this.dataset.writeDataPoint({
      indexes: [...point.indexes],
      blobs: [...point.blobs],
      doubles: [...point.doubles].slice(0, AE_MAX_DOUBLES),
    });
  }
}

/**
 * An in-memory sink implementing the same port. Used by the tests to prove the
 * *deployed* app hands the sink exactly the points it should, with no live
 * dataset and no way for a passing assertion to be an artefact of a stubbed
 * router.
 */
export class RecordingTelemetrySink implements TelemetrySink {
  readonly name = "recording";
  readonly points: TelemetryDataPoint[] = [];

  write(point: TelemetryDataPoint): void {
    this.points.push(point);
  }
}

// ---------------------------------------------------------------------------
// Point builders — blob positions are FIXED
// ---------------------------------------------------------------------------

/**
 * Attribute pairs as `key=value` blobs, sorted for a stable column order across
 * invocations. AE blobs are positional: `blob6` must mean the same thing every
 * time or the dataset is unqueryable.
 */
function attributeBlobs(attributes: Record<string, string>): string[] {
  return Object.keys(attributes)
    .sort()
    .map((key) => `${key}=${attributes[key]}`);
}

/** A built point plus whether the AE clamps had to shorten it. */
export interface BuiltPoint {
  point: TelemetryDataPoint;
  truncated: boolean;
}

function build(
  tenant: string,
  blobCandidates: readonly string[],
  doubles: readonly number[],
): BuiltPoint {
  const clamped: ClampedBlobs = clampBlobs(blobCandidates);
  return {
    point: {
      indexes: [clampIndex(tenant)],
      blobs: clamped.blobs,
      doubles: clampDoubles(doubles),
    },
    truncated: clamped.truncated,
  };
}

/**
 * Metric point. Blobs: 0 `"metric"`, 1 name, 2 service, 3 scope, 4 metric kind,
 * 5+ sorted `key=value` attributes. Doubles: 0 value.
 */
export function buildMetricPoint(metric: ParsedMetricPoint, tenant: string): BuiltPoint {
  return build(
    tenant,
    [
      "metric",
      metric.name,
      metric.serviceName,
      metric.scopeName,
      metric.kind,
      ...attributeBlobs(metric.attributes),
    ],
    [metric.value],
  );
}

/**
 * Span summary. Blobs: 0 `"span"`, 1 name, 2 traceId, 3 spanId, 4 parentSpanId,
 * 5 service, 6 scope, 7+ sorted attributes. Doubles: 0 duration ms, 1 OTLP span
 * kind. The full span also goes to Workers Logs (`logs.ts`).
 */
export function buildSpanPoint(span: ParsedSpan, tenant: string): BuiltPoint {
  return build(
    tenant,
    [
      "span",
      span.name,
      span.traceId,
      span.spanId,
      span.parentSpanId,
      span.serviceName,
      span.scopeName,
      ...attributeBlobs(span.attributes),
    ],
    [span.durationMs, span.kind],
  );
}

/**
 * Log record. Blobs: 0 `"log"`, 1 severity, 2 service, 3 scope, 4 traceId,
 * 5 spanId, 6 body, 7+ sorted attributes. Doubles: 0 OTLP severity number.
 *
 * The Rust-era collector sent log records to Workers Logs ONLY. In-Worker they
 * are written to Analytics Engine as well, so all three signals share one
 * queryable store and a log batch's acceptance is observable in the response
 * exactly like metrics and traces. Workers Logs remains the full-fidelity trail
 * (`logs.ts`) — nothing is dropped, one store is added.
 */
export function buildLogPoint(record: ParsedLogRecord, tenant: string): BuiltPoint {
  return build(
    tenant,
    [
      "log",
      record.severityText || "INFO",
      record.serviceName,
      record.scopeName,
      record.traceId,
      record.spanId,
      record.body,
      ...attributeBlobs(record.attributes),
    ],
    [record.severityNumber],
  );
}

// ---------------------------------------------------------------------------
// Per-invocation writer
// ---------------------------------------------------------------------------

/** What one invocation did, for the response summary and the warn line. */
export interface SinkSummary {
  /** Points actually handed to the sink. */
  written: number;
  /** Points NOT written: over the per-invocation cap, or the sink threw. */
  dropped: number;
  /** Points whose blobs had to be shortened to fit the 16 KB budget. */
  truncated: number;
}

/**
 * Enforces the Analytics Engine per-invocation write cap around any
 * {@link TelemetrySink}.
 *
 * Cloudflare accepts at most {@link AE_MAX_WRITES_PER_INVOCATION}
 * `writeDataPoint()` calls per invocation. Past that the writer stops calling
 * and COUNTS the excess: the count is returned in the HTTP response and emitted
 * as a `console.warn`, so an over-cap batch is visible as data loss instead of
 * vanishing silently.
 */
export class SinkWriter {
  #written = 0;
  #dropped = 0;
  #truncated = 0;
  readonly cap: number;

  constructor(
    private readonly sink: TelemetrySink,
    cap: number = AE_MAX_WRITES_PER_INVOCATION,
  ) {
    this.cap = Math.max(0, Math.min(cap, AE_MAX_WRITES_PER_INVOCATION));
  }

  /** True once the invocation has spent its whole write budget. */
  get atCap(): boolean {
    return this.#written >= this.cap;
  }

  writeMetric(metric: ParsedMetricPoint, tenant: string): boolean {
    return this.write(buildMetricPoint(metric, tenant));
  }

  writeSpan(span: ParsedSpan, tenant: string): boolean {
    return this.write(buildSpanPoint(span, tenant));
  }

  writeLog(record: ParsedLogRecord, tenant: string): boolean {
    return this.write(buildLogPoint(record, tenant));
  }

  /** Write one pre-built point. Returns false when it was dropped. */
  write(built: BuiltPoint): boolean {
    if (built.truncated) this.#truncated++;
    if (this.atCap) {
      this.#dropped++;
      return false;
    }
    try {
      this.sink.write(built.point);
      this.#written++;
      return true;
    } catch (error) {
      // A throwing write must not abort the rest of the batch.
      this.#dropped++;
      console.warn(
        JSON.stringify({
          event: "telemetry.sink.write_failed",
          sink: this.sink.name,
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      return false;
    }
  }

  /**
   * Close out the invocation: emit ONE warn line when anything was lost or
   * clamped, and hand back the counters for the HTTP response.
   */
  finish(route: string): SinkSummary {
    const summary: SinkSummary = {
      written: this.#written,
      dropped: this.#dropped,
      truncated: this.#truncated,
    };
    if (summary.dropped > 0 || summary.truncated > 0) {
      console.warn(
        JSON.stringify({
          event: "telemetry.sink.limits",
          route,
          sink: this.sink.name,
          written: summary.written,
          dropped: summary.dropped,
          truncated: summary.truncated,
          cap: this.cap,
          reason: this.atCap ? "per_invocation_write_cap" : "sink_write_error",
        }),
      );
    }
    return summary;
  }
}
