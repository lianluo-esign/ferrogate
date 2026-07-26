// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — Analytics Engine writes for the
//   telemetry-collector Worker (issue #520), with every AE hard limit enforced BEFORE the
//   write. `writeDataPoint()` is a Worker BINDING with no HTTP equivalent, which is the
//   entire reason this collector has to exist: a Rust process cannot reach it directly.

import type { ParsedMetricPoint, ParsedSpan, Attributes } from "./otlp";
import {
  AE_MAX_DOUBLES,
  AE_MAX_WRITES_PER_INVOCATION,
  clampBlobs,
  clampDoubles,
  clampIndex,
} from "./limits";

/** A data point in the exact shape `AnalyticsEngineDataset.writeDataPoint()` takes. */
export interface DataPoint {
  /** EXACTLY one entry: the tenant id, clamped to 96 bytes. */
  indexes: string[];
  blobs: string[];
  doubles: number[];
}

/** A built point plus whether the limit clamps had to shorten it. */
export interface BuiltPoint {
  point: DataPoint;
  truncated: boolean;
}

/** What one invocation did, for the response summary and the warn line. */
export interface AnalyticsSummary {
  /** `writeDataPoint()` calls actually made. */
  written: number;
  /** Points NOT written: over the per-invocation cap, or no binding. */
  dropped: number;
  /** Points whose blobs had to be shortened to fit the 16 KB budget. */
  truncated: number;
}

/**
 * Attribute pairs as `key=value` blobs, sorted for a stable column order across
 * invocations (AE blobs are positional — `blob6` must mean the same thing every
 * time or the dataset is unqueryable).
 */
function attributeBlobs(attributes: Attributes): string[] {
  return Object.keys(attributes)
    .sort()
    .map((key) => `${key}=${attributes[key]}`);
}

/**
 * Build the AE point for a metric data point.
 *
 * Blob positions are FIXED: 0 kind, 1 metric name, 2 service, 3 scope, 4 metric
 * type, 5+ sorted `key=value` attributes. Double 0 is the value.
 */
export function buildMetricPoint(metric: ParsedMetricPoint, tenant: string): BuiltPoint {
  const { blobs, truncated } = clampBlobs([
    "metric",
    metric.name,
    metric.serviceName,
    metric.scopeName,
    metric.kind,
    ...attributeBlobs(metric.attributes),
  ]);
  return {
    point: {
      indexes: [clampIndex(tenant)],
      blobs,
      doubles: clampDoubles([metric.value]),
    },
    truncated,
  };
}

/**
 * Build the AE point for a span SUMMARY (the full span also goes to Workers Logs).
 *
 * Blob positions are FIXED: 0 kind, 1 span name, 2 traceId, 3 spanId, 4
 * parentSpanId, 5 service, 6 scope, 7+ sorted `key=value` attributes. Double 0 is
 * the duration in ms, double 1 the OTLP span kind.
 */
export function buildSpanPoint(span: ParsedSpan, tenant: string): BuiltPoint {
  const { blobs, truncated } = clampBlobs([
    "span",
    span.name,
    span.traceId,
    span.spanId,
    span.parentSpanId,
    span.serviceName,
    span.scopeName,
    ...attributeBlobs(span.attributes),
  ]);
  return {
    point: {
      indexes: [clampIndex(tenant)],
      blobs,
      doubles: clampDoubles([span.durationMs, span.kind]),
    },
    truncated,
  };
}

/**
 * The Analytics Engine binding surface this collector needs. Declared locally so
 * the writer can be unit-tested against a stub (workerd's AE binding cannot be
 * observed from inside the Worker).
 */
export interface AnalyticsEngineLike {
  writeDataPoint(point: { indexes?: string[]; blobs?: string[]; doubles?: number[] }): void;
}

/**
 * Per-invocation Analytics Engine writer that enforces the 250-write cap.
 *
 * Cloudflare accepts at most {@link AE_MAX_WRITES_PER_INVOCATION} `writeDataPoint()`
 * calls per invocation. Past that the writer stops calling and COUNTS the excess:
 * the count is returned in the HTTP response and emitted as a `console.warn`, so
 * an over-cap batch is visible as data loss instead of vanishing silently.
 */
export class AnalyticsWriter {
  private written = 0;
  private dropped = 0;
  private truncatedCount = 0;
  private readonly cap: number;

  constructor(
    private readonly dataset: AnalyticsEngineLike | undefined,
    cap: number = AE_MAX_WRITES_PER_INVOCATION,
  ) {
    this.cap = Math.max(0, Math.min(cap, AE_MAX_WRITES_PER_INVOCATION));
  }

  /** True once the invocation has spent its whole write budget. */
  get atCap(): boolean {
    return this.written >= this.cap;
  }

  writeMetric(metric: ParsedMetricPoint, tenant: string): boolean {
    return this.write(buildMetricPoint(metric, tenant));
  }

  writeSpan(span: ParsedSpan, tenant: string): boolean {
    return this.write(buildSpanPoint(span, tenant));
  }

  /** Write one pre-built point. Returns false when it was dropped. */
  write(built: BuiltPoint): boolean {
    if (built.truncated) this.truncatedCount++;
    if (!this.dataset || this.atCap) {
      this.dropped++;
      return false;
    }
    // Defensive: a throwing write must not abort the rest of the batch.
    try {
      this.dataset.writeDataPoint({
        indexes: built.point.indexes,
        blobs: built.point.blobs,
        doubles: built.point.doubles.slice(0, AE_MAX_DOUBLES),
      });
      this.written++;
      return true;
    } catch (error) {
      this.dropped++;
      console.warn(
        JSON.stringify({
          event: "telemetry.analytics.write_failed",
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
  finish(route: string): AnalyticsSummary {
    const summary: AnalyticsSummary = {
      written: this.written,
      dropped: this.dropped,
      truncated: this.truncatedCount,
    };
    if (summary.dropped > 0 || summary.truncated > 0) {
      console.warn(
        JSON.stringify({
          event: "telemetry.analytics.limits",
          route,
          written: summary.written,
          dropped: summary.dropped,
          truncated: summary.truncated,
          cap: this.cap,
          reason: this.dataset ? "per_invocation_write_cap" : "no_analytics_binding",
        }),
      );
    }
    return summary;
  }
}
