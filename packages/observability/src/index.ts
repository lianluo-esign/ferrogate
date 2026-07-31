/**
 * `@ferrogate/observability` — metrics, logs, and traces.
 *
 * Replaces the Rust crate `ferrogate-observability`. On Cloudflare this writes
 * to Analytics Engine and Tail/Logpush.
 */
import type { Scope } from "@ferrogate/core";

/** A single metric data point. */
export interface Metric {
  name: string;
  value: number;
  scope?: Scope;
  labels?: Record<string, string>;
}

/** Severity levels for structured logs. */
export type LogLevel = "debug" | "info" | "warn" | "error";

/** A structured log line. */
export interface LogRecord {
  level: LogLevel;
  message: string;
  scope?: Scope;
  fields?: Record<string, unknown>;
}

/** Sink for metrics/logs/traces (Analytics Engine `writeDataPoint`, Tail). */
export interface TelemetrySink {
  metric(metric: Metric): void;
  log(record: LogRecord): void;
}
