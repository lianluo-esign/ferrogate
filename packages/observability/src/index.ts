/**
 * `@ferrogate/observability` — logging, metrics, and tracing boundaries.
 *
 * Faithful clean-room port of the Rust crate `ferrogate-observability`: an
 * I/O-free crate whose backends **build** OTLP/HTTP+JSON requests (they never
 * send them) and whose exporters render the {@link GatewayMetricsSnapshot}
 * counter bag to Prometheus text or OTLP/JSON. The Rust surface is split into
 * cohesive modules and re-exported below, unchanged in semantics:
 *
 *  - `config`      — pipeline/exporter config, the plugin contract, exporter
 *                    validation, and the `ObservabilityConfigError` taxonomy
 *                    (+ Zod wire schemas, inventory §4.5).
 *  - `metrics`     — `GatewayMetricsSnapshot` and its sub-totals.
 *  - `spans`       — the 6 canonical gateway span templates.
 *  - `otlp`        — OTLP/JSON record types + metrics/traces/logs builders.
 *  - `backend`     — the `TelemetryBackend` contract + `OtlpBackend`.
 *  - `cloudflare`  — `CloudflareBackend` (bearer-authed collector Worker, #520).
 *  - `prometheus`  — the Prometheus text-exposition renderer.
 *
 *  - `analytics-engine` — `AnalyticsEngineSink`: the IN-WORKER destination that
 *                    holds the dataset binding and calls `writeDataPoint()`
 *                    directly, with no collector hop (inventory §4.5).
 *
 * The one surface that CANNOT be ported is metric ACCUMULATION: a Worker has no
 * long-lived process to hold counters in, so a `/metrics` route must be fed
 * from a Durable Object or an Analytics Engine read. That is the remaining
 * `PORT-TODO(§4.5)` in `prometheus.ts`; the renderer itself is complete.
 */

export * from "./config.js";
export * from "./metrics.js";
export * from "./spans.js";
export * from "./otlp.js";
export * from "./backend.js";
export * from "./cloudflare.js";
export * from "./prometheus.js";
export * from "./analytics-engine.js";
