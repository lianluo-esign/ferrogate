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
 * On Cloudflare the "build request, don't send" split collapses into direct
 * Analytics Engine / Logpush / Tail bindings (inventory §4.5, §5); the
 * `PORT-TODO(§4.5)` markers in `cloudflare.ts` and `prometheus.ts` flag where
 * the in-Worker re-architecture attaches.
 */

export * from "./config.js";
export * from "./metrics.js";
export * from "./spans.js";
export * from "./otlp.js";
export * from "./backend.js";
export * from "./cloudflare.js";
export * from "./prometheus.js";
