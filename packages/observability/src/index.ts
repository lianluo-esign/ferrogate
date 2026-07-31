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
 *
 * ## PORT-TODO(inventory §4.5) — THIS PACKAGE HAS NO PRODUCER. NOT A PLATFORM
 * ## LIMIT. NOT CLOSED. See `docs/rewrite/parity-audit-dead-packages.md` §5.
 *
 * Every export below is implemented and tested, and **no application code calls
 * any of it at runtime**. A module-specifier census over every `.ts` under
 * every app's `src` tree finds exactly ONE reference to this package:
 * `apps/gateway/src/cache/metrics.ts:37`, and it is `import type`, which the
 * compiler ERASES. This package therefore contributes zero bytes to every
 * deployed Worker. `CloudflareBackend`, `OtlpBackend`, `renderPrometheusText`
 * and the three `buildOtlp*Request` builders are constructed nowhere outside
 * this package and its own tests.
 *
 * What is concretely broken while this stands:
 *
 *  - Rust ran a background sender (`ferrogate-gateway/src/telemetry.rs:32`)
 *    that pushed a metrics snapshot + OTLP logs (request logs, audit events,
 *    billing events) + trace spans to a backend every 5s. `apps/gateway` does
 *    none of it — the 6 span templates in `spans.ts` are never emitted.
 *  - `apps/gateway/src/middleware/trace.ts` correctly ADOPTS an inbound W3C
 *    `traceparent` and then has no consumer to turn it into a span, so the
 *    correlation id is computed and discarded.
 *  - `apps/telemetry` is a deployed, bearer-authenticated OTLP collector that
 *    accepts exactly what `CloudflareBackend` emits — and therefore **cannot
 *    receive a single byte in production**, because nothing sends.
 *  - `apps/mcp`'s `InMemoryAuditSink` (including the #522 `agent_run_id`
 *    correlation rows) names `apps/telemetry` as the durable sink it is waiting
 *    on; the two are never connected.
 *
 * Where it must mount: `apps/gateway`, building a backend from env (collector
 * endpoint + bearer token) and flushing via `ctx.waitUntil(...)` at request end
 * and/or from the `scheduled` handler that Worker already has. Rust's 5s thread
 * has no workerd twin, so `waitUntil` is the faithful mapping, not a
 * compromise. The mount gate must drive a request through `SELF` and assert an
 * outbound fetch to the collector carrying the adopted trace id — a test that
 * calls `buildOtlpTracesRequest` directly would survive un-wiring, exactly as
 * the circuit-breaker tests did.
 *
 * ## PORT-TODO(§4.5) — `AE_MAX_BLOB_BYTES` IS WRONG, and dead code is why
 *
 * `analytics-engine.ts:45` declares `AE_MAX_BLOB_BYTES = 5120`. Cloudflare's
 * documented limit is **16 KB of total blob bytes per data point** (20 blobs,
 * 20 doubles, 1 index <= 96 bytes, 250 `writeDataPoint` calls per invocation),
 * which is what `apps/telemetry/src/limits.ts:35` independently declares. So
 * `analyticsEngineDataPointViolation` rejects legitimate data points at ~1/3 of
 * the real ceiling. A 3x error in a platform constant survived because nothing
 * calls it. `apps/telemetry/src/limits.ts` + its own `AnalyticsEngineSink` are
 * a full local re-implementation of `analytics-engine.ts`; fix the constant
 * here, then collapse one into the other.
 */

export * from "./config.js";
export * from "./metrics.js";
export * from "./spans.js";
export * from "./otlp.js";
export * from "./backend.js";
export * from "./cloudflare.js";
export * from "./prometheus.js";
export * from "./analytics-engine.js";
