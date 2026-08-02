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
 * `PORT_TODO(§4.5)` in `prometheus.ts`; the renderer itself is complete.
 *
 * ## THE "NO PRODUCER" MARKER IS CLOSED — do not re-add it
 *
 * It read "THIS PACKAGE HAS NO PRODUCER … contributes zero bytes to every
 * deployed Worker", and that was true: the only reference from any app's `src`
 * was an `import type` in `apps/gateway/src/cache/metrics.ts`, which the
 * compiler erases. It is now false, and the census that proves it is
 * reproducible: `apps/gateway/src/telemetry/emit.ts` VALUE-imports
 * `CloudflareBackend`, `GATEWAY_REQUEST_SPAN`, `ObservabilitySignal`,
 * `defaultGatewayMetricsSnapshot` and `otlpAttribute` from this package, and
 * two call sites reach it: the global `src/telemetry/middleware.ts` (every
 * operation) and `src/inference/route-module.ts` (the six inference
 * operations), which `emitRequestTelemetry` de-duplicates.
 * `apps/gateway/wrangler.toml` declares the `[[services]]
 * TELEMETRY_COLLECTOR` binding the emitter reads, and the span carries the
 * trace id adopted by `middleware/trace.ts`, which closes the "correlation id
 * computed and discarded" item too.
 *
 * MUTATION-VERIFIED, with a caveat worth writing down. Deleting the emit call
 * in `telemetry/middleware.ts` alone turns
 * `apps/gateway/test/telemetry/middleware-mount.test.ts` RED (2 failures).
 * Deleting BOTH turns `mount.test.ts` RED as well (6 failures across the two
 * files). But deleting the `route-module.ts` call ALONE leaves all 27 telemetry
 * tests GREEN — the global middleware still emits for the same request, so
 * `mount.test.ts`'s own docstring claim that it is "RED the moment the
 * `emitRequestTelemetry` call is removed from `src/inference/route-module.ts`"
 * is overstated. The PACKAGE's mount is genuinely gated (no emit site survives
 * un-noticed); the inference-specific LEG is not independently gated. That is
 * an `apps/gateway` test to tighten, not a defect in this package.
 *
 * ## PORT-TODO(P: inventory §4.5) — TWO SURFACES OF THIS PACKAGE STILL HAVE NO
 * ## CONSUMER. NOT A PLATFORM LIMIT. NOT CLOSED.
 *
 * Narrowed to exactly what remains dead, so this marker cannot be read as
 * either "all fine" or "nothing flows":
 *
 *  - **`AnalyticsEngineSink` (`analytics-engine.ts`) has no importer.** The
 *    collector Worker re-implements it locally: `apps/telemetry/src/sink.ts`
 *    declares its OWN `AnalyticsEngineSink` and `apps/telemetry/src/limits.ts`
 *    its own clamp constants, and `apps/telemetry/src/ports.ts` constructs the
 *    local one. Two implementations of one platform contract, with nothing
 *    forcing them to agree — which is not hypothetical: `AE_MAX_BLOB_BYTES`
 *    diverged 3x between them and stayed wrong here for exactly as long as
 *    nothing called it (fixed in this slice; see the constant's own doc). This
 *    is a duplication to collapse, not a gap to wire — the direct in-Worker
 *    sink is only reachable by a Worker holding an
 *    `[[analytics_engine_datasets]]` binding, and today only `apps/telemetry`
 *    does. Collapse toward ONE implementation before a second constant drifts.
 *  - **`OtlpBackend` (`backend.ts`) has no importer.** The gateway builds a
 *    `CloudflareBackend` for BOTH transports (service binding and plain HTTPS
 *    `TELEMETRY_ENDPOINT`), so the vendor-neutral backend is reached by no
 *    deployed path. It is a faithful port of the Rust backend a self-hosted
 *    OTLP deployment would use; it stays because deleting it would drop parity
 *    surface, but nobody should read its presence as "OTLP-generic export is
 *    live".
 *
 * Still open elsewhere and NOT this package's to close: `apps/mcp`'s
 * `InMemoryAuditSink` (including the #522 `agent_run_id` correlation rows)
 * names `apps/telemetry` as the durable sink it waits on, and the two are still
 * not connected — that is an `apps/mcp` composition-root job.
 *
 * ## Closed in this slice: `AE_MAX_BLOB_BYTES`
 *
 * It declared `5120` against a documented Cloudflare ceiling of **16 KB of
 * total blob bytes per data point** (20 blobs, 20 doubles, 1 index <= 96 bytes,
 * 250 `writeDataPoint` calls per invocation), so
 * `analyticsEngineDataPointViolation` refused legitimate points at ~1/3 of the
 * real limit. Now `16 * 1024`, matching what `apps/telemetry/src/limits.ts`
 * always declared, and pinned as a LITERAL in `test/analytics-engine.test.ts`
 * (a self-referential `expect(AE_MAX_BLOB_BYTES).toBe(AE_MAX_BLOB_BYTES)` is
 * exactly the assertion shape that let a 3x error survive).
 */

export * from "./config.js";
export * from "./metrics.js";
export * from "./spans.js";
export * from "./otlp.js";
export * from "./backend.js";
export * from "./cloudflare.js";
export * from "./prometheus.js";
export * from "./analytics-engine.js";
