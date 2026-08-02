/**
 * `ferrogate-telemetry` Worker — OTLP/HTTP + JSON ingest → Analytics Engine.
 *
 * Clean-room port of `ferrogate-observability`'s collector role
 * (`docs/legacy/inventory-data-billing.md` §4.4/§4.5; the read-only reference
 * shape is `workers/telemetry-collector/`).
 *
 * ## Why this Worker exists
 *
 * Cloudflare ships **no observability ingest endpoint anywhere**: no OTLP
 * receiver, no Workers Logs write API, and Analytics Engine's
 * `writeDataPoint()` is a Worker **binding** whose only HTTP API is the SQL
 * *read* API. So the ingest endpoint has to be a Worker we deploy — this one.
 * It accepts the OTLP/JSON that `@ferrogate/observability`'s
 * `CloudflareBackend` emits (and that Cloudflare's own native Workers OTLP
 * export emits), and fans each record out to Analytics Engine + Workers Logs.
 *
 * ## Surface
 *
 * | Route | Auth | Purpose |
 * |---|---|---|
 * | `GET /healthz` | anonymous | shared contract op `getHealthz` |
 * | `GET /readyz` | anonymous | shared contract op `getReadyz` (503 unconfigured) |
 * | `GET /health`, `GET /version` | anonymous | scaffold probes, kept |
 * | `POST /v1/metrics` | bearer | OTLP/HTTP + JSON metrics |
 * | `POST /v1/traces` | bearer | OTLP/HTTP + JSON traces |
 * | `POST /v1/logs` | bearer | OTLP/HTTP + JSON logs |
 *
 * `apps/telemetry` owns no other contract operation — it is the observability
 * sink fed by the other Workers (`docs/rewrite/ROUTE-MAP.md`).
 *
 * This module is the ONE composition root: it builds the app with production
 * wiring (the sink is resolved per request from the `TELEMETRY` binding) and
 * exports it. The tests drive this exact object — via `SELF.fetch`, or by
 * calling its `fetch` with a substituted env — never a router assembled in the
 * test file.
 */
import { createTelemetryApp } from "./app.js";

const app = createTelemetryApp();

export default app;

export {
  OTLP_ROUTES,
  RUNTIME_NAME,
  SERVICE_NAME,
  SHARED_OPERATION_IDS,
  TELEMETRY_ROUTES,
  createTelemetryApp,
} from "./app.js";
export type { TelemetryApp, TelemetryAppOptions, TelemetryRoute } from "./app.js";
export { handleIngest, readJsonBody } from "./ingest.js";
export type { IngestSummary } from "./ingest.js";
export { resolveSink } from "./ports.js";
export type { TelemetryBindings, TelemetryEnv } from "./ports.js";
export {
  AnalyticsEngineSink,
  RecordingTelemetrySink,
  SinkWriter,
  buildLogPoint,
  buildMetricPoint,
  buildSpanPoint,
} from "./sink.js";
export type {
  AnalyticsEngineLike,
  BuiltPoint,
  SinkSummary,
  TelemetryDataPoint,
  TelemetrySink,
} from "./sink.js";
export { TelemetryErrorCode } from "./errors.js";
export type { ErrorBody, ErrorObject } from "./errors.js";
export * from "./limits.js";
export * from "./otlp.js";
export * from "./schemas.js";
