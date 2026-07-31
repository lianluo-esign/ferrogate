/**
 * `ferrogate-telemetry` Worker — OTLP ingest → Analytics Engine.
 *
 * Replaces the `workers/telemetry-collector` reference. Bearer-gated OTLP/HTTP
 * receiver writing to an Analytics Engine dataset (`writeDataPoint`).
 */
import { Hono } from "hono";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

// Route groups this Worker will own (bearer-gated by COLLECTOR_TOKEN):
//   POST /v1/metrics   OTLP/HTTP+JSON metrics
//   POST /v1/traces    OTLP/HTTP+JSON traces
//   POST /v1/logs      OTLP/HTTP+JSON logs
//   body-cap 413; parsed in otlp.ts; sink = TELEMETRY Analytics Engine dataset

export default app;
