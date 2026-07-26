// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — the telemetry-collector Worker
//   (issue #520): the OTLP/HTTP+JSON ingest endpoint Cloudflare does not ship. There is no
//   OTLP receiver, no Workers Logs write API, and `writeDataPoint()` is a Worker BINDING
//   with a read-only HTTP API — so a Rust process in a container cannot write telemetry to
//   Cloudflare at all without a collector we deploy ourselves. This file is routing and
//   wiring only; the pipeline lives in ingest.ts.

import { json, requireBearer } from "./auth";
import { handleIngest, type IngestEnv, type Signal } from "./ingest";

/**
 * Worker bindings.
 *
 * - `TELEMETRY` — the Analytics Engine dataset metrics and span summaries are
 *   written to. Its `writeDataPoint()` binding is the ONLY write path Cloudflare
 *   offers; the dataset's HTTP API is SQL read-only.
 * - `COLLECTOR_TOKEN` — the shared secret every ingest request must present as
 *   `Authorization: Bearer`. Seeded with `wrangler secret put COLLECTOR_TOKEN`;
 *   never committed. Absent it, the collector fails closed with 500.
 * - `MAX_BODY_BYTES` — optional per-request body ceiling (string, Worker vars are
 *   strings). Over it, ingest answers 413.
 */
export interface Env extends IngestEnv {
  TELEMETRY?: AnalyticsEngineDataset;
  COLLECTOR_TOKEN?: string;
  MAX_BODY_BYTES?: string;
}

/**
 * The OTLP/HTTP route table. These paths are fixed by the OTLP specification and
 * are exactly what FerroGate's Rust exporter (and Cloudflare's own native Workers
 * OTLP export) POSTs to.
 */
const ROUTES: Record<string, Signal> = {
  "/v1/metrics": "metrics",
  "/v1/traces": "traces",
  "/v1/logs": "logs",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Unauthenticated liveness probe: no telemetry crosses it.
    if (url.pathname === "/healthz") {
      return json({ ok: true, worker: "ferrogate-telemetry-collector" });
    }

    const signal = ROUTES[url.pathname];
    if (!signal) {
      return json({ error: `unknown route: ${url.pathname}` }, 404);
    }
    if (request.method !== "POST") {
      return json({ error: "method not allowed" }, 405);
    }

    const denial = requireBearer(request, env.COLLECTOR_TOKEN);
    if (denial) return denial;

    return handleIngest(signal, request, env);
  },
} satisfies ExportedHandler<Env>;
