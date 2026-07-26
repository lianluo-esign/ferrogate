// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Worker-side E2E for the telemetry-collector wire contract (issue #520).
//   Boots the REAL Worker (src/index.ts) in workerd via @cloudflare/vitest-pool-workers +
//   miniflare and drives the exact payloads crates/ferrogate-observability/src/otlp.rs
//   builds — so the contract is proven against the shipped encoder's shapes, not a
//   paraphrase of them: bearer rejection, the three OTLP/JSON payloads, the 250-write
//   Analytics Engine cap being enforced AND reported, a malformed body, and the size cap.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

const TOKEN = "test-collector-secret";
const BASE = "https://telemetry-collector.test";

interface Summary {
  accepted: number;
  dataPoints: number;
  dropped: number;
}

function post(path: string, body: unknown, headers: Record<string, string> = {}) {
  return SELF.fetch(`${BASE}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** `{key, value:{stringValue}}` — the only attribute form the Rust encoder emits. */
function attr(key: string, value: string) {
  return { key, value: { stringValue: value } };
}

const RESOURCE = { attributes: [attr("service.name", "ferrogate")] };
const SCOPE = { name: "ferrogate", version: "0.1.0" };

/** A `sum` metric exactly as `sum_metric_json` builds it. */
function sumMetric(name: string, value: number, attributes: ReturnType<typeof attr>[] = []) {
  return {
    name,
    description: `${name} description`,
    sum: {
      aggregationTemporality: 2,
      isMonotonic: true,
      dataPoints: [{ asDouble: value, attributes }],
    },
  };
}

function metricsBody(metrics: unknown[]) {
  return {
    resourceMetrics: [{ resource: RESOURCE, scopeMetrics: [{ scope: SCOPE, metrics }] }],
  };
}

function tracesBody(spans: unknown[]) {
  return { resourceSpans: [{ resource: RESOURCE, scopeSpans: [{ scope: SCOPE, spans }] }] };
}

function logsBody(logRecords: unknown[]) {
  return { resourceLogs: [{ resource: RESOURCE, scopeLogs: [{ scope: SCOPE, logRecords }] }] };
}

describe("telemetry-collector wire contract (Worker-side E2E)", () => {
  it("serves the unauthenticated liveness probe", async () => {
    const res = await SELF.fetch(`${BASE}/healthz`);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, worker: "ferrogate-telemetry-collector" });
  });

  // ---- Auth ---------------------------------------------------------------

  it("rejects an unauthenticated ingest with 401 on every signal", async () => {
    for (const path of ["/v1/metrics", "/v1/traces", "/v1/logs"]) {
      const res = await SELF.fetch(`${BASE}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status, `${path} must require auth`).toBe(401);
      expect(await res.json()).toMatchObject({ error: "unauthorized" });
    }
  });

  it("rejects a WRONG bearer token with 401 (not 403 — no oracle for probers)", async () => {
    const res = await post("/v1/metrics", metricsBody([sumMetric("x", 1)]), {
      authorization: "Bearer not-the-secret",
    });
    expect(res.status).toBe(401);
  });

  it("rejects a non-Bearer Authorization scheme with 401", async () => {
    const res = await post("/v1/metrics", metricsBody([sumMetric("x", 1)]), {
      authorization: `Basic ${TOKEN}`,
    });
    expect(res.status).toBe(401);
  });

  it("auth is checked BEFORE the body is parsed (garbage body still 401)", async () => {
    const res = await SELF.fetch(`${BASE}/v1/logs`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "}{not json at all",
    });
    expect(res.status).toBe(401);
  });

  // ---- The three OTLP/JSON shapes -----------------------------------------

  it("accepts the /v1/metrics shape and counts every data point", async () => {
    const res = await post(
      "/v1/metrics",
      metricsBody([
        sumMetric("ferrogate.request_logs", 12),
        sumMetric("ferrogate.ai_cache.requests", 3, [attr("status", "hit")]),
        sumMetric("ferrogate.ai_cache.requests", 1, [attr("status", "miss")]),
      ]),
      { "x-ferrogate-tenant": "tenant-alpha" },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json<Summary>()).toEqual({ accepted: 3, dataPoints: 3, dropped: 0 });
  });

  it("accepts the /v1/traces shape, including a null parentSpanId root span", async () => {
    const res = await post(
      "/v1/traces",
      tracesBody([
        {
          traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
          spanId: "00f067aa0ba902b7",
          // The Rust encoder emits JSON `null` for a root span.
          parentSpanId: null,
          name: "gateway.request",
          kind: 2,
          startTimeUnixNano: "1753500000000000000",
          endTimeUnixNano: "1753500000123000000",
          attributes: [attr("http.status_code", "200")],
        },
        {
          traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
          spanId: "00f067aa0ba902b8",
          parentSpanId: "00f067aa0ba902b7",
          name: "provider.call",
          kind: 2,
          startTimeUnixNano: "1753500000010000000",
          endTimeUnixNano: "1753500000090000000",
          attributes: [attr("provider", "openai")],
        },
      ]),
      { "x-ferrogate-tenant": "tenant-alpha" },
    );
    expect(res.status).toBe(200);
    // Spans produce one AE summary point each AND one Workers Logs line each.
    expect(await res.json<Summary>()).toEqual({ accepted: 2, dataPoints: 2, dropped: 0 });
  });

  it("accepts the /v1/logs shape (logs go to Workers Logs, never Analytics Engine)", async () => {
    const res = await post(
      "/v1/logs",
      logsBody([
        {
          timeUnixNano: "1753500000000000000",
          traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
          spanId: "00f067aa0ba902b7",
          severityText: "ERROR",
          body: { stringValue: "upstream refused the request" },
          attributes: [attr("route", "/v1/chat/completions")],
        },
        {
          timeUnixNano: "1753500000500000000",
          traceId: null,
          spanId: null,
          severityText: "INFO",
          body: { stringValue: "request served" },
          attributes: [],
        },
      ]),
      { "x-ferrogate-tenant": "tenant-alpha" },
    );
    expect(res.status).toBe(200);
    // dataPoints is 0 by design: log records are not Analytics Engine points.
    expect(await res.json<Summary>()).toEqual({ accepted: 2, dataPoints: 0, dropped: 0 });
  });

  it("derives the tenant from record attributes when the header is absent", async () => {
    // No X-FerroGate-Tenant header: the tenant must come from the attributes.
    // The response shape is identical; what this pins is that a headerless batch
    // is still WRITABLE (a point with no index cannot be written at all).
    const res = await post(
      "/v1/metrics",
      metricsBody([sumMetric("ferrogate.tokens", 7, [attr("tenant_id", "tenant-from-attrs")])]),
    );
    expect(res.status).toBe(200);
    expect(await res.json<Summary>()).toEqual({ accepted: 1, dataPoints: 1, dropped: 0 });
  });

  // ---- The 250-writeDataPoint per-invocation cap ---------------------------

  it("enforces the 250 writeDataPoint cap per invocation and REPORTS the drops", async () => {
    const metrics = Array.from({ length: 251 }, (_, i) => sumMetric(`m${i}`, i));
    const res = await post("/v1/metrics", metricsBody(metrics), {
      "x-ferrogate-tenant": "tenant-cap",
    });
    expect(res.status).toBe(200);
    const summary = await res.json<Summary>();
    // Every point was accepted from the payload, exactly 250 were written, and
    // the 251st is reported as dropped rather than silently discarded.
    expect(summary).toEqual({ accepted: 251, dataPoints: 250, dropped: 1 });
  });

  // ---- Bad input ----------------------------------------------------------

  it("returns 400 for a malformed JSON body", async () => {
    const res = await post("/v1/metrics", "{not json");
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "malformed JSON body" });
  });

  it("returns 400 for valid JSON that is not the OTLP envelope", async () => {
    const res = await post("/v1/traces", { nope: [] });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid OTLP traces payload" });
  });

  it("returns 413 when the body exceeds MAX_BODY_BYTES", async () => {
    // MAX_BODY_BYTES is 65536 in the test harness; this body is well past it.
    const filler = "x".repeat(2000);
    const metrics = Array.from({ length: 64 }, (_, i) => sumMetric(`${filler}-${i}`, i));
    const res = await post("/v1/metrics", metricsBody(metrics));
    expect(res.status).toBe(413);
    expect(await res.json()).toMatchObject({ error: "payload too large", limit: 65536 });
  });

  it("skips unusable records without failing the batch", async () => {
    // A span with no traceId/spanId cannot be correlated with anything. The batch
    // still succeeds — OTLP exporters retry WHOLE batches, so failing 1000 good
    // spans over one bad one would amplify load — and the loss is reported.
    const res = await post(
      "/v1/traces",
      tracesBody([
        { name: "no-ids", startTimeUnixNano: "1", endTimeUnixNano: "2" },
        {
          traceId: "aa",
          spanId: "bb",
          name: "usable",
          kind: 2,
          startTimeUnixNano: "1753500000000000000",
          endTimeUnixNano: "1753500000001000000",
          attributes: [],
        },
      ]),
    );
    expect(res.status).toBe(200);
    expect(await res.json<Summary>()).toEqual({ accepted: 1, dataPoints: 1, dropped: 1 });
  });

  // ---- Routing ------------------------------------------------------------

  it("returns 404 for an unknown route and 405 for a non-POST ingest", async () => {
    const unknown = await SELF.fetch(`${BASE}/v1/profiles`, { method: "POST" });
    expect(unknown.status).toBe(404);

    const wrongMethod = await SELF.fetch(`${BASE}/v1/metrics`, { method: "GET" });
    expect(wrongMethod.status).toBe(405);
  });
});
