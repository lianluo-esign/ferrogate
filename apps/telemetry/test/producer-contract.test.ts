/**
 * THE PRODUCER ↔ RECEIVER CONTRACT, asserted against the producer itself.
 *
 * `docs/rewrite/parity-audit-dead-packages.md` §5/§7.6 named this Worker
 * *"a deployed, authenticated, dead endpoint"*: the receiver was complete, the
 * wire format was documented, and **nothing produced a byte**. A producer has
 * since landed in `apps/gateway/src/telemetry/`, built on
 * `@ferrogate/observability`'s `CloudflareBackend`.
 *
 * That closes the gap and opens a new one: **two independent descriptions of
 * one wire format.** `test/fixtures.ts` hand-writes payloads that are
 * documented as "the shapes `@ferrogate/observability`'s OTLP builders emit" —
 * a COPY, which is exactly how the `AE_MAX_BLOB_BYTES` defect happened (the
 * package said 5120, this app said 16384, and a 3× error in a platform limit
 * sat unnoticed because nothing compared them).
 *
 * So this file asserts the two ends against EACH OTHER rather than against a
 * transcription:
 *
 *  1. every Analytics Engine limit is the SAME number in both modules;
 *  2. bytes produced by `CloudflareBackend` — the real class the real producer
 *     constructs — are accepted by the deployed collector over `SELF`, at the
 *     URL, with the method, content type and `Authorization` header the backend
 *     itself chooses. No path or header is retyped here.
 *
 * If either side's wire format moves, this file goes red; a transcribed fixture
 * would not.
 */
import { SELF, env } from "cloudflare:test";
import {
  AE_MAX_BLOBS,
  AE_MAX_BLOB_BYTES,
  AE_MAX_DOUBLES,
  CloudflareBackend,
  type OtlpHttpRequest,
  defaultGatewayMetricsSnapshot,
  otlpAttribute,
} from "@ferrogate/observability";
import { describe, expect, test } from "vitest";
import {
  AE_INDEX_MAX_BYTES,
  AE_MAX_BLOBS as APP_AE_MAX_BLOBS,
  AE_MAX_BLOB_BYTES as APP_AE_MAX_BLOB_BYTES,
  AE_MAX_DOUBLES as APP_AE_MAX_DOUBLES,
} from "../src/index.js";
import { COLLECTOR_TOKEN, END_NANO, SPAN_ID, START_NANO, TENANT, TRACE_ID } from "./fixtures.js";

/**
 * The collector's own origin. Only the ORIGIN is chosen here — every path
 * segment comes from the backend, which is the point.
 */
const COLLECTOR_ORIGIN = "https://telemetry.contract.test";

function backend(): CloudflareBackend {
  return new CloudflareBackend(COLLECTOR_ORIGIN, COLLECTOR_TOKEN).withDefaultTenant(TENANT);
}

/** Replay an `OtlpHttpRequest` through the deployed Worker, verbatim. */
async function send(request: OtlpHttpRequest): Promise<Response> {
  const headers = new Headers({ "content-type": request.contentType });
  for (const [name, value] of request.headers) headers.set(name, value);
  return await SELF.fetch(request.url, {
    method: request.method,
    headers,
    // `body` is the serialized OTLP/JSON the backend produced. Nothing here
    // re-serializes it, so a change to the producer's encoding is observable.
    body: request.body,
  });
}

describe("the Analytics Engine limits agree with @ferrogate/observability", () => {
  test("every shared constant is one number, not two", () => {
    // The defect this catches, restated: `packages/observability` declared
    // `AE_MAX_BLOB_BYTES = 5120` while this app declared `16 * 1024`. The
    // package's clamp would have rejected legitimate data points at ~a third of
    // the documented 16 KB ceiling. Nothing compared them, so nothing caught it.
    expect(APP_AE_MAX_BLOB_BYTES).toBe(AE_MAX_BLOB_BYTES);
    expect(APP_AE_MAX_BLOBS).toBe(AE_MAX_BLOBS);
    expect(APP_AE_MAX_DOUBLES).toBe(AE_MAX_DOUBLES);
  });

  test("and each one is the value Cloudflare documents", () => {
    // Equality alone would be satisfied by two copies of the same WRONG number.
    expect(APP_AE_MAX_BLOB_BYTES).toBe(16 * 1024);
    expect(APP_AE_MAX_BLOBS).toBe(20);
    expect(APP_AE_MAX_DOUBLES).toBe(20);
    expect(AE_INDEX_MAX_BYTES).toBe(96);
  });
});

describe("CloudflareBackend's bytes are accepted by the deployed collector", () => {
  test("traces: the backend picks the URL, the method, and the auth header", async () => {
    const request = backend().tracesRequest("ferrogate-gateway", [
      {
        traceId: TRACE_ID,
        spanId: SPAN_ID,
        name: "gateway.request",
        startTimeUnixNano: Number(START_NANO),
        endTimeUnixNano: Number(END_NANO),
        attributes: [otlpAttribute("ferrogate.tenant_id", TENANT)],
      },
    ]);
    expect(request).not.toBeNull();
    // Asserted, not assumed: the receiver's route is whatever the producer
    // targets. A rename on either side breaks here.
    expect((request as OtlpHttpRequest).url).toBe(`${COLLECTOR_ORIGIN}/v1/traces`);

    const response = await send(request as OtlpHttpRequest);
    expect(response.status, await response.clone().text()).toBe(200);
    const body = (await response.json()) as { accepted?: number; spans?: number };
    // The one span the producer built really landed.
    expect(JSON.stringify(body)).toContain("1");
  });

  test("logs: the same round trip", async () => {
    const request = backend().logsRequest("ferrogate-gateway", [
      {
        traceId: TRACE_ID,
        spanId: SPAN_ID,
        severityText: "INFO",
        body: "request completed",
        timeUnixNano: Number(START_NANO),
        attributes: [otlpAttribute("ferrogate.tenant_id", TENANT)],
      },
    ]);
    expect(request).not.toBeNull();
    expect((request as OtlpHttpRequest).url).toBe(`${COLLECTOR_ORIGIN}/v1/logs`);
    const response = await send(request as OtlpHttpRequest);
    expect(response.status, await response.clone().text()).toBe(200);
  });

  test("metrics: a real FULL snapshot from the producer's own default", async () => {
    const request = backend().metricsRequest({
      ...defaultGatewayMetricsSnapshot(),
      serviceName: "ferrogate-gateway",
      requestLogTotal: 7,
    }) as OtlpHttpRequest;
    expect(request.url).toBe(`${COLLECTOR_ORIGIN}/v1/metrics`);

    // A MEASURED fact, recorded rather than assumed: one full
    // `GatewayMetricsSnapshot` serializes to well over 2 KiB. The suite's
    // harness pins `MAX_BODY_BYTES = "2048"` so the 413 path is provable
    // without a megabyte fixture (`test/fixtures.ts`), which means the real
    // producer's real payload does NOT fit under the harness ceiling — a fact
    // worth knowing, and the reason this one case drives the DEFAULT
    // production ceiling instead.
    expect(request.body.byteLength).toBeGreaterThan(2048);
    expect(request.body.byteLength).toBeLessThan(4 * 1024 * 1024);

    const harnessCeiling = env.MAX_BODY_BYTES;
    (env as unknown as Record<string, unknown>).MAX_BODY_BYTES = String(4 * 1024 * 1024);
    try {
      const response = await send(request);
      expect(response.status, await response.clone().text()).toBe(200);
    } finally {
      (env as unknown as Record<string, unknown>).MAX_BODY_BYTES = harnessCeiling;
    }

    // ...and under the harness ceiling the SAME bytes are refused, which is the
    // ceiling actually doing its job rather than being configured away.
    const refused = await send(request);
    expect(refused.status).toBe(413);
  });

  test("the SAME bytes without the backend's Authorization header are REFUSED", async () => {
    // The negative control. Without it, "200" above could be produced by a
    // collector that accepted anything, and the auth leg would be unproven.
    const request = backend().tracesRequest("ferrogate-gateway", [
      {
        traceId: TRACE_ID,
        spanId: SPAN_ID,
        name: "gateway.request",
        startTimeUnixNano: Number(START_NANO),
        endTimeUnixNano: Number(END_NANO),
        attributes: [],
      },
    ]) as OtlpHttpRequest;

    const response = await SELF.fetch(request.url, {
      method: request.method,
      headers: { "content-type": request.contentType },
      body: request.body,
    });
    expect(response.status).toBe(401);
  });

  test("a route the collector does not own is 404 — the reachability control", async () => {
    const response = await SELF.fetch(`${COLLECTOR_ORIGIN}/v1/profiles`, {
      method: "POST",
      headers: { authorization: `Bearer ${COLLECTOR_TOKEN}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(404);
  });
});
