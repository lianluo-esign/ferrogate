/**
 * W3C trace-context INGRESS — `src/middleware/trace.ts`, the port of Rust
 * `ingress_trace_context` (`server/mod.rs:156`), plus its wiring into the
 * `requestId` middleware.
 *
 * The behaviour under test is a JOIN, so the assertions are about what a caller
 * can correlate: with a valid inbound `traceparent` the gateway ADOPTS the
 * caller's trace id and reports it as `x-trace-id` on every response and inside
 * every error envelope; with no header, or a malformed one, `x-trace-id` is the
 * gateway's own request id — which is exactly what every pre-existing
 * assertion in `test/auth.test.ts` pins, and why this port is additive.
 *
 * The validity table is deliberately exhaustive: each row is a way a header
 * that LOOKS like a traceparent must be refused. Accepting any one of them
 * would let a caller pin the gateway's logs to a trace id of their choosing,
 * including one shared with another tenant.
 */
import { describe, expect, it } from "vitest";

import { ingressTraceContext, validTraceparent } from "../../src/middleware/trace.js";
import { createGatewayApp } from "../../src/routes/index.js";

const BASE = "https://gw.test";
const VALID = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736";

function headers(entries: Record<string, string>): Headers {
  return new Headers(entries);
}

function call(path: string, extra: Record<string, string> = {}): Promise<Response> {
  const { app } = createGatewayApp();
  return Promise.resolve(app.request(`${BASE}${path}`, { headers: extra }, {}));
}

describe("validTraceparent — Rust `valid_traceparent`", () => {
  it("accepts a well-formed sampled header", () => {
    expect(validTraceparent(VALID)).toBe(VALID);
    // Unsampled (`-00`) is still a valid context to join.
    expect(validTraceparent(VALID.replace(/-01$/, "-00"))).not.toBeUndefined();
  });

  it("refuses every malformed shape", () => {
    const cases: Record<string, string> = {
      "too few fields": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
      "too many fields": `${VALID}-extra`,
      "short trace id": "00-4bf92f3577b34da6-00f067aa0ba902b7-01",
      "short parent id": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa-01",
      "short version": "0-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "short flags": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
      "reserved version ff": "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "uppercase hex": "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
      "non-hex": "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01",
      "all-zero trace id": "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
      "all-zero parent id": "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
      empty: "",
    };
    for (const [label, value] of Object.entries(cases)) {
      expect(`${label}: ${validTraceparent(value)}`).toBe(`${label}: undefined`);
    }
  });
});

describe("ingressTraceContext", () => {
  it("adopts the inbound trace id", () => {
    const trace = ingressTraceContext(headers({ traceparent: VALID }), "fg-1");
    expect(trace.traceId).toBe(TRACE_ID);
    expect(trace.traceparent).toBe(VALID);
  });

  it("falls back to the request id when the header is absent or invalid", () => {
    expect(ingressTraceContext(headers({}), "fg-1").traceId).toBe("fg-1");
    expect(ingressTraceContext(headers({ traceparent: "bogus" }), "fg-1").traceId).toBe("fg-1");
    expect(ingressTraceContext(headers({ traceparent: "bogus" }), "fg-1").traceparent).toBeUndefined();
  });

  it("carries tracestate ONLY alongside a valid traceparent", () => {
    expect(
      ingressTraceContext(headers({ traceparent: VALID, tracestate: "vendor=xyz" }), "fg-1")
        .tracestate,
    ).toBe("vendor=xyz");
    // An orphan `tracestate` belongs to no trace we adopted, so it is dropped.
    expect(ingressTraceContext(headers({ tracestate: "vendor=xyz" }), "fg-1").tracestate).toBeUndefined();
    expect(
      ingressTraceContext(headers({ traceparent: "bogus", tracestate: "vendor=xyz" }), "fg-1")
        .tracestate,
    ).toBeUndefined();
  });

  it("drops an oversized or empty tracestate (the 512-byte Rust cap)", () => {
    const long = `v=${"x".repeat(511)}`;
    expect(long.length).toBeGreaterThan(512);
    expect(
      ingressTraceContext(headers({ traceparent: VALID, tracestate: long }), "fg-1").tracestate,
    ).toBeUndefined();
    expect(
      ingressTraceContext(headers({ traceparent: VALID, tracestate: "   " }), "fg-1").tracestate,
    ).toBeUndefined();
  });
});

describe("the gateway adopts the caller's trace", () => {
  it("reports the adopted trace id on a 200, with its own request id alongside", async () => {
    const res = await call("/healthz", { traceparent: VALID, "x-request-id": "req_1" });
    expect(res.status).toBe(200);
    expect(res.headers.get("x-request-id")).toBe("req_1");
    // Before this port `x-trace-id` always echoed `x-request-id`, severing the
    // caller's trace at the gateway. Removing the adoption makes this red.
    expect(res.headers.get("x-trace-id")).toBe(TRACE_ID);
  });

  it("reports the adopted trace id on an ERROR too — the response most needing it", async () => {
    const res = await call("/v1/tools", { traceparent: VALID, "x-request-id": "req_2" });
    expect(res.status).toBe(401);
    expect(res.headers.get("x-request-id")).toBe("req_2");
    expect(res.headers.get("x-trace-id")).toBe(TRACE_ID);
    // The envelope keeps reporting the REQUEST id: it is this gateway's own
    // handle on the call, and the two are distinct identifiers.
    expect((await res.json()) as { error: { request_id: string } }).toMatchObject({
      error: { request_id: "req_2", code: "missing_api_key" },
    });
  });

  it("falls back to the request id when no valid trace arrives", async () => {
    const clean = await call("/healthz", { "x-request-id": "req_3" });
    expect(clean.headers.get("x-trace-id")).toBe("req_3");
    const malformed = await call("/healthz", { "x-request-id": "req_4", traceparent: "00-bad-01" });
    expect(malformed.headers.get("x-trace-id")).toBe("req_4");
  });
});
