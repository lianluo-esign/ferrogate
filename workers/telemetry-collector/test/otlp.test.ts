// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the OTLP/JSON parsers of the telemetry-collector
//   (issue #520). Drives the exact JSON crates/ferrogate-observability/src/otlp.rs emits —
//   `sum` metrics with `asDouble`, nanosecond timestamps as JSON STRINGS, `body.stringValue`
//   — plus the extra value shapes Cloudflare's own native Workers OTLP export produces into
//   this same collector, and the tenant fallback that keeps the AE index non-empty.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { describe, it, expect } from "vitest";
import {
  OtlpParseError,
  flattenAttributes,
  parseLogs,
  parseMetrics,
  parseTraces,
} from "../src/otlp";
import { resolveTenant } from "../src/auth";

function attr(key: string, value: string) {
  return { key, value: { stringValue: value } };
}

const RESOURCE = { attributes: [attr("service.name", "ferrogate")] };
const SCOPE = { name: "ferrogate", version: "0.1.0" };

describe("parseMetrics", () => {
  it("parses the sum shape the Rust encoder emits", () => {
    const { records, skipped } = parseMetrics({
      resourceMetrics: [
        {
          resource: RESOURCE,
          scopeMetrics: [
            {
              scope: SCOPE,
              metrics: [
                {
                  name: "ferrogate.ai_cache.requests",
                  description: "AI response cache hits.",
                  sum: {
                    aggregationTemporality: 2,
                    isMonotonic: true,
                    dataPoints: [{ asDouble: 17, attributes: [attr("status", "hit")] }],
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    expect(skipped).toBe(0);
    expect(records).toEqual([
      {
        name: "ferrogate.ai_cache.requests",
        description: "AI response cache hits.",
        kind: "sum",
        value: 17,
        attributes: { status: "hit" },
        resourceAttributes: { "service.name": "ferrogate" },
        scopeName: "ferrogate",
        serviceName: "ferrogate",
      },
    ]);
  });

  it("also accepts gauge and histogram (Cloudflare's own OTLP export emits them)", () => {
    const { records } = parseMetrics({
      resourceMetrics: [
        {
          resource: RESOURCE,
          scopeMetrics: [
            {
              scope: SCOPE,
              metrics: [
                // `asInt` arrives as a JSON STRING in OTLP.
                { name: "cf.cpu_ms", gauge: { dataPoints: [{ asInt: "1200", attributes: [] }] } },
                {
                  name: "cf.duration",
                  histogram: { dataPoints: [{ sum: 9.5, count: 3, attributes: [] }] },
                },
              ],
            },
          ],
        },
      ],
    });
    expect(records.map((r) => [r.name, r.kind, r.value])).toEqual([
      ["cf.cpu_ms", "gauge", 1200],
      ["cf.duration", "histogram", 9.5],
    ]);
  });

  it("skips valueless and nameless points instead of failing the batch", () => {
    const { records, skipped } = parseMetrics({
      resourceMetrics: [
        {
          resource: RESOURCE,
          scopeMetrics: [
            {
              scope: SCOPE,
              metrics: [
                { name: "", sum: { dataPoints: [{ asDouble: 1 }] } },
                { name: "ok", sum: { dataPoints: [{ attributes: [] }, { asDouble: 2 }] } },
              ],
            },
          ],
        },
      ],
    });
    expect(records).toHaveLength(1);
    expect(skipped).toBe(2);
  });

  it("throws OtlpParseError when the envelope is missing", () => {
    expect(() => parseMetrics({ resourceSpans: [] })).toThrow(OtlpParseError);
    expect(() => parseMetrics("not an object")).toThrow(OtlpParseError);
    expect(() => parseMetrics({ resourceMetrics: {} })).toThrow(OtlpParseError);
  });
});

describe("parseTraces", () => {
  it("keeps nanosecond timestamps as strings and derives duration in BigInt", () => {
    const { records } = parseTraces({
      resourceSpans: [
        {
          resource: RESOURCE,
          scopeSpans: [
            {
              scope: SCOPE,
              spans: [
                {
                  traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
                  spanId: "00f067aa0ba902b7",
                  parentSpanId: null,
                  name: "gateway.request",
                  kind: 2,
                  startTimeUnixNano: "1753500000000000000",
                  endTimeUnixNano: "1753500000123456789",
                  attributes: [attr("http.method", "POST")],
                },
              ],
            },
          ],
        },
      ],
    });
    const span = records[0];
    // The nanos exceed 2^53 — they must survive as strings, not as Numbers.
    expect(span.startTimeUnixNano).toBe("1753500000000000000");
    expect(span.endTimeUnixNano).toBe("1753500000123456789");
    expect(span.durationMs).toBeCloseTo(123.456789, 6);
    expect(span.parentSpanId).toBe("");
    expect(span.attributes).toEqual({ "http.method": "POST" });
  });

  it("clamps a negative or unparseable duration to zero", () => {
    const { records } = parseTraces({
      resourceSpans: [
        {
          resource: RESOURCE,
          scopeSpans: [
            {
              scope: SCOPE,
              spans: [
                { traceId: "a", spanId: "b", startTimeUnixNano: "20", endTimeUnixNano: "10" },
                { traceId: "c", spanId: "d", startTimeUnixNano: "oops", endTimeUnixNano: "10" },
              ],
            },
          ],
        },
      ],
    });
    expect(records.map((r) => r.durationMs)).toEqual([0, 0]);
  });

  it("skips a span with no traceId or spanId", () => {
    const { records, skipped } = parseTraces({
      resourceSpans: [
        { resource: RESOURCE, scopeSpans: [{ scope: SCOPE, spans: [{ name: "orphan" }] }] },
      ],
    });
    expect(records).toHaveLength(0);
    expect(skipped).toBe(1);
  });
});

describe("parseLogs", () => {
  it("unwraps body.stringValue and the optional trace correlation ids", () => {
    const { records, skipped } = parseLogs({
      resourceLogs: [
        {
          resource: RESOURCE,
          scopeLogs: [
            {
              scope: SCOPE,
              logRecords: [
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
                  body: { stringValue: "served" },
                  attributes: [],
                },
              ],
            },
          ],
        },
      ],
    });
    expect(skipped).toBe(0);
    expect(records[0]).toMatchObject({
      severityText: "ERROR",
      body: "upstream refused the request",
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      attributes: { route: "/v1/chat/completions" },
      serviceName: "ferrogate",
    });
    // A root/uncorrelated record carries empty ids, never `null` — the log line
    // must stay a flat, indexable set of scalar fields.
    expect(records[1].traceId).toBe("");
    expect(records[1].spanId).toBe("");
  });

  it("throws OtlpParseError on the wrong envelope", () => {
    expect(() => parseLogs({ resourceLogs: null })).toThrow(OtlpParseError);
  });
});

describe("attribute flattening + tenant resolution", () => {
  it("renders every AnyValue variant as a flat string", () => {
    expect(
      flattenAttributes([
        { key: "s", value: { stringValue: "text" } },
        { key: "i", value: { intValue: "9007199254740993" } },
        { key: "d", value: { doubleValue: 1.5 } },
        { key: "b", value: { boolValue: true } },
        { key: "arr", value: { arrayValue: { values: [{ stringValue: "x" }] } } },
        { key: "", value: { stringValue: "dropped: no key" } },
        { key: "empty" },
      ]),
    ).toEqual({
      s: "text",
      // The int keeps full precision because it is never coerced to a Number.
      i: "9007199254740993",
      d: "1.5",
      b: "true",
      arr: '["x"]',
      empty: "",
    });
  });

  it("prefers the header, then resource attributes, then record attributes", () => {
    expect(resolveTenant("hdr", { tenant_id: "res" }, { tenant_id: "rec" })).toBe("hdr");
    expect(resolveTenant(null, { tenant_id: "res" }, { tenant_id: "rec" })).toBe("res");
    expect(resolveTenant(null, {}, { "ferrogate.tenant_id": "rec" })).toBe("rec");
    expect(resolveTenant(null, {}, {})).toBe("unknown");
  });
});
