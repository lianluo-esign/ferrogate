/**
 * Unit coverage for the pieces a request-level test cannot pin down: the
 * Analytics Engine limit clamps, the OTLP flatteners, the body-cap reader, and
 * the per-invocation write cap.
 *
 * These run in `workerd` alongside the integration suite (same pool) but touch
 * no binding — the sink port is exercised through {@link RecordingTelemetrySink}.
 */
import { describe, expect, it } from "vitest";
import {
  AE_MAX_BLOBS,
  AE_MAX_BLOB_BYTES,
  AE_MAX_WRITES_PER_INVOCATION,
  DEFAULT_MAX_BODY_BYTES,
  OtlpEnvelopeError,
  RecordingTelemetrySink,
  SinkWriter,
  UNKNOWN_TENANT,
  anyValueToString,
  buildMetricPoint,
  byteLength,
  clampBlobs,
  clampDoubles,
  clampIndex,
  durationMsOf,
  flattenAttributes,
  parseLogs,
  parseMetrics,
  parseTraces,
  readJsonBody,
  resolveMaxBodyBytes,
  truncateUtf8,
} from "../src/index.js";
import { logsPayload, metricsPayload, tracesPayload } from "./fixtures.js";

describe("Analytics Engine limit clamps", () => {
  it("truncates an index at 96 BYTES without splitting a code point", () => {
    // "€" is 3 bytes: 33 of them is 99 bytes, one over the 96-byte budget.
    const index = clampIndex("€".repeat(33));
    expect(byteLength(index)).toBeLessThanOrEqual(96);
    expect(index).toBe("€".repeat(32));
    expect(index.includes("�")).toBe(false);
  });

  it("falls back to the unknown-tenant index rather than an empty one", () => {
    // A point with no index cannot be written at all.
    expect(clampIndex("   ")).toBe(UNKNOWN_TENANT);
    expect(clampIndex("")).toBe(UNKNOWN_TENANT);
  });

  it("keeps at most 20 blobs and flags the truncation", () => {
    const clamped = clampBlobs(Array.from({ length: 25 }, (_, i) => `b${i}`));
    expect(clamped.blobs).toHaveLength(AE_MAX_BLOBS);
    expect(clamped.truncated).toBe(true);
  });

  it("spends the 16 KB blob budget front-to-back and never exceeds it", () => {
    const clamped = clampBlobs(["identity", "x".repeat(AE_MAX_BLOB_BYTES), "dropped"]);
    expect(clamped.truncated).toBe(true);
    expect(clamped.blobs[0]).toBe("identity");
    const total = clamped.blobs.reduce((sum, blob) => sum + byteLength(blob), 0);
    expect(total).toBeLessThanOrEqual(AE_MAX_BLOB_BYTES);
  });

  it("replaces non-finite doubles with 0 rather than poisoning the write", () => {
    expect(clampDoubles([1, Number.NaN, Number.POSITIVE_INFINITY])).toEqual([1, 0, 0]);
  });

  it("truncateUtf8 is a no-op below the budget and cuts on a boundary above it", () => {
    expect(truncateUtf8("héllo", 100)).toBe("héllo");
    expect(truncateUtf8("é", 1)).toBe("");
  });
});

describe("the body cap", () => {
  it("defaults to 4 MiB when the var is unset, empty, or unparseable", () => {
    expect(resolveMaxBodyBytes(undefined)).toBe(DEFAULT_MAX_BODY_BYTES);
    expect(resolveMaxBodyBytes("")).toBe(DEFAULT_MAX_BODY_BYTES);
    expect(resolveMaxBodyBytes("banana")).toBe(DEFAULT_MAX_BODY_BYTES);
    // A non-positive override must NOT be read as "unlimited" — or as 0, which
    // would reject every request.
    expect(resolveMaxBodyBytes("0")).toBe(DEFAULT_MAX_BODY_BYTES);
    expect(resolveMaxBodyBytes("-1")).toBe(DEFAULT_MAX_BODY_BYTES);
  });

  it("honours a valid override", () => {
    expect(resolveMaxBodyBytes("2048")).toBe(2048);
  });

  it("rejects an over-limit body declared by Content-Length, unbuffered", async () => {
    const request = new Request("https://t.test/v1/logs", {
      method: "POST",
      headers: { "content-length": "64" },
      body: "x".repeat(64),
    });
    expect(request.headers.get("content-length")).toBe("64");
    const read = await readJsonBody(request, 32);
    expect(read.ok).toBe(false);
    if (!read.ok) expect(read.response.status).toBe(413);
    // The declared length is checked FIRST, so the body was never read in.
    expect(request.bodyUsed).toBe(false);
  });

  it("does not trust a LYING Content-Length: a small claim cannot smuggle a big body", async () => {
    const request = new Request("https://t.test/v1/logs", {
      method: "POST",
      headers: { "content-length": "1" },
      body: "x".repeat(64),
    });
    const read = await readJsonBody(request, 32);
    expect(read.ok).toBe(false);
    if (!read.ok) expect(read.response.status).toBe(413);
  });

  it("rejects an over-limit body even when Content-Length is absent", async () => {
    // A streamed upload carries no Content-Length, so the buffered length is
    // re-checked; without that second check the cap would be bypassable.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("x".repeat(64)));
        controller.close();
      },
    });
    const request = new Request("https://t.test/v1/logs", {
      method: "POST",
      body: stream,
      // @ts-expect-error `duplex` is required for a stream body but missing from
      // the ambient Workers RequestInit type.
      duplex: "half",
    });
    expect(request.headers.get("content-length")).toBeNull();
    const read = await readJsonBody(request, 32);
    expect(read.ok).toBe(false);
    if (!read.ok) expect(read.response.status).toBe(413);
  });

  it("accepts a body at exactly the limit", async () => {
    const body = JSON.stringify({ resourceLogs: [] });
    const request = new Request("https://t.test/v1/logs", { method: "POST", body });
    const read = await readJsonBody(request, body.length);
    expect(read.ok).toBe(true);
  });
});

describe("OTLP value flattening", () => {
  it("renders every AnyValue variant as a flat string", () => {
    expect(anyValueToString({ stringValue: "s" })).toBe("s");
    // 64-bit ints arrive as JSON STRINGS; they must survive verbatim.
    expect(anyValueToString({ intValue: "9007199254740993" })).toBe("9007199254740993");
    expect(anyValueToString({ doubleValue: 1.5 })).toBe("1.5");
    expect(anyValueToString({ boolValue: false })).toBe("false");
    expect(anyValueToString({ arrayValue: { values: [{ stringValue: "a" }] } })).toBe('["a"]');
    expect(
      anyValueToString({ kvlistValue: { values: [{ key: "k", value: { stringValue: "v" } }] } }),
    ).toBe('{"k":"v"}');
    expect(anyValueToString(undefined)).toBe("");
  });

  it("ignores malformed attribute entries instead of failing the record", () => {
    expect(
      flattenAttributes([{ key: "ok", value: { stringValue: "1" } }, 42, { value: {} }]),
    ).toEqual({ ok: "1" });
  });

  it("computes span durations in BigInt so nanos past 2^53 stay exact", () => {
    expect(durationMsOf("1700000000000000000", "1700000000500000000")).toBe(500);
    // End before start, or non-numeric, must not produce a negative/NaN double.
    expect(durationMsOf("2", "1")).toBe(0);
    expect(durationMsOf("", "1")).toBe(0);
  });
});

describe("OTLP parsing", () => {
  it("throws OtlpEnvelopeError (→400) when the envelope key is missing", () => {
    expect(() => parseMetrics({})).toThrow(OtlpEnvelopeError);
    expect(() => parseTraces({ resourceSpans: {} })).toThrow(OtlpEnvelopeError);
    expect(() => parseLogs("not an object")).toThrow(OtlpEnvelopeError);
  });

  it("flattens a metrics batch, carrying resource + point attributes", () => {
    const parsed = parseMetrics(metricsPayload());
    expect(parsed.skipped).toBe(0);
    expect(parsed.records).toHaveLength(1);
    const [point] = parsed.records;
    expect(point?.name).toBe("ferrogate.requests.total");
    expect(point?.kind).toBe("sum");
    expect(point?.value).toBe(42);
    expect(point?.serviceName).toBe("ferrogate-gateway");
    expect(point?.scopeName).toBe("ferrogate");
    expect(point?.attributes).toEqual({ status: "200" });
    expect(point?.resourceAttributes["ferrogate.tenant_id"]).toBe("tenant-a");
  });

  it("accepts gauge and histogram metrics (CF's own OTLP export emits them)", () => {
    const parsed = parseMetrics(
      metricsPayload([
        { name: "g", gauge: { dataPoints: [{ asInt: "7" }] } },
        { name: "h", histogram: { dataPoints: [{ sum: 12.5, count: 3 }] } },
      ]),
    );
    expect(parsed.records.map((r) => [r.name, r.kind, r.value])).toEqual([
      ["ferrogate.requests.total", "sum", 42],
      ["g", "gauge", 7],
      ["h", "histogram", 12.5],
    ]);
  });

  it("skips an unnamed metric and a valueless point, keeping the rest", () => {
    const parsed = parseMetrics(
      metricsPayload([
        { name: "", sum: { dataPoints: [{ asDouble: 1 }] } },
        { name: "novalue", sum: { dataPoints: [{ attributes: [] }] } },
      ]),
    );
    expect(parsed.records).toHaveLength(1);
    expect(parsed.skipped).toBe(2);
  });

  it("flattens a traces batch and defaults a root span's parent to empty", () => {
    const parsed = parseTraces(
      tracesPayload([
        { traceId: "t2", spanId: "s2", startTimeUnixNano: "0", endTimeUnixNano: "0" },
      ]),
    );
    expect(parsed.skipped).toBe(0);
    expect(parsed.records[1]?.parentSpanId).toBe("");
    expect(parsed.records[1]?.durationMs).toBe(0);
    expect(parsed.records[0]?.durationMs).toBe(500);
  });

  it("skips a span with no traceId/spanId — it cannot be correlated", () => {
    const parsed = parseTraces(tracesPayload([{ name: "orphan" }, { traceId: "t", spanId: "" }]));
    expect(parsed.records).toHaveLength(1);
    expect(parsed.skipped).toBe(2);
  });

  it("flattens a logs batch, accepting an AnyValue body or a bare string", () => {
    const parsed = parseLogs(
      logsPayload([{ severityText: "INFO", body: "plain", timeUnixNano: "1" }]),
    );
    expect(parsed.skipped).toBe(0);
    expect(parsed.records[0]?.body).toBe("upstream refused the request");
    expect(parsed.records[0]?.severityNumber).toBe(17);
    expect(parsed.records[1]?.body).toBe("plain");
  });
});

describe("the per-invocation write cap", () => {
  it("stops at 250 writes and counts the remainder as dropped", () => {
    const sink = new RecordingTelemetrySink();
    const writer = new SinkWriter(sink);
    const metric = parseMetrics(metricsPayload()).records[0];
    if (!metric) throw new Error("fixture produced no metric");

    for (let i = 0; i < AE_MAX_WRITES_PER_INVOCATION + 17; i++) {
      writer.writeMetric(metric, "tenant-a");
    }

    const summary = writer.finish("metrics");
    expect(summary.written).toBe(AE_MAX_WRITES_PER_INVOCATION);
    expect(summary.dropped).toBe(17);
    expect(sink.points).toHaveLength(AE_MAX_WRITES_PER_INVOCATION);
  });

  it("cannot be raised above the platform cap", () => {
    expect(new SinkWriter(new RecordingTelemetrySink(), 10_000).cap).toBe(
      AE_MAX_WRITES_PER_INVOCATION,
    );
  });

  it("counts a clamped point as truncated", () => {
    const sink = new RecordingTelemetrySink();
    const writer = new SinkWriter(sink);
    const metric = parseMetrics(metricsPayload()).records[0];
    if (!metric) throw new Error("fixture produced no metric");
    writer.write(buildMetricPoint({ ...metric, name: "x".repeat(AE_MAX_BLOB_BYTES + 1) }, "t"));
    expect(writer.finish("metrics").truncated).toBe(1);
  });
});
