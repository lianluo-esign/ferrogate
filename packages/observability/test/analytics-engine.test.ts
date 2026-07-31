/**
 * The in-Worker Analytics Engine sink.
 *
 * ## Why a recorder and not a real binding
 *
 * `writeDataPoint()` is fire-and-forget by design: it returns `void`, has no
 * response, and is a LOCAL NO-OP under `wrangler dev --local` / miniflare —
 * there is no local AE store to read back. So a real binding here would assert
 * nothing at all. What is under test is not the platform's durability but THIS
 * module's behavior: which data points it shapes, and — the part that actually
 * bites in production — which ones it REFUSES to hand over, because Analytics
 * Engine drops an over-limit point silently, with no throw and no counter.
 * A recorder is the correct instrument for that; the D1/R2/DO suites elsewhere
 * use real bindings precisely because they DO have observable state.
 */
import { describe, expect, test } from "vitest";
import {
  AE_MAX_BLOBS,
  AE_MAX_BLOB_BYTES,
  AE_MAX_DOUBLES,
  AE_MAX_INDEX_BYTES,
  AnalyticsEngineSink,
  ObservabilityConfigError,
  analyticsEngineDataPointViolation,
  defaultGatewayMetricsSnapshot,
  otlpAttribute,
  type AnalyticsEngineDataPoint,
  type AnalyticsEngineDatasetBinding,
  type OtlpLogRecord,
  type OtlpSpanRecord,
} from "../src/index.js";

function recorder(): AnalyticsEngineDatasetBinding & { points: AnalyticsEngineDataPoint[] } {
  const points: AnalyticsEngineDataPoint[] = [];
  return { points, writeDataPoint: (event) => void points.push(event) };
}

describe("analyticsEngineDataPointViolation — the limits AE drops points for", () => {
  const ok: AnalyticsEngineDataPoint = { indexes: ["tenant_a"], blobs: ["x"], doubles: [1] };

  test("a conforming point has no violation", () => {
    expect(analyticsEngineDataPointViolation(ok)).toBeNull();
  });

  test("the index must be present, non-empty, and within 96 bytes", () => {
    expect(analyticsEngineDataPointViolation({ ...ok, indexes: [""] })).toContain("empty");
    // Multi-byte: 40 × 3-byte characters is 120 bytes but only 40 `.length`.
    const wide = "日".repeat(40);
    expect(wide.length).toBeLessThan(AE_MAX_INDEX_BYTES);
    expect(analyticsEngineDataPointViolation({ ...ok, indexes: [wide] })).toContain("120 bytes");
    expect(analyticsEngineDataPointViolation({ ...ok, indexes: ["a".repeat(96)] })).toBeNull();
    expect(analyticsEngineDataPointViolation({ ...ok, indexes: ["a".repeat(97)] })).toContain(
      "over the 96-byte limit",
    );
  });

  test("exactly one index — zero or two is a violation", () => {
    const zero = { indexes: [] as unknown as [string] };
    expect(analyticsEngineDataPointViolation(zero)).toContain("exactly 1 index");
    const two = { indexes: ["a", "b"] as unknown as [string] };
    expect(analyticsEngineDataPointViolation(two)).toContain("exactly 1 index");
  });

  test("blob and double counts", () => {
    const blobs = Array.from({ length: AE_MAX_BLOBS }, () => "b");
    expect(analyticsEngineDataPointViolation({ ...ok, blobs })).toBeNull();
    expect(analyticsEngineDataPointViolation({ ...ok, blobs: [...blobs, "b"] })).toContain(
      "at most 20 blobs",
    );
    const doubles = Array.from({ length: AE_MAX_DOUBLES }, () => 1);
    expect(analyticsEngineDataPointViolation({ ...ok, doubles })).toBeNull();
    expect(analyticsEngineDataPointViolation({ ...ok, doubles: [...doubles, 1] })).toContain(
      "at most 20 doubles",
    );
  });

  test("total blob bytes", () => {
    const under = ["a".repeat(AE_MAX_BLOB_BYTES)];
    expect(analyticsEngineDataPointViolation({ ...ok, blobs: under })).toBeNull();
    const over = ["a".repeat(AE_MAX_BLOB_BYTES), "a"];
    expect(analyticsEngineDataPointViolation({ ...ok, blobs: over })).toContain(
      "over the 5120-byte limit",
    );
  });

  test("a non-finite double is refused (JSON has no NaN/Infinity)", () => {
    expect(analyticsEngineDataPointViolation({ ...ok, doubles: [Number.NaN] })).toContain(
      "finite",
    );
    expect(
      analyticsEngineDataPointViolation({ ...ok, doubles: [Number.POSITIVE_INFINITY] }),
    ).toContain("finite");
  });
});

describe("AnalyticsEngineSink — refusal is visible, never silent", () => {
  test("an over-limit point is NOT handed to the binding and IS reported", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "tenant_default");
    const written = sink.writeDataPoint({ indexes: ["a".repeat(200)], blobs: ["x"] });
    expect(written).toBe(false);
    // The whole point: AE would have accepted the call and dropped the row.
    expect(dataset.points).toHaveLength(0);
    expect(sink.dropped()).toHaveLength(1);
    expect(sink.dropped()[0]?.reason).toContain("index");
  });

  test("a conforming point IS handed over and is not reported", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "tenant_default");
    expect(sink.writeDataPoint({ indexes: ["tenant_a"], doubles: [1] })).toBe(true);
    expect(dataset.points).toHaveLength(1);
    expect(sink.dropped()).toHaveLength(0);
  });

  test("clearDropped empties the buffer", () => {
    const sink = new AnalyticsEngineSink(recorder(), "t");
    sink.writeDataPoint({ indexes: [""] });
    expect(sink.dropped()).toHaveLength(1);
    sink.clearDropped();
    expect(sink.dropped()).toHaveLength(0);
  });
});

describe("AnalyticsEngineSink — validate", () => {
  test("an empty default tenant is refused at STARTUP", () => {
    // AE requires exactly one index per point and the tenant is it, so an empty
    // default means every tenantless record would be silently dropped later.
    expect(new AnalyticsEngineSink(recorder(), "   ").validate()).toBeInstanceOf(
      ObservabilityConfigError,
    );
  });

  test("an over-long default tenant is refused at startup", () => {
    expect(new AnalyticsEngineSink(recorder(), "a".repeat(97)).validate()).toBeInstanceOf(
      ObservabilityConfigError,
    );
  });

  test("a usable default tenant validates", () => {
    expect(new AnalyticsEngineSink(recorder(), "tenant_a").validate()).toBeNull();
    expect(new AnalyticsEngineSink(recorder(), "t").name()).toBe("analytics_engine");
  });
});

describe("AnalyticsEngineSink — what it writes", () => {
  test("metrics: one totals point plus one point per model/provider pair", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "tenant_default");
    const snapshot = {
      ...defaultGatewayMetricsSnapshot(),
      serviceName: "ferrogate",
      requestLogTotal: 7,
      requestErrorTotal: 2,
      modelProviderTotals: [
        { logicalModel: "best-reasoning", provider: "anthropic", requests: 5, totalTokens: 900 },
      ],
    };
    expect(sink.writeMetrics(snapshot, "tenant_a")).toBe(2);
    expect(dataset.points).toHaveLength(2);
    expect(dataset.points[0]).toEqual({
      indexes: ["tenant_a"],
      blobs: ["gateway_totals", "ferrogate"],
      doubles: [7, 2, 0, 0, 0, 0],
    });
    expect(dataset.points[1]).toEqual({
      indexes: ["tenant_a"],
      blobs: ["model_provider", "ferrogate", "best-reasoning", "anthropic"],
      doubles: [5, 900],
    });
  });

  test("the per-record tenant attribute wins over the caller's, which wins over the default", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "tenant_default");
    const span = (attributes: OtlpSpanRecord["attributes"]): OtlpSpanRecord => ({
      traceId: "t1",
      spanId: "s1",
      name: "gateway.request",
      startTimeUnixNano: 1_000_000,
      endTimeUnixNano: 3_000_000,
      attributes,
    });
    sink.writeSpans("ferrogate", [span([otlpAttribute("tenant", "tenant_from_span")])], "arg");
    sink.writeSpans("ferrogate", [span([])], "tenant_from_arg");
    sink.writeSpans("ferrogate", [span([])]);
    expect(dataset.points.map((p) => p.indexes[0])).toEqual([
      "tenant_from_span",
      "tenant_from_arg",
      "tenant_default",
    ]);
  });

  test("spans carry the identity blobs and millisecond timestamps", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "t");
    sink.writeSpans("ferrogate", [
      {
        traceId: "trace_1",
        spanId: "span_1",
        name: "gateway.upstream",
        startTimeUnixNano: 2_000_000,
        endTimeUnixNano: 5_000_000,
        attributes: [],
      },
    ]);
    expect(dataset.points[0]).toEqual({
      indexes: ["t"],
      blobs: ["span", "ferrogate", "gateway.upstream", "trace_1", "span_1"],
      // Nanos → millis, so the double stays inside a range AE renders usefully.
      doubles: [2, 5],
    });
  });

  test("logs carry severity and body", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "t");
    const log: OtlpLogRecord = {
      severityText: "ERROR",
      body: "upstream refused",
      timeUnixNano: 4_000_000,
      attributes: [otlpAttribute("tenant", "tenant_b")],
    };
    expect(sink.writeLogs("ferrogate", [log])).toBe(1);
    expect(dataset.points[0]).toEqual({
      indexes: ["tenant_b"],
      blobs: ["log", "ferrogate", "ERROR", "upstream refused"],
      doubles: [4],
    });
  });

  test("an over-limit record inside a batch does not stop the rest", () => {
    const dataset = recorder();
    const sink = new AnalyticsEngineSink(dataset, "t");
    const base: OtlpLogRecord = {
      severityText: "INFO",
      body: "ok",
      timeUnixNano: 1_000_000,
      attributes: [],
    };
    const written = sink.writeLogs("ferrogate", [
      { ...base, body: "a".repeat(AE_MAX_BLOB_BYTES + 1) },
      base,
    ]);
    expect(written).toBe(1);
    expect(dataset.points).toHaveLength(1);
    expect(sink.dropped()).toHaveLength(1);
  });
});
