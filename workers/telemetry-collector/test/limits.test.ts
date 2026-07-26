// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Unit coverage for the Cloudflare hard limits the telemetry-collector must
//   respect (issue #520). These run INSIDE workerd (same pool as the E2E suite) but drive
//   the clamps and the Analytics Engine writer directly, against an observable stub —
//   necessary because nothing inside a Worker can read back what writeDataPoint() accepted,
//   so an E2E alone could never prove the point shape or the truncation.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { describe, it, expect, vi } from "vitest";
import {
  AE_INDEX_MAX_BYTES,
  AE_MAX_BLOBS,
  AE_MAX_BLOB_BYTES,
  AE_MAX_DOUBLES,
  AE_MAX_WRITES_PER_INVOCATION,
  byteLength,
  clampBlobs,
  clampDoubles,
  clampIndex,
  truncateUtf8,
} from "../src/limits";
import {
  AnalyticsWriter,
  buildMetricPoint,
  buildSpanPoint,
  type AnalyticsEngineLike,
} from "../src/analytics";
import { serializeLine } from "../src/logs";
import type { ParsedMetricPoint, ParsedSpan } from "../src/otlp";

/** Observable stand-in for the Analytics Engine binding. */
class StubDataset implements AnalyticsEngineLike {
  readonly points: { indexes?: string[]; blobs?: string[]; doubles?: number[] }[] = [];
  writeDataPoint(point: { indexes?: string[]; blobs?: string[]; doubles?: number[] }): void {
    this.points.push(point);
  }
}

function metric(overrides: Partial<ParsedMetricPoint> = {}): ParsedMetricPoint {
  return {
    name: "ferrogate.request_logs",
    description: "Total structured request logs recorded by FerroGate.",
    kind: "sum",
    value: 42,
    attributes: {},
    resourceAttributes: { "service.name": "ferrogate" },
    scopeName: "ferrogate",
    serviceName: "ferrogate",
    ...overrides,
  };
}

function span(overrides: Partial<ParsedSpan> = {}): ParsedSpan {
  return {
    traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
    spanId: "00f067aa0ba902b7",
    parentSpanId: "",
    name: "gateway.request",
    kind: 2,
    startTimeUnixNano: "1753500000000000000",
    endTimeUnixNano: "1753500000123000000",
    durationMs: 123,
    attributes: {},
    resourceAttributes: { "service.name": "ferrogate" },
    scopeName: "ferrogate",
    serviceName: "ferrogate",
    ...overrides,
  };
}

describe("Analytics Engine index (the tenancy axis)", () => {
  it("truncates the index to 96 BYTES", () => {
    const tenant = "t".repeat(200);
    const index = clampIndex(tenant);
    expect(byteLength(index)).toBe(AE_INDEX_MAX_BYTES);
    expect(index).toBe("t".repeat(96));
  });

  it("measures BYTES not characters, and never splits a code point", () => {
    // Each emoji is 4 UTF-8 bytes: 30 of them = 120 bytes > the 96-byte cap.
    const index = clampIndex("🐛".repeat(30));
    expect(byteLength(index)).toBeLessThanOrEqual(AE_INDEX_MAX_BYTES);
    // 96 / 4 = exactly 24 whole emoji, with no lone surrogate at the cut.
    expect(index).toBe("🐛".repeat(24));
    expect(index.includes("�")).toBe(false);
  });

  it("falls back to a non-empty index (a point with no index cannot be written)", () => {
    expect(clampIndex("   ")).toBe("unknown");
    expect(clampIndex("")).toBe("unknown");
  });

  it("puts EXACTLY ONE index on every point, and it is the tenant", () => {
    expect(buildMetricPoint(metric(), "tenant-alpha").point.indexes).toEqual(["tenant-alpha"]);
    expect(buildSpanPoint(span(), "tenant-alpha").point.indexes).toEqual(["tenant-alpha"]);
  });

  it("truncates a long tenant id on the built point, not just via clampIndex", () => {
    const built = buildMetricPoint(metric(), "x".repeat(300));
    expect(built.point.indexes).toHaveLength(1);
    expect(byteLength(built.point.indexes[0])).toBe(AE_INDEX_MAX_BYTES);
  });
});

describe("Analytics Engine blob budget", () => {
  it("truncates the COMBINED blobs at 16 KB rather than letting the write fail", () => {
    const { blobs, truncated } = clampBlobs(["a".repeat(20_000), "b".repeat(20_000)]);
    expect(truncated).toBe(true);
    const total = blobs.reduce((sum, blob) => sum + byteLength(blob), 0);
    expect(total).toBe(AE_MAX_BLOB_BYTES);
    // The first blob is truncated to the whole budget; the second is dropped.
    expect(blobs).toHaveLength(1);
    expect(blobs[0]).toBe("a".repeat(AE_MAX_BLOB_BYTES));
  });

  it("keeps small blobs whole and spends the budget front to back", () => {
    const { blobs, truncated } = clampBlobs(["metric", "name", "svc"]);
    expect(truncated).toBe(false);
    expect(blobs).toEqual(["metric", "name", "svc"]);
  });

  it("drops blobs past the 20-blob ceiling", () => {
    const { blobs, truncated } = clampBlobs(Array.from({ length: 40 }, (_, i) => `b${i}`));
    expect(blobs).toHaveLength(AE_MAX_BLOBS);
    expect(truncated).toBe(true);
  });

  it("clamps a metric point built from a huge attribute set to the AE budget", () => {
    const attributes: Record<string, string> = {};
    for (let i = 0; i < 50; i++) attributes[`k${i}`] = "v".repeat(1000);
    const built = buildMetricPoint(metric({ attributes }), "tenant-alpha");
    expect(built.truncated).toBe(true);
    expect(built.point.blobs.length).toBeLessThanOrEqual(AE_MAX_BLOBS);
    const total = built.point.blobs.reduce((sum, blob) => sum + byteLength(blob), 0);
    expect(total).toBeLessThanOrEqual(AE_MAX_BLOB_BYTES);
  });

  it("caps doubles at 20 and replaces non-finite values", () => {
    const doubles = clampDoubles([...Array.from({ length: 30 }, (_, i) => i), Number.NaN]);
    expect(doubles).toHaveLength(AE_MAX_DOUBLES);
    expect(clampDoubles([Number.NaN, Number.POSITIVE_INFINITY])).toEqual([0, 0]);
  });

  it("truncateUtf8 is a no-op below the budget", () => {
    expect(truncateUtf8("short", 96)).toBe("short");
    expect(truncateUtf8("short", 0)).toBe("");
  });
});

describe("Analytics Engine point shape", () => {
  it("uses FIXED blob positions for a metric point (AE blobs are positional)", () => {
    const built = buildMetricPoint(
      metric({ attributes: { status: "hit", provider: "openai" }, value: 3 }),
      "tenant-alpha",
    );
    expect(built.point.blobs).toEqual([
      "metric",
      "ferrogate.request_logs",
      "ferrogate",
      "ferrogate",
      "sum",
      // Attributes are SORTED so a column means the same thing every invocation.
      "provider=openai",
      "status=hit",
    ]);
    expect(built.point.doubles).toEqual([3]);
  });

  it("uses FIXED blob positions for a span point and carries duration + kind", () => {
    const built = buildSpanPoint(span({ parentSpanId: "0011223344556677" }), "tenant-alpha");
    expect(built.point.blobs).toEqual([
      "span",
      "gateway.request",
      "4bf92f3577b34da6a3ce929d0e0e4736",
      "00f067aa0ba902b7",
      "0011223344556677",
      "ferrogate",
      "ferrogate",
    ]);
    expect(built.point.doubles).toEqual([123, 2]);
  });
});

describe("Analytics Engine per-invocation write cap", () => {
  it("stops at 250 writeDataPoint calls and reports the remainder as dropped", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const dataset = new StubDataset();
      const writer = new AnalyticsWriter(dataset);
      for (let i = 0; i < 300; i++) writer.writeMetric(metric({ name: `m${i}` }), "tenant-alpha");

      const summary = writer.finish("metrics");
      expect(dataset.points).toHaveLength(AE_MAX_WRITES_PER_INVOCATION);
      expect(summary.written).toBe(AE_MAX_WRITES_PER_INVOCATION);
      expect(summary.dropped).toBe(300 - AE_MAX_WRITES_PER_INVOCATION);
      expect(writer.atCap).toBe(true);

      // NOT a silent truncation: the loss is warned about exactly once.
      expect(warn).toHaveBeenCalledTimes(1);
      const line = JSON.parse(warn.mock.calls[0][0] as string) as Record<string, unknown>;
      expect(line).toMatchObject({
        event: "telemetry.analytics.limits",
        route: "metrics",
        written: AE_MAX_WRITES_PER_INVOCATION,
        dropped: 50,
        reason: "per_invocation_write_cap",
      });
    } finally {
      warn.mockRestore();
    }
  });

  it("does not warn when nothing was dropped or truncated", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const writer = new AnalyticsWriter(new StubDataset());
      writer.writeMetric(metric(), "tenant-alpha");
      const summary = writer.finish("metrics");
      expect(summary).toEqual({ written: 1, dropped: 0, truncated: 0 });
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("counts every point as dropped when the TELEMETRY binding is absent", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const writer = new AnalyticsWriter(undefined);
      writer.writeSpan(span(), "tenant-alpha");
      const summary = writer.finish("traces");
      expect(summary.written).toBe(0);
      expect(summary.dropped).toBe(1);
      const line = JSON.parse(warn.mock.calls[0][0] as string) as Record<string, unknown>;
      expect(line).toMatchObject({ reason: "no_analytics_binding" });
    } finally {
      warn.mockRestore();
    }
  });

  it("a throwing writeDataPoint drops one point but does not abort the batch", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      let calls = 0;
      const flaky: AnalyticsEngineLike = {
        writeDataPoint() {
          calls++;
          if (calls === 1) throw new Error("boom");
        },
      };
      const writer = new AnalyticsWriter(flaky);
      writer.writeMetric(metric(), "t");
      writer.writeMetric(metric(), "t");
      const summary = writer.finish("metrics");
      expect(summary).toMatchObject({ written: 1, dropped: 1 });
    } finally {
      warn.mockRestore();
    }
  });
});

describe("Workers Logs line budget", () => {
  it("keeps a line under the 256 KB cap by shedding attributes then clipping the body", () => {
    const entry: Record<string, unknown> = {
      signal: "log",
      tenant: "tenant-alpha",
      body: "b".repeat(400_000),
    };
    for (let i = 0; i < 20; i++) entry[`attr.k${i}`] = "v".repeat(10_000);

    const line = serializeLine(entry);
    expect(byteLength(line)).toBeLessThanOrEqual(256 * 1024);
    // Still valid JSON after clamping — a platform-truncated line would not be.
    const parsed = JSON.parse(line) as Record<string, unknown>;
    expect(parsed.tenant).toBe("tenant-alpha");
    expect(parsed.truncated).toBe(true);
    expect(parsed["attr.k0"]).toBeUndefined();
  });

  it("leaves a normal line untouched", () => {
    const line = serializeLine({ signal: "log", tenant: "t", body: "hello" });
    expect(JSON.parse(line)).toEqual({ signal: "log", tenant: "t", body: "hello" });
  });
});
