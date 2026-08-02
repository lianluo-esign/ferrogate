import { describe, expect, test } from "vitest";
import {
  CloudflareBackend,
  defaultGatewayMetricsSnapshot,
  ObservabilitySignal,
  OtlpBackend,
  otlpAttribute,
  type GatewayMetricsSnapshot,
  type OtlpLogRecord,
  type OtlpSpanRecord,
  type TelemetryBackend,
} from "../src/index.js";

function snapshot(): GatewayMetricsSnapshot {
  return { ...defaultGatewayMetricsSnapshot(), serviceName: "ferrogate" };
}

function span(): OtlpSpanRecord {
  return {
    traceId: "0af7651916cd43dd8448eb211c80319c",
    spanId: "b7ad6b7169203331",
    name: "ferrogate.gateway.request",
    startTimeUnixNano: 1,
    endTimeUnixNano: 2,
    attributes: [otlpAttribute("tenant", "acme")],
  };
}

function log(): OtlpLogRecord {
  return {
    severityText: "INFO",
    body: "request",
    timeUnixNano: 1,
    attributes: [],
  };
}

describe("OtlpBackend", () => {
  test("builds a request per signal", () => {
    const backend = new OtlpBackend("http://collector:4318");
    expect(backend.metricsRequest(snapshot())?.url).toBe(
      "http://collector:4318/v1/metrics",
    );
    expect(backend.tracesRequest("ferrogate", [span()])?.url).toBe(
      "http://collector:4318/v1/traces",
    );
    expect(backend.logsRequest("ferrogate", [log()])?.url).toBe(
      "http://collector:4318/v1/logs",
    );
  });

  test("skips empty batches", () => {
    const backend = new OtlpBackend("http://collector:4318");
    expect(backend.tracesRequest("ferrogate", [])).toBeNull();
    expect(backend.logsRequest("ferrogate", [])).toBeNull();
  });

  test("skips signals it does not carry", () => {
    const backend = new OtlpBackend("http://collector:4318").withSignals([
      ObservabilitySignal.Metric,
    ]);
    expect(backend.supports(ObservabilitySignal.Metric)).toBe(true);
    expect(backend.supports(ObservabilitySignal.Trace)).toBe(false);
    expect(backend.metricsRequest(snapshot())).not.toBeNull();
    expect(backend.tracesRequest("ferrogate", [span()])).toBeNull();
    expect(backend.logsRequest("ferrogate", [log()])).toBeNull();
  });

  test("validate rejects a scheme-less endpoint", () => {
    expect(new OtlpBackend("collector:4318").validate()?.errorKind).toBe(
      "InvalidEndpoint",
    );
  });

  test("validate rejects an empty endpoint", () => {
    expect(new OtlpBackend("   ").validate()?.errorKind).toBe("MissingEndpoint");
  });

  test("carries no credential headers", () => {
    const metrics = new OtlpBackend("http://collector:4318").metricsRequest(
      snapshot(),
    );
    expect(metrics?.headers).toEqual([]);
  });
});

describe("TelemetryBackend as a common contract", () => {
  test("backends are usable through the shared interface", () => {
    const backends: TelemetryBackend[] = [
      new OtlpBackend("http://collector:4318"),
      new CloudflareBackend(
        "https://collector.example.workers.dev",
        "token",
      ),
    ];
    expect(backends.map((b) => b.name())).toEqual(["otlp", "cloudflare"]);
    for (const backend of backends) {
      expect(backend.validate()).toBeNull();
      expect(backend.metricsRequest(snapshot())).not.toBeNull();
    }
  });
});
