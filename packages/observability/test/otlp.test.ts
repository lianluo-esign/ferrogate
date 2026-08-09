import { describe, expect, test } from "vitest";
import {
  type GatewayMetricsSnapshot,
  ObservabilityConfigError,
  buildOtlpLogsRequest,
  buildOtlpMetricsRequest,
  buildOtlpTracesRequest,
  defaultGatewayMetricsSnapshot,
  otlpAttribute,
} from "../src/index.js";

function decode(body: Uint8Array): unknown {
  return JSON.parse(new TextDecoder().decode(body));
}

describe("OTLP/JSON request builders", () => {
  test("builds metrics, traces, and logs requests", () => {
    const snapshot: GatewayMetricsSnapshot = {
      ...defaultGatewayMetricsSnapshot(),
      serviceName: "ferrogate",
      billingEventTotal: 1,
      guardrailPolicyCasConflictTotal: 2,
      tokenTotals: { promptTokens: 3, completionTokens: 5, totalTokens: 8 },
    };

    const metrics = buildOtlpMetricsRequest("http://collector:4318", snapshot);
    expect(metrics.method).toBe("POST");
    expect(metrics.url).toBe("http://collector:4318/v1/metrics");
    expect(metrics.contentType).toBe("application/json");
    const metricsBody = decode(metrics.body) as any;
    expect(metricsBody.resourceMetrics[0].resource.attributes[0].value.stringValue).toBe(
      "ferrogate",
    );
    const metricNames = metricsBody.resourceMetrics[0].scopeMetrics[0].metrics.map(
      (m: any) => m.name,
    );
    expect(metricNames).toContain("ferrogate.tokens");
    expect(metricNames).toContain("ferrogate.guardrail.policy_cas_conflicts");

    const traces = buildOtlpTracesRequest("http://collector:4318/", "ferrogate", [
      {
        traceId: "00000000000000000000000000000001",
        spanId: "0000000000000001",
        name: "ferrogate.gateway.request",
        startTimeUnixNano: 1,
        endTimeUnixNano: 2,
        attributes: [otlpAttribute("request_id", "fg-1")],
      },
    ]);
    expect(traces.url).toBe("http://collector:4318/v1/traces");
    const tracesBody = decode(traces.body) as any;
    expect(tracesBody.resourceSpans[0].scopeSpans[0].spans[0].name).toBe(
      "ferrogate.gateway.request",
    );
    // Option<parent> absent → null, kind 2, times stringified.
    expect(tracesBody.resourceSpans[0].scopeSpans[0].spans[0].parentSpanId).toBeNull();
    expect(tracesBody.resourceSpans[0].scopeSpans[0].spans[0].kind).toBe(2);
    expect(tracesBody.resourceSpans[0].scopeSpans[0].spans[0].startTimeUnixNano).toBe("1");

    const logs = buildOtlpLogsRequest("http://collector:4318", "ferrogate", [
      {
        traceId: "00000000000000000000000000000001",
        spanId: "0000000000000001",
        severityText: "INFO",
        body: "request completed",
        timeUnixNano: 3,
        attributes: [otlpAttribute("status_code", "200")],
      },
    ]);
    expect(logs.url).toBe("http://collector:4318/v1/logs");
    const logsBody = decode(logs.body) as any;
    expect(logsBody.resourceLogs[0].scopeLogs[0].logRecords[0].body.stringValue).toBe(
      "request completed",
    );
  });

  test("rejects a scheme-less endpoint", () => {
    const snapshot = defaultGatewayMetricsSnapshot();
    try {
      buildOtlpMetricsRequest("collector:4318", snapshot);
      throw new Error("expected throw");
    } catch (error) {
      expect(error).toBeInstanceOf(ObservabilityConfigError);
      expect((error as ObservabilityConfigError).errorKind).toBe("InvalidEndpoint");
      expect((error as ObservabilityConfigError).endpoint).toBe("collector:4318");
    }
  });

  test("rejects an empty endpoint", () => {
    expect(() => buildOtlpMetricsRequest("   ", defaultGatewayMetricsSnapshot())).toThrowError(
      ObservabilityConfigError,
    );
  });

  test("guardrail pass count saturates and is emitted as a verdict data point", () => {
    const snapshot: GatewayMetricsSnapshot = {
      ...defaultGatewayMetricsSnapshot(),
      serviceName: "ferrogate",
      guardrailEvaluationTotal: 5,
      guardrailEvaluationFailTotal: 2,
      guardrailEvaluationErrorTotal: 1,
    };
    const body = decode(buildOtlpMetricsRequest("http://c:4318", snapshot).body) as any;
    const evals = body.resourceMetrics[0].scopeMetrics[0].metrics.filter(
      (m: any) => m.name === "ferrogate.guardrail.evaluations",
    );
    const pass = evals.find(
      (m: any) => m.sum.dataPoints[0].attributes[0].value.stringValue === "pass",
    );
    // 5 - 2 - 1 = 2 pass.
    expect(pass.sum.dataPoints[0].asDouble).toBe(2);
  });

  test("empty snapshot never underflows the saturating pass subtraction", () => {
    const snapshot: GatewayMetricsSnapshot = {
      ...defaultGatewayMetricsSnapshot(),
      guardrailEvaluationTotal: 0,
      guardrailEvaluationFailTotal: 3,
    };
    const body = decode(buildOtlpMetricsRequest("http://c:4318", snapshot).body) as any;
    const pass = body.resourceMetrics[0].scopeMetrics[0].metrics
      .filter((m: any) => m.name === "ferrogate.guardrail.evaluations")
      .find((m: any) => m.sum.dataPoints[0].attributes[0].value.stringValue === "pass");
    expect(pass.sum.dataPoints[0].asDouble).toBe(0);
  });
});
