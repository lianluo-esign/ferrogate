import { describe, expect, it } from "vitest";
import {
  aggregateReportedCorrelation,
  parseReportedCorrelation,
} from "@/components/worker-ops/worker-ops-primitives";

describe("parseReportedCorrelation", () => {
  it("lifts root-level correlation fields", () => {
    const result = parseReportedCorrelation(
      JSON.stringify({
        request_id: "req-1",
        trace_id: "trace-1",
        agent_run_id: "run-1",
        parent_action_fingerprint: "sha256:parent",
      }),
    );
    expect(result).toEqual({
      requestId: "req-1",
      traceId: "trace-1",
      agentRunId: "run-1",
      parentActionFingerprint: "sha256:parent",
    });
  });

  it("falls back to a nested correlation object", () => {
    const result = parseReportedCorrelation(
      JSON.stringify({ correlation: { request_id: "req-nested" } }),
    );
    expect(result.requestId).toBe("req-nested");
    expect(result.traceId).toBeNull();
  });

  it("returns all-null for malformed or empty json without throwing", () => {
    for (const input of ["not json {", "", null, undefined, "[1,2,3]", '"str"']) {
      expect(parseReportedCorrelation(input)).toEqual({
        requestId: null,
        traceId: null,
        agentRunId: null,
        parentActionFingerprint: null,
      });
    }
  });
});

describe("aggregateReportedCorrelation", () => {
  it("takes the first non-null value seen across events", () => {
    const result = aggregateReportedCorrelation([
      JSON.stringify({ request_id: "req-a" }),
      JSON.stringify({ trace_id: "trace-b", request_id: "req-b" }),
      "malformed",
    ]);
    expect(result.requestId).toBe("req-a");
    expect(result.traceId).toBe("trace-b");
    expect(result.agentRunId).toBeNull();
  });
});
