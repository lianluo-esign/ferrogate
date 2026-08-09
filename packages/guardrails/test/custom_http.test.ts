import { describe, expect, test } from "vitest";
import {
  CustomHttpDetector,
  DetectorError,
  parseDetectorResponse,
  statusError,
  validateCustomHttpEndpoint,
} from "../src/index.js";

const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

describe("validateCustomHttpEndpoint", () => {
  test("accepts a public https endpoint", () => {
    expect(() =>
      validateCustomHttpEndpoint(new URL("https://detector.example.com/scan"), false),
    ).not.toThrow();
  });

  test.each([
    ["ftp://x.example.com", false],
    ["https://user:pw@x.example.com", false],
    ["https://x.example.com/?q=1", false],
    ["https://x.example.com/#frag", false],
    ["http://localhost/scan", false],
    ["http://10.0.0.1/scan", false],
  ])("rejects %s", (url) => {
    expect(() => validateCustomHttpEndpoint(new URL(url), false)).toThrow(DetectorError);
  });

  test("private endpoint allowed when explicitly opted in", () => {
    expect(() => validateCustomHttpEndpoint(new URL("http://10.0.0.1/scan"), true)).not.toThrow();
  });
});

describe("parseDetectorResponse", () => {
  test("new-style verdict", () => {
    const result = parseDetectorResponse(enc({ verdict: "fail", detector_version: "v9" }));
    expect(result.verdict).toBe("fail");
    expect(result.detector_version).toBe("v9");
  });

  test("legacy match+matched_text becomes a finding", () => {
    const result = parseDetectorResponse(
      enc({ match: true, matched_text: "hit", category: "custom" }),
    );
    expect(result.verdict).toBe("fail");
    expect(result.findings[0]?.category).toBe("custom");
    expect(result.findings[0]?.matched_text).toBe("hit");
  });

  test("missing verdict is invalid_response", () => {
    expect(() => parseDetectorResponse(enc({ findings: [] }))).toThrow(/verdict/);
  });

  test("legacy match=true without matched_text is invalid", () => {
    expect(() => parseDetectorResponse(enc({ match: true }))).toThrow(/matched_text/);
  });

  test("non-JSON body is invalid_response", () => {
    expect(() => parseDetectorResponse(new TextEncoder().encode("not json"))).toThrow(
      DetectorError,
    );
  });
});

describe("statusError mapping", () => {
  test.each([
    [401, "unauthorized"],
    [403, "unauthorized"],
    [429, "overloaded"],
    [503, "unavailable"],
    [418, "invalid_response"],
  ])("HTTP %i → %s", (status, kind) => {
    expect(statusError(status).kind).toBe(kind);
  });
});

describe("CustomHttpDetector config validation", () => {
  test("timeout above 30s is rejected", () => {
    expect(() =>
      CustomHttpDetector.new({
        id: "d",
        endpoint: "https://x.example.com/scan",
        timeoutMs: 31_000,
        maxConcurrency: 4,
        circuitFailureThreshold: 3,
        circuitCooldownMs: 1000,
        maxRetries: 0,
        maxPayloadBytes: 1024,
        maxResponseBytes: 1024,
        allowPrivateNetwork: false,
        supportedSources: ["user"],
      }),
    ).toThrow(DetectorError);
  });

  test("max_retries above 1 is rejected", () => {
    expect(() =>
      CustomHttpDetector.new({
        id: "d",
        endpoint: "https://x.example.com/scan",
        timeoutMs: 2000,
        maxConcurrency: 4,
        circuitFailureThreshold: 3,
        circuitCooldownMs: 1000,
        maxRetries: 2,
        maxPayloadBytes: 1024,
        maxResponseBytes: 1024,
        allowPrivateNetwork: false,
        supportedSources: ["user"],
      }),
    ).toThrow(/retries exceed one/);
  });

  test("valid config builds and reports a healthy circuit", () => {
    const detector = CustomHttpDetector.new({
      id: "d",
      endpoint: "https://x.example.com/scan",
      timeoutMs: 2000,
      maxConcurrency: 4,
      circuitFailureThreshold: 3,
      circuitCooldownMs: 1000,
      maxRetries: 1,
      maxPayloadBytes: 1024,
      maxResponseBytes: 1024,
      allowPrivateNetwork: false,
      supportedSources: ["user"],
    });
    expect(detector.health().circuit_open).toBe(false);
    expect(detector.descriptor().credential).toBe("none");
  });
});
