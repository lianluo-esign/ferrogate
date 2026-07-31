import { describe, expect, test } from "vitest";
import {
  DetectorError,
  DetectorSecret,
  findingSchema,
  firstMatchedText,
  type DetectorResult,
} from "../src/index.js";

describe("DetectorSecret redaction", () => {
  test("never leaks under toString/JSON/template", () => {
    const secret = DetectorSecret.new("super-secret-token");
    expect(String(secret)).toBe("<redacted>");
    expect(`${secret}`).toBe("<redacted>");
    expect(JSON.stringify({ token: secret })).toBe('{"token":"<redacted>"}');
    // ...but is exposable where explicitly needed.
    expect(secret.expose()).toBe("super-secret-token");
  });
});

describe("DetectorError classification", () => {
  test("affectsCircuit / retriable per taxonomy", () => {
    expect(DetectorError.new("timeout", "x").affectsCircuit()).toBe(true);
    expect(DetectorError.new("invalid_response", "x").affectsCircuit()).toBe(true);
    expect(DetectorError.new("unauthorized", "x").affectsCircuit()).toBe(false);
    expect(DetectorError.new("timeout", "x").retriable()).toBe(true);
    expect(DetectorError.new("invalid_response", "x").retriable()).toBe(false);
    expect(DetectorError.new("overloaded", "x").retriable()).toBe(true);
  });
});

describe("finding severity default", () => {
  test("missing severity defaults to high", () => {
    const parsed = findingSchema.parse({ category: "x" });
    expect(parsed.severity).toBe("high");
    expect(parsed.attributes).toEqual({});
  });
});

describe("firstMatchedText", () => {
  test("returns first in-memory matched_text", () => {
    const result: DetectorResult = {
      verdict: "fail",
      findings: [
        { category: "a", severity: "high", attributes: {} },
        { category: "b", severity: "high", matched_text: "hit", attributes: {} },
      ],
      patches: [],
      detector_version: "v",
    };
    expect(firstMatchedText(result)).toBe("hit");
  });
});
