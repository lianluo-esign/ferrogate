import { describe, expect, test } from "vitest";
import {
  DetectorSecret,
  DeterministicDetector,
  MockAdapter,
  allBehavioursExercised,
  assertDetectorConforms,
  runDetectorConformance,
} from "../src/index.js";

describe("conformance harness", () => {
  test("a secret-scanning deterministic detector conforms", async () => {
    const detector = DeterministicDetector.new({
      id: "secrets",
      supported_sources: ["user"],
      keywords: [],
      regex: [],
      secret_patterns: ["aws_access_key_id"],
      fingerprint_key: DetectorSecret.new("evidence-key"),
    });
    const report = await runDetectorConformance(detector);
    expect(report.failures).toEqual([]);
    expect(allBehavioursExercised(report)).toBe(true);
  });

  test("the scripted MockAdapter conforms", async () => {
    await expect(assertDetectorConforms(MockAdapter.conforming())).resolves.toBeDefined();
  });

  test("a detector that always passes fails the sanitized-fail behaviour", async () => {
    // A keyword detector that never matches the probe → no Fail on probe content.
    const detector = DeterministicDetector.new({
      id: "never",
      supported_sources: ["user"],
      keywords: ["this-keyword-never-appears"],
      regex: [],
      secret_patterns: [],
    });
    const report = await runDetectorConformance(detector);
    expect(allBehavioursExercised(report)).toBe(false);
    expect(report.failures.length).toBeGreaterThan(0);
  });
});
