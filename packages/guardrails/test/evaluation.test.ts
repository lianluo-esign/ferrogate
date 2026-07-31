import { describe, expect, test } from "vitest";
import {
  DetectorSecret,
  DeterministicDetector,
  PromotionGate,
  conservativeThresholds,
  maliciousCount,
  recordShadowObservations,
  referenceCorpus,
  runDetectorEvaluation,
  scoreShadowObservations,
} from "../src/index.js";

const secretDetector = () =>
  DeterministicDetector.new({
    id: "secrets",
    supported_sources: ["user", "system", "developer", "assistant"],
    keywords: [],
    regex: [],
    secret_patterns: ["aws_access_key_id"],
    fingerprint_key: DetectorSecret.new("k"),
  });

describe("runDetectorEvaluation", () => {
  test("a secret-only detector scores honest partial recall on the reference corpus", async () => {
    const corpus = referenceCorpus();
    expect(maliciousCount(corpus)).toBe(4);
    const metrics = await runDetectorEvaluation(secretDetector(), corpus);
    // Catches exactly the one secret case; no false positives on benign prose.
    expect(metrics.true_positives).toBe(1);
    expect(metrics.false_positives).toBe(0);
    expect(metrics.false_negatives).toBe(3);
    expect(metrics.precision).toBe(1);
    expect(metrics.recall).toBeCloseTo(0.25, 5);
    expect(metrics.errors).toBe(0);
  });
});

describe("shadow scoring parity", () => {
  test("recorded shadow observations score identically to the live run", async () => {
    const corpus = referenceCorpus();
    const observations = await recordShadowObservations(secretDetector(), corpus);
    const shadow = scoreShadowObservations(corpus.version, observations);
    expect(shadow.true_positives).toBe(1);
    expect(shadow.precision).toBe(1);
    expect(shadow.recall).toBeCloseTo(0.25, 5);
  });
});

describe("PromotionGate", () => {
  const gate = new PromotionGate(conservativeThresholds());

  test("holds a candidate below the recall bar", () => {
    const metrics = {
      corpus_version: "v",
      total: 8,
      true_positives: 1,
      false_positives: 0,
      true_negatives: 4,
      false_negatives: 3,
      errors: 0,
      precision: 1,
      recall: 0.25,
      f1: 0.4,
      latency_p50_ms: 0,
      latency_p95_ms: 0,
      latency_max_ms: 0,
      false_positive_cases: [],
      false_negative_cases: [],
      error_cases: [],
    };
    const decision = gate.assessShadow(metrics);
    expect(decision.kind).toBe("hold");
  });

  test("promotes a candidate that clears every threshold", () => {
    const metrics = {
      corpus_version: "v",
      total: 8,
      true_positives: 4,
      false_positives: 0,
      true_negatives: 4,
      false_negatives: 0,
      errors: 0,
      precision: 1,
      recall: 1,
      f1: 1,
      latency_p50_ms: 0,
      latency_p95_ms: 0,
      latency_max_ms: 0,
      false_positive_cases: [],
      false_negative_cases: [],
      error_cases: [],
    };
    expect(gate.assessShadow(metrics).kind).toBe("promote");
    expect(gate.assessEnforced(metrics).kind).toBe("keep");
  });

  test("rolls back an enforced revision below the (looser) floor", () => {
    const metrics = {
      corpus_version: "v",
      total: 8,
      true_positives: 1,
      false_positives: 2,
      true_negatives: 2,
      false_negatives: 3,
      errors: 0,
      precision: 0.33,
      recall: 0.25,
      f1: 0.28,
      latency_p50_ms: 0,
      latency_p95_ms: 0,
      latency_max_ms: 0,
      false_positive_cases: [],
      false_negative_cases: [],
      error_cases: [],
    };
    expect(gate.assessEnforced(metrics).kind).toBe("rollback");
  });
});
