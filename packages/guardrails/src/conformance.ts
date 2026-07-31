/**
 * Reusable detector conformance harness + scriptable mock — port of
 * `ferrogate-guardrails::conformance`.
 *
 * `runDetectorConformance` drives any detector through the six required
 * behaviours: (1) Pass on benign, (2) sanitized Fail (fingerprint present, raw
 * value never serialized, no `matched_text`), (3) a transform whose patches
 * validate, (4) an error whose kind is declared, (5) timeout on an expired
 * deadline, (6) non-empty version reporting.
 */
import {
  DetectorError,
  firstMatchedText,
  type ContentPatch,
  type DetectorDescriptor,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type GuardrailDetector,
} from "./contract.js";
import {
  allContentSources,
  envelopeFromText,
  validateContentPatchesForSegments,
  type GuardrailEnvelope,
} from "./envelope.js";
import { byteLen, encodeUtf8 } from "./bytes.js";

/** Synthetic AWS-style access key. NOT a real credential (assembled). */
export const PROBE_SECRET = "AKIA" + "IOSFODNN7" + "EXAMPLE";

function benignEnvelope(): GuardrailEnvelope {
  return envelopeFromText(
    "chat_completions",
    "request",
    "user",
    "messages[0].content",
    "the quick brown fox jumps over the lazy dog",
  );
}

function probeEnvelope(): GuardrailEnvelope {
  return envelopeFromText(
    "chat_completions",
    "request",
    "user",
    "messages[0].content",
    `leaked credential ${PROBE_SECRET} in transit`,
  );
}

function detectorInput(envelope: GuardrailEnvelope): DetectorInput {
  return {
    protocol: envelope.protocol,
    stage: envelope.stage,
    tenant: { organization_id: "conformance-org" },
    model: "conformance-model",
    provider: "conformance-provider",
    text: envelope.segments[0]?.text ?? "",
    segments: envelope.segments,
  };
}

export interface ConformanceReport {
  pass_verdict: boolean;
  sanitized_fail: boolean;
  transform_validated: boolean;
  error_classified: boolean;
  timeout_enforced: boolean;
  version_reported: boolean;
  failures: string[];
}

export function conforms(report: ConformanceReport): boolean {
  return report.failures.length === 0;
}

export function allBehavioursExercised(report: ConformanceReport): boolean {
  return (
    conforms(report) &&
    report.pass_verdict &&
    report.sanitized_fail &&
    report.transform_validated &&
    report.error_classified &&
    report.timeout_enforced &&
    report.version_reported
  );
}

/** Drive `detector` through the six required behaviours. */
export async function runDetectorConformance(detector: GuardrailDetector): Promise<ConformanceReport> {
  const report: ConformanceReport = {
    pass_verdict: false,
    sanitized_fail: false,
    transform_validated: false,
    error_classified: false,
    timeout_enforced: false,
    version_reported: false,
    failures: [],
  };
  const fail = (message: string) => report.failures.push(message);
  const descriptor = detector.descriptor();
  if (descriptor.version.trim().length === 0) {
    fail("descriptor().version is empty");
  }

  const far = Date.now() + 5_000;

  const benign = benignEnvelope();
  const benignInput = detectorInput(benign);
  try {
    const result = await detector.evaluate(benignInput, far);
    report.pass_verdict = result.verdict === "pass";
    if (!report.pass_verdict) {
      fail("benign content did not produce a Pass verdict");
    }
    if (result.detector_version.trim().length === 0) {
      fail("DetectorResult.detector_version is empty");
    }
    report.version_reported =
      descriptor.version.trim().length > 0 && result.detector_version.trim().length > 0;
  } catch (error) {
    fail(`benign evaluation errored: ${(error as DetectorError).kind ?? "unknown"}`);
  }

  const probe = probeEnvelope();
  const probeInput = detectorInput(probe);
  try {
    const result = await detector.evaluate(probeInput, far);
    if (result.verdict !== "fail") {
      fail("probe content did not produce a Fail verdict");
    }
    const serialized = JSON.stringify(result);
    const leaksRawValue = serialized.includes(PROBE_SECRET);
    const carriesMatchedText = firstMatchedText(result) !== undefined;
    const hasFingerprint = result.findings.some((f) => f.fingerprint != null);
    if (leaksRawValue) {
      fail("serialized DetectorResult leaked the raw matched value");
    }
    if (carriesMatchedText) {
      fail("a finding carried raw matched_text in persisted evidence");
    }
    if (result.findings.length === 0) {
      fail("fail verdict produced no findings");
    } else if (!hasFingerprint) {
      fail("no finding carried a sanitized fingerprint");
    }
    report.sanitized_fail =
      result.verdict === "fail" && !leaksRawValue && !carriesMatchedText && hasFingerprint;

    try {
      validateContentPatchesForSegments(probe.segments, result.patches);
      if (descriptor.supports_transform && result.patches.length === 0) {
        fail("supports_transform detector emitted no patch for patch-eligible content");
      } else {
        report.transform_validated = true;
      }
    } catch (error) {
      fail(`emitted patch failed validation: ${(error as DetectorError).kind}`);
    }
  } catch (error) {
    fail(`probe evaluation errored: ${(error as DetectorError).kind ?? "unknown"}`);
  }

  const expired = Date.now() - 1_000;
  try {
    await detector.evaluate(benignInput, expired);
    fail("expired deadline did not produce an error");
  } catch (error) {
    const detectorError = error as DetectorError;
    report.timeout_enforced = detectorError.kind === "timeout";
    if (!report.timeout_enforced) {
      fail(`expired deadline produced ${detectorError.kind} instead of timeout`);
    }
    report.error_classified = descriptor.declared_failure_modes.includes(detectorError.kind);
    if (!report.error_classified) {
      fail(`error kind ${detectorError.kind} is not a declared failure mode`);
    }
  }

  return report;
}

/** Run the harness and throw unless every required behaviour was exercised. */
export async function assertDetectorConforms(detector: GuardrailDetector): Promise<ConformanceReport> {
  const report = await runDetectorConformance(detector);
  if (!allBehavioursExercised(report)) {
    throw new Error(`detector failed guardrail conformance: ${JSON.stringify(report.failures)}`);
  }
  return report;
}

// --- MockAdapter ------------------------------------------------------------

export interface MockResponse {
  outcome: { ok: true; result: DetectorResult } | { ok: false; kind: DetectorError["kind"] };
  delayMs?: number;
}

export const mockResponses = {
  pass: (detectorVersion: string): MockResponse => ({
    outcome: {
      ok: true,
      result: { verdict: "pass", findings: [], patches: [], detector_version: detectorVersion },
    },
  }),
  error: (kind: DetectorError["kind"]): MockResponse => ({ outcome: { ok: false, kind } }),
  result: (result: DetectorResult): MockResponse => ({ outcome: { ok: true, result } }),
  after: (response: MockResponse, delayMs: number): MockResponse => ({ ...response, delayMs }),
};

/** Build a sanitized Fail result aligned with the harness probe segment. */
export function conformanceProbeResult(detectorVersion: string): DetectorResult {
  const probe = probeEnvelope();
  const segment = probe.segments[0];
  if (!segment) {
    throw new Error("probe envelope has one segment");
  }
  const start = byteLen(segment.text.slice(0, segment.text.indexOf(PROBE_SECRET)));
  const end = start + encodeUtf8(PROBE_SECRET).length;
  return {
    verdict: "fail",
    findings: [
      {
        category: "secret.mock",
        severity: "critical",
        confidence: 0.99,
        byte_start: start,
        byte_end: end,
        segment_id: segment.segment_id,
        fingerprint: "hmac-sha256:mock",
        matched_text: null,
        attributes: {},
      },
    ],
    patches: [
      {
        segment_id: segment.segment_id,
        expected_fingerprint: segment.fingerprint,
        protocol_location: segment.protocol_location,
        byte_start: start,
        byte_end: end,
        replacement: "[REDACTED]",
      },
    ],
    detector_version: detectorVersion,
  };
}

/** A programmable detector: fixed descriptor + FIFO scripted replies. */
export class MockAdapter implements GuardrailDetector {
  private readonly desc: DetectorDescriptor;
  private responses: MockResponse[] = [];
  private defaultResponse: MockResponse;

  constructor(descriptor: DetectorDescriptor) {
    this.desc = descriptor;
    this.defaultResponse = mockResponses.pass(descriptor.version);
  }

  script(responses: MockResponse[]): this {
    this.responses.push(...responses);
    return this;
  }

  push(response: MockResponse): void {
    this.responses.push(response);
  }

  withDefault(response: MockResponse): this {
    this.defaultResponse = response;
    return this;
  }

  static conforming(): MockAdapter {
    const descriptor: DetectorDescriptor = {
      id: "mock-adapter",
      version: "mock/1",
      supports_request: true,
      supports_response: true,
      supports_transform: true,
      supported_sources: allContentSources(),
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: Number.MAX_SAFE_INTEGER,
      declared_failure_modes: ["timeout", "unavailable", "internal"],
    };
    return new MockAdapter(descriptor).script([
      mockResponses.pass("mock/1"),
      mockResponses.result(conformanceProbeResult("mock/1")),
    ]);
  }

  descriptor(): DetectorDescriptor {
    return { ...this.desc, supported_sources: [...this.desc.supported_sources] };
  }

  health(): DetectorHealth {
    return {
      circuit_open: false,
      consecutive_failures: 0,
      in_flight: 0,
      request_total: 0,
      success_total: 0,
      failure_total: 0,
    };
  }

  private nextResponse(): MockResponse {
    return this.responses.shift() ?? this.defaultResponse;
  }

  async evaluate(_input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    if (Date.now() >= deadlineMs) {
      throw DetectorError.new("timeout", "mock adapter deadline expired before execution");
    }
    const response = this.nextResponse();
    if (response.delayMs !== undefined) {
      await new Promise((resolve) => setTimeout(resolve, response.delayMs));
      if (Date.now() >= deadlineMs) {
        throw DetectorError.new("timeout", "mock adapter deadline expired during scripted delay");
      }
    }
    if (response.outcome.ok) {
      return response.outcome.result;
    }
    throw DetectorError.new(response.outcome.kind, "mock adapter scripted error");
  }
}

// Re-export so `firstMatchedText` reads through the conformance surface too.
export { firstMatchedText, type ContentPatch };
