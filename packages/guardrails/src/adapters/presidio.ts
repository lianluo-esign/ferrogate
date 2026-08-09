/**
 * Microsoft Presidio analyzer adapter — port of
 * `ferrogate-guardrails::adapters::presidio`.
 *
 * Speaks the Presidio `POST /analyze` contract against a customer-VPC self-hosted
 * deployment. Presidio returns CODE-POINT-indexed entity spans; this adapter
 * converts them to UTF-8 byte offsets, emits `pii.presidio.<entity>` findings
 * (High), and — since spans are known — redacts each span on mutable text
 * segments (non-overlapping). CustomerVpc residency.
 */

import { TIMED_OUT, withTimeout } from "../async.js";
import { byteLen, byteSlice } from "../bytes.js";
import {
  type ContentPatch,
  type ContentSegment,
  type ContentSource,
  type DetectorDescriptor,
  DetectorError,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type DetectorSecret,
  type Finding,
  type GuardrailDetector,
  MAX_DETECTOR_TIMEOUT_MS,
} from "../contract.js";
import { validateCustomHttpEndpoint } from "../custom_http.js";
import { isMutableTextSegment } from "../deterministic.js";
import {
  AdapterCounters,
  type DetectorTransport,
  HttpJsonTransport,
  adapterStatusError,
  charIndexToByteOffset,
  configDigest,
  hmacEvidenceFingerprint,
  nativeAdapterFailureModes,
} from "./transport.js";

const PRESIDIO_ADAPTER_VERSION = "presidio-analyzer-adapter/1";
const REDACTION = "[REDACTED]";

export interface PresidioDetectorConfig {
  id: string;
  endpoint: string;
  language: string;
  scoreThresholdPercent: number;
  entities?: string[];
  timeoutMs: number;
  maxPayloadBytes: number;
  maxResponseBytes: number;
  allowPrivateNetwork: boolean;
  supportedSources: ContentSource[];
  bearerToken?: DetectorSecret;
  fingerprintKey: DetectorSecret;
}

interface RecognizerResult {
  entity_type: string;
  start: number;
  end: number;
  score: number;
}

function validateConfig(config: PresidioDetectorConfig): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(config.endpoint);
  } catch {
    throw DetectorError.new(
      "invalid_configuration",
      "presidio detector endpoint is not a valid URL",
    );
  }
  validateCustomHttpEndpoint(endpoint, config.allowPrivateNetwork);
  if (
    config.id.trim().length === 0 ||
    config.language.trim().length === 0 ||
    config.scoreThresholdPercent > 100 ||
    config.timeoutMs === 0 ||
    config.timeoutMs > MAX_DETECTOR_TIMEOUT_MS ||
    config.maxPayloadBytes === 0 ||
    config.maxResponseBytes === 0 ||
    config.supportedSources.length === 0 ||
    new Set(config.supportedSources).size !== config.supportedSources.length ||
    (config.entities !== undefined &&
      (config.entities.length === 0 ||
        config.entities.some((e) => e.trim().length === 0) ||
        new Set(config.entities).size !== config.entities.length))
  ) {
    throw DetectorError.new(
      "invalid_configuration",
      "presidio detector id, language, threshold, limits, sources, or entities are invalid",
    );
  }
  return endpoint;
}

export class PresidioDetector implements GuardrailDetector {
  private config: PresidioDetectorConfig;
  private transport: DetectorTransport;
  private version: string;
  private counters = new AdapterCounters();

  private constructor(
    config: PresidioDetectorConfig,
    transport: DetectorTransport,
    version: string,
  ) {
    this.config = config;
    this.transport = transport;
    this.version = version;
  }

  static new(config: PresidioDetectorConfig): PresidioDetector {
    const endpoint = validateConfig(config);
    const transport = HttpJsonTransport.build(
      endpoint,
      config.timeoutMs,
      config.allowPrivateNetwork,
      config.bearerToken,
      config.maxResponseBytes,
    );
    return PresidioDetector.withTransport(config, transport);
  }

  static withTransport(
    config: PresidioDetectorConfig,
    transport: DetectorTransport,
  ): PresidioDetector {
    validateConfig(config);
    const digest = configDigest([
      config.language,
      String(config.scoreThresholdPercent),
      config.entities ? config.entities.join(",") : "",
    ]);
    return new PresidioDetector(config, transport, `${PRESIDIO_ADAPTER_VERSION}+cfg.${digest}`);
  }

  private scoreThreshold(): number {
    return this.config.scoreThresholdPercent / 100.0;
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.config.id,
      version: this.version,
      supports_request: true,
      supports_response: true,
      supports_transform: true,
      supported_sources: [...this.config.supportedSources],
      credential: this.config.bearerToken ? "bearer_token" : "none",
      data_residency: "customer_vpc",
      max_payload_bytes: this.config.maxPayloadBytes,
      declared_failure_modes: nativeAdapterFailureModes(),
    };
  }

  health(): DetectorHealth {
    return this.counters.health();
  }

  private async analyzeSegment(
    segment: ContentSegment,
    deadlineMs: number,
    findings: Finding[],
    patches: ContentPatch[],
  ): Promise<void> {
    const request = {
      text: segment.text,
      language: this.config.language,
      score_threshold: this.scoreThreshold(),
      ...(this.config.entities ? { entities: this.config.entities } : {}),
    };
    const body = new TextEncoder().encode(JSON.stringify(request));
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw DetectorError.new("timeout", "presidio detector deadline expired");
    }
    const attemptTimeout = Math.min(remaining, this.config.timeoutMs);
    const raced = await withTimeout(this.transport.postJson(body), attemptTimeout);
    if (raced === TIMED_OUT) {
      throw DetectorError.new("timeout", "presidio detector request timed out");
    }
    if (raced.status !== 200) {
      throw adapterStatusError(raced.status);
    }
    let results: RecognizerResult[];
    try {
      results = JSON.parse(new TextDecoder().decode(raced.body)) as RecognizerResult[];
      if (!Array.isArray(results)) {
        throw new Error("not an array");
      }
    } catch {
      throw DetectorError.new(
        "invalid_response",
        "presidio detector returned a malformed analyze response",
      );
    }

    const threshold = this.scoreThreshold();
    const spans: Array<[number, number, RecognizerResult]> = [];
    for (const result of results) {
      if (result.score < threshold) {
        continue;
      }
      const byteStart = charIndexToByteOffset(segment.text, result.start);
      const byteEnd = charIndexToByteOffset(segment.text, result.end);
      if (byteStart === undefined || byteEnd === undefined) {
        throw DetectorError.new(
          "invalid_response",
          "presidio detector returned an out-of-range entity span",
        );
      }
      if (byteStart >= byteEnd) {
        throw DetectorError.new(
          "invalid_response",
          "presidio detector returned an empty or inverted entity span",
        );
      }
      spans.push([byteStart, byteEnd, result]);
    }
    spans.sort((a, b) => (a[0] !== b[0] ? a[0] - b[0] : a[1] - b[1]));
    let lastPatchedEnd: number | undefined;
    for (const [byteStart, byteEnd, result] of spans) {
      const matched = byteSlice(segment.text, byteStart, byteEnd);
      findings.push({
        category: `pii.presidio.${result.entity_type.toLowerCase()}`,
        severity: "high",
        confidence: result.score,
        byte_start: byteStart,
        byte_end: byteEnd,
        segment_id: segment.segment_id,
        fingerprint: hmacEvidenceFingerprint(this.config.fingerprintKey, matched),
        matched_text: null,
        attributes: {},
      });
      const overlaps = lastPatchedEnd !== undefined && byteStart < lastPatchedEnd;
      if (isMutableTextSegment(segment) && !overlaps) {
        lastPatchedEnd = byteEnd;
        patches.push({
          segment_id: segment.segment_id,
          expected_fingerprint: segment.fingerprint,
          protocol_location: segment.protocol_location,
          byte_start: byteStart,
          byte_end: byteEnd,
          replacement: REDACTION,
        });
      }
    }
  }

  private async evaluateInner(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    const selected = input.segments.filter((s) => this.config.supportedSources.includes(s.source));
    const totalBytes = selected.reduce((acc, s) => acc + byteLen(s.text), 0);
    if (totalBytes > this.config.maxPayloadBytes) {
      throw DetectorError.new(
        "payload_too_large",
        "presidio detector request exceeds configured limit",
      );
    }
    const findings: Finding[] = [];
    const patches: ContentPatch[] = [];
    for (const segment of selected) {
      if (segment.text.length === 0) {
        continue;
      }
      await this.analyzeSegment(segment, deadlineMs, findings, patches);
    }
    return {
      verdict: findings.length === 0 ? "pass" : "fail",
      findings,
      patches,
      detector_version: this.version,
    };
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    this.counters.recordRequest();
    if (Date.now() >= deadlineMs) {
      this.counters.recordFailureNow();
      throw DetectorError.new("timeout", "presidio detector deadline expired before execution");
    }
    return this.counters.recordOutcome(this.evaluateInner(input, deadlineMs));
  }
}
