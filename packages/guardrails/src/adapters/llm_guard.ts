/**
 * ProtectAI LLM-Guard prompt-injection adapter — port of
 * `ferrogate-guardrails::adapters::llm_guard`.
 *
 * Speaks `POST /analyze/prompt` against a customer-VPC self-hosted deployment.
 * The scanner classifies whole prompts and returns no spans, so this adapter is
 * DETECT-ONLY (`supports_transform: false`): a hit denies/records, never redacts.
 * Hit iff `!is_valid || scanners["PromptInjection"] >= threshold`.
 */

import { TIMED_OUT, withTimeout } from "../async.js";
import { byteLen } from "../bytes.js";
import {
  type ContentSource,
  type DetectorDescriptor,
  DetectorError,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type DetectorSecret,
  type GuardrailDetector,
  MAX_DETECTOR_TIMEOUT_MS,
} from "../contract.js";
import { validateCustomHttpEndpoint } from "../custom_http.js";
import {
  AdapterCounters,
  type DetectorTransport,
  HttpJsonTransport,
  adapterStatusError,
  configDigest,
  hmacEvidenceFingerprint,
  nativeAdapterFailureModes,
} from "./transport.js";

const LLM_GUARD_ADAPTER_VERSION = "llm-guard-prompt-injection-adapter/1";
const PROMPT_INJECTION_SCANNER = "PromptInjection";

export interface LlmGuardPromptInjectionConfig {
  id: string;
  endpoint: string;
  scoreThresholdPercent: number;
  timeoutMs: number;
  maxPayloadBytes: number;
  maxResponseBytes: number;
  allowPrivateNetwork: boolean;
  supportedSources: ContentSource[];
  bearerToken?: DetectorSecret;
  fingerprintKey: DetectorSecret;
}

interface AnalyzePromptResponse {
  is_valid: boolean;
  scanners?: Record<string, number>;
  sanitized_prompt?: string | null;
}

function validateConfig(config: LlmGuardPromptInjectionConfig): URL {
  let endpoint: URL;
  try {
    endpoint = new URL(config.endpoint);
  } catch {
    throw DetectorError.new(
      "invalid_configuration",
      "llm-guard detector endpoint is not a valid URL",
    );
  }
  validateCustomHttpEndpoint(endpoint, config.allowPrivateNetwork);
  if (
    config.id.trim().length === 0 ||
    config.scoreThresholdPercent > 100 ||
    config.timeoutMs === 0 ||
    config.timeoutMs > MAX_DETECTOR_TIMEOUT_MS ||
    config.maxPayloadBytes === 0 ||
    config.maxResponseBytes === 0 ||
    config.supportedSources.length === 0 ||
    new Set(config.supportedSources).size !== config.supportedSources.length
  ) {
    throw DetectorError.new(
      "invalid_configuration",
      "llm-guard detector id, threshold, limits, or sources are invalid",
    );
  }
  return endpoint;
}

export class LlmGuardPromptInjectionDetector implements GuardrailDetector {
  private config: LlmGuardPromptInjectionConfig;
  private transport: DetectorTransport;
  private version: string;
  private counters = new AdapterCounters();

  private constructor(
    config: LlmGuardPromptInjectionConfig,
    transport: DetectorTransport,
    version: string,
  ) {
    this.config = config;
    this.transport = transport;
    this.version = version;
  }

  static new(config: LlmGuardPromptInjectionConfig): LlmGuardPromptInjectionDetector {
    const endpoint = validateConfig(config);
    const transport = HttpJsonTransport.build(
      endpoint,
      config.timeoutMs,
      config.allowPrivateNetwork,
      config.bearerToken,
      config.maxResponseBytes,
    );
    return LlmGuardPromptInjectionDetector.withTransport(config, transport);
  }

  static withTransport(
    config: LlmGuardPromptInjectionConfig,
    transport: DetectorTransport,
  ): LlmGuardPromptInjectionDetector {
    validateConfig(config);
    const digest = configDigest([String(config.scoreThresholdPercent)]);
    return new LlmGuardPromptInjectionDetector(
      config,
      transport,
      `${LLM_GUARD_ADAPTER_VERSION}+cfg.${digest}`,
    );
  }

  private passResult(): DetectorResult {
    return { verdict: "pass", findings: [], patches: [], detector_version: this.version };
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.config.id,
      version: this.version,
      supports_request: true,
      supports_response: true,
      supports_transform: false,
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

  private async evaluateInner(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    const projected = input.segments
      .filter((s) => this.config.supportedSources.includes(s.source))
      .map((s) => s.text)
      .join("\n");
    if (byteLen(projected) > this.config.maxPayloadBytes) {
      throw DetectorError.new(
        "payload_too_large",
        "llm-guard detector request exceeds configured limit",
      );
    }
    if (projected.length === 0) {
      return this.passResult();
    }
    const body = new TextEncoder().encode(JSON.stringify({ prompt: projected }));
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw DetectorError.new("timeout", "llm-guard detector deadline expired");
    }
    const attemptTimeout = Math.min(remaining, this.config.timeoutMs);
    const raced = await withTimeout(this.transport.postJson(body), attemptTimeout);
    if (raced === TIMED_OUT) {
      throw DetectorError.new("timeout", "llm-guard detector request timed out");
    }
    if (raced.status !== 200) {
      throw adapterStatusError(raced.status);
    }
    let response: AnalyzePromptResponse;
    try {
      response = JSON.parse(new TextDecoder().decode(raced.body)) as AnalyzePromptResponse;
      if (typeof response.is_valid !== "boolean") {
        throw new Error("missing is_valid");
      }
    } catch {
      throw DetectorError.new(
        "invalid_response",
        "llm-guard detector returned a malformed analyze response",
      );
    }

    const score = response.scanners?.[PROMPT_INJECTION_SCANNER];
    const threshold = this.config.scoreThresholdPercent / 100.0;
    const hit = !response.is_valid || (score !== undefined && score >= threshold);
    if (!hit) {
      return this.passResult();
    }
    return {
      verdict: "fail",
      findings: [
        {
          category: "prompt_injection.llm_guard",
          severity: "high",
          confidence: score ?? null,
          byte_start: null,
          byte_end: null,
          segment_id: null,
          fingerprint: hmacEvidenceFingerprint(this.config.fingerprintKey, projected),
          matched_text: null,
          attributes: {},
        },
      ],
      patches: [],
      detector_version: this.version,
    };
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    this.counters.recordRequest();
    if (Date.now() >= deadlineMs) {
      this.counters.recordFailureNow();
      throw DetectorError.new("timeout", "llm-guard detector deadline expired before execution");
    }
    return this.counters.recordOutcome(this.evaluateInner(input, deadlineMs));
  }
}
