/**
 * Shared fixtures for the guardrail request-path suite.
 *
 * Every policy here is a REAL `PolicyRevision` that passes
 * `validatePolicyRevision`, and every detector is a REAL detector from
 * `@ferrogate/guardrails` (or, for the timeout/error cases, a scripted
 * `GuardrailDetector` that throws the exact `DetectorError` a hung upstream
 * would). Nothing about a detector is stubbed to a convenient verdict.
 */
import {
  type ContentSource,
  DetectorError,
  type GuardrailDetector,
  PROBE_SECRET,
  type PolicyRevision,
  policyRevisionSchema,
} from "@ferrogate/guardrails";
import {
  type GuardrailEvaluationContext,
  type GuardrailPolicyRuntime,
  compilePolicyChecks,
  policySourceFromRuntimes,
} from "../../src/guardrails/index.js";

export { PROBE_SECRET };

/** The keyed-evidence secret every fingerprinting detector resolves. */
export const FINGERPRINT_SECRET_REF = "GUARDRAIL_FINGERPRINT_KEY";
export const TEST_SECRETS = (ref: string): string | undefined =>
  ref === FINGERPRINT_SECRET_REF ? "test-fingerprint-key" : undefined;

export const EVIDENCE_HMAC_KEY = new TextEncoder().encode("test-evidence-key");

/** A canonical scope selector that matches everything. */
const OPEN_SCOPE: Record<string, string[]> = {
  tenant_ids: [],
  organization_ids: [],
  project_ids: [],
  workspace_ids: [],
  api_key_ids: [],
  service_account_ids: [],
  gateway_config_ids: [],
  models: [],
  providers: [],
};

export interface PolicyOverrides {
  readonly policyId?: string;
  readonly stage?: "request" | "response";
  readonly mode?: "enforce" | "shadow";
  readonly streaming?: "buffer_and_enforce" | "shadow_after_complete" | "reject_streaming";
  readonly onFail?: PolicyRevision["on_fail"];
  readonly onError?: PolicyRevision["on_error"];
  readonly detector?: PolicyRevision["checks"][number]["detector"];
  readonly deadlineMs?: number;
  readonly scope?: Partial<typeof OPEN_SCOPE>;
  /**
   * The content sources this check selects. Defaults to the six a chat body
   * carries. Overridden by #703's transcript-egress policy, which screens
   * `text_attachment` — the trust class a transcription's answer belongs to,
   * since whoever supplied the audio chose every word of it.
   */
  readonly sources?: readonly ContentSource[];
}

/** A one-check policy over the deterministic secret scanner. */
export function secretScanPolicy(overrides: PolicyOverrides = {}): PolicyRevision {
  return policyRevisionSchema.parse({
    policy_id: overrides.policyId ?? "secret-scan",
    revision: 1,
    name: "secret scan",
    enforced: true,
    scope: { ...OPEN_SCOPE, ...(overrides.scope ?? {}) },
    checks: [
      {
        id: "deterministic",
        enabled: true,
        stage: overrides.stage ?? "request",
        sources: overrides.sources ?? [
          "system",
          "developer",
          "user",
          "assistant",
          "tool_arguments",
          "tool_result",
        ],
        detector: overrides.detector ?? {
          kind: "local",
          keywords: ["FERROGATE-GUARDRAIL-PROBE"],
          regex: [],
          secret_patterns: ["aws_access_key_id", "open_ai_api_key"],
          fingerprint_secret_ref: FINGERPRINT_SECRET_REF,
        },
      },
    ],
    aggregation: { type: "all" },
    execution: "sequential",
    mode: overrides.mode ?? "enforce",
    streaming: overrides.streaming ?? "buffer_and_enforce",
    on_pass: [{ kind: "allow" }],
    on_fail: overrides.onFail ?? [
      { kind: "block", code: "guardrail_blocked", message: "request blocked by guardrail policy" },
    ],
    on_error: overrides.onError ?? [
      {
        kind: "block",
        code: "guardrail_provider_unavailable",
        message: "guardrail detector for rule 'secret scan' failed",
      },
    ],
    deadline_ms: overrides.deadlineMs ?? 2000,
    created_at_unix: 0,
    created_by: "test",
  }) as PolicyRevision;
}

/** Compile a revision into a runtime, optionally substituting the detector. */
export function runtimeFor(
  revision: PolicyRevision,
  detectorOverrides: Record<string, GuardrailDetector> = {},
): GuardrailPolicyRuntime {
  return {
    revision,
    checks: compilePolicyChecks(revision, {
      secrets: TEST_SECRETS,
      detectorOverrides,
    }),
  };
}

export function sourceFor(
  revision: PolicyRevision,
  detectorOverrides: Record<string, GuardrailDetector> = {},
): ReturnType<typeof policySourceFromRuntimes> {
  return policySourceFromRuntimes([runtimeFor(revision, detectorOverrides)]);
}

/** A detector that always throws the given `DetectorError` kind. */
export function failingDetector(
  kind: Parameters<typeof DetectorError.new>[0],
  message = "scripted detector failure",
): GuardrailDetector {
  return {
    descriptor: () => ({
      id: "scripted",
      version: "scripted-1",
      supports_request: true,
      supports_response: true,
      supports_transform: false,
      supported_sources: ["user", "assistant"],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: 1024,
      declared_failure_modes: ["timeout", "unavailable"],
    }),
    health: () => ({
      circuit_open: false,
      consecutive_failures: 1,
      in_flight: 0,
      request_total: 1,
      success_total: 0,
      failure_total: 1,
    }),
    evaluate: () => Promise.reject(DetectorError.new(kind, message)),
  };
}

/**
 * A detector that respects the deadline the way a real one does: it resolves
 * only after `delayMs`, and raises `timeout` when the deadline has passed.
 * Drives the REAL timeout path rather than pre-baking a rejection.
 */
export function slowDetector(delayMs: number): GuardrailDetector {
  const base = failingDetector("timeout");
  return {
    ...base,
    evaluate: async (_input, deadlineMs) => {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (Date.now() >= deadlineMs) {
        throw DetectorError.new("timeout", "guardrail detector deadline exceeded");
      }
      return { verdict: "pass", findings: [], patches: [], detector_version: "scripted-1" };
    },
  };
}

/** A minimal evaluation context for a chat request. */
export function chatContext(
  overrides: Partial<GuardrailEvaluationContext> & Pick<GuardrailEvaluationContext, "envelope">,
): GuardrailEvaluationContext {
  return {
    requestId: "fg-0000000000000001",
    tenant: { organizationId: "tenant_a", apiKeyId: "key_tools" },
    actorApiKeyId: "key_tools",
    model: "gpt-4o",
    provider: "openai",
    streaming: false,
    ...overrides,
  };
}

/** An OpenAI chat request body carrying the synthetic AWS probe secret. */
export function bodyWithProbeSecret(): Record<string, unknown> {
  return {
    model: "gpt-4o",
    messages: [{ role: "user", content: `please store ${PROBE_SECRET} for me` }],
  };
}

/** A clean OpenAI chat request body. */
export function cleanBody(): Record<string, unknown> {
  return { model: "gpt-4o", messages: [{ role: "user", content: "hello there" }] };
}
