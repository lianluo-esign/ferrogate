/**
 * Typed detector contract — port of `ferrogate-guardrails::contract`.
 *
 * Stages, detector input, descriptors, verdicts, findings, patches, the error
 * taxonomy, health counters, the `GuardrailDetector` interface, and the
 * redacting `DetectorSecret` wrapper. Every snake_case serde enum maps to a Zod
 * `z.enum([...])`; JSON-valued fields (`attributes`) map to `jsonValueSchema`.
 *
 * Security invariants preserved verbatim (inventory appendix):
 *  - `matched_text` is kept ONLY in the in-memory decision path and must NEVER
 *    be persisted as evidence; `fingerprint` is the keyed, non-reversible id.
 *  - `DetectorSecret` redacts under `toJSON`/`console`/`String` so a secret can
 *    never leak through logs.
 */

import { type JsonValue, jsonValueSchema } from "@ferrogate/core";
import { z } from "zod";
import type { ContentSegment, ContentSource, GuardrailProtocol } from "./envelope.js";

/** Contract version echoed in the `custom_http` request body. */
export const CONTRACT_VERSION = 1;

/** Hard ceiling on any detector timeout: 30 seconds, in milliseconds. */
export const MAX_DETECTOR_TIMEOUT_MS = 30_000;

export const detectorStageSchema = z.enum(["request", "response"]);
export type DetectorStage = z.infer<typeof detectorStageSchema>;

/** Tenant attribution carried into a detector call (borrowed strs in Rust). */
export interface DetectorTenant {
  organization_id?: string;
  team_id?: string;
  project_id?: string;
  user_id?: string;
  api_key_id?: string;
}

/** The full input handed to `GuardrailDetector.evaluate`. */
export interface DetectorInput {
  protocol: GuardrailProtocol;
  stage: DetectorStage;
  tenant: DetectorTenant;
  model?: string;
  provider?: string;
  text: string;
  segments: ContentSegment[];
}

export const detectorCredentialTypeSchema = z.enum(["none", "bearer_token"]);
export type DetectorCredentialType = z.infer<typeof detectorCredentialTypeSchema>;

export const dataResidencySchema = z.enum(["in_repo", "provider_saas", "customer_vpc"]);
export type DataResidency = z.infer<typeof dataResidencySchema>;

export const detectorVerdictSchema = z.enum(["pass", "fail"]);
export type DetectorVerdict = z.infer<typeof detectorVerdictSchema>;

/** Ordered least→most severe; `high` is the serde `#[default]`. */
export const findingSeveritySchema = z.enum(["info", "low", "medium", "high", "critical"]);
export type FindingSeverity = z.infer<typeof findingSeveritySchema>;
export const DEFAULT_FINDING_SEVERITY: FindingSeverity = "high";

export const detectorErrorKindSchema = z.enum([
  "timeout",
  "unavailable",
  "invalid_response",
  "overloaded",
  "unauthorized",
  "payload_too_large",
  "circuit_open",
  "invalid_configuration",
  "invalid_patch",
  "stale_patch",
  "protected_path",
  "internal",
]);
export type DetectorErrorKind = z.infer<typeof detectorErrorKindSchema>;

/**
 * A single detector finding. `attributes` is arbitrary JSON. `matched_text` is
 * the non-persisted in-memory redaction hint; `fingerprint` is the keyed
 * `hmac-sha256:<hex>` evidence id.
 */
export const findingSchema = z.object({
  category: z.string(),
  severity: findingSeveritySchema.default(DEFAULT_FINDING_SEVERITY),
  confidence: z.number().nullable().optional(),
  byte_start: z.number().int().nonnegative().nullable().optional(),
  byte_end: z.number().int().nonnegative().nullable().optional(),
  segment_id: z.string().nullable().optional(),
  fingerprint: z.string().nullable().optional(),
  matched_text: z.string().nullable().optional(),
  attributes: z.record(jsonValueSchema).default({}),
});
export type Finding = {
  category: string;
  severity: FindingSeverity;
  confidence?: number | null;
  byte_start?: number | null;
  byte_end?: number | null;
  segment_id?: string | null;
  fingerprint?: string | null;
  matched_text?: string | null;
  attributes: Record<string, JsonValue>;
};

export const contentPatchSchema = z.object({
  segment_id: z.string(),
  expected_fingerprint: z.string(),
  protocol_location: z.string(),
  byte_start: z.number().int().nonnegative(),
  byte_end: z.number().int().nonnegative(),
  replacement: z.string(),
});
export type ContentPatch = z.infer<typeof contentPatchSchema>;

export const detectorResultSchema = z.object({
  verdict: detectorVerdictSchema,
  findings: z.array(findingSchema).default([]),
  patches: z.array(contentPatchSchema).default([]),
  detector_version: z.string(),
});
export type DetectorResult = {
  verdict: DetectorVerdict;
  findings: Finding[];
  patches: ContentPatch[];
  detector_version: string;
};

/** First non-null `matched_text` across the findings (in-memory only). */
export function firstMatchedText(result: DetectorResult): string | undefined {
  for (const finding of result.findings) {
    if (finding.matched_text != null) {
      return finding.matched_text;
    }
  }
  return undefined;
}

export interface DetectorDescriptor {
  id: string;
  version: string;
  supports_request: boolean;
  supports_response: boolean;
  supports_transform: boolean;
  supported_sources: ContentSource[];
  credential: DetectorCredentialType;
  data_residency: DataResidency;
  max_payload_bytes: number;
  declared_failure_modes: DetectorErrorKind[];
}

export interface DetectorHealth {
  circuit_open: boolean;
  consecutive_failures: number;
  in_flight: number;
  request_total: number;
  success_total: number;
  failure_total: number;
}

/**
 * The boundary error. `safeMessage()` returns the operator-safe text.
 *  - `affectsCircuit`: Timeout | Unavailable | InvalidResponse | Overloaded.
 *  - `retriable`:      Timeout | Unavailable | Overloaded.
 */
export class DetectorError extends Error {
  readonly kind: DetectorErrorKind;

  constructor(kind: DetectorErrorKind, message: string) {
    super(message);
    this.name = "DetectorError";
    this.kind = kind;
  }

  static new(kind: DetectorErrorKind, message: string): DetectorError {
    return new DetectorError(kind, message);
  }

  safeMessage(): string {
    return this.message;
  }

  affectsCircuit(): boolean {
    return (
      this.kind === "timeout" ||
      this.kind === "unavailable" ||
      this.kind === "invalid_response" ||
      this.kind === "overloaded"
    );
  }

  retriable(): boolean {
    return this.kind === "timeout" || this.kind === "unavailable" || this.kind === "overloaded";
  }
}

/**
 * The detector interface (Rust `#[async_trait] trait GuardrailDetector`).
 * `deadline` is an absolute epoch-millis instant (the TS twin of `Instant`);
 * an already-passed deadline yields a `timeout` error.
 */
export interface GuardrailDetector {
  descriptor(): DetectorDescriptor;
  health(): DetectorHealth;
  evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult>;
}

/** Re-exported for callers that only import the contract surface. */
export type { ContentSegment, ContentSource, GuardrailProtocol };

/**
 * A redacting secret wrapper. `toString`/`toJSON` print `<redacted>`; `expose()`
 * and `asBytes()` reveal the value only where an authenticated call needs it.
 */
export class DetectorSecret {
  #value: string;

  constructor(value: string) {
    this.#value = value;
  }

  static new(value: string): DetectorSecret {
    return new DetectorSecret(value);
  }

  expose(): string {
    return this.#value;
  }

  asBytes(): Uint8Array {
    return new TextEncoder().encode(this.#value);
  }

  toString(): string {
    return "<redacted>";
  }

  toJSON(): string {
    return "<redacted>";
  }
}
