/**
 * Deterministic in-repo guardrail detector — port of
 * `ferrogate-guardrails::deterministic`.
 *
 * No backend, transform-capable. Runs keyword / regex / built-in-secret matchers
 * plus JSON-schema/pointer and request-constraint checks, emitting sanitized
 * findings and non-overlapping redaction patches. Offsets are UTF-8 byte offsets.
 *
 * Faithful behaviors preserved:
 *  - Coalesced same-source group scan (catches a token split across adjacent
 *    parts) PLUS a per-segment scan (restores `\b`/`^` anchor context); both
 *    funnel through `addTextMatch`, which dedupes by
 *    `(category, segment_id, byte_start, byte_end)` and keeps patches
 *    non-overlapping per segment.
 *  - Bounded evidence: after `MAX_FINDINGS_PER_EVALUATION` findings, stop and
 *    emit ONE zero-width `detector.truncated` (Critical) finding with no covering
 *    patch → forces fail-closed (unredactable).
 *  - Secrets are Critical (conf 0.99); keyword/regex are High (conf 1.0);
 *    fingerprints are keyed `hmac-sha256:<hex>`; `matched_text` is never set.
 */
import { z } from "zod";
import { byteLen, byteMatchIndices, byteOffsetMap, byteSlice } from "./bytes.js";
import { hmacSha256, toHex } from "./hash.js";
import { evaluateSchema, isValidSchema, jsonPointerExists, resolveJsonPointer } from "./jsonschema.js";
import {
  DetectorError,
  DetectorSecret,
  type ContentPatch,
  type DetectorDescriptor,
  type DetectorHealth,
  type DetectorInput,
  type DetectorResult,
  type Finding,
  type FindingSeverity,
  type GuardrailDetector,
} from "./contract.js";
import {
  guardrailProtocolSchema,
  type ContentSegment,
  type ContentSource,
  type GuardrailProtocol,
} from "./envelope.js";

const DETERMINISTIC_VERSION = "deterministic/1";
const REDACTION = "[REDACTED]";

/** Hard cap on findings per evaluate; overflow emits one truncation marker. */
export const MAX_FINDINGS_PER_EVALUATION = 10_000;

export const jsonConstraintsSchema = z
  .object({
    schema: z.unknown().optional(),
    required_keys: z.array(z.string()).default([]),
    forbidden_keys: z.array(z.string()).default([]),
  })
  .strict();
export type JsonConstraints = {
  schema?: unknown;
  required_keys: string[];
  forbidden_keys: string[];
};

export function jsonConstraintsIsEmpty(c: JsonConstraints): boolean {
  return c.schema === undefined && c.required_keys.length === 0 && c.forbidden_keys.length === 0;
}

export const secretPatternSchema = z.enum(["open_ai_api_key", "github_token", "aws_access_key_id"]);
export type SecretPattern = z.infer<typeof secretPatternSchema>;

function secretCategory(pattern: SecretPattern): string {
  switch (pattern) {
    case "open_ai_api_key":
      return "secret.openai_api_key";
    case "github_token":
      return "secret.github_token";
    case "aws_access_key_id":
      return "secret.aws_access_key_id";
  }
}

function secretExpression(pattern: SecretPattern): string {
  switch (pattern) {
    case "open_ai_api_key":
      return "\\bsk-(?:proj-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})\\b";
    case "github_token":
      return "\\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\\b";
    case "aws_access_key_id":
      return "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b";
  }
}

export const requestConstraintsSchema = z
  .object({
    allowed_endpoints: z.array(guardrailProtocolSchema).default([]),
    allowed_models: z.array(z.string()).default([]),
    forbidden_models: z.array(z.string()).default([]),
    allowed_providers: z.array(z.string()).default([]),
    forbidden_providers: z.array(z.string()).default([]),
    metadata: jsonConstraintsSchema.optional(),
    tool_parameters: jsonConstraintsSchema.optional(),
  })
  .strict();
export type RequestConstraints = {
  allowed_endpoints: GuardrailProtocol[];
  allowed_models: string[];
  forbidden_models: string[];
  allowed_providers: string[];
  forbidden_providers: string[];
  metadata?: JsonConstraints;
  tool_parameters?: JsonConstraints;
};

export function requestConstraintsIsEmpty(c: RequestConstraints): boolean {
  return (
    c.allowed_endpoints.length === 0 &&
    c.allowed_models.length === 0 &&
    c.forbidden_models.length === 0 &&
    c.allowed_providers.length === 0 &&
    c.forbidden_providers.length === 0 &&
    (c.metadata === undefined || jsonConstraintsIsEmpty(c.metadata)) &&
    (c.tool_parameters === undefined || jsonConstraintsIsEmpty(c.tool_parameters))
  );
}

export interface DeterministicDetectorConfig {
  id: string;
  supported_sources: ContentSource[];
  keywords: string[];
  regex: string[];
  max_input_bytes?: number;
  json?: JsonConstraints;
  request?: RequestConstraints;
  secret_patterns: SecretPattern[];
  fingerprint_key?: DetectorSecret;
}

function invalidConfig(message: string): DetectorError {
  return DetectorError.new("invalid_configuration", message);
}

function validateJsonPointers(pointers: string[], name: string): void {
  if (pointers.some((p) => p.length > 0 && !p.startsWith("/"))) {
    const message =
      name === "metadata"
        ? "metadata key constraints must use RFC 6901 JSON pointers"
        : name === "tool_parameters"
          ? "tool parameter key constraints must use RFC 6901 JSON pointers"
          : "JSON key constraints must use RFC 6901 JSON pointers";
    throw invalidConfig(message);
  }
}

function validateJsonConstraints(c: JsonConstraints, name: string): void {
  validateJsonPointers(c.required_keys, name);
  validateJsonPointers(c.forbidden_keys, name);
  if (
    new Set(c.required_keys).size !== c.required_keys.length ||
    new Set(c.forbidden_keys).size !== c.forbidden_keys.length
  ) {
    throw invalidConfig("structured Guardrail key constraints must be unique");
  }
  if (c.schema !== undefined && !isValidSchema(c.schema)) {
    throw invalidConfig("structured Guardrail contains an invalid JSON Schema");
  }
}

function validateRequestConstraints(c: RequestConstraints): void {
  for (const values of [c.allowed_models, c.forbidden_models, c.allowed_providers, c.forbidden_providers]) {
    if (values.some((v) => v.trim().length === 0) || new Set(values).size !== values.length) {
      throw invalidConfig("request Guardrail constraints must be non-empty and unique");
    }
  }
  if (new Set(c.allowed_endpoints).size !== c.allowed_endpoints.length) {
    throw invalidConfig("request Guardrail endpoint constraints must be unique");
  }
  if (c.metadata) {
    validateJsonConstraints(c.metadata, "metadata");
  }
  if (c.tool_parameters) {
    validateJsonConstraints(c.tool_parameters, "tool_parameters");
  }
}

function validateConfig(config: DeterministicDetectorConfig): void {
  if (
    config.id.trim().length === 0 ||
    config.supported_sources.length === 0 ||
    config.keywords.some((k) => k.length === 0) ||
    config.max_input_bytes === 0 ||
    new Set(config.supported_sources).size !== config.supported_sources.length ||
    new Set(config.secret_patterns).size !== config.secret_patterns.length
  ) {
    throw invalidConfig("deterministic Guardrail id, limits, patterns, or sources are invalid");
  }
  if (
    config.keywords.length === 0 &&
    config.regex.length === 0 &&
    config.max_input_bytes === undefined &&
    (config.json === undefined || jsonConstraintsIsEmpty(config.json)) &&
    (config.request === undefined || requestConstraintsIsEmpty(config.request)) &&
    config.secret_patterns.length === 0
  ) {
    throw invalidConfig("deterministic Guardrail requires at least one constraint");
  }
  if (config.secret_patterns.length > 0 && config.fingerprint_key === undefined) {
    throw invalidConfig("secret detection requires fingerprint_secret_ref for keyed evidence");
  }
  if (config.json) {
    validateJsonConstraints(config.json, "json");
  }
  if (config.request) {
    validateRequestConstraints(config.request);
  }
}

interface TextMatch {
  category: string;
  severity: FindingSeverity;
  confidence: number | null;
  start: number;
  end: number;
}

interface CoalescedGroup {
  text: string;
  segments: ContentSegment[];
  starts: number[];
}

/** Whether a segment is a mutable text source eligible for a redaction patch. */
export function isMutableTextSegment(segment: ContentSegment): boolean {
  const mutableSource =
    segment.source === "system" ||
    segment.source === "developer" ||
    segment.source === "user" ||
    segment.source === "assistant" ||
    segment.source === "tool_result" ||
    segment.source === "text_attachment";
  return mutableSource && (segment.content_type === "text" || segment.content_type === "text_attachment");
}

function coalesceSelectedSegments(selected: ContentSegment[]): CoalescedGroup[] {
  const groups: CoalescedGroup[] = [];
  for (const segment of selected) {
    const last = groups[groups.length - 1];
    const extend = last !== undefined && last.segments[last.segments.length - 1]?.source === segment.source;
    const group = extend ? (last as CoalescedGroup) : { text: "", segments: [], starts: [] };
    if (!extend) {
      groups.push(group);
    }
    group.starts.push(byteLen(group.text));
    group.text += segment.text;
    group.segments.push(segment);
  }
  return groups;
}

class TextMatchSink {
  findings: Finding[] = [];
  patches: ContentPatch[] = [];
  seenFindings = new Set<string>();
  patchedIntervals = new Map<string, Array<[number, number]>>();
  truncated = false;
}

/** Regex byte matches over `text`, non-overlapping, mirroring `find_iter`. */
function regexByteMatches(source: string, text: string): Array<[number, number]> {
  const map = byteOffsetMap(text);
  const re = new RegExp(source, "g");
  const out: Array<[number, number]> = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const startUnit = match.index;
    const endUnit = match.index + match[0].length;
    out.push([map[startUnit] as number, map[endUnit] as number]);
    if (match[0].length === 0) {
      re.lastIndex += 1;
    }
  }
  return out;
}

export class DeterministicDetector implements GuardrailDetector {
  private config: DeterministicDetectorConfig;
  private regex: string[];
  private secrets: Array<[SecretPattern, string]>;

  private constructor(config: DeterministicDetectorConfig) {
    this.config = config;
    this.regex = config.regex;
    this.secrets = config.secret_patterns.map((p) => [p, secretExpression(p)]);
  }

  static new(config: DeterministicDetectorConfig): DeterministicDetector {
    validateConfig(config);
    for (const expression of config.regex) {
      try {
        new RegExp(expression, "g");
      } catch {
        throw invalidConfig("local Guardrail contains an invalid regex");
      }
    }
    for (const [, expression] of config.secret_patterns.map((p) => [p, secretExpression(p)] as const)) {
      try {
        new RegExp(expression, "g");
      } catch {
        throw invalidConfig("built-in secret pattern failed to compile");
      }
    }
    return new DeterministicDetector(config);
  }

  descriptor(): DetectorDescriptor {
    return {
      id: this.config.id,
      version: DETERMINISTIC_VERSION,
      supports_request: true,
      supports_response: true,
      supports_transform: true,
      supported_sources: [...this.config.supported_sources],
      credential: "none",
      data_residency: "in_repo",
      max_payload_bytes: this.config.max_input_bytes ?? Number.MAX_SAFE_INTEGER,
      declared_failure_modes: ["timeout", "internal", "invalid_configuration"],
    };
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

  private hmacFingerprint(value: string): string | undefined {
    const key = this.config.fingerprint_key;
    if (!key) {
      return undefined;
    }
    return `hmac-sha256:${toHex(hmacSha256(key.asBytes(), new TextEncoder().encode(value)))}`;
  }

  private finding(
    category: string,
    severity: FindingSeverity,
    confidence: number | null,
    segment: ContentSegment | undefined,
    range: [number, number] | undefined,
    sensitiveValue: string | undefined,
  ): Finding {
    return {
      category,
      severity,
      confidence,
      byte_start: range ? range[0] : null,
      byte_end: range ? range[1] : null,
      segment_id: segment ? segment.segment_id : null,
      fingerprint: sensitiveValue !== undefined ? (this.hmacFingerprint(sensitiveValue) ?? null) : null,
      matched_text: null,
      attributes: {},
    };
  }

  private addTextMatch(sink: TextMatchSink, segment: ContentSegment, detected: TextMatch): void {
    if (sink.truncated) {
      return;
    }
    if (sink.findings.length >= MAX_FINDINGS_PER_EVALUATION) {
      sink.truncated = true;
      sink.findings.push(this.finding("detector.truncated", "critical", 1.0, segment, [0, 0], undefined));
      return;
    }
    const { category, severity, confidence, start, end } = detected;
    const matched = byteSlice(segment.text, start, end);
    const key = `${category} ${segment.segment_id} ${start} ${end}`;
    if (!sink.seenFindings.has(key)) {
      sink.seenFindings.add(key);
      sink.findings.push(this.finding(category, severity, confidence, segment, [start, end], matched));
    }
    if (isMutableTextSegment(segment)) {
      const intervals = sink.patchedIntervals.get(segment.segment_id) ?? [];
      const overlaps = intervals.some(([s, e]) => start < e && s < end);
      if (!overlaps) {
        intervals.push([start, end]);
        sink.patchedIntervals.set(segment.segment_id, intervals);
        sink.patches.push({
          segment_id: segment.segment_id,
          expected_fingerprint: segment.fingerprint,
          protocol_location: segment.protocol_location,
          byte_start: start,
          byte_end: end,
          replacement: REDACTION,
        });
      }
    }
  }

  private addGroupMatch(sink: TextMatchSink, group: CoalescedGroup, detected: TextMatch): void {
    group.segments.forEach((segment, index) => {
      const segmentStart = group.starts[index] as number;
      const segmentEnd = segmentStart + byteLen(segment.text);
      const overlapStart = Math.max(detected.start, segmentStart);
      const overlapEnd = Math.min(detected.end, segmentEnd);
      if (overlapStart < overlapEnd) {
        this.addTextMatch(sink, segment, {
          ...detected,
          start: overlapStart - segmentStart,
          end: overlapEnd - segmentStart,
        });
      }
    });
  }

  async evaluate(input: DetectorInput, deadlineMs: number): Promise<DetectorResult> {
    if (Date.now() >= deadlineMs) {
      throw DetectorError.new("timeout", "deterministic Guardrail deadline expired before execution");
    }
    const selected = input.segments.filter((s) => this.config.supported_sources.includes(s.source));
    const sink = new TextMatchSink();

    if (
      this.config.max_input_bytes !== undefined &&
      selected.reduce((acc, s) => acc + byteLen(s.text), 0) > this.config.max_input_bytes
    ) {
      sink.findings.push(this.finding("size.input_bytes", "high", 1.0, undefined, undefined, undefined));
    }

    for (const group of coalesceSelectedSegments(selected)) {
      for (const keyword of this.config.keywords) {
        for (const start of byteMatchIndices(group.text, keyword)) {
          this.addGroupMatch(sink, group, {
            category: "contains",
            severity: "high",
            confidence: 1.0,
            start,
            end: start + byteLen(keyword),
          });
        }
      }
      for (const expression of this.regex) {
        for (const [start, end] of regexByteMatches(expression, group.text)) {
          this.addGroupMatch(sink, group, { category: "regex", severity: "high", confidence: 1.0, start, end });
        }
      }
      for (const [pattern, expression] of this.secrets) {
        for (const [start, end] of regexByteMatches(expression, group.text)) {
          this.addGroupMatch(sink, group, {
            category: secretCategory(pattern),
            severity: "critical",
            confidence: 0.99,
            start,
            end,
          });
        }
      }
    }

    for (const segment of selected) {
      for (const keyword of this.config.keywords) {
        for (const start of byteMatchIndices(segment.text, keyword)) {
          this.addTextMatch(sink, segment, {
            category: "contains",
            severity: "high",
            confidence: 1.0,
            start,
            end: start + byteLen(keyword),
          });
        }
      }
      for (const expression of this.regex) {
        for (const [start, end] of regexByteMatches(expression, segment.text)) {
          this.addTextMatch(sink, segment, { category: "regex", severity: "high", confidence: 1.0, start, end });
        }
      }
      for (const [pattern, expression] of this.secrets) {
        for (const [start, end] of regexByteMatches(expression, segment.text)) {
          this.addTextMatch(sink, segment, {
            category: secretCategory(pattern),
            severity: "critical",
            confidence: 0.99,
            start,
            end,
          });
        }
      }
    }

    if (this.config.json) {
      for (const segment of selected) {
        this.evaluateJsonSegment(this.config.json, segment, "json", sink.findings);
      }
    }

    if (this.config.request) {
      this.evaluateRequestConstraints(this.config.request, input, selected, sink.findings);
    }

    return {
      verdict: sink.findings.length === 0 ? "pass" : "fail",
      findings: sink.findings,
      patches: sink.patches,
      detector_version: DETERMINISTIC_VERSION,
    };
  }

  private evaluateJsonSegment(
    constraints: JsonConstraints,
    segment: ContentSegment,
    prefix: string,
    findings: Finding[],
  ): void {
    let value: unknown;
    try {
      value = JSON.parse(segment.text);
    } catch {
      findings.push(this.finding(`${prefix}.invalid`, "high", 1.0, segment, undefined, undefined));
      return;
    }
    for (const failure of evaluateJsonConstraints(constraints, value)) {
      findings.push(this.finding(`${prefix}.${failure}`, "high", 1.0, segment, undefined, undefined));
    }
  }

  private evaluateRequestConstraints(
    definition: RequestConstraints,
    input: DetectorInput,
    selected: ContentSegment[],
    findings: Finding[],
  ): void {
    const endpointDenied =
      definition.allowed_endpoints.length > 0 && !definition.allowed_endpoints.includes(input.protocol);
    this.addContextFinding(findings, endpointDenied, "request.endpoint");

    const model = input.model;
    const modelDenied =
      model !== undefined &&
      ((definition.allowed_models.length > 0 && !definition.allowed_models.includes(model)) ||
        definition.forbidden_models.includes(model));
    this.addContextFinding(findings, modelDenied, "request.model");

    const provider = input.provider;
    const providerDenied =
      provider !== undefined &&
      ((definition.allowed_providers.length > 0 && !definition.allowed_providers.includes(provider)) ||
        definition.forbidden_providers.includes(provider));
    this.addContextFinding(findings, providerDenied, "request.provider");

    if (definition.metadata) {
      for (const segment of selected.filter((s) => s.source === "metadata")) {
        this.evaluateJsonSegment(definition.metadata, segment, "metadata", findings);
      }
    }
    if (definition.tool_parameters) {
      for (const segment of selected.filter((s) => s.source === "tool_arguments")) {
        this.evaluateJsonSegment(definition.tool_parameters, segment, "tool_parameters", findings);
      }
    }
  }

  private addContextFinding(findings: Finding[], denied: boolean, category: string): void {
    if (denied) {
      findings.push(this.finding(category, "high", 1.0, undefined, undefined, undefined));
    }
  }
}

function evaluateJsonConstraints(constraints: JsonConstraints, value: unknown): string[] {
  const failures: string[] = [];
  if (constraints.schema !== undefined && !evaluateSchema(constraints.schema, value)) {
    failures.push("json_schema");
  }
  if (constraints.required_keys.some((pointer) => !jsonPointerExists(value, pointer))) {
    failures.push("required_key");
  }
  if (constraints.forbidden_keys.some((pointer) => resolveJsonPointer(value, pointer) !== undefined)) {
    failures.push("forbidden_key");
  }
  return failures;
}
