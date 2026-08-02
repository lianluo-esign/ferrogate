/**
 * Guardrail EVIDENCE — sanitized rows only.
 *
 * `docs/legacy/inventory-policy-core.md`, "Appendix: cross-cutting security
 * invariants to preserve verbatim":
 *
 * > 1. **`matched_text` is never persisted** (guardrails) — only `fingerprint`
 * >    goes to durable evidence; conformance harness asserts the raw value
 * >    never appears in serialized results.
 * > 2. **HMAC-keyed, non-reversible fingerprints** (`hmac-sha256:<hex>`) for
 * >    all secret/PII evidence.
 *
 * The rows built here are therefore a CLOSED, structural vocabulary:
 * verdict / action / enforcement / stage / mode, per-category finding COUNTS,
 * detector version + config digest, latency — plus one keyed
 * `input_fingerprint` over the envelope's per-segment content fingerprints.
 * **No prompt text, no completion text, no matched value, no byte content ever
 * enters an evidence row.** `Finding.matched_text` exists only inside the
 * in-memory decision path and is dropped at this boundary, which is why
 * {@link buildCheckEvidence} takes {@link GuardrailCheckEvaluation} (already
 * projected to counts) rather than the raw `DetectorResult`.
 *
 * Port of `state_quota_and_policy.rs:935 record_guardrail_evaluation`,
 * `:1250 guardrail_envelope_fingerprint` and `:1477 sanitized_guardrail_evidence_token`.
 */
import {
  type AggregateOutcome,
  type DetectorStage,
  hmacSha256,
  toHex,
} from "@ferrogate/guardrails";
import type {
  GuardrailCheckEvaluation,
  GuardrailCheckEvidence,
  GuardrailEvaluationContext,
  GuardrailEvidence,
  GuardrailEvidenceSink,
  GuardrailFindingEvidence,
  GuardrailPolicyRuntime,
  PolicyAction,
} from "./ports.js";

/**
 * `sanitized_guardrail_evidence_token` — a token that is not a short
 * `[A-Za-z0-9._\-/]` string is replaced by a constant, so a hostile detector
 * cannot smuggle content out through a category name or version string.
 */
export function sanitizedEvidenceToken(value: string, fallback: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 64 || !/^[A-Za-z0-9._\-/]+$/.test(trimmed)) {
    return fallback;
  }
  return trimmed;
}

// ---------------------------------------------------------------------------
// The REDACTED excerpt  (#665)
// ---------------------------------------------------------------------------

/**
 * How many findings one check row carries in detail.
 *
 * A detector scanning a large document can produce thousands, and the row is
 * written on every screened request; `findingCount` keeps the TRUE total, so
 * truncating the detail is visibly a truncation rather than a wrong number.
 */
export const MAX_EVIDENCE_FINDINGS = 32;

/** How many mask characters an excerpt shows before it summarises the rest. */
const MAX_EXCERPT_MASK = 40;

/**
 * Build the REDACTED excerpt for one finding.
 *
 * ## Why this is a reconstruction and not a snippet
 *
 * The obvious reading of "store a redacted excerpt" is: take the matched text,
 * blank the middle, keep the edges. That is what most gateways do and it is
 * wrong here, for two reasons that are not stylistic.
 *
 *  1. The cross-cutting invariant this tree preserves verbatim
 *     (`docs/legacy/inventory-policy-core.md`, appendix §1) is that
 *     `matched_text` is NEVER persisted — only a keyed fingerprint. An excerpt
 *     with edges kept is `matched_text` with fewer characters: the first four
 *     bytes of an AWS key identify the key type, and the surrounding words of a
 *     prompt are the prompt.
 *  2. The whole point of #665 is that a BLOCKED request must be investigable.
 *     If investigating it required reading the content that got it blocked,
 *     the evidence table would be a place secrets accumulate and every operator
 *     with `guardrails.evidence.read` would become a holder of them.
 *
 * So the excerpt is built from the finding's STRUCTURE — its category, its
 * segment, its byte range — plus a run of `*` as wide as the match. It answers
 * "a 20-byte AWS access key at bytes 13..33 of the first user message" without
 * answering "which one", which is exactly the split an investigation needs: the
 * WHAT and the WHERE are the operator's business, the value is the customer's.
 *
 * `sanitizedEvidenceToken` is applied to every token that came from a detector,
 * so a hostile or buggy detector cannot smuggle content out through a category
 * name or a segment id.
 */
export function redactedExcerpt(finding: {
  category: string;
  segment_id?: string | null;
  byte_start?: number | null;
  byte_end?: number | null;
}): string {
  const category = sanitizedEvidenceToken(finding.category, "uncategorized");
  const segment = sanitizedEvidenceToken(finding.segment_id ?? "", "unsegmented");
  const start = typeof finding.byte_start === "number" ? finding.byte_start : undefined;
  const end = typeof finding.byte_end === "number" ? finding.byte_end : undefined;

  if (start === undefined || end === undefined || end < start) {
    // A STRUCTURAL finding (a size cap, a JSON-schema violation) has no span.
    // Saying so is the honest excerpt; inventing `0..0` would claim a location.
    return `[${category}] ${segment}:unlocated`;
  }
  const width = end - start;
  const mask = "*".repeat(Math.min(width, MAX_EXCERPT_MASK));
  const overflow = width > MAX_EXCERPT_MASK ? `+${width - MAX_EXCERPT_MASK}` : "";
  return `[${category}] ${segment}:${start}..${end} ${mask}${overflow}`;
}

/** `confidence`, clamped and rounded; `undefined` when the detector gave none. */
function evidenceConfidence(value: number | null | undefined): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  // Clamped rather than trusted: `confidence` reaches here from an external
  // detector's JSON, and a `1e308` in an evidence row breaks every consumer
  // that treats it as a probability.
  return Math.round(Math.min(Math.max(value, 0), 1) * 1_000) / 1_000;
}

/** A detector-supplied fingerprint, only when it is shaped like one. */
function evidenceFingerprint(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  return /^(hmac-)?sha256:[0-9a-f]{8,128}$/.test(value) ? value : undefined;
}

/**
 * Project raw detector findings onto durable evidence.
 *
 * THE boundary. `Finding.matched_text` is read by nothing below this line and
 * has no field to land in; every value that does cross is either a number this
 * function clamped, a token `sanitizedEvidenceToken` accepted, or the mask
 * {@link redactedExcerpt} built.
 */
export function sanitizedFindings(
  findings: readonly {
    category: string;
    severity?: string;
    confidence?: number | null;
    segment_id?: string | null;
    byte_start?: number | null;
    byte_end?: number | null;
    fingerprint?: string | null;
  }[],
): GuardrailFindingEvidence[] {
  return findings.slice(0, MAX_EVIDENCE_FINDINGS).map((finding) => {
    const confidence = evidenceConfidence(finding.confidence);
    const fingerprint = evidenceFingerprint(finding.fingerprint);
    return {
      category: sanitizedEvidenceToken(finding.category, "uncategorized"),
      severity: sanitizedEvidenceToken(finding.severity ?? "", "high"),
      ...(confidence !== undefined ? { confidence } : {}),
      ...(typeof finding.segment_id === "string"
        ? { segmentId: sanitizedEvidenceToken(finding.segment_id, "unsegmented") }
        : {}),
      ...(typeof finding.byte_start === "number" ? { byteStart: finding.byte_start } : {}),
      ...(typeof finding.byte_end === "number" ? { byteEnd: finding.byte_end } : {}),
      ...(fingerprint !== undefined ? { fingerprint } : {}),
      redactedExcerpt: redactedExcerpt(finding),
    };
  });
}

/** `guardrail_evaluation_id` — deterministic per (request, policy@rev, stage). */
export function evaluationId(
  requestId: string,
  policyImmutableId: string,
  stage: DetectorStage,
): string {
  return `${requestId}/${policyImmutableId}/${stage}`;
}

/**
 * `guardrail_envelope_fingerprint` (`state_quota_and_policy.rs:1250`).
 *
 * HMAC over `tenant \0 protocol \0 stage (\0 segment_fingerprint)*`. The segment
 * fingerprints are themselves `sha256:<hex>` of the content, so the evidence row
 * is two hashes removed from any plaintext. With no key configured the Rust
 * returned the literal `hmac-sha256:unavailable` rather than an unkeyed digest —
 * reproduced verbatim, because an unkeyed digest of a short prompt IS reversible.
 */
export function envelopeFingerprint(
  context: Pick<GuardrailEvaluationContext, "envelope" | "tenant">,
  key: Uint8Array | undefined,
): string {
  if (key === undefined || key.byteLength === 0) {
    return "hmac-sha256:unavailable";
  }
  const encoder = new TextEncoder();
  const parts: Uint8Array[] = [
    encoder.encode(context.tenant.organizationId ?? "platform"),
    new Uint8Array([0]),
    encoder.encode(context.envelope.protocol),
    new Uint8Array([0]),
    encoder.encode(context.envelope.stage),
  ];
  for (const segment of context.envelope.segments) {
    parts.push(new Uint8Array([0]), encoder.encode(segment.fingerprint));
  }
  let total = 0;
  for (const part of parts) {
    total += part.byteLength;
  }
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.byteLength;
  }
  return `hmac-sha256:${toHex(hmacSha256(key, message))}`;
}

/** `guardrail_evidence_action` — the action label when no candidate was built. */
export function evidenceAction(actions: readonly PolicyAction[]): string {
  for (const action of actions) {
    if (action.kind === "block" || action.kind === "require_approval") {
      return "block";
    }
    if (action.kind === "redact" || action.kind === "quarantine") {
      return "redact";
    }
  }
  return actions.some((action) => action.kind === "record") ? "record" : "allow";
}

/** `guardrail_evidence_scope` — the most specific declared tenancy dimension. */
function evidenceScope(tenant: GuardrailEvaluationContext["tenant"]): {
  scopeType: string;
  scopeId?: string;
} {
  if (tenant.apiKeyId !== undefined) return { scopeType: "api_key", scopeId: tenant.apiKeyId };
  if (tenant.projectId !== undefined) return { scopeType: "project", scopeId: tenant.projectId };
  if (tenant.workspaceId !== undefined) {
    return { scopeType: "workspace", scopeId: tenant.workspaceId };
  }
  if (tenant.organizationId !== undefined) {
    return { scopeType: "organization", scopeId: tenant.organizationId };
  }
  return { scopeType: "platform" };
}

export interface BuildEvaluationEvidenceArgs {
  readonly id: string;
  readonly context: GuardrailEvaluationContext;
  readonly policy: GuardrailPolicyRuntime;
  readonly stage: DetectorStage;
  readonly aggregate: AggregateOutcome;
  readonly action: string;
  readonly enforcementStatus: string;
  readonly evaluations: readonly GuardrailCheckEvaluation[];
  readonly latencyMs: number;
  readonly applied: boolean;
  readonly hmacKey?: Uint8Array | undefined;
  readonly nowUnix: number;
}

export function buildEvaluationEvidence(args: BuildEvaluationEvidenceArgs): GuardrailEvidence {
  const findingCategoryCounts: Record<string, number> = {};
  let findingCount = 0;
  for (const evaluation of args.evaluations) {
    findingCount += evaluation.findingCount;
    for (const [category, count] of Object.entries(evaluation.findingCategoryCounts)) {
      findingCategoryCounts[category] = (findingCategoryCounts[category] ?? 0) + count;
    }
  }
  const scope = evidenceScope(args.context.tenant);
  const target = [args.context.model, args.context.provider]
    .filter((value): value is string => value !== undefined)
    .join("/");
  return {
    id: args.id,
    requestId: args.context.requestId,
    ...(args.context.traceId !== undefined ? { traceId: args.context.traceId } : {}),
    ...(args.context.agentRunId !== undefined ? { agentRunId: args.context.agentRunId } : {}),
    ...(args.context.actorApiKeyId !== undefined ? { subjectId: args.context.actorApiKeyId } : {}),
    tenant: args.context.tenant,
    scopeType: scope.scopeType,
    ...(scope.scopeId !== undefined ? { scopeId: scope.scopeId } : {}),
    target: target.length > 0 ? target : "unspecified",
    protocol: args.context.envelope.protocol,
    stage: args.stage,
    mode: args.policy.revision.mode,
    policyId: args.policy.revision.policy_id,
    policyRevision: args.policy.revision.revision,
    verdict: args.aggregate,
    action: args.action,
    enforcementStatus: args.enforcementStatus,
    latencyMs: args.latencyMs,
    findingCategoryCounts,
    findingCount,
    transformed: args.applied && args.action === "redact" && args.aggregate === "fail",
    inputFingerprint: envelopeFingerprint(args.context, args.hmacKey),
    occurredAtUnix: args.nowUnix,
    ...(args.context.actionFingerprint !== undefined
      ? { actionFingerprint: args.context.actionFingerprint }
      : {}),
  };
}

export interface BuildCheckEvidenceArgs {
  readonly evaluationId: string;
  readonly policy: GuardrailPolicyRuntime;
  readonly stage: DetectorStage;
  readonly action: string;
  readonly enforcementStatus: string;
  readonly evaluations: readonly GuardrailCheckEvaluation[];
  readonly candidateCheckId?: string | undefined;
  readonly aggregate: AggregateOutcome;
  readonly applied: boolean;
  /** `[verdict, error_kind]` for a check that never executed. */
  readonly syntheticCheck?: readonly [string, string] | undefined;
}

export function buildCheckEvidence(
  args: BuildCheckEvidenceArgs,
): readonly GuardrailCheckEvidence[] {
  if (args.syntheticCheck !== undefined) {
    const [verdict, errorKind] = args.syntheticCheck;
    return args.policy.checks
      .filter((check) => check.enabled && check.stage === args.stage)
      .map((check) => ({
        id: `${args.evaluationId}/${check.id}`,
        evaluationId: args.evaluationId,
        checkId: check.id,
        detectorId: check.detectorId,
        detectorVersion: "not_executed",
        configDigest: check.detectorConfigDigest,
        verdict: verdict as GuardrailCheckEvidence["verdict"],
        action: args.action,
        enforcementStatus: args.enforcementStatus,
        latencyMs: 0,
        findingCategoryCounts: {},
        findingCount: 0,
        // A check that never executed found nothing, and an empty array says
        // exactly that. It is not the same as a check that ran and matched
        // nothing — `verdict` carries that distinction.
        findings: [],
        transformed: false,
        usedFallback: false,
        errorKind: sanitizedEvidenceToken(errorKind, "streaming_error"),
      }));
  }
  return args.evaluations.map((evaluation) => {
    const runtime = args.policy.checks.find((check) => check.id === evaluation.checkId);
    return {
      id: `${args.evaluationId}/${evaluation.checkId}`,
      evaluationId: args.evaluationId,
      checkId: evaluation.checkId,
      detectorId: runtime?.detectorId ?? "unknown",
      detectorVersion: evaluation.detectorVersion,
      configDigest: runtime?.detectorConfigDigest ?? "sha256:unknown",
      verdict: evaluation.outcome,
      action: args.action,
      enforcementStatus: args.enforcementStatus,
      latencyMs: evaluation.latencyMs,
      findingCategoryCounts: evaluation.findingCategoryCounts,
      findingCount: evaluation.findingCount,
      findings: evaluation.findings,
      transformed:
        args.applied &&
        args.action === "redact" &&
        args.candidateCheckId === evaluation.checkId &&
        evaluation.outcome === "fail",
      usedFallback: evaluation.usedFallback,
      ...(evaluation.detectorError !== undefined
        ? { errorKind: evaluation.detectorError.kind }
        : {}),
    };
  });
}

/**
 * Bounded in-isolate evidence sink.
 *
 * The Rust guarded persistence with a semaphore and **failed closed when the
 * permit could not be acquired** (`state_quota_and_policy.rs:1094-1105`:
 * "guardrail evaluation persistence queue is full; failing closed" → returns
 * `false`). Reproduced here: once `capacity` rows are buffered, `append`
 * returns `false` and the engine converts the request into
 * `guardrail_evidence_unavailable`.
 *
 * PORT-TODO(P: inventory-data-billing §guardrail_evaluations): durable evidence is
 * D1 (`guardrail_evaluations` + `guardrail_check_evaluations`); the Postgres
 * RLS scoping is replaced by per-tenant database separation. This sink is the
 * offline/local implementation and the one the suite asserts non-persistence
 * against.
 *
 * Blocked on the SCHEMA, not on the platform, and the schema is OUTSIDE this
 * app: both tables exist only in the legacy Postgres DDL
 * (`sql/001_init_postgres.sql:454`) and have not been translated into either D1
 * migration (`sql/d1-ts/{tenant,control}` carry the guardrail POLICY tables —
 * which `./d1.ts` now reads — but no evaluation tables). `sql/d1-ts/**` and
 * `packages/storage` are not this agent's to edit, so writing the sink here
 * would mean writing INSERTs against tables no migration creates: every append
 * would reject, and because the sink fails CLOSED on a refused append
 * (`guardrail_evidence_unavailable`) that would take every screened request
 * down. Hence the marker rather than a half-landing.
 *
 * The choice of database is a real decision the slice has to make, not a copy:
 * evidence is per-tenant append-only, so it belongs in the TENANT database
 * (split rule (a)), unlike the policy tables, which are control-plane authored
 * and live in CONTROL.
 */
export class InMemoryGuardrailEvidenceSink implements GuardrailEvidenceSink {
  readonly #evaluations: GuardrailEvidence[] = [];
  readonly #checks: GuardrailCheckEvidence[] = [];
  readonly #capacity: number;

  constructor(capacity = 1024) {
    this.#capacity = capacity;
  }

  /**
   * UPSERT by `evaluation.id`. `guardrail_evaluation_id` is deterministic per
   * `(request_id, policy@revision, stage)`, so a second write for the same id is
   * the same logical row — which is what makes INCREMENTAL streaming screening
   * (one engine call per SSE frame, `stream.ts`) produce ONE evidence row per
   * policy instead of one per frame. The last write wins, i.e. the row records
   * the frame that actually decided the stream.
   */
  append(evaluation: GuardrailEvidence, checks: readonly GuardrailCheckEvidence[]): boolean {
    const existing = this.#evaluations.findIndex((row) => row.id === evaluation.id);
    if (existing >= 0) {
      this.#evaluations[existing] = evaluation;
      for (let i = this.#checks.length - 1; i >= 0; i -= 1) {
        if (this.#checks[i]?.evaluationId === evaluation.id) {
          this.#checks.splice(i, 1);
        }
      }
      this.#checks.push(...checks);
      return true;
    }
    if (this.#evaluations.length >= this.#capacity) {
      return false;
    }
    this.#evaluations.push(evaluation);
    this.#checks.push(...checks);
    return true;
  }

  evaluations(): readonly GuardrailEvidence[] {
    return this.#evaluations;
  }

  checks(): readonly GuardrailCheckEvidence[] {
    return this.#checks;
  }

  /** Everything this sink would durably write, as one serialized blob. */
  serialized(): string {
    return JSON.stringify({ evaluations: this.#evaluations, checks: this.#checks });
  }
}

/** An evidence sink that always refuses — drives the fail-closed branch. */
export const unavailableEvidenceSink: GuardrailEvidenceSink = {
  append: () => false,
};
