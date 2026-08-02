/**
 * Guardrail ENFORCEMENT seams for the gateway request path.
 *
 * `@ferrogate/guardrails` owns detector EXECUTION and the immutable policy
 * domain. It deliberately stops short of the gateway: "Policy composition and
 * gateway wiring live elsewhere — this crate only executes one detector at a
 * time and reports a verdict" (`docs/legacy/inventory-policy-core.md` §3.1).
 * *Elsewhere* is here — this directory is the clean-room port of the Rust
 * enforcement chokepoint:
 *
 * | this module                    | Rust                                                         |
 * |--------------------------------|--------------------------------------------------------------|
 * | `GuardrailMatch`               | `state.rs:2284 struct GuardrailMatch`                          |
 * | `GuardrailEvaluationContext`   | `state.rs:2349 struct GuardrailEvaluationContext`               |
 * | `GuardrailPolicyRuntime`       | `state.rs GuardrailPolicyRuntime` (revision + compiled checks)  |
 * | `matchGuardrail`               | `state_quota_and_policy.rs:391 AppState::match_guardrail`       |
 * | `streamingGuardrailPlan`       | `state_quota_and_policy.rs:651 AppState::streaming_guardrail_plan` |
 * | `GuardrailEvidenceSink`        | `state_quota_and_policy.rs:935 record_guardrail_evaluation`     |
 * | `GuardrailAuditSink`           | `record_guardrail_audit_event`                                  |
 * | `GuardrailPolicySource`        | `AppState.guardrail_policies` (the config snapshot + bindings)  |
 *
 * NOTHING here re-implements a detector. Every verdict comes from a
 * `GuardrailDetector` built by `detectors.ts` out of the ported package.
 */
import type {
  ActionKind,
  CheckOutcome,
  ContentPatch,
  ContentSource,
  DetectorError,
  DetectorStage,
  GuardrailDetector,
  GuardrailEnvelope,
  GuardrailProtocol,
  ManagedActionContext,
  PolicyAction,
  PolicyRevision,
  PolicySelectionContext,
} from "@ferrogate/guardrails";

// ---------------------------------------------------------------------------
// Enforcement vocabulary
// ---------------------------------------------------------------------------

/**
 * `ferrogate_config::GuardrailEffect`. The two things the model-content path
 * can do about a match. `require_approval` collapses to `deny` and `quarantine`
 * to `redact` (`state_quota_and_policy.rs:1509-1516`, issue #200); the
 * originating {@link GuardrailMatch.actionKind} preserves the distinction.
 */
export type GuardrailEffect = "deny" | "redact";

/** `state.rs:2306 enum StreamingGuardrailPlan`. */
export type StreamingGuardrailPlan = "none" | "shadow_after_complete" | "buffer_and_enforce";

/**
 * The selected enforcement for a request/response, or `null` when every
 * matching policy passed (or only produced `allow`/`record` actions).
 *
 * Rust `state.rs:2284`. `contentPatches` + `patchEnvelope` + `patchSources` are
 * carried so {@link GuardrailMatch} can redact the response document itself
 * (`redact_text`, `state.rs:2321`) rather than leaking the patch machinery to
 * the caller.
 */
export interface GuardrailMatch {
  readonly ruleId: string;
  readonly ruleName: string;
  readonly policyRevision: number;
  readonly checkId?: string | undefined;
  readonly effect: GuardrailEffect;
  /** The originating policy action kind, before the effect collapse. */
  readonly actionKind: ActionKind;
  readonly segmentId?: string | undefined;
  readonly byteStart?: number | undefined;
  readonly byteEnd?: number | undefined;
  readonly contentPatches: readonly ContentPatch[];
  readonly patchEnvelope?: GuardrailEnvelope | undefined;
  readonly patchSources: readonly ContentSource[];
  /** Error `code` written into the FerroGate envelope. */
  readonly code: string;
  /** Error `message` written into the FerroGate envelope. */
  readonly message: string;
}

// ---------------------------------------------------------------------------
// Evaluation context
// ---------------------------------------------------------------------------

/** `ferrogate_core::TenantContext`, as the guardrail path reads it. */
export interface GuardrailTenant {
  readonly organizationId?: string | undefined;
  readonly teamId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  readonly userId?: string | undefined;
  readonly apiKeyId?: string | undefined;
}

/** `state.rs:2349 GuardrailEvaluationContext`. */
export interface GuardrailEvaluationContext {
  readonly requestId: string;
  readonly traceId?: string | undefined;
  readonly agentRunId?: string | undefined;
  readonly workflowId?: string | undefined;
  readonly workflowVersion?: number | undefined;
  readonly workflowNodeId?: string | undefined;
  readonly actorApiKeyId?: string | undefined;
  readonly tenant: GuardrailTenant;
  readonly serviceAccountId?: string | undefined;
  readonly gatewayConfigId?: string | undefined;
  readonly model?: string | undefined;
  readonly provider?: string | undefined;
  readonly streaming: boolean;
  readonly envelope: GuardrailEnvelope;
  readonly managedAction?: ManagedActionContext | undefined;
  readonly actionFingerprint?: string | undefined;
}

/** Project an evaluation context onto the package's policy-selection context. */
export function selectionContextFrom(
  context: Pick<
    GuardrailEvaluationContext,
    "tenant" | "serviceAccountId" | "gatewayConfigId" | "model" | "provider" | "managedAction"
  >,
): PolicySelectionContext {
  const selection: PolicySelectionContext = {};
  if (context.tenant.organizationId !== undefined) {
    selection.organization_id = context.tenant.organizationId;
  }
  if (context.tenant.projectId !== undefined) {
    selection.project_id = context.tenant.projectId;
  }
  if (context.tenant.workspaceId !== undefined) {
    selection.workspace_id = context.tenant.workspaceId;
  }
  if (context.tenant.apiKeyId !== undefined) {
    selection.api_key_id = context.tenant.apiKeyId;
  }
  if (context.serviceAccountId !== undefined) {
    selection.service_account_id = context.serviceAccountId;
  }
  if (context.gatewayConfigId !== undefined) {
    selection.gateway_config_id = context.gatewayConfigId;
  }
  if (context.model !== undefined) {
    selection.model = context.model;
  }
  if (context.provider !== undefined) {
    selection.provider = context.provider;
  }
  if (context.managedAction !== undefined) {
    selection.managed_action = context.managedAction;
  }
  return selection;
}

// ---------------------------------------------------------------------------
// Compiled policy runtime
// ---------------------------------------------------------------------------

/**
 * One compiled check: the immutable {@link CheckBinding} plus the constructed
 * detector(s). Rust `state.rs GuardrailCheckRuntime`.
 */
export interface GuardrailCheckRuntime {
  readonly id: string;
  readonly enabled: boolean;
  readonly stage: DetectorStage;
  readonly sources: readonly ContentSource[];
  readonly detector: GuardrailDetector;
  readonly fallbackDetector?: GuardrailDetector | undefined;
  /** `detector_id` on the evidence row. */
  readonly detectorId: string;
  /** `config_digest` on the evidence row (`sha256:<8 hex>`). */
  readonly detectorConfigDigest: string;
}

/** A selected policy revision plus its compiled checks. */
export interface GuardrailPolicyRuntime {
  readonly revision: PolicyRevision;
  readonly checks: readonly GuardrailCheckRuntime[];
}

/**
 * Which guardrail policies apply to this caller.
 *
 * The Rust snapshot holds `AppState.guardrail_policies`, rebuilt on config
 * reload from the static `[[guardrails]]` table PLUS the durable
 * `guardrail_policy_bindings` rows (each binding names the one `active_revision`
 * of its policy). `binding.ts` ports the binding + its generation-guarded CAS;
 * this port is what the engine consumes.
 *
 * Implementations MUST already have applied scope selection semantics
 * equivalent to `selectPolicyRevisions` — `defaultPolicySource` does exactly
 * that, in `(administrative_rank, policy_id, revision)` order.
 */
export interface GuardrailPolicySource {
  policiesFor(selection: PolicySelectionContext): readonly GuardrailPolicyRuntime[];
}

// ---------------------------------------------------------------------------
// Evidence + audit
// ---------------------------------------------------------------------------

/**
 * One sanitized finding, as it reaches durable evidence (#665).
 *
 * `docs/legacy/inventory-policy-core.md`'s cross-cutting invariant is that
 * `matched_text` is NEVER persisted, and this type is the boundary that
 * enforces it: it has no field that can carry content. What it does carry is
 * everything an investigation needs to act — WHICH detector category fired, how
 * confident it was, and WHERE in the request it fired — plus
 * {@link redactedExcerpt}, which is a RECONSTRUCTION of the matched span (the
 * category, the byte range, and a run of `*` as wide as the match) built from
 * the finding's structure and never from its bytes.
 *
 * An excerpt that carried the matched text would move the leak into the
 * evidence table rather than stop it; an evidence row with no excerpt at all
 * leaves an operator unable to tell a 20-byte credential from a 2 000-byte
 * document. The mask answers the second question without opening the first.
 */
export interface GuardrailFindingEvidence {
  /** Sanitized detector category (`aws_access_key_id`, `regex`, …). */
  readonly category: string;
  /** `info` | `low` | `medium` | `high` | `critical`, sanitized. */
  readonly severity: string;
  /** The detector's own confidence, clamped to `[0, 1]`. Absent when it gave none. */
  readonly confidence?: number | undefined;
  readonly segmentId?: string | undefined;
  readonly byteStart?: number | undefined;
  readonly byteEnd?: number | undefined;
  /** The detector's keyed `hmac-sha256:<hex>` / `sha256:<hex>` finding id, when it produced one. */
  readonly fingerprint?: string | undefined;
  /** The MASK. Contains no byte of the screened content — see the type docblock. */
  readonly redactedExcerpt: string;
}

/**
 * One `guardrail_check_evaluations` row. **Sanitized**: no prompt text, no
 * `matched_text`, only category COUNTS, the detector's own version tokens, and
 * the {@link GuardrailFindingEvidence} projection of each finding.
 */
export interface GuardrailCheckEvidence {
  readonly id: string;
  readonly evaluationId: string;
  readonly checkId: string;
  readonly detectorId: string;
  readonly detectorVersion: string;
  readonly configDigest: string;
  readonly verdict: CheckOutcome;
  readonly action: string;
  readonly enforcementStatus: string;
  readonly latencyMs: number;
  readonly findingCategoryCounts: Readonly<Record<string, number>>;
  readonly findingCount: number;
  /**
   * The per-finding detail, bounded (see
   * `evidence.ts::MAX_EVIDENCE_FINDINGS`). `findingCount` remains the TRUE
   * count, so a truncated array is visible rather than silently authoritative.
   */
  readonly findings: readonly GuardrailFindingEvidence[];
  readonly transformed: boolean;
  readonly usedFallback: boolean;
  readonly errorKind?: string | undefined;
}

/**
 * One `guardrail_evaluations` row.
 *
 * `inputFingerprint` is the keyed, non-reversible `hmac-sha256:<hex>` over the
 * envelope's per-segment content fingerprints — never the content itself
 * (`state_quota_and_policy.rs:1250 guardrail_envelope_fingerprint`).
 */
export interface GuardrailEvidence {
  readonly id: string;
  readonly requestId: string;
  readonly traceId?: string | undefined;
  readonly agentRunId?: string | undefined;
  readonly subjectId?: string | undefined;
  readonly tenant: GuardrailTenant;
  readonly scopeType: string;
  readonly scopeId?: string | undefined;
  readonly target: string;
  readonly protocol: GuardrailProtocol;
  readonly stage: DetectorStage;
  readonly mode: string;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly verdict: string;
  readonly action: string;
  readonly enforcementStatus: string;
  readonly latencyMs: number;
  readonly findingCategoryCounts: Readonly<Record<string, number>>;
  readonly findingCount: number;
  readonly transformed: boolean;
  readonly inputFingerprint: string;
  readonly occurredAtUnix: number;
  readonly actionFingerprint?: string | undefined;
}

/**
 * Durable evidence sink.
 *
 * **Returning `false` fails the request CLOSED** — `match_guardrail`
 * (`state_quota_and_policy.rs:644-646`) replaces the enforcement with
 * `guardrail_evidence_unavailable_match` when evidence capacity is gone, so an
 * unrecordable evaluation denies rather than silently proceeding.
 */
export interface GuardrailEvidenceSink {
  append(
    evaluation: GuardrailEvidence,
    checks: readonly GuardrailCheckEvidence[],
  ): boolean | Promise<boolean>;
  /**
   * Hand everything buffered to durable storage. OPTIONAL, and never awaited on
   * the request path (#665).
   *
   * `append` is called from inside `matchGuardrail`, i.e. in front of the
   * client's first byte, so a durable sink may not do I/O there — the same
   * hot-path rule `apps/gateway/src/requestlog/` states. A durable sink
   * therefore BUFFERS in `append` (which is what keeps the fail-closed capacity
   * check synchronous) and writes here, from
   * `ctx.waitUntil(...)` in `./middleware.ts`.
   *
   * Implementations MUST NOT reject: a logging failure is never a request
   * failure.
   */
  flush?(runtime: {
    env: unknown;
    ctx?: { waitUntil(work: Promise<unknown>): void };
  }): Promise<void>;
  /**
   * Re-key buffered evidence onto the request id the CLIENT was actually told.
   * OPTIONAL, and only meaningful before a {@link GuardrailEvidenceSink.flush}.
   *
   * ## Why this is needed at all
   *
   * `inference/handlers.ts:1190` does
   * `c.set("requestId", c.req.header("x-request-id") ?? requestIds.next())`,
   * i.e. the inference route OVERWRITES the id
   * `middleware/errors.ts::requestId` minted before any middleware ran. The
   * guardrail middleware screens BEFORE the route, so its evaluation is built
   * with the earlier id, while `request_logs.request_id` (#664) and the
   * `x-request-id` response header carry the later one.
   *
   * Left alone that is a silent correlation break: `GET
   * /admin/v1/investigations?request_id=<what the client was told>` would find
   * the request log and NOT the guardrail evaluation, i.e. would report that a
   * blocked request was never screened. Adopting the client's id here is the
   * narrow fix; making the route stop overwriting is a fleet-wide change to
   * request-id semantics that does not belong in an evidence slice.
   */
  recorrelate?(previousRequestId: string, requestId: string): void;
}

/** `AdminAuditEventDraft` — the subset the guardrail path writes. */
export interface GuardrailAuditEvent {
  readonly requestId: string;
  readonly traceId?: string | undefined;
  readonly agentRunId?: string | undefined;
  readonly actorApiKeyId?: string | undefined;
  readonly tenant: GuardrailTenant;
  readonly action: string;
  readonly target: string;
  readonly outcome: string;
  readonly message: string;
}

export interface GuardrailAuditSink {
  record(event: GuardrailAuditEvent): void | Promise<void>;
}

/** `metrics.record_guardrail_match` / `record_guardrail_evaluation`. */
export interface GuardrailMetricsSink {
  recordMatch?(effect: GuardrailEffect): void;
  recordEvaluation?(verdict: string, enforcementStatus: string): void;
  recordDetectorError?(kind: string): void;
  recordEvidencePersistenceFailure?(): void;
  recordStreamCaptureOverflow?(): void;
}

// ---------------------------------------------------------------------------
// Internal evaluation record (exported for evidence + tests)
// ---------------------------------------------------------------------------

/** `state_quota_and_policy.rs GuardrailCheckEvaluation`. */
export interface GuardrailCheckEvaluation {
  readonly checkId: string;
  readonly outcome: CheckOutcome;
  readonly segmentId?: string | undefined;
  readonly byteStart?: number | undefined;
  readonly byteEnd?: number | undefined;
  readonly contentPatches: readonly ContentPatch[];
  readonly detectorError?: DetectorError | undefined;
  readonly usedFallback: boolean;
  readonly detectorVersion: string;
  readonly latencyMs: number;
  readonly findingCategoryCounts: Readonly<Record<string, number>>;
  readonly findingCount: number;
  /**
   * The sanitized per-finding projection (#665). Built at the ONE point the
   * raw `Finding[]` is available (`engine.ts::externalEvaluation`) and carrying
   * no content, so `matched_text` never leaves the in-memory decision path.
   */
  readonly findings: readonly GuardrailFindingEvidence[];
  /**
   * A located finding no patch covers. Forces a `redact` to fail closed to
   * `deny` — reporting it as a successful redaction would return the flagged
   * content verbatim while the audit claims it was scrubbed
   * (`state_quota_and_policy.rs:1553-1567`).
   */
  readonly hasUnredactableFindings: boolean;
}

/** Everything the enforcement engine needs, injected. */
export interface GuardrailEngineDeps {
  readonly policies: GuardrailPolicySource;
  readonly evidence: GuardrailEvidenceSink;
  readonly audit?: GuardrailAuditSink | undefined;
  readonly metrics?: GuardrailMetricsSink | undefined;
  /**
   * HMAC key for {@link GuardrailEvidence.inputFingerprint}. Absent yields
   * `hmac-sha256:unavailable`, exactly as the Rust did when no evidence key was
   * configured (`state_quota_and_policy.rs:1255-1257`).
   */
  readonly evidenceHmacKey?: Uint8Array | undefined;
  /** Injectable clock (epoch millis). Defaults to `Date.now`. */
  readonly now?: (() => number) | undefined;
}

export type { PolicyAction, PolicyRevision, PolicySelectionContext };
