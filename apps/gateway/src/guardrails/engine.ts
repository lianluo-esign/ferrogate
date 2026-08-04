/**
 * The guardrail ENFORCEMENT chokepoint.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/state_quota_and_policy.rs`:
 * `AppState::match_guardrail` (:391), `evaluate_guardrail_check` (:1319),
 * `external_guardrail_evaluation` (:1420), `guardrail_enforcement` (:1489),
 * `guardrail_enforcement_rank` (:1583), `merge_guardrail_enforcement` (:1596),
 * `guardrail_evidence_unavailable_match` (:1613) and
 * `AppState::streaming_guardrail_plan` (:651).
 *
 * ## FAIL POSTURE — FAIL CLOSED
 *
 * A detector timeout/error does NOT pass the request through. The chain is:
 *
 *   detector throws `DetectorError`
 *     → `CheckOutcome::Error`            (`state_quota_and_policy.rs:1373`)
 *     → `AggregateOutcome::Error`        (`aggregate_check_outcomes`)
 *     → the policy's `on_error` actions  (`state_quota_and_policy.rs:539-545`)
 *
 * and `on_error` is compiled from `provider_on_error`, whose serde `#[default]`
 * is **`Block`** (`crates/ferrogate-config/src/config/types.rs:1954-1959`):
 *
 * ```rust
 * // crates/ferrogate-gateway/src/state.rs:6335-6342
 * let on_error = match rule.provider_runtime.provider_on_error {
 *     GuardrailProviderErrorMode::Block => vec![PolicyAction::block(
 *         "guardrail_provider_unavailable",
 *         format!("guardrail detector for rule '{}' failed", rule.name))],
 *     GuardrailProviderErrorMode::Record | GuardrailProviderErrorMode::FallbackDetector =>
 *         vec![PolicyAction::record()],
 * };
 * ```
 *
 * So: **an unreachable / slow detector denies the request with 403
 * `guardrail_provider_unavailable`** unless the operator explicitly opted into
 * `record` (fail open) or `fallback_detector`. `validate_policy_revision` also
 * refuses an EMPTY `on_error`, so "no posture declared" is unrepresentable.
 *
 * Three further fail-closed branches are ported verbatim:
 *  - a `redact` with no patch, or with a located finding no patch covers,
 *    downgrades to `deny` `guardrail_invalid_redaction` (:1553-1567);
 *  - unrecordable evidence replaces the enforcement with `deny`
 *    `guardrail_evidence_unavailable` (:644-646);
 *  - a policy that declares `streaming = reject_streaming` denies a streaming
 *    request BEFORE dispatch with `guardrail_streaming_unsupported` (:417-484).
 */
import {
  type AggregateOutcome,
  type CheckOutcome,
  type ContentPatch,
  DetectorError,
  type DetectorInput,
  type DetectorStage,
  type Finding,
  type GuardrailEnvelope,
  type PolicyAction,
  aggregateCheckOutcomes,
  applyContentPatchesToDocument,
  flattenedText,
  immutableId,
  validateContentPatchPermissions,
} from "@ferrogate/guardrails";
import {
  buildCheckEvidence,
  buildEvaluationEvidence,
  evaluationId,
  evidenceAction,
  sanitizedEvidenceToken,
  sanitizedFindings,
} from "./evidence.js";
import type {
  GuardrailCheckEvaluation,
  GuardrailCheckRuntime,
  GuardrailEffect,
  GuardrailEngineDeps,
  GuardrailEvaluationContext,
  GuardrailMatch,
  GuardrailPolicyRuntime,
  StreamingGuardrailPlan,
} from "./ports.js";
import { selectionContextFrom } from "./ports.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export class GuardrailEngine {
  readonly #deps: GuardrailEngineDeps;
  readonly #now: () => number;

  constructor(deps: GuardrailEngineDeps) {
    this.#deps = deps;
    this.#now = deps.now ?? (() => Date.now());
  }

  /** Canonical identity of the complete active policy-revision set selected for this request. */
  policyRevisionMarker(context: GuardrailEvaluationContext): string {
    const selection = selectionContextFrom(context);
    return JSON.stringify(
      this.#deps.policies
        .policiesFor(selection)
        .map((policy) => immutableId(policy.revision))
        .sort(),
    );
  }

  /**
   * `AppState::match_guardrail`. Returns the selected enforcement, or `null`
   * when nothing enforcing matched.
   */
  async matchGuardrail(
    stage: DetectorStage,
    context: GuardrailEvaluationContext,
  ): Promise<GuardrailMatch | null> {
    const selection = selectionContextFrom(context);
    let enforcement: GuardrailMatch | null = null;
    const pending: PendingEvidence[] = [];

    for (const policy of this.#deps.policies.policiesFor(selection)) {
      if (context.streaming && policy.revision.streaming === "reject_streaming") {
        const record = this.#rejectStreaming(policy, stage, context);
        if (record.candidate !== undefined) {
          enforcement = mergeEnforcement(enforcement, record.candidate);
        }
        pending.push(record.pending);
        await this.#deps.audit?.record(record.audit);
        continue;
      }

      const stageChecks = policy.checks.filter((check) => check.stage === stage);
      if (!stageChecks.some((check) => check.enabled)) {
        continue;
      }

      const startedAt = this.#now();
      const deadline = startedAt + policy.revision.deadline_ms;
      const evaluations =
        policy.revision.execution === "parallel"
          ? await Promise.all(
              stageChecks.map((check) => evaluateCheck(check, stage, context, deadline, this.#now)),
            )
          : await sequential(stageChecks, (check) =>
              evaluateCheck(check, stage, context, deadline, this.#now),
            );

      for (const evaluation of evaluations) {
        if (evaluation.detectorError !== undefined) {
          this.#deps.metrics?.recordDetectorError?.(evaluation.detectorError.kind);
          const detectorErrorOutcome = evaluation.usedFallback
            ? "fallback"
            : policy.revision.on_error.some(
                  (action) => action.kind === "block" || action.kind === "redact",
                )
              ? "blocked"
              : "recorded";
          await this.#deps.audit?.record({
            requestId: context.requestId,
            ...(context.traceId !== undefined ? { traceId: context.traceId } : {}),
            ...(context.agentRunId !== undefined ? { agentRunId: context.agentRunId } : {}),
            ...(context.actorApiKeyId !== undefined
              ? { actorApiKeyId: context.actorApiKeyId }
              : {}),
            tenant: context.tenant,
            action: "guardrail.detector_error",
            target: `${immutableId(policy.revision)}/${evaluation.checkId}`,
            outcome: detectorErrorOutcome,
            // `safe_message()` — never the detector's raw body.
            message: `guardrail detector error: ${evaluation.detectorError.kind}`,
          });
        }
      }

      const aggregate = aggregateCheckOutcomes(
        policy.revision.aggregation,
        evaluations.map((evaluation) => evaluation.outcome),
      );
      const actions =
        aggregate === "pass"
          ? policy.revision.on_pass
          : aggregate === "fail"
            ? policy.revision.on_fail
            : policy.revision.on_error;

      // Shadow mode never enforces; a streaming RESPONSE under
      // `shadow_after_complete` is evaluated only after the client already has
      // the bytes, so it is recorded as `not_enforced`.
      const effectiveShadow =
        policy.revision.mode === "shadow" ||
        (context.streaming &&
          stage === "response" &&
          policy.revision.streaming === "shadow_after_complete");
      const notEnforced = context.streaming && stage === "response" && effectiveShadow;

      await this.#deps.audit?.record({
        requestId: context.requestId,
        ...(context.traceId !== undefined ? { traceId: context.traceId } : {}),
        ...(context.agentRunId !== undefined ? { agentRunId: context.agentRunId } : {}),
        ...(context.actorApiKeyId !== undefined ? { actorApiKeyId: context.actorApiKeyId } : {}),
        tenant: context.tenant,
        action: "guardrail.policy_evaluate",
        target: immutableId(policy.revision),
        outcome: outcomeLabel(notEnforced, effectiveShadow, aggregate),
        message: notEnforced
          ? `streaming output completed before shadow evaluation; aggregate ${aggregate} was not enforced`
          : `guardrail policy evaluated ${evaluations.length} checks with ${actions.length} action(s)`,
      });

      const candidate = effectiveShadow
        ? undefined
        : enforcementFor(policy, evaluations, aggregate, actions, context.envelope);
      if (candidate !== undefined) {
        enforcement = mergeEnforcement(enforcement, candidate);
      }

      pending.push({
        policy,
        stage,
        aggregate,
        actions,
        effectiveShadow,
        notEnforced,
        evaluations,
        latencyMs: this.#now() - startedAt,
        candidate,
      });
    }

    for (const record of pending) {
      const applied =
        record.candidate !== undefined &&
        enforcement !== null &&
        enforcement.ruleId === record.candidate.ruleId &&
        enforcement.policyRevision === record.candidate.policyRevision &&
        enforcement.effect === record.candidate.effect &&
        enforcement.checkId === record.candidate.checkId;
      const accepted = await this.#persist(record, context, applied);
      if (!accepted) {
        enforcement = evidenceUnavailableMatch(record.policy);
      }
    }

    if (enforcement !== null) {
      this.#deps.metrics?.recordMatch?.(enforcement.effect);
    }
    return enforcement;
  }

  /**
   * `AppState::streaming_guardrail_plan` — decides, BEFORE dispatch, how a
   * streaming response must be handled.
   */
  streamingGuardrailPlan(context: GuardrailEvaluationContext): StreamingGuardrailPlan {
    let plan: StreamingGuardrailPlan = "none";
    const selection = selectionContextFrom(context);
    for (const policy of this.#deps.policies.policiesFor(selection)) {
      if (!policy.checks.some((check) => check.enabled && check.stage === "response")) {
        continue;
      }
      if (policy.revision.streaming === "reject_streaming") {
        continue;
      }
      if (
        policy.revision.mode === "enforce" &&
        policy.revision.streaming === "buffer_and_enforce"
      ) {
        return "buffer_and_enforce";
      }
      plan = "shadow_after_complete";
    }
    return plan;
  }

  /**
   * `record_guardrail_stream_capture_overflow` — a streaming shadow evaluation
   * whose capture buffer overflowed produces a synthetic `error` evidence row
   * so an unscreened stream is never silently unrecorded.
   */
  async recordStreamCaptureOverflow(context: GuardrailEvaluationContext): Promise<void> {
    this.#deps.metrics?.recordStreamCaptureOverflow?.();
    const selection = selectionContextFrom(context);
    for (const policy of this.#deps.policies.policiesFor(selection)) {
      if (!policy.checks.some((check) => check.enabled && check.stage === "response")) {
        continue;
      }
      await this.#deps.audit?.record({
        requestId: context.requestId,
        ...(context.traceId !== undefined ? { traceId: context.traceId } : {}),
        tenant: context.tenant,
        action: "guardrail.policy_evaluate",
        target: immutableId(policy.revision),
        outcome: "error",
        message: "streaming capture overflowed before response guardrail evaluation",
      });
      await this.#persist(
        {
          policy,
          stage: "response",
          aggregate: "error",
          actions: policy.revision.on_error,
          effectiveShadow: policy.revision.mode === "shadow",
          notEnforced: true,
          evaluations: [],
          latencyMs: 0,
          candidate: undefined,
          syntheticCheck: ["error", "shadow_capture_overflow"],
        },
        context,
        false,
      );
    }
  }

  async #persist(
    record: PendingEvidence,
    context: GuardrailEvaluationContext,
    applied: boolean,
  ): Promise<boolean> {
    const action =
      record.candidate !== undefined
        ? record.candidate.effect === "deny"
          ? "block"
          : "redact"
        : evidenceAction(record.actions);
    const enforcementStatus = record.notEnforced
      ? "not_enforced"
      : record.effectiveShadow
        ? "shadow_only"
        : record.candidate !== undefined && !applied
          ? "not_enforced"
          : "enforced";
    const id = evaluationId(context.requestId, immutableId(record.policy.revision), record.stage);
    const evaluation = buildEvaluationEvidence({
      id,
      context,
      policy: record.policy,
      stage: record.stage,
      aggregate: record.aggregate,
      action,
      enforcementStatus,
      evaluations: record.evaluations,
      latencyMs: record.latencyMs,
      applied,
      hmacKey: this.#deps.evidenceHmacKey,
      nowUnix: Math.floor(this.#now() / 1000),
    });
    const checks = buildCheckEvidence({
      evaluationId: id,
      policy: record.policy,
      stage: record.stage,
      action,
      enforcementStatus,
      evaluations: record.evaluations,
      candidateCheckId: record.candidate?.checkId,
      aggregate: record.aggregate,
      applied,
      ...(record.syntheticCheck !== undefined ? { syntheticCheck: record.syntheticCheck } : {}),
    });
    this.#deps.metrics?.recordEvaluation?.(evaluation.verdict, enforcementStatus);
    try {
      const accepted = await this.#deps.evidence.append(evaluation, checks);
      if (!accepted) {
        this.#deps.metrics?.recordEvidencePersistenceFailure?.();
      }
      return accepted;
    } catch {
      this.#deps.metrics?.recordEvidencePersistenceFailure?.();
      return false;
    }
  }

  #rejectStreaming(
    policy: GuardrailPolicyRuntime,
    stage: DetectorStage,
    context: GuardrailEvaluationContext,
  ): {
    candidate: GuardrailMatch | undefined;
    pending: PendingEvidence;
    audit: Parameters<NonNullable<GuardrailEngineDeps["audit"]>["record"]>[0];
  } {
    const shadow = policy.revision.mode === "shadow";
    const evidenceStage =
      policy.checks.find((check) => check.enabled && check.stage === stage)?.stage ??
      policy.checks.find((check) => check.enabled)?.stage ??
      stage;
    const candidate: GuardrailMatch | undefined = shadow
      ? undefined
      : {
          ruleId: policy.revision.policy_id,
          ruleName: policy.revision.name,
          policyRevision: policy.revision.revision,
          effect: "deny",
          actionKind: "block",
          contentPatches: [],
          patchSources: [],
          code: "guardrail_streaming_unsupported",
          message: `guardrail policy '${policy.revision.name}' does not allow streaming`,
        };
    return {
      candidate,
      pending: {
        policy,
        stage: evidenceStage,
        aggregate: "fail",
        actions: policy.revision.on_fail,
        effectiveShadow: shadow,
        notEnforced: false,
        evaluations: [],
        latencyMs: 0,
        candidate,
        syntheticCheck: ["skipped", "streaming_unsupported"],
      },
      audit: {
        requestId: context.requestId,
        ...(context.traceId !== undefined ? { traceId: context.traceId } : {}),
        ...(context.agentRunId !== undefined ? { agentRunId: context.agentRunId } : {}),
        ...(context.actorApiKeyId !== undefined ? { actorApiKeyId: context.actorApiKeyId } : {}),
        tenant: context.tenant,
        action: "guardrail.policy_evaluate",
        target: immutableId(policy.revision),
        outcome: shadow ? "shadow_fail" : "fail",
        message: "guardrail policy rejected streaming before provider dispatch",
      },
    };
  }
}

// ---------------------------------------------------------------------------
// GuardrailMatch helpers
// ---------------------------------------------------------------------------

/**
 * `GuardrailMatch::redact_text` (`state.rs:2321`).
 *
 * Applies the validated content patches to the response DOCUMENT; if the body
 * is not JSON, or any patch fails re-validation against the live text (stale
 * fingerprint, protected path), the whole body collapses to the literal
 * `"[REDACTED]"`. Failing OPEN here — returning the original text — would emit
 * flagged content while the audit row claims a redaction.
 */
export function redactText(match: GuardrailMatch, text: string): string {
  if (match.contentPatches.length === 0 || match.patchEnvelope === undefined) {
    return "[REDACTED]";
  }
  try {
    const document: unknown = JSON.parse(text);
    const patched = applyContentPatchesToDocument(
      document,
      match.patchEnvelope,
      [...match.patchSources],
      [...match.contentPatches],
    );
    return JSON.stringify(patched);
  } catch {
    return "[REDACTED]";
  }
}

/** `GuardrailMatch::evidence_target` — `policy@rev[/check]`. */
export function evidenceTarget(match: GuardrailMatch): string {
  const revision = `${match.ruleId}@${match.policyRevision}`;
  return match.checkId !== undefined ? `${revision}/${match.checkId}` : revision;
}

/** `GuardrailMatch::evidence_location`. */
export function evidenceLocation(match: GuardrailMatch): string {
  if (
    match.segmentId !== undefined &&
    match.byteStart !== undefined &&
    match.byteEnd !== undefined
  ) {
    return `segment ${match.segmentId} bytes ${match.byteStart}..${match.byteEnd}`;
  }
  if (match.segmentId !== undefined) {
    return `segment ${match.segmentId}`;
  }
  return "unlocated content";
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface PendingEvidence {
  readonly policy: GuardrailPolicyRuntime;
  readonly stage: DetectorStage;
  readonly aggregate: AggregateOutcome;
  readonly actions: readonly PolicyAction[];
  readonly effectiveShadow: boolean;
  readonly notEnforced: boolean;
  readonly evaluations: readonly GuardrailCheckEvaluation[];
  readonly latencyMs: number;
  readonly candidate: GuardrailMatch | undefined;
  readonly syntheticCheck?: readonly [string, string];
}

async function sequential<T, R>(items: readonly T[], run: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (const item of items) {
    out.push(await run(item));
  }
  return out;
}

function outcomeLabel(notEnforced: boolean, shadow: boolean, aggregate: AggregateOutcome): string {
  if (notEnforced) {
    return "not_enforced";
  }
  return shadow ? `shadow_${aggregate}` : aggregate;
}

/** `evaluate_guardrail_check` (`state_quota_and_policy.rs:1319`). */
async function evaluateCheck(
  check: GuardrailCheckRuntime,
  stage: DetectorStage,
  context: GuardrailEvaluationContext,
  deadline: number,
  now: () => number,
): Promise<GuardrailCheckEvaluation> {
  if (!check.enabled) {
    return disabledEvaluation(check.id);
  }
  const started = now();
  const input: DetectorInput = {
    protocol: context.envelope.protocol,
    stage,
    tenant: {
      ...(context.tenant.organizationId !== undefined
        ? { organization_id: context.tenant.organizationId }
        : {}),
      ...(context.tenant.teamId !== undefined ? { team_id: context.tenant.teamId } : {}),
      ...(context.tenant.projectId !== undefined ? { project_id: context.tenant.projectId } : {}),
      ...(context.tenant.userId !== undefined ? { user_id: context.tenant.userId } : {}),
      ...(context.tenant.apiKeyId !== undefined ? { api_key_id: context.tenant.apiKeyId } : {}),
    },
    ...(context.model !== undefined ? { model: context.model } : {}),
    ...(context.provider !== undefined ? { provider: context.provider } : {}),
    text: flattenedText(context.envelope),
    segments: [...context.envelope.segments],
  };

  let evaluation: GuardrailCheckEvaluation;
  try {
    const result = await check.detector.evaluate(input, deadline);
    try {
      validateContentPatchPermissions(context.envelope, [...check.sources], [...result.patches]);
      evaluation = externalEvaluation(check.id, result, context.envelope);
    } catch (error) {
      evaluation = errorEvaluation(check.id, asDetectorError(error));
    }
  } catch (error) {
    const primary = asDetectorError(error);
    if (check.fallbackDetector !== undefined) {
      try {
        const result = await check.fallbackDetector.evaluate(input, deadline);
        try {
          validateContentPatchPermissions(
            context.envelope,
            [...check.sources],
            [...result.patches],
          );
          evaluation = {
            ...externalEvaluation(check.id, result, context.envelope),
            detectorError: primary,
            usedFallback: true,
          };
        } catch (patchError) {
          evaluation = errorEvaluation(check.id, asDetectorError(patchError));
        }
      } catch {
        // Fallback ALSO failed → the primary error stands and the outcome is
        // `error`, so `on_error` (default: block) decides. Never a pass.
        evaluation = errorEvaluation(check.id, primary);
      }
    } else {
      evaluation = errorEvaluation(check.id, primary);
    }
  }
  return { ...evaluation, latencyMs: Math.max(0, now() - started) };
}

function asDetectorError(error: unknown): DetectorError {
  if (error instanceof DetectorError) {
    return error;
  }
  // An adapter that throws a plain error is still a detector failure, and it
  // must classify as `internal` (an `affects_circuit`-free hard error), never
  // as a pass.
  return DetectorError.new("internal", error instanceof Error ? error.message : String(error));
}

function disabledEvaluation(checkId: string): GuardrailCheckEvaluation {
  return {
    checkId,
    outcome: "disabled",
    contentPatches: [],
    usedFallback: false,
    detectorVersion: "disabled",
    latencyMs: 0,
    findingCategoryCounts: {},
    findingCount: 0,
    findings: [],
    hasUnredactableFindings: false,
  };
}

function errorEvaluation(checkId: string, error: DetectorError): GuardrailCheckEvaluation {
  return {
    checkId,
    outcome: "error",
    contentPatches: [],
    detectorError: error,
    usedFallback: false,
    detectorVersion: "unavailable",
    latencyMs: 0,
    findingCategoryCounts: {},
    findingCount: 0,
    // A detector that ERRORED reported no findings, and an empty array is the
    // truthful projection. `outcome: "error"` is what tells an auditor the
    // control did not conclude, so an empty array here cannot read as a pass.
    findings: [],
    hasUnredactableFindings: false,
  };
}

/** `external_guardrail_evaluation` (`state_quota_and_policy.rs:1420`). */
function externalEvaluation(
  checkId: string,
  result: {
    verdict: "pass" | "fail";
    findings: Finding[];
    patches: ContentPatch[];
    detector_version: string;
  },
  envelope: GuardrailEnvelope,
): GuardrailCheckEvaluation {
  const finding = result.findings[0];
  const findingCategoryCounts: Record<string, number> = {};
  for (const item of result.findings) {
    const category = sanitizedEvidenceToken(item.category, "uncategorized");
    findingCategoryCounts[category] = (findingCategoryCounts[category] ?? 0) + 1;
  }
  const segmentId =
    finding?.segment_id ??
    (envelope.segments.length === 1 ? envelope.segments[0]?.segment_id : undefined);

  // A LOCATED finding (segment + byte range) is only safely redactable when a
  // patch overlaps it. No overlap means the flagged text lives in an immutable
  // segment (tool-call arguments, metadata) that redaction cannot scrub, so the
  // redact must fail closed. Structural findings with no byte range
  // (size/request/json constraints) are not redaction-relevant.
  const hasUnredactableFindings = result.findings.some((item) => {
    const start = item.byte_start;
    const end = item.byte_end;
    if (
      item.segment_id === undefined ||
      item.segment_id === null ||
      start === undefined ||
      start === null ||
      end === undefined ||
      end === null
    ) {
      return false;
    }
    return !result.patches.some(
      (patch) =>
        patch.segment_id === item.segment_id && patch.byte_start < end && start < patch.byte_end,
    );
  });

  return {
    checkId,
    outcome: result.verdict === "pass" ? ("pass" as CheckOutcome) : ("fail" as CheckOutcome),
    ...(segmentId !== undefined && segmentId !== null ? { segmentId } : {}),
    ...(finding?.byte_start !== undefined && finding?.byte_start !== null
      ? { byteStart: finding.byte_start }
      : {}),
    ...(finding?.byte_end !== undefined && finding?.byte_end !== null
      ? { byteEnd: finding.byte_end }
      : {}),
    contentPatches: result.patches,
    usedFallback: false,
    detectorVersion: sanitizedEvidenceToken(result.detector_version, "unknown"),
    latencyMs: 0,
    findingCategoryCounts,
    findingCount: result.findings.length,
    // THE boundary: `sanitizedFindings` is the only thing that ever sees the
    // raw `Finding[]`, and it has no field that can carry `matched_text`
    // (#665). Everything downstream of here is already redacted.
    findings: sanitizedFindings(result.findings),
    hasUnredactableFindings,
  };
}

/** `guardrail_enforcement` (`state_quota_and_policy.rs:1489`). */
function enforcementFor(
  policy: GuardrailPolicyRuntime,
  evaluations: readonly GuardrailCheckEvaluation[],
  aggregate: AggregateOutcome,
  actions: readonly PolicyAction[],
  envelope: GuardrailEnvelope,
): GuardrailMatch | undefined {
  const evidence =
    aggregate === "fail"
      ? evaluations.find((evaluation) => evaluation.outcome === "fail")
      : aggregate === "error"
        ? evaluations.find((evaluation) => evaluation.outcome === "error")
        : evaluations[0];

  let selected: GuardrailMatch | undefined;
  for (const action of actions) {
    let effect: GuardrailEffect;
    switch (action.kind) {
      case "allow":
      case "record":
        continue;
      case "block":
        effect = "deny";
        break;
      case "redact":
        effect = "redact";
        break;
      // #200: no inline approval or output-hold on the model-content path, so
      // both fail closed — require_approval → deny, quarantine → withhold.
      case "require_approval":
        effect = "deny";
        break;
      case "quarantine":
        effect = "redact";
        break;
    }

    const sources =
      evidence !== undefined
        ? (policy.checks.find((check) => check.id === evidence.checkId)?.sources ?? [])
        : [];
    let candidate: GuardrailMatch = {
      ruleId: policy.revision.policy_id,
      ruleName: policy.revision.name,
      policyRevision: policy.revision.revision,
      ...(evidence !== undefined ? { checkId: evidence.checkId } : {}),
      effect,
      actionKind: action.kind,
      ...(evidence?.segmentId !== undefined ? { segmentId: evidence.segmentId } : {}),
      ...(evidence?.byteStart !== undefined ? { byteStart: evidence.byteStart } : {}),
      ...(evidence?.byteEnd !== undefined ? { byteEnd: evidence.byteEnd } : {}),
      contentPatches: evidence?.contentPatches ?? [],
      patchEnvelope: envelope,
      patchSources: [...sources],
      code: action.code ?? "guardrail_blocked",
      message: action.message ?? "request blocked by guardrail policy",
    };

    // FAIL CLOSED: a redaction that cannot fully scrub the flagged content
    // becomes a deny. Reporting it as a successful redaction would return the
    // flagged content verbatim while the audit claims otherwise.
    if (
      candidate.effect === "redact" &&
      (candidate.contentPatches.length === 0 || evidence?.hasUnredactableFindings === true)
    ) {
      candidate = {
        ...candidate,
        effect: "deny",
        code: "guardrail_invalid_redaction",
        message: `guardrail policy '${policy.revision.name}' could not produce safe redaction evidence`,
      };
    }

    if (selected === undefined || candidate.effect === "deny") {
      selected = candidate;
    }
  }
  return selected;
}

/**
 * `guardrail_enforcement_rank` (`state_quota_and_policy.rs:1583`). Higher wins.
 *
 * An UNCONDITIONAL deny must outrank an approval-gated one: the chokepoint
 * branches on `actionKind`, and a `require_approval` still executes once a human
 * approves. Treating both as "effect === deny" let a hard `block` be silently
 * downgraded whenever a `require_approval` policy co-matched and sorted first.
 */
function enforcementRank(candidate: GuardrailMatch): number {
  if (candidate.effect === "deny") {
    return candidate.actionKind === "require_approval" ? 2 : 3;
  }
  return 1;
}

/** `merge_guardrail_enforcement` — strictly-greater, so ties keep the first. */
function mergeEnforcement(
  current: GuardrailMatch | null,
  candidate: GuardrailMatch,
): GuardrailMatch {
  if (current === null) {
    return candidate;
  }
  return enforcementRank(candidate) > enforcementRank(current) ? candidate : current;
}

/** `guardrail_evidence_unavailable_match` (`state_quota_and_policy.rs:1613`). */
export function evidenceUnavailableMatch(policy: GuardrailPolicyRuntime): GuardrailMatch {
  return {
    ruleId: policy.revision.policy_id,
    ruleName: policy.revision.name,
    policyRevision: policy.revision.revision,
    effect: "deny",
    actionKind: "block",
    contentPatches: [],
    patchSources: [],
    code: "guardrail_evidence_unavailable",
    message: "guardrail evidence capacity is unavailable; request denied",
  };
}
