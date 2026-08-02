/**
 * The Queue message / D1 document form of a guardrail evidence row (#665).
 *
 * ## Why this shares #664's queue rather than declaring its own
 *
 * `[[queues.producers]] binding = "REQUEST_LOG"` already exists, its consumer
 * already runs on this Worker, and the only thing that has to happen to either
 * kind of message is an upsert into the CONTROL database — which both tables
 * live in. A second queue would mean a second binding, a second consumer
 * stanza, a second dead-letter policy and a second set of retry semantics to
 * keep in step, for exactly the same statement against exactly the same
 * database.
 *
 * The two message kinds are told apart by `object`, which is why
 * {@link GUARDRAIL_EVALUATION_OBJECT} is checked FIRST in the consumer: a
 * request-log decoder is permissive (it fills defaults for missing fields), so
 * handing it a guardrail message would produce a plausible, wrong `request_logs`
 * row rather than an error. Discriminating before decoding is what stops that.
 *
 * ## Why the wire is nested where the request log's is flat
 *
 * `requestlog/record.ts` keeps its wire flat because every fact it carries is a
 * scalar. Guardrail evidence is not: `finding_category_counts` is a map and
 * `checks[].findings[]` is an array of objects, and flattening either would
 * mean inventing a key encoding at the producer and parsing it at the consumer.
 * A Queue body is structured-clone encoded and a D1 column is text, so both
 * handle nesting natively; what matters is that the shape is TOTAL on decode,
 * which {@link guardrailEvidenceFromWire} is.
 */
import type { GuardrailCheckEvidence, GuardrailEvidence } from "./ports.js";

/** `object` on the wire and in the stored document. */
export const GUARDRAIL_EVALUATION_OBJECT = "guardrail_evaluation";

/** One evaluation plus its checks, as one message. */
export interface GuardrailEvidenceEnvelope {
  readonly evaluation: GuardrailEvidence;
  readonly checks: readonly GuardrailCheckEvidence[];
}

export type GuardrailEvidenceWire = Record<string, unknown>;

function put(out: GuardrailEvidenceWire, key: string, value: unknown): void {
  if (value === undefined) return;
  // A blank string is the same "nothing" a missing field is, and storing it
  // would make `WHERE trace_id IS NOT NULL` lie.
  if (typeof value === "string" && value === "") return;
  out[key] = value;
}

function checkToWire(check: GuardrailCheckEvidence): GuardrailEvidenceWire {
  const wire: GuardrailEvidenceWire = {
    id: check.id,
    evaluation_id: check.evaluationId,
    check_id: check.checkId,
    detector_id: check.detectorId,
    detector_version: check.detectorVersion,
    config_digest: check.configDigest,
    verdict: check.verdict,
    action: check.action,
    enforcement_status: check.enforcementStatus,
    latency_ms: check.latencyMs,
    finding_category_counts: check.findingCategoryCounts,
    finding_count: check.findingCount,
    transformed: check.transformed,
    used_fallback: check.usedFallback,
    findings: check.findings.map((finding) => {
      const out: GuardrailEvidenceWire = {
        category: finding.category,
        severity: finding.severity,
        // The MASK, never the match. See `evidence.ts::redactedExcerpt`.
        redacted_excerpt: finding.redactedExcerpt,
      };
      put(out, "confidence", finding.confidence);
      put(out, "segment_id", finding.segmentId);
      put(out, "byte_start", finding.byteStart);
      put(out, "byte_end", finding.byteEnd);
      put(out, "fingerprint", finding.fingerprint);
      return out;
    }),
  };
  put(wire, "error_kind", check.errorKind);
  return wire;
}

/** Encode one evaluation for the Queue and for the two D1 documents. */
export function guardrailEvidenceToWire(
  envelope: GuardrailEvidenceEnvelope,
): GuardrailEvidenceWire {
  const evaluation = envelope.evaluation;
  const wire: GuardrailEvidenceWire = {
    object: GUARDRAIL_EVALUATION_OBJECT,
    id: evaluation.id,
    request_id: evaluation.requestId,
    scope_type: evaluation.scopeType,
    target: evaluation.target,
    protocol: evaluation.protocol,
    stage: evaluation.stage,
    mode: evaluation.mode,
    policy_id: evaluation.policyId,
    policy_revision: evaluation.policyRevision,
    verdict: evaluation.verdict,
    action: evaluation.action,
    enforcement_status: evaluation.enforcementStatus,
    latency_ms: evaluation.latencyMs,
    finding_category_counts: evaluation.findingCategoryCounts,
    finding_count: evaluation.findingCount,
    transformed: evaluation.transformed,
    input_fingerprint: evaluation.inputFingerprint,
    occurred_at_unix: evaluation.occurredAtUnix,
    checks: envelope.checks.map(checkToWire),
  };
  put(wire, "trace_id", evaluation.traceId);
  put(wire, "agent_run_id", evaluation.agentRunId);
  put(wire, "subject_id", evaluation.subjectId);
  // The tenancy tuple is flattened onto the wire because the FENCE reads
  // `tenant` as a column; a nested object would have to be dug out at the
  // consumer, and a consumer that got the digging wrong would write NULL —
  // i.e. would silently make the row invisible to its own tenant.
  put(wire, "tenant_id", evaluation.tenant.organizationId);
  put(wire, "project_id", evaluation.tenant.projectId);
  put(wire, "workspace_id", evaluation.tenant.workspaceId);
  put(wire, "user_id", evaluation.tenant.userId);
  put(wire, "api_key_id", evaluation.tenant.apiKeyId);
  put(wire, "scope_id", evaluation.scopeId);
  put(wire, "action_fingerprint", evaluation.actionFingerprint);
  return wire;
}

function str(wire: GuardrailEvidenceWire, key: string): string | undefined {
  const value = wire[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

function num(wire: GuardrailEvidenceWire, key: string): number | undefined {
  const value = wire[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function counts(wire: GuardrailEvidenceWire, key: string): Record<string, number> {
  const value = wire[key];
  if (typeof value !== "object" || value === null) return {};
  const out: Record<string, number> = {};
  for (const [category, count] of Object.entries(value as Record<string, unknown>)) {
    if (typeof count === "number" && Number.isFinite(count)) out[category] = count;
  }
  return out;
}

function checkFromWire(raw: unknown, evaluationId: string): GuardrailCheckEvidence | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const wire = raw as GuardrailEvidenceWire;
  const id = str(wire, "id");
  const checkId = str(wire, "check_id");
  if (id === undefined || checkId === undefined) return undefined;
  const findingsRaw = Array.isArray(wire["findings"]) ? (wire["findings"] as unknown[]) : [];
  return {
    id,
    evaluationId,
    checkId,
    detectorId: str(wire, "detector_id") ?? "unknown",
    detectorVersion: str(wire, "detector_version") ?? "unknown",
    configDigest: str(wire, "config_digest") ?? "sha256:unknown",
    verdict: (str(wire, "verdict") ?? "error") as GuardrailCheckEvidence["verdict"],
    action: str(wire, "action") ?? "record",
    enforcementStatus: str(wire, "enforcement_status") ?? "not_enforced",
    latencyMs: num(wire, "latency_ms") ?? 0,
    findingCategoryCounts: counts(wire, "finding_category_counts"),
    findingCount: num(wire, "finding_count") ?? 0,
    findings: findingsRaw.flatMap((entry) => {
      if (typeof entry !== "object" || entry === null) return [];
      const finding = entry as GuardrailEvidenceWire;
      const category = str(finding, "category");
      if (category === undefined) return [];
      const confidence = num(finding, "confidence");
      const segmentId = str(finding, "segment_id");
      const byteStart = num(finding, "byte_start");
      const byteEnd = num(finding, "byte_end");
      const fingerprint = str(finding, "fingerprint");
      return [
        {
          category,
          severity: str(finding, "severity") ?? "high",
          ...(confidence !== undefined ? { confidence } : {}),
          ...(segmentId !== undefined ? { segmentId } : {}),
          ...(byteStart !== undefined ? { byteStart } : {}),
          ...(byteEnd !== undefined ? { byteEnd } : {}),
          ...(fingerprint !== undefined ? { fingerprint } : {}),
          redactedExcerpt: str(finding, "redacted_excerpt") ?? "",
        },
      ];
    }),
    transformed: wire["transformed"] === true,
    usedFallback: wire["used_fallback"] === true,
    ...(str(wire, "error_kind") !== undefined
      ? { errorKind: str(wire, "error_kind") as string }
      : {}),
  };
}

/**
 * Decode a wire body — the Queue CONSUMER's entry point.
 *
 * Total, never throwing, for the reason `requestLogFromWire` gives: a Queue
 * delivers at least once and a malformed body would otherwise poison a whole
 * batch of good evidence. A message missing the fields that make a row
 * addressable (`id`, `request_id`, `occurred_at_unix`) is rejected by returning
 * `undefined`, because a row keyed on `""` would collide every such message
 * onto one another under the primary key — many decisions silently collapsed
 * into one, which is worse than dropping them visibly.
 *
 * `object` must match, and that check is the discriminator that keeps
 * request-log and guardrail messages from decoding as one another.
 */
export function guardrailEvidenceFromWire(body: unknown): GuardrailEvidenceEnvelope | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const wire = body as GuardrailEvidenceWire;
  if (wire["object"] !== GUARDRAIL_EVALUATION_OBJECT) return undefined;

  const id = str(wire, "id");
  const requestId = str(wire, "request_id");
  const occurredAtUnix = num(wire, "occurred_at_unix");
  if (id === undefined || requestId === undefined || occurredAtUnix === undefined) {
    return undefined;
  }

  const traceId = str(wire, "trace_id");
  const agentRunId = str(wire, "agent_run_id");
  const subjectId = str(wire, "subject_id");
  const scopeId = str(wire, "scope_id");
  const actionFingerprint = str(wire, "action_fingerprint");
  const organizationId = str(wire, "tenant_id");
  const projectId = str(wire, "project_id");
  const workspaceId = str(wire, "workspace_id");
  const userId = str(wire, "user_id");
  const apiKeyId = str(wire, "api_key_id");

  const evaluation: GuardrailEvidence = {
    id,
    requestId,
    ...(traceId !== undefined ? { traceId } : {}),
    ...(agentRunId !== undefined ? { agentRunId } : {}),
    ...(subjectId !== undefined ? { subjectId } : {}),
    tenant: {
      ...(organizationId !== undefined ? { organizationId } : {}),
      ...(projectId !== undefined ? { projectId } : {}),
      ...(workspaceId !== undefined ? { workspaceId } : {}),
      ...(userId !== undefined ? { userId } : {}),
      ...(apiKeyId !== undefined ? { apiKeyId } : {}),
    },
    scopeType: str(wire, "scope_type") ?? "platform",
    ...(scopeId !== undefined ? { scopeId } : {}),
    target: str(wire, "target") ?? "unspecified",
    protocol: (str(wire, "protocol") ?? "chat_completions") as GuardrailEvidence["protocol"],
    stage: (str(wire, "stage") ?? "request") as GuardrailEvidence["stage"],
    mode: str(wire, "mode") ?? "enforce",
    policyId: str(wire, "policy_id") ?? "unknown",
    policyRevision: num(wire, "policy_revision") ?? 0,
    // An unreadable verdict degrades to `error`, never to `pass`: an
    // undecodable evidence row must not be recorded as a control having passed.
    verdict: str(wire, "verdict") ?? "error",
    action: str(wire, "action") ?? "record",
    enforcementStatus: str(wire, "enforcement_status") ?? "not_enforced",
    latencyMs: num(wire, "latency_ms") ?? 0,
    findingCategoryCounts: counts(wire, "finding_category_counts"),
    findingCount: num(wire, "finding_count") ?? 0,
    transformed: wire["transformed"] === true,
    inputFingerprint: str(wire, "input_fingerprint") ?? "hmac-sha256:unavailable",
    occurredAtUnix,
    ...(actionFingerprint !== undefined ? { actionFingerprint } : {}),
  };

  const rawChecks = Array.isArray(wire["checks"]) ? (wire["checks"] as unknown[]) : [];
  const checks = rawChecks.flatMap((entry) => {
    const check = checkFromWire(entry, id);
    return check === undefined ? [] : [check];
  });
  return { evaluation, checks };
}
