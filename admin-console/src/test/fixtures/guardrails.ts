// Guardrail fixtures for #316 component tests.
//
// Every builder is typed against the generated OpenAPI schemas
// (src/lib/api-types.generated.ts), so a contract change that alters these
// shapes fails the test suite at compile time, not silently at runtime.
import type { AdminSchema } from "@/lib/gateway-client";

type Revision = AdminSchema<"GuardrailPolicyRevisionView">;
type CheckEvaluation = AdminSchema<"GuardrailCheckEvaluation">;
type Evaluation = AdminSchema<"GuardrailEvaluationView">;
type Investigation = AdminSchema<"GuardrailInvestigationTimeline">;
type Correlation = AdminSchema<"InvestigationActionCorrelation">;
type Tenant = AdminSchema<"TenantContext">;
type DryRun = AdminSchema<"GuardrailPolicyDryRunResponse">;

export const FP_ACTION = "sha256:aaaa1111bbbb2222cccc3333dddd4444";
export const FP_PARENT = "sha256:9999eeee8888ffff7777aaaa6666bbbb";

export function tenantContext(): Tenant {
  return {
    organization_id: "org-1",
    team_id: null,
    project_id: "proj-1",
    user_id: null,
    api_key_id: "key-1",
  };
}

export function policyRevision(overrides: Partial<Revision> = {}): Revision {
  return {
    policy_id: "pol-pii",
    name: "PII guard",
    description: "Blocks obvious PII in requests",
    enforced: true,
    scope: {
      tenant_ids: [],
      organization_ids: [],
      project_ids: [],
      workspace_ids: [],
      api_key_ids: [],
      gateway_config_ids: [],
      models: [],
      providers: [],
    },
    checks: [
      {
        id: "pii-local",
        enabled: true,
        stage: "request",
        detector: {
          kind: "GuardrailLocalDetector",
          keywords: ["ssn"],
          regex: [],
          secret_patterns: [],
        },
      },
    ],
    aggregation: { type: "all" },
    execution: "sequential",
    mode: "enforce",
    streaming: "buffer_and_enforce",
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "pii_detected", message: "Blocked by PII guard" }],
    on_error: [{ kind: "record" }],
    deadline_ms: 2000,
    revision: 1,
    created_at_unix: 1_752_000_000,
    created_by: "admin@example.com",
    status: "active",
    ...overrides,
  };
}

export function checkEvaluation(
  overrides: Partial<CheckEvaluation> = {},
): CheckEvaluation {
  return {
    id: "chk-1",
    evaluation_id: "eval-1",
    check_id: "pii-local",
    detector_id: "local",
    detector_version: "1",
    config_digest: "digest-1",
    verdict: "fail",
    action: "block",
    enforcement_status: "enforced",
    latency_ms: 12,
    finding_category_counts: { pii: 2 },
    finding_count: 2,
    transformed: false,
    used_fallback: false,
    error_kind: null,
    ...overrides,
  };
}

export function evaluation(overrides: Partial<Evaluation> = {}): Evaluation {
  return {
    id: "eval-1",
    request_id: "req-1",
    trace_id: "trace-1",
    agent_run_id: "run-1",
    subject_id: null,
    tenant: tenantContext(),
    scope_type: "tenant",
    scope_id: "tenant-1",
    target: "model:gpt-4o",
    protocol: "chat_completions",
    stage: "request",
    mode: "enforce",
    policy_id: "pol-pii",
    policy_revision: 3,
    verdict: "fail",
    action: "block",
    enforcement_status: "enforced",
    latency_ms: 18,
    finding_category_counts: { pii: 2 },
    finding_count: 2,
    transformed: false,
    input_fingerprint: "hmac-input-1",
    action_fingerprint: FP_ACTION,
    decision: "deny",
    decision_reason: "guardrail:fail:block:enforced",
    occurred_at_unix: 1_752_000_100,
    checks: [checkEvaluation()],
    ...overrides,
  };
}

export function dryRunResponse(overrides: Partial<DryRun> = {}): DryRun {
  return {
    object: "guardrail_policy_dry_run",
    policy_revision: "pol-pii@3",
    selected: true,
    result: "planned",
    checks: [{ id: "pii-local", detector: "local", result: "fail" }],
    on_pass: [{ kind: "allow" }],
    on_fail: [{ kind: "block", code: "pii_detected", message: "Blocked by PII guard" }],
    on_error: [{ kind: "record" }],
    provider_dispatched: false,
    external_action_dispatched: false,
    ...overrides,
  };
}

export function correlation(overrides: Partial<Correlation> = {}): Correlation {
  return {
    action_fingerprint: FP_ACTION,
    guardrail_evaluation_ids: ["eval-1"],
    approval_ids: ["appr-1"],
    agent_event_ids: ["evt-1"],
    audit_event_ids: ["aud-1"],
    child_request_ids: ["req-child-1"],
    child_dispatch_ids: ["disp-child-1"],
    ...overrides,
  };
}

export function investigation(overrides: Partial<Investigation> = {}): Investigation {
  return {
    object: "guardrail_investigation",
    selector: "request_id=req-1",
    identity: tenantContext(),
    agent_runs: [
      {
        id: "run-1",
        request_id: "req-1",
        trace_id: "trace-1",
        tenant: tenantContext(),
        status: "completed",
        provider: "openai",
        turns_executed: 2,
        output_recorded: true,
        started_at_unix: 1_752_000_000,
        completed_at_unix: 1_752_000_200,
      },
    ],
    agent_events: [
      {
        id: "evt-1",
        run_id: "run-1",
        request_id: "req-1",
        trace_id: "trace-1",
        tenant: tenantContext(),
        turn: 1,
        kind: "tool_call",
        target: "mcp:files/write",
        outcome: "denied",
        tool_call_id: "call-1",
        message: null,
        occurred_at_unix: 1_752_000_120,
        action_fingerprint: FP_ACTION,
        decision: "deny",
        decision_reason: "guardrail:fail:block:enforced",
        output_disposition: "withheld",
      },
    ],
    requests: [
      {
        request_id: "req-1",
        trace_id: "trace-1",
        agent_run_id: "run-1",
        workflow_id: null,
        workflow_version: null,
        workflow_node_id: null,
        parent_action_fingerprint: FP_PARENT,
        tenant: tenantContext(),
        route: "/v1/chat/completions",
        provider: "openai",
        logical_model: "gpt-4o",
        provider_model: "gpt-4o-2024-08-06",
        status_code: 403,
        error_code: "guardrail_blocked",
        cache_status: null,
        started_at_unix: 1_752_000_000,
        completed_at_unix: 1_752_000_180,
      },
    ],
    guardrail_evaluations: [evaluation()],
    audit_events: [
      {
        id: "aud-1",
        request_id: "req-1",
        trace_id: "trace-1",
        agent_run_id: "run-1",
        actor_api_key_id: "key-1",
        tenant: tenantContext(),
        action: "guardrail.enforce",
        target: "model:gpt-4o",
        outcome: "blocked",
        message: "guardrail blocked the request",
        occurred_at_unix: 1_752_000_150,
        action_fingerprint: FP_ACTION,
        decision: "deny",
        decision_reason: "guardrail:fail:block:enforced",
        output_disposition: "withheld",
      },
    ],
    approvals: [
      {
        id: "appr-1",
        request_id: "req-1",
        trace_id: "trace-1",
        agent_run_id: "run-1",
        workflow_id: null,
        workflow_node_id: null,
        action_fingerprint: FP_ACTION,
        decision: "deny",
        decision_reason: "approval_denied",
        tenant: tenantContext(),
        actor_api_key_id: "key-1",
        tool_name: "files/write",
        server_name: "files",
        route: "/v1/chat/completions",
        status: "denied",
        reviewer_api_key_id: "key-admin",
        reviewer_authority: "admin",
        terminal_reason: "denied by reviewer",
        requested_at_unix: 1_752_000_100,
        expires_at_unix: 1_752_003_700,
        decided_at_unix: 1_752_000_160,
      },
    ],
    billing_events: [
      {
        request_id: "req-1",
        trace_id: "trace-1",
        agent_run_id: "run-1",
        tenant: tenantContext(),
        logical_model: "gpt-4o",
        provider: "openai",
        provider_model: "gpt-4o-2024-08-06",
        usage: { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 },
        status_code: 403,
        occurred_at_unix: 1_752_000_180,
        cost_usd: 0.0123,
        latency_ms: 900,
        wallet_delta_credits: -12,
        wallet_balance_after_credits: 988,
      },
    ],
    action_correlations: [correlation()],
    total_cost_usd: 0.0123,
    final_outcome: "blocked",
    ...overrides,
  };
}
