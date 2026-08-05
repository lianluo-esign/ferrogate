-- ===========================================================================
-- Tenant-private guardrail screening evidence (#860, #831)
--
-- Tenant-attributed evaluations and checks are authoritative in the owning
-- SQLite-backed TenantDataObject. The same-named CONTROL tables are derived
-- compatibility projections for platform/fleet reads until #825 supplies the
-- bounded fan-out contract; they are never a fallback for this object.
--
-- Platform/unattributed evaluations have no tenant object and remain in the
-- control projection only. A tenant object therefore requires tenant on both
-- rows, and the parent/check pair moves together under one local transaction.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS guardrail_evaluations (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    agent_run_id TEXT,
    subject_id TEXT,
    tenant TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT,
    target TEXT NOT NULL,
    protocol TEXT NOT NULL,
    stage TEXT NOT NULL,
    mode TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    action TEXT NOT NULL,
    enforcement_status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    input_fingerprint TEXT NOT NULL,
    action_fingerprint TEXT,
    occurred_at_unix INTEGER NOT NULL,
    evaluation_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_tenant_time
    ON guardrail_evaluations(tenant, occurred_at_unix DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_request
    ON guardrail_evaluations(request_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_trace
    ON guardrail_evaluations(trace_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_agent_run
    ON guardrail_evaluations(agent_run_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_policy_time
    ON guardrail_evaluations(policy_id, policy_revision, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_evaluations_verdict_action
    ON guardrail_evaluations(verdict, action, occurred_at_unix DESC);

CREATE TABLE IF NOT EXISTS guardrail_check_evaluations (
    id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL REFERENCES guardrail_evaluations(id) ON DELETE CASCADE,
    tenant TEXT NOT NULL,
    check_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    verdict TEXT NOT NULL,
    action TEXT NOT NULL,
    enforcement_status TEXT NOT NULL,
    error_kind TEXT,
    check_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (evaluation_id, check_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_checks_evaluation
    ON guardrail_check_evaluations(evaluation_id, check_id);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_checks_detector_verdict
    ON guardrail_check_evaluations(detector_id, verdict);

CREATE INDEX IF NOT EXISTS idx_tenant_guardrail_checks_error
    ON guardrail_check_evaluations(error_kind);
