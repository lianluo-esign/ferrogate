-- ===========================================================================
-- Platform/unattributed guardrail screening evidence (Zero-D1 Plan B).
--
-- The `PlatformDataObject` singleton IS the authoritative home for
-- platform-scoped guardrail evidence (`scope_type = 'platform'`, no owning
-- tenant), which has no TenantDataObject to live in and used to sit in the
-- control projection only. Removing the entire control D1 therefore requires
-- this object: it holds exactly the rows every fan-out reader cannot reach,
-- because there is no roster tenant for an unattributed call.
--
-- Every row in this object is platform-scoped, so `tenant` is NULLable (there
-- is no owner) and reads need no tenant fence — the whole table IS the platform
-- domain. The column is kept (rather than dropped) so the row shape stays
-- byte-identical to the control/tenant guardrail tables and the one-time
-- control-`WHERE tenant IS NULL`→object backfill is a lossless `SELECT *`.
-- Single object → `id` PRIMARY KEY is unique on its own; there is no
-- `projection_key` (that column only disambiguated tenants inside the shared
-- control projection).
-- ===========================================================================

CREATE TABLE IF NOT EXISTS guardrail_evaluations (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    agent_run_id TEXT,
    subject_id TEXT,
    tenant TEXT,
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

-- The one read this object serves is the operator fleet list: the whole table
-- ordered newest-first. No tenant column leads the index because every row is
-- platform-scoped.
CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_time
    ON guardrail_evaluations(occurred_at_unix DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_request
    ON guardrail_evaluations(request_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_trace
    ON guardrail_evaluations(trace_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_agent_run
    ON guardrail_evaluations(agent_run_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_policy_time
    ON guardrail_evaluations(policy_id, policy_revision, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_verdict_action
    ON guardrail_evaluations(verdict, action, occurred_at_unix DESC);

CREATE TABLE IF NOT EXISTS guardrail_check_evaluations (
    id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL REFERENCES guardrail_evaluations(id) ON DELETE CASCADE,
    tenant TEXT,
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

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_evaluation
    ON guardrail_check_evaluations(evaluation_id, check_id);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_detector_verdict
    ON guardrail_check_evaluations(detector_id, verdict);

CREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_error
    ON guardrail_check_evaluations(error_kind);
