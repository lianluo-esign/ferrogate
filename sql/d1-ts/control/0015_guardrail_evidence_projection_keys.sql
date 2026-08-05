-- ===========================================================================
-- Tenant-qualified guardrail evidence projections (#860, #831)
--
-- Tenant-attributed guardrail evidence is authoritative in TenantDataObject.
-- These control-D1 tables remain the derived projection used by platform/fleet
-- readers until #825 supplies bounded fan-out and freshness semantics.
--
-- Evaluation/check ids are logical ids and are not account-global. A client or
-- gateway retry can reuse the same id in two tenants, so keeping either id as
-- the control primary key would let one projection overwrite the other. The
-- length-prefixed key matches `evidenceProjectionKey` in gateway code:
--
--     length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id
--
-- The child stores its parent's projection key and tenant as well as the
-- logical evaluation id. This keeps the projection foreign key/cascade safe
-- and prevents an id-only child join from mixing tenants.
-- ===========================================================================

DROP INDEX IF EXISTS idx_guardrail_evaluations_tenant_time;
DROP INDEX IF EXISTS idx_guardrail_evaluations_request;
DROP INDEX IF EXISTS idx_guardrail_evaluations_trace;
DROP INDEX IF EXISTS idx_guardrail_evaluations_agent_run;
DROP INDEX IF EXISTS idx_guardrail_evaluations_policy_time;
DROP INDEX IF EXISTS idx_guardrail_evaluations_verdict_action;
DROP INDEX IF EXISTS idx_guardrail_checks_evaluation;
DROP INDEX IF EXISTS idx_guardrail_checks_detector_verdict;
DROP INDEX IF EXISTS idx_guardrail_checks_error;

ALTER TABLE guardrail_check_evaluations RENAME TO guardrail_check_evaluations_projection_legacy;
ALTER TABLE guardrail_evaluations RENAME TO guardrail_evaluations_projection_legacy;

CREATE TABLE guardrail_evaluations (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
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

INSERT INTO guardrail_evaluations (
    projection_key, id, request_id, trace_id, agent_run_id, subject_id, tenant,
    scope_type, scope_id, target, protocol, stage, mode, policy_id,
    policy_revision, verdict, action, enforcement_status, latency_ms,
    finding_count, input_fingerprint, action_fingerprint, occurred_at_unix,
    evaluation_json
)
SELECT
    length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id,
    id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type,
    scope_id, target, protocol, stage, mode, policy_id, policy_revision,
    verdict, action, enforcement_status, latency_ms, finding_count,
    input_fingerprint, action_fingerprint, occurred_at_unix, evaluation_json
FROM guardrail_evaluations_projection_legacy;

CREATE INDEX idx_guardrail_evaluations_tenant_time
    ON guardrail_evaluations(tenant, occurred_at_unix DESC, id ASC);
CREATE INDEX idx_guardrail_evaluations_request
    ON guardrail_evaluations(request_id, occurred_at_unix DESC);
CREATE INDEX idx_guardrail_evaluations_trace
    ON guardrail_evaluations(trace_id, occurred_at_unix DESC);
CREATE INDEX idx_guardrail_evaluations_agent_run
    ON guardrail_evaluations(agent_run_id, occurred_at_unix DESC);
CREATE INDEX idx_guardrail_evaluations_policy_time
    ON guardrail_evaluations(policy_id, policy_revision, occurred_at_unix DESC);
CREATE INDEX idx_guardrail_evaluations_verdict_action
    ON guardrail_evaluations(verdict, action, occurred_at_unix DESC);

CREATE TABLE guardrail_check_evaluations (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    evaluation_projection_key TEXT NOT NULL
      REFERENCES guardrail_evaluations(projection_key) ON DELETE CASCADE,
    evaluation_id TEXT NOT NULL,
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
    UNIQUE (evaluation_projection_key, check_id)
);

INSERT INTO guardrail_check_evaluations (
    projection_key, id, evaluation_projection_key, evaluation_id, tenant,
    check_id, detector_id, detector_version, config_digest, verdict, action,
    enforcement_status, error_kind, check_json
)
SELECT
    length(COALESCE(parent.tenant, '')) || ':' || COALESCE(parent.tenant, '') || ':' || child.id,
    child.id,
    length(COALESCE(parent.tenant, '')) || ':' || COALESCE(parent.tenant, '') || ':' || child.evaluation_id,
    child.evaluation_id,
    parent.tenant,
    child.check_id, child.detector_id, child.detector_version, child.config_digest,
    child.verdict, child.action, child.enforcement_status, child.error_kind,
    child.check_json
FROM guardrail_check_evaluations_projection_legacy AS child
JOIN guardrail_evaluations_projection_legacy AS parent
  ON parent.id = child.evaluation_id;

DROP TABLE guardrail_check_evaluations_projection_legacy;
DROP TABLE guardrail_evaluations_projection_legacy;

CREATE INDEX idx_guardrail_checks_evaluation
    ON guardrail_check_evaluations(evaluation_projection_key, evaluation_id, check_id);
CREATE INDEX idx_guardrail_checks_tenant_evaluation
    ON guardrail_check_evaluations(tenant, evaluation_id, check_id);
CREATE INDEX idx_guardrail_checks_detector_verdict
    ON guardrail_check_evaluations(detector_id, verdict);
CREATE INDEX idx_guardrail_checks_error
    ON guardrail_check_evaluations(error_kind);
