-- ===========================================================================
-- Tenant-owned usage evidence and derived rollups (#852, #831)
--
-- The tenant object is authoritative for facts whose tenant is already known.
-- Control-D1 keeps only the fleet projection of these tables; its projection
-- keys are added by the matching control migration.
--
-- Usage aggregate tables already live in the tenant schema from 0001. This
-- migration adds the remaining tenant-owned evidence rows and closes the
-- second audit writer's chain gap.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS online_eval_scores (
    request_id TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    project TEXT,
    workspace TEXT,
    api_key_id TEXT,
    agent_run_id TEXT,
    operation_id TEXT,
    provider TEXT,
    logical_model TEXT,
    provider_model TEXT,
    experiment_id TEXT,
    experiment_arm TEXT,
    sampling_key TEXT NOT NULL,
    sampling_unit TEXT NOT NULL,
    sample_rate REAL NOT NULL,
    judge_model TEXT NOT NULL,
    score REAL NOT NULL,
    rationale TEXT,
    prompt_truncated INTEGER NOT NULL DEFAULT 0,
    completion_truncated INTEGER NOT NULL DEFAULT 0,
    scored_at_unix INTEGER NOT NULL,
    PRIMARY KEY (request_id, criterion_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_online_eval_scores_trend
    ON online_eval_scores(tenant, criterion_id, scored_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_online_eval_scores_model
    ON online_eval_scores(tenant, logical_model, scored_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_online_eval_scores_sampling_key
    ON online_eval_scores(tenant, sampling_key);

CREATE TABLE IF NOT EXISTS online_eval_regressions (
    claim_key TEXT NOT NULL PRIMARY KEY,
    tenant TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    judge_model TEXT NOT NULL,
    logical_model TEXT,
    baseline_mean REAL NOT NULL,
    baseline_count INTEGER NOT NULL,
    recent_mean REAL NOT NULL,
    recent_count INTEGER NOT NULL,
    drop_amount REAL NOT NULL,
    detected_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_online_eval_regressions_tenant
    ON online_eval_regressions(tenant, detected_at_unix DESC);

CREATE TABLE IF NOT EXISTS experiment_shadow_legs (
    leg_id TEXT NOT NULL PRIMARY KEY,
    client_request_id TEXT NOT NULL,
    experiment_id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    project TEXT,
    workspace TEXT,
    api_key_id TEXT,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT NOT NULL,
    status_code INTEGER,
    error_code TEXT,
    latency_ms INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    cost_usd REAL,
    observed_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_experiment_shadow_legs_experiment
    ON experiment_shadow_legs(experiment_id, observed_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_experiment_shadow_legs_tenant
    ON experiment_shadow_legs(tenant, observed_at_unix DESC);

CREATE TABLE IF NOT EXISTS spend_anomaly_episodes (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    signal TEXT NOT NULL,
    severity TEXT NOT NULL,
    peak_severity TEXT NOT NULL,
    window_start_unix INTEGER NOT NULL,
    window_secs INTEGER NOT NULL,
    opened_at_unix INTEGER NOT NULL,
    last_seen_unix INTEGER NOT NULL,
    resolved_at_unix INTEGER,
    windows_seen INTEGER NOT NULL DEFAULT 1,
    notified_count INTEGER NOT NULL DEFAULT 0,
    last_notified_unix INTEGER,
    observed_usd REAL NOT NULL,
    baseline_usd REAL,
    threshold_usd REAL,
    bound_by TEXT,
    baseline_windows INTEGER,
    active_windows INTEGER,
    projected_usd REAL,
    budget_usd REAL,
    period_month TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_spend_anomaly_open
    ON spend_anomaly_episodes(scope_type, scope_id, signal)
    WHERE resolved_at_unix IS NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_spend_anomaly_scope_seen
    ON spend_anomaly_episodes(scope_id, last_seen_unix);

CREATE INDEX IF NOT EXISTS idx_tenant_spend_anomaly_seen
    ON spend_anomaly_episodes(last_seen_unix);

-- The managed-worker compliance evidence follows the session's tenant object.
CREATE TABLE IF NOT EXISTS managed_worker_isolation_evidence (
    id TEXT PRIMARY KEY,
    occurred_at_unix INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_managed_worker_isolation_evidence_occurred
    ON managed_worker_isolation_evidence(occurred_at_unix, id);

-- A durable intent for the derived CONTROL projection. The tenant usage batch
-- inserts this row atomically with the additive rollups, so a control outage
-- cannot leave the object with no record of which snapshot still needs repair.
CREATE TABLE IF NOT EXISTS usage_projection_retries (
    source_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    occurred_at_unix INTEGER NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tenant_usage_projection_retries_due
    ON usage_projection_retries(next_attempt_unix, source_id);

-- One append-only chain per tenant. The empty chain key remains control-owned
-- for platform/unattributed mutations.
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    agent_run_id TEXT,
    tenant TEXT NOT NULL,
    occurred_at_unix INTEGER NOT NULL,
    audit_json TEXT NOT NULL DEFAULT '{}',
    chain_key TEXT NOT NULL,
    seq INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL,
    UNIQUE (chain_key, seq)
);

CREATE INDEX IF NOT EXISTS idx_tenant_audit_events_agent_run
    ON audit_events(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_tenant_audit_events_occurred
    ON audit_events(occurred_at_unix);

CREATE INDEX IF NOT EXISTS idx_tenant_audit_events_chain_head
    ON audit_events(chain_key, seq DESC);
