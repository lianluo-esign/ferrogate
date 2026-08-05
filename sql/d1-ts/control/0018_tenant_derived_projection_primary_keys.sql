-- ===========================================================================
-- Make the #852 control copies real tenant-qualified projections.
--
-- `0017` added the projection key and backfilled it, but SQLite cannot change
-- an existing PRIMARY KEY with ALTER TABLE. Leaving the old logical key in
-- place would still reject (or overwrite, for a broad UPSERT) two tenants
-- that reuse a request, audit, leg, or episode id. Rebuild the five tables so
-- the projection key is the physical arbiter while the logical ids remain
-- available to existing fleet joins and API responses.
-- ===========================================================================

-- audit_events ---------------------------------------------------------------
DROP INDEX IF EXISTS ux_audit_events_projection_key;
DROP INDEX IF EXISTS ux_audit_events_chain_seq;
DROP INDEX IF EXISTS idx_audit_events_chain_head;
DROP INDEX IF EXISTS idx_audit_events_agent_run;
DROP INDEX IF EXISTS idx_audit_events_occurred;

ALTER TABLE audit_events RENAME TO audit_events_projection_legacy;
CREATE TABLE audit_events (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    agent_run_id TEXT,
    tenant TEXT,
    occurred_at_unix INTEGER NOT NULL,
    audit_json TEXT NOT NULL DEFAULT '{}',
    chain_key TEXT,
    seq INTEGER,
    prev_hash TEXT,
    row_hash TEXT
);
INSERT INTO audit_events (
    projection_key, id, request_id, agent_run_id, tenant, occurred_at_unix,
    audit_json, chain_key, seq, prev_hash, row_hash
)
SELECT
    projection_key, id, request_id, agent_run_id, tenant, occurred_at_unix,
    audit_json, chain_key, seq, prev_hash, row_hash
FROM audit_events_projection_legacy;
DROP TABLE audit_events_projection_legacy;

CREATE UNIQUE INDEX ux_audit_events_chain_seq
    ON audit_events(chain_key, seq);
CREATE UNIQUE INDEX ux_audit_events_tenant_id
    ON audit_events(tenant, id);
CREATE INDEX idx_audit_events_chain_head
    ON audit_events(chain_key, seq DESC);
CREATE INDEX idx_audit_events_agent_run
    ON audit_events(agent_run_id);
CREATE INDEX idx_audit_events_occurred
    ON audit_events(occurred_at_unix);

-- online_eval_scores ---------------------------------------------------------
DROP INDEX IF EXISTS ux_online_eval_scores_projection_key;
DROP INDEX IF EXISTS idx_online_eval_scores_experiment;
DROP INDEX IF EXISTS idx_online_eval_scores_sampling_key;
DROP INDEX IF EXISTS idx_online_eval_scores_model;
DROP INDEX IF EXISTS idx_online_eval_scores_trend;

ALTER TABLE online_eval_scores RENAME TO online_eval_scores_projection_legacy;
CREATE TABLE online_eval_scores (
    projection_key TEXT PRIMARY KEY,
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
    scored_at_unix INTEGER NOT NULL
);
INSERT INTO online_eval_scores (
    projection_key, request_id, criterion_id, tenant, project, workspace, api_key_id,
    agent_run_id, operation_id, provider, logical_model, provider_model,
    experiment_id, experiment_arm, sampling_key, sampling_unit, sample_rate,
    judge_model, score, rationale, prompt_truncated, completion_truncated,
    scored_at_unix
)
SELECT
    projection_key, request_id, criterion_id, tenant, project, workspace, api_key_id,
    agent_run_id, operation_id, provider, logical_model, provider_model,
    experiment_id, experiment_arm, sampling_key, sampling_unit, sample_rate,
    judge_model, score, rationale, prompt_truncated, completion_truncated,
    scored_at_unix
FROM online_eval_scores_projection_legacy;
DROP TABLE online_eval_scores_projection_legacy;

CREATE UNIQUE INDEX ux_online_eval_scores_tenant_source
    ON online_eval_scores(tenant, request_id, criterion_id);
CREATE INDEX idx_online_eval_scores_trend
    ON online_eval_scores(tenant, criterion_id, scored_at_unix DESC);
CREATE INDEX idx_online_eval_scores_model
    ON online_eval_scores(tenant, logical_model, scored_at_unix DESC);
CREATE INDEX idx_online_eval_scores_sampling_key
    ON online_eval_scores(tenant, sampling_key);
CREATE INDEX idx_online_eval_scores_experiment
    ON online_eval_scores(experiment_id, criterion_id, judge_model, experiment_arm);

-- online_eval_regressions ----------------------------------------------------
DROP INDEX IF EXISTS ux_online_eval_regressions_projection_key;
DROP INDEX IF EXISTS idx_online_eval_regressions_tenant;

ALTER TABLE online_eval_regressions RENAME TO online_eval_regressions_projection_legacy;
CREATE TABLE online_eval_regressions (
    projection_key TEXT PRIMARY KEY,
    claim_key TEXT NOT NULL,
    tenant TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    judge_model TEXT NOT NULL,
    logical_model TEXT,
    baseline_mean REAL NOT NULL,
    baseline_count INTEGER NOT NULL,
    recent_mean REAL NOT NULL,
    recent_count INTEGER NOT NULL,
    drop_amount REAL NOT NULL,
    detected_at_unix INTEGER NOT NULL,
    UNIQUE (claim_key)
);
INSERT INTO online_eval_regressions (
    projection_key, claim_key, tenant, criterion_id, judge_model, logical_model,
    baseline_mean, baseline_count, recent_mean, recent_count, drop_amount,
    detected_at_unix
)
SELECT
    projection_key, claim_key, tenant, criterion_id, judge_model, logical_model,
    baseline_mean, baseline_count, recent_mean, recent_count, drop_amount,
    detected_at_unix
FROM online_eval_regressions_projection_legacy;
DROP TABLE online_eval_regressions_projection_legacy;

CREATE INDEX idx_online_eval_regressions_tenant
    ON online_eval_regressions(tenant, detected_at_unix DESC);

-- experiment_shadow_legs ----------------------------------------------------
DROP INDEX IF EXISTS ux_experiment_shadow_legs_projection_key;
DROP INDEX IF EXISTS idx_experiment_shadow_legs_tenant;
DROP INDEX IF EXISTS idx_experiment_shadow_legs_experiment;

ALTER TABLE experiment_shadow_legs RENAME TO experiment_shadow_legs_projection_legacy;
CREATE TABLE experiment_shadow_legs (
    projection_key TEXT PRIMARY KEY,
    leg_id TEXT NOT NULL,
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
INSERT INTO experiment_shadow_legs (
    projection_key, leg_id, client_request_id, experiment_id, tenant, project,
    workspace, api_key_id, logical_model, provider, provider_model, status_code,
    error_code, latency_ms, prompt_tokens, completion_tokens, total_tokens,
    cost_usd, observed_at_unix
)
SELECT
    projection_key, leg_id, client_request_id, experiment_id, tenant, project,
    workspace, api_key_id, logical_model, provider, provider_model, status_code,
    error_code, latency_ms, prompt_tokens, completion_tokens, total_tokens,
    cost_usd, observed_at_unix
FROM experiment_shadow_legs_projection_legacy;
DROP TABLE experiment_shadow_legs_projection_legacy;

CREATE UNIQUE INDEX ux_experiment_shadow_legs_tenant_source
    ON experiment_shadow_legs(tenant, leg_id);
CREATE INDEX idx_experiment_shadow_legs_experiment
    ON experiment_shadow_legs(experiment_id, observed_at_unix DESC);
CREATE INDEX idx_experiment_shadow_legs_tenant
    ON experiment_shadow_legs(tenant, observed_at_unix DESC);

-- spend_anomaly_episodes -----------------------------------------------------
DROP INDEX IF EXISTS ux_spend_anomaly_episodes_projection_key;
DROP INDEX IF EXISTS idx_tenant_spend_anomaly_open;
DROP INDEX IF EXISTS idx_tenant_spend_anomaly_scope_seen;
DROP INDEX IF EXISTS idx_tenant_spend_anomaly_seen;

ALTER TABLE spend_anomaly_episodes RENAME TO spend_anomaly_episodes_projection_legacy;
CREATE TABLE spend_anomaly_episodes (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
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
INSERT INTO spend_anomaly_episodes (
    projection_key, id, scope_type, scope_id, signal, severity, peak_severity,
    window_start_unix, window_secs, opened_at_unix, last_seen_unix,
    resolved_at_unix, windows_seen, notified_count, last_notified_unix,
    observed_usd, baseline_usd, threshold_usd, bound_by, baseline_windows,
    active_windows, projected_usd, budget_usd, period_month, detail_json
)
SELECT
    projection_key, id, scope_type, scope_id, signal, severity, peak_severity,
    window_start_unix, window_secs, opened_at_unix, last_seen_unix,
    resolved_at_unix, windows_seen, notified_count, last_notified_unix,
    observed_usd, baseline_usd, threshold_usd, bound_by, baseline_windows,
    active_windows, projected_usd, budget_usd, period_month, detail_json
FROM spend_anomaly_episodes_projection_legacy;
DROP TABLE spend_anomaly_episodes_projection_legacy;

CREATE UNIQUE INDEX idx_spend_anomaly_open
    ON spend_anomaly_episodes(scope_type, scope_id, signal)
    WHERE resolved_at_unix IS NULL;
CREATE INDEX idx_spend_anomaly_scope_seen
    ON spend_anomaly_episodes(scope_id, last_seen_unix);
CREATE INDEX idx_spend_anomaly_seen
    ON spend_anomaly_episodes(last_seen_unix);
