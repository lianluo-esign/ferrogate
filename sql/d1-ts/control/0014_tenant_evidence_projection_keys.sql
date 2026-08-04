-- ===========================================================================
-- Tenant-qualified compatibility projection keys (#859)
--
-- The control copies of request_logs, agent_runs and agent_run_events are
-- derived fleet projections. Their business ids are not account-global:
-- request ids can be supplied by a client and run/event ids are scoped to the
-- tenant object that owns them. A global PRIMARY KEY therefore lets one
-- tenant overwrite another tenant's projection row.
--
-- `projection_key` is deliberately separate from the logical id used by
-- existing joins and API documents. Writers build it as:
--
--     length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id
--
-- The length prefix keeps tenant ids containing ':' unambiguous. Runtime
-- writers use the same format in TypeScript. Empty and NULL tenant values are
-- the single unscoped/platform namespace.
--
-- SQLite cannot change a PRIMARY KEY in place, so the migration rebuilds the
-- three tables. The old columns and indexes are preserved; rows already in a
-- control database are backfilled before the old tables are removed.
-- ===========================================================================

DROP INDEX IF EXISTS idx_agent_runs_request;
DROP INDEX IF EXISTS idx_agent_runs_started;
DROP INDEX IF EXISTS idx_agent_run_events_run_time;
DROP INDEX IF EXISTS idx_agent_run_events_request;
DROP INDEX IF EXISTS idx_request_logs_agent_run;
DROP INDEX IF EXISTS idx_request_logs_started;
DROP INDEX IF EXISTS idx_request_logs_tenant_started;
DROP INDEX IF EXISTS idx_request_logs_model_provider_started;
DROP INDEX IF EXISTS idx_request_logs_trace;
DROP INDEX IF EXISTS idx_request_logs_delegation_root;
DROP INDEX IF EXISTS idx_request_logs_experiment;

ALTER TABLE agent_runs RENAME TO agent_runs_projection_legacy;
CREATE TABLE agent_runs (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tenant TEXT,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    run_json TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO agent_runs (
    projection_key, id, request_id, tenant, started_at_unix, completed_at_unix, run_json
)
SELECT
    length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id,
    id, request_id, tenant, started_at_unix, completed_at_unix, run_json
FROM agent_runs_projection_legacy;
DROP TABLE agent_runs_projection_legacy;

CREATE INDEX idx_agent_runs_request
    ON agent_runs(request_id);
CREATE INDEX idx_agent_runs_started
    ON agent_runs(started_at_unix);

ALTER TABLE agent_run_events RENAME TO agent_run_events_projection_legacy;
CREATE TABLE agent_run_events (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tenant TEXT,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO agent_run_events (
    projection_key, id, run_id, request_id, tenant, occurred_at_unix, event_json
)
SELECT
    length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id,
    id, run_id, request_id, tenant, occurred_at_unix, event_json
FROM agent_run_events_projection_legacy;
DROP TABLE agent_run_events_projection_legacy;

CREATE INDEX idx_agent_run_events_run_time
    ON agent_run_events(run_id, occurred_at_unix);
CREATE INDEX idx_agent_run_events_request
    ON agent_run_events(request_id);

ALTER TABLE request_logs RENAME TO request_logs_projection_legacy;
CREATE TABLE request_logs (
    projection_key TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    agent_run_id TEXT,
    tenant TEXT,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    request_json TEXT NOT NULL DEFAULT '{}',
    trace_id TEXT,
    project TEXT,
    workspace TEXT,
    api_key_id TEXT,
    route TEXT,
    provider TEXT,
    logical_model TEXT,
    provider_model TEXT,
    status_code INTEGER,
    error_code TEXT,
    cache_status TEXT,
    latency_ms INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    guardrail_verdict TEXT,
    guardrail_policy_id TEXT,
    streamed INTEGER NOT NULL DEFAULT 0,
    delegation_chain TEXT,
    delegation_root TEXT,
    experiment_id TEXT,
    experiment_arm TEXT
);
INSERT INTO request_logs (
    projection_key, request_id, agent_run_id, tenant, started_at_unix,
    completed_at_unix, request_json, trace_id, project, workspace, api_key_id,
    route, provider, logical_model, provider_model, status_code, error_code,
    cache_status, latency_ms, prompt_tokens, completion_tokens, total_tokens,
    guardrail_verdict, guardrail_policy_id, streamed, delegation_chain,
    delegation_root, experiment_id, experiment_arm
)
SELECT
    length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || request_id,
    request_id, agent_run_id, tenant, started_at_unix, completed_at_unix,
    request_json, trace_id, project, workspace, api_key_id, route, provider,
    logical_model, provider_model, status_code, error_code, cache_status,
    latency_ms, prompt_tokens, completion_tokens, total_tokens,
    guardrail_verdict, guardrail_policy_id, streamed, delegation_chain,
    delegation_root, experiment_id, experiment_arm
FROM request_logs_projection_legacy;
DROP TABLE request_logs_projection_legacy;

CREATE INDEX idx_request_logs_agent_run
    ON request_logs(agent_run_id);
CREATE INDEX idx_request_logs_started
    ON request_logs(started_at_unix);
CREATE INDEX idx_request_logs_tenant_started
    ON request_logs(tenant, started_at_unix DESC);
CREATE INDEX idx_request_logs_model_provider_started
    ON request_logs(logical_model, provider, started_at_unix DESC);
CREATE INDEX idx_request_logs_trace
    ON request_logs(trace_id);
CREATE INDEX idx_request_logs_delegation_root
    ON request_logs(tenant, delegation_root, started_at_unix DESC);
CREATE INDEX idx_request_logs_experiment
    ON request_logs(experiment_id, experiment_arm, started_at_unix DESC);
