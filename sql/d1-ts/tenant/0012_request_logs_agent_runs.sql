-- ===========================================================================
-- Tenant-private request evidence (#859, #831)
--
-- These tables are authoritative in the tenant's SQLite-backed
-- TenantDataObject. The same-named CONTROL tables are compatibility
-- projections for existing fleet joins only; they are never a fallback for
-- this database and may be stale.
--
-- Every row is physically attributed to this object. Unattributed/platform
-- request logs are not inserted here and remain control-projection-only.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS request_logs (
    request_id TEXT PRIMARY KEY,
    trace_id TEXT,
    agent_run_id TEXT,
    delegation_chain TEXT,
    delegation_root TEXT,
    experiment_id TEXT,
    experiment_arm TEXT,
    tenant TEXT NOT NULL,
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
    guardrail_verdict TEXT NOT NULL DEFAULT 'not_screened',
    guardrail_policy_id TEXT,
    streamed INTEGER NOT NULL DEFAULT 0,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    request_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_request_logs_started
    ON request_logs(tenant, started_at_unix DESC, request_id ASC);

CREATE INDEX IF NOT EXISTS idx_tenant_request_logs_agent_run
    ON request_logs(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_tenant_request_logs_trace
    ON request_logs(trace_id);

CREATE INDEX IF NOT EXISTS idx_tenant_request_logs_model_provider_started
    ON request_logs(logical_model, provider, started_at_unix DESC);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    run_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_agent_runs_request
    ON agent_runs(request_id);

CREATE INDEX IF NOT EXISTS idx_tenant_agent_runs_started
    ON agent_runs(started_at_unix ASC, id ASC);

CREATE TABLE IF NOT EXISTS agent_run_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL DEFAULT '',
    tenant TEXT NOT NULL,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_agent_run_events_run_time
    ON agent_run_events(run_id, occurred_at_unix ASC, id ASC);

CREATE INDEX IF NOT EXISTS idx_tenant_agent_run_events_request
    ON agent_run_events(request_id);
