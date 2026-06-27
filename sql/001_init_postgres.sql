-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-11
-- description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

CREATE TABLE IF NOT EXISTS control_plane_resources (
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    document_json JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    PRIMARY KEY (resource_kind, resource_id)
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'control_plane_resources'
          AND column_name = 'document_json'
          AND data_type <> 'jsonb'
    ) THEN
        ALTER TABLE control_plane_resources
            ALTER COLUMN document_json TYPE JSONB USING document_json::JSONB;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_control_plane_resources_kind
    ON control_plane_resources(resource_kind, resource_id);

CREATE INDEX IF NOT EXISTS idx_control_plane_resources_document_gin
    ON control_plane_resources USING GIN(document_json);

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    tenant TEXT,
    status TEXT NOT NULL,
    provider TEXT,
    started_at_unix BIGINT NOT NULL,
    completed_at_unix BIGINT,
    run_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant_started
    ON agent_runs(tenant, started_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_agent_runs_request
    ON agent_runs(request_id);

CREATE INDEX IF NOT EXISTS idx_agent_runs_trace
    ON agent_runs(trace_id);

CREATE INDEX IF NOT EXISTS idx_agent_runs_status
    ON agent_runs(status);

CREATE TABLE IF NOT EXISTS agent_run_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    tenant TEXT,
    turn BIGINT NOT NULL,
    kind TEXT NOT NULL,
    target TEXT,
    outcome TEXT,
    occurred_at_unix BIGINT NOT NULL,
    event_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_run_time
    ON agent_run_events(run_id, occurred_at_unix ASC);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_tenant_time
    ON agent_run_events(tenant, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_request
    ON agent_run_events(request_id);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_trace
    ON agent_run_events(trace_id);

CREATE TABLE IF NOT EXISTS request_logs (
    request_id TEXT PRIMARY KEY,
    trace_id TEXT,
    agent_run_id TEXT,
    workflow_id TEXT,
    workflow_version TEXT,
    workflow_node_id TEXT,
    cluster_id TEXT,
    node_id TEXT,
    tenant TEXT,
    route TEXT,
    provider TEXT,
    logical_model TEXT,
    provider_model TEXT,
    gateway_config_id TEXT,
    gateway_config_revision BIGINT,
    status_code INTEGER,
    error_code TEXT,
    cache_status TEXT,
    started_at_unix BIGINT NOT NULL,
    completed_at_unix BIGINT,
    request_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_started
    ON request_logs(tenant, started_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_request_logs_model_provider_started
    ON request_logs(logical_model, provider, started_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_request_logs_trace
    ON request_logs(trace_id);

CREATE INDEX IF NOT EXISTS idx_request_logs_agent_run
    ON request_logs(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_request_logs_status
    ON request_logs(status_code, error_code);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    request_id TEXT,
    trace_id TEXT,
    agent_run_id TEXT,
    workflow_id TEXT,
    workflow_version TEXT,
    workflow_node_id TEXT,
    cluster_id TEXT,
    node_id TEXT,
    actor_api_key_id TEXT,
    tenant TEXT,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,
    occurred_at_unix BIGINT NOT NULL,
    audit_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_time
    ON audit_events(tenant, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_actor_time
    ON audit_events(actor_api_key_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_audit_events_action_outcome
    ON audit_events(action, outcome);

CREATE INDEX IF NOT EXISTS idx_audit_events_request
    ON audit_events(request_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_trace
    ON audit_events(trace_id);

CREATE TABLE IF NOT EXISTS billing_metering_events (
    request_id TEXT PRIMARY KEY,
    trace_id TEXT,
    agent_run_id TEXT,
    workflow_id TEXT,
    workflow_version TEXT,
    workflow_node_id TEXT,
    cluster_id TEXT,
    node_id TEXT,
    tenant TEXT NOT NULL,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    usage_source TEXT NOT NULL,
    status_code INTEGER,
    occurred_at_unix BIGINT NOT NULL,
    event_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_billing_metering_tenant_time
    ON billing_metering_events(tenant, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_billing_metering_model_provider_time
    ON billing_metering_events(logical_model, provider, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_billing_metering_provider_model_time
    ON billing_metering_events(provider, provider_model, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_billing_metering_trace
    ON billing_metering_events(trace_id);

CREATE TABLE IF NOT EXISTS usage_aggregates (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    tenant TEXT,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    usage_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_usage_aggregates_org_project_model_provider
    ON usage_aggregates(organization_id, project_id, logical_model, provider);

CREATE INDEX IF NOT EXISTS idx_usage_aggregates_api_key_model_provider
    ON usage_aggregates(api_key_id, logical_model, provider);

CREATE INDEX IF NOT EXISTS idx_usage_aggregates_tenant_model_provider
    ON usage_aggregates(tenant, logical_model, provider);

CREATE TABLE IF NOT EXISTS tenant_contexts (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    team_id TEXT,
    project_id TEXT,
    user_id TEXT,
    api_key_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_tenant_contexts_org_project
    ON tenant_contexts(organization_id, project_id);

CREATE INDEX IF NOT EXISTS idx_tenant_contexts_api_key
    ON tenant_contexts(api_key_id);

CREATE TABLE IF NOT EXISTS metering_events (
    request_id TEXT PRIMARY KEY,
    tenant_context_id TEXT NOT NULL REFERENCES tenant_contexts(id),
    trace_id TEXT,
    agent_run_id TEXT,
    workflow_id TEXT,
    workflow_version INTEGER,
    workflow_node_id TEXT,
    cluster_id TEXT,
    node_id TEXT,
    status_code INTEGER NOT NULL,
    occurred_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_metering_events_tenant_time
    ON metering_events(tenant_context_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_metering_events_trace
    ON metering_events(trace_id);

CREATE TABLE IF NOT EXISTS metering_event_routes (
    request_id TEXT PRIMARY KEY REFERENCES metering_events(request_id) ON DELETE CASCADE,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT
);

CREATE INDEX IF NOT EXISTS idx_metering_event_routes_model_provider
    ON metering_event_routes(logical_model, provider);

CREATE TABLE IF NOT EXISTS metering_event_usage (
    request_id TEXT PRIMARY KEY REFERENCES metering_events(request_id) ON DELETE CASCADE,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    usage_source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_aggregate_rollups (
    id TEXT PRIMARY KEY,
    tenant_context_id TEXT NOT NULL REFERENCES tenant_contexts(id),
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_usage_rollups_tenant_model_provider
    ON usage_aggregate_rollups(tenant_context_id, logical_model, provider);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL DEFAULT '',
    applied_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

ALTER TABLE storage_schema_migrations
    ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT '';

INSERT INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_postgres')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (2, '002_supabase_control_plane_billing_evidence')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (3, '003_supabase_structured_metering_usage')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;
