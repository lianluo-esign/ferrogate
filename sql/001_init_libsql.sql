-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-11
-- description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

CREATE TABLE IF NOT EXISTS control_plane_resources (
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (resource_kind, resource_id)
);

CREATE INDEX IF NOT EXISTS idx_control_plane_resources_kind
    ON control_plane_resources(resource_kind, resource_id);

CREATE TABLE IF NOT EXISTS request_logs (
    request_id TEXT PRIMARY KEY,
    trace_id TEXT,
    tenant_id TEXT,
    route TEXT,
    upstream TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    request_body_logged INTEGER NOT NULL DEFAULT 0,
    response_body_logged INTEGER NOT NULL DEFAULT 0,
    logged_at_unix INTEGER NOT NULL,
    document_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_request_logs_logged_at
    ON request_logs(logged_at_unix DESC, request_id);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    actor_id TEXT,
    target_kind TEXT,
    target_id TEXT,
    outcome TEXT NOT NULL,
    occurred_at_unix INTEGER NOT NULL,
    document_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at
    ON audit_events(occurred_at_unix DESC, event_id);

CREATE TABLE IF NOT EXISTS billing_events (
    event_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    subject TEXT,
    model TEXT,
    provider TEXT,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_microusd INTEGER,
    occurred_at_unix INTEGER NOT NULL,
    document_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_billing_events_tenant_time
    ON billing_events(tenant_id, occurred_at_unix DESC, event_id);

CREATE TABLE IF NOT EXISTS usage_aggregates (
    aggregate_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    subject TEXT,
    model TEXT,
    provider TEXT,
    window_start_unix INTEGER NOT NULL,
    window_end_unix INTEGER NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    document_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_usage_aggregates_tenant_window
    ON usage_aggregates(tenant_id, window_start_unix, window_end_unix);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_libsql');
