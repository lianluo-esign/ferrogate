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

CREATE TABLE IF NOT EXISTS managed_worker_templates (
    id TEXT PRIMARY KEY,
    framework_adapter TEXT NOT NULL,
    isolation_backend_kind TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    max_tenant_sessions BIGINT,
    max_workspace_sessions BIGINT,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_templates_enabled_adapter
    ON managed_worker_templates(enabled, framework_adapter);

CREATE TABLE IF NOT EXISTS agent_worker_instances (
    id TEXT PRIMARY KEY,
    process_name TEXT NOT NULL,
    host_id TEXT,
    worker_version TEXT,
    status TEXT NOT NULL,
    started_at_unix BIGINT NOT NULL,
    last_seen_at_unix BIGINT,
    process_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_agent_worker_instances_status_seen
    ON agent_worker_instances(status, last_seen_at_unix DESC);

CREATE TABLE IF NOT EXISTS managed_worker_sessions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    worker_template_id TEXT NOT NULL REFERENCES managed_worker_templates(id),
    agent_worker_instance_id TEXT REFERENCES agent_worker_instances(id),
    status TEXT NOT NULL,
    isolation_backend_kind TEXT NOT NULL,
    microvm_id TEXT,
    capability_envelope_id TEXT NOT NULL,
    requested_at_unix BIGINT NOT NULL,
    started_at_unix BIGINT,
    completed_at_unix BIGINT,
    cleanup_completed_at_unix BIGINT,
    capability_envelope_json JSONB NOT NULL DEFAULT '{}'::JSONB,
    resource_limits_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_tenant_status
    ON managed_worker_sessions(tenant, status, requested_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_workspace_status
    ON managed_worker_sessions(workspace_id, status, requested_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_agent_worker
    ON managed_worker_sessions(agent_worker_instance_id, requested_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_run
    ON managed_worker_sessions(run_id);

CREATE TABLE IF NOT EXISTS managed_worker_lifecycle_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES managed_worker_sessions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    agent_worker_instance_id TEXT REFERENCES agent_worker_instances(id),
    status TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    occurred_at_unix BIGINT NOT NULL,
    evidence_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_lifecycle_session_time
    ON managed_worker_lifecycle_events(session_id, occurred_at_unix ASC);

CREATE INDEX IF NOT EXISTS idx_managed_worker_lifecycle_tenant_time
    ON managed_worker_lifecycle_events(tenant, occurred_at_unix DESC);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_selections (
    session_id TEXT PRIMARY KEY REFERENCES managed_worker_sessions(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    agent_worker_instance_id TEXT REFERENCES agent_worker_instances(id),
    backend_name TEXT NOT NULL,
    backend_version TEXT NOT NULL,
    backend_kind TEXT NOT NULL,
    host_lifecycle_owner TEXT NOT NULL,
    gateway_controls_backend BOOLEAN NOT NULL,
    capability_envelope_id TEXT NOT NULL,
    selected_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_selection_backend
    ON managed_worker_isolation_selections(backend_kind, selected_at_unix DESC);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_policies (
    session_id TEXT PRIMARY KEY REFERENCES managed_worker_sessions(id) ON DELETE CASCADE,
    cpu_count INTEGER NOT NULL,
    memory_mib INTEGER NOT NULL,
    disk_mib INTEGER NOT NULL,
    max_runtime_millis BIGINT,
    direct_public_egress BOOLEAN NOT NULL,
    gateway_control_channel BOOLEAN NOT NULL,
    governed_egress BOOLEAN NOT NULL,
    read_only_rootfs BOOLEAN NOT NULL,
    writable_workspace BOOLEAN NOT NULL,
    host_path_mounts BOOLEAN NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_policy_egress
    ON managed_worker_isolation_policies(direct_public_egress, governed_egress);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_evidence (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES managed_worker_sessions(id) ON DELETE CASCADE,
    lifecycle_event_id TEXT NOT NULL REFERENCES managed_worker_lifecycle_events(id) ON DELETE CASCADE,
    run_id TEXT NOT NULL,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    agent_worker_instance_id TEXT REFERENCES agent_worker_instances(id),
    isolation_instance_id TEXT,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    failure_reason TEXT,
    occurred_at_unix BIGINT NOT NULL,
    evidence_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_evidence_session_time
    ON managed_worker_isolation_evidence(session_id, occurred_at_unix ASC);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_evidence_outcome
    ON managed_worker_isolation_evidence(outcome, occurred_at_unix DESC);

CREATE TABLE IF NOT EXISTS self_hosted_worker_registrations (
    id TEXT PRIMARY KEY,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    worker_name TEXT NOT NULL,
    status TEXT NOT NULL,
    identity_fingerprint TEXT NOT NULL,
    identity_expires_at_unix BIGINT,
    orchestration_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    registered_at_unix BIGINT NOT NULL,
    last_seen_at_unix BIGINT,
    trust_level TEXT NOT NULL,
    capability_envelope_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_registrations_tenant_status
    ON self_hosted_worker_registrations(tenant, status, last_seen_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_registrations_workspace_status
    ON self_hosted_worker_registrations(workspace_id, status, last_seen_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_registrations_identity
    ON self_hosted_worker_registrations(identity_fingerprint);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_registrations_identity_expiry
    ON self_hosted_worker_registrations(identity_expires_at_unix);

ALTER TABLE self_hosted_worker_registrations
    ADD COLUMN IF NOT EXISTS identity_expires_at_unix BIGINT;

CREATE TABLE IF NOT EXISTS self_hosted_worker_heartbeats (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES self_hosted_worker_registrations(id) ON DELETE CASCADE,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reported_at_unix BIGINT NOT NULL,
    observed_at_unix BIGINT NOT NULL,
    heartbeat_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_heartbeats_worker_time
    ON self_hosted_worker_heartbeats(worker_id, reported_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_heartbeats_tenant_time
    ON self_hosted_worker_heartbeats(tenant, reported_at_unix DESC);

CREATE TABLE IF NOT EXISTS self_hosted_worker_telemetry_events (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES self_hosted_worker_registrations(id) ON DELETE CASCADE,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    session_id TEXT,
    run_id TEXT,
    kind TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    occurred_at_unix BIGINT NOT NULL,
    ingested_at_unix BIGINT NOT NULL,
    event_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_telemetry_worker_time
    ON self_hosted_worker_telemetry_events(worker_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_telemetry_run_time
    ON self_hosted_worker_telemetry_events(run_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_telemetry_tenant_kind_time
    ON self_hosted_worker_telemetry_events(tenant, kind, occurred_at_unix DESC);

CREATE TABLE IF NOT EXISTS self_hosted_worker_artifacts (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES self_hosted_worker_registrations(id) ON DELETE CASCADE,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    artifact_name TEXT NOT NULL,
    content_type TEXT,
    size_bytes BIGINT NOT NULL,
    trust_level TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    artifact_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_artifacts_run
    ON self_hosted_worker_artifacts(run_id, created_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_artifacts_worker_time
    ON self_hosted_worker_artifacts(worker_id, created_at_unix DESC);

CREATE TABLE IF NOT EXISTS self_hosted_worker_checkpoints (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES self_hosted_worker_registrations(id) ON DELETE CASCADE,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    checkpoint_name TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    trust_level TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    checkpoint_json JSONB NOT NULL DEFAULT '{}'::JSONB
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_checkpoints_run
    ON self_hosted_worker_checkpoints(run_id, created_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_checkpoints_worker_time
    ON self_hosted_worker_checkpoints(worker_id, created_at_unix DESC);

CREATE TABLE IF NOT EXISTS self_hosted_run_dispatches (
    dispatch_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    tenant TEXT,
    workspace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    framework_adapter TEXT NOT NULL,
    workload_ref TEXT NOT NULL,
    queued_at_unix BIGINT NOT NULL,
    assigned_worker_id TEXT REFERENCES self_hosted_worker_registrations(id) ON DELETE SET NULL,
    lease_id TEXT,
    lease_expires_at_unix BIGINT,
    attempt BIGINT NOT NULL DEFAULT 0,
    acknowledged_status TEXT,
    acknowledged_at_unix BIGINT
);

CREATE TABLE IF NOT EXISTS self_hosted_run_dispatch_capabilities (
    dispatch_id TEXT NOT NULL REFERENCES self_hosted_run_dispatches(dispatch_id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    PRIMARY KEY (dispatch_id, capability)
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatches_tenant_queue
    ON self_hosted_run_dispatches(tenant, acknowledged_status, queued_at_unix ASC);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatches_worker_lease
    ON self_hosted_run_dispatches(assigned_worker_id, lease_expires_at_unix);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatches_run
    ON self_hosted_run_dispatches(run_id);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatch_capabilities_capability
    ON self_hosted_run_dispatch_capabilities(capability, dispatch_id);

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

-- Added after the multi-tenant hierarchy (TOK-11) introduced workspace_id on
-- the Rust TenantContext struct; this column was missing here, so every
-- metering event silently dropped workspace attribution when persisted.
ALTER TABLE tenant_contexts
    ADD COLUMN IF NOT EXISTS workspace_id TEXT;

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

-- P1-4: settled cost and request latency, added alongside usage_monthly_rollups.
ALTER TABLE metering_events
    ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION;
ALTER TABLE metering_events
    ADD COLUMN IF NOT EXISTS latency_ms BIGINT;

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

-- P1-4: per-scope, per-calendar-month cost/usage rollup across the same
-- tenant/project/workspace/key hierarchy P1-3's quota_policies uses
-- (scope_type reuses that enum). One row per (period_month, scope_type,
-- scope_id); incremented on every settled request. This is the read side of
-- "current month cumulative cost for scope X" for monthly budget
-- enforcement, and the source for the usage/cost report API.
CREATE TABLE IF NOT EXISTS usage_monthly_rollups (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'project', 'workspace', 'key')),
    scope_id TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (period_month, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_usage_monthly_rollups_scope
    ON usage_monthly_rollups(scope_type, scope_id, period_month);

CREATE INDEX IF NOT EXISTS idx_usage_monthly_rollups_period
    ON usage_monthly_rollups(period_month);

-- Multi-tenant hierarchy: Tenant -> Project -> Workspace.
-- Virtual API keys bind to a workspace and resolve upward to project_id and
-- tenant_id for routing, quota, metering, and audit.
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_projects_tenant
    ON projects(tenant_id);

CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'default',
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (project_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_workspaces_project
    ON workspaces(project_id);

CREATE INDEX IF NOT EXISTS idx_workspaces_tenant
    ON workspaces(tenant_id);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last4 TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    scopes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    rotated_at_unix BIGINT,
    expires_at_unix BIGINT,
    revoked_at_unix BIGINT
);

-- Per-key allow-lists and budget/rate fields, added after the initial
-- 010_virtual_api_keys migration shipped without them; the Rust
-- `StoredApiKey` struct always carried these fields, but the Postgres/
-- Supabase backend silently dropped them on every read-back until now.
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS allowed_models_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS allowed_providers_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS monthly_token_budget BIGINT;
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS request_limit_per_minute BIGINT;

CREATE INDEX IF NOT EXISTS idx_api_keys_workspace
    ON api_keys(workspace_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_project
    ON api_keys(tenant_id, project_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
    ON api_keys(key_prefix);

-- Human admin-console identities (issue #157). Distinct from api_keys, which
-- model machine/tenant-level gateway access -- admin_users are the people who
-- sign in to the admin console to manage tenants/workspaces/keys/policies.
CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    superadmin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    last_login_at_unix BIGINT,
    disabled_at_unix BIGINT
);

-- A user may belong to more than one tenant account, each with its own role.
CREATE TABLE IF NOT EXISTS admin_user_tenant_memberships (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_user
    ON admin_user_tenant_memberships(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_tenant
    ON admin_user_tenant_memberships(tenant_id);

-- Refresh tokens are stored hashed (never plaintext) so a durable-storage
-- read cannot itself mint a valid session; revocation/rotation just marks a
-- row instead of deleting it, preserving an audit trail.
CREATE TABLE IF NOT EXISTS admin_user_refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    expires_at_unix BIGINT NOT NULL,
    revoked_at_unix BIGINT
);

CREATE INDEX IF NOT EXISTS idx_admin_user_refresh_tokens_user
    ON admin_user_refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_user_refresh_tokens_hash
    ON admin_user_refresh_tokens(token_hash);

-- Quota/rate-limit policy attached to a scope in the tenant -> project ->
-- workspace -> key hierarchy. Resolution merges key -> workspace -> project
-- -> tenant: the nearest defined value overrides, but may not exceed the
-- cap set by an ancestor scope; model_allowlist is the intersection of every
-- scope in the chain that defines one.
CREATE TABLE IF NOT EXISTS quota_policies (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'project', 'workspace', 'key')),
    scope_id TEXT NOT NULL,
    model_allowlist_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    rpm_limit BIGINT,
    tpm_limit BIGINT,
    monthly_budget_usd DOUBLE PRECISION,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_quota_policies_scope
    ON quota_policies(scope_type, scope_id);

-- Percent-of-monthly_budget_usd tiers (e.g. [75, 90, 95], issue #170) that
-- each fire a one-time webhook notification strictly before the 100% hard
-- deny in AppState::monthly_budget_exceeded. Added via ALTER (not the
-- CREATE TABLE above) so this migration stays idempotent against
-- already-provisioned quota_policies tables.
ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS alert_threshold_pcts_json JSONB NOT NULL DEFAULT '[]'::jsonb;

-- budget_alert_notifications: idempotency ledger for issue #170 -- exactly
-- one row per (scope, period, tier) means a threshold fires its webhook
-- once per billing period, not on every subsequent request after crossing
-- it. The deterministic id (see budget_alert_notification_id in
-- ferrogate-storage) makes "insert if absent" the natural check.
CREATE TABLE IF NOT EXISTS budget_alert_notifications (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'project', 'workspace', 'key')),
    scope_id TEXT NOT NULL,
    period_month TEXT NOT NULL,
    threshold_pct SMALLINT NOT NULL,
    notified_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (scope_type, scope_id, period_month, threshold_pct)
);

-- Arbitrary caller-supplied request metadata (issue #171): tags a settled
-- request beyond the built-in tenant/project/workspace/key scope chain, so
-- a reseller platform can attribute cost to its own end-customer id,
-- feature flag, or experiment arm. Bounded at request-ingress time (see
-- ferrogate_billing::validate_request_metadata), not here.
ALTER TABLE metering_events
    ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb;

-- usage_metadata_rollups: per-calendar-month usage/cost rollup keyed by an
-- arbitrary metadata key/value pair (issue #171), aggregated alongside (not
-- instead of) usage_monthly_rollups. A settled request with N metadata
-- pairs increments N of these rows -- mirrors how one request fans out
-- into up to four usage_monthly_rollups rows (one per scope level).
CREATE TABLE IF NOT EXISTS usage_metadata_rollups (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    metadata_key TEXT NOT NULL,
    metadata_value TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (period_month, metadata_key, metadata_value)
);

CREATE INDEX IF NOT EXISTS idx_usage_metadata_rollups_key
    ON usage_metadata_rollups(metadata_key, period_month);

-- plans: sellable subscription tiers (issue #168). A named bundle of feature
-- flags plus default quota values that seed the effective-quota merge chain
-- as its floor, below any explicit scope-level quota_policies row. Shared
-- across tenants, like quota_policies is shared across scopes.
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    mcp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    self_hosted_workers_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    admin_console_seats BIGINT,
    default_model_allowlist_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    default_rpm_limit BIGINT,
    default_tpm_limit BIGINT,
    default_monthly_budget_usd DOUBLE PRECISION,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

-- Gates /v1/assets/* (issue #176/#177) the same way mcp_enabled gates MCP
-- tool governance. Added via ALTER rather than the CREATE TABLE above so
-- this migration file stays idempotent against already-provisioned plans
-- tables (mirrors the tenants.plan_id ALTER pattern just below).
ALTER TABLE plans
    ADD COLUMN IF NOT EXISTS asset_hosting_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE plans
    ADD COLUMN IF NOT EXISTS default_asset_storage_quota_bytes BIGINT;

-- Every tenant lands on this plan unless explicitly assigned another one --
-- seeded before the `tenants.plan_id` foreign key below is added, since that
-- column's default value must reference a row that already exists.
INSERT INTO plans (id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats)
VALUES ('free', 'Free', 'free', FALSE, FALSE, 1)
ON CONFLICT (id) DO NOTHING;

-- Unlike mcp_enabled/self_hosted_workers_enabled (left FALSE above), a small
-- free asset-hosting quota is a deliberate self-serve growth lever (issue
-- #176/#177), matching the in-memory default_free_plan(). A separate UPDATE
-- (rather than folding into the INSERT) so re-running this migration also
-- backfills the value onto a 'free' row created before these columns
-- existed -- the ADD COLUMN default above would otherwise leave it FALSE.
UPDATE plans
    SET asset_hosting_enabled = TRUE, default_asset_storage_quota_bytes = 10485760
    WHERE id = 'free';

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS plan_id TEXT NOT NULL DEFAULT 'free' REFERENCES plans(id);

-- stored_assets: tenant-scoped static asset storage (issue #176), the
-- foundation of the unified agent-asset hosting epic (#175) -- CLI tool
-- packages, MCP connection manifests, Skill bundles, static sites, and
-- config files all share this one table instead of being special-cased.
--
-- `content` stores file bytes inline (BYTEA, which Postgres TOASTs/
-- compresses transparently above ~2KB) rather than referencing a separate
-- object-storage bucket, so every asset operation is a single Postgres/
-- Supabase round trip with no external bucket credentials required. The
-- `size_bytes` check constraint caps a single asset at 10 MiB as a hard
-- backstop until a real object-storage backend replaces inline BYTEA for
-- larger files.
--
-- Isolation is enforced at the application layer via `tenant_id` (same
-- model as every other multi-tenant table in this schema -- tenants,
-- projects, workspaces, quota_policies, plans -- none of which use
-- Postgres RLS today, since FerroGate connects as one shared service role
-- rather than issuing per-tenant JWTs that `auth.uid()`-style RLS expects).
-- Genuine RLS/S3-scoped-credential isolation is tracked as a follow-up in
-- issue #179 once this moves to real Supabase Storage buckets.
CREATE TABLE IF NOT EXISTS stored_assets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    project_id TEXT,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 10485760),
    content BYTEA NOT NULL,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (tenant_id, asset_type, name, version)
);

-- Composite index: leftmost prefix (tenant_id, tenant_id+asset_type) covers
-- both "list everything for a tenant" and "list one asset_type for a
-- tenant", and the full column set covers the ORDER BY name, version list
-- query without a separate sort step.
CREATE INDEX IF NOT EXISTS idx_stored_assets_tenant_type_name
    ON stored_assets(tenant_id, asset_type, name, version);

-- permissions / roles / tenant_role_bindings: tenant-level entitlement
-- system (issue #182). A permission is a dynamically-definable,
-- finest-grained capability unit (string-keyed, e.g. "assets.host") --
-- creating a new one is a plain INSERT, not a migration. A role is a
-- named, horizontally-extensible bundle of permission keys (JSONB array,
-- same pattern as plans.default_model_allowlist_json). A tenant may hold
-- multiple roles (tenant_role_bindings is many-to-many); its effective
-- permission set is the union of every bound role's permission_keys.
-- Granting a tenant a new capability becomes "bind a role" -- one write --
-- instead of adding a new plans.* boolean column + migration.
--
-- Isolation note: like every other multi-tenant table in this schema
-- (tenants, projects, workspaces, quota_policies, plans, stored_assets),
-- there is no Postgres RLS here -- FerroGate enforces tenant scoping at
-- the application layer since it connects as one shared service role, not
-- per-tenant JWTs.
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permission_keys_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE TABLE IF NOT EXISTS tenant_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    role_id TEXT NOT NULL REFERENCES roles(id),
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    UNIQUE (tenant_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_role_bindings_tenant
    ON tenant_role_bindings(tenant_id);

-- No seed data here deliberately: unlike `plans` (which needs a 'free' row
-- to exist before ALTER TABLE tenants can default plan_id to it),
-- permissions/roles have no bootstrap dependency, and issue #182's own
-- closed-loop E2E test (tests/rbac_api.rs) creates its own permission/role
-- through the admin API -- a stronger proof of "no code change required"
-- than a SQL fixture would be.

-- billing_ledger: the settled money/credit flow produced by the standalone
-- billing microservice (issue #129). Each row is one priced charge derived
-- from a single usage event. `entry_json` carries the full LedgerEntry for
-- fidelity; the flattened numeric columns exist for aggregation/reporting.
-- Append-only and idempotent on `id` (the request/trace-derived key) so a
-- retried charge never double-bills.
CREATE TABLE IF NOT EXISTS billing_ledger (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    organization_id TEXT,
    project_id TEXT,
    workspace_id TEXT,
    api_key_id TEXT,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT NOT NULL,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    total_tokens BIGINT NOT NULL DEFAULT 0,
    usage_source TEXT NOT NULL DEFAULT 'provider_usage',
    status_code INTEGER NOT NULL DEFAULT 0,
    input_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    output_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    total_cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    currency TEXT NOT NULL DEFAULT 'USD',
    credits DOUBLE PRECISION NOT NULL DEFAULT 0,
    entry_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at_unix BIGINT,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_tenant_time
    ON billing_ledger(organization_id, project_id, occurred_at_unix);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_model_provider
    ON billing_ledger(provider, provider_model);

-- billing_report_outbox: durable delivery queue for gateway -> billing service
-- usage reports (issue #137). Every settled request is enqueued here in the
-- same path that persists the metering event; a background sweeper drains it,
-- POSTs each event to the billing service (idempotent on the ledger entry id),
-- and deletes the row on success — so a charge survives a billing outage or a
-- gateway restart rather than being lost by a fire-and-forget POST. `id` is the
-- ledger entry id so re-enqueue is naturally idempotent.
CREATE TABLE IF NOT EXISTS billing_report_outbox (
    id TEXT PRIMARY KEY,
    event_json JSONB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix BIGINT NOT NULL,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT),
    updated_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);

-- dead_lettered_at_unix (issue #143): a permanently-failing delivery (e.g. the
-- billing service's rate card has no rule for the event's model, a 4xx that
-- can never succeed on retry) is marked here after MAX_BILLING_OUTBOX_ATTEMPTS
-- instead of being rescheduled forever. The row is kept (not deleted) for
-- operator inspection via the dead-letter admin API, and excluded from
-- `list_due_billing_reports` so it stops consuming sweeper batch capacity.
ALTER TABLE billing_report_outbox
    ADD COLUMN IF NOT EXISTS dead_lettered_at_unix BIGINT;

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_due
    ON billing_report_outbox(next_attempt_unix);

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_dead_lettered
    ON billing_report_outbox(dead_lettered_at_unix)
    WHERE dead_lettered_at_unix IS NOT NULL;

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

INSERT INTO storage_schema_migrations (version, name)
VALUES (4, '004_supabase_managed_worker_lifecycle')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (5, '005_supabase_self_hosted_worker_lifecycle')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (6, '006_self_hosted_worker_identity_expiry')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (7, '007_self_hosted_run_dispatch_state')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (8, '008_managed_worker_isolation_evidence')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (9, '009_multi_tenant_hierarchy')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (10, '010_virtual_api_keys')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (11, '011_quota_policies')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (12, '012_usage_cost_accounting')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (13, '013_billing_ledger')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (14, '014_billing_report_outbox')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (15, '015_billing_report_outbox_dead_letter')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (16, '016_admin_console_users')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (17, '017_plans')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (18, '018_stored_assets')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (19, '019_rbac_tenant_entitlements')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (20, '020_budget_alert_notifications')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;

INSERT INTO storage_schema_migrations (version, name)
VALUES (21, '021_usage_metadata_rollups')
ON CONFLICT (version) DO UPDATE
SET name = EXCLUDED.name;
