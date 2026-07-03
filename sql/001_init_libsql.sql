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

-- Multi-tenant hierarchy: Tenant -> Project -> Workspace.
-- Virtual API keys bind to a workspace and resolve upward to project_id and
-- tenant_id for routing, quota, metering, and audit.
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
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
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
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
    enabled INTEGER NOT NULL DEFAULT 1,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    rotated_at_unix INTEGER,
    expires_at_unix INTEGER,
    revoked_at_unix INTEGER
);

CREATE INDEX IF NOT EXISTS idx_api_keys_workspace
    ON api_keys(workspace_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_project
    ON api_keys(tenant_id, project_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix
    ON api_keys(key_prefix);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_libsql');

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (9, '009_multi_tenant_hierarchy');

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (10, '010_virtual_api_keys');
