-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-07-24
-- description: Cloudflare D1 (SQLite dialect) core control-plane schema for the per-tenant D1 backend (issue #420).
--
-- Ported from the CORE tables of sql/001_init_postgres.sql. Intentional
-- divergences from the Postgres dialect, documented in
-- docs/cloudflare-d1-backend.md:
--   * No RLS policies and no GUC-based tenant scoping: isolation is physical
--     (one D1 database per tenant), so row-level tenant fencing is redundant.
--   * No cross-table FOREIGN KEY constraints: the tenants row for a tenant
--     database lives in the CONTROL database, so intra-database FKs to
--     `tenants` cannot resolve. Referential integrity is enforced at the
--     application layer (e.g. reject-if-referenced deletes).
--   * JSONB columns become TEXT (SQLite stores JSON as text); BIGINT becomes
--     INTEGER (SQLite integers are 64-bit); BOOLEAN becomes INTEGER 0/1.
--   * Applied over the D1 HTTP query API as one multi-statement batch by the
--     provisioning path (D1ControlPlaneStore::provision_tenant_database).

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

-- Multi-tenant hierarchy: Tenant -> Project -> Workspace. In the per-tenant
-- topology the tenants table is only populated in the CONTROL database; it
-- exists everywhere so one migration file provisions both roles.
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    plan_id TEXT NOT NULL DEFAULT 'free',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
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
    project_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
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
    workspace_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    last4 TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    allowed_models_json TEXT NOT NULL DEFAULT '[]',
    allowed_providers_json TEXT NOT NULL DEFAULT '[]',
    monthly_token_budget INTEGER,
    request_limit_per_minute INTEGER,
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
VALUES (1, '001_init_d1');
