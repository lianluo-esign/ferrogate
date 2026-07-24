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

-- --- Account-global control-plane entities (issue #440) ---
--
-- These families are account-scoped configuration, not per-request tenant
-- data, so they live ONLY in the CONTROL database (like `tenants`) and are
-- never fanned out over tenant databases. The tables exist in every
-- provisioned database because one migration file provisions both roles, but
-- the backend only ever reads/writes them against the control database.
-- SQLite dialect divergences from sql/001_init_postgres.sql (documented in
-- docs/cloudflare-d1-backend.md): BOOLEAN -> INTEGER 0/1, JSONB -> TEXT,
-- BIGINT -> INTEGER, DOUBLE PRECISION -> REAL, no cross-table FOREIGN KEYs
-- (referential integrity is enforced at the application layer), and CHECK
-- constraints on enumerations are dropped (validated in Rust before write).

-- Admin console human identities (issue #157), distinct from api_keys.
CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    superadmin INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    last_login_at_unix INTEGER,
    disabled_at_unix INTEGER
);

-- One admin user's membership in one tenant, with a per-tenant role. A user
-- may belong to more than one tenant; hence these edges cannot live in any
-- single tenant database and stay in the control database.
CREATE TABLE IF NOT EXISTS admin_user_tenant_memberships (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_user
    ON admin_user_tenant_memberships(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_tenant
    ON admin_user_tenant_memberships(tenant_id);

-- Hashed refresh tokens backing admin console sessions (never plaintext);
-- revocation marks a row rather than deleting it, preserving an audit trail.
CREATE TABLE IF NOT EXISTS admin_user_refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    tenant_id TEXT,
    role TEXT,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at_unix INTEGER NOT NULL,
    revoked_at_unix INTEGER
);

CREATE INDEX IF NOT EXISTS idx_admin_user_refresh_tokens_user
    ON admin_user_refresh_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_user_refresh_tokens_hash
    ON admin_user_refresh_tokens(token_hash);

CREATE INDEX IF NOT EXISTS idx_admin_user_refresh_tokens_user_tenant
    ON admin_user_refresh_tokens(user_id, tenant_id);

-- Per-tenant single-sign-on configuration (issue #283); exactly one config
-- per tenant for EITHER OIDC or SAML. OIDC client secrets are NEVER stored
-- here in plaintext -- only a ferrogate-secrets reference URI.
CREATE TABLE IF NOT EXISTS sso_provider_configs (
    tenant_id TEXT PRIMARY KEY,
    provider_kind TEXT NOT NULL,
    default_role TEXT NOT NULL DEFAULT 'member',
    group_role_mapping_json TEXT NOT NULL DEFAULT '{}',
    oidc_issuer TEXT,
    oidc_client_id TEXT,
    oidc_client_secret_ref TEXT,
    oidc_redirect_uri TEXT,
    oidc_group_claim TEXT,
    saml_idp_entity_id TEXT,
    saml_idp_sso_url TEXT,
    saml_idp_certificate TEXT,
    saml_sp_entity_id TEXT,
    saml_acs_url TEXT,
    saml_email_attribute TEXT,
    saml_name_attribute TEXT,
    saml_groups_attribute TEXT,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Restart-safe state for an in-flight SSO authorize->callback round trip
-- (issue #283), keyed by the opaque state token; consumed on first use.
CREATE TABLE IF NOT EXISTS sso_pending_flows (
    state TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    provider_kind TEXT NOT NULL,
    code_verifier TEXT,
    request_id TEXT,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sso_pending_flows_expiry
    ON sso_pending_flows(expires_at_unix);

-- Quota/rate-limit policy attached to one scope (tenant/project/workspace/
-- key). Resolved with no tenant context in the signature, so these live in
-- the control database rather than being routed per-tenant.
CREATE TABLE IF NOT EXISTS quota_policies (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    model_allowlist_json TEXT NOT NULL DEFAULT '[]',
    rpm_limit INTEGER,
    tpm_limit INTEGER,
    monthly_budget_usd REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    alert_threshold_pcts_json TEXT NOT NULL DEFAULT '[]',
    asset_storage_quota_bytes INTEGER,
    monthly_egress_bytes_budget INTEGER,
    download_rpm_limit INTEGER,
    UNIQUE (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_quota_policies_scope
    ON quota_policies(scope_type, scope_id);

-- Sellable subscription tiers (issue #168): feature flags plus default quota
-- values shared across tenants. Global, so control database only.
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    mcp_enabled INTEGER NOT NULL DEFAULT 0,
    self_hosted_workers_enabled INTEGER NOT NULL DEFAULT 0,
    admin_console_seats INTEGER,
    default_model_allowlist_json TEXT NOT NULL DEFAULT '[]',
    default_rpm_limit INTEGER,
    default_tpm_limit INTEGER,
    default_monthly_budget_usd REAL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    asset_hosting_enabled INTEGER NOT NULL DEFAULT 0,
    default_asset_storage_quota_bytes INTEGER,
    extension_tools_enabled INTEGER NOT NULL DEFAULT 0,
    default_monthly_egress_bytes_budget INTEGER,
    default_download_rpm_limit INTEGER
);

-- Seed the default 'free' plan every tenant lands on unless assigned another,
-- mirroring sql/001_init_postgres.sql and the in-memory default_free_plan().
INSERT OR IGNORE INTO plans
    (id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats,
     asset_hosting_enabled, default_asset_storage_quota_bytes,
     default_monthly_egress_bytes_budget)
VALUES ('free', 'Free', 'free', 0, 0, 1, 1, 10485760, 104857600);

-- --- Account-global admin/config families (issue #445) ---
--
-- Like the issue #440 families above, these are account-scoped control-plane
-- configuration (not per-request tenant data), so the backend only ever
-- reads/writes them against the CONTROL database; they are never fanned out
-- over tenant databases. Ported from sql/001_init_postgres.sql with the same
-- SQLite dialect divergences: BOOLEAN -> INTEGER 0/1, JSONB -> TEXT, BIGINT/
-- SMALLINT -> INTEGER, no cross-table FOREIGN KEYs (the tenants/roles rows a
-- binding references live in the control database; referential integrity is
-- enforced in Rust), and CHECK constraints on enumerations dropped (validated
-- in Rust before write).

-- Tenant-level RBAC entitlements (issue #182): a dynamically-definable,
-- finest-grained capability unit. Global, like plans -- control database only.
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- A named, horizontally-extensible bundle of permission keys (issue #182).
-- permission_keys_json is a plain JSON string list (JSONB -> TEXT).
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permission_keys_json TEXT NOT NULL DEFAULT '[]',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Many-to-many tenant<->role edges (issue #182). The Postgres FKs to
-- tenants(id)/roles(id) are dropped here; a binding's tenants/roles rows live
-- in the control database, so intra-database FKs cannot resolve. Deterministic
-- id (tenant_id:role_id) keeps binding idempotent; UNIQUE mirrors Postgres.
CREATE TABLE IF NOT EXISTS tenant_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_role_bindings_tenant
    ON tenant_role_bindings(tenant_id);

-- Custom-domain bindings for hosted static sites (issue #265): one exact
-- hostname -> {tenant}/{site}. hostname is the natural key; serve-path lookups
-- carry no tenant context, so this lives in the control database (like
-- quota_policies) rather than being routed per tenant.
CREATE TABLE IF NOT EXISTS site_domains (
    hostname TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_site_domains_tenant
    ON site_domains(tenant_id);

-- Idempotency ledger for proactive budget-threshold alerting (issue #170):
-- exactly one row per (scope, period, tier). The Postgres CHECK on scope_type
-- is dropped (QuotaScopeKind is validated in Rust); threshold_pct is a small
-- integer (SMALLINT -> INTEGER).
CREATE TABLE IF NOT EXISTS budget_alert_notifications (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    period_month TEXT NOT NULL,
    threshold_pct INTEGER NOT NULL,
    notified_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (scope_type, scope_id, period_month, threshold_pct)
);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_d1');
