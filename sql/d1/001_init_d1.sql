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

-- --- Observability append/analytics families (issue #447) ---
--
-- Agent runs/events plus request/audit logs. On Postgres these are single
-- global tables scanned time-ordered across every tenant (whole-table
-- analytics reads, count(*)-paginated, and a cross-family UNION seed query);
-- their `tenant` column is a COMPOSITE storage key, not a routing tenant id.
-- Routing them per tenant would force a lossy fan-out merge-sort for every
-- list plus fetch-all-then-slice pagination, so this backend keeps them in the
-- CONTROL database as single tables -- the faithful mirror of the Postgres
-- single-query ordering/pagination and UNION seed. They exist in every
-- provisioned database (one migration file) but the backend only ever
-- reads/writes them against the control database. Each row stores the FULL
-- record as a `*_json` TEXT document (the read paths deserialize it) plus the
-- projection columns the filter/order/paginate SQL needs. SQLite dialect
-- divergences match the tables above (JSONB -> TEXT, BIGINT -> INTEGER, no
-- cross-table FOREIGN KEYs, no RLS).

CREATE TABLE IF NOT EXISTS agent_runs (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    tenant TEXT,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    run_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agent_runs_request
    ON agent_runs(request_id);

CREATE INDEX IF NOT EXISTS idx_agent_runs_started
    ON agent_runs(started_at_unix);

CREATE TABLE IF NOT EXISTS agent_run_events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tenant TEXT,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_run_time
    ON agent_run_events(run_id, occurred_at_unix);

CREATE INDEX IF NOT EXISTS idx_agent_run_events_request
    ON agent_run_events(request_id);

CREATE TABLE IF NOT EXISTS request_logs (
    request_id TEXT PRIMARY KEY,
    agent_run_id TEXT,
    tenant TEXT,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    request_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_request_logs_agent_run
    ON request_logs(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_request_logs_started
    ON request_logs(started_at_unix);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    agent_run_id TEXT,
    tenant TEXT,
    occurred_at_unix INTEGER NOT NULL,
    audit_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_agent_run
    ON audit_events(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred
    ON audit_events(occurred_at_unix);

-- Durable control-plane snapshot replay floor (issue #206), keyed by
-- (tenant_id, deployment_id): the monotonic high-water revision a deployment
-- has accepted. Account-global control-plane state (no tenant-database
-- routing), so it lives in the CONTROL database. The Postgres upsert uses
-- GREATEST + RETURNING; this backend uses SQLite `max()` and a follow-up
-- SELECT (the HTTP query API exposes no RETURNING), documented in the module.
CREATE TABLE IF NOT EXISTS control_plane_replay_floors (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    last_accepted_revision INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id)
);

-- --- Billing / metering families (issue #449) ---
--
-- Ledger entries, the durable gateway->billing report outbox, and settled
-- metering (billing) events. On Postgres these are normalized across several
-- tables (billing_ledger, billing_report_outbox, metering_events + routes +
-- usage); this backend follows the issue #447 document pattern instead -- each
-- row stores the FULL record as a `*_json` TEXT document (the read paths
-- deserialize it) plus the projection columns the filter/order/paginate SQL
-- needs. Billing is account-global cross-tenant metering whose reads are
-- whole-table (list all, count(*)-paginated) with no routing tenant in the
-- signature, so like the #447 observability tables they live in the CONTROL
-- database as single tables. SQLite dialect divergences match the tables above
-- (JSONB -> TEXT, BIGINT -> INTEGER, no cross-table FOREIGN KEYs, no RLS).

CREATE TABLE IF NOT EXISTS billing_ledger (
    id TEXT PRIMARY KEY,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    created_at_unix INTEGER NOT NULL,
    entry_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_scope
    ON billing_ledger(organization_id, project_id, api_key_id);

CREATE INDEX IF NOT EXISTS idx_billing_ledger_created
    ON billing_ledger(created_at_unix, id);

CREATE TABLE IF NOT EXISTS billing_report_outbox (
    id TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix INTEGER NOT NULL,
    dead_lettered_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_due
    ON billing_report_outbox(next_attempt_unix);

CREATE INDEX IF NOT EXISTS idx_billing_report_outbox_dead
    ON billing_report_outbox(dead_lettered_at_unix);

CREATE TABLE IF NOT EXISTS billing_events (
    billing_event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    provider_attempt_index INTEGER NOT NULL DEFAULT 0,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_events_occurred
    ON billing_events(occurred_at_unix, request_id, provider_attempt_index);

-- --- Guardrail policy revisions + bindings (issue #449) ---
--
-- Immutable policy revisions plus the mutable active/archived binding per
-- policy. Account-global guardrail configuration (like plans/RBAC), so the
-- CONTROL database owns them; each row stores the full record as a `*_json`
-- document plus projection columns. The atomic activate/archive/restore CAS
-- transitions (generation-guarded) are NOT implemented on this backend -- they
-- need the compare-and-swap transaction semantics the D1 HTTP query API lacks
-- and stay deferred to the proxy-Worker path.

CREATE TABLE IF NOT EXISTS guardrail_policy_revisions (
    policy_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    immutable_id TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    revision_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (policy_id, revision)
);

CREATE TABLE IF NOT EXISTS guardrail_policy_bindings (
    policy_id TEXT PRIMARY KEY,
    active_revision INTEGER,
    updated_at_unix INTEGER NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    binding_json TEXT NOT NULL DEFAULT '{}'
);

-- --- Managed worker stores (issue #449) ---
--
-- Managed-worker templates/instances/sessions plus lifecycle events and the
-- isolation selection/policy/evidence trio (issues #200/#294). All whole-table
-- admin reads with no routing tenant in the signature (the `tenant` inside each
-- record is a composite storage key), so like the #447 observability tables
-- they live in the CONTROL database. Each row stores the full record as a
-- `*_json` document plus the projection columns the ORDER BY needs.

CREATE TABLE IF NOT EXISTS managed_worker_templates (
    id TEXT PRIMARY KEY,
    template_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS agent_worker_instances (
    id TEXT PRIMARY KEY,
    started_at_unix INTEGER,
    instance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agent_worker_instances_started
    ON agent_worker_instances(started_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_sessions (
    id TEXT PRIMARY KEY,
    requested_at_unix INTEGER,
    session_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_requested
    ON managed_worker_sessions(requested_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_lifecycle_events (
    id TEXT PRIMARY KEY,
    occurred_at_unix INTEGER,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_lifecycle_events_occurred
    ON managed_worker_lifecycle_events(occurred_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_selections (
    session_id TEXT PRIMARY KEY,
    selected_at_unix INTEGER,
    selection_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_selections_selected
    ON managed_worker_isolation_selections(selected_at_unix, session_id);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_policies (
    session_id TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_evidence (
    id TEXT PRIMARY KEY,
    occurred_at_unix INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_evidence_occurred
    ON managed_worker_isolation_evidence(occurred_at_unix, id);

-- --- Self-hosted worker stores (issue #449) ---
--
-- Registrations, heartbeats, telemetry events, artifacts, checkpoints, and run
-- dispatches for operator-hosted workers (issues #221/#228/#231/#329). The
-- Postgres backend keeps a normalized dispatch-capability side table; here the
-- required capabilities ride inside the dispatch document. Whole-table +
-- worker/run-filtered admin reads with no routing tenant, so CONTROL database;
-- each row stores the full record as a `*_json` document plus projection
-- columns (`worker_id`/`run_id` for the filtered reads, timestamps for order).

CREATE TABLE IF NOT EXISTS self_hosted_worker_registrations (
    id TEXT PRIMARY KEY,
    registered_at_unix INTEGER,
    registration_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_registrations_registered
    ON self_hosted_worker_registrations(registered_at_unix, id);

CREATE TABLE IF NOT EXISTS self_hosted_worker_heartbeats (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    reported_at_unix INTEGER,
    heartbeat_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_heartbeats_worker
    ON self_hosted_worker_heartbeats(worker_id, reported_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_worker_telemetry_events (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    run_id TEXT,
    occurred_at_unix INTEGER,
    ingested_at_unix INTEGER,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_telemetry_worker
    ON self_hosted_worker_telemetry_events(worker_id, occurred_at_unix);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_telemetry_run
    ON self_hosted_worker_telemetry_events(run_id, occurred_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_worker_artifacts (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    created_at_unix INTEGER,
    artifact_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_artifacts_worker
    ON self_hosted_worker_artifacts(worker_id, created_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_worker_checkpoints (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    created_at_unix INTEGER,
    checkpoint_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_checkpoints_worker
    ON self_hosted_worker_checkpoints(worker_id, created_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_run_dispatches (
    dispatch_id TEXT PRIMARY KEY,
    queued_at_unix INTEGER,
    dispatch_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatches_queued
    ON self_hosted_run_dispatches(queued_at_unix, dispatch_id);

-- --- Wallets + reservations + settlements (issue #455) ---
--
-- Per-tenant prepaid-credit FINANCIAL state (issues #169/#281). Unlike the
-- account-global billing/guardrail families above, these are TENANT-SCOPED: in
-- the database-per-tenant topology a tenant's wallet, its live holds, and its
-- settlement ledger live in THAT tenant's own D1 database (never the control
-- database), so the tables carry no routing FK to `tenants` (physical
-- isolation). Balances are integer credits (no float drift). Ported column-for-
-- column from the Postgres wallets/wallet_reservations/wallet_settlements tables
-- (SQLite divergences: BIGINT->INTEGER, BOOLEAN->INTEGER 0/1, no cross-table FK)
-- because the reserve-no-oversell guard does real SQL arithmetic on
-- balance_credits and SUM(amount_credits), which a `*_json` document could not
-- serve. The atomic reserve/settle/release transitions run through the
-- proxy-Worker `/d1/batch` + `/d1/query` binding (issue #450) selected onto the
-- tenant database (issue #455); a REST-only deployment leaves them fail-closed.
CREATE TABLE IF NOT EXISTS wallets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL UNIQUE,
    balance_credits INTEGER NOT NULL DEFAULT 0,
    auto_recharge_threshold_credits INTEGER,
    auto_recharge_amount_credits INTEGER,
    dunning INTEGER NOT NULL DEFAULT 0,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

-- One durable row per hold. `settlement_id` (equal to the hold id) is set when
-- the hold captures, linking the ledger charge back to its originating hold.
-- The active/unexpired holds are summed against `balance_credits` to compute
-- AVAILABLE balance for the no-oversell reserve guard.
CREATE TABLE IF NOT EXISTS wallet_reservations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    amount_credits INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    expires_at_unix INTEGER NOT NULL,
    settlement_id TEXT,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wallet_reservations_tenant_status
    ON wallet_reservations(tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_wallet_reservations_active_expiry
    ON wallet_reservations(expires_at_unix);

-- One durable row per settled debit/credit. Claiming this id and moving the
-- balance commit together (one atomic /d1/batch), so replay returns the first
-- outcome instead of debiting twice (idempotent through the primary key).
CREATE TABLE IF NOT EXISTS wallet_settlements (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    delta_credits INTEGER NOT NULL,
    balance_after_credits INTEGER,
    created_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wallet_settlements_tenant_time
    ON wallet_settlements(tenant_id, created_at_unix DESC);

CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '001_init_d1');
