-- ===========================================================================
-- FerroGate TS/CF rewrite — CONTROL database schema (migration 0001)
--
-- Clean-room TypeScript-project port of the Rust-era hand-written D1 schema
-- `sql/d1/001_init_d1.sql` (1123 lines), which provisioned ONE file into BOTH
-- database roles. This rewrite SPLITS that single file in two, because the user
-- directive for the TS project is:
--
--     one D1 database PER TENANT  +  one account-global CONTROL database.
--
-- Splitting is not cosmetic. In the Rust file every table existed in every
-- provisioned database and only the *backend* remembered which role owned a
-- family, so a routing bug wrote a control row into a tenant database (or vice
-- versa) and nothing complained — the table was there. Here the schema itself
-- is the guard: a control-only table does not exist in a tenant database, so a
-- mis-routed write fails loudly with `no such table`.
--
-- ---------------------------------------------------------------------------
-- THE SPLIT RULE
-- ---------------------------------------------------------------------------
-- A family lives in CONTROL when ANY of these hold:
--
--   (a) It is account-global configuration shared across tenants
--       (`plans`, `permissions`, `roles`, the model/provider registry).
--   (b) It is read on a path that has NO tenant id yet, so it cannot be
--       routed to a tenant database — the lookup is what *produces* the tenant
--       id (`api_key_directory`, `site_domains`, `quota_policies`,
--       `sso_pending_flows`).
--   (c) Its rows span tenants by nature (`tenants` itself,
--       `admin_user_tenant_memberships`: one human can belong to several
--       tenants, so the edge cannot live in any single tenant database).
--   (d) Its reads are whole-table, time-ordered, `count(*)`-paginated
--       cross-tenant analytics whose `tenant` column is a COMPOSITE STORAGE
--       KEY, not a routing key. Sharding these per tenant would turn every
--       list into a lossy fan-out merge-sort plus fetch-all-then-slice
--       pagination (observability, billing, worker stores).
--
-- Everything else — a tenant's own money, usage, assets, schedules and
-- presence — is TENANT-scoped and lives in `../tenant/0001_init_tenant.sql`.
-- The prose version of this table lives in `packages/storage/README.md`.
--
-- ---------------------------------------------------------------------------
-- DIALECT (inherited verbatim from the Rust D1 file, so column names match)
-- ---------------------------------------------------------------------------
--   * JSONB -> TEXT, BIGINT/SMALLINT -> INTEGER, BOOLEAN -> INTEGER 0/1,
--     DOUBLE PRECISION -> REAL.
--   * No RLS and no `current_setting('ferrogate.tenant_id')` scoping: isolation
--     is PHYSICAL (a database per tenant), so row-level fencing is redundant.
--   * No cross-table FOREIGN KEYs. A tenant database's rows reference `tenants`
--     rows that live HERE, so an intra-database FK could not resolve.
--     Referential integrity is enforced in application code
--     (reject-if-referenced deletes; see `retention.ts` / the guarded-delete
--     ports).
--   * CHECK constraints on descriptive enumerations are dropped (validated by
--     Zod before the write). The TWO deliberate exceptions are kept from the
--     Rust file because they are PRIVILEGE TIERS, not descriptions:
--     `admin_user_tenant_memberships.role` (#517) and
--     `usage_monthly_rollups.scope_type` (the latter is in the tenant file).
--
-- COLUMN NAMES ARE PARITY. Every column below that exists in
-- `sql/d1/001_init_d1.sql` keeps its exact Rust-era name and type. A rename is
-- a silent parity break: the Rust reader would still compile, the row would
-- still write, and the value would simply stop arriving. New columns/tables
-- introduced by this rewrite are called out explicitly as NEW.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Migration bookkeeping
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS storage_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- The generic kind-keyed config-document table. Also the home of the
-- tenant->database registry document the router reads (see
-- `packages/storage/src/tenant-router.ts`, `TENANT_DATABASE_REGISTRY_KIND`).
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

-- ---------------------------------------------------------------------------
-- Tenants / organizations  (split rule (c))
--
-- The root of the Tenant -> Project -> Workspace hierarchy. `projects` and
-- `workspaces` are NOT here — they are tenant-scoped and live in the tenant
-- database, exactly as the Rust backend routed them.
--
-- NOTE ON THE WORD "ORGANIZATION": the Rust tree uses BOTH `tenant_id` (the
-- hierarchy/routing identity) and `organization_id` (the billing/attribution
-- identity carried on `tenant_contexts`, `billing_ledger` and
-- `usage_metadata_rollups`). They are NOT synonyms and are NOT merged here;
-- merging them would silently collapse the metadata-rollup scoping of #171/#226.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    plan_id TEXT NOT NULL DEFAULT 'free',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- NEW (this rewrite). The tenant -> D1 database binding map, materialized as a
-- table instead of only as a `control_plane_resources` JSON document.
--
-- WHY: the Rust backend kept the registry solely as a config document because
-- it reached D1 over the HTTP API by uuid. In the TS port the router runs
-- INSIDE a Worker where a database handle is a deploy-time BINDING NAME, so the
-- registry has to carry that name too, and the hot path wants a point lookup
-- rather than deserializing a whole document. `database_uuid` is retained for
-- the REST/admin/provisioning path (`wrangler d1` + the D1 REST API address a
-- database by uuid, not by binding name).
--
-- `binding_name` is NULL for a tenant that has been provisioned but not yet
-- redeployed with its binding — the router MUST fail closed on that row rather
-- than falling back to the control database (see `TenantDatabaseRouter`).
CREATE TABLE IF NOT EXISTS tenant_databases (
    tenant_id TEXT PRIMARY KEY,
    database_uuid TEXT NOT NULL,
    database_name TEXT NOT NULL,
    binding_name TEXT,
    schema_version INTEGER NOT NULL DEFAULT 1,
    provisioned_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (database_uuid)
);

CREATE INDEX IF NOT EXISTS idx_tenant_databases_binding
    ON tenant_databases(binding_name);

-- ---------------------------------------------------------------------------
-- API keys  (split rule (b))
--
-- ### The one deliberate ROUTING divergence from the Rust D1 file
--
-- The Rust backend put `api_keys` in the TENANT database and resolved a bearer
-- credential by FANNING OUT the id-only read across every provisioned tenant
-- database (`locate_*` in `control_plane_store_d1/*.rs`). That is defensible on
-- an admin path. It is not defensible on the inference hot path: authenticating
-- one `/v1/chat/completions` request would cost N database round trips for N
-- tenants, and the fan-out is itself a cross-tenant read.
--
-- So this rewrite keeps the FULL `api_keys` row in the tenant database (below,
-- in the tenant migration — a key's scopes/allowlists/budgets are that tenant's
-- data and must be physically isolated) and adds ONE narrow control-database
-- lookup index, `api_key_directory`, holding only what the router needs to
-- answer "which tenant does this credential belong to": the hash, the id, the
-- owning tenant/project/workspace, and the two fail-closed lifecycle columns.
--
-- This is the minimum viable answer to the chicken-and-egg in JOB 3: a
-- `TenantDatabaseRouter` maps tenantId -> handle, but the gateway starts with a
-- bearer token and no tenant id. Something has to resolve credential -> tenant,
-- and that something CANNOT itself be tenant-routed.
--
-- The cost is honest and stated here so it is not discovered later: this is a
-- SECOND source of truth for four columns (`enabled`, `revoked_at_unix`,
-- `expires_at_unix`, and the routing ids). Writers MUST update the directory and
-- the tenant row together. Because they are in different D1 databases there is
-- no cross-database transaction, so the ordering rule is FAIL-CLOSED:
--
--   * on create : write the tenant row FIRST, then the directory row.
--     (A crash between them leaves a key that cannot authenticate — closed.)
--   * on revoke : write the DIRECTORY row first, then the tenant row.
--     (A crash between them leaves a key that cannot authenticate — closed.)
--
-- PORT-TODO(inventory-data-billing §1.7 "per-tenant D1 binding at runtime"):
-- if D1 gains a runtime bind-by-uuid API, this directory can collapse back into
-- a single per-tenant `api_keys` read and the dual write disappears.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_key_directory (
    -- Same hash the tenant-database `api_keys.key_hash` column holds.
    key_hash TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    last4 TEXT NOT NULL,
    -- Mirrors `api_keys.enabled`. A DISABLED native key answers 401
    -- `invalid_api_key`, never 403 — the suspension defect the Rust tree was
    -- bitten by (inventory-edge-control §5.2); the taxonomy lives in the auth
    -- middleware, this column only supplies the bit.
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at_unix INTEGER,
    revoked_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (id)
);

CREATE INDEX IF NOT EXISTS idx_api_key_directory_tenant
    ON api_key_directory(tenant_id, project_id);

CREATE INDEX IF NOT EXISTS idx_api_key_directory_prefix
    ON api_key_directory(key_prefix);

-- Operator-authored STATIC keys (the `GATEWAY_STATIC_API_KEYS` var in
-- `apps/gateway/wrangler.toml`). These are account-global by construction — a
-- platform-operator key has no owning tenant at all — so they can only live
-- here. Kept in the same shape as the var so the composition root can swap the
-- var-backed table for this one without touching the auth taxonomy.
--
-- The asymmetry the gateway's `adapters.ts` documents is preserved: a STATIC
-- key with no scopes means ALL access, while a NATIVE key with no scopes means
-- data-plane scopes only. `scopes_json = NULL` is the wildcard; `'[]'` is the
-- empty set. Those are different values and must not be normalized together.
CREATE TABLE IF NOT EXISTS static_api_keys (
    key_hash TEXT PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    tenant_id TEXT,
    platform_operator INTEGER NOT NULL DEFAULT 0,
    scopes_json TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ---------------------------------------------------------------------------
-- Model / provider registry  (split rule (a))
--
-- NEW AS TABLES (this rewrite); the DATA is a 1:1 port, not an invention.
--
-- In the Rust tree this registry is CONFIGURATION, not storage: the
-- `[[providers]]` / `[[models]]` TOML tables of `config/ferrogate.example.toml`,
-- loaded into `ferrogate_providers::{ProviderConfig, ModelRegistryEntry}`. The
-- CF port currently carries them as the `GATEWAY_PROVIDERS` / `GATEWAY_MODELS`
-- Worker vars parsed by `apps/gateway/src/inference/catalog.ts`. There is
-- therefore no Rust *table* to keep column parity with — so the columns below
-- are named after the CONFIG KEYS that `catalog.ts` already validates
-- (`providerRecordSchema` / `modelRecordSchema`), which is the parity surface
-- that actually exists.
--
-- Two invariants carried over from `catalog.ts` and encoded here in DDL:
--   * `models.name` is UNIQUE — the Rust loader REFUSES TO BOOT on
--     `ModelRegistryError::DuplicateModel`.
--   * a model's `provider` must name a provider row — the Rust loader refuses
--     to boot on an unknown provider reference. SQLite cannot express that
--     across a DB-per-tenant split in general, but BOTH tables are control-only
--     so the FK DOES resolve here; it is declared and is enforced whenever the
--     connection has `PRAGMA foreign_keys = ON` (D1 sets it on).
--
-- CREDENTIALS ARE NEVER STORED. `api_key_var` names a Worker SECRET binding /
-- Secrets Store entry, exactly as `api_key_env` named an environment variable
-- in Rust. A schema that could hold a provider key would be a regression.
--
-- PORT-TODO(inventory-request-path §1.6 "Provider secrets"): the composition
-- root still reads the two vars. Swapping in a D1-backed `ModelResolver` is a
-- `packages/routing` slice; this schema is its destination, and the flattening
-- into `PhysicalRoute` is unchanged.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS gateway_providers (
    -- `ProviderConfig.name`; joined to `gateway_models.provider`.
    name TEXT PRIMARY KEY,
    -- `ProviderConfig.kind`; must be a known adapter family or alias
    -- (`canonicalProviderKind` in `apps/gateway/src/inference/adapters.ts`).
    kind TEXT NOT NULL,
    -- `ProviderConfig.base_url`; adapters append their own endpoint path.
    base_url TEXT NOT NULL,
    -- Names the SECRET BINDING holding the credential. NEVER the credential.
    api_key_var TEXT,
    -- 'bearer' | 'x-api-key'. NULL = use the adapter family's hard-coded default.
    auth_scheme TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS gateway_models (
    -- `ModelRegistryEntry.name` — the LOGICAL name a client sends. UNIQUE
    -- because the Rust registry refuses to boot on a duplicate.
    name TEXT PRIMARY KEY,
    provider TEXT NOT NULL REFERENCES gateway_providers(name),
    -- `ModelRoute.provider_model` — the id actually put on the upstream wire.
    -- The client's `model` string is NEVER forwarded as-is; that indirection is
    -- the entire point of the registry.
    provider_model TEXT NOT NULL,
    -- JSON array of `ModelCapability` (chat/streaming/vision/images/
    -- embeddings/tools/structured_output).
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    -- `ModelRoute.region` (#173).
    region TEXT,
    -- Owning tenant of a PRIVATE model; NULL = globally visible (#515). This is
    -- a visibility filter, not a routing key — the registry stays control-only
    -- so `GET /v1/models` is one query, not a fan-out.
    tenant_id TEXT,
    project_id TEXT,
    -- `owned_by` in `GET /v1/models`; Rust echoes the provider name.
    owned_by TEXT,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_gateway_models_provider
    ON gateway_models(provider);

-- The model-visibility read for `GET /v1/models`: global rows plus the caller's
-- own tenant rows.
CREATE INDEX IF NOT EXISTS idx_gateway_models_tenant
    ON gateway_models(tenant_id, project_id);

-- ---------------------------------------------------------------------------
-- Quota policy + plans  (split rule (a)/(b))
--
-- `quota_policies` is resolved with NO tenant context in the Rust signature
-- (`resolve_effective_quota` walks key -> workspace -> project -> tenant ->
-- plan), so the whole chain must be readable in one place. Column-for-column
-- from the Rust D1 file.
-- ---------------------------------------------------------------------------
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
    -- Per-object (not cumulative) asset byte ceiling, tenant-only (#259);
    -- distinct from the cumulative asset_storage_quota_bytes above. The
    -- tenant-only invariant is enforced by `validateQuotaPolicy`
    -- (packages/storage/src/quota.ts), not by a CHECK, because the Rust
    -- validator owns the error message.
    asset_max_object_bytes INTEGER,
    -- Per-tenant monthly USD ceiling on CF-hosted-agent runtime cost (#428);
    -- money (REAL) mirroring monthly_budget_usd, settable at ANY scope and
    -- merged min-across-the-chain (NOT tenant-only).
    agent_cost_budget_usd REAL,
    UNIQUE (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_quota_policies_scope
    ON quota_policies(scope_type, scope_id);

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
    default_download_rpm_limit INTEGER,
    default_asset_max_object_bytes INTEGER,
    default_agent_cost_budget_usd REAL
);

-- The default 'free' plan every tenant lands on unless assigned another.
-- Values copied EXACTLY from sql/d1/001_init_d1.sql (10 MiB asset quota,
-- 100 MiB monthly egress, 1 console seat, asset hosting on, MCP off).
INSERT OR IGNORE INTO plans
    (id, name, slug, mcp_enabled, self_hosted_workers_enabled, admin_console_seats,
     asset_hosting_enabled, default_asset_storage_quota_bytes,
     default_monthly_egress_bytes_budget)
VALUES ('free', 'Free', 'free', 0, 0, 1, 1, 10485760, 104857600);

-- ---------------------------------------------------------------------------
-- RBAC  (split rule (a)/(c))
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    permission_keys_json TEXT NOT NULL DEFAULT '[]',
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Deterministic id (`tenant_id:role_id`) keeps binding idempotent; the UNIQUE
-- mirrors Postgres.
CREATE TABLE IF NOT EXISTS tenant_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_role_bindings_tenant
    ON tenant_role_bindings(tenant_id);

-- ---------------------------------------------------------------------------
-- Admin-console identities + sessions + SSO  (split rule (c))
-- ---------------------------------------------------------------------------
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

-- Issue #517: the `role` CHECK is a DELIBERATE EXCEPTION to "enumeration CHECKs
-- are dropped". This column is a privilege tier, not a description — it decides
-- which scopes a console session's gateway API key is minted with — so both
-- backends must agree on its domain. Kept verbatim from the Rust file.
CREATE TABLE IF NOT EXISTS admin_user_tenant_memberships (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_user
    ON admin_user_tenant_memberships(user_id);

CREATE INDEX IF NOT EXISTS idx_admin_user_tenant_memberships_tenant
    ON admin_user_tenant_memberships(tenant_id);

-- Refresh tokens are stored HASHED (never plaintext), so a durable-storage read
-- cannot itself mint a session; revocation marks a row instead of deleting it.
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

-- Exactly one SSO config per tenant, for EITHER OIDC or SAML (#283). OIDC
-- client secrets are NEVER stored here in plaintext — only a
-- `@ferrogate/secrets` reference URI.
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

-- Restart-safe state for an in-flight SSO authorize->callback round trip (#283),
-- keyed by the opaque state token; consumed on first use. Control-only: the
-- callback arrives with a state token and NO tenant id (split rule (b)).
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

-- ---------------------------------------------------------------------------
-- Custom domains  (split rule (b))
--
-- A serve-path hostname lookup carries no tenant context — resolving the
-- hostname is what PRODUCES the tenant — so both tables are control-only.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS site_domains (
    hostname TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    site TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_site_domains_tenant
    ON site_domains(tenant_id);

-- `site_domains` records INTENT; this records EVIDENCE (#488). Keyed on
-- (tenant_id, hostname) and NOT on hostname alone, so a challenge one tenant
-- started can never be redeemed by another, and several tenants may hold a
-- PENDING challenge for one hostname — a squatter's unverified binding cannot
-- block the tenant that actually owns the domain.
CREATE TABLE IF NOT EXISTS site_domain_verifications (
    tenant_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    site TEXT NOT NULL,
    state TEXT NOT NULL,
    challenge_token TEXT NOT NULL,
    issued_at_unix INTEGER NOT NULL,
    token_expires_at_unix INTEGER NOT NULL,
    verified_at_unix INTEGER,
    verification_expires_at_unix INTEGER,
    last_checked_at_unix INTEGER,
    last_failure_reason TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, hostname)
);

-- ---------------------------------------------------------------------------
-- Budget-alert idempotency ledger (#170)  (split rule (a))
--
-- Exactly one row per (scope, period, tier). The UNIQUE is the idempotency gate:
-- `INSERT ... ON CONFLICT DO NOTHING` fires a tier's alert at most once.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS budget_alert_notifications (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    period_month TEXT NOT NULL,
    threshold_pct INTEGER NOT NULL,
    notified_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (scope_type, scope_id, period_month, threshold_pct)
);

-- ---------------------------------------------------------------------------
-- Control-plane snapshot replay floors (#206)  (split rule (a))
--
-- Keyed by (tenant_id, deployment_id): the MONOTONIC high-water revision a
-- deployment has accepted. The upsert uses SQLite `max()` (Postgres used
-- GREATEST) so a delayed/out-of-order write can never regress the floor. See
-- `MonotonicUpserts.raiseReplayFloor` in packages/storage/src/d1/monotonic.ts.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS control_plane_replay_floors (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    last_accepted_revision INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id)
);

-- ---------------------------------------------------------------------------
-- Billing / metering ledger  (split rule (d))
--
-- Account-global CROSS-TENANT metering whose reads are whole-table
-- (list-all, `count(*)`-paginated) with no routing tenant in the signature.
-- Each row stores the FULL record as a `*_json` TEXT document plus the
-- projection columns the filter/order/paginate SQL needs — the #447 document
-- pattern, kept verbatim.
--
-- PORT-TODO(inventory-data-billing §1.7): `billing_events` is append-heavy and
-- time-ordered, which is the exact shape Analytics Engine is for. Keeping it in
-- D1 preserves the queryable admin surface; a follow-up slice may dual-write to
-- Analytics Engine and demote this table to the recent window.
-- ---------------------------------------------------------------------------
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

-- The durable gateway -> billing report outbox. `append_billing_event_with_
-- outbox_enqueue` writes the metering event and the outbox row in ONE atomic
-- batch (inventory §1.5.8), which on D1 is `batch([event, outbox])` on this
-- database — both rows are here, so the atomicity is real and needs no
-- cross-database coordination.
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

-- Settled metering events. `billing_event_id` is the primary key, so an insert
-- replay of the same settled event is idempotent through the PK; the
-- (request_id, provider_attempt_index) pair is the #135 provider-attempt
-- identity that keeps a retried upstream call from double-billing.
CREATE TABLE IF NOT EXISTS billing_events (
    billing_event_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    provider_attempt_index INTEGER NOT NULL DEFAULT 0,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_billing_events_occurred
    ON billing_events(occurred_at_unix, request_id, provider_attempt_index);

-- ---------------------------------------------------------------------------
-- Guardrail policy revisions + bindings  (split rule (a))
--
-- Immutable revisions plus the ONE mutable active/archived binding row per
-- policy. `generation` is the CAS token: activate/archive/restore are
-- generation-guarded compare-and-swaps (`UPDATE ... WHERE generation = ?
-- RETURNING policy_id`; an empty RETURNING set is a lost update -> typed
-- Conflict). Inventory §1.5.5.
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- Observability append/analytics compatibility projections (split rule (d))
--
-- As of #859, tenant-attributed `request_logs`, `agent_runs`, and
-- `agent_run_events` are authoritative in the exact tenant's
-- `TenantDataObject`. These same-named CONTROL tables remain as derived
-- compatibility projections for bounded fleet discovery and existing joins;
-- they are never a fallback for an unavailable object. Unattributed/platform
-- request rows remain control-only. `audit_events` remains control-owned.
--
-- Keeping this projection preserves existing one-database fleet surfaces while
-- #825 defines their bounded, paginated, freshness, and deletion contract.
--
-- PORT-TODO(inventory-data-billing §1.7): `request_logs` / `audit_events` are
-- Analytics Engine candidates in the tree (`writeDataPoint` + the SQL API).
-- Analytics Engine remains a documented future option; #859 keeps the
-- queryable compatibility projection and does not implement that sink swap.
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- Managed worker stores (#200/#294/#449)  (split rule (d))
--
-- Whole-table admin reads with no routing tenant in the signature (the `tenant`
-- inside each record is a composite storage key). Document rows plus the
-- projection columns the ORDER BY needs.
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- Self-hosted worker stores (#221/#228/#231/#329)  (split rule (d))
--
-- The Postgres backend kept a normalized dispatch-capability side table; here
-- the required capabilities ride inside the dispatch document, matching the
-- Rust D1 file.
-- ---------------------------------------------------------------------------
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

-- ---------------------------------------------------------------------------
-- Record the migration LAST, so a partially-applied file is not reported as
-- complete.
-- ---------------------------------------------------------------------------
INSERT OR IGNORE INTO storage_schema_migrations (version, name)
VALUES (1, '0001_init_control');
