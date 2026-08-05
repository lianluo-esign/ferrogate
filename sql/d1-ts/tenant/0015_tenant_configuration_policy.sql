-- M9 Step 5 / issue #863
--
-- These records are authoritative inside one tenant's SQLite-backed Durable
-- Object. The shared `roles` catalog remains in CONTROL; the role snapshot is
-- the narrow local projection needed for an object-local authorization join.

CREATE TABLE IF NOT EXISTS tenant_provider_credentials (
    tenant_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    provider TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    last4 TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    rotated_at_unix INTEGER NOT NULL,
    revoked_at_unix INTEGER,
    PRIMARY KEY (tenant_id, alias)
);

CREATE INDEX IF NOT EXISTS idx_tenant_provider_credentials_tenant
    ON tenant_provider_credentials (tenant_id, provider);

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

CREATE TABLE IF NOT EXISTS tenant_role_catalog (
    role_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permission_keys_json TEXT NOT NULL DEFAULT '[]',
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_role_bindings (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_role_bindings_tenant
    ON tenant_role_bindings (tenant_id);

CREATE TABLE IF NOT EXISTS semantic_cache_policies (
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    enabled INTEGER,
    mode TEXT,
    similarity_threshold REAL,
    ttl_seconds INTEGER,
    scoped_models TEXT,
    invalidation_epoch INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    updated_by TEXT,
    generation INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_semantic_cache_policies_scope
    ON semantic_cache_policies (scope_type, scope_id);

CREATE TABLE IF NOT EXISTS delegation_revocations (
    tenant TEXT NOT NULL,
    subject TEXT NOT NULL,
    reason TEXT,
    revoked_by TEXT,
    revoked_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER,
    PRIMARY KEY (tenant, subject)
);

CREATE INDEX IF NOT EXISTS idx_delegation_revocations_expiry
    ON delegation_revocations (expires_at_unix);

CREATE TABLE IF NOT EXISTS control_plane_replay_floors (
    tenant_id TEXT NOT NULL,
    deployment_id TEXT NOT NULL,
    last_accepted_revision INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS budget_alert_notifications (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    period_month TEXT NOT NULL,
    threshold_pct INTEGER NOT NULL,
    notified_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, scope_type, scope_id, period_month, threshold_pct)
);

CREATE INDEX IF NOT EXISTS idx_budget_alert_notifications_tenant_scope
    ON budget_alert_notifications (tenant_id, scope_type, scope_id, period_month);
