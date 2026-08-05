-- ===========================================================================
-- Tenant-owned MCP server catalog and runtime identity state (#862, #831)
--
-- The catalog and the per-user MCP OAuth grant are tenant data. They are
-- authoritative in the tenant's SQLite-backed TenantDataObject, not in the
-- control database. The tenant_id columns remain deliberate mis-routing
-- tripwires and every application query keeps the tenant predicate.
--
-- OAuth flow state is intentionally absent: the separate MCP_OAUTH_FLOWS
-- Durable Object owns the single-use claim for an in-flight callback. These
-- tables hold only the tenant-owned server configuration, encrypted token
-- material, and the generation used to reject stale authorization callbacks.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS mcp_servers (
    tenant_id             TEXT    NOT NULL,
    name                  TEXT    NOT NULL,
    transport             TEXT    NOT NULL,
    url                   TEXT,
    auth_type             TEXT    NOT NULL,
    tools_to_execute      TEXT    NOT NULL,
    tools_to_auto_execute TEXT    NOT NULL,
    tools_to_exclude      TEXT,
    headers               TEXT,
    oauth                 TEXT,
    signed_jwt_audience   TEXT,
    timeout_ms            INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_servers_tenant_name
    ON mcp_servers (tenant_id, name);

CREATE TABLE IF NOT EXISTS mcp_oauth_credentials (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT    NOT NULL,
    workspace_id             TEXT    NOT NULL,
    user_id                  TEXT    NOT NULL,
    server_name              TEXT    NOT NULL,
    issuer                   TEXT    NOT NULL,
    subject                  TEXT    NOT NULL,
    token_type               TEXT    NOT NULL,
    scopes                   TEXT    NOT NULL,
    access_token_nonce       TEXT    NOT NULL,
    access_token_ciphertext  TEXT    NOT NULL,
    refresh_token_nonce      TEXT,
    refresh_token_ciphertext TEXT,
    expires_at_unix          INTEGER NOT NULL,
    key_version              INTEGER NOT NULL,
    version                  INTEGER NOT NULL,
    authorization_generation INTEGER NOT NULL,
    created_at_unix          INTEGER NOT NULL,
    updated_at_unix          INTEGER NOT NULL,
    revoked_at_unix          INTEGER,
    last_refresh_outcome     TEXT,
    last_revocation_outcome  TEXT,
    UNIQUE (tenant_id, workspace_id, user_id, server_name)
);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_credentials_actor
    ON mcp_oauth_credentials (tenant_id, workspace_id, user_id, server_name);

CREATE INDEX IF NOT EXISTS idx_mcp_oauth_credentials_expiry
    ON mcp_oauth_credentials (tenant_id, expires_at_unix);

CREATE TABLE IF NOT EXISTS mcp_identity_generations (
    tenant_id    TEXT    NOT NULL,
    workspace_id TEXT    NOT NULL,
    user_id      TEXT    NOT NULL,
    server_name  TEXT    NOT NULL,
    generation   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, user_id, server_name)
);
