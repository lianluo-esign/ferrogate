-- ===========================================================================
-- Tenant push rollups (#825)
--
-- These tables are projections, not billing authority. TenantDataObject replaces
-- a tenant's rows during its periodic flush, so retries are idempotent and a
-- partial flush never adds the same spend twice. There is intentionally no
-- foreign key to tenant_databases: retirement removes the roster row first and
-- explicitly removes these retained projections in the same lifecycle path.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS tenant_agent_cost_rollups (
    tenant_id TEXT NOT NULL,
    agent_key TEXT NOT NULL,
    period TEXT NOT NULL,
    accumulated_usd REAL NOT NULL,
    first_seen_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    as_of_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, agent_key, period)
);

CREATE INDEX IF NOT EXISTS idx_tenant_agent_cost_rollups_period
    ON tenant_agent_cost_rollups(period, accumulated_usd DESC, tenant_id, agent_key);

CREATE TABLE IF NOT EXISTS tenant_spend_rollups (
    tenant_id TEXT NOT NULL,
    period TEXT NOT NULL,
    accumulated_usd REAL NOT NULL,
    as_of_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, period)
);

CREATE INDEX IF NOT EXISTS idx_tenant_spend_rollups_period
    ON tenant_spend_rollups(period, accumulated_usd DESC, tenant_id);

CREATE TABLE IF NOT EXISTS tenant_asset_rollups (
    tenant_id TEXT PRIMARY KEY,
    asset_count INTEGER NOT NULL,
    asset_bytes INTEGER NOT NULL,
    channel_count INTEGER NOT NULL,
    as_of_unix INTEGER NOT NULL
);
