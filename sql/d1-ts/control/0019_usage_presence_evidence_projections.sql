-- ===========================================================================
-- Tenant-derived fleet projections (#852, #831)
--
-- Tenant Durable Objects own usage rollups, observed presence, and managed
-- worker isolation evidence. Control D1 keeps only tenant-qualified snapshots
-- needed by fleet views. Every projection is replaced by its current object
-- value, so a retry cannot add the same spend or presence twice.
-- ===========================================================================

-- managed_worker_isolation_evidence ------------------------------------------
ALTER TABLE managed_worker_isolation_evidence ADD COLUMN projection_key TEXT;
UPDATE managed_worker_isolation_evidence
   SET projection_key = length(COALESCE(
                         CASE WHEN json_valid(evidence_json)
                              THEN json_extract(evidence_json, '$.tenant_id')
                         END,
                         ''
                       )) || ':' ||
                       COALESCE(
                         CASE WHEN json_valid(evidence_json)
                              THEN json_extract(evidence_json, '$.tenant_id')
                         END,
                         ''
                       ) || ':' || id
 WHERE projection_key IS NULL;

DROP INDEX IF EXISTS ux_managed_worker_isolation_evidence_projection_key;
DROP INDEX IF EXISTS idx_managed_worker_isolation_evidence_occurred;
ALTER TABLE managed_worker_isolation_evidence
    RENAME TO managed_worker_isolation_evidence_projection_legacy;
CREATE TABLE managed_worker_isolation_evidence (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    tenant TEXT,
    occurred_at_unix INTEGER,
    evidence_json TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO managed_worker_isolation_evidence (
    projection_key, id, tenant, occurred_at_unix, evidence_json
)
SELECT
    projection_key,
    id,
    CASE WHEN json_valid(evidence_json)
         THEN json_extract(evidence_json, '$.tenant_id')
    END,
    occurred_at_unix,
    evidence_json
FROM managed_worker_isolation_evidence_projection_legacy;
DROP TABLE managed_worker_isolation_evidence_projection_legacy;
CREATE INDEX idx_managed_worker_isolation_evidence_occurred
    ON managed_worker_isolation_evidence(occurred_at_unix, id);

-- usage_monthly_rollups -------------------------------------------------------
CREATE TABLE IF NOT EXISTS usage_monthly_rollups (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    period_month TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'project', 'workspace', 'key')),
    scope_id TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cached_input_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (tenant, period_month, scope_type, scope_id)
);
CREATE INDEX IF NOT EXISTS idx_control_usage_monthly_tenant_period
    ON usage_monthly_rollups(tenant, period_month, updated_at_unix DESC);

-- usage_aggregate_rollups -----------------------------------------------------
-- The tenant object keeps the cumulative token accumulator. This is the
-- tenant-qualified fleet copy used by platform billing/report reads; it is
-- replaced from the object snapshot and never incremented in control D1.
CREATE TABLE IF NOT EXISTS usage_aggregate_rollups (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    tenant_context_id TEXT NOT NULL,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cached_input_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (tenant, id)
);
CREATE INDEX IF NOT EXISTS idx_control_usage_aggregate_tenant_model
    ON usage_aggregate_rollups(tenant, logical_model, provider, updated_at_unix DESC);

-- usage_metadata_rollups ------------------------------------------------------
CREATE TABLE IF NOT EXISTS usage_metadata_rollups (
    projection_key TEXT PRIMARY KEY,
    id TEXT NOT NULL,
    tenant TEXT NOT NULL,
    period_month TEXT NOT NULL,
    organization_id TEXT NOT NULL DEFAULT '',
    metadata_key TEXT NOT NULL,
    metadata_value TEXT NOT NULL,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    request_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (tenant, id)
);
CREATE INDEX IF NOT EXISTS idx_control_usage_metadata_tenant_key
    ON usage_metadata_rollups(tenant, metadata_key, period_month);

-- observed_agent_presence ----------------------------------------------------
CREATE TABLE IF NOT EXISTS observed_agent_presence (
    projection_key TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    api_key_id TEXT NOT NULL,
    first_seen_at_unix INTEGER NOT NULL,
    last_seen_at_unix INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (tenant_id, api_key_id)
);
CREATE INDEX IF NOT EXISTS idx_control_observed_presence_last_seen
    ON observed_agent_presence(last_seen_at_unix DESC, tenant_id, api_key_id);
