-- ===========================================================================
-- Retire the legacy D1-per-tenant registry columns (#830)
--
-- Durable Object addressing is the tenant-data default. binding_name remains
-- only for explicit native-binding compatibility deployments; runtime database
-- UUIDs and operator-facing D1 names have no reader after the REST and lifecycle
-- apparatus was removed.
--
-- SQLite cannot drop columns portably in the supported D1 dialect, so rebuild
-- the registry while preserving the provisioning and #824 backfill state.
-- ===========================================================================

CREATE TABLE tenant_databases_v3 (
    tenant_id TEXT PRIMARY KEY,

    storage_backend TEXT NOT NULL DEFAULT 'native_binding',
    provisioning_status TEXT NOT NULL DEFAULT 'pending',
    schema_version INTEGER NOT NULL DEFAULT 0,
    catalog_seeded_at_unix INTEGER,
    last_error TEXT,
    location_hint TEXT,

    -- Native-binding/self-hosted compatibility only. Durable Object tenants
    -- are addressed by idFromName(tenant_id) and leave this NULL.
    binding_name TEXT,

    provisioned_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),

    migration_state TEXT NOT NULL DEFAULT 'shared'
        CHECK (migration_state IN ('shared', 'copying', 'verifying', 'cut', 'done')),
    migration_epoch INTEGER NOT NULL DEFAULT 0
        CHECK (migration_epoch >= 0),
    migration_frozen_at_unix INTEGER,
    migration_cutover_at_unix INTEGER,
    migration_retention_until_unix INTEGER,
    migration_last_error TEXT,
    migration_receipt_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(migration_receipt_json) = 1),
    migration_progress_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(migration_progress_json) = 1)
);

INSERT INTO tenant_databases_v3 (
    tenant_id,
    storage_backend,
    provisioning_status,
    schema_version,
    catalog_seeded_at_unix,
    last_error,
    location_hint,
    binding_name,
    provisioned_at_unix,
    updated_at_unix,
    migration_state,
    migration_epoch,
    migration_frozen_at_unix,
    migration_cutover_at_unix,
    migration_retention_until_unix,
    migration_last_error,
    migration_receipt_json,
    migration_progress_json
)
SELECT
    tenant_id,
    storage_backend,
    provisioning_status,
    schema_version,
    catalog_seeded_at_unix,
    last_error,
    location_hint,
    binding_name,
    provisioned_at_unix,
    updated_at_unix,
    migration_state,
    migration_epoch,
    migration_frozen_at_unix,
    migration_cutover_at_unix,
    migration_retention_until_unix,
    migration_last_error,
    migration_receipt_json,
    migration_progress_json
FROM tenant_databases;

DROP TABLE tenant_databases;

ALTER TABLE tenant_databases_v3 RENAME TO tenant_databases;

CREATE INDEX IF NOT EXISTS idx_tenant_databases_binding
    ON tenant_databases(binding_name);

CREATE INDEX IF NOT EXISTS idx_tenant_databases_status
    ON tenant_databases(provisioning_status, tenant_id);

CREATE INDEX IF NOT EXISTS idx_tenant_databases_migration_state
    ON tenant_databases(migration_state, migration_epoch, tenant_id);

CREATE INDEX IF NOT EXISTS idx_tenant_databases_migration_retention
    ON tenant_databases(migration_retention_until_unix, tenant_id);
