-- ===========================================================================
-- Tenant backfill state (#824)
--
-- `provisioning_status` remains the onboarding/provisioning state from #820.
-- It answers whether a tenant object was provisioned successfully and is not
-- changed by this migration. The columns below describe a separate data
-- migration from the legacy shared tenant database into that object.
--
-- Existing rows deliberately start at `shared`, even when `storage_backend`
-- already says `durable_object`. The migration driver must have a verified
-- receipt before it is allowed to serve the object for this backfill; inferring
-- completion from the backend label could expose an incompletely copied tenant.
-- ===========================================================================

ALTER TABLE tenant_databases
    ADD COLUMN migration_state TEXT NOT NULL DEFAULT 'shared'
    CHECK (migration_state IN ('shared', 'copying', 'verifying', 'cut', 'done'));

ALTER TABLE tenant_databases
    ADD COLUMN migration_epoch INTEGER NOT NULL DEFAULT 0
    CHECK (migration_epoch >= 0);

-- The freeze is acquired before the first source scan. `cut` records the
-- point at which routing may begin selecting the Durable Object. Both remain
-- NULL for tenants that have not started this migration.
ALTER TABLE tenant_databases
    ADD COLUMN migration_frozen_at_unix INTEGER;

ALTER TABLE tenant_databases
    ADD COLUMN migration_cutover_at_unix INTEGER;

-- Source rows are retained through this deadline so a verified rollback can
-- return routing to the shared database without reconstructing deleted data.
ALTER TABLE tenant_databases
    ADD COLUMN migration_retention_until_unix INTEGER;

ALTER TABLE tenant_databases
    ADD COLUMN migration_last_error TEXT;

-- The receipt is the durable per-table verification record. Its JSON payload
-- is owned by the migration driver and contains source/destination row counts,
-- checksums, schema fingerprint, and the receipt version. `{}` is an explicit
-- "no receipt" value for existing and not-yet-started rows.
ALTER TABLE tenant_databases
    ADD COLUMN migration_receipt_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(migration_receipt_json) = 1);

-- The progress document stores the current table, stable keyset cursor, page
-- counters, and retry metadata. It is updated after each idempotent page so a
-- crashed worker can resume without relying on in-memory state.
ALTER TABLE tenant_databases
    ADD COLUMN migration_progress_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(migration_progress_json) = 1);

-- Tenants already provisioned on a Durable Object are outside this legacy-D1
-- backfill: #820 created their object and recorded it as ready. Only rows that
-- still point at the old binding/shared topology need the new state machine.
-- The explicit update also keeps test and production registries from routing a
-- healthy, already-object-backed tenant through the legacy source merely
-- because this migration added a column with a conservative default.
UPDATE tenant_databases
SET migration_state = 'done'
WHERE storage_backend = 'durable_object'
  AND provisioning_status = 'ready';

-- The migration worklist and CAS transition reads are both keyed by state.
CREATE INDEX IF NOT EXISTS idx_tenant_databases_migration_state
    ON tenant_databases(migration_state, migration_epoch, tenant_id);

-- Retention sweeps must find source rows whose rollback window has expired
-- without scanning every tenant in the registry.
CREATE INDEX IF NOT EXISTS idx_tenant_databases_migration_retention
    ON tenant_databases(migration_retention_until_unix, tenant_id);
