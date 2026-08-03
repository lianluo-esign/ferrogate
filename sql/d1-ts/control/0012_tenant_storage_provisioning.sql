-- ===========================================================================
-- `tenant_databases` becomes the PROVISIONING STATE record (#820)
--
-- The table survives the move to one Durable Object per tenant
-- (`docs/design/per-tenant-durable-object-storage-2026-08.md`). Its MEANING
-- does not.
--
-- ## What it used to be, and why that is now wrong
--
-- It was a ROUTING TABLE. `EnvBindingTenantDatabaseRouter.forTenant()` read
-- `binding_name` out of it on the request path, because under the D1-per-tenant
-- topology the row carried the ANSWER: no row, no route. Under `durable_object`
-- the address IS `idFromName(tenantId)`, a pure function of the tenant id, so
-- `DurableObjectTenantDatabaseRouter.forTenant()` reads NOTHING (#819 deleted
-- even the cache that used to front the read, and
-- `apps/gateway/test/tenancy/durable-object.spec.ts` counts `prepare()` calls
-- and asserts zero). The row carries no part of the answer any more.
--
-- What it must carry instead is the thing a Durable Object namespace cannot be
-- asked: **who exists, and did their provisioning finish**. A DO namespace
-- cannot be enumerated in production (`listDurableObjectIds` is a
-- `cloudflare:test` helper), and an object materialises the moment anyone calls
-- `idFromName` — including a typo, a probe or a deleted tenant. So this table is
-- simultaneously the fleet roster (`provisionedTenants()`, which
-- `apps/control-plane/src/store/asset_fleet.ts` fans out over) and the
-- provisioning ledger.
--
-- ## Why this is a table REBUILD and not three `ALTER TABLE ADD COLUMN`s
--
-- Because two of the three D1-topology columns are `NOT NULL`, and a
-- Durable-Object tenant has neither a database uuid nor a database name. SQLite
-- cannot relax `NOT NULL` in place, so the twelve-step rebuild is the only way
-- to say the true thing. Writing `''` into them instead was the tempting
-- alternative and it is worse than it looks: `UNIQUE (database_uuid)` would then
-- admit exactly ONE Durable-Object tenant and refuse the second with a
-- constraint error nobody could read.
--
-- ## Why the three columns are KEPT rather than dropped
--
-- The brief for this slice called them dead. Two of them are not, and dropping
-- a live column to make a doc comment true is how a topology that is still
-- deployed stops working:
--
--   * `binding_name` is LIVE. The design doc keeps `native_binding` for
--     single-tenant and self-hosted deployments, `GATEWAY_TENANT_DB_ROUTING`
--     still accepts `binding` / `binding_strict`, and
--     `EnvBindingTenantDatabaseRouter` resolves `env[binding_name]` from this
--     column. `apps/gateway/test/tenancy/harness/` deploys that posture on
--     purpose so the fail-closed refusals stay observable.
--   * `database_uuid` is read by `NonAtomicD1RestTenantDatabaseRouter`
--     (`packages/storage/src/tenant-rest.ts`), which the `rest` mode still
--     mounts. `rest` is RETIRED BY DECISION and not yet removed from the
--     resolver; deleting the column would turn a documented, tested,
--     still-branched mode into a runtime `no such column`. Retiring the mode is
--     its own slice, and it is the slice that gets to drop this column.
--   * `database_name` is carried by both of the above as the operator-facing
--     name of the D1 database. It is dead the moment `rest` goes.
--
-- What this migration DOES do is stop them reading like a live design: they are
-- nullable now, they are grouped and commented as the D1-topology columns, and a
-- `durable_object` tenant writes NULL into all three. A row with three NULLs
-- there and `storage_backend = 'durable_object'` is unambiguous.
--
-- ## The new columns
--
--   * `storage_backend` — which topology this tenant's data actually lives in.
--     Its default is the LEGACY value, `native_binding`, and that is deliberate:
--     every writer that omits the column is a writer that predates this slice,
--     and every writer that predates this slice is a binding-topology one (it
--     had no other option). Defaulting to `durable_object` would relabel a real,
--     deployed D1 tenant as living somewhere it does not. The `durable_object`
--     provisioner always states the value explicitly.
--   * `provisioning_status` — the resumability signal, and the whole point of
--     the slice. Recording state and seeding the object span the control D1 and
--     a Durable Object and CANNOT be one transaction, so a crash between them is
--     inevitable and must be DETECTABLE. `pending` is written BEFORE the object
--     is touched and `ready` only after every step has confirmed; a row stuck at
--     `pending` or sitting at `failed` is exactly the "some tenants mysteriously
--     have no models" case, made visible and resumable.
--   * `schema_version` — kept, and re-pointed. It used to be "which tenant
--     migration was applied to this D1 database", written by whoever ran
--     `wrangler d1 migrations apply`. It is now the version the OBJECT last
--     REPORTED out of its own `storage_schema_migrations` ledger. The object
--     migrates itself on every cold start, so this is a cached observation and
--     never an instruction — nothing reads it to decide what to apply. Default
--     `0`, meaning "never observed", which is distinguishable from version 1.
--   * `catalog_seeded_at_unix` — NULL until the model catalog has been seeded.
--     The authoritative record is the object's own `tenant_provisioning_marks`
--     row (see `sql/d1-ts/tenant/0008_model_catalog.sql` for why it has to be);
--     this is the operator-visible projection of it.
--   * `last_error` — the refusal that stopped the last attempt, verbatim. NULL
--     on success. An operator resuming a half-provisioned tenant needs to know
--     whether it stopped because the `tenants` row was missing or because the
--     schema apply threw, and those get different fixes.
--   * `location_hint` — the `locationHint` the object was FIRST addressed with,
--     or NULL. A Durable Object is homed near its first `get()` and cannot be
--     moved afterwards (cost #1 in the design doc), so the choice is permanent
--     and must be auditable rather than accidental. Nothing passes a hint yet;
--     the column exists so that when something does, the value it used is
--     recorded rather than inferred from where the backfill job happened to run.
--
-- No CHECK on `storage_backend` or `provisioning_status`, following the dialect
-- rule this schema has followed since `0001_init_control.sql`: descriptive
-- enumerations are validated by the writer and again by the reader. The values
-- are `TenantDatabaseSource` and `TenantProvisioningStatus` in
-- `packages/storage/src/tenant-router.ts`.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS tenant_databases_v2 (
    tenant_id TEXT PRIMARY KEY,

    -- ---- provisioning state (the reason this table still exists) ----------
    storage_backend TEXT NOT NULL DEFAULT 'native_binding',
    provisioning_status TEXT NOT NULL DEFAULT 'pending',
    schema_version INTEGER NOT NULL DEFAULT 0,
    catalog_seeded_at_unix INTEGER,
    last_error TEXT,
    location_hint TEXT,

    -- ---- the D1-topology columns ------------------------------------------
    -- NULL for every `durable_object` tenant. See the header for why each is
    -- still here and which slice gets to drop it.
    database_uuid TEXT,
    database_name TEXT,
    binding_name TEXT,

    provisioned_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),

    -- Two tenants sharing one D1 database is the cross-tenant leak the whole
    -- topology exists to prevent, so the constraint stays. SQLite exempts NULL
    -- from UNIQUE, so every `durable_object` tenant writing NULL here is fine —
    -- and their isolation is enforced by `idFromName` being injective, not by
    -- a table constraint.
    UNIQUE (database_uuid)
);

-- Every pre-existing row describes a real, deployed D1 database, so it is
-- backfilled as `native_binding` and NOT as the new default. A row that was
-- routable (it names a binding) is `ready`; a row with no binding name is the
-- "provisioned but not yet redeployed" state the binding router already refuses,
-- which is exactly `pending` in the new vocabulary. Their `schema_version`
-- carries over verbatim: it was a real observation about a real database.
INSERT INTO tenant_databases_v2
    (tenant_id, storage_backend, provisioning_status, schema_version,
     catalog_seeded_at_unix, last_error, location_hint,
     database_uuid, database_name, binding_name,
     provisioned_at_unix, updated_at_unix)
SELECT
    tenant_id,
    'native_binding',
    CASE WHEN binding_name IS NULL OR binding_name = '' THEN 'pending' ELSE 'ready' END,
    schema_version,
    NULL,
    NULL,
    NULL,
    database_uuid,
    database_name,
    binding_name,
    provisioned_at_unix,
    updated_at_unix
FROM tenant_databases;

DROP TABLE tenant_databases;

ALTER TABLE tenant_databases_v2 RENAME TO tenant_databases;

-- Recreated because `DROP TABLE` took the original with it. Same index, same
-- reason: the binding router's reverse lookup.
CREATE INDEX IF NOT EXISTS idx_tenant_databases_binding
    ON tenant_databases(binding_name);

-- The operator's roster query — "which tenants are not ready" — and the sweep a
-- resume job runs. Without it that is a full scan of the whole fleet.
CREATE INDEX IF NOT EXISTS idx_tenant_databases_status
    ON tenant_databases(provisioning_status, tenant_id);
