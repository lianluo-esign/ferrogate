-- ===========================================================================
-- `asset_bundle_files` — the per-bundle file index for `static_site` (#736)
--
-- A static website is a directory tree, but `stored_assets` describes exactly
-- one object with one content type. This table is the missing half: for a
-- `static_site` version published as a tar/zip, one row per file inside it,
-- mapping the bundle-relative path to the R2 key holding those bytes.
--
-- ## Why it is a side table and not columns on `stored_assets`
--
-- Because a bundle version must NOT get its own resolution path. Channels,
-- semver ranges, platform variants, yank and the manifest all resolve to a
-- `stored_assets` row, and that stays true byte for byte for a bundle: the row
-- is the version, this table is only what is inside it. `asset_id` is the same
-- `stored_assets.id`, so a pull resolves the version first — through the one
-- registry path in `src/assets/registry.ts` — and consults this table only
-- afterwards, to pick which file of the already-resolved artifact to serve. A
-- yanked bundle therefore drops out of channel resolution before this table is
-- ever read, which is exactly the property a second resolution path would lose.
--
-- ## Why there is no FOREIGN KEY
--
-- The rest of this schema does not declare them either (see the note at the top
-- of `0001_init_tenant.sql`): D1 does not enforce foreign keys by default, so a
-- declared one would be documentation that reads as an enforced constraint.
-- `AssetService` owns the two directions instead, and both are explicit:
-- `#unwindBundlePublish` drops the index when a publish fails mid-expansion,
-- and `deleteAsset` drops it — and reclaims the objects it names — after the
-- version row's delete has committed.
--
-- ## Ordering, and why a partial index is never observable
--
-- The whole index of one bundle is written while the version row is still
-- `pending_scan`, i.e. while `isDownloadable` keeps it out of every read path.
-- Only after every object AND every row has landed does the existing
-- `promotePendingAssetVisibility` CAS move the version to `visible`. A crash
-- anywhere before that leaves a version nothing can resolve, which is the whole
-- definition of atomic here.
--
-- ## Keys
--
-- The primary key is `(asset_id, path)`: a bundle may not contain one path
-- twice (the expander refuses duplicates too — this is the durable backstop),
-- and it is also the exact lookup a `?path=` pull performs. `tenant_id` is
-- carried on every row for the same reason every other table in this database
-- carries it: under `GATEWAY_TENANT_DB_ROUTING = "off"` one physical database
-- holds many tenants and the predicate IS the isolation.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS asset_bundle_files (
    asset_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    path TEXT NOT NULL,
    storage_uri TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    PRIMARY KEY (asset_id, path)
);

-- Covers the "everything in this bundle" read that `deleteAsset` and the
-- unwind path perform, and keeps the tenant predicate index-satisfiable.
CREATE INDEX IF NOT EXISTS idx_asset_bundle_files_tenant
    ON asset_bundle_files(tenant_id, asset_id);
