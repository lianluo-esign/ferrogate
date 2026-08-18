-- ===========================================================================
-- Shared control-plane config, MIRRORED read-only into the tenant DO (#948)
--
-- The control plane owns the platform's shared configuration — billing groups
-- (分组), plans (套餐), announcements (公告), the model catalog. That config is
-- authored ONCE, on the control DB, by an operator on Vega. Historically every
-- tenant read that needed it paid a synchronous cross-region round trip to the
-- single `ControlDataObject` to MERGE those shared rows in at read time (the
-- `control_plane_resources` platform-row fence in `store/split.ts`). That fence
-- is the per-request tax this migration exists to remove.
--
-- ## The channel, and why the mirror is here
--
-- Shared config now flows ONE WAY, asynchronously, into each tenant's own
-- Durable Object: the control plane pushes a snapshot (at tenant creation) and
-- deltas (on a cron cadence) through the privileged tenant-write RPC
-- (`TenantDataObject.privilegedBatch`). After that, a tenant resolves shared
-- config from THESE local tables with no control-plane hop at all, and every
-- authenticated tenant operation touches only its own object. The control DB
-- and the tenant DB become coupled solely by this push — performance isolation
-- (no shared single-thread on the hot path) and security isolation (the tenant
-- never reaches across into the control DB) in the same seam.
--
-- ## READ-ONLY inside the tenant
--
-- These tables are a projection the tenant may only SELECT. The privileged
-- push RPC is the ONLY writer; ordinary tenant `query`/`batch` traffic is
-- refused against them by `PRIVILEGED_WRITE_TABLES` in
-- `packages/storage/src/tenant-data-object.ts`, the same gate that protects the
-- role-binding projection. A tenant cannot manufacture its own billing
-- multiplier or plan any more than it can grant itself a permission.
--
-- ## Eventual consistency is the contract
--
-- A config edit reaches a tenant at most one cron cadence late. That is
-- acceptable for plans/groups/announcements (none are on the money hot path in
-- a way a few minutes of staleness breaks — a dangling/updated multiplier
-- fails toward 1.0, never a 500). `config_revision` records which control-plane
-- revision produced each mirrored row so a push is auditable and, later,
-- delta-able. Pushes are monotonic by revision; the applier is last-writer-wins
-- under the (rare) stale-push race and self-heals on the next cadence.
--
-- DIALECT: identical rules to the rest of the tenant schema — no cross-database
-- FK (the source rows live in the CONTROL database), BOOLEAN -> INTEGER 0/1,
-- provider edges DENORMALISED to a JSON array because a read-only mirror has no
-- need of the source's junction table.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Per-domain sync cursor: the highest control-plane revision this tenant has
-- applied for each shared-config domain ('billing_groups', 'plans', ...).
--
-- One row per domain. The push RPC advances it in the SAME transaction as the
-- domain's rows, so the cursor and the data it describes can never disagree.
-- A domain with no row yet reads as revision 0 — "never synced" — which is
-- exactly what makes an already-provisioned tenant back-fill on the first cron
-- pass after this migration lands.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shared_config_cursor (
    domain          TEXT PRIMARY KEY,
    revision        INTEGER NOT NULL DEFAULT 0,
    applied_at_unix INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ---------------------------------------------------------------------------
-- Billing groups (分组) — mirror of the control DB's `platform_billing_groups`.
--
-- Column parity with the source (id, name, multiplier, description, enabled)
-- plus the group's bound provider ids as a JSON array (the source keeps them in
-- the `platform_billing_group_providers` junction; a read-only mirror flattens
-- it). `multiplier` stays REAL so the tenant-local multiplier comparison is the
-- byte-identical arithmetic the gateway does today against the control row.
-- `config_revision` stamps the push that wrote the row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS shared_billing_groups (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    multiplier        REAL NOT NULL DEFAULT 1.0,
    description       TEXT,
    enabled           INTEGER NOT NULL DEFAULT 1,
    provider_ids_json TEXT NOT NULL DEFAULT '[]',
    config_revision   INTEGER NOT NULL DEFAULT 0,
    synced_at_unix    INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Enabled-group lookup for the multiplier resolution the gateway will read
-- locally once the fence is removed.
CREATE INDEX IF NOT EXISTS idx_shared_billing_groups_enabled
    ON shared_billing_groups(enabled);

-- NB: this file deliberately does NOT write `storage_schema_migrations`. Only
-- `0001_init_tenant.sql` seeds that ledger (version 1); every migration after
-- it records nothing of its own. The DO migration runner
-- (`tenant-data-object.ts`) stamps each applied version into the ledger itself,
-- and under D1/native the ledger is vestigial (wrangler's `d1_migrations` does
-- the real bookkeeping, and the native leg deliberately reports schema
-- version 1). Adding an explicit INSERT here breaks that native-leg invariant.
