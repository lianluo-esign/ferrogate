-- ===========================================================================
-- Auto-throttle moves into the tenant object (control-D1 removal)
--
-- `spend_throttles` was born in `../control/0010_spend_anomaly.sql`, in the same
-- database the admission path already read `quota_policies` and `plans` from, so
-- the overlay cost ONE extra statement in the SAME `db.batch()` — one round
-- trip, one implicit transaction (`apps/gateway/src/ratelimit/quota.ts`).
--
-- The per-tenant-object cutover removes the shared control database, so the
-- table has to live somewhere a tenant's OWN storage can hold it. The detector
-- only ever writes `scope_type = 'tenant'` rows (`apps/control-plane/src/finops/`
-- consults tenant scope alone), so every throttle a tenant can carry is a row
-- ABOUT that tenant — it belongs in that tenant's object with the rest of its
-- money and usage.
--
-- ## The shape is kept byte-for-byte, on purpose
--
-- `(scope_type, scope_id)` is retained even though `scope_type` is always
-- `'tenant'` and `scope_id` is always this object's tenant here. Keeping the
-- columns means the finops WRITE (`applyThrottle`) and the three admission READS
-- (gateway / agent-runtime / mcp) run the IDENTICAL SQL against the object
-- handle they run against the control handle — the cutover is a change of which
-- database the statement is bound to, not a rewrite of the statement. It also
-- matches the composite-storage-key convention `0001_init_tenant.sql` sets out:
-- the tenant id stays in the row so a mis-routed handle cannot silently pass a
-- foreign throttle to admission.
--
-- ## Why it is safe to ship this migration AHEAD of the readers
--
-- Nothing reads or writes the object copy until the finops writer and the three
-- admission readers are switched over in a later release. Until then this table
-- sits empty, and an empty throttle table is exactly the "no brake applied"
-- state admission already treats as normal. The readers probe for the table
-- STRUCTURALLY and skip the read when it is absent (`spendThrottlesProvisioned`
-- and its agent-runtime / mcp twins), so the ordering that fails safe is the one
-- this migration establishes: the table exists before any reader is pointed at
-- it, never the reverse — which is the same "provisioning precedes traffic" rule
-- the control-side reader documents.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS spend_throttles (
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    rpm_limit INTEGER NOT NULL,
    -- Free text for the operator reading `GET /admin/v1/spend-anomalies` — the
    -- machine-readable link is `episode_id`.
    reason TEXT NOT NULL,
    episode_id TEXT,
    created_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    PRIMARY KEY (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_spend_throttles_expiry
    ON spend_throttles(expires_at_unix);
