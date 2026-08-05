-- ===========================================================================
-- Idempotent usage-event claims
--
-- The control billing claim and this tenant claim cannot share a D1
-- transaction. The tenant usage batch guards every additive statement with
-- `applied_at_unix IS NULL` and marks the claim applied as its final statement.
-- A retry after the control claim has already won therefore repairs the object
-- without adding the counters twice.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS usage_event_claims (
    source_id TEXT PRIMARY KEY,
    applied_at_unix INTEGER
);
