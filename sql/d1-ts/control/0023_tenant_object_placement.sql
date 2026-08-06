-- ===========================================================================
-- Tenant Durable Object placement and jurisdiction (#827)
--
-- Placement is decided by the first namespace get(). The location hint is a
-- best-effort preference; the jurisdiction is part of the object address and
-- is a hard boundary. These fields are nullable for rows written before this
-- migration so historical absence is not mistaken for a new decision.
-- ===========================================================================

ALTER TABLE tenant_databases ADD COLUMN location_hint_source TEXT;
ALTER TABLE tenant_databases ADD COLUMN location_hint_recorded_at_unix INTEGER;
ALTER TABLE tenant_databases ADD COLUMN jurisdiction TEXT;
