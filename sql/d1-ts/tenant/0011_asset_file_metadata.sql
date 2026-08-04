-- ===========================================================================
-- OpenAI Files metadata on the existing stored asset row (#742)
--
-- Files are not a second object or quota ledger. The asset row remains the
-- source of truth for bytes, screening, visibility, and lifecycle; this
-- nullable JSON projection carries the OpenAI filename/purpose pair without
-- exposing it on the ordinary `/v1/assets` summary.
-- ===========================================================================

ALTER TABLE stored_assets ADD COLUMN metadata_json TEXT;
