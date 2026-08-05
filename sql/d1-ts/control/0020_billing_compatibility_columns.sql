-- ===========================================================================
-- Billing compatibility projection columns (#858, #831)
--
-- New billing authority is tenant-local. These control tables remain during
-- backfill and fleet-report cutover, so give their payload-only rows an
-- explicit tenant address. Existing rows are deliberately nullable: their
-- tenant can be recovered from the legacy JSON during backfill, while every
-- new tenant-authoritative row carries a required tenant_id in its source.
-- ===========================================================================

ALTER TABLE billing_ledger ADD COLUMN tenant_id TEXT;
ALTER TABLE billing_report_outbox ADD COLUMN tenant_id TEXT;
ALTER TABLE billing_events ADD COLUMN tenant_id TEXT;

-- Recover the routing tenant for legacy payload rows when the old document
-- already carried it. Rows with malformed or tenantless payloads stay NULL and
-- remain platform-only until an operator can reconcile them explicitly.
UPDATE billing_ledger
SET tenant_id = NULLIF(trim(CAST(json_extract(entry_json, '$.tenant.organization_id') AS TEXT)), '')
WHERE tenant_id IS NULL
  AND json_valid(entry_json) = 1
  AND typeof(json_extract(entry_json, '$.tenant.organization_id')) = 'text'
  AND trim(CAST(json_extract(entry_json, '$.tenant.organization_id') AS TEXT)) <> '';

UPDATE billing_report_outbox
SET tenant_id = NULLIF(trim(CAST(json_extract(event_json, '$.tenant.organization_id') AS TEXT)), '')
WHERE tenant_id IS NULL
  AND json_valid(event_json) = 1
  AND typeof(json_extract(event_json, '$.tenant.organization_id')) = 'text'
  AND trim(CAST(json_extract(event_json, '$.tenant.organization_id') AS TEXT)) <> '';

UPDATE billing_events
SET tenant_id = NULLIF(trim(CAST(json_extract(event_json, '$.tenant.organization_id') AS TEXT)), '')
WHERE tenant_id IS NULL
  AND json_valid(event_json) = 1
  AND typeof(json_extract(event_json, '$.tenant.organization_id')) = 'text'
  AND trim(CAST(json_extract(event_json, '$.tenant.organization_id') AS TEXT)) <> '';

CREATE INDEX IF NOT EXISTS idx_control_billing_ledger_tenant
    ON billing_ledger(tenant_id, created_at_unix, id);

CREATE INDEX IF NOT EXISTS idx_control_billing_report_outbox_tenant
    ON billing_report_outbox(tenant_id, next_attempt_unix, id);

CREATE INDEX IF NOT EXISTS idx_control_billing_events_tenant
    ON billing_events(tenant_id, occurred_at_unix, request_id, provider_attempt_index);
