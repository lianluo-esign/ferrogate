-- ===========================================================================
-- Tenant-owned billing and wallet consistency domain (#858, #831)
--
-- A priced charge, its billing event, report intent and wallet settlement now
-- live in the same tenant database. D1 batch() therefore provides the only
-- transaction boundary that matters for reserve/settle/release accounting:
-- the charge cannot commit without its report intent or its wallet debit.
--
-- `tenant_id` remains explicit even though a tenant object is physically
-- isolated. It is the mis-routing tripwire and lets control-plane projections
-- address a source row without parsing an opaque JSON payload.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS billing_ledger (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    created_at_unix INTEGER NOT NULL,
    entry_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_billing_ledger_scope
    ON billing_ledger(tenant_id, organization_id, project_id, api_key_id);

CREATE INDEX IF NOT EXISTS idx_tenant_billing_ledger_created
    ON billing_ledger(tenant_id, created_at_unix, id);

CREATE TABLE IF NOT EXISTS billing_report_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix INTEGER NOT NULL,
    dead_lettered_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_billing_report_outbox_due
    ON billing_report_outbox(tenant_id, next_attempt_unix);

CREATE INDEX IF NOT EXISTS idx_tenant_billing_report_outbox_dead
    ON billing_report_outbox(tenant_id, dead_lettered_at_unix);

CREATE TABLE IF NOT EXISTS billing_events (
    billing_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    provider_attempt_index INTEGER NOT NULL DEFAULT 0,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenant_billing_events_occurred
    ON billing_events(tenant_id, occurred_at_unix, request_id, provider_attempt_index);
