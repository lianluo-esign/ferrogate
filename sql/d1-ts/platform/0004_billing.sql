-- ===========================================================================
-- Platform/unattributed billing evidence (Zero-D1 Plan B).
--
-- The `PlatformDataObject` singleton is the authoritative home for
-- platform-scoped billing rows (`tenant_id IS NULL` — a metered call the
-- gateway could not attribute to a tenant: a platform-operator / static
-- platform-key call, or any settlement whose attribution did not resolve a
-- tenant id). Those rows have no TenantDataObject to live in and today sit in
-- the control projection only, so removing the entire control D1 requires this
-- object to hold them — they are exactly the rows every tenant fan-out reader
-- cannot reach, because there is no roster tenant for an unattributed charge.
--
-- Row shape mirrors the CONTROL billing tables
-- (`sql/d1-ts/control/0001_init_control.sql` billing_events / billing_ledger,
-- plus the nullable `tenant_id` from `0020_billing_compatibility_columns.sql`),
-- so the gateway's CONTROL-variant settlement INSERTs
-- (`BILLING_EVENT_INSERT_SQL` / `BILLING_LEDGER_INSERT_SQL` in
-- `packages/billing/src/metering/d1.ts`) apply here VERBATIM — the platform
-- shadow leg binds the same statements, and `tenant_id` simply keeps its NULL
-- default (every row here is unattributed by construction).
--
-- Two deliberate scope choices:
--   * `tenant_id` is kept (not dropped) and NULLable so the row stays
--     byte-shape-compatible with the control tables and the one-time
--     control-`WHERE tenant_id IS NULL` backfill is a lossless column copy.
--   * `billing_report_outbox` is NOT mirrored here. Unlike these two
--     append-only tables it is mutable over its lifecycle (reschedule /
--     dead-letter / reap) and its drain (`D1DurableOutbox`) is bound to the
--     same database as the writer; migrating it means moving the drain too, so
--     it is a separate slice.
-- ===========================================================================

-- Settled metering events. `billing_event_id` is the primary key, so an insert
-- replay of the same settled event is idempotent through the PK (matching the
-- control `ON CONFLICT (billing_event_id) DO NOTHING`); the (request_id,
-- provider_attempt_index) pair is the #135 provider-attempt identity.
CREATE TABLE IF NOT EXISTS billing_events (
    billing_event_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    request_id TEXT NOT NULL,
    provider_attempt_index INTEGER NOT NULL DEFAULT 0,
    occurred_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

-- Load-bearing: every reader that will one day read this object reaches
-- billing_events by `request_id` (the request_logs<->billing correlation), and
-- the control table has no standalone request_id index. No tenant column leads
-- any index because every row is platform-scoped (tenant_id IS NULL).
CREATE INDEX IF NOT EXISTS idx_platform_billing_events_request
    ON billing_events(request_id, provider_attempt_index);

CREATE INDEX IF NOT EXISTS idx_platform_billing_events_occurred
    ON billing_events(occurred_at_unix, request_id, provider_attempt_index);

-- The ledger row batched alongside each event. `id` == the event's
-- `billing_event_id`; append-only and idempotent through the PK.
CREATE TABLE IF NOT EXISTS billing_ledger (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    organization_id TEXT,
    project_id TEXT,
    api_key_id TEXT,
    created_at_unix INTEGER NOT NULL,
    entry_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_platform_billing_ledger_created
    ON billing_ledger(created_at_unix, id);
