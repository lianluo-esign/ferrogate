-- ===========================================================================
-- Platform/unattributed billing report outbox (Zero-D1 Plan B).
--
-- This is the 'separate slice' `0004_billing.sql` deferred (0004 lines 26-30):
-- the mutable `billing_report_outbox` that `0004` deliberately left out because,
-- unlike the append-only `billing_events` / `billing_ledger`, it changes over
-- its lifecycle (reschedule / dead-letter / reap) and its drain
-- (`D1DurableOutbox`) is bound to the same database as the writer.
--
-- Row shape mirrors the CONTROL outbox
-- (`sql/d1-ts/control/0001_init_control.sql` billing_report_outbox) VERBATIM,
-- PLUS a nullable `tenant_id` for byte-shape parity with the tenant/control-0020
-- outbox. Every row here is unattributed by construction (`tenant_id IS NULL`);
-- the control-variant `BILLING_OUTBOX_INSERT_SQL` never binds the column, so it
-- simply keeps its NULL default. The control-variant outbox statements in
-- `packages/billing/src/metering/d1.ts` — `BILLING_OUTBOX_INSERT_SQL`,
-- `BILLING_OUTBOX_LIST_DUE_SQL` (which JOINs `billing_ledger` on `id`),
-- `BILLING_OUTBOX_DELETE_SQL`, `BILLING_OUTBOX_RESCHEDULE_SQL` and
-- `BILLING_OUTBOX_DEAD_LETTER_SQL` — all apply here VERBATIM.
--
-- The drain in THIS slice is the gateway's `usage.sweepPlatform()` RECOVERY
-- sweep: the request path publishes the platform outbox row once in the same
-- best-effort pass that writes it and reaps it, so this table is EMPTY at rest
-- and a row a sweep finds is unambiguously a crash remnant. Control remains the
-- authoritative request-path drain until the deferred G2 flip; readers of this
-- object's outbox (and its dead-letters) are deferred to the polaris slice.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS billing_report_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_unix INTEGER NOT NULL,
    dead_lettered_at_unix INTEGER,
    created_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_platform_billing_report_outbox_due
    ON billing_report_outbox(next_attempt_unix);

CREATE INDEX IF NOT EXISTS idx_platform_billing_report_outbox_dead
    ON billing_report_outbox(dead_lettered_at_unix);
