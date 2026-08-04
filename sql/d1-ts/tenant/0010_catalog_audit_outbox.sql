-- ===========================================================================
-- Tenant catalog audit outbox (#813)
--
-- Catalog mutations commit in a tenant Durable Object while the existing
-- hash-chained audit log lives in the control database. Those databases cannot
-- share a transaction. This outbox records the audit payload in the same
-- tenant batch as the catalog mutation and revision bump, so a temporary
-- control-database failure leaves durable evidence to reconcile later.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS catalog_audit_outbox (
    id                TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    revision          INTEGER NOT NULL,
    action            TEXT NOT NULL,
    collection        TEXT NOT NULL,
    record_json       TEXT NOT NULL,
    audit_json        TEXT NOT NULL,
    request_id        TEXT NOT NULL DEFAULT '',
    actor_scope       TEXT NOT NULL,
    actor_tenant_id   TEXT,
    created_at_unix   INTEGER NOT NULL DEFAULT (unixepoch()),
    attempt_count     INTEGER NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, revision)
);

CREATE INDEX IF NOT EXISTS idx_catalog_audit_outbox_pending
    ON catalog_audit_outbox (tenant_id, revision, created_at_unix);
