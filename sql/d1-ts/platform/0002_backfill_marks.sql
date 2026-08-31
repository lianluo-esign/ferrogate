-- ===========================================================================
-- One-time-migration bookkeeping for the platform object (Zero-D1 Plan B).
--
-- The control-`WHERE tenant IS NULL`→platform-object guardrail backfill needs a
-- durable, object-local marker so it is resumable and, once complete, cannot be
-- reopened by an older in-flight call copying later projection lag into the
-- authority. The tenant bridge stores that marker in `tenant_provisioning_marks`
-- keyed by `tenant_id`; the platform singleton has no tenant id, so it keeps the
-- same JSON `detail` shape keyed by `mark` alone.
--
-- Deliberately NOT the schema ledger (`platform_schema_applied`): that table is
-- the migration applier's own gate and is keyed/queried by migration name — a
-- data-backfill marker sharing it would be a category error. This is a separate,
-- tiny table whose only writer/reader is
-- `apps/control-plane/src/store/platform_guardrail_evidence_backfill.ts`.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS platform_backfill_marks (
    mark TEXT PRIMARY KEY,
    detail TEXT,
    applied_at_unix INTEGER NOT NULL DEFAULT 0
);
