-- ===========================================================================
-- Tenant-owned online-eval leg-quality projection (Track A write migration)
--
-- `online_eval_leg_quality` is a recomputed PROJECTION (one row per grouping
-- tuple, REPLACED on every refresh — nothing accumulates, so a redelivered queue
-- batch or a double cron tick cannot inflate a mean). Its scores authority,
-- `online_eval_scores`, already lives in this tenant object (0019); the recompute
-- GROUP BY index `idx_online_eval_scores_leg` is already here (0023). The one
-- thing missing was this derived table itself, so the refresh could only write
-- the shared CONTROL copy.
--
-- This migration adds the tenant-object home so `refreshOnlineEvalLegQuality`
-- can DUAL-WRITE: the tenant object becomes the authoritative projection while
-- the control copy stays the router's read source until the reader is switched.
-- The table shape MUST match the control copy (`0026_online_eval_leg_quality`)
-- byte-for-byte in columns and key, because the same upsert/prune SQL writes
-- both. `IF EXISTS`/`IF NOT EXISTS` keep it idempotent (0013 precedent).
--
-- No `mean` column, on purpose: the reader divides `score_total` by
-- `score_count`; a stored pre-divided mean would look authoritative when a
-- partial refresh left its count no longer matching it.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS online_eval_leg_quality (
    tenant TEXT NOT NULL,
    criterion_id TEXT NOT NULL,
    judge_model TEXT NOT NULL,
    logical_model TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_model TEXT NOT NULL,
    score_total REAL NOT NULL,
    score_count INTEGER NOT NULL,
    window_start_unix INTEGER NOT NULL,
    as_of_unix INTEGER NOT NULL,
    PRIMARY KEY (tenant, criterion_id, judge_model, logical_model, provider, provider_model)
);

-- The router's read: one seek per tenant, the whole ladder set in one scan.
CREATE INDEX IF NOT EXISTS idx_online_eval_leg_quality_ladder
    ON online_eval_leg_quality(tenant, logical_model, criterion_id, judge_model);
