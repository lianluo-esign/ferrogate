-- ===========================================================================
-- Index the per-leg score grouping inside the tenant object (#894)
--
-- The scores are AUTHORITATIVE here, so the per-leg aggregate is recomputed by
-- reading this table (`apps/gateway/src/evals/leg-quality.ts`) and only the
-- resulting rows are projected into control D1. The existing indexes stop at
-- `(tenant, criterion_id, scored_at_unix)` / `(tenant, logical_model, ...)`,
-- neither of which covers a GROUP BY that also names `judge_model`, `provider`
-- and `provider_model`.
--
-- No aggregate TABLE is created here: the reader that needs it is the ROUTER,
-- which runs in the gateway isolate with the control binding, and a per-object
-- copy would be a second authority for the same projection.
-- ===========================================================================

CREATE INDEX IF NOT EXISTS idx_online_eval_scores_leg
    ON online_eval_scores(tenant, criterion_id, judge_model, logical_model, provider, provider_model);
