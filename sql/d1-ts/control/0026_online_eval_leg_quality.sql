-- ===========================================================================
-- Per-provider-leg online-eval quality aggregate + candidate-coverage opt-in (#894)
--
-- Numbered 0026 rather than 0025: 0025 is reserved for the platform model
-- catalog (#889), which is in flight on another branch. Migrations here are
-- discovered by directory glob with no manifest, so a gap is inert and a REUSED
-- number is silently wrong.
--
-- ## online_eval_leg_quality
--
-- A PROJECTION, not authority. `online_eval_scores` in the tenant object holds
-- the scores; this table holds one recomputed row per grouping tuple, REPLACED
-- on every refresh (queue consumer + cron) exactly as `0024_tenant_rollups.sql`
-- replaces a tenant's rollups. Nothing accumulates here, so a redelivered queue
-- batch or a double cron tick cannot inflate a mean.
--
-- The grouping tuple is the one `apps/gateway/src/evals/policy.ts:20-46` says is
-- the only legitimate comparison axis — same tenant, same criterion, same judge
-- — narrowed further to the FAILOVER LADDER (`logical_model`) and to the LEG
-- inside it (`provider`, `provider_model`). `ONLINE_EVAL_WINDOW_AGGREGATE_SQL`
-- stops at `logical_model`, which is constant across one ladder and therefore
-- cannot rank the ladder's candidates against each other.
--
-- There is no `mean` column on purpose: the reader divides `score_total` by
-- `score_count`, and storing a pre-divided mean would make a partially-refreshed
-- row look authoritative when its count no longer matched it.
--
-- ## quota_policies.online_eval_coverage_percent
--
-- Candidate coverage MIRRORS a request to a non-primary ladder candidate so that
-- candidate accumulates comparable scores. That spends real provider tokens on a
-- response no client sees, and it ships the tenant's prompt to a second
-- provider. Both are consent decisions belonging to the tenant, so the knob is a
-- column on that tenant's own governance row beside the other `online_eval_*`
-- controls — NOT a fleet var. DEFAULT 0 is OFF, and off is what every existing
-- deployment gets.
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

-- The GROUP BY the refresh runs. Without this the recompute is a full scan of
-- the tenant's scores; `idx_online_eval_scores_trend` stops at `criterion_id`.
CREATE INDEX IF NOT EXISTS idx_online_eval_scores_leg
    ON online_eval_scores(tenant, criterion_id, judge_model, logical_model, provider, provider_model);

ALTER TABLE quota_policies ADD COLUMN online_eval_coverage_percent REAL NOT NULL DEFAULT 0;
