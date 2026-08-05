-- ===========================================================================
-- Tenant-qualified derived projections (#852, #831)
--
-- The rows remain in control D1 for fleet reads, but their logical ids are not
-- account-global. A projection key prevents tenant B from overwriting tenant A
-- when a request, shadow leg, anomaly id, or audit id is reused.
-- ===========================================================================

ALTER TABLE audit_events ADD COLUMN projection_key TEXT;
UPDATE audit_events
   SET projection_key = length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || id
 WHERE projection_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_events_projection_key
    ON audit_events(projection_key);

ALTER TABLE online_eval_scores ADD COLUMN projection_key TEXT;
UPDATE online_eval_scores
   SET projection_key = length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || request_id || ':' || criterion_id
 WHERE projection_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_online_eval_scores_projection_key
    ON online_eval_scores(projection_key);

ALTER TABLE online_eval_regressions ADD COLUMN projection_key TEXT;
UPDATE online_eval_regressions
   SET projection_key = length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || claim_key
 WHERE projection_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_online_eval_regressions_projection_key
    ON online_eval_regressions(projection_key);

ALTER TABLE experiment_shadow_legs ADD COLUMN projection_key TEXT;
UPDATE experiment_shadow_legs
   SET projection_key = length(COALESCE(tenant, '')) || ':' || COALESCE(tenant, '') || ':' || leg_id
 WHERE projection_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_experiment_shadow_legs_projection_key
    ON experiment_shadow_legs(projection_key);

ALTER TABLE spend_anomaly_episodes ADD COLUMN projection_key TEXT;
UPDATE spend_anomaly_episodes
   SET projection_key = length(COALESCE(scope_id, '')) || ':' || COALESCE(scope_id, '') || ':' || id
 WHERE projection_key IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_spend_anomaly_episodes_projection_key
    ON spend_anomaly_episodes(projection_key);
