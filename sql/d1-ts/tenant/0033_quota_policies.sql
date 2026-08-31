-- ===========================================================================
-- Quota policy chain moves into the tenant object (control-D1 removal)
--
-- `quota_policies` was a CONTROL-only table under split rule (a)/(b) of
-- `../control/0001_init_control.sql`: the Rust `resolve_effective_quota`
-- signature took no tenant id, so the whole key -> workspace -> project ->
-- tenant chain was kept in one place. That reasoning is a Rust-signature
-- artifact, not a data-ownership fact. Every row a request can match is scoped
-- to one of that request's OWN ids (`scope_type IN ('tenant','project',
-- 'workspace','key')`, and a project/workspace/key each belongs to exactly one
-- tenant), so the entire chain for any single request belongs to ONE tenant and
-- can live in that tenant's object with the rest of its limits and money.
--
-- ## The shape is the full squashed control shape, on purpose
--
-- The control table grew 16 base columns (0001) plus 25 more by ALTER across
-- 0006 (attribution tags), 0007 (residency), 0009/0026/0027 (online eval) and
-- 0010 (spend anomaly). The tenant object applies its schema fresh on cold
-- start, so this migration reproduces the FINAL 41-column shape in one CREATE
-- rather than replaying the historical ALTER sequence. Keeping every column
-- name and type byte-for-byte means the eight readers that select column
-- SUBSETS from this table -- the three admission workers (16-col chain read),
-- the gateway attribution / online-eval / residency sources, the control-plane
-- finops spend-anomaly pass and the control-plane residency read -- run the
-- IDENTICAL SQL against the object handle they run against the control handle.
-- The cutover is a change of which database the statement binds to, not a
-- rewrite of the statement. `UNIQUE (scope_type, scope_id)` is retained (the
-- routes derive `id` as `scope_type:scope_id`, so the two agree) and matches
-- the composite-storage-key convention of `0001_init_tenant.sql`.
--
-- ## Why it is safe to ship this migration AHEAD of the readers and writers
--
-- Nothing reads or writes the object copy until the operator write route, the
-- eight readers and the finops fleet scan are switched over together in a later
-- release. Until then this table sits empty. The admission chain read matches
-- no rows and returns no policy -- which is exactly the "no configured policy,
-- nothing restricts" state admission already treats as normal (an unprovisioned
-- deployment has no `quota_policies` rows either). The finops fleet scan
-- (`WHERE scope_type = 'tenant'`) that today reads every tenant at once becomes
-- a per-tenant fan-out over the same objects the episode pass already iterates.
-- So the ordering that fails safe is the one this migration establishes: the
-- table exists on every object BEFORE any reader or writer is pointed at it,
-- never the reverse -- the same "provisioning precedes traffic" rule the
-- control-side reader documents and `0032_spend_throttles.sql` follows.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS quota_policies (
    id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    model_allowlist_json TEXT NOT NULL DEFAULT '[]',
    rpm_limit INTEGER,
    tpm_limit INTEGER,
    monthly_budget_usd REAL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch()),
    alert_threshold_pcts_json TEXT NOT NULL DEFAULT '[]',
    asset_storage_quota_bytes INTEGER,
    monthly_egress_bytes_budget INTEGER,
    download_rpm_limit INTEGER,
    -- Per-object (not cumulative) asset byte ceiling, tenant-only (#259),
    -- distinct from the cumulative asset_storage_quota_bytes above. The
    -- tenant-only invariant is enforced by validateQuotaPolicy
    -- (packages/storage/src/quota.ts), not by a CHECK.
    asset_max_object_bytes INTEGER,
    -- Per-tenant monthly USD ceiling on CF-hosted-agent runtime cost (#428),
    -- money (REAL) mirroring monthly_budget_usd, settable at ANY scope and
    -- merged min-across-the-chain (NOT tenant-only).
    agent_cost_budget_usd REAL,
    -- 0006 attribution-tag policy.
    required_tags_json TEXT NOT NULL DEFAULT '[]',
    on_missing_tags TEXT,
    -- 0007 residency policy.
    residency_regions_json TEXT NOT NULL DEFAULT '[]',
    require_zero_data_retention INTEGER NOT NULL DEFAULT 0,
    log_residency TEXT,
    -- 0009 online-eval sampling and regression.
    online_eval_enabled INTEGER NOT NULL DEFAULT 0,
    online_eval_sample_rate REAL,
    online_eval_sampling_unit TEXT,
    online_eval_judge_model TEXT,
    online_eval_criteria_json TEXT,
    online_eval_regression_drop REAL,
    online_eval_regression_min_samples INTEGER,
    -- 0010 spend-anomaly detector config.
    spend_anomaly_enabled INTEGER NOT NULL DEFAULT 1,
    spend_anomaly_baseline_windows INTEGER,
    spend_anomaly_min_baseline_windows INTEGER,
    spend_anomaly_min_active_windows INTEGER,
    spend_anomaly_min_window_usd REAL,
    spend_anomaly_ratio REAL,
    spend_anomaly_critical_ratio REAL,
    spend_anomaly_cooldown_secs INTEGER,
    spend_anomaly_forecast_min_pct REAL,
    spend_anomaly_auto_throttle_rpm INTEGER,
    spend_anomaly_throttle_ttl_secs INTEGER,
    -- 0026 online-eval coverage target.
    online_eval_coverage_percent REAL NOT NULL DEFAULT 0,
    -- 0027 task-aware cost/quality routing.
    online_eval_cost_quality_routing INTEGER NOT NULL DEFAULT 0,
    UNIQUE (scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_quota_policies_scope
    ON quota_policies(scope_type, scope_id);
