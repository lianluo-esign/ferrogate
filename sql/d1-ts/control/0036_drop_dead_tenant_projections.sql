-- ===========================================================================
-- Drop six dead tenant-attributed projection tables (Track A red-line)
--
-- These six control-side tables are retired projection *mirrors*. Their
-- authoritative home is the per-tenant TenantDataObject, and every live
-- producer and reader already targets that tenant object — the control copies
-- have no remaining writer or reader:
--
--   * managed_worker_isolation_evidence — written by agent-runtime to the
--     tenant object (runs/evidence.ts); control mirror had no reader.
--   * online_eval_regressions           — object-first producer writes the
--     tenant table (evals/regression.ts); control copy was schema-only.
--   * usage_monthly_rollups             — usage ledger writes the tenant
--   * usage_aggregate_rollups             object (metering sink stopped
--   * usage_metadata_rollups             writing these to control; the repair
--   * observed_agent_presence            sweeps are disabled). All readers use
--     the tenant handle (admin_managed_worker / billing / quota).
--
-- Keeping the empty control mirrors implies a second source of truth and lets a
-- future writer accidentally bypass tenant isolation — the exact red line this
-- program eliminates. `IF EXISTS` keeps this idempotent for fresh and already
-- migrated control databases, matching the 0013 precedent. None of the six is
-- referenced by an inbound foreign key, so drop order is free.
-- ===========================================================================

DROP TABLE IF EXISTS managed_worker_isolation_evidence;
DROP TABLE IF EXISTS online_eval_regressions;
DROP TABLE IF EXISTS usage_monthly_rollups;
DROP TABLE IF EXISTS usage_aggregate_rollups;
DROP TABLE IF EXISTS usage_metadata_rollups;
DROP TABLE IF EXISTS observed_agent_presence;
