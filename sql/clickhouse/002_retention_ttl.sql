-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-07-19
-- description: Native ClickHouse TTL clauses (issue #284) mirroring the
-- Postgres-side compliance retention engine (retention_policies +
-- state_asset_lifecycle sweeper). These are DATA-MINIMIZATION defaults: the
-- analytics warehouse ages out operational rows automatically, so the mirror
-- of the control-plane per-tenant policy is enforced storage-side too. Tune
-- the intervals per your compliance obligations; audit data keeps a LONGER
-- floor than request logs, exactly like the Postgres side.
--
-- Applied with ON CLUSTER omitted (single-shard default); add
-- `ON CLUSTER '{cluster}'` for a replicated deployment. `ALTER ... MODIFY TTL`
-- is idempotent, so re-running this migration is safe.

-- Request logs: shortest floor (highest-volume, lowest legal-retention need).
ALTER TABLE ferrogate.ferrogate_request_logs
    MODIFY TTL event_date + INTERVAL 90 DAY;

-- Trace spans: short-lived debugging telemetry.
ALTER TABLE ferrogate.ferrogate_trace_spans
    MODIFY TTL event_date + INTERVAL 30 DAY;

-- Usage metrics: kept longer for billing reconciliation / trend reporting.
ALTER TABLE ferrogate.ferrogate_usage_metrics
    MODIFY TTL event_date + INTERVAL 400 DAY;

-- Billing metering events: kept for the billing-dispute / reconciliation window.
ALTER TABLE ferrogate.ferrogate_billing_metering_events
    MODIFY TTL event_date + INTERVAL 400 DAY;

-- Audit timeline: LONGEST floor (compliance evidence of admin/data actions).
ALTER TABLE ferrogate.ferrogate_audit_timeline
    MODIFY TTL event_date + INTERVAL 365 DAY;
