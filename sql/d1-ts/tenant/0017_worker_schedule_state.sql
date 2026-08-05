-- ===========================================================================
-- Tenant-owned managed and self-hosted worker state (#856, #831)
--
-- These rows belong to the tenant addressed by this database. The object
-- boundary is the isolation boundary, so the worker documents keep the
-- existing control-D1 shape and do not need a tenant predicate on every read.
--
-- Agent schedules and their fire ledger are already tenant tables from
-- 0001_init_tenant.sql. Their unique (schedule_id, scheduled_fire_at_unix)
-- constraint remains the at-most-once claim used by the object alarm.
--
-- Deliberately not moved here:
--   * self_hosted_worker_registrations is the control-plane bootstrap
--     directory, because worker_id is the lookup key before a tenant is known
--   * self_hosted_worker_telemetry_events and managed_worker_isolation_evidence
--     are high-volume or derived projection state owned by later slices
-- ===========================================================================

CREATE TABLE IF NOT EXISTS managed_worker_templates (
    id TEXT PRIMARY KEY,
    template_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS agent_worker_instances (
    id TEXT PRIMARY KEY,
    started_at_unix INTEGER,
    instance_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agent_worker_instances_started
    ON agent_worker_instances(started_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_sessions (
    id TEXT PRIMARY KEY,
    requested_at_unix INTEGER,
    session_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_sessions_requested
    ON managed_worker_sessions(requested_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_lifecycle_events (
    id TEXT PRIMARY KEY,
    occurred_at_unix INTEGER,
    event_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_lifecycle_events_occurred
    ON managed_worker_lifecycle_events(occurred_at_unix, id);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_selections (
    session_id TEXT PRIMARY KEY,
    selected_at_unix INTEGER,
    selection_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_managed_worker_isolation_selections_selected
    ON managed_worker_isolation_selections(selected_at_unix, session_id);

CREATE TABLE IF NOT EXISTS managed_worker_isolation_policies (
    session_id TEXT PRIMARY KEY,
    policy_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS self_hosted_worker_heartbeats (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    reported_at_unix INTEGER,
    heartbeat_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_heartbeats_worker
    ON self_hosted_worker_heartbeats(worker_id, reported_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_worker_artifacts (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    created_at_unix INTEGER,
    artifact_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_artifacts_worker
    ON self_hosted_worker_artifacts(worker_id, created_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_worker_checkpoints (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    created_at_unix INTEGER,
    checkpoint_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_worker_checkpoints_worker
    ON self_hosted_worker_checkpoints(worker_id, created_at_unix);

CREATE TABLE IF NOT EXISTS self_hosted_run_dispatches (
    dispatch_id TEXT PRIMARY KEY,
    queued_at_unix INTEGER,
    dispatch_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_self_hosted_run_dispatches_queued
    ON self_hosted_run_dispatches(queued_at_unix, dispatch_id);
