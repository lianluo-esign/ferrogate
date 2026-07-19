-- #253 — Remove the stale control-plane duplicate from the `public` schema.
--
-- STATUS: EXECUTED against the live project (wpgzljfyunypmuacyesv) on 2026-07-19.
--   Result: 57 public duplicates dropped; public now holds 0 control-plane tables.
--   Pre-drop finding: `wallet_settlements` was MISSING from the authoritative
--   `ferrogate_control` (present in code/001_init but never provisioned live) and
--   existed ONLY in `public` (as test scaffolding). It was first created in
--   `ferrogate_control` (idempotent DDL), then the empty `public.wallet_settlements`
--   scaffolding was dropped. Live `ferrogate_control` is now the single authoritative
--   schema: 58/58 base tables, ledger v37. This file is retained as the audit record
--   and a re-runnable guard (all statements are idempotent / IF EXISTS).
--
-- WHY: the authoritative control-plane schema is `ferrogate_control` (the app pins
-- search_path to it post-#250). A full 57-table duplicate sits in `public` from the
-- pre-#237/#250 unpinned-DDL era. It is FROZEN historical state (proof: at audit
-- time `control_plane_resources` was 8 rows in ferrogate_control vs 3 in public —
-- the app grows fc, not public), and no user/billing data is public-only (wallets /
-- billing_ledger / tenants / admin_users public copies are empty). Removing it makes
-- live match the single-`ferrogate_control` design.
--
-- ⚠️ DESTRUCTIVE — irreversible. DO NOT RUN until you have:
--   1. Taken a backup / snapshot you can restore, e.g.:
--        pg_dump "$DSN" --schema=public --format=custom --file=public_cp_backup_2026-07-19.dump
--      (or a Supabase dashboard point-in-time snapshot)
--   2. Confirmed no external consumer reads these `public.*` tables directly
--      (the app uses ferrogate_control; PostgREST/other public objects are NOT in
--      this list — see the explicit names below).
--
-- SAFETY DESIGN:
--   * Explicit hardcoded 57-table list (no dynamic SQL) — cannot touch
--     `ferrogate_control` or any object not named here.
--   * Wrapped in a transaction with a pre-flight guard that ABORTS unless the
--     authoritative `ferrogate_control` copy of each table still exists.
--   * `wallet_settlements` is PUBLIC-ONLY (no ferrogate_control counterpart) and is
--     intentionally EXCLUDED — decide on it separately (it was empty at audit time).
--
-- HOW TO RUN (after backup): psql "$DSN" -f this_file.sql
--   Review the NOTICE output; COMMIT only happens if the guard passes.

BEGIN;

-- Pre-flight guard: refuse to drop the public copies unless the authoritative
-- ferrogate_control schema holds all 57 tables (so we never delete the only copy).
DO $$
DECLARE
    fc_count integer;
BEGIN
    SELECT count(*) INTO fc_count
    FROM information_schema.tables
    WHERE table_schema = 'ferrogate_control'
      AND table_type = 'BASE TABLE'
      AND table_name IN (
        'admin_user_refresh_tokens','admin_user_tenant_memberships','admin_users',
        'agent_run_events','agent_runs','agent_schedule_fires','agent_schedules',
        'agent_worker_instances','api_keys','audit_events','billing_ledger',
        'billing_metering_events','billing_report_outbox','budget_alert_notifications',
        'control_plane_replay_floors','control_plane_resources','guardrail_check_evaluations',
        'guardrail_evaluations','guardrail_policy_bindings','guardrail_policy_revisions',
        'managed_worker_isolation_evidence','managed_worker_isolation_policies',
        'managed_worker_isolation_selections','managed_worker_lifecycle_events',
        'managed_worker_sessions','managed_worker_templates','mcp_oauth_authorization_states',
        'mcp_oauth_credentials','mcp_oauth_flows','metering_event_routes','metering_event_usage',
        'metering_events','payment_methods','permissions','plans','projects','quota_policies',
        'request_logs','roles','self_hosted_run_dispatch_capabilities','self_hosted_run_dispatches',
        'self_hosted_worker_artifacts','self_hosted_worker_checkpoints','self_hosted_worker_heartbeats',
        'self_hosted_worker_registrations','self_hosted_worker_telemetry_events','storage_schema_migrations',
        'stored_assets','tenant_contexts','tenant_role_bindings','tenants','usage_aggregate_rollups',
        'usage_aggregates','usage_metadata_rollups','usage_monthly_rollups','wallets','workspaces'
      );
    IF fc_count <> 57 THEN
        RAISE EXCEPTION 'ABORT: ferrogate_control holds % of 57 expected control-plane tables; refusing to drop the public copies', fc_count;
    END IF;
    RAISE NOTICE 'Guard passed: ferrogate_control holds all 57 authoritative tables. Dropping public duplicates...';
END $$;

-- Drop the 57 public duplicates. CASCADE clears FKs/indexes/views local to public.
DROP TABLE IF EXISTS public.admin_user_refresh_tokens CASCADE;
DROP TABLE IF EXISTS public.admin_user_tenant_memberships CASCADE;
DROP TABLE IF EXISTS public.admin_users CASCADE;
DROP TABLE IF EXISTS public.agent_run_events CASCADE;
DROP TABLE IF EXISTS public.agent_runs CASCADE;
DROP TABLE IF EXISTS public.agent_schedule_fires CASCADE;
DROP TABLE IF EXISTS public.agent_schedules CASCADE;
DROP TABLE IF EXISTS public.agent_worker_instances CASCADE;
DROP TABLE IF EXISTS public.api_keys CASCADE;
DROP TABLE IF EXISTS public.audit_events CASCADE;
DROP TABLE IF EXISTS public.billing_ledger CASCADE;
DROP TABLE IF EXISTS public.billing_metering_events CASCADE;
DROP TABLE IF EXISTS public.billing_report_outbox CASCADE;
DROP TABLE IF EXISTS public.budget_alert_notifications CASCADE;
DROP TABLE IF EXISTS public.control_plane_replay_floors CASCADE;
DROP TABLE IF EXISTS public.control_plane_resources CASCADE;
DROP TABLE IF EXISTS public.guardrail_check_evaluations CASCADE;
DROP TABLE IF EXISTS public.guardrail_evaluations CASCADE;
DROP TABLE IF EXISTS public.guardrail_policy_bindings CASCADE;
DROP TABLE IF EXISTS public.guardrail_policy_revisions CASCADE;
DROP TABLE IF EXISTS public.managed_worker_isolation_evidence CASCADE;
DROP TABLE IF EXISTS public.managed_worker_isolation_policies CASCADE;
DROP TABLE IF EXISTS public.managed_worker_isolation_selections CASCADE;
DROP TABLE IF EXISTS public.managed_worker_lifecycle_events CASCADE;
DROP TABLE IF EXISTS public.managed_worker_sessions CASCADE;
DROP TABLE IF EXISTS public.managed_worker_templates CASCADE;
DROP TABLE IF EXISTS public.mcp_oauth_authorization_states CASCADE;
DROP TABLE IF EXISTS public.mcp_oauth_credentials CASCADE;
DROP TABLE IF EXISTS public.mcp_oauth_flows CASCADE;
DROP TABLE IF EXISTS public.metering_event_routes CASCADE;
DROP TABLE IF EXISTS public.metering_event_usage CASCADE;
DROP TABLE IF EXISTS public.metering_events CASCADE;
DROP TABLE IF EXISTS public.payment_methods CASCADE;
DROP TABLE IF EXISTS public.permissions CASCADE;
DROP TABLE IF EXISTS public.plans CASCADE;
DROP TABLE IF EXISTS public.projects CASCADE;
DROP TABLE IF EXISTS public.quota_policies CASCADE;
DROP TABLE IF EXISTS public.request_logs CASCADE;
DROP TABLE IF EXISTS public.roles CASCADE;
DROP TABLE IF EXISTS public.self_hosted_run_dispatch_capabilities CASCADE;
DROP TABLE IF EXISTS public.self_hosted_run_dispatches CASCADE;
DROP TABLE IF EXISTS public.self_hosted_worker_artifacts CASCADE;
DROP TABLE IF EXISTS public.self_hosted_worker_checkpoints CASCADE;
DROP TABLE IF EXISTS public.self_hosted_worker_heartbeats CASCADE;
DROP TABLE IF EXISTS public.self_hosted_worker_registrations CASCADE;
DROP TABLE IF EXISTS public.self_hosted_worker_telemetry_events CASCADE;
DROP TABLE IF EXISTS public.storage_schema_migrations CASCADE;
DROP TABLE IF EXISTS public.stored_assets CASCADE;
DROP TABLE IF EXISTS public.tenant_contexts CASCADE;
DROP TABLE IF EXISTS public.tenant_role_bindings CASCADE;
DROP TABLE IF EXISTS public.tenants CASCADE;
DROP TABLE IF EXISTS public.usage_aggregate_rollups CASCADE;
DROP TABLE IF EXISTS public.usage_aggregates CASCADE;
DROP TABLE IF EXISTS public.usage_metadata_rollups CASCADE;
DROP TABLE IF EXISTS public.usage_monthly_rollups CASCADE;
DROP TABLE IF EXISTS public.wallets CASCADE;
DROP TABLE IF EXISTS public.workspaces CASCADE;

-- Post-check: no control-plane table should remain in public.
DO $$
DECLARE
    remaining integer;
BEGIN
    SELECT count(*) INTO remaining
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_type = 'BASE TABLE'
      AND table_name IN (
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'ferrogate_control' AND table_type = 'BASE TABLE'
      );
    RAISE NOTICE 'Post-check: % control-plane duplicate table(s) remain in public (expected 0).', remaining;
END $$;

-- `public.wallet_settlements`: this was the one PUBLIC-ONLY table (no ferrogate_control
-- counterpart) — but it is a REAL base-schema table (sql/001_init) that had simply
-- never been provisioned into live ferrogate_control. So the fix was NOT to drop it
-- blindly: first create the authoritative copy, then drop the empty public scaffolding.
SET search_path TO ferrogate_control, public;
CREATE TABLE IF NOT EXISTS wallet_settlements (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    delta_credits BIGINT NOT NULL,
    balance_after_credits BIGINT,
    created_at_unix BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT)
);
CREATE INDEX IF NOT EXISTS idx_wallet_settlements_tenant_time
    ON wallet_settlements(tenant_id, created_at_unix DESC);
-- Only after the authoritative copy exists, remove the empty public scaffolding:
DROP TABLE IF EXISTS public.wallet_settlements CASCADE;

-- Review the NOTICE output above. If the guard passed and the post-check reads 0,
-- finish with:  COMMIT;   Otherwise:  ROLLBACK;
COMMIT;
