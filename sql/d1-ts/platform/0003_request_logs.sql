-- ===========================================================================
-- Platform/unattributed request logs (Zero-D1 Plan B).
--
-- The `PlatformDataObject` singleton IS the authoritative home for
-- platform-scoped request evidence (`tenant IS NULL` — platform-operator or
-- unattributed calls), which has no TenantDataObject to live in and used to sit
-- in the control projection only. Removing the entire control D1 therefore
-- requires this object: it holds exactly the rows every tenant fan-out reader
-- cannot reach, because there is no roster tenant for an unattributed call.
--
-- Row shape mirrors the TENANT request_logs table
-- (`sql/d1-ts/tenant/0012_request_logs_agent_runs.sql` +
-- `0025_request_log_routing_decision.sql`), so the gateway's tenant-object
-- write `TENANT_REQUEST_LOG_UPSERT_SQL` (`ON CONFLICT (request_id)`) and its
-- `tenantRequestLogBindings` apply here VERBATIM — the platform leg binds the
-- same statement with the `tenant` slot forced NULL.
--
-- Two shape differences from the tenant table, both because this is a single
-- unattributed object rather than a per-tenant one:
--   * `tenant` is NULLable (there is no owner; every row is platform-scoped).
--     The column is kept, not dropped, so the row stays byte-identical to the
--     tenant/control tables and the one-time control-`WHERE tenant IS NULL`
--     backfill is a lossless column-for-column copy.
--   * No `projection_key` (that column only disambiguated tenants inside the
--     shared control projection); `request_id` PRIMARY KEY is unique on its own.
--
-- Agent-run tables (`agent_runs`, `agent_run_events`) are NOT mirrored here —
-- they are a separate slice; this object serves the request-log leg only.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS request_logs (
    request_id TEXT PRIMARY KEY,
    trace_id TEXT,
    agent_run_id TEXT,
    delegation_chain TEXT,
    delegation_root TEXT,
    experiment_id TEXT,
    experiment_arm TEXT,
    routing_decision TEXT,
    tenant TEXT,
    project TEXT,
    workspace TEXT,
    api_key_id TEXT,
    route TEXT,
    provider TEXT,
    logical_model TEXT,
    provider_model TEXT,
    status_code INTEGER,
    error_code TEXT,
    cache_status TEXT,
    latency_ms INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    guardrail_verdict TEXT NOT NULL DEFAULT 'not_screened',
    guardrail_policy_id TEXT,
    streamed INTEGER NOT NULL DEFAULT 0,
    started_at_unix INTEGER NOT NULL,
    completed_at_unix INTEGER,
    request_json TEXT NOT NULL DEFAULT '{}'
);

-- The one read this object serves is the operator fleet list/export: the whole
-- table ordered newest-first. No tenant column leads the index because every
-- row is platform-scoped — the whole table IS the platform domain.
CREATE INDEX IF NOT EXISTS idx_platform_request_logs_started
    ON request_logs(started_at_unix DESC, request_id ASC);

CREATE INDEX IF NOT EXISTS idx_platform_request_logs_agent_run
    ON request_logs(agent_run_id);

CREATE INDEX IF NOT EXISTS idx_platform_request_logs_trace
    ON request_logs(trace_id);

CREATE INDEX IF NOT EXISTS idx_platform_request_logs_model_provider_started
    ON request_logs(logical_model, provider, started_at_unix DESC);
