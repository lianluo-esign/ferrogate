-- ---------------------------------------------------------------------------
-- `request_logs` — the queryable columns the evidence surface needs  (#664)
--
-- `0001_init_control.sql` created `request_logs` with only the CORRELATION
-- keys (`request_id`, `agent_run_id`, `tenant`, the two timestamps) plus a
-- `request_json` document, which was enough for a table nothing wrote. It is
-- not enough for a table an auditor reads: `GET /admin/v1/request-logs` has to
-- fence on the tenant, order by recency and page, and the EU AI Act Art. 12/72
-- record-keeping obligation is per DECISION — tenant, project, credential,
-- model (logical AND physical), route, latency, status, tokens and the
-- guardrail verdict, for every inference request.
--
-- ## Why columns AND `request_json`, rather than one or the other
--
-- The document is kept and is still written in full: it is the extension point
-- (a later slice can add a field without a migration, exactly as
-- `audit_events.audit_json` does) and it is what the JSONL export streams. The
-- columns exist for the three things a JSON blob cannot do in SQLite without a
-- scan: the tenant FENCE, the recency ORDER BY, and the joins the dependent
-- slices need (cost attribution by model/provider, SIEM export by status).
-- Where both carry a fact, the COLUMN is authoritative on read — see
-- `apps/control-plane/src/routes/admin_request_log.ts::requestLogDocument`,
-- which applies the columns last for the same reason `auditEventDocument`
-- does: the document is assembled from operator-influenced request data and
-- must not be able to rename its own tenant.
--
-- ## Parity
--
-- `sql/001_init_postgres.sql:379` is the reference shape and every column it
-- has that this gateway can populate is reproduced under the same name
-- (`trace_id`, `route`, `provider`, `logical_model`, `provider_model`,
-- `status_code`, `error_code`, `cache_status`) with the same three indexes.
--
-- FIVE columns here have no Postgres counterpart — `project`, `workspace`,
-- `api_key_id`, `latency_ms`, `prompt_tokens` / `completion_tokens` /
-- `total_tokens`, `guardrail_verdict` / `guardrail_policy_id`, `streamed` —
-- and that is deliberate rather than drift: they are the facts issue #664's
-- acceptance criteria names that the Rust row carried only inside its
-- `request_json`. Reading a token count out of a JSON blob is what made cost
-- attribution a scan.
--
-- The Postgres columns NOT reproduced (`workflow_*`, `cluster_id`, `node_id`,
-- `gateway_config_*`) are omitted because nothing in `apps/gateway/src` can
-- populate them today: a column that is always NULL is a promise to an
-- operator that the platform does not keep. They belong to the slice that
-- lands the fact, together with its writer.
-- ---------------------------------------------------------------------------

ALTER TABLE request_logs ADD COLUMN trace_id TEXT;
ALTER TABLE request_logs ADD COLUMN project TEXT;
ALTER TABLE request_logs ADD COLUMN workspace TEXT;
ALTER TABLE request_logs ADD COLUMN api_key_id TEXT;
ALTER TABLE request_logs ADD COLUMN route TEXT;
ALTER TABLE request_logs ADD COLUMN provider TEXT;
ALTER TABLE request_logs ADD COLUMN logical_model TEXT;
ALTER TABLE request_logs ADD COLUMN provider_model TEXT;
ALTER TABLE request_logs ADD COLUMN status_code INTEGER;
ALTER TABLE request_logs ADD COLUMN error_code TEXT;
ALTER TABLE request_logs ADD COLUMN cache_status TEXT;
ALTER TABLE request_logs ADD COLUMN latency_ms INTEGER;
ALTER TABLE request_logs ADD COLUMN prompt_tokens INTEGER;
ALTER TABLE request_logs ADD COLUMN completion_tokens INTEGER;
ALTER TABLE request_logs ADD COLUMN total_tokens INTEGER;
ALTER TABLE request_logs ADD COLUMN guardrail_verdict TEXT;
ALTER TABLE request_logs ADD COLUMN guardrail_policy_id TEXT;
ALTER TABLE request_logs ADD COLUMN streamed INTEGER NOT NULL DEFAULT 0;

-- The tenant fence + recency order the admin list issues verbatim. Without it
-- every page is a full scan of an append-heavy table.
CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_started
    ON request_logs(tenant, started_at_unix DESC);

-- Cost attribution and per-model latency reads (`sql/001_init_postgres.sql:406`).
CREATE INDEX IF NOT EXISTS idx_request_logs_model_provider_started
    ON request_logs(logical_model, provider, started_at_unix DESC);

-- Joining a customer's incident report (a W3C trace id) to the decision row.
CREATE INDEX IF NOT EXISTS idx_request_logs_trace
    ON request_logs(trace_id);
