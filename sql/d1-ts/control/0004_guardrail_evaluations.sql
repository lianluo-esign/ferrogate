-- ---------------------------------------------------------------------------
-- `guardrail_evaluations` + `guardrail_check_evaluations` — durable screening
-- evidence  (#665)
--
-- Until this migration, guardrail evidence existed only inside a Worker isolate
-- (`apps/gateway/src/guardrails/evidence.ts::InMemoryGuardrailEvidenceSink`).
-- The isolate ended and the record of what the control decided ended with it,
-- while `GET /admin/v1/guardrail-evaluations` and `GET /admin/v1/investigations`
-- answered — authenticated, RBAC-gated, contract-conformant — that no guardrail
-- had ever evaluated anything. A guardrail you cannot audit is a guardrail you
-- cannot defend in a review, and the absence of a record is how an auditor
-- concludes a control did not run.
--
-- ## Current storage boundary
--
-- This migration is the original CONTROL-side shape retained for upgrade
-- compatibility. Tenant-attributed evidence is authoritative in
-- `sql/d1-ts/tenant/0013_guardrail_evaluations.sql`; the gateway writes that
-- object first and projects a copy here for bounded fleet/operator reads.
-- `sql/d1-ts/control/0015_guardrail_evidence_projection_keys.sql` rebuilds
-- these tables with tenant-qualified `projection_key` values because the
-- logical evaluation id is only unique inside one TenantDataObject. Unscoped
-- platform evidence remains CONTROL-owned because it has no tenant object.
--
-- The split preserves one queue and one fleet reader without making CONTROL a
-- fallback authority for a tenant. Tenant-scoped list/investigation reads use
-- the exact object; operator reads use the projection until #825 defines the
-- general bounded/as-of fan-out freshness contract.
--
-- ## Parity
--
-- `sql/001_init_postgres.sql:454` is the reference shape and every column it
-- has is reproduced under the same name, with three deliberate differences:
--
--  1. **`tenant`, not `tenant_id`.** The evidence FAMILY in this schema
--     (`request_logs`, `audit_events`, `agent_runs`) spells the composite
--     storage key `tenant`, and the readers' fence helpers are written against
--     that name. One evidence table spelling it differently is how a fence gets
--     written against the wrong column.
--  2. **`scope_id` is NULLABLE.** Postgres declared it `NOT NULL`, but the
--     gateway's `evidenceScope` legitimately produces `{scopeType:"platform"}`
--     with no id for an un-attributed call, and storing `""` there would make
--     `WHERE scope_id IS NOT NULL` lie.
--  3. **`trace_id` / `agent_run_id` / `input_fingerprint` / `action_fingerprint`
--     are indexed for the investigation selectors** the operator doc promises
--     (`docs/guardrails/investigation-view.md`: "accepts `trace_id` or
--     `agent_run_id`").
--
-- RLS has no D1 equivalent; the tenant fence is a SQL predicate applied by the
-- reader (`admin_request_log.ts::guardrailTenantFence`) and is held by
-- `apps/control-plane/test/guardrail-evidence-read.test.ts` from both tenants'
-- sides.
--
-- ## What is NOT stored, and this is the load-bearing part
--
-- No prompt text. No completion text. No `matched_text`. The cross-cutting
-- security invariant this schema is built around
-- (`docs/legacy/inventory-policy-core.md`, appendix §1/§2) is that only a
-- keyed, non-reversible fingerprint reaches durable evidence. A guardrail that
-- blocks a prompt for carrying a secret and then stores that secret verbatim in
-- a table an operator can list has MOVED the leak, not stopped it.
--
-- `check_json.findings[].redacted_excerpt` is therefore a reconstruction, not a
-- copy: category, span and a run of `*` as wide as the matched bytes, built in
-- `apps/gateway/src/guardrails/evidence.ts::redactedExcerpt` from the finding's
-- STRUCTURE and never from its content. `apps/gateway/test/guardrails/
-- evidence-write.test.ts` blocks a request on a known secret and asserts the
-- stored bytes do not contain it.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS guardrail_evaluations (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    trace_id TEXT,
    agent_run_id TEXT,
    subject_id TEXT,
    tenant TEXT,
    scope_type TEXT NOT NULL,
    scope_id TEXT,
    target TEXT NOT NULL,
    protocol TEXT NOT NULL,
    stage TEXT NOT NULL,
    mode TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    action TEXT NOT NULL,
    enforcement_status TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    input_fingerprint TEXT NOT NULL,
    action_fingerprint TEXT,
    occurred_at_unix INTEGER NOT NULL,
    -- The whole sanitized evidence document. Kept alongside the columns for the
    -- reason `request_logs` keeps `request_json`: it is the extension point a
    -- later slice adds a fact through without a migration, and it carries the
    -- per-category finding counts, which are a map and therefore not a column.
    -- Where both carry a fact the COLUMN is authoritative on read.
    evaluation_json TEXT NOT NULL DEFAULT '{}'
);

-- The tenant fence + recency order the admin list issues verbatim. Without it
-- every page is a full scan of an append-heavy table.
CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_tenant_time
    ON guardrail_evaluations(tenant, occurred_at_unix DESC);

-- The investigation selectors (`?request_id=` / `?trace_id=` / `?agent_run_id=`).
CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_request
    ON guardrail_evaluations(request_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_trace
    ON guardrail_evaluations(trace_id, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_agent_run
    ON guardrail_evaluations(agent_run_id, occurred_at_unix DESC);

-- "Which policy revision is blocking traffic" — the read an operator makes
-- immediately after activating a revision (`sql/001_init_postgres.sql:489`).
CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_policy_time
    ON guardrail_evaluations(policy_id, policy_revision, occurred_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_guardrail_evaluations_verdict_action
    ON guardrail_evaluations(verdict, action, occurred_at_unix DESC);

-- One row per CHECK, i.e. per detector that ran (or was skipped, or errored).
-- `ON DELETE CASCADE` matches the Postgres reference and is what makes the
-- retention sweep correct with a single `DELETE FROM guardrail_evaluations`:
-- an orphaned check row is evidence pointing at a decision that no longer
-- exists, which is worse than no row.
CREATE TABLE IF NOT EXISTS guardrail_check_evaluations (
    id TEXT PRIMARY KEY,
    evaluation_id TEXT NOT NULL REFERENCES guardrail_evaluations(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    verdict TEXT NOT NULL,
    action TEXT NOT NULL,
    enforcement_status TEXT NOT NULL,
    error_kind TEXT,
    -- Per-check counts, `used_fallback`, `transformed`, and the sanitized
    -- per-finding array (category / severity / confidence / span / REDACTED
    -- excerpt). See the module header for why the excerpt carries no content.
    check_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (evaluation_id, check_id)
);

CREATE INDEX IF NOT EXISTS idx_guardrail_checks_evaluation
    ON guardrail_check_evaluations(evaluation_id, check_id);

-- "Which detector is producing these verdicts" and "which detector is failing"
-- — the two fleet-health reads (`sql/001_init_postgres.sql:511`/`:515`).
CREATE INDEX IF NOT EXISTS idx_guardrail_checks_detector_verdict
    ON guardrail_check_evaluations(detector_id, verdict);

CREATE INDEX IF NOT EXISTS idx_guardrail_checks_error
    ON guardrail_check_evaluations(error_kind);
