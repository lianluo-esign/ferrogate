/**
 * GENERATED FILE — DO NOT EDIT BY HAND.
 *
 * Source: `sql/d1-ts/platform/*.sql` — the schema the platform Durable Object
 * (`PlatformDataObject`, exactly one instance) applies to its own embedded
 * SQLite database on first wake.
 *
 * Regenerate with:
 *
 *     node scripts/generate-platform-schema-sql.mjs
 *
 * `packages/storage/test/platform-schema-sql.test.ts` re-reads the directory
 * from disk and compares byte-for-byte, so an edit here that does not
 * correspond to an edit there is red — and so is a migration added to
 * `sql/d1-ts/platform/` without regenerating.
 *
 * `ordinal` is the 1-based position in filename order; the applier gates by
 * NAME (see the generator's docblock).
 */

/** One platform migration file, exactly as it sits in `sql/d1-ts/platform/`. */
export interface PlatformMigration {
  /** 1-based position in filename apply order. */
  readonly ordinal: number;
  /** The filename without `.sql`; the applier's ledger key. */
  readonly name: string;
  /** The file's verbatim contents, comments and all. */
  readonly sql: string;
}

/** Every platform migration, ascending by filename. Order IS the contract. */
export const PLATFORM_MIGRATIONS: readonly PlatformMigration[] = [
  {
    ordinal: 1,
    name: "0001_guardrail_evaluations",
    sql: "-- ===========================================================================\n-- Platform/unattributed guardrail screening evidence (Zero-D1 Plan B).\n--\n-- The `PlatformDataObject` singleton IS the authoritative home for\n-- platform-scoped guardrail evidence (`scope_type = 'platform'`, no owning\n-- tenant), which has no TenantDataObject to live in and used to sit in the\n-- control projection only. Removing the entire control D1 therefore requires\n-- this object: it holds exactly the rows every fan-out reader cannot reach,\n-- because there is no roster tenant for an unattributed call.\n--\n-- Every row in this object is platform-scoped, so `tenant` is NULLable (there\n-- is no owner) and reads need no tenant fence — the whole table IS the platform\n-- domain. The column is kept (rather than dropped) so the row shape stays\n-- byte-identical to the control/tenant guardrail tables and the one-time\n-- control-`WHERE tenant IS NULL`→object backfill is a lossless `SELECT *`.\n-- Single object → `id` PRIMARY KEY is unique on its own; there is no\n-- `projection_key` (that column only disambiguated tenants inside the shared\n-- control projection).\n-- ===========================================================================\n\nCREATE TABLE IF NOT EXISTS guardrail_evaluations (\n    id TEXT PRIMARY KEY,\n    request_id TEXT NOT NULL,\n    trace_id TEXT,\n    agent_run_id TEXT,\n    subject_id TEXT,\n    tenant TEXT,\n    scope_type TEXT NOT NULL,\n    scope_id TEXT,\n    target TEXT NOT NULL,\n    protocol TEXT NOT NULL,\n    stage TEXT NOT NULL,\n    mode TEXT NOT NULL,\n    policy_id TEXT NOT NULL,\n    policy_revision INTEGER NOT NULL,\n    verdict TEXT NOT NULL,\n    action TEXT NOT NULL,\n    enforcement_status TEXT NOT NULL,\n    latency_ms INTEGER NOT NULL DEFAULT 0,\n    finding_count INTEGER NOT NULL DEFAULT 0,\n    input_fingerprint TEXT NOT NULL,\n    action_fingerprint TEXT,\n    occurred_at_unix INTEGER NOT NULL,\n    evaluation_json TEXT NOT NULL DEFAULT '{}'\n);\n\n-- The one read this object serves is the operator fleet list: the whole table\n-- ordered newest-first. No tenant column leads the index because every row is\n-- platform-scoped.\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_time\n    ON guardrail_evaluations(occurred_at_unix DESC, id ASC);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_request\n    ON guardrail_evaluations(request_id, occurred_at_unix DESC);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_trace\n    ON guardrail_evaluations(trace_id, occurred_at_unix DESC);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_agent_run\n    ON guardrail_evaluations(agent_run_id, occurred_at_unix DESC);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_policy_time\n    ON guardrail_evaluations(policy_id, policy_revision, occurred_at_unix DESC);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_evaluations_verdict_action\n    ON guardrail_evaluations(verdict, action, occurred_at_unix DESC);\n\nCREATE TABLE IF NOT EXISTS guardrail_check_evaluations (\n    id TEXT PRIMARY KEY,\n    evaluation_id TEXT NOT NULL REFERENCES guardrail_evaluations(id) ON DELETE CASCADE,\n    tenant TEXT,\n    check_id TEXT NOT NULL,\n    detector_id TEXT NOT NULL,\n    detector_version TEXT NOT NULL,\n    config_digest TEXT NOT NULL,\n    verdict TEXT NOT NULL,\n    action TEXT NOT NULL,\n    enforcement_status TEXT NOT NULL,\n    error_kind TEXT,\n    check_json TEXT NOT NULL DEFAULT '{}',\n    UNIQUE (evaluation_id, check_id)\n);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_evaluation\n    ON guardrail_check_evaluations(evaluation_id, check_id);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_detector_verdict\n    ON guardrail_check_evaluations(detector_id, verdict);\n\nCREATE INDEX IF NOT EXISTS idx_platform_guardrail_checks_error\n    ON guardrail_check_evaluations(error_kind);\n",
  },
  {
    ordinal: 2,
    name: "0002_backfill_marks",
    sql: "-- ===========================================================================\n-- One-time-migration bookkeeping for the platform object (Zero-D1 Plan B).\n--\n-- The control-`WHERE tenant IS NULL`→platform-object guardrail backfill needs a\n-- durable, object-local marker so it is resumable and, once complete, cannot be\n-- reopened by an older in-flight call copying later projection lag into the\n-- authority. The tenant bridge stores that marker in `tenant_provisioning_marks`\n-- keyed by `tenant_id`; the platform singleton has no tenant id, so it keeps the\n-- same JSON `detail` shape keyed by `mark` alone.\n--\n-- Deliberately NOT the schema ledger (`platform_schema_applied`): that table is\n-- the migration applier's own gate and is keyed/queried by migration name — a\n-- data-backfill marker sharing it would be a category error. This is a separate,\n-- tiny table whose only writer/reader is\n-- `apps/control-plane/src/store/platform_guardrail_evidence_backfill.ts`.\n-- ===========================================================================\n\nCREATE TABLE IF NOT EXISTS platform_backfill_marks (\n    mark TEXT PRIMARY KEY,\n    detail TEXT,\n    applied_at_unix INTEGER NOT NULL DEFAULT 0\n);\n",
  },
];
