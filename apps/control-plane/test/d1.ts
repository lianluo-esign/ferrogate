/**
 * D1 test plumbing: a REAL `env.DB` with the REAL control-database migration
 * applied.
 *
 * `TEST_D1_SCHEMA` is bound by `vitest.config.ts`, which reads
 * `sql/d1-ts/control/` — the same directory `wrangler.toml`'s `migrations_dir`
 * points at. Nothing here restates a `CREATE TABLE`; if the migration renames a
 * column, these tests go red, which is the whole point of not keeping a fixture
 * copy of the schema.
 *
 * `applySchema()` belongs in `beforeAll` (the migration is idempotent and
 * bookkept in `d1_migrations`); `resetD1()` belongs in `beforeEach` and is what
 * actually gives each test a clean database — see its docblock for why the pool
 * does not do that for you.
 */
import { applyD1Migrations, env } from "cloudflare:test";
import type { StoreRecord } from "../src/ports.js";
import { SIEM_CURSOR_TABLE } from "../src/siem/cursor.js";
import {
  AUDIT_TABLE,
  BILLING_EVENT_TABLE,
  GUARDRAIL_CHECK_TABLE,
  GUARDRAIL_EVALUATION_TABLE,
  REQUEST_LOG_TABLE,
  RESOURCE_TABLE,
} from "../src/store/d1.js";

interface D1TestBindings {
  readonly DB: D1Database;
  readonly TEST_D1_SCHEMA: Parameters<typeof applyD1Migrations>[1];
}

/** The database the Worker under test writes through. */
export function db(): D1Database {
  return (env as unknown as D1TestBindings).DB;
}

/** Apply `sql/d1-ts/control/`. Call once per file, in `beforeAll`. */
export async function applySchema(): Promise<void> {
  const bindings = env as unknown as D1TestBindings;
  await applyD1Migrations(bindings.DB, bindings.TEST_D1_SCHEMA);
}

/**
 * Empty the tables this app reads or writes. Call in `beforeEach`.
 *
 * The pool does NOT roll a test's D1 writes back (the old `isolatedStorage`
 * switch is gone from `@cloudflare/vitest-pool-workers` 0.18's `cloudflareTest`
 * plugin), and the database is persisted under `.wrangler/state`, so without
 * this a passing assertion could be a previous test's — or a previous RUN's —
 * leftover row. Truncating is also honest about what it does not do: it leaves
 * the schema alone, so the migration still only runs once.
 *
 * `request_logs` is truncated here even though this app never writes it (#664:
 * the writer is `apps/gateway`), because the READER is served from this
 * database and a leftover row would make an "empty first" precondition lie.
 */
export async function resetD1(): Promise<void> {
  await db().batch([
    db().prepare(`DELETE FROM ${RESOURCE_TABLE}`),
    db().prepare(`DELETE FROM ${AUDIT_TABLE}`),
    db().prepare(`DELETE FROM ${REQUEST_LOG_TABLE}`),
    // Same argument as `request_logs`: written by `apps/gateway`, READ here
    // (#677 joins it for the per-request cost), so a leftover row would make an
    // "empty first" precondition lie and would attach a stale cost to a
    // freshly seeded request id.
    db().prepare(`DELETE FROM ${BILLING_EVENT_TABLE}`),
    // Children first: `guardrail_check_evaluations` has a foreign key onto the
    // evaluation, so deleting the parents first would fail on a database with
    // enforcement on. D1 runs a batch in order, so the order here is the
    // guarantee.
    db().prepare(`DELETE FROM ${GUARDRAIL_CHECK_TABLE}`),
    db().prepare(`DELETE FROM ${GUARDRAIL_EVALUATION_TABLE}`),
    // #683: the SIEM export cursors. A leftover cursor is the one kind of stale
    // row that makes a LATER test see nothing and call it correct — the pump
    // would report `idle` over rows it had never sent, in this run.
    db().prepare(`DELETE FROM ${SIEM_CURSOR_TABLE}`),
    // #697: the spend-anomaly ledger and its single-flight claim. The CLAIM is
    // the dangerous leftover — `spend_anomaly_runs` makes a second evaluation
    // of the same window a no-op, so without this every test after the first
    // would observe a detector that "correctly found nothing" while never
    // having run at all. The episode rows are the same trap one layer out: a
    // previous test's alert would satisfy a later test's assertion.
    db().prepare("DELETE FROM spend_anomaly_runs"),
    db().prepare("DELETE FROM spend_anomaly_episodes"),
    db().prepare("DELETE FROM spend_throttles"),
    // Tuning rides `quota_policies`, so a policy row left behind would silently
    // re-tune the next test's detector.
    db().prepare("DELETE FROM quota_policies"),
    // THE ROSTER. It decides which BACKEND a tenant routes to
    // (`BackendDispatchingTenantDatabaseRouter`), so a row left behind by a test
    // that created a tenant-account silently re-points every later test's tenant
    // writes into that tenant's Durable Object — where the document-only
    // assertions cannot see them, and where the previous test's balance is still
    // sitting. Before the dispatcher existed this leak was invisible, because
    // the binding router refused a `durable_object` row and every caller fell
    // back to the document. `tenants` goes with it: it is the row provisioning
    // admits on, so keeping one without its roster row is a state no request
    // produces.
    db().prepare("DELETE FROM tenant_databases"),
    db().prepare("DELETE FROM tenants"),
  ]);
}

/**
 * One `guardrail_evaluations` row plus its child checks, in the shape the
 * gateway's writer produces (#665).
 *
 * The same cross-Worker-seam fixture argument {@link RequestLogSeed} makes
 * applies here: `apps/gateway` owns the writer and cannot be driven from this
 * suite, so what these fixtures hold is that the READER returns what the tables
 * hold and fences it by tenant. The end-to-end "a real blocked request produces
 * this row, and its excerpt carries no secret" proof lives in
 * `apps/gateway/test/guardrails/evidence-write.test.ts`.
 */
export interface GuardrailCheckSeed {
  readonly id: string;
  readonly checkId: string;
  readonly detectorId: string;
  readonly detectorVersion: string;
  readonly configDigest: string;
  readonly verdict: string;
  readonly action: string;
  readonly enforcementStatus: string;
  readonly errorKind?: string | null;
  readonly document?: Record<string, unknown>;
}

export interface GuardrailEvaluationSeed {
  readonly id: string;
  readonly requestId: string;
  readonly traceId?: string | null;
  readonly agentRunId?: string | null;
  readonly subjectId?: string | null;
  readonly tenant?: string | null;
  readonly scopeType?: string;
  readonly scopeId?: string | null;
  readonly target?: string;
  readonly protocol?: string;
  readonly stage?: string;
  readonly mode?: string;
  readonly policyId?: string;
  readonly policyRevision?: number;
  readonly verdict?: string;
  readonly action?: string;
  readonly enforcementStatus?: string;
  readonly latencyMs?: number;
  readonly findingCount?: number;
  readonly inputFingerprint?: string;
  readonly actionFingerprint?: string | null;
  readonly occurredAtUnix: number;
  readonly document?: Record<string, unknown>;
  readonly checks?: readonly GuardrailCheckSeed[];
}

function evidenceProjectionKey(tenantId: string | null | undefined, logicalId: string): string {
  const tenant = tenantId ?? "";
  return `${Array.from(tenant).length}:${tenant}:${logicalId}`;
}

/** Seed the two evidence tables with raw SQL — see {@link GuardrailEvaluationSeed}. */
export async function seedGuardrailEvaluations(
  rows: readonly GuardrailEvaluationSeed[],
): Promise<void> {
  if (rows.length === 0) return;
  const statements = [];
  for (const row of rows) {
    statements.push(
      db()
        .prepare(
          `INSERT INTO ${GUARDRAIL_EVALUATION_TABLE}
             (projection_key, id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type, scope_id,
              target, protocol, stage, mode, policy_id, policy_revision, verdict, action,
              enforcement_status, latency_ms, finding_count, input_fingerprint,
              action_fingerprint, occurred_at_unix, evaluation_json)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)`,
        )
        .bind(
          evidenceProjectionKey(row.tenant, row.id),
          row.id,
          row.requestId,
          row.traceId ?? null,
          row.agentRunId ?? null,
          row.subjectId ?? null,
          row.tenant ?? null,
          row.scopeType ?? "organization",
          row.scopeId ?? null,
          row.target ?? "unspecified",
          row.protocol ?? "chat_completions",
          row.stage ?? "request",
          row.mode ?? "enforce",
          row.policyId ?? "policy",
          row.policyRevision ?? 1,
          row.verdict ?? "fail",
          row.action ?? "block",
          row.enforcementStatus ?? "enforced",
          row.latencyMs ?? 0,
          row.findingCount ?? 0,
          row.inputFingerprint ?? "hmac-sha256:unavailable",
          row.actionFingerprint ?? null,
          row.occurredAtUnix,
          JSON.stringify(row.document ?? {}),
        ),
    );
    for (const check of row.checks ?? []) {
      statements.push(
        db()
          .prepare(
            `INSERT INTO ${GUARDRAIL_CHECK_TABLE}
               (projection_key, id, evaluation_projection_key, evaluation_id, tenant, check_id,
                detector_id, detector_version, config_digest,
                verdict, action, enforcement_status, error_kind, check_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)`,
          )
          .bind(
            evidenceProjectionKey(row.tenant, check.id),
            check.id,
            evidenceProjectionKey(row.tenant, row.id),
            row.id,
            row.tenant ?? null,
            check.checkId,
            check.detectorId,
            check.detectorVersion,
            check.configDigest,
            check.verdict,
            check.action,
            check.enforcementStatus,
            check.errorKind ?? null,
            JSON.stringify(check.document ?? {}),
          ),
      );
    }
  }
  await db().batch(statements);
}

/** One `audit_events` row, for the investigation join. */
export interface AuditEventSeed {
  readonly id: string;
  readonly requestId: string;
  readonly agentRunId?: string | null;
  readonly tenant?: string | null;
  readonly occurredAtUnix: number;
  readonly audit?: Record<string, unknown>;
}

export async function seedAuditEvents(rows: readonly AuditEventSeed[]): Promise<void> {
  if (rows.length === 0) return;
  await db().batch(
    rows.map((row) =>
      db()
        .prepare(
          `INSERT INTO ${AUDIT_TABLE}
             (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          row.id,
          row.requestId,
          row.agentRunId ?? null,
          row.tenant ?? null,
          row.occurredAtUnix,
          JSON.stringify(row.audit ?? {}),
        ),
    ),
  );
}

/**
 * One `request_logs` row, in the shape the gateway's writer produces (#664).
 *
 * This is the CROSS-WORKER seam and the only place in this app's suite where a
 * fixture is the honest tool: `apps/gateway` owns the writer, is a different
 * Worker with a different `wrangler.toml`, and cannot be driven from here. The
 * end-to-end "a real inference request produces this row" proof therefore lives
 * in `apps/gateway/test/requestlog/write.test.ts`, against the SAME columns; what
 * these fixtures hold is that the reader returns what the table holds and fences
 * it by tenant.
 */
export interface RequestLogSeed {
  readonly requestId: string;
  readonly traceId?: string | null;
  /** `#305/#522` — the agent run, which is one of #677's chargeback dimensions. */
  readonly agentRunId?: string | null;
  readonly tenant?: string | null;
  readonly project?: string | null;
  readonly workspace?: string | null;
  readonly apiKeyId?: string | null;
  /** `#691` — the verified delegation chain, and the principal it roots at. */
  readonly delegationChain?: string | null;
  readonly delegationRoot?: string | null;
  readonly startedAtUnix: number;
  readonly completedAtUnix?: number | null;
  readonly route?: string | null;
  readonly provider?: string | null;
  readonly logicalModel?: string | null;
  readonly providerModel?: string | null;
  readonly statusCode?: number | null;
  readonly cacheStatus?: string | null;
  readonly latencyMs?: number | null;
  readonly promptTokens?: number | null;
  readonly completionTokens?: number | null;
  readonly totalTokens?: number | null;
  readonly guardrailVerdict?: string | null;
  readonly streamed?: boolean;
  readonly document?: Record<string, unknown>;
}

/** Seed `request_logs` with raw SQL — see {@link RequestLogSeed}. */
export async function seedRequestLogs(rows: readonly RequestLogSeed[]): Promise<void> {
  if (rows.length === 0) return;
  await db().batch(
    rows.map((row) =>
      db()
        .prepare(
          `INSERT INTO ${REQUEST_LOG_TABLE}
             (request_id, trace_id, agent_run_id, tenant, project, workspace, api_key_id,
              delegation_chain, delegation_root, started_at_unix, completed_at_unix,
              route, provider, logical_model, provider_model, status_code, cache_status,
              latency_ms, prompt_tokens, completion_tokens, total_tokens,
              guardrail_verdict, streamed, request_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          row.requestId,
          row.traceId ?? null,
          row.agentRunId ?? null,
          row.tenant ?? null,
          row.project ?? null,
          row.workspace ?? null,
          row.apiKeyId ?? null,
          row.delegationChain ?? null,
          row.delegationRoot ?? null,
          row.startedAtUnix,
          row.completedAtUnix ?? null,
          row.route ?? null,
          row.provider ?? null,
          row.logicalModel ?? null,
          row.providerModel ?? null,
          row.statusCode ?? null,
          row.cacheStatus ?? null,
          row.latencyMs ?? null,
          row.promptTokens ?? null,
          row.completionTokens ?? null,
          row.totalTokens ?? null,
          row.guardrailVerdict ?? null,
          row.streamed === true ? 1 : 0,
          JSON.stringify(row.document ?? {}),
        ),
    ),
  );
}

/**
 * One settled (or deliberately unpriced) `billing_events` row, in the shape
 * `apps/gateway/src/metering/d1.ts` writes.
 *
 * The same cross-Worker-seam argument {@link RequestLogSeed} makes applies:
 * the writer is the gateway's metering sink, a different Worker with a
 * different `wrangler.toml`, so what these fixtures hold is that the READER
 * joins and fences what the table holds. `event` is the raw `event_json`
 * document, stated verbatim rather than assembled by a helper — the reader
 * reads that document with `json_extract`, so a fixture built by the encoder
 * under test could not show that the two agree.
 *
 * `cost` is deliberately `number | null`, not `number | undefined` collapsed to
 * 0: #663's whole point is that a usage nothing could price leaves a durable
 * row whose `cost_usd` is ABSENT, and "absent" must not read as "$0".
 */
export interface BillingEventSeed {
  readonly id: string;
  readonly requestId: string;
  readonly attemptIndex?: number;
  readonly occurredAtUnix: number;
  readonly event: Record<string, unknown>;
}

/** Seed `billing_events` with raw SQL — see {@link BillingEventSeed}. */
export async function seedBillingEvents(rows: readonly BillingEventSeed[]): Promise<void> {
  if (rows.length === 0) return;
  await db().batch(
    rows.map((row) =>
      db()
        .prepare(
          `INSERT INTO ${BILLING_EVENT_TABLE}
             (billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .bind(
          row.id,
          row.requestId,
          row.attemptIndex ?? 0,
          row.occurredAtUnix,
          JSON.stringify(row.event),
        ),
    ),
  );
}

/**
 * Insert rows the way the store does, for the read-only collections that have
 * no create route (`models`, `providers`, `metering-events`, …).
 *
 * Deliberately raw SQL rather than a call into `D1ControlPlaneStore`: a fixture
 * built with the code under test cannot show that the code under test reads what
 * is actually in the table.
 */
export async function seedD1(collection: string, records: readonly StoreRecord[]): Promise<void> {
  if (records.length === 0) return;
  await db().batch(
    records.map((record) =>
      db()
        .prepare(
          `INSERT INTO ${RESOURCE_TABLE}
             (resource_kind, resource_id, document_json, revision, created_at_unix, updated_at_unix)
           VALUES (?, ?, ?, 1, ?, ?)`,
        )
        .bind(collection, record.id, JSON.stringify(record), 1, 1),
    ),
  );
}

/** The raw stored document, read straight out of the table. */
export async function rawDocument(
  collection: string,
  id: string,
): Promise<Record<string, unknown> | null> {
  const row = await db()
    .prepare(
      `SELECT document_json FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`,
    )
    .bind(collection, id)
    .first<{ document_json: string }>();
  return row === null ? null : (JSON.parse(row.document_json) as Record<string, unknown>);
}

/** The storage revision of a stored row, or `null` when it is gone. */
export async function rawRevision(collection: string, id: string): Promise<number | null> {
  const row = await db()
    .prepare(`SELECT revision FROM ${RESOURCE_TABLE} WHERE resource_kind = ? AND resource_id = ?`)
    .bind(collection, id)
    .first<{ revision: number }>();
  return row === null ? null : row.revision;
}

/** One decoded `audit_events` row. */
export interface AuditRow {
  readonly id: string;
  readonly request_id: string;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  readonly audit: Record<string, unknown>;
}

/** Every audit row written so far, oldest first. */
export async function auditRows(): Promise<readonly AuditRow[]> {
  const rows = await db()
    .prepare(`SELECT id, request_id, tenant, occurred_at_unix, audit_json FROM ${AUDIT_TABLE}`)
    .all<{
      id: string;
      request_id: string;
      tenant: string | null;
      occurred_at_unix: number;
      audit_json: string;
    }>();
  return rows.results.map((row) => ({
    id: row.id,
    request_id: row.request_id,
    tenant: row.tenant,
    occurred_at_unix: row.occurred_at_unix,
    audit: JSON.parse(row.audit_json) as Record<string, unknown>,
  }));
}
