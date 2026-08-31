/**
 * `guardrail_evaluations` / `guardrail_check_evaluations` persistence (#665,
 * #860).
 *
 * Tenant-attributed rows are authoritative in the owning TenantDataObject from
 * `sql/d1-ts/tenant/0013_guardrail_evaluations.sql`. The control-D1 tables from
 * `sql/d1-ts/control/0004_guardrail_evaluations.sql` remain a derived,
 * tenant-qualified projection for platform/fleet readers until #825.
 *
 * Both stores use the same COALESCE upsert semantics and parent-before-child
 * batch ordering. The database-specific conflict key is the important split:
 * a tenant object can use its local logical id, while the shared projection
 * must use the tenant-qualified `evidenceProjectionKey`.
 */
import { evidenceProjectionKey, requestLogTenantDatabaseFrom } from "../requestlog/d1.js";
import { type GuardrailEvidenceEnvelope, guardrailEvidenceToWire } from "./evidence-wire.js";

/** The tables `apps/control-plane/src/store/d1.ts` reads. */
export const GUARDRAIL_EVALUATION_TABLE = "guardrail_evaluations";
export const GUARDRAIL_CHECK_TABLE = "guardrail_check_evaluations";

/**
 * The evaluation upsert.
 *
 * ## Why UPSERT and not INSERT
 *
 * Three reasons, each sufficient on its own:
 *
 *  1. **Queues are at-least-once.** A consumer that has already applied a
 *     message may be handed it again; a bare `INSERT` would fail the retry on
 *     the primary key and the whole batch would redeliver forever.
 *  2. **Streaming screening re-decides.** `stream.ts` calls the engine once per
 *     SSE frame and the evaluation id is deterministic per
 *     `(request, policy@revision, stage)`, so a streamed response produces ONE
 *     logical row that is rewritten as the stream progresses. The last write
 *     wins, i.e. the row records the frame that actually decided the stream —
 *     which is exactly what `InMemoryGuardrailEvidenceSink.append` already did.
 *  3. **Later legs.** The same request id will grow cost and tamper-evidence
 *     legs; merging now means those add a column rather than a table.
 *
 * ## Why every updated column is `COALESCE(excluded.x, …)` except the verdict
 *
 * A partial write must never ERASE a fact. The DECISION columns
 * (`verdict`/`action`/`enforcement_status`/`latency_ms`/`finding_count`/
 * `evaluation_json`) are the exception and are REPLACED, because for those the
 * later write is the more truthful one: a stream that passed frame 1 and failed
 * frame 9 was blocked, and a `COALESCE` there would preserve the `pass` and
 * report that the guardrail let it through.
 */
const GUARDRAIL_EVALUATION_UPDATE_SET = `DO UPDATE SET
  trace_id = COALESCE(excluded.trace_id, ${GUARDRAIL_EVALUATION_TABLE}.trace_id),
  agent_run_id = COALESCE(excluded.agent_run_id, ${GUARDRAIL_EVALUATION_TABLE}.agent_run_id),
  subject_id = COALESCE(excluded.subject_id, ${GUARDRAIL_EVALUATION_TABLE}.subject_id),
  tenant = COALESCE(excluded.tenant, ${GUARDRAIL_EVALUATION_TABLE}.tenant),
  scope_type = excluded.scope_type,
  scope_id = COALESCE(excluded.scope_id, ${GUARDRAIL_EVALUATION_TABLE}.scope_id),
  target = excluded.target,
  protocol = excluded.protocol,
  stage = excluded.stage,
  mode = excluded.mode,
  policy_id = excluded.policy_id,
  policy_revision = excluded.policy_revision,
  verdict = excluded.verdict,
  action = excluded.action,
  enforcement_status = excluded.enforcement_status,
  latency_ms = excluded.latency_ms,
  finding_count = excluded.finding_count,
  input_fingerprint = excluded.input_fingerprint,
  action_fingerprint = COALESCE(excluded.action_fingerprint, ${GUARDRAIL_EVALUATION_TABLE}.action_fingerprint),
  occurred_at_unix = excluded.occurred_at_unix,
  evaluation_json = excluded.evaluation_json`;

/** Control-D1 projection write; the tenant-qualified key is the conflict key. */
export const GUARDRAIL_EVALUATION_UPSERT_SQL = `INSERT INTO ${GUARDRAIL_EVALUATION_TABLE} (
  projection_key, id, request_id, trace_id, agent_run_id, subject_id, tenant,
  scope_type, scope_id, target, protocol, stage, mode,
  policy_id, policy_revision, verdict, action, enforcement_status,
  latency_ms, finding_count, input_fingerprint, action_fingerprint,
  occurred_at_unix, evaluation_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) ${GUARDRAIL_EVALUATION_UPDATE_SET}`;

/** Tenant-object authoritative write; one object contains one tenant. */
export const TENANT_GUARDRAIL_EVALUATION_UPSERT_SQL = `INSERT INTO ${GUARDRAIL_EVALUATION_TABLE} (
  id, request_id, trace_id, agent_run_id, subject_id, tenant,
  scope_type, scope_id, target, protocol, stage, mode,
  policy_id, policy_revision, verdict, action, enforcement_status,
  latency_ms, finding_count, input_fingerprint, action_fingerprint,
  occurred_at_unix, evaluation_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) ${GUARDRAIL_EVALUATION_UPDATE_SET}`;

/**
 * The check upsert.
 *
 * Keyed on the check's own id, with `(evaluation_id, check_id)` UNIQUE behind
 * it. Same replace-the-decision rule as the parent, for the same streaming
 * reason: a detector that passed an early frame and failed a later one has
 * failed.
 */
const GUARDRAIL_CHECK_UPDATE_SET = `DO UPDATE SET
  detector_id = excluded.detector_id,
  detector_version = excluded.detector_version,
  config_digest = excluded.config_digest,
  verdict = excluded.verdict,
  action = excluded.action,
  enforcement_status = excluded.enforcement_status,
  error_kind = COALESCE(excluded.error_kind, ${GUARDRAIL_CHECK_TABLE}.error_kind),
  check_json = excluded.check_json`;

/** Control-D1 projection child write; its parent key carries tenant scope. */
export const GUARDRAIL_CHECK_UPSERT_SQL = `INSERT INTO ${GUARDRAIL_CHECK_TABLE} (
  projection_key, id, evaluation_projection_key, evaluation_id, tenant,
  check_id, detector_id, detector_version, config_digest,
  verdict, action, enforcement_status, error_kind, check_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) ${GUARDRAIL_CHECK_UPDATE_SET}`;

/** Tenant-object authoritative child write. */
export const TENANT_GUARDRAIL_CHECK_UPSERT_SQL = `INSERT INTO ${GUARDRAIL_CHECK_TABLE} (
  id, evaluation_id, tenant, check_id, detector_id, detector_version, config_digest,
  verdict, action, enforcement_status, error_kind, check_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) ${GUARDRAIL_CHECK_UPDATE_SET}`;

/** `undefined` → SQL NULL, so an unknown fact is stored as unknown. */
function bindOptional(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

/**
 * The `D1Database` surface this module uses, structurally.
 *
 * Shaped so a live binding satisfies it with no cast — the same device
 * `../requestlog/d1.ts` uses — so a test can supply a failing decorator without
 * the production code knowing a test exists.
 */
export interface GuardrailEvidenceDatabase {
  prepare(query: string): {
    bind(...values: unknown[]): { run(): Promise<unknown>; all(): Promise<unknown> };
  };
  batch(statements: unknown[]): Promise<unknown[]>;
}

/** Resolve the authoritative SQLite-backed TenantDataObject facade. */
export function guardrailTenantDatabaseFromEnv(
  env: unknown,
  tenantId: string,
): GuardrailEvidenceDatabase | undefined {
  if (
    typeof env !== "object" ||
    env === null ||
    (env as { TENANT_DATA?: unknown }).TENANT_DATA === undefined
  ) {
    return undefined;
  }
  return requestLogTenantDatabaseFrom(env, tenantId) as GuardrailEvidenceDatabase | undefined;
}

/** A non-empty authenticated tenant id is required for object-authoritative writes. */
function tenantIdOf(envelope: GuardrailEvidenceEnvelope): string {
  const tenantId = envelope.evaluation.tenant.organizationId;
  if (typeof tenantId !== "string" || tenantId.trim() === "") {
    throw new Error(
      `guardrail evidence ${envelope.evaluation.id} has no tenant and cannot enter a TenantDataObject`,
    );
  }
  return tenantId;
}

/**
 * Persist a batch of evidence envelopes in ONE D1 round trip.
 *
 * The PARENT statements are emitted before the child ones, and D1 applies a
 * batch in order: `guardrail_check_evaluations.evaluation_id` is a foreign key,
 * so a child written first would be rejected on a database with enforcement on.
 *
 * Rejects on failure — deliberately, and unlike everything else on this path.
 * The caller is either the Queue consumer (whose retry ladder needs a rejection
 * to arm) or {@link DurableGuardrailEvidenceSink}, which swallows it and counts
 * it.
 */
export async function writeGuardrailEvidence(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): Promise<void> {
  if (envelopes.length === 0) return;
  await db.batch(guardrailEvidenceStatements(db, envelopes));
}

/** Persist one same-tenant batch in its authoritative object. */
export async function writeTenantGuardrailEvidence(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): Promise<void> {
  if (envelopes.length === 0) return;
  await db.batch(tenantGuardrailEvidenceStatements(db, envelopes));
}

/**
 * Persist a batch of platform/unattributed evidence in the platform object
 * (Zero-D1 Plan B).
 *
 * These are the `unscoped` envelopes — the ones whose `tenant.organizationId`
 * is empty, i.e. `scope_type = 'platform'` screening of platform-operator /
 * anonymous calls. They have no owning tenant, so unlike
 * {@link writeTenantGuardrailEvidence} there is no single-tenant assertion and
 * the `tenant` column is written NULL. The platform table shares the tenant
 * table's id-keyed shape (no `projection_key`), so the same `ON CONFLICT (id)`
 * upsert applies verbatim.
 */
export async function writePlatformGuardrailEvidence(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): Promise<void> {
  if (envelopes.length === 0) return;
  await db.batch(platformGuardrailEvidenceStatements(db, envelopes));
}

/**
 * The prepared statements for a batch, WITHOUT running them.
 *
 * Exported so the shared queue consumer can put request-log and guardrail
 * statements into the SAME `db.batch` — one delivery, one round trip, one
 * atomic unit, which is what makes `retryAll()` safe for a mixed batch.
 */
export function guardrailEvidenceStatements(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): unknown[] {
  const evaluationStatement = db.prepare(GUARDRAIL_EVALUATION_UPSERT_SQL);
  const checkStatement = db.prepare(GUARDRAIL_CHECK_UPSERT_SQL);
  const parents: unknown[] = [];
  const children: unknown[] = [];
  for (const envelope of envelopes) {
    const wire = guardrailEvidenceToWire(envelope);
    const evaluation = envelope.evaluation;
    const tenantId = evaluation.tenant.organizationId;
    parents.push(
      evaluationStatement.bind(
        evidenceProjectionKey(tenantId, evaluation.id),
        evaluation.id,
        evaluation.requestId,
        bindOptional(evaluation.traceId),
        bindOptional(evaluation.agentRunId),
        bindOptional(evaluation.subjectId),
        bindOptional(evaluation.tenant.organizationId),
        evaluation.scopeType,
        bindOptional(evaluation.scopeId),
        evaluation.target,
        evaluation.protocol,
        evaluation.stage,
        evaluation.mode,
        evaluation.policyId,
        evaluation.policyRevision,
        evaluation.verdict,
        evaluation.action,
        evaluation.enforcementStatus,
        evaluation.latencyMs,
        evaluation.findingCount,
        evaluation.inputFingerprint,
        bindOptional(evaluation.actionFingerprint),
        evaluation.occurredAtUnix,
        JSON.stringify(wire),
      ),
    );
    const checkWires = Array.isArray(wire.checks) ? (wire.checks as unknown[]) : [];
    envelope.checks.forEach((check, index) => {
      children.push(
        checkStatement.bind(
          evidenceProjectionKey(tenantId, check.id),
          check.id,
          evidenceProjectionKey(tenantId, evaluation.id),
          evaluation.id,
          tenantId ?? null,
          check.checkId,
          check.detectorId,
          check.detectorVersion,
          check.configDigest,
          check.verdict,
          check.action,
          check.enforcementStatus,
          bindOptional(check.errorKind),
          JSON.stringify(checkWires[index] ?? {}),
        ),
      );
    });
  }
  return [...parents, ...children];
}

/** Prepared parent-before-child statements for one same-tenant object batch. */
export function tenantGuardrailEvidenceStatements(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): unknown[] {
  const evaluationStatement = db.prepare(TENANT_GUARDRAIL_EVALUATION_UPSERT_SQL);
  const checkStatement = db.prepare(TENANT_GUARDRAIL_CHECK_UPSERT_SQL);
  const parents: unknown[] = [];
  const children: unknown[] = [];
  let batchTenant: string | undefined;

  for (const envelope of envelopes) {
    const tenantId = tenantIdOf(envelope);
    if (batchTenant === undefined) batchTenant = tenantId;
    if (batchTenant !== tenantId) {
      throw new Error(
        `guardrail evidence batch mixes tenants ${batchTenant} and ${tenantId}; split by object`,
      );
    }
    const wire = guardrailEvidenceToWire(envelope);
    const evaluation = envelope.evaluation;
    parents.push(
      evaluationStatement.bind(
        evaluation.id,
        evaluation.requestId,
        bindOptional(evaluation.traceId),
        bindOptional(evaluation.agentRunId),
        bindOptional(evaluation.subjectId),
        tenantId,
        evaluation.scopeType,
        bindOptional(evaluation.scopeId),
        evaluation.target,
        evaluation.protocol,
        evaluation.stage,
        evaluation.mode,
        evaluation.policyId,
        evaluation.policyRevision,
        evaluation.verdict,
        evaluation.action,
        evaluation.enforcementStatus,
        evaluation.latencyMs,
        evaluation.findingCount,
        evaluation.inputFingerprint,
        bindOptional(evaluation.actionFingerprint),
        evaluation.occurredAtUnix,
        JSON.stringify(wire),
      ),
    );
    const checkWires = Array.isArray(wire.checks) ? (wire.checks as unknown[]) : [];
    envelope.checks.forEach((check, index) => {
      children.push(
        checkStatement.bind(
          check.id,
          evaluation.id,
          tenantId,
          check.checkId,
          check.detectorId,
          check.detectorVersion,
          check.configDigest,
          check.verdict,
          check.action,
          check.enforcementStatus,
          bindOptional(check.errorKind),
          JSON.stringify(checkWires[index] ?? {}),
        ),
      );
    });
  }
  return [...parents, ...children];
}

/**
 * Prepared parent-before-child statements for one platform-object batch.
 *
 * The platform twin of {@link tenantGuardrailEvidenceStatements}, with two
 * differences that follow from the platform object holding only unattributed
 * rows:
 *
 *  * **`tenant` is written NULL**, not the envelope's org id. These envelopes
 *    reached this function precisely because their `organizationId` was empty
 *    (the `unscoped` split), and every row in the platform object is
 *    unattributed by construction — the schema drops the tenant `NOT NULL` for
 *    exactly this, and reads over the object need no tenant fence.
 *  * **No single-tenant homogeneity assertion.** The tenant builder refuses a
 *    batch that mixes tenants because each tenant object may hold only its own
 *    rows; the one platform object holds them all, so there is nothing to fence.
 *
 * It reuses the `TENANT_*_UPSERT_SQL` statements verbatim: the platform table
 * shares the tenant table's id-keyed shape (`ON CONFLICT (id)`, no
 * `projection_key`), so the SQL is identical and only the bindings differ.
 */
export function platformGuardrailEvidenceStatements(
  db: GuardrailEvidenceDatabase,
  envelopes: readonly GuardrailEvidenceEnvelope[],
): unknown[] {
  const evaluationStatement = db.prepare(TENANT_GUARDRAIL_EVALUATION_UPSERT_SQL);
  const checkStatement = db.prepare(TENANT_GUARDRAIL_CHECK_UPSERT_SQL);
  const parents: unknown[] = [];
  const children: unknown[] = [];

  for (const envelope of envelopes) {
    const wire = guardrailEvidenceToWire(envelope);
    const evaluation = envelope.evaluation;
    parents.push(
      evaluationStatement.bind(
        evaluation.id,
        evaluation.requestId,
        bindOptional(evaluation.traceId),
        bindOptional(evaluation.agentRunId),
        bindOptional(evaluation.subjectId),
        // Unattributed by construction — the platform object's whole domain.
        null,
        evaluation.scopeType,
        bindOptional(evaluation.scopeId),
        evaluation.target,
        evaluation.protocol,
        evaluation.stage,
        evaluation.mode,
        evaluation.policyId,
        evaluation.policyRevision,
        evaluation.verdict,
        evaluation.action,
        evaluation.enforcementStatus,
        evaluation.latencyMs,
        evaluation.findingCount,
        evaluation.inputFingerprint,
        bindOptional(evaluation.actionFingerprint),
        evaluation.occurredAtUnix,
        JSON.stringify(wire),
      ),
    );
    const checkWires = Array.isArray(wire.checks) ? (wire.checks as unknown[]) : [];
    envelope.checks.forEach((check, index) => {
      children.push(
        checkStatement.bind(
          check.id,
          evaluation.id,
          null,
          check.checkId,
          check.detectorId,
          check.detectorVersion,
          check.configDigest,
          check.verdict,
          check.action,
          check.enforcementStatus,
          bindOptional(check.errorKind),
          JSON.stringify(checkWires[index] ?? {}),
        ),
      );
    });
  }
  return [...parents, ...children];
}
