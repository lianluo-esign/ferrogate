/**
 * Request-log persistence for the tenant-authoritative evidence trail (#664,
 * #859).
 *
 * `TenantDataObject` owns the authoritative table from
 * `sql/d1-ts/tenant/0012_request_logs_agent_runs.sql`. The same table in
 * `sql/d1-ts/control` is a derived compatibility projection for existing fleet
 * joins. The control copy is never a fallback for a tenant object and may be
 * stale.
 */
import { DurableObjectD1Database } from "@ferrogate/storage";
import { tenantObjectAddressForEnv } from "../residency/carrier.js";
import { type TenantDataBindings, tenantDataObjectFor } from "../tenancy/tenant-data.js";
import type { RequestLogRecord } from "./record.js";
import { requestLogToWire } from "./record.js";

/** The table `apps/control-plane/src/store/d1.ts::REQUEST_LOG_TABLE` reads. */
export const REQUEST_LOG_TABLE = "request_logs";

/** The control-D1 table is a derived compatibility projection, never authority. */
export const REQUEST_LOG_PROJECTION_TABLE = REQUEST_LOG_TABLE;

/**
 * Key the derived projection by its owning tenant and logical id. The length
 * prefix keeps tenant ids containing `:` unambiguous while leaving the
 * human-facing request id unchanged for joins and exports.
 */
export function evidenceProjectionKey(
  tenantId: string | null | undefined,
  logicalId: string,
): string {
  const tenant = tenantId ?? "";
  // SQLite length() counts Unicode code points; JS string.length counts UTF-16 units.
  return `${Array.from(tenant).length}:${tenant}:${logicalId}`;
}

/**
 * The control-projection upsert. Tenant-object writes use the sibling
 * `TENANT_REQUEST_LOG_UPSERT_SQL`, whose single physical database makes the
 * logical request id sufficient as its conflict target.
 *
 * ## Why UPSERT and not INSERT
 *
 * Two independent reasons, and each on its own would be enough:
 *
 *  1. **Queues are at-least-once.** A consumer that has already applied a
 *     message may be handed it again after a partial batch failure. A bare
 *     `INSERT` would fail the retry on the primary key and the whole batch
 *     would be redelivered forever; `INSERT OR IGNORE` would be safe but would
 *     also silently drop a genuine correction.
 *  2. **The row is assembled from more than one leg.** Today the middleware
 *     writes it whole, but the shape this change is built for is more legs
 *     landing later — cost attribution, tamper evidence, online evals all hang
 *     off the same `request_id`. Making the write a merge now means those
 *     slices add a column and a leg rather than a second table.
 *
 * ## Why every updated column is `COALESCE(excluded.x, request_logs.x)`
 *
 * Because a partial write must never ERASE a fact. If a redelivered or later
 * leg knows nothing about `total_tokens`, `excluded.total_tokens` is NULL, and
 * a plain `SET total_tokens = excluded.total_tokens` would blank a token count
 * the first write got right. Evidence that gets less complete over time is the
 * one thing an audit trail may not do.
 *
 * The two exceptions are `completed_at_unix` / `latency_ms` / `status_code`,
 * which are also COALESCEd for the same reason — there is no field here whose
 * later NULL is more truthful than an earlier value.
 *
 * `request_json` is the exception in the other direction: it is REPLACED when
 * the new document is non-empty, because it is the whole document rather than
 * one fact, and merging two JSON blobs in SQLite would need `json_patch()` and
 * a decision about array semantics that nothing here needs yet.
 */
const REQUEST_LOG_UPDATE_SET = `DO UPDATE SET
  trace_id = COALESCE(excluded.trace_id, ${REQUEST_LOG_TABLE}.trace_id),
  agent_run_id = COALESCE(excluded.agent_run_id, ${REQUEST_LOG_TABLE}.agent_run_id),
  delegation_chain = COALESCE(excluded.delegation_chain, ${REQUEST_LOG_TABLE}.delegation_chain),
  delegation_root = COALESCE(excluded.delegation_root, ${REQUEST_LOG_TABLE}.delegation_root),
  experiment_id = COALESCE(excluded.experiment_id, ${REQUEST_LOG_TABLE}.experiment_id),
  experiment_arm = COALESCE(excluded.experiment_arm, ${REQUEST_LOG_TABLE}.experiment_arm),
  routing_decision = COALESCE(excluded.routing_decision, ${REQUEST_LOG_TABLE}.routing_decision),
  tenant = COALESCE(excluded.tenant, ${REQUEST_LOG_TABLE}.tenant),
  project = COALESCE(excluded.project, ${REQUEST_LOG_TABLE}.project),
  workspace = COALESCE(excluded.workspace, ${REQUEST_LOG_TABLE}.workspace),
  api_key_id = COALESCE(excluded.api_key_id, ${REQUEST_LOG_TABLE}.api_key_id),
  route = COALESCE(excluded.route, ${REQUEST_LOG_TABLE}.route),
  provider = COALESCE(excluded.provider, ${REQUEST_LOG_TABLE}.provider),
  logical_model = COALESCE(excluded.logical_model, ${REQUEST_LOG_TABLE}.logical_model),
  provider_model = COALESCE(excluded.provider_model, ${REQUEST_LOG_TABLE}.provider_model),
  status_code = COALESCE(excluded.status_code, ${REQUEST_LOG_TABLE}.status_code),
  error_code = COALESCE(excluded.error_code, ${REQUEST_LOG_TABLE}.error_code),
  cache_status = COALESCE(excluded.cache_status, ${REQUEST_LOG_TABLE}.cache_status),
  latency_ms = COALESCE(excluded.latency_ms, ${REQUEST_LOG_TABLE}.latency_ms),
  prompt_tokens = COALESCE(excluded.prompt_tokens, ${REQUEST_LOG_TABLE}.prompt_tokens),
  completion_tokens = COALESCE(excluded.completion_tokens, ${REQUEST_LOG_TABLE}.completion_tokens),
  total_tokens = COALESCE(excluded.total_tokens, ${REQUEST_LOG_TABLE}.total_tokens),
  guardrail_verdict = COALESCE(excluded.guardrail_verdict, ${REQUEST_LOG_TABLE}.guardrail_verdict),
  guardrail_policy_id = COALESCE(excluded.guardrail_policy_id, ${REQUEST_LOG_TABLE}.guardrail_policy_id),
  streamed = MAX(excluded.streamed, ${REQUEST_LOG_TABLE}.streamed),
  completed_at_unix = COALESCE(excluded.completed_at_unix, ${REQUEST_LOG_TABLE}.completed_at_unix),
  request_json = CASE WHEN excluded.request_json = '{}' THEN ${REQUEST_LOG_TABLE}.request_json
                      ELSE excluded.request_json END`;

/** Control-D1 projection write: the tenant-qualified key is authoritative. */
export const REQUEST_LOG_UPSERT_SQL = `INSERT INTO ${REQUEST_LOG_TABLE} (
  projection_key, request_id, trace_id, agent_run_id, delegation_chain, delegation_root,
  experiment_id, experiment_arm, routing_decision,
  tenant, project, workspace, api_key_id,
  route, provider, logical_model, provider_model,
  status_code, error_code, cache_status, latency_ms,
  prompt_tokens, completion_tokens, total_tokens,
  guardrail_verdict, guardrail_policy_id, streamed,
  started_at_unix, completed_at_unix, request_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) ${REQUEST_LOG_UPDATE_SET}`;

/** Tenant-object write: one object contains one tenant, so request_id is enough. */
export const TENANT_REQUEST_LOG_UPSERT_SQL = `INSERT INTO ${REQUEST_LOG_TABLE} (
  request_id, trace_id, agent_run_id, delegation_chain, delegation_root,
  experiment_id, experiment_arm, routing_decision,
  tenant, project, workspace, api_key_id,
  route, provider, logical_model, provider_model,
  status_code, error_code, cache_status, latency_ms,
  prompt_tokens, completion_tokens, total_tokens,
  guardrail_verdict, guardrail_policy_id, streamed,
  started_at_unix, completed_at_unix, request_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (request_id) ${REQUEST_LOG_UPDATE_SET}`;

/** `undefined` → SQL NULL, so an unknown fact is stored as unknown. */
function bindOptional(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

/** The bound values for one record, in `REQUEST_LOG_UPSERT_SQL`'s column order. */
export function requestLogBindings(record: RequestLogRecord): (string | number | null)[] {
  return [
    evidenceProjectionKey(record.tenantId, record.requestId),
    ...tenantRequestLogBindings(record),
  ];
}

/** Bound values for the tenant-object SQL, which has no projection key column. */
export function tenantRequestLogBindings(record: RequestLogRecord): (string | number | null)[] {
  return [
    record.requestId,
    bindOptional(record.traceId),
    bindOptional(record.agentRunId),
    bindOptional(record.delegationChain),
    bindOptional(record.delegationRoot),
    bindOptional(record.experimentId),
    bindOptional(record.experimentArm),
    bindOptional(record.routingDecision),
    bindOptional(record.tenantId),
    bindOptional(record.projectId),
    bindOptional(record.workspaceId),
    bindOptional(record.apiKeyId),
    bindOptional(record.route),
    bindOptional(record.provider),
    bindOptional(record.logicalModel),
    bindOptional(record.providerModel),
    bindOptional(record.statusCode),
    bindOptional(record.errorCode),
    bindOptional(record.cacheStatus),
    bindOptional(record.latencyMs),
    bindOptional(record.promptTokens),
    bindOptional(record.completionTokens),
    bindOptional(record.totalTokens),
    record.guardrailVerdict,
    bindOptional(record.guardrailPolicyId),
    record.streamed ? 1 : 0,
    record.startedAtUnix,
    bindOptional(record.completedAtUnix),
    JSON.stringify(requestLogToWire(record)),
  ];
}

/**
 * The `D1Database` surface this module uses, structurally.
 *
 * Shaped so a live binding satisfies it with no cast — the same device
 * `src/metering/ports.ts` and `src/assets/ports.ts` use — so a test can supply
 * a recording decorator without the production code knowing a test exists.
 */
export interface RequestLogDatabase {
  prepare(query: string): {
    bind(...values: unknown[]): { run(): Promise<unknown>; all(): Promise<unknown> };
  };
  batch(statements: unknown[]): Promise<unknown[]>;
}

/** Resolve the authoritative object-backed database for one tenant. */
export function requestLogTenantDatabaseFrom(
  env: unknown,
  tenantId: string,
): RequestLogDatabase | undefined {
  if (tenantId.trim() === "") return undefined;
  if (typeof env !== "object" || env === null) return undefined;
  const stub = tenantDataObjectFor(
    env as TenantDataBindings,
    tenantId,
    tenantObjectAddressForEnv(env, tenantId),
  );
  return new DurableObjectD1Database(tenantId, stub).asD1Database() as RequestLogDatabase;
}

/**
 * Persist a batch of records in ONE D1 round trip.
 *
 * `batch` rather than N `run()`s because this is the queue consumer's whole
 * job: a hundred decisions arriving together should cost one round trip, and
 * D1's batch is also the only atomic unit it offers. A batch that fails fails
 * whole, which is what lets the Queue redeliver it safely against the upsert.
 *
 * Rejects on failure — deliberately, and unlike everything else on this path.
 * Here the caller is either a Queue consumer (whose retry ladder needs a
 * rejection to arm) or {@link RequestLogSink}, which swallows it and counts it.
 */
export async function writeRequestLogs(
  db: RequestLogDatabase,
  records: readonly RequestLogRecord[],
): Promise<void> {
  if (records.length === 0) return;
  const statement = db.prepare(REQUEST_LOG_UPSERT_SQL);
  await db.batch(records.map((record) => statement.bind(...requestLogBindings(record))));
}

/** Persist tenant-attributed rows through their authoritative object. */
export async function writeTenantRequestLogs(
  db: RequestLogDatabase,
  records: readonly RequestLogRecord[],
): Promise<void> {
  if (records.length === 0) return;
  const statement = db.prepare(TENANT_REQUEST_LOG_UPSERT_SQL);
  await db.batch(records.map((record) => statement.bind(...tenantRequestLogBindings(record))));
}
