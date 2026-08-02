/**
 * `request_logs` in the CONTROL database — the durable half of the evidence
 * trail (#664).
 *
 * The table is defined by `sql/d1-ts/control/0001_init_control.sql` (the
 * correlation keys) plus `0003_request_log_columns.sql` (the queryable decision
 * columns). `apps/control-plane` READS it; this module is the only writer in
 * the tree, and it deliberately lives on the gateway because that is the only
 * Worker on the inference path.
 */
import type { RequestLogRecord } from "./record.js";
import { requestLogToWire } from "./record.js";

/** The table `apps/control-plane/src/store/d1.ts::REQUEST_LOG_TABLE` reads. */
export const REQUEST_LOG_TABLE = "request_logs";

/**
 * The upsert every write goes through.
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
export const REQUEST_LOG_UPSERT_SQL = `INSERT INTO ${REQUEST_LOG_TABLE} (
  request_id, trace_id, agent_run_id, delegation_chain, delegation_root,
  experiment_id, experiment_arm,
  tenant, project, workspace, api_key_id,
  route, provider, logical_model, provider_model,
  status_code, error_code, cache_status, latency_ms,
  prompt_tokens, completion_tokens, total_tokens,
  guardrail_verdict, guardrail_policy_id, streamed,
  started_at_unix, completed_at_unix, request_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (request_id) DO UPDATE SET
  trace_id = COALESCE(excluded.trace_id, ${REQUEST_LOG_TABLE}.trace_id),
  agent_run_id = COALESCE(excluded.agent_run_id, ${REQUEST_LOG_TABLE}.agent_run_id),
  delegation_chain = COALESCE(excluded.delegation_chain, ${REQUEST_LOG_TABLE}.delegation_chain),
  delegation_root = COALESCE(excluded.delegation_root, ${REQUEST_LOG_TABLE}.delegation_root),
  experiment_id = COALESCE(excluded.experiment_id, ${REQUEST_LOG_TABLE}.experiment_id),
  experiment_arm = COALESCE(excluded.experiment_arm, ${REQUEST_LOG_TABLE}.experiment_arm),
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

/** `undefined` → SQL NULL, so an unknown fact is stored as unknown. */
function bindOptional(value: string | number | undefined): string | number | null {
  return value === undefined ? null : value;
}

/** The bound values for one record, in `REQUEST_LOG_UPSERT_SQL`'s column order. */
export function requestLogBindings(record: RequestLogRecord): (string | number | null)[] {
  return [
    record.requestId,
    bindOptional(record.traceId),
    bindOptional(record.agentRunId),
    bindOptional(record.delegationChain),
    bindOptional(record.delegationRoot),
    bindOptional(record.experimentId),
    bindOptional(record.experimentArm),
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
