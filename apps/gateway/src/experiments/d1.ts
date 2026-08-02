/**
 * `experiment_shadow_legs` in the CONTROL database.
 *
 * The table is defined by `sql/d1-ts/control/0010_experiment_outcomes.sql`, and
 * lives in the CONTROL database for the reason `0009_online_eval.sql` and
 * `0004_guardrail_evaluations.sql` both give at length: the read that matters —
 * the shadow arm's cost and latency beside the SERVED arms' (`request_logs`,
 * `billing_events`) — is a single-database query here and an impossible one
 * across two, because D1 has no read spanning databases.
 */
import type { ShadowLegRecord } from "./record.js";

export const EXPERIMENT_SHADOW_LEG_TABLE = "experiment_shadow_legs";

/**
 * The leg upsert.
 *
 * `ON CONFLICT (leg_id) DO UPDATE` makes a re-mirrored request replace its own
 * row rather than double-count the arm. `leg_id` is derived from the client's
 * request id, so "the same request was mirrored twice" and "two different
 * requests" stay distinguishable — and a doubled leg would silently over-weight
 * whichever requests happened to be retried, which is exactly the bias the
 * `(request_id, criterion_id)` arbiter protects the score table from.
 */
export const EXPERIMENT_SHADOW_LEG_UPSERT_SQL = `INSERT INTO ${EXPERIMENT_SHADOW_LEG_TABLE} (
  leg_id, client_request_id, experiment_id, tenant, project, workspace, api_key_id,
  logical_model, provider, provider_model,
  status_code, error_code, latency_ms,
  prompt_tokens, completion_tokens, total_tokens, cost_usd, observed_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (leg_id) DO UPDATE SET
  status_code = excluded.status_code,
  error_code = excluded.error_code,
  latency_ms = excluded.latency_ms,
  prompt_tokens = excluded.prompt_tokens,
  completion_tokens = excluded.completion_tokens,
  total_tokens = excluded.total_tokens,
  cost_usd = excluded.cost_usd,
  observed_at_unix = excluded.observed_at_unix`;

/** Bind order for {@link EXPERIMENT_SHADOW_LEG_UPSERT_SQL}. */
export function shadowLegBindings(record: ShadowLegRecord): unknown[] {
  return [
    record.legId,
    record.clientRequestId,
    record.experimentId,
    record.tenantId,
    record.projectId ?? null,
    record.workspaceId ?? null,
    record.apiKeyId ?? null,
    record.logicalModel,
    record.provider,
    record.providerModel,
    record.statusCode ?? null,
    record.errorCode ?? null,
    record.latencyMs,
    record.promptTokens ?? null,
    record.completionTokens ?? null,
    record.totalTokens ?? null,
    record.costUsd ?? null,
    record.observedAtUnix,
  ];
}

/** The `D1Database` subset this writer needs. A live binding fits. */
export interface ExperimentDatabase {
  prepare(query: string): {
    bind(...values: unknown[]): { run(): Promise<unknown> };
  };
}

/** `env.CONTROL_DB` (or its `BILLING_DB` alias), when it really is a binding. */
export function experimentDatabaseFrom(env: unknown): ExperimentDatabase | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const bindings = env as { CONTROL_DB?: unknown; BILLING_DB?: unknown };
  for (const candidate of [bindings.CONTROL_DB, bindings.BILLING_DB]) {
    if (
      typeof candidate === "object" &&
      candidate !== null &&
      typeof (candidate as ExperimentDatabase).prepare === "function"
    ) {
      return candidate as ExperimentDatabase;
    }
  }
  return undefined;
}

/**
 * Persist one leg.
 *
 * REJECTS on failure — the caller decides. `./sink.ts` swallows it, because the
 * only caller is inside the mirror's own fire-and-forget task and a rejection
 * there would surface as a logged Worker exception on a request that succeeded.
 * Keeping the throw HERE rather than inside means a future caller with a retry
 * ladder still has something to arm.
 */
export async function writeShadowLeg(
  db: ExperimentDatabase,
  record: ShadowLegRecord,
): Promise<void> {
  await db
    .prepare(EXPERIMENT_SHADOW_LEG_UPSERT_SQL)
    .bind(...shadowLegBindings(record))
    .run();
}
