/**
 * `experiment_shadow_legs` in the tenant object.
 *
 * The table is defined by `sql/d1-ts/tenant/…` and the tenant object is the SOLE
 * authoritative store for the shadow leg — a shadow leg is tenant data and lives
 * in the owning object, never mirrored into the shared control store (#859/#881
 * red line). The control-D1 projection this module once dual-wrote was DROPPED
 * from the control object by `0043_drop_experiment_eval_projections.sql`; the
 * operator report reads the tenant objects by fan-out (`admin_experiment.ts`,
 * f11bd842), so there is no control projection to write, repair or sweep.
 */

import { requestLogTenantDatabaseFrom } from "../requestlog/d1.js";
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
interface ExperimentPreparedStatement {
  bind(...values: unknown[]): {
    run(): Promise<unknown>;
  };
}

export interface ExperimentDatabase {
  prepare(query: string): ExperimentPreparedStatement;
}

/** Resolve the authoritative object database for one tenant. */
export function experimentTenantDatabaseFrom(
  env: unknown,
  tenantId: string,
): ExperimentDatabase | undefined {
  if (tenantId.trim() === "") return undefined;
  if (typeof env !== "object" || env === null) return undefined;
  if ((env as { TENANT_DATA?: unknown }).TENANT_DATA === undefined) return undefined;
  return requestLogTenantDatabaseFrom(env, tenantId) as ExperimentDatabase | undefined;
}

/**
 * Persist one leg to the tenant-authoritative object.
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
