/**
 * `experiment_shadow_legs` in the tenant object, with a CONTROL projection.
 *
 * The table is defined by `sql/d1-ts/control/0011_experiment_outcomes.sql`, and
 * The tenant object is authoritative for the shadow leg. The control row is a
 * tenant-qualified projection used by cross-request reports beside the SERVED
 * arms' (`request_logs`, `billing_events`) because D1 has no read spanning
 * databases. The scheduled repair sweep rebuilds that projection from the
 * object when a mirror write is interrupted.
 */
import type { ShadowLegErrorCode, ShadowLegRecord } from "./record.js";
import { controlDatabaseFrom } from "../control-data.js";
import { evidenceProjectionKey, requestLogTenantDatabaseFrom } from "../requestlog/d1.js";

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

/** Control-D1 projection, keyed by tenant plus the shadow leg id. */
export const EXPERIMENT_SHADOW_LEG_PROJECTION_UPSERT_SQL = `INSERT INTO ${EXPERIMENT_SHADOW_LEG_TABLE} (
  projection_key, leg_id, client_request_id, experiment_id, tenant, project, workspace, api_key_id,
  logical_model, provider, provider_model,
  status_code, error_code, latency_ms,
  prompt_tokens, completion_tokens, total_tokens, cost_usd, observed_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
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

export function shadowLegProjectionBindings(record: ShadowLegRecord): unknown[] {
  return [evidenceProjectionKey(record.tenantId, record.legId), ...shadowLegBindings(record)];
}

/** The `D1Database` subset this writer needs. A live binding fits. */
interface ExperimentPreparedStatement {
  bind(...values: unknown[]): {
    run(): Promise<unknown>;
    all?<T>(): Promise<{ results: T[] }>;
  };
}

export interface ExperimentDatabase {
  prepare(query: string): ExperimentPreparedStatement;
}

/** The CONTROL database facade, when it really is a binding. */
export function experimentDatabaseFrom(env: unknown): ExperimentDatabase | undefined {
  const candidate = controlDatabaseFrom(env);
  return typeof candidate === "object" &&
    candidate !== null &&
    typeof (candidate as ExperimentDatabase).prepare === "function"
    ? (candidate as unknown as ExperimentDatabase)
    : undefined;
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

/** Persist the control projection after the object-authoritative write. */
export async function writeShadowLegProjection(
  db: ExperimentDatabase,
  record: ShadowLegRecord,
): Promise<void> {
  // The object write is authoritative. A short retry keeps a transient control
  // D1 outage repairable without duplicating the shadow leg in the object.
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      await db
        .prepare(EXPERIMENT_SHADOW_LEG_PROJECTION_UPSERT_SQL)
        .bind(...shadowLegProjectionBindings(record))
        .run();
      return;
    } catch (error) {
      if (attempt === 3) throw error;
    }
  }
}

interface StoredShadowLegRow {
  readonly leg_id: string;
  readonly client_request_id: string;
  readonly experiment_id: string;
  readonly tenant: string;
  readonly project: string | null;
  readonly workspace: string | null;
  readonly api_key_id: string | null;
  readonly logical_model: string;
  readonly provider: string;
  readonly provider_model: string;
  readonly status_code: number | null;
  readonly error_code: string | null;
  readonly latency_ms: number;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly cost_usd: number | null;
  readonly observed_at_unix: number;
}

const SHADOW_LEG_ERROR_CODES = new Set<ShadowLegErrorCode>([
  "shadow_budget_exhausted",
  "adapter_unavailable",
  "adapter_refused",
  "provider_dispatch_error",
]);

function shadowLegRecordFromRow(row: StoredShadowLegRow): ShadowLegRecord {
  const errorCode =
    row.error_code !== null && SHADOW_LEG_ERROR_CODES.has(row.error_code as ShadowLegErrorCode)
      ? (row.error_code as ShadowLegErrorCode)
      : undefined;
  return {
    legId: row.leg_id,
    clientRequestId: row.client_request_id,
    experimentId: row.experiment_id,
    tenantId: row.tenant,
    ...(row.project === null ? {} : { projectId: row.project }),
    ...(row.workspace === null ? {} : { workspaceId: row.workspace }),
    ...(row.api_key_id === null ? {} : { apiKeyId: row.api_key_id }),
    logicalModel: row.logical_model,
    provider: row.provider,
    providerModel: row.provider_model,
    ...(row.status_code === null ? {} : { statusCode: row.status_code }),
    ...(errorCode === undefined ? {} : { errorCode }),
    latencyMs: row.latency_ms,
    ...(row.prompt_tokens === null ? {} : { promptTokens: row.prompt_tokens }),
    ...(row.completion_tokens === null ? {} : { completionTokens: row.completion_tokens }),
    ...(row.total_tokens === null ? {} : { totalTokens: row.total_tokens }),
    ...(row.cost_usd === null ? {} : { costUsd: row.cost_usd }),
    observedAtUnix: row.observed_at_unix,
  };
}

/** Rebuild control projections from tenant-authoritative shadow legs. */
export async function sweepExperimentProjections(
  env: unknown,
  tenantIds: readonly string[],
  limit = 500,
): Promise<void> {
  const projection = experimentDatabaseFrom(env);
  if (projection === undefined) return;
  for (const tenantId of tenantIds) {
    if (tenantId.trim() === "") continue;
    try {
      const tenant = experimentTenantDatabaseFrom(env, tenantId);
      if (tenant === undefined) continue;
      const pageSize = Math.max(1, Math.trunc(limit));
      let cursor: { observedAtUnix: number; legId: string } | undefined;
      for (;;) {
        const statement =
          cursor === undefined
            ? tenant
                .prepare(
                  "SELECT leg_id, client_request_id, experiment_id, tenant, project, workspace, api_key_id, " +
                    "logical_model, provider, provider_model, status_code, error_code, latency_ms, " +
                    "prompt_tokens, completion_tokens, total_tokens, cost_usd, observed_at_unix " +
                    "FROM experiment_shadow_legs ORDER BY observed_at_unix ASC, leg_id ASC LIMIT ?",
                )
                .bind(pageSize)
            : tenant
                .prepare(
                  "SELECT leg_id, client_request_id, experiment_id, tenant, project, workspace, api_key_id, " +
                    "logical_model, provider, provider_model, status_code, error_code, latency_ms, " +
                    "prompt_tokens, completion_tokens, total_tokens, cost_usd, observed_at_unix " +
                    "FROM experiment_shadow_legs " +
                    "WHERE observed_at_unix > ? OR (observed_at_unix = ? AND leg_id > ?) " +
                    "ORDER BY observed_at_unix ASC, leg_id ASC LIMIT ?",
                )
                .bind(cursor.observedAtUnix, cursor.observedAtUnix, cursor.legId, pageSize);
        if (statement.all === undefined) break;
        const rows = (await statement.all<StoredShadowLegRow>()).results;
        for (const row of rows) {
          await writeShadowLegProjection(projection, shadowLegRecordFromRow(row));
        }
        const last = rows.at(-1);
        if (last === undefined || rows.length < pageSize) break;
        cursor = { observedAtUnix: last.observed_at_unix, legId: last.leg_id };
      }
    } catch (error) {
      console.warn(
        `[ferrogate] experiment projection repair skipped for ${tenantId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
}
