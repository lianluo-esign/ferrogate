/**
 * Narrow, replace-style projections for tenant-derived usage views (#852).
 *
 * The tenant object remains the only additive writer. These functions read the
 * committed object snapshot and replace the matching control row, so a retry
 * after a partial control batch cannot double-count spend, tokens, or presence.
 */
import {
  evidenceProjectionKey,
  type RequestLogDatabase,
} from "../requestlog/d1.js";
import { periodMonthFromUnix, usageMetadataRollupId, usageMonthlyRollupId } from "@ferrogate/storage";
import type { UsageAggregateWrite } from "@ferrogate/storage";

/** The stable dimensions needed to rebuild a replace-style usage projection. */
export interface UsageProjectionRequest {
  readonly context: UsageAggregateWrite["context"];
  readonly logicalModel: string;
  readonly provider: string;
  readonly occurredAtUnix: number;
  readonly metadata?: ReadonlyMap<string, string> | undefined;
  readonly presenceApiKeyId?: string | undefined;
}

/** Convert a settled usage write into the projection-only request shape. */
export function usageProjectionRequestFor(write: UsageAggregateWrite): UsageProjectionRequest {
  return {
    context: write.context,
    logicalModel: write.logicalModel,
    provider: write.provider,
    occurredAtUnix: write.occurredAtUnix,
    ...(write.metadata === undefined ? {} : { metadata: write.metadata }),
    ...(write.presenceTouch === undefined
      ? {}
      : { presenceApiKeyId: write.presenceTouch.apiKeyId }),
  };
}

interface UsageProjectionRetryPayload {
  context: UsageAggregateWrite["context"];
  logicalModel: string;
  provider: string;
  occurredAtUnix: number;
  metadata?: readonly [string, string][];
  presenceApiKeyId?: string;
}

function usageProjectionRequestFromPayload(payloadJson: string): UsageProjectionRequest {
  const payload = JSON.parse(payloadJson) as UsageProjectionRetryPayload;
  if (
    payload === null ||
    typeof payload !== "object" ||
    payload.context === null ||
    typeof payload.context !== "object" ||
    typeof payload.logicalModel !== "string" ||
    typeof payload.provider !== "string" ||
    !Number.isSafeInteger(payload.occurredAtUnix) ||
    payload.occurredAtUnix < 0
  ) {
    throw new Error("invalid usage projection retry payload");
  }
  const metadata = payload.metadata === undefined ? undefined : new Map(payload.metadata);
  return {
    context: payload.context,
    logicalModel: payload.logicalModel,
    provider: payload.provider,
    occurredAtUnix: payload.occurredAtUnix,
    ...(metadata === undefined ? {} : { metadata }),
    ...(payload.presenceApiKeyId === undefined
      ? {}
      : { presenceApiKeyId: payload.presenceApiKeyId }),
  };
}

const USAGE_MONTHLY_PROJECTION_UPSERT_SQL = `INSERT INTO usage_monthly_rollups (
  projection_key, id, tenant, period_month, scope_type, scope_id,
  prompt_tokens, completion_tokens, total_tokens, cached_input_tokens,
  cache_write_tokens, reasoning_tokens, cost_usd, request_count, error_count,
  updated_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  id = excluded.id,
  tenant = excluded.tenant,
  period_month = excluded.period_month,
  scope_type = excluded.scope_type,
  scope_id = excluded.scope_id,
  prompt_tokens = excluded.prompt_tokens,
  completion_tokens = excluded.completion_tokens,
  total_tokens = excluded.total_tokens,
  cached_input_tokens = excluded.cached_input_tokens,
  cache_write_tokens = excluded.cache_write_tokens,
  reasoning_tokens = excluded.reasoning_tokens,
  cost_usd = excluded.cost_usd,
  request_count = excluded.request_count,
  error_count = excluded.error_count,
  updated_at_unix = excluded.updated_at_unix`;

const USAGE_METADATA_PROJECTION_UPSERT_SQL = `INSERT INTO usage_metadata_rollups (
  projection_key, id, tenant, period_month, organization_id, metadata_key,
  metadata_value, prompt_tokens, completion_tokens, total_tokens, cost_usd,
  request_count, error_count, updated_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  id = excluded.id,
  tenant = excluded.tenant,
  period_month = excluded.period_month,
  organization_id = excluded.organization_id,
  metadata_key = excluded.metadata_key,
  metadata_value = excluded.metadata_value,
  prompt_tokens = excluded.prompt_tokens,
  completion_tokens = excluded.completion_tokens,
  total_tokens = excluded.total_tokens,
  cost_usd = excluded.cost_usd,
  request_count = excluded.request_count,
  error_count = excluded.error_count,
  updated_at_unix = excluded.updated_at_unix`;

const USAGE_AGGREGATE_PROJECTION_UPSERT_SQL = `INSERT INTO usage_aggregate_rollups (
  projection_key, id, tenant, tenant_context_id, organization_id, project_id, api_key_id,
  logical_model, provider, prompt_tokens, completion_tokens, total_tokens,
  cached_input_tokens, cache_write_tokens, reasoning_tokens, updated_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  id = excluded.id,
  tenant = excluded.tenant,
  tenant_context_id = excluded.tenant_context_id,
  organization_id = excluded.organization_id,
  project_id = excluded.project_id,
  api_key_id = excluded.api_key_id,
  logical_model = excluded.logical_model,
  provider = excluded.provider,
  prompt_tokens = excluded.prompt_tokens,
  completion_tokens = excluded.completion_tokens,
  total_tokens = excluded.total_tokens,
  cached_input_tokens = excluded.cached_input_tokens,
  cache_write_tokens = excluded.cache_write_tokens,
  reasoning_tokens = excluded.reasoning_tokens,
  updated_at_unix = excluded.updated_at_unix`;

const OBSERVED_PRESENCE_PROJECTION_UPSERT_SQL = `INSERT INTO observed_agent_presence (
  projection_key, tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix,
  request_count, updated_at_unix
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (projection_key) DO UPDATE SET
  tenant_id = excluded.tenant_id,
  api_key_id = excluded.api_key_id,
  first_seen_at_unix = excluded.first_seen_at_unix,
  last_seen_at_unix = excluded.last_seen_at_unix,
  request_count = excluded.request_count,
  updated_at_unix = excluded.updated_at_unix`;

interface MonthlyRow {
  id: string;
  period_month: string;
  scope_type: string;
  scope_id: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cached_input_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  cost_usd: number;
  request_count: number;
  error_count: number;
  updated_at_unix: number;
}

interface MetadataRow {
  id: string;
  period_month: string;
  organization_id: string;
  metadata_key: string;
  metadata_value: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cost_usd: number;
  request_count: number;
  error_count: number;
  updated_at_unix: number;
}

interface AggregateRow {
  id: string;
  tenant_context_id: string;
  organization_id: string | null;
  project_id: string | null;
  api_key_id: string | null;
  logical_model: string;
  provider: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cached_input_tokens: number;
  cache_write_tokens: number;
  reasoning_tokens: number;
  updated_at_unix: number;
}

interface PresenceRow {
  tenant_id: string;
  api_key_id: string;
  first_seen_at_unix: number;
  last_seen_at_unix: number;
  request_count: number;
  updated_at_unix: number;
}

/** A control-D1-shaped database; the structural type also accepts test doubles. */
type ProjectionDatabase = Pick<RequestLogDatabase, "prepare" | "batch">;

/** A durable tenant-local control projection repair intent. */
export interface UsageProjectionRetryRow {
  readonly sourceId: string;
  readonly tenantId: string;
  readonly occurredAtUnix: number;
  readonly payloadJson: string;
  readonly attempts: number;
}

function projectionKey(tenantId: string, logicalId: string): string {
  return evidenceProjectionKey(tenantId, logicalId);
}

/** Project committed usage snapshots and any metadata rows touched. */
export async function projectUsageRollups(
  tenantDatabase: D1Database,
  projectionDatabase: ProjectionDatabase,
  write: UsageProjectionRequest,
): Promise<void> {
  const tenantId = write.context.organizationId?.trim() ?? "";
  if (tenantId === "") return;

  const periodMonth = periodMonthFromUnix(write.occurredAtUnix);
  const monthlyId = usageMonthlyRollupId(periodMonth, "tenant", tenantId);
  const monthly = await tenantDatabase
    .prepare(
      "SELECT id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens, " +
        "total_tokens, cached_input_tokens, cache_write_tokens, reasoning_tokens, cost_usd, " +
        "request_count, error_count, updated_at_unix FROM usage_monthly_rollups WHERE id = ?",
    )
    .bind(monthlyId)
    .first<MonthlyRow>();
  if (monthly === null) {
    throw new Error(`tenant usage monthly rollup ${monthlyId} is unavailable`);
  }

  const aggregateId = `${write.context.id}:${write.logicalModel}:${write.provider}`;
  const aggregate = await tenantDatabase
    .prepare(
      "SELECT r.id, r.tenant_context_id, c.organization_id, c.project_id, c.api_key_id, " +
        "r.logical_model, r.provider, r.prompt_tokens, r.completion_tokens, r.total_tokens, " +
        "r.cached_input_tokens, r.cache_write_tokens, r.reasoning_tokens, r.updated_at_unix " +
        "FROM usage_aggregate_rollups r JOIN tenant_contexts c ON c.id = r.tenant_context_id " +
        "WHERE r.id = ?",
    )
    .bind(aggregateId)
    .first<AggregateRow>();
  if (aggregate === null) {
    throw new Error(`tenant usage aggregate rollup ${aggregateId} is unavailable`);
  }

  const statements: unknown[] = [
    projectionDatabase
      .prepare(USAGE_MONTHLY_PROJECTION_UPSERT_SQL)
      .bind(
        projectionKey(tenantId, monthly.id),
        monthly.id,
        tenantId,
        monthly.period_month,
        monthly.scope_type,
        monthly.scope_id,
        monthly.prompt_tokens,
        monthly.completion_tokens,
        monthly.total_tokens,
        monthly.cached_input_tokens ?? 0,
        monthly.cache_write_tokens ?? 0,
        monthly.reasoning_tokens ?? 0,
        monthly.cost_usd,
        monthly.request_count,
        monthly.error_count,
        monthly.updated_at_unix,
      ),
    projectionDatabase
      .prepare(USAGE_AGGREGATE_PROJECTION_UPSERT_SQL)
      .bind(
        projectionKey(tenantId, aggregate.id),
        aggregate.id,
        tenantId,
        aggregate.tenant_context_id,
        aggregate.organization_id,
        aggregate.project_id,
        aggregate.api_key_id,
        aggregate.logical_model,
        aggregate.provider,
        aggregate.prompt_tokens,
        aggregate.completion_tokens,
        aggregate.total_tokens,
        aggregate.cached_input_tokens ?? 0,
        aggregate.cache_write_tokens ?? 0,
        aggregate.reasoning_tokens ?? 0,
        aggregate.updated_at_unix,
      ),
  ];

  const metadata = [...(write.metadata?.entries() ?? [])].sort(([a], [b]) =>
    a.localeCompare(b),
  );
  for (const [metadataKey, metadataValue] of metadata) {
    const metadataId = usageMetadataRollupId(periodMonth, tenantId, metadataKey, metadataValue);
    const row = await tenantDatabase
      .prepare(
        "SELECT id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens, " +
          "completion_tokens, total_tokens, cost_usd, request_count, error_count, updated_at_unix " +
          "FROM usage_metadata_rollups WHERE id = ?",
      )
      .bind(metadataId)
      .first<MetadataRow>();
    if (row === null) {
      throw new Error(`tenant usage metadata rollup ${metadataId} is unavailable`);
    }
    statements.push(
      projectionDatabase
        .prepare(USAGE_METADATA_PROJECTION_UPSERT_SQL)
        .bind(
          projectionKey(tenantId, row.id),
          row.id,
          tenantId,
          row.period_month,
          row.organization_id,
          row.metadata_key,
          row.metadata_value,
          row.prompt_tokens,
          row.completion_tokens,
          row.total_tokens,
          row.cost_usd,
          row.request_count,
          row.error_count,
          row.updated_at_unix,
        ),
    );
  }

  if (write.presenceApiKeyId !== undefined && write.presenceApiKeyId !== "") {
    const presence = await tenantDatabase
      .prepare(
        "SELECT tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, " +
          "updated_at_unix FROM observed_agent_presence WHERE tenant_id = ? AND api_key_id = ?",
      )
      .bind(tenantId, write.presenceApiKeyId)
      .first<PresenceRow>();
    if (presence === null) {
      throw new Error(`tenant observed presence ${tenantId}/${write.presenceApiKeyId} is unavailable`);
    }
    statements.push(
      projectionDatabase
        .prepare(OBSERVED_PRESENCE_PROJECTION_UPSERT_SQL)
        .bind(
          projectionKey(tenantId, write.presenceApiKeyId),
          presence.tenant_id,
          presence.api_key_id,
          presence.first_seen_at_unix,
          presence.last_seen_at_unix,
          presence.request_count,
          presence.updated_at_unix,
        ),
    );
  }

  await projectionDatabase.batch(statements);
}

/** Read due repair intents from the authoritative tenant object. */
export async function listUsageProjectionRetries(
  tenantDatabase: D1Database,
  nowUnix: number,
  limit: number,
): Promise<UsageProjectionRetryRow[]> {
  const result = await tenantDatabase
    .prepare(
      "SELECT source_id, tenant_id, occurred_at_unix, payload_json, attempts " +
        "FROM usage_projection_retries WHERE next_attempt_unix <= ? " +
        "ORDER BY next_attempt_unix ASC, source_id ASC LIMIT ?",
    )
    .bind(nowUnix, Math.max(0, Math.trunc(limit)))
    .all<{
      source_id: string;
      tenant_id: string;
      occurred_at_unix: number;
      payload_json: string;
      attempts: number;
    }>();
  return result.results.map((row) => ({
    sourceId: row.source_id,
    tenantId: row.tenant_id,
    occurredAtUnix: Number(row.occurred_at_unix),
    payloadJson: row.payload_json,
    attempts: Number(row.attempts),
  }));
}

/** Project one durable intent without touching additive tenant counters. */
export async function projectUsageProjectionRetry(
  tenantDatabase: D1Database,
  projectionDatabase: ProjectionDatabase,
  row: UsageProjectionRetryRow,
): Promise<void> {
  const request = usageProjectionRequestFromPayload(row.payloadJson);
  const rowTenantId = row.tenantId.trim();
  const payloadTenantId = request.context.organizationId?.trim() ?? "";
  if (rowTenantId === "" || payloadTenantId !== rowTenantId) {
    throw new Error(
      `usage projection retry ${row.sourceId} tenant mismatch: row=${row.tenantId}, payload=${payloadTenantId}`,
    );
  }
  await projectUsageRollups(
    tenantDatabase,
    projectionDatabase,
    request,
  );
}

/** Remove an intent only after every replace-style projection has committed. */
export async function clearUsageProjectionRetry(
  tenantDatabase: D1Database,
  sourceId: string,
): Promise<void> {
  await tenantDatabase
    .prepare("DELETE FROM usage_projection_retries WHERE source_id = ?")
    .bind(sourceId)
    .run();
}

/** Back off a repeatedly unavailable control projection. */
export async function deferUsageProjectionRetry(
  tenantDatabase: D1Database,
  row: UsageProjectionRetryRow,
  nowUnix: number,
): Promise<void> {
  const attempts = row.attempts + 1;
  const delay = Math.min(300, 2 ** Math.min(attempts, 8));
  await tenantDatabase
    .prepare(
      "UPDATE usage_projection_retries SET attempts = ?, next_attempt_unix = ?, " +
        "updated_at_unix = ? WHERE source_id = ?",
    )
    .bind(attempts, nowUnix + delay, nowUnix, row.sourceId)
    .run();
}

/** Project one object-authoritative presence row by its tenant-qualified key. */
export async function projectObservedPresence(
  tenantDatabase: D1Database,
  projectionDatabase: ProjectionDatabase,
  tenantId: string,
  apiKeyId: string,
): Promise<void> {
  const row = await tenantDatabase
    .prepare(
      "SELECT tenant_id, api_key_id, first_seen_at_unix, last_seen_at_unix, request_count, " +
        "updated_at_unix FROM observed_agent_presence WHERE tenant_id = ? AND api_key_id = ?",
    )
    .bind(tenantId, apiKeyId)
    .first<PresenceRow>();
  if (row === null) {
    throw new Error(`tenant observed presence ${tenantId}/${apiKeyId} is unavailable`);
  }
  await projectionDatabase.batch([
    projectionDatabase
      .prepare(OBSERVED_PRESENCE_PROJECTION_UPSERT_SQL)
      .bind(
        projectionKey(tenantId, apiKeyId),
        row.tenant_id,
        row.api_key_id,
        row.first_seen_at_unix,
        row.last_seen_at_unix,
        row.request_count,
        row.updated_at_unix,
      ),
  ]);
}
