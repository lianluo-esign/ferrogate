import {
  TENANT_REQUEST_LOG_UPSERT_SQL,
  tenantRequestLogBindings,
} from "../../../../apps/gateway/src/requestlog/d1.js";
import type { RequestLogRecord } from "../../../../apps/gateway/src/requestlog/record.js";
import { STORED_ASSET_COLUMNS } from "../../src/d1/assets-d1.js";
import { usageMetadataRollupId } from "../../src/ids.js";
import type {
  TenantDataBatchRequest,
  TenantDataNamespace,
  TenantDataObject,
  TenantDataResult,
  TenantDataStatement,
} from "../../src/tenant-data-object.js";

export const EXPECTED_THROUGHPUT_PATHS = [
  "inferenceMeteringWrite",
  "walletReserve",
  "usageRollupUpdate",
  "assetRead",
  "requestLogWrite",
] as const;

export type ThroughputPath = (typeof EXPECTED_THROUGHPUT_PATHS)[number];

export interface ThroughputPathMetrics {
  readonly opCount: number;
  readonly throughputOpsPerSec: number;
  readonly p50LatencyMs: number;
  readonly p99LatencyMs: number;
  readonly totalLatencyMs: number;
  /** Wall-time share, used as a CPU-work proxy in local workerd. */
  readonly latencySharePercent: number;
}

export type ThroughputPathMetricsByName = {
  readonly [Path in ThroughputPath]: ThroughputPathMetrics;
};

export interface ThroughputRunMetrics {
  readonly concurrency: number;
  readonly inferenceEvents: number;
  readonly storageOperations: number;
  readonly wallClockMs: number;
  readonly inferenceEventsPerSec: number;
  readonly storageOperationsPerSec: number;
  readonly p50LatencyMs: number;
  readonly p99LatencyMs: number;
  readonly queueingObserved: boolean;
  readonly paths: ThroughputPathMetricsByName;
}

export interface ThroughputRowEvidence {
  readonly requestLogs: number;
  readonly walletReservations: number;
  readonly usageAggregateRows: number;
  readonly usageMetadataRows: number;
  readonly agentCostBurnRows: number;
  readonly storedAssets: number;
  readonly usageAggregateTotalTokens: number;
  readonly usageMetadataRequestCount: number;
  readonly agentCostAccumulatedUsd: number;
}

export interface TenantThroughputReport {
  readonly tenantId: string;
  readonly eventsPerWorker: number;
  readonly totalInferenceEvents: number;
  readonly totalStorageOperations: number;
  readonly queueingBaselineP99Ms: number;
  readonly queueingThresholdP99Ms: number;
  readonly beforeQueueing: {
    readonly concurrency: number;
    readonly inferenceEventsPerSec: number;
    readonly storageOperationsPerSec: number;
    readonly p99LatencyMs: number;
  };
  readonly paths: ThroughputPathMetricsByName;
  readonly runs: readonly ThroughputRunMetrics[];
  readonly rowEvidence: ThroughputRowEvidence;
}

type TenantStub = DurableObjectStub<TenantDataObject> & {
  batch(request: TenantDataBatchRequest): Promise<TenantDataResult[]>;
  query(request: {
    readonly tenantId: string;
    readonly sql: string;
    readonly params?: readonly (ArrayBuffer | string | number | null)[];
  }): Promise<TenantDataResult>;
};

type PathSamples = { -readonly [Path in ThroughputPath]: number[] };

const NOW_UNIX = 1_785_974_400;
const PERIOD_MONTH = "2026-08";
const EVENTS_PER_WORKER = 4;
const CONCURRENCY_LEVELS = [1, 4, 8, 16] as const;
const PROMPT_TOKENS = 100;
const COMPLETION_TOKENS = 40;
const TOTAL_TOKENS = PROMPT_TOKENS + COMPLETION_TOKENS;
const COST_USD = 0.000002;
const AGENT_KEY = "throughput-agent";
const LOGICAL_MODEL = "gpt-4o-mini";
const PROVIDER = "openai";
const METADATA_KEY = "feature";
const METADATA_VALUE = "throughput";
const ASSET_TYPE = "skill";
const ASSET_NAME = "throughput-fixture";
const ASSET_VERSION = "1.0.0";

const CONTEXT_SQL =
  "INSERT INTO tenant_contexts " +
  "(id, organization_id, team_id, project_id, workspace_id, user_id, api_key_id) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING";

// The following statements intentionally mirror D1UsageLedger.persistUsageAggregate
// (src/d1/usage-d1.ts:218-279, 336-372, and 406-429). The harness measures the
// object RPC around them; it does not benchmark a synthetic table or a fake write.
const AGGREGATE_SQL =
  "INSERT INTO usage_aggregate_rollups " +
  "(id, tenant_context_id, logical_model, provider, prompt_tokens, " +
  " completion_tokens, total_tokens, cached_input_tokens, cache_write_tokens, " +
  " reasoning_tokens, updated_at_unix) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) " +
  "ON CONFLICT (id) DO UPDATE SET " +
  "prompt_tokens = usage_aggregate_rollups.prompt_tokens + excluded.prompt_tokens, " +
  "completion_tokens = usage_aggregate_rollups.completion_tokens + excluded.completion_tokens, " +
  "total_tokens = usage_aggregate_rollups.total_tokens + excluded.total_tokens, " +
  "cached_input_tokens = usage_aggregate_rollups.cached_input_tokens + excluded.cached_input_tokens, " +
  "cache_write_tokens = usage_aggregate_rollups.cache_write_tokens + excluded.cache_write_tokens, " +
  "reasoning_tokens = usage_aggregate_rollups.reasoning_tokens + excluded.reasoning_tokens, " +
  "updated_at_unix = max(usage_aggregate_rollups.updated_at_unix, excluded.updated_at_unix)";

const AGENT_COST_BURN_SQL =
  "INSERT INTO agent_cost_burn " +
  "(tenant_id, agent_key, period, accumulated_usd, first_seen_unix, updated_at_unix) " +
  "VALUES (?, ?, ?, ?, ?, ?) " +
  "ON CONFLICT (tenant_id, agent_key, period) DO UPDATE SET " +
  "accumulated_usd = agent_cost_burn.accumulated_usd + excluded.accumulated_usd, " +
  "first_seen_unix = min(agent_cost_burn.first_seen_unix, excluded.first_seen_unix), " +
  "updated_at_unix = max(agent_cost_burn.updated_at_unix, excluded.updated_at_unix)";

const USAGE_METADATA_ROLLUP_SQL =
  "INSERT INTO usage_metadata_rollups " +
  "(id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens, " +
  " completion_tokens, total_tokens, cost_usd, request_count, error_count, updated_at_unix) " +
  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?) " +
  "ON CONFLICT (id) DO UPDATE SET " +
  "prompt_tokens = usage_metadata_rollups.prompt_tokens + excluded.prompt_tokens, " +
  "completion_tokens = usage_metadata_rollups.completion_tokens + excluded.completion_tokens, " +
  "total_tokens = usage_metadata_rollups.total_tokens + excluded.total_tokens, " +
  "cost_usd = usage_metadata_rollups.cost_usd + excluded.cost_usd, " +
  "request_count = usage_metadata_rollups.request_count + excluded.request_count, " +
  "error_count = usage_metadata_rollups.error_count + excluded.error_count, " +
  "updated_at_unix = max(usage_metadata_rollups.updated_at_unix, excluded.updated_at_unix)";

// This is the exact three-statement reserve shape from D1WalletStore
// (src/d1/wallet-d1.ts:327-371). It stays one object batch so the guarded money
// decision retains the atomicity the production path requires.
const RESERVATION_SELECT_SQL =
  "SELECT id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, " +
  "created_at_unix, updated_at_unix FROM wallet_reservations WHERE id = ?";

const RESERVATION_INSERT_SQL =
  "INSERT INTO wallet_reservations " +
  "(id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, " +
  " created_at_unix, updated_at_unix) " +
  "SELECT ?, ?, ?, 'active', ?, NULL, ?, ? " +
  "FROM wallets w " +
  "WHERE w.tenant_id = ? " +
  "  AND ? <= w.balance_credits - COALESCE(( " +
  "      SELECT SUM(r.amount_credits) FROM wallet_reservations r " +
  "      WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ? " +
  "  ), 0) " +
  "ON CONFLICT (id) DO NOTHING RETURNING id";

const WALLET_STATE_SQL =
  "SELECT w.balance_credits AS balance_credits, " +
  "COALESCE((SELECT SUM(r.amount_credits) FROM wallet_reservations r " +
  "WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ?), 0) " +
  "AS outstanding_credits FROM wallets w WHERE w.tenant_id = ?";

const ASSET_READ_SQL = `SELECT ${STORED_ASSET_COLUMNS} FROM stored_assets WHERE id = ?`;

function objectFor(namespace: TenantDataNamespace, tenantId: string): TenantStub {
  return namespace.get(namespace.idFromName(tenantId)) as unknown as TenantStub;
}

function statement(
  sql: string,
  params: readonly (ArrayBuffer | string | number | null)[],
): TenantDataStatement {
  return { sql, params };
}

function emptySamples(): PathSamples {
  return {
    inferenceMeteringWrite: [],
    walletReserve: [],
    usageRollupUpdate: [],
    assetRead: [],
    requestLogWrite: [],
  };
}

function percentile(samples: readonly number[], percentileRank: number): number {
  const ordered = [...samples].sort((left, right) => left - right);
  const index = Math.min(
    ordered.length - 1,
    Math.max(0, Math.ceil(ordered.length * percentileRank) - 1),
  );
  return ordered[index] ?? 0;
}

function positiveDurationMs(startedAt: number): number {
  return Math.max(performance.now() - startedAt, 0.001);
}

function contextIdFor(tenantId: string): string {
  return `${tenantId}:throughput-context`;
}

function aggregateIdFor(tenantId: string): string {
  return `${contextIdFor(tenantId)}:${LOGICAL_MODEL}:${PROVIDER}`;
}

function metadataIdFor(tenantId: string): string {
  return usageMetadataRollupId(PERIOD_MONTH, tenantId, METADATA_KEY, METADATA_VALUE);
}

function assetIdFor(tenantId: string): string {
  return `${tenantId}:${ASSET_TYPE}:${ASSET_NAME}:${ASSET_VERSION}:`;
}

function inferenceStatements(tenantId: string, eventId: number): TenantDataStatement[] {
  const now = NOW_UNIX + eventId;
  return [
    statement(CONTEXT_SQL, [
      contextIdFor(tenantId),
      tenantId,
      null,
      "throughput-project",
      "throughput-workspace",
      null,
      "throughput-key",
    ]),
    statement(AGGREGATE_SQL, [
      aggregateIdFor(tenantId),
      contextIdFor(tenantId),
      LOGICAL_MODEL,
      PROVIDER,
      PROMPT_TOKENS,
      COMPLETION_TOKENS,
      TOTAL_TOKENS,
      0,
      0,
      0,
      now,
    ]),
    statement(AGENT_COST_BURN_SQL, [tenantId, AGENT_KEY, PERIOD_MONTH, COST_USD, now, now]),
  ];
}

function walletReserveStatements(tenantId: string, eventId: number): TenantDataStatement[] {
  const reservationId = `${tenantId}:throughput-reservation:${eventId}`;
  const now = NOW_UNIX + eventId;
  const expiresAt = now + 3_600;
  return [
    statement(RESERVATION_SELECT_SQL, [reservationId]),
    statement(RESERVATION_INSERT_SQL, [
      reservationId,
      tenantId,
      1,
      expiresAt,
      now,
      now,
      tenantId,
      1,
      tenantId,
      now,
    ]),
    statement(WALLET_STATE_SQL, [tenantId, now, tenantId]),
  ];
}

function usageRollupStatements(tenantId: string, eventId: number): TenantDataStatement[] {
  const now = NOW_UNIX + eventId;
  return [
    statement(USAGE_METADATA_ROLLUP_SQL, [
      metadataIdFor(tenantId),
      PERIOD_MONTH,
      tenantId,
      METADATA_KEY,
      METADATA_VALUE,
      PROMPT_TOKENS,
      COMPLETION_TOKENS,
      TOTAL_TOKENS,
      COST_USD,
      0,
      now,
    ]),
  ];
}

function requestLogRecord(tenantId: string, eventId: number): RequestLogRecord {
  const startedAtUnix = NOW_UNIX + eventId;
  return {
    requestId: `${tenantId}:throughput-request:${eventId}`,
    traceId: `${tenantId}:throughput-trace:${eventId}`,
    agentRunId: `${tenantId}:throughput-run:${eventId}`,
    tenantId,
    projectId: "throughput-project",
    workspaceId: "throughput-workspace",
    apiKeyId: "throughput-key",
    method: "POST",
    path: "/v1/chat/completions",
    route: "openai.chat.completions",
    provider: PROVIDER,
    logicalModel: LOGICAL_MODEL,
    providerModel: LOGICAL_MODEL,
    statusCode: 200,
    startedAtUnix,
    completedAtUnix: startedAtUnix + 1,
    latencyMs: 1,
    promptTokens: PROMPT_TOKENS,
    completionTokens: COMPLETION_TOKENS,
    totalTokens: TOTAL_TOKENS,
    guardrailVerdict: "allowed",
    streamed: false,
  };
}

async function runBatch(
  stub: TenantStub,
  tenantId: string,
  statements: readonly TenantDataStatement[],
): Promise<TenantDataResult[]> {
  const results = await stub.batch({ tenantId, statements });
  if (results.length !== statements.length) {
    throw new Error(
      `throughput harness received ${results.length} results for ${statements.length} statements`,
    );
  }
  return results;
}

async function measure(samples: number[], operation: () => Promise<void>): Promise<void> {
  const startedAt = performance.now();
  await operation();
  samples.push(positiveDurationMs(startedAt));
}

function summarizePath(
  samples: readonly number[],
  wallClockMs: number,
  totalLatencyMs: number,
): ThroughputPathMetrics {
  const total = samples.reduce((sum, sample) => sum + sample, 0);
  return {
    opCount: samples.length,
    throughputOpsPerSec: samples.length / (wallClockMs / 1_000),
    p50LatencyMs: percentile(samples, 0.5),
    p99LatencyMs: percentile(samples, 0.99),
    totalLatencyMs: total,
    latencySharePercent: totalLatencyMs === 0 ? 0 : (total / totalLatencyMs) * 100,
  };
}

function summarizeRun(
  concurrency: number,
  samples: PathSamples,
  wallClockMs: number,
): Omit<ThroughputRunMetrics, "queueingObserved"> {
  const allSamples = EXPECTED_THROUGHPUT_PATHS.flatMap((path) => samples[path]);
  const totalLatencyMs = allSamples.reduce((sum, sample) => sum + sample, 0);
  const inferenceEvents = concurrency * EVENTS_PER_WORKER;
  const storageOperations = inferenceEvents * EXPECTED_THROUGHPUT_PATHS.length;
  const paths = {
    inferenceMeteringWrite: summarizePath(
      samples.inferenceMeteringWrite,
      wallClockMs,
      totalLatencyMs,
    ),
    walletReserve: summarizePath(samples.walletReserve, wallClockMs, totalLatencyMs),
    usageRollupUpdate: summarizePath(samples.usageRollupUpdate, wallClockMs, totalLatencyMs),
    assetRead: summarizePath(samples.assetRead, wallClockMs, totalLatencyMs),
    requestLogWrite: summarizePath(samples.requestLogWrite, wallClockMs, totalLatencyMs),
  } satisfies ThroughputPathMetricsByName;
  return {
    concurrency,
    inferenceEvents,
    storageOperations,
    wallClockMs,
    inferenceEventsPerSec: inferenceEvents / (wallClockMs / 1_000),
    storageOperationsPerSec: storageOperations / (wallClockMs / 1_000),
    p50LatencyMs: percentile(allSamples, 0.5),
    p99LatencyMs: percentile(allSamples, 0.99),
    paths,
  };
}

async function seedTenant(stub: TenantStub, tenantId: string): Promise<void> {
  const assetId = assetIdFor(tenantId);
  await runBatch(stub, tenantId, [
    statement("DELETE FROM request_logs", []),
    statement("DELETE FROM usage_metadata_rollups", []),
    statement("DELETE FROM usage_aggregate_rollups", []),
    statement("DELETE FROM tenant_contexts", []),
    statement("DELETE FROM agent_cost_burn", []),
    statement("DELETE FROM wallet_reservations", []),
    statement("DELETE FROM wallets", []),
    statement("DELETE FROM stored_assets", []),
    statement(
      "INSERT INTO wallets (id, tenant_id, balance_credits, dunning, created_at_unix, updated_at_unix) " +
        "VALUES (?, ?, ?, 0, ?, ?)",
      [tenantId, tenantId, 1_000_000, NOW_UNIX, NOW_UNIX],
    ),
    statement(
      "INSERT INTO stored_assets " +
        "(id, tenant_id, project_id, asset_type, name, version, content_type, content_hash, " +
        "size_bytes, created_at_unix, updated_at_unix, storage_uri, variant, yanked, visibility) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'visible')",
      [
        assetId,
        tenantId,
        "throughput-project",
        ASSET_TYPE,
        ASSET_NAME,
        ASSET_VERSION,
        "application/zip",
        "throughput-fixture-hash",
        128,
        NOW_UNIX,
        NOW_UNIX,
        `assets/${assetId}`,
        "",
      ],
    ),
  ]);
}

async function rowEvidence(stub: TenantStub, tenantId: string): Promise<ThroughputRowEvidence> {
  const result = await stub.query({
    tenantId,
    sql:
      "SELECT " +
      "(SELECT COUNT(*) FROM request_logs) AS request_logs, " +
      "(SELECT COUNT(*) FROM wallet_reservations) AS wallet_reservations, " +
      "(SELECT COUNT(*) FROM usage_aggregate_rollups WHERE id = ?) AS usage_aggregate_rows, " +
      "(SELECT COUNT(*) FROM usage_metadata_rollups WHERE id = ?) AS usage_metadata_rows, " +
      "(SELECT COUNT(*) FROM agent_cost_burn WHERE tenant_id = ? AND agent_key = ? AND period = ?) AS agent_cost_burn_rows, " +
      "(SELECT COUNT(*) FROM stored_assets WHERE id = ?) AS stored_assets, " +
      "(SELECT COALESCE(total_tokens, 0) FROM usage_aggregate_rollups WHERE id = ?) AS usage_aggregate_total_tokens, " +
      "(SELECT COALESCE(request_count, 0) FROM usage_metadata_rollups WHERE id = ?) AS usage_metadata_request_count, " +
      "(SELECT COALESCE(accumulated_usd, 0) FROM agent_cost_burn WHERE tenant_id = ? AND agent_key = ? AND period = ?) AS agent_cost_accumulated_usd",
    params: [
      aggregateIdFor(tenantId),
      metadataIdFor(tenantId),
      tenantId,
      AGENT_KEY,
      PERIOD_MONTH,
      assetIdFor(tenantId),
      aggregateIdFor(tenantId),
      metadataIdFor(tenantId),
      tenantId,
      AGENT_KEY,
      PERIOD_MONTH,
    ],
  });
  const row = result.results[0];
  if (row === undefined) throw new Error("throughput harness row evidence query returned no row");
  const numberValue = (key: string): number => Number(row[key] ?? 0);
  return {
    requestLogs: numberValue("request_logs"),
    walletReservations: numberValue("wallet_reservations"),
    usageAggregateRows: numberValue("usage_aggregate_rows"),
    usageMetadataRows: numberValue("usage_metadata_rows"),
    agentCostBurnRows: numberValue("agent_cost_burn_rows"),
    storedAssets: numberValue("stored_assets"),
    usageAggregateTotalTokens: numberValue("usage_aggregate_total_tokens"),
    usageMetadataRequestCount: numberValue("usage_metadata_request_count"),
    agentCostAccumulatedUsd: numberValue("agent_cost_accumulated_usd"),
  };
}

export async function runTenantThroughputHarness(
  namespace: TenantDataNamespace,
  tenantId: string,
): Promise<TenantThroughputReport> {
  const stub = objectFor(namespace, tenantId);
  await seedTenant(stub, tenantId);
  const runs: Omit<ThroughputRunMetrics, "queueingObserved">[] = [];
  const allSamples = emptySamples();
  let eventOffset = 0;

  for (const concurrency of CONCURRENCY_LEVELS) {
    const samples = emptySamples();
    const runStartedAt = performance.now();
    await Promise.all(
      Array.from({ length: concurrency }, async (_, worker) => {
        for (let iteration = 0; iteration < EVENTS_PER_WORKER; iteration += 1) {
          const eventId = eventOffset + worker * EVENTS_PER_WORKER + iteration;
          await Promise.all([
            measure(samples.inferenceMeteringWrite, async () => {
              await runBatch(stub, tenantId, inferenceStatements(tenantId, eventId));
            }),
            measure(samples.walletReserve, async () => {
              const results = await runBatch(
                stub,
                tenantId,
                walletReserveStatements(tenantId, eventId),
              );
              if ((results[1]?.results.length ?? 0) !== 1) {
                throw new Error(`wallet reserve path did not admit event ${eventId}`);
              }
            }),
            measure(samples.usageRollupUpdate, async () => {
              await runBatch(stub, tenantId, usageRollupStatements(tenantId, eventId));
            }),
            measure(samples.assetRead, async () => {
              const result = await stub.query({
                tenantId,
                sql: ASSET_READ_SQL,
                params: [assetIdFor(tenantId)],
              });
              if (result.results.length !== 1) {
                throw new Error(`asset read path did not find the fixture for event ${eventId}`);
              }
            }),
            measure(samples.requestLogWrite, async () => {
              const record = requestLogRecord(tenantId, eventId);
              await runBatch(stub, tenantId, [
                statement(TENANT_REQUEST_LOG_UPSERT_SQL, tenantRequestLogBindings(record)),
              ]);
            }),
          ]);
        }
      }),
    );
    const wallClockMs = positiveDurationMs(runStartedAt);
    runs.push(summarizeRun(concurrency, samples, wallClockMs));
    for (const path of EXPECTED_THROUGHPUT_PATHS) {
      allSamples[path].push(...samples[path]);
    }
    eventOffset += concurrency * EVENTS_PER_WORKER;
  }

  // workerd exposes no queue-depth signal, so use a relative p99 inflection:
  // a non-baseline run must exceed both 2x baseline and baseline + 1 ms.
  const queueingBaselineP99Ms = runs[0]?.p99LatencyMs ?? 0;
  const queueingThresholdP99Ms = Math.max(queueingBaselineP99Ms * 2, queueingBaselineP99Ms + 1);
  const measuredRuns: ThroughputRunMetrics[] = runs.map((run) => ({
    ...run,
    queueingObserved: run.concurrency > 1 && run.p99LatencyMs > queueingThresholdP99Ms,
  }));
  const preQueueRun =
    [...measuredRuns].reverse().find((run) => !run.queueingObserved) ?? measuredRuns[0];
  if (preQueueRun === undefined) throw new Error("throughput harness produced no load runs");
  const totalInferenceEvents = eventOffset;
  const totalStorageOperations = totalInferenceEvents * EXPECTED_THROUGHPUT_PATHS.length;
  const totalWallClockMs = measuredRuns.reduce((sum, run) => sum + run.wallClockMs, 0);
  const totalLatencyMs = EXPECTED_THROUGHPUT_PATHS.reduce(
    (sum, path) => sum + allSamples[path].reduce((pathSum, sample) => pathSum + sample, 0),
    0,
  );
  const paths = {
    inferenceMeteringWrite: summarizePath(
      allSamples.inferenceMeteringWrite,
      totalWallClockMs,
      totalLatencyMs,
    ),
    walletReserve: summarizePath(allSamples.walletReserve, totalWallClockMs, totalLatencyMs),
    usageRollupUpdate: summarizePath(
      allSamples.usageRollupUpdate,
      totalWallClockMs,
      totalLatencyMs,
    ),
    assetRead: summarizePath(allSamples.assetRead, totalWallClockMs, totalLatencyMs),
    requestLogWrite: summarizePath(allSamples.requestLogWrite, totalWallClockMs, totalLatencyMs),
  } satisfies ThroughputPathMetricsByName;

  return {
    tenantId,
    eventsPerWorker: EVENTS_PER_WORKER,
    totalInferenceEvents,
    totalStorageOperations,
    queueingBaselineP99Ms,
    queueingThresholdP99Ms,
    beforeQueueing: {
      concurrency: preQueueRun.concurrency,
      inferenceEventsPerSec: preQueueRun.inferenceEventsPerSec,
      storageOperationsPerSec: preQueueRun.storageOperationsPerSec,
      p99LatencyMs: preQueueRun.p99LatencyMs,
    },
    paths,
    runs: measuredRuns,
    rowEvidence: await rowEvidence(stub, tenantId),
  };
}

export function assertCompleteThroughputReport(report: TenantThroughputReport): void {
  if (!Number.isInteger(report.totalInferenceEvents) || report.totalInferenceEvents <= 0) {
    throw new Error("throughput report has no inference events");
  }
  if (
    report.totalStorageOperations !==
    report.totalInferenceEvents * EXPECTED_THROUGHPUT_PATHS.length
  ) {
    throw new Error("throughput report storage operation count does not match the five-path mix");
  }
  for (const path of EXPECTED_THROUGHPUT_PATHS) {
    const metrics = report.paths[path];
    if (metrics === undefined || metrics.opCount !== report.totalInferenceEvents) {
      throw new Error(`${path} is missing or was silently skipped`);
    }
    if (
      !Number.isFinite(metrics.throughputOpsPerSec) ||
      metrics.throughputOpsPerSec <= 0 ||
      !Number.isFinite(metrics.p50LatencyMs) ||
      metrics.p50LatencyMs < 0 ||
      !Number.isFinite(metrics.p99LatencyMs) ||
      metrics.p99LatencyMs < metrics.p50LatencyMs ||
      !Number.isFinite(metrics.latencySharePercent) ||
      metrics.latencySharePercent < 0
    ) {
      throw new Error(`${path} metrics are not well formed`);
    }
  }
  if (report.runs.length !== CONCURRENCY_LEVELS.length) {
    throw new Error("throughput report did not record every concurrency run");
  }
  for (const run of report.runs) {
    if (run.storageOperations !== run.inferenceEvents * EXPECTED_THROUGHPUT_PATHS.length) {
      throw new Error(`concurrency ${run.concurrency} did not execute the five-path mix`);
    }
    for (const path of EXPECTED_THROUGHPUT_PATHS) {
      if (run.paths[path].opCount !== run.inferenceEvents) {
        throw new Error(`${path} was skipped at concurrency ${run.concurrency}`);
      }
    }
  }
  if (
    report.rowEvidence.requestLogs !== report.totalInferenceEvents ||
    report.rowEvidence.walletReservations !== report.totalInferenceEvents ||
    report.rowEvidence.usageAggregateRows !== 1 ||
    report.rowEvidence.usageMetadataRows !== 1 ||
    report.rowEvidence.agentCostBurnRows !== 1 ||
    report.rowEvidence.storedAssets !== 1 ||
    report.rowEvidence.usageMetadataRequestCount !== report.totalInferenceEvents
  ) {
    throw new Error("throughput report row evidence does not prove every path reached real tables");
  }
}
