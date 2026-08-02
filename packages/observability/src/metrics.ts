/**
 * Gateway metrics snapshot data model: the counter/total structs every
 * exporter renders from.
 *
 * Clean-room port of `ferrogate-observability::metrics`. Rust `u64` counters
 * become plain `number`s (all values stay well within `Number.MAX_SAFE_INTEGER`
 * for the counter ranges FerroGate emits); the `Default`-derived zero snapshot
 * is reproduced by {@link defaultGatewayMetricsSnapshot}.
 */

/** Structured request logs grouped by HTTP status code. */
export interface RequestStatusMetric {
  statusCode: number;
  count: number;
}

/** Prompt/completion/total token totals recorded by metering events. */
export interface TokenMetricTotals {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

/** Billing events grouped by logical model and provider. */
export interface ModelProviderMetricTotal {
  logicalModel: string;
  provider: string;
  requests: number;
  totalTokens: number;
}

/** Per-operation MCP ingress counts keyed by `Mcp-Method`/`Mcp-Name` (#277). */
export interface McpMethodMetricTotal {
  method: string;
  /** Operation target (tool name for `tools/call`); empty for nameless methods. */
  name: string;
  requests: number;
}

/**
 * #522: governed agent actions that reached a gateway surface without a
 * declared action id (`x-ferrogate-agent-run-id`). Deliberately
 * low-cardinality: only `tenant` and `surface` labels (issue #500).
 */
export interface UnjoinableActionMetricTotal {
  /** Authenticated tenant key (never a client-declared value). */
  tenant: string;
  /** Ingress surface that observed the missing id (`mcp`, `asset`). */
  surface: string;
  requests: number;
}

/**
 * A large flat counter bag every exporter renders from. Field docs mirror the
 * Rust crate; the issue tags (#151/#166/#263/#273/#277/#309/#368/#522) are the
 * acceptance-criteria anchors.
 */
export interface GatewayMetricsSnapshot {
  serviceName: string;
  requestLogTotal: number;
  requestErrorTotal: number;
  requestStatusTotals: RequestStatusMetric[];
  cacheHitsTotal: number;
  cacheMissesTotal: number;
  /** Subset of `cacheHitsTotal` served by the semantic layer (#273). */
  semanticCacheHitsTotal: number;
  guardrailMatchTotal: number;
  guardrailDenialTotal: number;
  guardrailRedactionTotal: number;
  guardrailDetectorErrorTotal: number;
  guardrailEvaluationTotal: number;
  guardrailEvaluationFailTotal: number;
  guardrailEvaluationErrorTotal: number;
  guardrailEvaluationShadowTotal: number;
  guardrailEvidencePersistenceFailureTotal: number;
  guardrailPolicyCasConflictTotal: number;
  billingEventTotal: number;
  /** Failures durably enqueueing a settled usage event (#151). */
  billingReportEnqueueFailureTotal: number;
  toolCallTotal: number;
  toolLatencyMsTotal: number;
  mcpIdentityResolutionTotal: number;
  mcpIdentityFailureTotal: number;
  mcpIdentityRefreshTotal: number;
  mcpIdentityRevocationTotal: number;
  mcpRefreshResponseDeadlineTotal: number;
  mcpRefreshStorageCancellationTotal: number;
  mcpRefreshStorageOutcomeUnknownTotal: number;
  mcpRefreshLateReconciliationTotal: number;
  mcpIdentityErrorAuditDeadlineTotal: number;
  postgresPoolAcquireTotal: number;
  postgresPoolAcquireTimeoutTotal: number;
  postgresPoolAcquireWaitMicrosTotal: number;
  /** #309: evidence-writer jobs accepted into the queue. */
  evidenceWriterEnqueuedTotal: number;
  /** #309: jobs the writer finished persisting. */
  evidenceWriterWrittenTotal: number;
  /** #309: evidence writes dropped past the bounded enqueue timeout. */
  evidenceWriterDroppedTotal: number;
  tokenTotals: TokenMetricTotals;
  modelProviderTotals: ModelProviderMetricTotal[];
  mcpMethodTotals: McpMethodMetricTotal[];
  /** Requests rejected pre-auth for not matching the IP allowlist (#166). */
  networkAccessDeniedTotal: number;
  /** Requests rejected pre-auth for exceeding the unauth rate limit (#166). */
  networkAccessRateLimitedTotal: number;
  /** Asset versions scanned by the lifecycle sweeper (#263). */
  assetLifecycleScannedTotal: number;
  /** Asset versions + unreferenced blobs pruned by the sweeper (#263). */
  assetLifecyclePrunedTotal: number;
  /** Lifecycle prune/GC delete operations that failed (#263). */
  assetLifecycleFailedTotal: number;
  /** #368: presign intents issued with a size/checksum-bound PUT URL. */
  assetPresignIntentIssuedTotal: number;
  /** #368: intents refused by the gateway's own preflight. Gateway-observed. */
  assetPresignIntentRejectedTotal: number;
  /** #368: client-asserted bucket refusals (not an independent observation). */
  assetPresignBucketRejectedTotal: number;
  /** #368: commits that found no staged object (own alertable class). */
  assetPresignStagingMissingTotal: number;
  /** #368: staged objects the gateway refused at commit. Gateway-observed. */
  assetPresignCommitRejectedTotal: number;
  /** #368: intents released through the abort surface (the release). */
  assetPresignAbortedTotal: number;
  /** #368: aborts that found staged bytes and failed to delete them. */
  assetPresignAbortReclaimFailedTotal: number;
}

/** Reproduces Rust's `#[derive(Default)]` zero snapshot. */
export function defaultGatewayMetricsSnapshot(): GatewayMetricsSnapshot {
  return {
    serviceName: "",
    requestLogTotal: 0,
    requestErrorTotal: 0,
    requestStatusTotals: [],
    cacheHitsTotal: 0,
    cacheMissesTotal: 0,
    semanticCacheHitsTotal: 0,
    guardrailMatchTotal: 0,
    guardrailDenialTotal: 0,
    guardrailRedactionTotal: 0,
    guardrailDetectorErrorTotal: 0,
    guardrailEvaluationTotal: 0,
    guardrailEvaluationFailTotal: 0,
    guardrailEvaluationErrorTotal: 0,
    guardrailEvaluationShadowTotal: 0,
    guardrailEvidencePersistenceFailureTotal: 0,
    guardrailPolicyCasConflictTotal: 0,
    billingEventTotal: 0,
    billingReportEnqueueFailureTotal: 0,
    toolCallTotal: 0,
    toolLatencyMsTotal: 0,
    mcpIdentityResolutionTotal: 0,
    mcpIdentityFailureTotal: 0,
    mcpIdentityRefreshTotal: 0,
    mcpIdentityRevocationTotal: 0,
    mcpRefreshResponseDeadlineTotal: 0,
    mcpRefreshStorageCancellationTotal: 0,
    mcpRefreshStorageOutcomeUnknownTotal: 0,
    mcpRefreshLateReconciliationTotal: 0,
    mcpIdentityErrorAuditDeadlineTotal: 0,
    postgresPoolAcquireTotal: 0,
    postgresPoolAcquireTimeoutTotal: 0,
    postgresPoolAcquireWaitMicrosTotal: 0,
    evidenceWriterEnqueuedTotal: 0,
    evidenceWriterWrittenTotal: 0,
    evidenceWriterDroppedTotal: 0,
    tokenTotals: { promptTokens: 0, completionTokens: 0, totalTokens: 0 },
    modelProviderTotals: [],
    mcpMethodTotals: [],
    networkAccessDeniedTotal: 0,
    networkAccessRateLimitedTotal: 0,
    assetLifecycleScannedTotal: 0,
    assetLifecyclePrunedTotal: 0,
    assetLifecycleFailedTotal: 0,
    assetPresignIntentIssuedTotal: 0,
    assetPresignIntentRejectedTotal: 0,
    assetPresignBucketRejectedTotal: 0,
    assetPresignStagingMissingTotal: 0,
    assetPresignCommitRejectedTotal: 0,
    assetPresignAbortedTotal: 0,
    assetPresignAbortReclaimFailedTotal: 0,
  };
}
