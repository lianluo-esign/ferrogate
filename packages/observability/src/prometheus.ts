/**
 * Prometheus text-format rendering of the gateway metrics snapshot.
 * Clean-room port of `ferrogate-observability::prometheus`.
 *
 * PORT-TODO(§4.5): in a stateless Worker there is no long-lived process to
 * accumulate `GatewayMetricsSnapshot`; a Hono `GET /metrics` route must feed
 * this renderer from a Durable Object counter or an Analytics Engine SQL read.
 * The renderer itself is a pure snapshot→text function and ports 1:1.
 */
import type {
  GatewayMetricsSnapshot,
  UnjoinableActionMetricTotal,
} from "./metrics.js";

export function renderPrometheusText(snapshot: GatewayMetricsSnapshot): string {
  const out: string[] = [];
  const service = escapeLabelValue(snapshot.serviceName);

  pushHelp(out, "ferrogate_info", "FerroGate process metadata.", "gauge");
  out.push(`ferrogate_info{service="${service}"} 1\n`);

  pushHelp(
    out,
    "ferrogate_request_logs_total",
    "Total structured request logs recorded by FerroGate.",
    "counter",
  );
  out.push(`ferrogate_request_logs_total ${snapshot.requestLogTotal}\n`);

  pushHelp(
    out,
    "ferrogate_request_errors_total",
    "Total structured request logs with errors or 4xx/5xx statuses.",
    "counter",
  );
  out.push(`ferrogate_request_errors_total ${snapshot.requestErrorTotal}\n`);

  pushHelp(
    out,
    "ferrogate_request_status_total",
    "Structured request logs grouped by HTTP status code.",
    "counter",
  );
  for (const status of snapshot.requestStatusTotals) {
    out.push(
      `ferrogate_request_status_total{status_code="${status.statusCode}"} ${status.count}\n`,
    );
  }

  pushHelp(
    out,
    "ferrogate_billing_events_total",
    "Total token metering events recorded by FerroGate.",
    "counter",
  );
  out.push(`ferrogate_billing_events_total ${snapshot.billingEventTotal}\n`);

  pushHelp(
    out,
    "ferrogate_billing_report_enqueue_failures_total",
    "Total failures durably enqueueing a settled usage event for delivery to the billing service (issue #151).",
    "counter",
  );
  out.push(
    `ferrogate_billing_report_enqueue_failures_total ${snapshot.billingReportEnqueueFailureTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_mcp_tool_calls_total",
    "Total MCP tool calls executed by FerroGate.",
    "counter",
  );
  out.push(`ferrogate_mcp_tool_calls_total ${snapshot.toolCallTotal}\n`);
  pushHelp(
    out,
    "ferrogate_mcp_tool_latency_ms_total",
    "Total MCP tool execution latency in milliseconds.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_tool_latency_ms_total ${snapshot.toolLatencyMsTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_identity_resolutions_total",
    "Total per-request MCP identity resolution attempts.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_identity_resolutions_total ${snapshot.mcpIdentityResolutionTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_identity_failures_total",
    "Total MCP identity resolution attempts rejected before dispatch.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_identity_failures_total ${snapshot.mcpIdentityFailureTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_identity_refreshes_total",
    "Total successful MCP OAuth credential refreshes.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_identity_refreshes_total ${snapshot.mcpIdentityRefreshTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_identity_revocations_total",
    "Total locally enforced MCP identity revocations.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_identity_revocations_total ${snapshot.mcpIdentityRevocationTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_refresh_response_deadlines_total",
    "Total MCP refresh storage operations that crossed the caller response deadline.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_refresh_response_deadlines_total ${snapshot.mcpRefreshResponseDeadlineTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_refresh_storage_cancellations_total",
    "Total MCP refresh storage operations fenced before commit.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_refresh_storage_cancellations_total ${snapshot.mcpRefreshStorageCancellationTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_refresh_storage_outcome_unknown_total",
    "Total MCP refresh storage operations whose final outcome could not be proven in time.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_refresh_storage_outcome_unknown_total ${snapshot.mcpRefreshStorageOutcomeUnknownTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_refresh_late_reconciliations_total",
    "Total MCP refresh storage outcomes reconciled after the response deadline.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_refresh_late_reconciliations_total ${snapshot.mcpRefreshLateReconciliationTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_mcp_identity_error_audit_deadlines_total",
    "Total MCP identity error audits fenced before they could delay the original response.",
    "counter",
  );
  out.push(
    `ferrogate_mcp_identity_error_audit_deadlines_total ${snapshot.mcpIdentityErrorAuditDeadlineTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_postgres_pool_acquires_total",
    "Total async PostgreSQL pool acquisition attempts.",
    "counter",
  );
  out.push(
    `ferrogate_postgres_pool_acquires_total ${snapshot.postgresPoolAcquireTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_postgres_pool_acquire_timeouts_total",
    "Total async PostgreSQL pool acquisition attempts that reached their Rust-side deadline.",
    "counter",
  );
  out.push(
    `ferrogate_postgres_pool_acquire_timeouts_total ${snapshot.postgresPoolAcquireTimeoutTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_postgres_pool_acquire_wait_seconds_total",
    "Cumulative time spent waiting for async PostgreSQL pool acquisition.",
    "counter",
  );
  out.push(
    `ferrogate_postgres_pool_acquire_wait_seconds_total ${
      snapshot.postgresPoolAcquireWaitMicrosTotal / 1_000_000.0
    }\n`,
  );
  pushHelp(
    out,
    "ferrogate_evidence_writer_enqueued_total",
    "Evidence writes (request logs, audit events, agent-run rows) accepted into the bounded background writer queue.",
    "counter",
  );
  out.push(
    `ferrogate_evidence_writer_enqueued_total ${snapshot.evidenceWriterEnqueuedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_evidence_writer_written_total",
    "Evidence writes the background writer finished persisting.",
    "counter",
  );
  out.push(
    `ferrogate_evidence_writer_written_total ${snapshot.evidenceWriterWrittenTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_evidence_writer_dropped_total",
    "Evidence writes dropped after the writer queue stayed full past the bounded enqueue timeout.",
    "counter",
  );
  out.push(
    `ferrogate_evidence_writer_dropped_total ${snapshot.evidenceWriterDroppedTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_ai_cache_requests_total",
    "AI response cache lookups grouped by cache status.",
    "counter",
  );
  out.push(
    `ferrogate_ai_cache_requests_total{status="hit"} ${snapshot.cacheHitsTotal}\n`,
  );
  out.push(
    `ferrogate_ai_cache_requests_total{status="miss"} ${snapshot.cacheMissesTotal}\n`,
  );
  out.push(
    `ferrogate_ai_cache_requests_total{status="semantic_hit"} ${snapshot.semanticCacheHitsTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_guardrail_matches_total",
    "Total configured guardrail rule matches.",
    "counter",
  );
  out.push(`ferrogate_guardrail_matches_total ${snapshot.guardrailMatchTotal}\n`);

  pushHelp(
    out,
    "ferrogate_guardrail_denials_total",
    "Total guardrail matches that blocked a request or response.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_denials_total ${snapshot.guardrailDenialTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_guardrail_redactions_total",
    "Total guardrail matches that redacted response content.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_redactions_total ${snapshot.guardrailRedactionTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_guardrail_detector_errors_total",
    "Total external guardrail detector evaluation errors.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_detector_errors_total ${snapshot.guardrailDetectorErrorTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_guardrail_evaluations_total",
    "Guardrail policy evaluations grouped by bounded verdict class.",
    "counter",
  );
  const passTotal = saturatingSub(
    saturatingSub(
      snapshot.guardrailEvaluationTotal,
      snapshot.guardrailEvaluationFailTotal,
    ),
    snapshot.guardrailEvaluationErrorTotal,
  );
  const verdicts: Array<[string, number]> = [
    ["pass", passTotal],
    ["fail", snapshot.guardrailEvaluationFailTotal],
    ["error", snapshot.guardrailEvaluationErrorTotal],
  ];
  for (const [verdict, count] of verdicts) {
    out.push(
      `ferrogate_guardrail_evaluations_total{verdict="${verdict}"} ${count}\n`,
    );
  }
  pushHelp(
    out,
    "ferrogate_guardrail_shadow_evaluations_total",
    "Guardrail evaluations that were shadow-only or not enforced.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_shadow_evaluations_total ${snapshot.guardrailEvaluationShadowTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_guardrail_evidence_persistence_failures_total",
    "Failures persisting sanitized Guardrail evaluation evidence.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_evidence_persistence_failures_total ${snapshot.guardrailEvidencePersistenceFailureTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_guardrail_policy_cas_conflicts_total",
    "Guardrail policy binding writes rejected by optimistic generation comparison.",
    "counter",
  );
  out.push(
    `ferrogate_guardrail_policy_cas_conflicts_total ${snapshot.guardrailPolicyCasConflictTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_network_access_denied_total",
    "Total requests rejected pre-authentication for not matching the configured IP allowlist.",
    "counter",
  );
  out.push(
    `ferrogate_network_access_denied_total ${snapshot.networkAccessDeniedTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_network_access_rate_limited_total",
    "Total requests rejected pre-authentication for exceeding the unauthenticated per-source-IP rate limit.",
    "counter",
  );
  out.push(
    `ferrogate_network_access_rate_limited_total ${snapshot.networkAccessRateLimitedTotal}\n`,
  );

  // #263: asset lifecycle sweeper (version retention + unreferenced-blob GC).
  pushHelp(
    out,
    "ferrogate_asset_lifecycle_scanned_total",
    "Total asset versions scanned by the lifecycle retention/GC sweeper.",
    "counter",
  );
  out.push(
    `ferrogate_asset_lifecycle_scanned_total ${snapshot.assetLifecycleScannedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_lifecycle_pruned_total",
    "Total asset versions and unreferenced blobs pruned/collected by the lifecycle sweeper.",
    "counter",
  );
  out.push(
    `ferrogate_asset_lifecycle_pruned_total ${snapshot.assetLifecyclePrunedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_lifecycle_failed_total",
    "Total lifecycle prune/GC delete operations that failed.",
    "counter",
  );
  out.push(
    `ferrogate_asset_lifecycle_failed_total ${snapshot.assetLifecycleFailedTotal}\n`,
  );

  // #368: presigned staging upload lifecycle. `stage` separates the three
  // rejection classes; `staging_missing` is deliberately its own stage — see
  // metrics.ts field docs for why commit-time absence is not a bucket refusal.
  pushHelp(
    out,
    "ferrogate_asset_presign_intents_issued_total",
    "Total presigned staging upload intents issued with a size/checksum-bound PUT URL.",
    "counter",
  );
  out.push(
    `ferrogate_asset_presign_intents_issued_total ${snapshot.assetPresignIntentIssuedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_presign_rejected_total",
    "Total presigned staging uploads rejected, by the stage that rejected them; stage=bucket is caller-asserted at abort with a negative gateway check, not an independent observation.",
    "counter",
  );
  out.push(
    `ferrogate_asset_presign_rejected_total{stage="intent"} ${snapshot.assetPresignIntentRejectedTotal}\n`,
  );
  out.push(
    `ferrogate_asset_presign_rejected_total{stage="bucket"} ${snapshot.assetPresignBucketRejectedTotal}\n`,
  );
  out.push(
    `ferrogate_asset_presign_rejected_total{stage="commit"} ${snapshot.assetPresignCommitRejectedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_presign_staging_missing_total",
    "Total presigned commits that found no staged object (never attempted, expired URL, or bucket-refused without an abort report).",
    "counter",
  );
  out.push(
    `ferrogate_asset_presign_staging_missing_total ${snapshot.assetPresignStagingMissingTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_presign_aborted_total",
    "Total presigned upload intents explicitly released through the abort surface (the release, not the reclamation).",
    "counter",
  );
  out.push(
    `ferrogate_asset_presign_aborted_total ${snapshot.assetPresignAbortedTotal}\n`,
  );
  pushHelp(
    out,
    "ferrogate_asset_presign_abort_reclaim_failed_total",
    "Total aborts that found staged bytes and failed to delete them, leaving them to the lifecycle GC.",
    "counter",
  );
  out.push(
    `ferrogate_asset_presign_abort_reclaim_failed_total ${snapshot.assetPresignAbortReclaimFailedTotal}\n`,
  );

  pushHelp(
    out,
    "ferrogate_tokens_total",
    "Total AI provider token usage recorded by metering events.",
    "counter",
  );
  out.push(
    `ferrogate_tokens_total{type="prompt"} ${snapshot.tokenTotals.promptTokens}\n`,
  );
  out.push(
    `ferrogate_tokens_total{type="completion"} ${snapshot.tokenTotals.completionTokens}\n`,
  );
  out.push(
    `ferrogate_tokens_total{type="total"} ${snapshot.tokenTotals.totalTokens}\n`,
  );

  pushHelp(
    out,
    "ferrogate_model_provider_requests_total",
    "Billing events grouped by logical model and provider.",
    "counter",
  );
  for (const total of snapshot.modelProviderTotals) {
    const logicalModel = escapeLabelValue(total.logicalModel);
    const provider = escapeLabelValue(total.provider);
    out.push(
      `ferrogate_model_provider_requests_total{logical_model="${logicalModel}",provider="${provider}"} ${total.requests}\n`,
    );
  }

  pushHelp(
    out,
    "ferrogate_model_provider_tokens_total",
    "Billing event token usage grouped by logical model and provider.",
    "counter",
  );
  for (const total of snapshot.modelProviderTotals) {
    const logicalModel = escapeLabelValue(total.logicalModel);
    const provider = escapeLabelValue(total.provider);
    out.push(
      `ferrogate_model_provider_tokens_total{logical_model="${logicalModel}",provider="${provider}"} ${total.totalTokens}\n`,
    );
  }

  pushHelp(
    out,
    "ferrogate_mcp_requests_total",
    "MCP ingress requests grouped by Mcp-Method routing header and target name.",
    "counter",
  );
  for (const total of snapshot.mcpMethodTotals) {
    const method = escapeLabelValue(total.method);
    const name = escapeLabelValue(total.name);
    out.push(
      `ferrogate_mcp_requests_total{method="${method}",name="${name}"} ${total.requests}\n`,
    );
  }

  return out.join("");
}

/**
 * #522: render the unjoinable-action counter as its own Prometheus block, kept
 * out of {@link GatewayMetricsSnapshot} because it is sourced from a separate
 * accumulator. Labels are `tenant` and `surface` only; the absent action id is
 * never a label (issue #500 low-cardinality rule).
 */
export function renderUnjoinableActionsText(
  totals: readonly UnjoinableActionMetricTotal[],
): string {
  const out: string[] = [];
  pushHelp(
    out,
    "ferrogate_unjoinable_actions_total",
    "Governed agent actions received without a declared x-ferrogate-agent-run-id, grouped by tenant and ingress surface.",
    "counter",
  );
  for (const total of totals) {
    const tenant = escapeLabelValue(total.tenant);
    const surface = escapeLabelValue(total.surface);
    out.push(
      `ferrogate_unjoinable_actions_total{tenant="${tenant}",surface="${surface}"} ${total.requests}\n`,
    );
  }
  return out.join("");
}

function pushHelp(
  out: string[],
  metric: string,
  help: string,
  kind: string,
): void {
  out.push(`# HELP ${metric} ${help}\n`);
  out.push(`# TYPE ${metric} ${kind}\n`);
}

function escapeLabelValue(value: string): string {
  return value
    .replaceAll("\\", "\\\\")
    .replaceAll("\n", "\\n")
    .replaceAll('"', '\\"');
}

function saturatingSub(a: number, b: number): number {
  return a > b ? a - b : 0;
}
