// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway metrics snapshot data model: the counter/total structs every
//! exporter renders from.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayMetricsSnapshot {
    pub service_name: String,
    pub request_log_total: u64,
    pub request_error_total: u64,
    pub request_status_totals: Vec<RequestStatusMetric>,
    pub cache_hits_total: u64,
    pub cache_misses_total: u64,
    /// Subset of `cache_hits_total` served by the semantic vector-similarity
    /// layer rather than an exact-match key (issue #273).
    pub semantic_cache_hits_total: u64,
    pub guardrail_match_total: u64,
    pub guardrail_denial_total: u64,
    pub guardrail_redaction_total: u64,
    pub guardrail_detector_error_total: u64,
    pub guardrail_evaluation_total: u64,
    pub guardrail_evaluation_fail_total: u64,
    pub guardrail_evaluation_error_total: u64,
    pub guardrail_evaluation_shadow_total: u64,
    pub guardrail_evidence_persistence_failure_total: u64,
    pub guardrail_policy_cas_conflict_total: u64,
    pub billing_event_total: u64,
    /// Failures durably enqueueing a settled usage event for delivery to the
    /// billing service (issue #151) — distinguishable from successful
    /// enqueues so operators can alert on silently dropped reports.
    pub billing_report_enqueue_failure_total: u64,
    pub tool_call_total: u64,
    pub tool_latency_ms_total: u64,
    pub mcp_identity_resolution_total: u64,
    pub mcp_identity_failure_total: u64,
    pub mcp_identity_refresh_total: u64,
    pub mcp_identity_revocation_total: u64,
    pub mcp_refresh_response_deadline_total: u64,
    pub mcp_refresh_storage_cancellation_total: u64,
    pub mcp_refresh_storage_outcome_unknown_total: u64,
    pub mcp_refresh_late_reconciliation_total: u64,
    pub mcp_identity_error_audit_deadline_total: u64,
    pub postgres_pool_acquire_total: u64,
    pub postgres_pool_acquire_timeout_total: u64,
    pub postgres_pool_acquire_wait_micros_total: u64,
    /// #309 bounded background evidence writer: jobs accepted into the queue.
    pub evidence_writer_enqueued_total: u64,
    /// #309: jobs the writer thread finished persisting (enqueued minus
    /// written = current queue depth).
    pub evidence_writer_written_total: u64,
    /// #309: evidence writes dropped because the queue stayed full past the
    /// bounded enqueue timeout — the alertable overflow-loss signal (billing
    /// events never route through the writer and cannot appear here).
    pub evidence_writer_dropped_total: u64,
    pub token_totals: TokenMetricTotals,
    pub model_provider_totals: Vec<ModelProviderMetricTotal>,
    /// Per-operation MCP ingress counts keyed by the `Mcp-Method`/`Mcp-Name`
    /// routing headers (falling back to the JSON-RPC body), so operators can
    /// route/alert per MCP method and tool without parsing bodies (issue #277).
    pub mcp_method_totals: Vec<McpMethodMetricTotal>,
    /// Requests rejected pre-authentication for not matching a configured
    /// `network_access.ip_allowlist` (issue #166).
    pub network_access_denied_total: u64,
    /// Requests rejected pre-authentication for exceeding
    /// `network_access.unauthenticated_rate_limit_per_minute` (issue #166).
    pub network_access_rate_limited_total: u64,
    /// Asset versions scanned by the lifecycle retention/GC sweeper (issue
    /// #263).
    pub asset_lifecycle_scanned_total: u64,
    /// Asset versions + unreferenced blobs pruned/collected by the lifecycle
    /// sweeper (issue #263). In `dry_run` mode this stays 0 (nothing deleted).
    pub asset_lifecycle_pruned_total: u64,
    /// Lifecycle prune/GC operations that failed (a bucket or registry delete
    /// error), so an operator can alert on a stuck sweeper (issue #263).
    pub asset_lifecycle_failed_total: u64,
    /// `self_hosted_run_dispatches` rows the #545 reclaim sweeper read this
    /// deployment's lifetime. The denominator for the two counters below, and
    /// the signal that the table is growing: nothing else prunes it.
    pub self_hosted_dispatch_reclaim_scanned_total: u64,
    /// Dispatch rows the #545 sweeper actually deleted (locally, durably, or
    /// both). Flat while `scanned` climbs means the sweeper has stopped making
    /// progress -- alert on that ratio.
    pub self_hosted_dispatch_reclaim_reclaimed_total: u64,
    /// Rows a #545 reclaim attempt did not remove anywhere: already gone (a peer
    /// swept the same run concurrently) or the durable delete errored. Retried
    /// next tick either way, so a persistently non-zero value means the durable
    /// delete is failing, not that a peer won a race.
    pub self_hosted_dispatch_reclaim_failed_total: u64,
    /// #368 presigned staging uploads: intents that were authorized and handed
    /// a size/checksum-bound PUT URL. The denominator every rejection class
    /// below is read against.
    pub asset_presign_intent_issued_total: u64,
    /// #368: intents refused by the gateway's own preflight (per-object ceiling
    /// or tenant storage quota) before any URL was issued. Gateway-observed.
    pub asset_presign_intent_rejected_total: u64,
    /// #368: uploads a *client asserted* were refused by the bucket, via the
    /// explicit abort surface, and which the gateway did not contradict (no
    /// object under the server-derived staging key).
    ///
    /// NOT an independent observation, and NOT a security signal on its own.
    /// The gateway is never in the direct PUT's path; the only check applied is
    /// the negative one, and absence conflates never-attempted, expired-URL and
    /// genuinely-refused -- the same ambiguity that keeps commit-time absence
    /// out of this counter and in `asset_presign_staging_missing_total`. Any
    /// caller holding `assets.write` can register an intent, upload nothing,
    /// and abort with `reason=bucket_rejected` to increment this counter at
    /// will. Read it as "clients reporting bucket refusals", alert on it only
    /// against `asset_presign_intent_issued_total`, and corroborate a suspected
    /// attack with bucket access logs, which the gateway cannot see.
    pub asset_presign_bucket_rejected_total: u64,
    /// #368: commits that found no staged object. Deliberately NOT counted as a
    /// bucket rejection: absence conflates never-attempted, expired-URL, and
    /// bucket-refused. Kept as its own alertable class instead of being folded
    /// into `asset_presign_bucket_rejected_total`.
    pub asset_presign_staging_missing_total: u64,
    /// #368: staged objects the gateway itself refused at commit -- size/sha256
    /// mismatch, content policy, trust screening, or quota. Gateway-observed.
    pub asset_presign_commit_rejected_total: u64,
    /// #368: intents explicitly released through the abort surface. Counts the
    /// release, not the reclamation -- an abort whose staging delete the bucket
    /// refused is counted here *and* in
    /// `asset_presign_abort_reclaim_failed_total`.
    pub asset_presign_aborted_total: u64,
    /// #368: aborts that found staged bytes and failed to delete them, so the
    /// promised immediate reclamation did not happen and the lifecycle GC
    /// (`asset_lifecycle_pruned_total`) is the only remaining path. The
    /// abort-surface twin of `asset_lifecycle_failed_total`: a non-zero value
    /// means tenant quota is being held by objects the gateway said it would
    /// free.
    pub asset_presign_abort_reclaim_failed_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestStatusMetric {
    pub status_code: u16,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenMetricTotals {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProviderMetricTotal {
    pub logical_model: String,
    pub provider: String,
    pub requests: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpMethodMetricTotal {
    pub method: String,
    /// Operation target (tool name for `tools/call`); empty for methods that
    /// carry no name.
    pub name: String,
    pub requests: u64,
}

/// #522: governed agent actions that reached a gateway surface without a
/// declared action id (`x-ferrogate-agent-run-id`), so the gateway cannot join
/// them into a correlation chain. Kept deliberately low-cardinality: the only
/// labels are the authenticated `tenant` and the ingress `surface` (`mcp`,
/// `asset`) — never the (absent) id and never any client-supplied value — so an
/// unbounded id space can never blow up the metric (issue #500).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnjoinableActionMetricTotal {
    /// Authenticated tenant key the action was attributed to (never a
    /// client-declared value).
    pub tenant: String,
    /// Ingress surface that observed the missing id (`mcp`, `asset`).
    pub surface: String,
    pub requests: u64,
}
