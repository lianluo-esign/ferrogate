// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Prometheus text-format rendering of the gateway metrics snapshot.

use crate::metrics::{GatewayMetricsSnapshot, UnjoinableActionMetricTotal};

pub fn render_prometheus_text(snapshot: &GatewayMetricsSnapshot) -> String {
    let mut output = String::new();
    let service = escape_label_value(&snapshot.service_name);

    push_help(
        &mut output,
        "ferrogate_info",
        "FerroGate process metadata.",
        "gauge",
    );
    output.push_str(&format!("ferrogate_info{{service=\"{service}\"}} 1\n"));

    push_help(
        &mut output,
        "ferrogate_request_logs_total",
        "Total structured request logs recorded by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_request_logs_total {}\n",
        snapshot.request_log_total
    ));

    push_help(
        &mut output,
        "ferrogate_request_errors_total",
        "Total structured request logs with errors or 4xx/5xx statuses.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_request_errors_total {}\n",
        snapshot.request_error_total
    ));

    push_help(
        &mut output,
        "ferrogate_request_status_total",
        "Structured request logs grouped by HTTP status code.",
        "counter",
    );
    for status in &snapshot.request_status_totals {
        output.push_str(&format!(
            "ferrogate_request_status_total{{status_code=\"{}\"}} {}\n",
            status.status_code, status.count
        ));
    }

    push_help(
        &mut output,
        "ferrogate_billing_events_total",
        "Total token metering events recorded by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_billing_events_total {}\n",
        snapshot.billing_event_total
    ));

    push_help(
        &mut output,
        "ferrogate_billing_report_enqueue_failures_total",
        "Total failures durably enqueueing a settled usage event for delivery to the billing service (issue #151).",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_billing_report_enqueue_failures_total {}\n",
        snapshot.billing_report_enqueue_failure_total
    ));

    push_help(
        &mut output,
        "ferrogate_mcp_tool_calls_total",
        "Total MCP tool calls executed by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_tool_calls_total {}\n",
        snapshot.tool_call_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_tool_latency_ms_total",
        "Total MCP tool execution latency in milliseconds.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_tool_latency_ms_total {}\n",
        snapshot.tool_latency_ms_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_resolutions_total",
        "Total per-request MCP identity resolution attempts.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_resolutions_total {}\n",
        snapshot.mcp_identity_resolution_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_failures_total",
        "Total MCP identity resolution attempts rejected before dispatch.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_failures_total {}\n",
        snapshot.mcp_identity_failure_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_refreshes_total",
        "Total successful MCP OAuth credential refreshes.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_refreshes_total {}\n",
        snapshot.mcp_identity_refresh_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_revocations_total",
        "Total locally enforced MCP identity revocations.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_revocations_total {}\n",
        snapshot.mcp_identity_revocation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_response_deadlines_total",
        "Total MCP refresh storage operations that crossed the caller response deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_response_deadlines_total {}\n",
        snapshot.mcp_refresh_response_deadline_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_storage_cancellations_total",
        "Total MCP refresh storage operations fenced before commit.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_storage_cancellations_total {}\n",
        snapshot.mcp_refresh_storage_cancellation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_storage_outcome_unknown_total",
        "Total MCP refresh storage operations whose final outcome could not be proven in time.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_storage_outcome_unknown_total {}\n",
        snapshot.mcp_refresh_storage_outcome_unknown_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_late_reconciliations_total",
        "Total MCP refresh storage outcomes reconciled after the response deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_late_reconciliations_total {}\n",
        snapshot.mcp_refresh_late_reconciliation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_error_audit_deadlines_total",
        "Total MCP identity error audits fenced before they could delay the original response.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_error_audit_deadlines_total {}\n",
        snapshot.mcp_identity_error_audit_deadline_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquires_total",
        "Total async PostgreSQL pool acquisition attempts.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquires_total {}\n",
        snapshot.postgres_pool_acquire_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquire_timeouts_total",
        "Total async PostgreSQL pool acquisition attempts that reached their Rust-side deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquire_timeouts_total {}\n",
        snapshot.postgres_pool_acquire_timeout_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquire_wait_seconds_total",
        "Cumulative time spent waiting for async PostgreSQL pool acquisition.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquire_wait_seconds_total {}\n",
        snapshot.postgres_pool_acquire_wait_micros_total as f64 / 1_000_000.0
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_enqueued_total",
        "Evidence writes (request logs, audit events, agent-run rows) accepted into the bounded background writer queue.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_enqueued_total {}\n",
        snapshot.evidence_writer_enqueued_total
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_written_total",
        "Evidence writes the background writer finished persisting.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_written_total {}\n",
        snapshot.evidence_writer_written_total
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_dropped_total",
        "Evidence writes dropped after the writer queue stayed full past the bounded enqueue timeout.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_dropped_total {}\n",
        snapshot.evidence_writer_dropped_total
    ));

    push_help(
        &mut output,
        "ferrogate_ai_cache_requests_total",
        "AI response cache lookups grouped by cache status.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"hit\"}} {}\n",
        snapshot.cache_hits_total
    ));
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"miss\"}} {}\n",
        snapshot.cache_misses_total
    ));
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"semantic_hit\"}} {}\n",
        snapshot.semantic_cache_hits_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_matches_total",
        "Total configured guardrail rule matches.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_matches_total {}\n",
        snapshot.guardrail_match_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_denials_total",
        "Total guardrail matches that blocked a request or response.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_denials_total {}\n",
        snapshot.guardrail_denial_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_redactions_total",
        "Total guardrail matches that redacted response content.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_redactions_total {}\n",
        snapshot.guardrail_redaction_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_detector_errors_total",
        "Total external guardrail detector evaluation errors.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_detector_errors_total {}\n",
        snapshot.guardrail_detector_error_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_evaluations_total",
        "Guardrail policy evaluations grouped by bounded verdict class.",
        "counter",
    );
    let pass_total = snapshot
        .guardrail_evaluation_total
        .saturating_sub(snapshot.guardrail_evaluation_fail_total)
        .saturating_sub(snapshot.guardrail_evaluation_error_total);
    for (verdict, count) in [
        ("pass", pass_total),
        ("fail", snapshot.guardrail_evaluation_fail_total),
        ("error", snapshot.guardrail_evaluation_error_total),
    ] {
        output.push_str(&format!(
            "ferrogate_guardrail_evaluations_total{{verdict=\"{verdict}\"}} {count}\n"
        ));
    }
    push_help(
        &mut output,
        "ferrogate_guardrail_shadow_evaluations_total",
        "Guardrail evaluations that were shadow-only or not enforced.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_shadow_evaluations_total {}\n",
        snapshot.guardrail_evaluation_shadow_total
    ));
    push_help(
        &mut output,
        "ferrogate_guardrail_evidence_persistence_failures_total",
        "Failures persisting sanitized Guardrail evaluation evidence.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_evidence_persistence_failures_total {}\n",
        snapshot.guardrail_evidence_persistence_failure_total
    ));
    push_help(
        &mut output,
        "ferrogate_guardrail_policy_cas_conflicts_total",
        "Guardrail policy binding writes rejected by optimistic generation comparison.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_policy_cas_conflicts_total {}\n",
        snapshot.guardrail_policy_cas_conflict_total
    ));

    push_help(
        &mut output,
        "ferrogate_network_access_denied_total",
        "Total requests rejected pre-authentication for not matching the configured IP allowlist.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_network_access_denied_total {}\n",
        snapshot.network_access_denied_total
    ));

    push_help(
        &mut output,
        "ferrogate_network_access_rate_limited_total",
        "Total requests rejected pre-authentication for exceeding the unauthenticated per-source-IP rate limit.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_network_access_rate_limited_total {}\n",
        snapshot.network_access_rate_limited_total
    ));

    // #263: asset lifecycle sweeper (version retention + unreferenced-blob GC).
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_scanned_total",
        "Total asset versions scanned by the lifecycle retention/GC sweeper.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_scanned_total {}\n",
        snapshot.asset_lifecycle_scanned_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_pruned_total",
        "Total asset versions and unreferenced blobs pruned/collected by the lifecycle sweeper.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_pruned_total {}\n",
        snapshot.asset_lifecycle_pruned_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_failed_total",
        "Total lifecycle prune/GC delete operations that failed.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_failed_total {}\n",
        snapshot.asset_lifecycle_failed_total
    ));

    // #368: presigned staging upload lifecycle. `stage` separates the three
    // rejection classes the acceptance criteria require to be distinguishable;
    // orphan GC stays on `ferrogate_asset_lifecycle_pruned_total` above.
    // `staging_missing` is intentionally a stage of its own rather than being
    // merged into `bucket` -- see the metrics.rs field docs for why absence at
    // commit time is not proof of a bucket refusal.
    push_help(
        &mut output,
        "ferrogate_asset_presign_intents_issued_total",
        "Total presigned staging upload intents issued with a size/checksum-bound PUT URL.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_presign_intents_issued_total {}\n",
        snapshot.asset_presign_intent_issued_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_presign_rejected_total",
        "Total presigned staging uploads rejected, by the stage that rejected them; stage=bucket is caller-asserted at abort with a negative gateway check, not an independent observation.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_presign_rejected_total{{stage=\"intent\"}} {}\n",
        snapshot.asset_presign_intent_rejected_total
    ));
    output.push_str(&format!(
        "ferrogate_asset_presign_rejected_total{{stage=\"bucket\"}} {}\n",
        snapshot.asset_presign_bucket_rejected_total
    ));
    output.push_str(&format!(
        "ferrogate_asset_presign_rejected_total{{stage=\"commit\"}} {}\n",
        snapshot.asset_presign_commit_rejected_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_presign_staging_missing_total",
        "Total presigned commits that found no staged object (never attempted, expired URL, or bucket-refused without an abort report).",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_presign_staging_missing_total {}\n",
        snapshot.asset_presign_staging_missing_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_presign_aborted_total",
        "Total presigned upload intents explicitly released through the abort surface (the release, not the reclamation).",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_presign_aborted_total {}\n",
        snapshot.asset_presign_aborted_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_presign_abort_reclaim_failed_total",
        "Total aborts that found staged bytes and failed to delete them, leaving them to the lifecycle GC.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_presign_abort_reclaim_failed_total {}\n",
        snapshot.asset_presign_abort_reclaim_failed_total
    ));

    // #354 box 5: the on-chain settlement reconciler's signal. `outcome` is a
    // closed, code-defined label set (no tenant, no attempt id, no merchant
    // value), so the cardinality is fixed at eight series regardless of traffic.
    // `overpaid` is a BREAKOUT of `settled`, so summing every outcome
    // double-counts overpayments -- sum the seven disjoint ones to recover
    // `scanned`.
    let x402 = &snapshot.x402_reconcile_totals;
    push_help(
        &mut output,
        "ferrogate_x402_reconcile_attempts_total",
        "Total post-submission x402 payment attempts driven by the settlement reconciler, by outcome; outcome=overpaid is a breakout of outcome=settled, not a disjoint class.",
        "counter",
    );
    for (outcome, value) in [
        ("settled", x402.settled),
        ("overpaid", x402.overpaid),
        ("failed", x402.failed),
        ("pending", x402.pending),
        ("mismatch", x402.mismatch),
        ("unresolved", x402.unresolved),
        ("skipped", x402.skipped),
        ("errored", x402.errored),
    ] {
        output.push_str(&format!(
            "ferrogate_x402_reconcile_attempts_total{{outcome=\"{outcome}\"}} {value}\n"
        ));
    }
    push_help(
        &mut output,
        "ferrogate_x402_reconcile_scanned_total",
        "Total post-submission x402 payment attempts the reconciler fetched and drove.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_x402_reconcile_scanned_total {}\n",
        x402.scanned
    ));
    push_help(
        &mut output,
        "ferrogate_x402_oldest_unresolved_hold_age_seconds",
        "Age of the oldest wallet hold the last reconcile tick scanned and left unresolved, measured from submission; a LOWER BOUND on the true oldest, because a tick scans one bounded page.",
        "gauge",
    );
    output.push_str(&format!(
        "ferrogate_x402_oldest_unresolved_hold_age_seconds {}\n",
        x402.oldest_unresolved_hold_age_seconds
    ));
    // LIVENESS, not outcomes. Four fixed, disjoint label values, so the
    // cardinality is constant. Without this series the outcome counters above
    // are unfalsifiable: a reconciler that is off, unbound, or failing to fetch
    // its candidate set every tick publishes the same frozen zeros as one that
    // is running perfectly with nothing to do. Alert on the absence of a
    // rising `completed`, and on any rate of `list_failed` / `unbound_rpc`.
    push_help(
        &mut output,
        "ferrogate_x402_reconcile_ticks_total",
        "Total x402 settlement reconciler ticks by how the tick ended; result=completed drove a candidate batch, the others did not run one (result=list_failed could not fetch candidates, result=disabled is switched off by config, result=unbound_rpc has no on-chain RPC bound).",
        "counter",
    );
    for (result, value) in [
        ("completed", x402.ticks_completed),
        ("list_failed", x402.ticks_list_failed),
        ("disabled", x402.ticks_disabled),
        ("unbound_rpc", x402.ticks_unbound_rpc),
    ] {
        output.push_str(&format!(
            "ferrogate_x402_reconcile_ticks_total{{result=\"{result}\"}} {value}\n"
        ));
    }

    push_help(
        &mut output,
        "ferrogate_tokens_total",
        "Total AI provider token usage recorded by metering events.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"prompt\"}} {}\n",
        snapshot.token_totals.prompt_tokens
    ));
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"completion\"}} {}\n",
        snapshot.token_totals.completion_tokens
    ));
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"total\"}} {}\n",
        snapshot.token_totals.total_tokens
    ));

    push_help(
        &mut output,
        "ferrogate_model_provider_requests_total",
        "Billing events grouped by logical model and provider.",
        "counter",
    );
    for total in &snapshot.model_provider_totals {
        let logical_model = escape_label_value(&total.logical_model);
        let provider = escape_label_value(&total.provider);
        output.push_str(&format!(
            "ferrogate_model_provider_requests_total{{logical_model=\"{logical_model}\",provider=\"{provider}\"}} {}\n",
            total.requests
        ));
    }

    push_help(
        &mut output,
        "ferrogate_model_provider_tokens_total",
        "Billing event token usage grouped by logical model and provider.",
        "counter",
    );
    for total in &snapshot.model_provider_totals {
        let logical_model = escape_label_value(&total.logical_model);
        let provider = escape_label_value(&total.provider);
        output.push_str(&format!(
            "ferrogate_model_provider_tokens_total{{logical_model=\"{logical_model}\",provider=\"{provider}\"}} {}\n",
            total.total_tokens
        ));
    }

    push_help(
        &mut output,
        "ferrogate_mcp_requests_total",
        "MCP ingress requests grouped by Mcp-Method routing header and target name.",
        "counter",
    );
    for total in &snapshot.mcp_method_totals {
        let method = escape_label_value(&total.method);
        let name = escape_label_value(&total.name);
        output.push_str(&format!(
            "ferrogate_mcp_requests_total{{method=\"{method}\",name=\"{name}\"}} {}\n",
            total.requests
        ));
    }

    output
}

/// #522: render the unjoinable-action counter as its own Prometheus block.
///
/// Kept out of [`GatewayMetricsSnapshot`] on purpose — it is sourced from a
/// separate accumulator and appended to the `/metrics` body — so the snapshot
/// data model (and the many exporters that construct it exhaustively) stay
/// untouched. Labels are `tenant` and `surface` only; the absent action id is
/// never a label (issue #500 low-cardinality rule).
pub fn render_unjoinable_actions_text(totals: &[UnjoinableActionMetricTotal]) -> String {
    let mut output = String::new();
    push_help(
        &mut output,
        "ferrogate_unjoinable_actions_total",
        "Governed agent actions received without a declared x-ferrogate-agent-run-id, grouped by tenant and ingress surface.",
        "counter",
    );
    for total in totals {
        let tenant = escape_label_value(&total.tenant);
        let surface = escape_label_value(&total.surface);
        output.push_str(&format!(
            "ferrogate_unjoinable_actions_total{{tenant=\"{tenant}\",surface=\"{surface}\"}} {}\n",
            total.requests
        ));
    }
    output
}

fn push_help(output: &mut String, metric: &str, help: &str, kind: &str) {
    output.push_str(&format!("# HELP {metric} {help}\n"));
    output.push_str(&format!("# TYPE {metric} {kind}\n"));
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}
