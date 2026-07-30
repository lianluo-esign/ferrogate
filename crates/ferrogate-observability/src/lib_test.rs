// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for observability contracts, kept outside business logic.

use super::*;

#[test]
fn default_observability_config_enables_all_signal_types() {
    let config = ObservabilityConfig::default();

    assert_eq!(config.service_name, "ferrogate");
    assert!(config.traces_enabled);
    assert!(config.metrics_enabled);
    assert!(config.logs_enabled);
}

#[test]
fn span_templates_cover_prd_request_provider_and_metering_hierarchy() {
    let templates = default_span_templates();

    assert_eq!(templates[0].name, "ferrogate.gateway.request");
    assert!(templates.iter().any(
        |template| template.kind == GatewaySpanKind::ProviderDispatch
            && template.fields.contains(&"retryable")
    ));
    assert!(templates
        .iter()
        .any(|template| template.kind == GatewaySpanKind::BillingWrite
            && template.name == "ferrogate.metering.write"
            && template.fields.contains(&"total_tokens")
            && template.fields.contains(&"result")));
}

#[test]
fn prometheus_exporter_is_a_metrics_plugin_boundary() {
    let exporter = ObservabilityExporterConfig::prometheus_metrics("/metrics");
    let pipeline = ObservabilityPipelineConfig::new("ferrogate").with_exporter(exporter.clone());

    assert_eq!(exporter.kind, ObservabilityExporterKind::Prometheus);
    assert_eq!(exporter.signals, vec![ObservabilitySignal::Metric]);
    assert_eq!(exporter.path.as_deref(), Some("/metrics"));
    assert!(pipeline.validate().is_ok());
}

#[test]
fn rejects_prometheus_log_plugin_misconfiguration() {
    let exporter = ObservabilityExporterConfig::new(
        "prometheus-logs",
        ObservabilityExporterKind::Prometheus,
        vec![ObservabilitySignal::Log],
    );

    assert_eq!(
        exporter.validate(),
        Err(ObservabilityConfigError::UnsupportedSignal {
            exporter: "prometheus-logs".to_string(),
            kind: ObservabilityExporterKind::Prometheus,
            signal: ObservabilitySignal::Log,
        })
    );
}

#[test]
fn allows_multiple_exporters_for_different_signal_types() {
    let pipeline = ObservabilityPipelineConfig::new("ferrogate")
        .with_exporter(ObservabilityExporterConfig::stdout_logs())
        .with_exporter(ObservabilityExporterConfig::prometheus_metrics("/metrics"))
        .with_exporter(ObservabilityExporterConfig::otlp(
            "http://localhost:4318/v1/traces",
        ));

    assert!(pipeline.validate().is_ok());
    assert_eq!(pipeline.exporters.len(), 3);
}

#[test]
fn validates_exporter_required_fields() {
    let empty_name = ObservabilityExporterConfig::new(
        " ",
        ObservabilityExporterKind::Stdout,
        vec![ObservabilitySignal::Log],
    );
    let empty_signals =
        ObservabilityExporterConfig::new("empty", ObservabilityExporterKind::Stdout, Vec::new());
    let bad_prometheus_path = ObservabilityExporterConfig::prometheus_metrics("metrics");

    assert_eq!(
        empty_name.validate(),
        Err(ObservabilityConfigError::MissingExporterName)
    );
    assert_eq!(
        empty_signals.validate(),
        Err(ObservabilityConfigError::MissingSignals {
            exporter: "empty".to_string(),
        })
    );
    assert_eq!(
        bad_prometheus_path.validate(),
        Err(ObservabilityConfigError::InvalidHttpPath {
            exporter: "prometheus".to_string(),
            path: "metrics".to_string(),
        })
    );
}

#[test]
fn renders_prometheus_text_for_gateway_metrics_snapshot() {
    let snapshot = GatewayMetricsSnapshot {
        service_name: "ferrogate".into(),
        request_log_total: 2,
        request_error_total: 1,
        request_status_totals: vec![
            RequestStatusMetric {
                status_code: 200,
                count: 1,
            },
            RequestStatusMetric {
                status_code: 429,
                count: 1,
            },
        ],
        cache_hits_total: 1,
        cache_misses_total: 1,
        semantic_cache_hits_total: 1,
        guardrail_match_total: 2,
        guardrail_denial_total: 1,
        guardrail_redaction_total: 1,
        guardrail_detector_error_total: 3,
        guardrail_evaluation_total: 5,
        guardrail_evaluation_fail_total: 2,
        guardrail_evaluation_error_total: 1,
        guardrail_evaluation_shadow_total: 2,
        guardrail_evidence_persistence_failure_total: 1,
        guardrail_policy_cas_conflict_total: 2,
        billing_event_total: 1,
        billing_report_enqueue_failure_total: 1,
        tool_call_total: 2,
        tool_latency_ms_total: 17,
        mcp_identity_resolution_total: 5,
        mcp_identity_failure_total: 1,
        mcp_identity_refresh_total: 2,
        mcp_identity_revocation_total: 1,
        mcp_refresh_response_deadline_total: 3,
        mcp_refresh_storage_cancellation_total: 2,
        mcp_refresh_storage_outcome_unknown_total: 4,
        mcp_refresh_late_reconciliation_total: 1,
        mcp_identity_error_audit_deadline_total: 4,
        postgres_pool_acquire_total: 7,
        postgres_pool_acquire_timeout_total: 2,
        postgres_pool_acquire_wait_micros_total: 1_500_000,
        evidence_writer_enqueued_total: 9,
        evidence_writer_written_total: 8,
        evidence_writer_dropped_total: 1,
        token_totals: TokenMetricTotals {
            prompt_tokens: 3,
            completion_tokens: 5,
            total_tokens: 8,
        },
        model_provider_totals: vec![ModelProviderMetricTotal {
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            requests: 1,
            total_tokens: 8,
        }],
        mcp_method_totals: vec![McpMethodMetricTotal {
            method: "tools/call".into(),
            name: "srv-search".into(),
            requests: 3,
        }],
        network_access_denied_total: 3,
        network_access_rate_limited_total: 4,
        asset_lifecycle_scanned_total: 7,
        asset_lifecycle_pruned_total: 5,
        asset_lifecycle_failed_total: 1,
        self_hosted_dispatch_reclaim_scanned_total: 9,
        self_hosted_dispatch_reclaim_reclaimed_total: 6,
        self_hosted_dispatch_reclaim_failed_total: 2,
        asset_presign_intent_issued_total: 11,
        asset_presign_intent_rejected_total: 2,
        asset_presign_bucket_rejected_total: 3,
        asset_presign_staging_missing_total: 4,
        asset_presign_commit_rejected_total: 5,
        asset_presign_aborted_total: 6,
        asset_presign_abort_reclaim_failed_total: 2,
    };

    let text = render_prometheus_text(&snapshot);

    assert!(text.contains("# TYPE ferrogate_request_logs_total counter"));
    assert!(text.contains("ferrogate_request_errors_total 1"));
    assert!(text.contains("ferrogate_ai_cache_requests_total{status=\"hit\"} 1"));
    assert!(text.contains("ferrogate_ai_cache_requests_total{status=\"miss\"} 1"));
    assert!(text.contains("ferrogate_ai_cache_requests_total{status=\"semantic_hit\"} 1"));
    assert!(text.contains("ferrogate_guardrail_matches_total 2"));
    assert!(text.contains("ferrogate_guardrail_denials_total 1"));
    assert!(text.contains("ferrogate_guardrail_redactions_total 1"));
    assert!(text.contains("ferrogate_guardrail_detector_errors_total 3"));
    assert!(text.contains("ferrogate_guardrail_evaluations_total{verdict=\"pass\"} 2"));
    assert!(text.contains("ferrogate_guardrail_shadow_evaluations_total 2"));
    assert!(text.contains("ferrogate_guardrail_evidence_persistence_failures_total 1"));
    assert!(text.contains("ferrogate_guardrail_policy_cas_conflicts_total 2"));
    assert!(text.contains("ferrogate_network_access_denied_total 3"));
    assert!(text.contains("ferrogate_network_access_rate_limited_total 4"));
    assert!(text.contains("ferrogate_asset_lifecycle_scanned_total 7"));
    assert!(text.contains("ferrogate_self_hosted_dispatch_reclaim_scanned_total 9"));
    assert!(text.contains("ferrogate_self_hosted_dispatch_reclaim_reclaimed_total 6"));
    assert!(text.contains("ferrogate_self_hosted_dispatch_reclaim_failed_total 2"));
    assert!(text.contains("ferrogate_asset_lifecycle_pruned_total 5"));
    assert!(text.contains("ferrogate_asset_lifecycle_failed_total 1"));
    // #368: the three presign rejection classes must stay separately readable,
    // and `staging_missing` must NOT be folded into the bucket stage.
    assert!(text.contains("ferrogate_asset_presign_intents_issued_total 11"));
    assert!(text.contains("ferrogate_asset_presign_rejected_total{stage=\"intent\"} 2"));
    assert!(text.contains("ferrogate_asset_presign_rejected_total{stage=\"bucket\"} 3"));
    assert!(text.contains("ferrogate_asset_presign_rejected_total{stage=\"commit\"} 5"));
    assert!(text.contains("ferrogate_asset_presign_staging_missing_total 4"));
    assert!(text.contains("ferrogate_asset_presign_aborted_total 6"));
    // #368: a reclamation the bucket refused is its own alertable series, not
    // an increment folded into `aborted_total` -- the abort-path twin of
    // `asset_lifecycle_failed_total`. Without it a stuck bucket looks like a
    // healthy stream of aborts.
    assert!(text.contains("ferrogate_asset_presign_abort_reclaim_failed_total 2"));
    assert!(text.contains("ferrogate_billing_report_enqueue_failures_total 1"));
    assert!(text.contains("ferrogate_mcp_tool_calls_total 2"));
    assert!(text.contains("ferrogate_mcp_tool_latency_ms_total 17"));
    assert!(text.contains("ferrogate_mcp_identity_resolutions_total 5"));
    assert!(text.contains("ferrogate_mcp_identity_failures_total 1"));
    assert!(text.contains("ferrogate_mcp_identity_refreshes_total 2"));
    assert!(text.contains("ferrogate_mcp_identity_revocations_total 1"));
    assert!(text.contains("ferrogate_mcp_refresh_response_deadlines_total 3"));
    assert!(text.contains("ferrogate_mcp_refresh_storage_cancellations_total 2"));
    assert!(text.contains("ferrogate_mcp_refresh_storage_outcome_unknown_total 4"));
    assert!(text.contains("ferrogate_postgres_pool_acquires_total 7"));
    assert!(text.contains("ferrogate_postgres_pool_acquire_timeouts_total 2"));
    assert!(text.contains("ferrogate_postgres_pool_acquire_wait_seconds_total 1.5"));
    assert!(text.contains("ferrogate_evidence_writer_enqueued_total 9"));
    assert!(text.contains("ferrogate_evidence_writer_written_total 8"));
    assert!(text.contains("ferrogate_evidence_writer_dropped_total 1"));
    assert!(text.contains("ferrogate_mcp_refresh_late_reconciliations_total 1"));
    assert!(text.contains("ferrogate_mcp_identity_error_audit_deadlines_total 4"));
    assert!(text.contains("ferrogate_tokens_total{type=\"total\"} 8"));
    assert!(text.contains(
        "ferrogate_model_provider_requests_total{logical_model=\"fast-chat\",provider=\"openai\"} 1"
    ));
    assert!(
        text.contains("ferrogate_mcp_requests_total{method=\"tools/call\",name=\"srv-search\"} 3")
    );
}

#[test]
fn builds_otlp_http_json_requests_for_metrics_traces_and_logs() {
    let snapshot = GatewayMetricsSnapshot {
        service_name: "ferrogate".into(),
        billing_event_total: 1,
        guardrail_policy_cas_conflict_total: 2,
        token_totals: TokenMetricTotals {
            prompt_tokens: 3,
            completion_tokens: 5,
            total_tokens: 8,
        },
        ..GatewayMetricsSnapshot::default()
    };

    let metrics = build_otlp_metrics_request("http://collector:4318", &snapshot).unwrap();
    assert_eq!(metrics.method, "POST");
    assert_eq!(metrics.url, "http://collector:4318/v1/metrics");
    assert_eq!(metrics.content_type, "application/json");
    let metrics_body: serde_json::Value = serde_json::from_slice(&metrics.body).unwrap();
    assert_eq!(
        metrics_body["resourceMetrics"][0]["resource"]["attributes"][0]["value"]["stringValue"],
        "ferrogate"
    );
    assert!(
        metrics_body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|metric| metric["name"] == "ferrogate.tokens")
    );
    assert!(
        metrics_body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|metric| metric["name"] == "ferrogate.guardrail.policy_cas_conflicts")
    );

    let traces = build_otlp_traces_request(
        "http://collector:4318/",
        "ferrogate",
        &[OtlpSpanRecord {
            trace_id: "00000000000000000000000000000001".into(),
            span_id: "0000000000000001".into(),
            parent_span_id: None,
            name: "ferrogate.gateway.request".into(),
            start_time_unix_nano: 1,
            end_time_unix_nano: 2,
            attributes: vec![OtlpAttribute::new("request_id", "fg-1")],
        }],
    )
    .unwrap();
    assert_eq!(traces.url, "http://collector:4318/v1/traces");
    let traces_body: serde_json::Value = serde_json::from_slice(&traces.body).unwrap();
    assert_eq!(
        traces_body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "ferrogate.gateway.request"
    );

    let logs = build_otlp_logs_request(
        "http://collector:4318",
        "ferrogate",
        &[OtlpLogRecord {
            trace_id: Some("00000000000000000000000000000001".into()),
            span_id: Some("0000000000000001".into()),
            severity_text: "INFO".into(),
            body: "request completed".into(),
            time_unix_nano: 3,
            attributes: vec![OtlpAttribute::new("status_code", "200")],
        }],
    )
    .unwrap();
    assert_eq!(logs.url, "http://collector:4318/v1/logs");
    let logs_body: serde_json::Value = serde_json::from_slice(&logs.body).unwrap();
    assert_eq!(
        logs_body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["body"]["stringValue"],
        "request completed"
    );
}

/// #522: the unjoinable-action exporter renders one counter line per
/// (tenant, surface) with those two labels and nothing else — the absent action
/// id is never a label (issue #500 low-cardinality rule). Reverting the
/// `escape_label_value`-wrapped format string to drop either label, or changing
/// the metric name, reds this.
#[test]
fn unjoinable_actions_render_low_cardinality_tenant_surface_counter() {
    let totals = vec![
        UnjoinableActionMetricTotal {
            tenant: "tenant-a".to_string(),
            surface: "mcp".to_string(),
            requests: 2,
        },
        UnjoinableActionMetricTotal {
            tenant: "tenant-b".to_string(),
            surface: "asset".to_string(),
            requests: 5,
        },
    ];

    let text = render_unjoinable_actions_text(&totals);

    assert!(text.contains("# TYPE ferrogate_unjoinable_actions_total counter"));
    assert!(
        text.contains("ferrogate_unjoinable_actions_total{tenant=\"tenant-a\",surface=\"mcp\"} 2")
    );
    assert!(text
        .contains("ferrogate_unjoinable_actions_total{tenant=\"tenant-b\",surface=\"asset\"} 5"));
    // The declared/absent id must never become a label.
    assert!(!text.contains("agent_run_id"));
    assert!(!text.contains("run-"));
}

#[test]
fn rejects_invalid_otlp_http_endpoint() {
    let snapshot = GatewayMetricsSnapshot::default();

    assert_eq!(
        build_otlp_metrics_request("collector:4318", &snapshot).unwrap_err(),
        ObservabilityConfigError::InvalidEndpoint {
            exporter: "otlp".to_string(),
            endpoint: "collector:4318".to_string(),
        }
    );
}
