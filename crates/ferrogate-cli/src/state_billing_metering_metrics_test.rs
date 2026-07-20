// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-12
// description: Provider-attempt-aware billing metrics coverage for issue #213.

use super::*;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

#[test]
fn prometheus_metrics_snapshot_aggregates_request_logs_and_distinct_attempts() {
    let config = Config {
        telemetry: crate::config::TelemetryConfig {
            service_name: "ferrogate-test".into(),
            log_bodies: false,
            otlp_endpoint: None,
            ..crate::config::TelemetryConfig::default()
        },
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            canary: None,
            shadow: None,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: Some(1.0),
            output_price_per_1m: Some(2.0),
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };
    let state = AppState::new(config);
    let request = RequestContext {
        request_id: "fg-test".into(),
        trace_id: Some("trace-test".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        route: Some("openai.chat.completions".into()),
        upstream: Some("openai".into()),
        tenant: ferrogate_core::TenantContext::default(),
    };

    state.record_request_log(StoredRequestLog {
        request_id: "fg-test".into(),
        trace_id: Some("trace-test".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        route: Some("openai.chat.completions".into()),
        provider: Some("openai".into()),
        logical_model: Some("fast-chat".into()),
        provider_model: Some("gpt-4o-mini".into()),
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: None,
        completed_at_unix: None,
        parent_action_fingerprint: None,
    });
    record_attempt(
        &state,
        &request,
        0,
        ProviderUsage {
            prompt_tokens: Some(3),
            completion_tokens: Some(5),
            total_tokens: Some(8),
        },
    );
    record_attempt(
        &state,
        &request,
        1,
        ProviderUsage {
            prompt_tokens: Some(7),
            completion_tokens: Some(11),
            total_tokens: Some(18),
        },
    );

    let snapshot = state.prometheus_metrics_snapshot();

    assert_eq!(snapshot.service_name, "ferrogate-test");
    assert_eq!(snapshot.request_log_total, 1);
    assert_eq!(snapshot.request_status_totals[0].status_code, 200);
    assert_eq!(snapshot.cache_hits_total, 0);
    assert_eq!(snapshot.cache_misses_total, 0);
    assert_eq!(snapshot.billing_event_total, 2);
    assert_eq!(snapshot.token_totals.total_tokens, 26);
    assert_eq!(snapshot.model_provider_totals[0].logical_model, "fast-chat");

    let aggregates = state.usage_aggregates(None);
    assert_eq!(aggregates.len(), 1);
    assert_eq!(aggregates[0].usage.prompt_tokens, 10);
    assert_eq!(aggregates[0].usage.completion_tokens, 16);
    assert_eq!(aggregates[0].usage.total_tokens, 26);
}

fn record_attempt(
    state: &AppState,
    request: &RequestContext,
    attempt_index: u32,
    usage: ProviderUsage,
) {
    block_on(state.record_provider_attempt_billing_event(
        BillingEventDraft {
            request,
            logical_model: "fast-chat",
            provider: "openai",
            provider_model: "gpt-4o-mini",
            status_code: 200,
            latency_ms: None,
            metadata: None,
        },
        &ProviderAttempt::for_request(&request.request_id, attempt_index),
        &usage,
    ))
    .unwrap();
}
