// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for the billing sink, including private poisoned-lock paths.

use super::*;

fn test_event(request_id: &str) -> BillingEvent {
    BillingEvent {
        request_id: request_id.into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext::default(),
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(1, 1, 2),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: None,
    }
}

fn poison_sink(sink: InMemoryBillingEventSink) {
    let result = std::panic::catch_unwind(move || {
        let _guard = sink.inner.lock().unwrap();
        panic!("poison billing event sink");
    });
    assert!(result.is_err());
}

#[test]
fn estimates_model_cost_from_token_usage() {
    let price = ModelPrice::usd(0.15, 0.60);
    let usage = TokenUsage::new(1_000, 2_000, 3_000);

    let cost = price.estimate(&usage);

    assert_eq!(cost.currency, "USD");
    assert!((cost.input_cost - 0.00015).abs() < f64::EPSILON);
    assert!((cost.output_cost - 0.0012).abs() < f64::EPSILON);
    assert!((cost.total_cost - 0.00135).abs() < f64::EPSILON);
}

#[test]
fn in_memory_sink_records_billing_events() {
    let sink = InMemoryBillingEventSink::default();
    sink.record(BillingEvent {
        request_id: "fg-test".into(),
        trace_id: Some("trace-test".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org".into()),
            team_id: None,
            project_id: Some("project".into()),
            user_id: None,
            api_key_id: Some("key_dev".into()),
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(3, 5, 8),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1),
    })
    .unwrap();

    let events = sink.list();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tenant.organization_id.as_deref(), Some("org"));
    assert_eq!(events[0].usage.total_tokens, 8);
}

#[test]
fn in_memory_sink_enforces_retention_limit() {
    let sink = InMemoryBillingEventSink::with_retention_limit(2);
    for request_id in ["fg-1", "fg-2", "fg-3"] {
        sink.record(BillingEvent {
            request_id: request_id.into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(1, 1, 2),
            usage_source: BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: None,
        })
        .unwrap();
    }

    let events = sink.list();
    assert_eq!(sink.len(), 2);
    assert_eq!(sink.recorded_total(), 3);
    assert_eq!(events[0].request_id, "fg-2");
    assert_eq!(events[1].request_id, "fg-3");
    assert_eq!(sink.list_paginated(1, 1)[0].request_id, "fg-3");
}

#[test]
fn record_reports_poisoned_lock() {
    let sink = InMemoryBillingEventSink::default();
    poison_sink(sink.clone());

    let error = sink.record(test_event("fg-poisoned")).unwrap_err();
    assert_eq!(error.code, "billing_sink_poisoned");
    assert_eq!(error.message, "billing event sink lock poisoned");
}

#[test]
fn set_retention_limit_reports_poisoned_lock() {
    let sink = InMemoryBillingEventSink::default();
    poison_sink(sink.clone());

    let error = sink.set_retention_limit(1).unwrap_err();
    assert_eq!(error.code, "billing_sink_poisoned");
    assert_eq!(error.message, "billing event sink lock poisoned");
}
