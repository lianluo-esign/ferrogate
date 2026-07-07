// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Scenario + property coverage for token metering and cost estimation (#105).

use ferrogate_billing::{
    BillingEvent, BillingEventSink, BillingUsageSource, InMemoryBillingEventSink, ModelPrice,
    TokenUsage,
};
use ferrogate_core::TenantContext;
use proptest::prelude::*;

fn event(request_id: &str) -> BillingEvent {
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
        cost_usd: None,
        latency_ms: None,
        metadata: std::collections::BTreeMap::new(),
    }
}

#[test]
fn estimate_missing_total_fills_only_when_zero() {
    // total==0 is treated as "not reported by provider" -> derive it.
    let derived = TokenUsage::new(10, 20, 0).estimate_missing_total();
    assert_eq!(derived.total_tokens, 30);
    // A provider-reported total is preserved, even if it disagrees with the sum.
    let preserved = TokenUsage::new(10, 20, 99).estimate_missing_total();
    assert_eq!(preserved.total_tokens, 99);
}

#[test]
fn zero_usage_costs_nothing() {
    let cost = ModelPrice::usd(1.0, 2.0).estimate(&TokenUsage::new(0, 0, 0));
    assert_eq!(cost.input_cost, 0.0);
    assert_eq!(cost.output_cost, 0.0);
    assert_eq!(cost.total_cost, 0.0);
    assert_eq!(cost.currency, "USD");
}

#[test]
fn billing_usage_source_wire_strings() {
    assert_eq!(BillingUsageSource::ProviderUsage.as_str(), "provider_usage");
    assert_eq!(
        BillingUsageSource::GatewayEstimate.as_str(),
        "gateway_estimate"
    );
    assert_eq!(
        BillingUsageSource::default(),
        BillingUsageSource::ProviderUsage
    );
}

#[test]
fn sink_is_empty_and_len_track_records() {
    let sink = InMemoryBillingEventSink::default();
    assert!(sink.is_empty());
    assert_eq!(sink.len(), 0);
    sink.record(event("fg-1")).unwrap();
    assert!(!sink.is_empty());
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.recorded_total(), 1);
}

#[test]
fn set_retention_limit_evicts_existing_events_immediately() {
    let sink = InMemoryBillingEventSink::default();
    for id in ["fg-1", "fg-2", "fg-3", "fg-4"] {
        sink.record(event(id)).unwrap();
    }
    assert_eq!(sink.len(), 4);

    // Tightening the retention limit must evict oldest events right away.
    sink.set_retention_limit(2).unwrap();
    let events = sink.list();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].request_id, "fg-3");
    assert_eq!(events[1].request_id, "fg-4");
    // recorded_total is a lifetime counter and is not reduced by eviction.
    assert_eq!(sink.recorded_total(), 4);
}

#[test]
fn pagination_offset_and_limit_bound_results() {
    let sink = InMemoryBillingEventSink::default();
    for id in ["fg-1", "fg-2", "fg-3"] {
        sink.record(event(id)).unwrap();
    }
    assert_eq!(sink.list_paginated(0, 2).len(), 2);
    assert_eq!(sink.list_paginated(2, 10)[0].request_id, "fg-3");
    // Offset past the end yields nothing rather than panicking.
    assert!(sink.list_paginated(99, 10).is_empty());
    assert!(sink.list_paginated(0, 0).is_empty());
}

proptest! {
    // Invariant: total cost equals input + output cost, and no cost is negative.
    #[test]
    fn cost_is_additive_and_non_negative(
        prompt in 0u64..2_000_000,
        completion in 0u64..2_000_000,
        input_price in 0.0f64..1000.0,
        output_price in 0.0f64..1000.0,
    ) {
        let price = ModelPrice::usd(input_price, output_price);
        let cost = price.estimate(&TokenUsage::new(prompt, completion, 0));
        prop_assert!(cost.input_cost >= 0.0);
        prop_assert!(cost.output_cost >= 0.0);
        prop_assert!((cost.total_cost - (cost.input_cost + cost.output_cost)).abs() < 1e-9);
    }

    // Invariant: the sink never retains more than its configured limit, and the
    // lifetime recorded_total always equals the number of records accepted.
    #[test]
    fn retention_never_exceeds_limit(
        limit in 1usize..8,
        records in 0usize..40,
    ) {
        let sink = InMemoryBillingEventSink::with_retention_limit(limit);
        for i in 0..records {
            sink.record(event(&format!("fg-{i}"))).unwrap();
        }
        prop_assert!(sink.len() <= limit);
        prop_assert_eq!(sink.recorded_total(), records as u64);
        prop_assert_eq!(sink.len(), records.min(limit));
    }
}
