// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit coverage for pricing/idempotency in the billing ledger, including
//! source-of-truth precedence (#135) and rate-card divergence detection (#152).

use super::*;
use crate::pricing::{PriceBook, PriceEntry};

fn event(request_id: &str, provider: &str, model: &str) -> BillingEvent {
    BillingEvent {
        request_id: request_id.into(),
        trace_id: Some(format!("trace-{request_id}")),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org".into()),
            api_key_id: Some("key".into()),
            ..TenantContext::default()
        },
        logical_model: "fast-chat".into(),
        provider: provider.into(),
        provider_model: model.into(),
        usage: TokenUsage::new(1_000, 2_000, 0),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: None,
        latency_ms: None,
        metadata: std::collections::BTreeMap::new(),
    }
}

fn book() -> PriceBook {
    PriceBook::new(vec![PriceEntry::new(
        "openai",
        "gpt-5.5",
        ModelPrice::usd(5.0, 15.0),
    )])
}

#[test]
fn charge_prices_usage_and_credits() {
    let entry = charge(&book(), &event("req-1", "openai", "gpt-5.5")).unwrap();
    // input: 1000 * 5 / 1e6 = 0.005 ; output: 2000 * 15 / 1e6 = 0.030
    assert!((entry.cost.input_cost - 0.005).abs() < 1e-9);
    assert!((entry.cost.output_cost - 0.030).abs() < 1e-9);
    assert!((entry.cost.total_cost - 0.035).abs() < 1e-9);
    // default 1e6 credits per usd
    assert!((entry.credits - 35_000.0).abs() < 1e-3);
    // total was 0 -> derived to 3000
    assert_eq!(entry.usage.total_tokens, 3_000);
    assert_eq!(entry.id, "ferrogate:trace-req-1:req-1");
}

#[test]
fn charge_fails_closed_on_missing_price() {
    let error = charge(&book(), &event("req-2", "anthropic", "claude")).unwrap_err();
    assert_eq!(error.code, "price_not_found");
}

#[test]
fn sink_is_idempotent_on_id() {
    let sink = InMemoryLedgerSink::default();
    let entry = charge(&book(), &event("req-3", "openai", "gpt-5.5")).unwrap();
    assert!(sink.record(&entry).unwrap());
    assert!(!sink.record(&entry).unwrap());
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.recorded_total(), 1);
    let totals = sink.totals();
    assert_eq!(totals.entries, 1);
    assert!((totals.total_cost_usd - 0.035).abs() < 1e-9);
}

#[test]
fn sink_lists_and_gets() {
    let sink = InMemoryLedgerSink::default();
    let entry = charge(&book(), &event("req-4", "openai", "gpt-5.5")).unwrap();
    sink.record(&entry).unwrap();
    assert_eq!(
        sink.list(&LedgerListFilter::default(), 0, 10)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(sink.get(&entry.id).unwrap().unwrap().request_id, "req-4");
    assert!(sink.get("missing").unwrap().is_none());
}

#[test]
fn charge_honors_gateway_settled_cost_over_pricebook() {
    // Gateway already settled $0.01; the PriceBook would compute $0.035.
    let mut e = event("req-5", "openai", "gpt-5.5");
    e.cost_usd = Some(0.01);
    let entry = charge(&book(), &e).unwrap();
    assert_eq!(entry.cost_source, CostSource::GatewaySettled);
    assert!((entry.cost.total_cost - 0.01).abs() < 1e-9);
    // breakdown scales to the settled total
    assert!((entry.cost.input_cost + entry.cost.output_cost - 0.01).abs() < 1e-9);
    // credits follow the settled total, not the re-price
    assert!((entry.credits - 10_000.0).abs() < 1e-3);
}

#[test]
fn charge_honors_settled_cost_even_without_a_pricebook_entry() {
    // Unknown provider/model: no PriceBook rule, but the gateway settled a
    // cost, so the ledger records it instead of failing closed.
    let mut e = event("req-6", "custom-vendor", "mystery-model");
    e.cost_usd = Some(0.5);
    let entry = charge(&book(), &e).unwrap();
    assert_eq!(entry.cost_source, CostSource::GatewaySettled);
    assert!((entry.cost.total_cost - 0.5).abs() < 1e-9);
}

#[test]
fn charge_reconciles_missing_completion_split_before_pricing() {
    // Provider reported prompt + total but omitted the completion split.
    let mut e = event("req-7", "openai", "gpt-5.5");
    e.usage = TokenUsage::new(1_000, 0, 3_000);
    let entry = charge(&book(), &e).unwrap();
    // completion derived as 3000 - 1000 = 2000, so output is billed
    assert_eq!(entry.usage.completion_tokens, 2_000);
    assert!((entry.cost.output_cost - 0.030).abs() < 1e-9);
    assert!((entry.cost.total_cost - 0.035).abs() < 1e-9);
}

#[test]
fn charge_honors_gateway_cost_even_when_it_diverges_from_pricebook() {
    // book() prices openai/gpt-5.5 at 0.035 for this usage; the gateway
    // settled a wildly different figure. #135 says the gateway wins; #152
    // only adds a log, it must not change the outcome.
    let mut e = event("req-8", "openai", "gpt-5.5");
    e.cost_usd = Some(1.0);
    let entry = charge(&book(), &e).unwrap();
    assert_eq!(entry.cost_source, CostSource::GatewaySettled);
    assert!((entry.cost.total_cost - 1.0).abs() < 1e-9);
}

#[test]
fn cost_diverges_flags_beyond_relative_tolerance() {
    assert!(cost_diverges(1.0, 0.035));
    assert!(!cost_diverges(0.035, 0.035));
    // within 5%
    assert!(!cost_diverges(0.0360, 0.035));
    // just beyond 5%
    assert!(cost_diverges(0.037, 0.035));
}

#[test]
fn cost_diverges_ignores_near_zero_noise() {
    // Both effectively zero: relative % would be huge, but the absolute
    // floor suppresses the noise.
    assert!(!cost_diverges(0.000_001, 0.000_002));
}
