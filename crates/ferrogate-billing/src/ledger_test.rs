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
        provider_attempt: ProviderAttempt::for_request(request_id, 0),
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
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
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
    assert_eq!(
        entry.id,
        "ferrogate:provider-attempt:req-1:provider-attempt:0"
    );
}

#[test]
fn provider_attempt_key_ignores_mutable_trace_and_request_context() {
    let original = event("req-original", "openai", "gpt-5.5");
    let mut replay = original.clone();
    replay.request_id = "req-replayed".into();
    replay.trace_id = None;

    assert_eq!(ledger_entry_id(&original), ledger_entry_id(&replay));
    assert_eq!(
        ledger_entry_id(&replay),
        "ferrogate:provider-attempt:req-original:provider-attempt:0"
    );
}

#[test]
fn charge_fails_closed_on_missing_price() {
    let error = charge(&book(), &event("req-2", "anthropic", "claude")).unwrap_err();
    assert_eq!(error.code, "price_not_found");
}

#[test]
fn provider_attempts_settle_distinctly_and_replay_idempotently() {
    let mut primary = event("req-multi", "openai", "gpt-5.5");
    primary.provider_attempt = ProviderAttempt::for_request("req-multi", 0);
    primary.status_code = 503;
    primary.usage = TokenUsage::new(1_000, 500, 1_500);

    let mut fallback = event("req-multi", "openai", "gpt-5.5");
    fallback.provider_attempt = ProviderAttempt::for_request("req-multi", 1);
    fallback.usage = TokenUsage::new(2_000, 1_000, 3_000);

    let primary_entry = charge(&book(), &primary).unwrap();
    let fallback_entry = charge(&book(), &fallback).unwrap();
    assert_ne!(primary_entry.id, fallback_entry.id);
    assert_eq!(primary_entry.provider_attempt.provider_attempt_index, 0);
    assert_eq!(fallback_entry.provider_attempt.provider_attempt_index, 1);

    let sink = InMemoryLedgerSink::default();
    assert!(sink.record(&primary_entry).unwrap());
    assert!(sink.record(&fallback_entry).unwrap());
    assert!(!sink.record(&primary_entry).unwrap());
    assert!(!sink.record(&fallback_entry).unwrap());

    let totals = sink.totals();
    assert_eq!(totals.entries, 2);
    assert_eq!(totals.total_tokens, 4_500);
    assert!((totals.total_cost_usd - 0.0375).abs() < 1e-9);
}

#[test]
fn provider_attempt_key_collision_fails_closed_for_settlement_mutations() {
    let original = charge(&book(), &event("req-collision", "openai", "gpt-5.5")).unwrap();
    let sink = InMemoryLedgerSink::default();
    assert!(sink.record(&original).unwrap());

    let mut mutations = Vec::new();
    let mut tenant = original.clone();
    tenant.tenant.organization_id = Some("other-tenant".into());
    mutations.push(tenant);
    let mut provider = original.clone();
    provider.provider = "other-provider".into();
    mutations.push(provider);
    let mut usage = original.clone();
    usage.usage.total_tokens += 1;
    mutations.push(usage);
    let mut cost = original.clone();
    cost.cost.total_cost += 1.0;
    mutations.push(cost);
    let mut index = original.clone();
    index.provider_attempt.provider_attempt_index += 1;
    mutations.push(index);

    for collision in mutations {
        let error = sink.record(&collision).unwrap_err();
        assert_eq!(error.code, "billing_idempotency_conflict");
    }
    assert_eq!(sink.len(), 1);
    assert_eq!(sink.get(&original.id).unwrap(), Some(original));
}

#[test]
fn provider_attempt_replay_requires_the_entire_entry_to_match() {
    let original = charge(&book(), &event("req-replay", "openai", "gpt-5.5")).unwrap();
    let sink = InMemoryLedgerSink::default();
    assert!(sink.record(&original).unwrap());
    assert!(!sink.record(&original).unwrap());

    let mut replay = original.clone();
    replay.request_id = "reconstructed-request".into();
    replay.trace_id = None;
    replay.occurred_at_unix = Some(99);

    let error = sink.record(&replay).unwrap_err();
    assert_eq!(error.code, "billing_idempotency_conflict");
    assert_eq!(sink.get(&original.id).unwrap(), Some(original));
}

#[test]
fn legacy_event_without_attempt_fields_preserves_request_idempotency_key() {
    let mut serialized = serde_json::to_value(event("req-legacy", "openai", "gpt-5.5")).unwrap();
    let object = serialized.as_object_mut().unwrap();
    object.remove("provider_attempt_id");
    object.remove("provider_attempt_index");
    let legacy: BillingEvent = serde_json::from_value(serialized).unwrap();

    assert!(legacy.provider_attempt.is_legacy());
    assert_eq!(
        ledger_entry_id(&legacy),
        "ferrogate:trace-req-legacy:req-legacy"
    );
}

#[test]
fn charge_mirrors_wallet_debit_fields_from_the_event_without_recomputing_them() {
    // Issue #169's GET /v1/billing/ledger acceptance criterion: wallet
    // debits show up alongside cost/credit fields. charge() must copy
    // these through verbatim from the event -- it has no way to compute
    // them itself (this crate can't depend on ferrogate-storage, where
    // the actual wallet lives; see BillingEvent::wallet_delta_credits's
    // doc comment).
    let mut source = event("req-wallet-1", "openai", "gpt-5.5");
    source.wallet_delta_credits = Some(-35_000);
    source.wallet_balance_after_credits = Some(465_000);

    let entry = charge(&book(), &source).unwrap();

    assert_eq!(entry.wallet_delta_credits, Some(-35_000));
    assert_eq!(entry.wallet_balance_after_credits, Some(465_000));
}

#[test]
fn charge_leaves_wallet_fields_none_for_a_tenant_without_a_wallet() {
    // The common case (no prepaid wallet adopted): both fields stay None,
    // not some sentinel like 0, so a ledger consumer can distinguish
    // "no wallet" from "debited zero credits".
    let entry = charge(&book(), &event("req-wallet-2", "openai", "gpt-5.5")).unwrap();

    assert_eq!(entry.wallet_delta_credits, None);
    assert_eq!(entry.wallet_balance_after_credits, None);
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
