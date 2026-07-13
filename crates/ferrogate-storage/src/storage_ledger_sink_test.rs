// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-12
// description: Durable billing-ledger error boundary coverage for issue #213.

use super::{deserialize_billing_event_document, ledger_storage_error, StorageError};

#[test]
fn durable_ledger_collision_preserves_the_http_409_contract() {
    let error = ledger_storage_error(StorageError::Conflict(
        "provider-attempt payload changed".into(),
    ));

    assert_eq!(error.code, "billing_idempotency_conflict");
    assert_eq!(ferrogate_billing::billing_error_http_status(&error), 409);
}

#[test]
fn durable_billing_event_document_preserves_attempt_and_wallet_settlement() {
    let event = ferrogate_billing::BillingEvent {
        request_id: "request-1".into(),
        trace_id: Some("trace-1".into()),
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request("request-1", 1),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("tenant-1".into()),
            ..ferrogate_core::TenantContext::default()
        },
        logical_model: "fallback-chat".into(),
        provider: "backup-openai".into(),
        provider_model: "gpt-4o-mini-fallback".into(),
        usage: ferrogate_billing::TokenUsage::new(4, 6, 10),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.000_016),
        latency_ms: Some(12),
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: Some(-16),
        wallet_balance_after_credits: Some(999_980),
    };
    let document = serde_json::to_string(&event).unwrap();

    let reloaded = deserialize_billing_event_document(&document).unwrap();

    assert_eq!(reloaded, event);
}
