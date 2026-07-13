use std::collections::BTreeMap;

use ferrogate_billing::{BillingEvent, BillingUsageSource, ProviderAttempt, TokenUsage};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    QuotaScopeKind, RuntimeStorageRepositories, StorageError, StorageProviderKind, StoredWallet,
};

fn repositories() -> RuntimeStorageRepositories {
    RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 10, 10)
}

fn billing_event() -> BillingEvent {
    BillingEvent {
        request_id: "request-original".into(),
        trace_id: Some("trace-original".into()),
        provider_attempt: ProviderAttempt {
            provider_attempt_id: "attempt-stable".into(),
            provider_attempt_index: 0,
        },
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("tenant-idempotency".into()),
            ..TenantContext::default()
        },
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: TokenUsage::new(3, 5, 8),
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_783_036_800),
        cost_usd: Some(0.25),
        latency_ms: Some(20),
        metadata: BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

#[test]
fn memory_billing_replay_does_not_increment_aggregates_or_rollups() {
    let repositories = repositories();
    let event = billing_event();
    assert!(repositories.append_billing_event(event.clone()).unwrap());
    assert!(!repositories.append_billing_event(event).unwrap());

    let aggregate = repositories.usage_aggregates().pop().unwrap();
    assert_eq!(aggregate.usage.total_tokens, 8);
    let rollup = repositories
        .get_usage_monthly_rollup(QuotaScopeKind::Tenant, "tenant-idempotency", "2026-07")
        .unwrap()
        .unwrap();
    assert_eq!(rollup.request_count, 1);
    assert_eq!(rollup.total_tokens, 8);
    assert!((rollup.cost_usd - 0.25).abs() < f64::EPSILON);
}

#[test]
fn memory_billing_attempt_key_collision_fails_closed_without_rollup_changes() {
    let repositories = repositories();
    let original = billing_event();
    assert!(repositories.append_billing_event(original.clone()).unwrap());

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
    cost.cost_usd = Some(99.0);
    mutations.push(cost);
    let mut index = original.clone();
    index.provider_attempt.provider_attempt_index += 1;
    mutations.push(index);
    let mut request_id = original.clone();
    request_id.request_id = "request-replayed".into();
    mutations.push(request_id);
    let mut trace_id = original.clone();
    trace_id.trace_id = None;
    mutations.push(trace_id);
    let mut occurred_at = original.clone();
    occurred_at.occurred_at_unix = Some(1_783_036_801);
    mutations.push(occurred_at);
    let mut latency = original.clone();
    latency.latency_ms = Some(21);
    mutations.push(latency);

    for collision in mutations {
        assert!(matches!(
            repositories.append_billing_event(collision),
            Err(StorageError::Conflict(_))
        ));
    }
    assert_eq!(repositories.usage_aggregates()[0].usage.total_tokens, 8);
    let rollup = repositories
        .get_usage_monthly_rollup(QuotaScopeKind::Tenant, "tenant-idempotency", "2026-07")
        .unwrap()
        .unwrap();
    assert_eq!(rollup.request_count, 1);
    assert_eq!(rollup.total_tokens, 8);
    assert!((rollup.cost_usd - 0.25).abs() < f64::EPSILON);
}

#[test]
fn memory_wallet_settlement_replay_returns_first_outcome_and_debits_once() {
    let repositories = repositories();
    repositories
        .upsert_wallet(StoredWallet {
            id: "tenant-idempotency".into(),
            tenant_id: "tenant-idempotency".into(),
            balance_credits: 1_000,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .unwrap();

    let first = repositories
        .settle_wallet_balance("attempt-stable", "tenant-idempotency", -125, 2)
        .unwrap();
    let replay = repositories
        .settle_wallet_balance("attempt-stable", "tenant-idempotency", -125, 99)
        .unwrap();

    assert!(first.newly_applied);
    assert!(!replay.newly_applied);
    assert_eq!(first.settlement, replay.settlement);
    assert_eq!(first.settlement.balance_after_credits, Some(875));
    assert_eq!(
        repositories
            .get_wallet("tenant-idempotency")
            .unwrap()
            .unwrap()
            .balance_credits,
        875
    );

    assert!(matches!(
        repositories.settle_wallet_balance("attempt-stable", "tenant-idempotency", -126, 3),
        Err(StorageError::Conflict(_))
    ));
}

#[test]
fn no_wallet_settlement_is_still_remembered_across_wallet_creation() {
    let repositories = repositories();
    let first = repositories
        .settle_wallet_balance("attempt-before-wallet", "tenant-later", -50, 1)
        .unwrap();
    assert!(first.newly_applied);
    assert_eq!(first.settlement.balance_after_credits, None);

    repositories
        .upsert_wallet(StoredWallet {
            id: "tenant-later".into(),
            tenant_id: "tenant-later".into(),
            balance_credits: 500,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: 2,
            updated_at_unix: 2,
        })
        .unwrap();
    let replay = repositories
        .settle_wallet_balance("attempt-before-wallet", "tenant-later", -50, 3)
        .unwrap();
    assert!(!replay.newly_applied);
    assert_eq!(replay.settlement.balance_after_credits, None);
    assert_eq!(
        repositories
            .get_wallet("tenant-later")
            .unwrap()
            .unwrap()
            .balance_credits,
        500
    );
}
