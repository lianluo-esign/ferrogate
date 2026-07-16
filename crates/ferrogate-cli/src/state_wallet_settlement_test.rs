use super::*;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

#[test]
fn gateway_wallet_replay_debits_and_audits_once() {
    let state = AppState::new(Config::default());
    block_on(state.upsert_wallet(StoredWallet {
        id: "tenant-wallet-replay".into(),
        tenant_id: "tenant-wallet-replay".into(),
        balance_credits: 1_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("tenant-wallet-replay".into()),
        ..ferrogate_core::TenantContext::default()
    };

    let first = block_on(state.debit_wallet_for_settled_cost(
        &tenant,
        0.000_125,
        "provider-attempt-replay",
    ))
    .unwrap();
    let replay = block_on(state.debit_wallet_for_settled_cost(
        &tenant,
        0.000_125,
        "provider-attempt-replay",
    ))
    .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.delta_credits, -125);
    assert_eq!(first.balance_after_credits, 875);
    assert_eq!(
        block_on(state.get_wallet("tenant-wallet-replay"))
            .unwrap()
            .unwrap()
            .balance_credits,
        875
    );
    let settlements = state
        .wallet_ledger_events("tenant-wallet-replay")
        .into_iter()
        .filter(|event| event.action == "wallet.settle")
        .collect::<Vec<_>>();
    assert_eq!(settlements.len(), 1);
}

#[test]
fn gateway_provider_attempt_collision_fails_closed_without_double_debiting_wallet() {
    let state = AppState::new(Config {
        providers: vec![Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:10001/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: Some(1.0),
            output_price_per_1m: Some(0.0),
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    });
    block_on(state.upsert_wallet(StoredWallet {
        id: "tenant-provider-replay".into(),
        tenant_id: "tenant-provider-replay".into(),
        balance_credits: 1_000_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
    let tenant = ferrogate_core::TenantContext {
        organization_id: Some("tenant-provider-replay".into()),
        ..ferrogate_core::TenantContext::default()
    };
    let original = RequestContext {
        request_id: "request-original".into(),
        trace_id: Some("trace-original".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        route: Some("openai.chat.completions".into()),
        upstream: Some("openai".into()),
        tenant: tenant.clone(),
    };
    let replay = RequestContext {
        request_id: "request-mutated-on-replay".into(),
        trace_id: None,
        ..original.clone()
    };
    let attempt = ProviderAttempt {
        provider_attempt_id: "stable-provider-attempt".into(),
        provider_attempt_index: 7,
    };
    let usage = ProviderUsage {
        prompt_tokens: Some(500_000),
        completion_tokens: Some(0),
        total_tokens: Some(500_000),
    };

    let record = |request: &RequestContext| {
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
            &attempt,
            &usage,
        ))
    };
    record(&original).unwrap();
    let collision = record(&replay).unwrap_err();
    assert_eq!(collision.code, "billing_persistence_failed");
    assert!(collision.message.contains("replayed with different"));

    assert_eq!(state.billing_events().len(), 1);
    assert_eq!(state.usage_aggregates(None)[0].usage.total_tokens, 500_000);
    let rollup = state
        .get_usage_monthly_rollup(
            ferrogate_storage::QuotaScopeKind::Tenant,
            "tenant-provider-replay",
            &state.current_period_month(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(rollup.request_count, 1);
    assert_eq!(rollup.total_tokens, 500_000);
    assert_eq!(
        block_on(state.get_wallet("tenant-provider-replay"))
            .unwrap()
            .unwrap()
            .balance_credits,
        500_000
    );
    assert_eq!(
        state
            .wallet_ledger_events("tenant-provider-replay")
            .into_iter()
            .filter(|event| event.action == "wallet.settle")
            .count(),
        1
    );
}
