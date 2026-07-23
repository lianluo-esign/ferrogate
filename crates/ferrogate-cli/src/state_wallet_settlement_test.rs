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
            cloudflare_ai_gateway: None,
            enabled: true,
        }],
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

fn overdraft_wallet(state: &AppState, tenant_id: &str, balance_credits: i64) {
    block_on(state.upsert_wallet(StoredWallet {
        id: tenant_id.into(),
        tenant_id: tenant_id.into(),
        balance_credits,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
}

fn overdraft_tenant(tenant_id: &str) -> ferrogate_core::TenantContext {
    ferrogate_core::TenantContext {
        organization_id: Some(tenant_id.into()),
        ..ferrogate_core::TenantContext::default()
    }
}

#[test]
fn wallet_reservation_bounds_concurrent_spend_to_the_funded_balance() {
    // A 100-credit wallet where every request is estimated at 50 credits, so
    // at most two requests can be in flight at once. Before this reservation
    // existed the only pre-request wallet gate was a bare `balance > 0` read
    // that took no hold, so N concurrent requests from one tenant all passed
    // it, all dispatched upstream, and all settled afterward -- driving the
    // balance arbitrarily negative and billing the operator for tokens the
    // attacker never funded. The reservation serializes the in-flight total
    // under one lock so it can never exceed the funded balance.
    let state = AppState::new(Config::default());
    overdraft_wallet(&state, "tenant-overdraft", 100);
    let tenant = overdraft_tenant("tenant-overdraft");

    // Eight concurrent requests race for the same wallet.
    let held: Arc<Mutex<Vec<WalletCreditReservation>>> = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let state = state.clone();
            let tenant = tenant.clone();
            let held = Arc::clone(&held);
            std::thread::spawn(move || {
                match block_on(state.try_reserve_wallet_credits(&tenant, 50)).unwrap() {
                    WalletReservationOutcome::Reserved(reservation) => {
                        assert_eq!(reservation.credits(), 50);
                        held.lock().unwrap().push(reservation);
                        true
                    }
                    WalletReservationOutcome::Insufficient => false,
                    WalletReservationOutcome::NotApplicable => {
                        panic!(
                            "a funded wallet must not report NotApplicable for a priced estimate"
                        )
                    }
                }
            })
        })
        .collect();
    let admitted = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(
        admitted, 2,
        "a 100-credit balance must admit exactly two 50-credit holds, never more"
    );

    // The gate now reports the wallet exhausted even though no debit has
    // landed yet: the two outstanding holds have consumed all 100 credits.
    assert!(
        state.wallet_balance_exhausted(&tenant).unwrap(),
        "outstanding reservations must make the pre-request gate fail closed"
    );

    // Only the two admitted requests settle. Total settled = 100 credits, so
    // the balance floors at exactly 0 -- never the -300 that eight
    // unreserved settlements (8 * 50 against a 100 balance) would produce.
    for index in 0..admitted {
        block_on(state.debit_wallet_for_settled_cost(
            &tenant,
            50.0 / ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD,
            &format!("settle-overdraft-{index}"),
        ))
        .unwrap();
    }
    assert_eq!(
        block_on(state.get_wallet("tenant-overdraft"))
            .unwrap()
            .unwrap()
            .balance_credits,
        0,
        "settling only the admitted requests must not drive the wallet negative"
    );

    drop(held);
}

#[test]
fn wallet_reservation_hold_is_released_when_the_request_errors_or_cancels() {
    let state = AppState::new(Config::default());
    overdraft_wallet(&state, "tenant-release", 100);
    let tenant = overdraft_tenant("tenant-release");
    let reserve = || block_on(state.try_reserve_wallet_credits(&tenant, 50)).unwrap();

    let first = match reserve() {
        WalletReservationOutcome::Reserved(reservation) => reservation,
        _ => panic!("the first 50-credit hold must be admitted"),
    };
    let _second = match reserve() {
        WalletReservationOutcome::Reserved(reservation) => reservation,
        _ => panic!("the second 50-credit hold must be admitted"),
    };
    // The balance is now fully held: a third request cannot be covered.
    assert!(matches!(reserve(), WalletReservationOutcome::Insufficient));
    assert!(state.wallet_balance_exhausted(&tenant).unwrap());

    // The first request errors/cancels before it ever settles. Dropping its
    // RAII guard must return the held credits rather than leak capacity.
    drop(first);
    assert!(
        !state.wallet_balance_exhausted(&tenant).unwrap(),
        "dropping an in-flight hold must free its credits back to the gate"
    );
    assert!(
        matches!(reserve(), WalletReservationOutcome::Reserved(_)),
        "the freed capacity must admit a fresh request"
    );
}

#[test]
fn wallet_reservation_is_a_noop_for_tenants_without_a_wallet_or_price() {
    // Opt-in, purely additive: a tenant with no wallet row, and a request on
    // an unpriced route, must never be blocked by the reservation gate.
    let state = AppState::new(Config::default());
    let tenant = overdraft_tenant("tenant-no-wallet");
    assert!(matches!(
        block_on(state.try_reserve_wallet_credits(&tenant, 50)).unwrap(),
        WalletReservationOutcome::NotApplicable
    ));

    overdraft_wallet(&state, "tenant-unpriced", 100);
    let priced_tenant = overdraft_tenant("tenant-unpriced");
    // A zero estimate (an unpriced route) reserves nothing and never blocks.
    assert!(matches!(
        block_on(state.try_reserve_wallet_credits(&priced_tenant, 0)).unwrap(),
        WalletReservationOutcome::NotApplicable
    ));
    assert!(!state.wallet_balance_exhausted(&priced_tenant).unwrap());
}

#[test]
fn estimated_request_credits_match_the_eventual_settlement_debit() {
    // The reservation must be sized in the same credit unit the settlement
    // debit uses, so a hold neither over- nor under-reserves versus the real
    // charge. 500_000 prompt tokens at $1/1M input (zero output) = $0.50 =
    // 500_000 credits, both when estimated up front and when debited.
    let route = ModelRoute::with_routing("openai", "gpt-4o-mini", Some(1.0), Some(0.0), 0, 1);
    let usage = BillingTokenUsage::new(500_000, 0, 500_000);
    let estimated = estimated_request_credits(&route, &usage);
    assert_eq!(estimated, 500_000);

    let state = AppState::new(Config::default());
    overdraft_wallet(&state, "tenant-parity", 1_000_000);
    let tenant = overdraft_tenant("tenant-parity");
    let debit = block_on(state.debit_wallet_for_settled_cost(&tenant, 0.5, "settle-parity"))
        .expect("a funded wallet must settle a real cost");
    assert_eq!(
        -debit.delta_credits, estimated,
        "the up-front reservation and the settled debit must agree in credits"
    );

    // An unpriced route reserves nothing, exactly as it produces no debit.
    let unpriced = ModelRoute::new("openai", "gpt-4o-mini");
    assert_eq!(estimated_request_credits(&unpriced, &usage), 0);
}
