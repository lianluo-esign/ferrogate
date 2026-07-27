// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit coverage for asset egress metering/billing + download-side
// audit + fail-closed egress quota enforcement (issue #262).

use std::collections::HashSet;

use ferrogate_core::TenantContext;
use ferrogate_policy::{EffectiveQuota, QuotaScopeSelector};
use ferrogate_storage::QuotaScopeKind;

fn scope(kind: QuotaScopeKind, id: &str) -> QuotaScopeSelector {
    QuotaScopeSelector {
        kind,
        id: id.to_string(),
    }
}

use super::{asset_egress_quota_denial, record_asset_egress};
use crate::gateway::ProxyContext;
use crate::state::AppState;
use ferrogate_config::Config;
use ferrogate_gateway::auth::AuthContext;

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn priced_state(price_per_gb: Option<f64>) -> AppState {
    let config = Config {
        asset_egress_price_per_gb: price_per_gb,
        ..Config::default()
    };
    AppState::new(config)
}

fn tenant() -> TenantContext {
    TenantContext {
        organization_id: Some("org".into()),
        team_id: None,
        project_id: Some("project".into()),
        workspace_id: None,
        user_id: None,
        api_key_id: Some("key_dev".into()),
    }
}

fn auth_with_quota(quota: EffectiveQuota) -> AuthContext {
    AuthContext {
        api_key_id: Some("key_dev".into()),
        scopes: HashSet::from(["assets.read".to_string()]),
        allowed_models: HashSet::new(),
        denied_models: HashSet::new(),
        allowed_providers: HashSet::new(),
        denied_providers: HashSet::new(),
        region_allowlist: HashSet::new(),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        organization_id: Some("org".into()),
        platform_operator: false,
        team_id: None,
        project_id: Some("project".into()),
        workspace_id: None,
        user_id: None,
        log_bodies: false,
        rbac_subject: None,
        effective_quota: quota,
    }
}

fn proxy_context() -> ProxyContext {
    ProxyContext {
        request_id: "fg-egress-test".into(),
        trace_id: Some("trace-egress".into()),
        traceparent: None,
        tracestate: None,
        tenant_id: Some("org".into()),
        route: None,
        upstream: None,
        upstream_endpoint: None,
        target_uri: None,
        original_host: None,
    }
}

#[test]
fn egress_event_is_metered_with_correct_bytes_and_priced_cost() {
    // $0.09/GB * 2 GB (2e9 bytes) settles to exactly $0.18. (#262)
    let state = priced_state(Some(0.09));
    block_on(state.record_asset_egress_event(
        "fg-egress-1",
        Some("trace-1"),
        &tenant(),
        "static_site",
        "docs",
        "v3",
        2_000_000_000,
    ))
    .unwrap();

    let events = state.billing_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.provider, "asset_egress");
    assert_eq!(event.logical_model, "asset_egress:static_site/docs");
    assert_eq!(event.provider_model, "v3");
    assert_eq!(event.usage.total_tokens, 0, "egress carries no token usage");
    assert_eq!(
        event.metadata.get("asset_egress_bytes").map(String::as_str),
        Some("2000000000")
    );
    assert!(
        (event.cost_usd.unwrap() - 0.18).abs() < 1e-9,
        "2GB @ $0.09/GB must settle to $0.18, got {:?}",
        event.cost_usd
    );
}

#[test]
fn unpriced_egress_is_metered_but_carries_no_cost() {
    // Egress stays metered + auditable even when unpriced -- no fabricated
    // cost, exactly how an unpriced model is metered but not charged. (#262)
    let state = priced_state(None);
    block_on(state.record_asset_egress_event(
        "fg-egress-2",
        None,
        &tenant(),
        "config_file",
        "app",
        "v1",
        1_000_000,
    ))
    .unwrap();
    let events = state.billing_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].cost_usd, None);
}

#[test]
fn egress_charge_debits_a_prepaid_wallet() {
    // #262 acceptance: a download draws down the tenant's prepaid wallet by
    // size x egress rate through the same debit path token usage uses.
    let state = priced_state(Some(0.09));
    block_on(state.upsert_wallet(ferrogate_storage::StoredWallet {
        id: "org".into(),
        tenant_id: "org".into(),
        balance_credits: 1_000_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 0,
        updated_at_unix: 0,
    }))
    .unwrap();
    // 1 GB @ $0.09/GB = $0.09 = 90_000 credits (DEFAULT_CREDITS_PER_USD).
    block_on(state.record_asset_egress_event(
        "fg-egress-3",
        None,
        &tenant(),
        "static_site",
        "site",
        "v1",
        1_000_000_000,
    ))
    .unwrap();
    let events = state.billing_events();
    assert_eq!(events[0].wallet_delta_credits, Some(-90_000));
    let wallet = block_on(state.get_wallet("org")).unwrap().unwrap();
    assert_eq!(wallet.balance_credits, 910_000);
}

#[test]
fn monthly_egress_byte_budget_denies_fail_closed() {
    // #262 acceptance: exceeding the resolved monthly egress budget denies
    // further downloads fail-closed with a distinct error code.
    let state = priced_state(Some(0.09));
    let quota = EffectiveQuota {
        monthly_egress_bytes_budget: Some(1_000),
        monthly_egress_bytes_scope: Some(scope(QuotaScopeKind::Tenant, "org")),
        ..EffectiveQuota::default()
    };
    let auth = auth_with_quota(quota);

    // A 500-byte object fits under the 1000-byte budget.
    assert!(asset_egress_quota_denial(&state, &auth, 500).is_none());

    // Record 800 bytes served this month; a further 500 would exceed 1000.
    state.record_asset_egress_bytes("egress:tenant:org", 800);
    let denial = asset_egress_quota_denial(&state, &auth, 500)
        .expect("500 more bytes over an 800/1000 budget must deny");
    assert_eq!(denial.0, "asset_egress_quota_exceeded");
}

#[test]
fn download_rpm_cap_denies_fail_closed_with_distinct_code() {
    // #262: the per-minute download cap is enforced independently of the byte
    // budget, with its own error code (not the token-side rate_limit_exceeded).
    let state = priced_state(None);
    let quota = EffectiveQuota {
        download_rpm_limit: Some(1),
        download_rpm_limit_scope: Some(scope(QuotaScopeKind::Key, "key_dev")),
        ..EffectiveQuota::default()
    };
    let auth = auth_with_quota(quota);
    // First download consumes the only token in the window.
    assert!(asset_egress_quota_denial(&state, &auth, 10).is_none());
    // Second within the same minute is denied.
    let denial = asset_egress_quota_denial(&state, &auth, 10).expect("second download must deny");
    assert_eq!(denial.0, "asset_download_rate_limit_exceeded");
}

#[test]
fn record_asset_egress_emits_metering_counter_and_pull_audit() {
    // #262: the single pull hook meters, accumulates the monthly counter, and
    // emits a symmetric pull-side audit event queryable by asset target.
    let state = priced_state(Some(0.09));
    let auth = auth_with_quota(EffectiveQuota {
        monthly_egress_bytes_budget: Some(10_000_000),
        monthly_egress_bytes_scope: Some(scope(QuotaScopeKind::Tenant, "org")),
        ..EffectiveQuota::default()
    });
    let ctx = proxy_context();
    block_on(record_asset_egress(
        &state,
        &ctx,
        &auth,
        "skill_bundle",
        "helper",
        "v2",
        4_096,
    ));

    // Metering event recorded.
    let events = state.billing_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].logical_model, "asset_egress:skill_bundle/helper");

    // Monthly egress counter accumulated for the byte-budget gate.
    assert_eq!(state.asset_egress_bytes_used("egress:tenant:org"), 4_096);

    // Pull-side audit event with the asset target + byte count.
    let audit = state.audit_events();
    let pull = audit
        .iter()
        .find(|event| event.action == "asset.pull")
        .expect("a pull audit event must be recorded");
    assert_eq!(pull.target, "org:skill_bundle:helper:v2");
    assert!(pull.message.contains("4096 bytes"));
    assert_eq!(pull.tenant.organization_id.as_deref(), Some("org"));
}
