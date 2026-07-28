// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for canary route promotion + shadow budget/metering
// state (issue #276).

use super::*;

use crate::model_routing::ModelRouteExclusionReason;
use ferrogate_config::{CanaryRoute, Model, Provider};
use ferrogate_providers::ModelCapability;

fn provider(name: &str, region: Option<&str>, enabled: bool) -> Provider {
    Provider {
        region: region.map(str::to_string),
        aws_access_key_id: None,
        aws_secret_access_key_env: None,
        aws_session_token_env: None,
        gcp_project_id: None,
        gcp_access_token_env: None,
        name: name.into(),
        kind: "openai".into(),
        base_url: format!("http://127.0.0.1:10001/{name}"),
        api_key_env: None,
        secret_ref: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        cloudflare_ai_gateway: None,
        enabled,
    }
}

fn model_with_canary(canary: Option<CanaryRoute>) -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "primary".into(),
        provider_model: "gpt-4o-mini".into(),
        routing_strategy: RoutingStrategy::Priority,
        canary,
        shadow: None,
        fallbacks: vec![],
        visible_organization_ids: vec![],
        visible_project_ids: vec![],
        capabilities: vec![],
        context_window: None,
        input_price_per_1m: Some(1.0),
        output_price_per_1m: Some(1.0),
        enabled: true,
        cache_enabled: None,
    }
}

fn canary_route(percent: u8, enabled: bool) -> CanaryRoute {
    CanaryRoute {
        provider: "canary".into(),
        provider_model: "gpt-4o".into(),
        capabilities: vec![],
        context_window: None,
        percent,
        input_price_per_1m: Some(2.0),
        output_price_per_1m: Some(2.0),
        enabled,
    }
}

fn state_with(
    canary: Option<CanaryRoute>,
    canary_region: Option<&str>,
    canary_enabled: bool,
) -> AppState {
    let config = Config {
        providers: vec![
            provider("primary", None, true),
            provider("canary", canary_region, canary_enabled),
        ],
        models: vec![model_with_canary(canary)],
        ..Config::default()
    };
    AppState::new(config)
}

fn candidate_routes(state: &AppState) -> ModelRoutingDecision {
    let resolved = state.resolve_model("fast-chat").unwrap();
    state.candidate_model_routes(
        &resolved,
        &ModelRouteRequirements::default(),
        None,
        &HashSet::new(),
    )
}

#[test]
fn canary_absent_leaves_routes_unchanged() {
    let state = state_with(None, None, true);
    let mut routes = candidate_routes(&state);
    let before = routes.clone();
    state.apply_canary_route("fast-chat", "api-key-1", &HashSet::new(), &mut routes);
    assert_eq!(
        routes, before,
        "no canary configured must not change routing"
    );
}

#[test]
fn canary_at_full_percent_leads_and_keeps_primary_as_fallback() {
    let state = state_with(Some(canary_route(100, true)), None, true);
    let mut routes = candidate_routes(&state);
    state.apply_canary_route("fast-chat", "any-key", &HashSet::new(), &mut routes);
    let providers = routes
        .iter()
        .map(|r| r.provider.as_str())
        .collect::<Vec<_>>();
    assert_eq!(providers, ["canary", "primary"]);
    // Canary carries its own price (used for governance/billing parity).
    assert_eq!(routes[0].input_price_per_1m, Some(2.0));
}

#[test]
fn incompatible_canary_is_excluded_before_it_can_lead() {
    let mut model = model_with_canary(Some(canary_route(100, true)));
    model.capabilities = vec![ModelCapability::Chat, ModelCapability::Tools];
    let state = AppState::new(Config {
        providers: vec![
            provider("primary", None, true),
            provider("canary", None, true),
        ],
        models: vec![model],
        ..Config::default()
    });
    let resolved = state.resolve_model("fast-chat").unwrap();
    let mut requirements = ModelRouteRequirements::default();
    requirements.require(ModelCapability::Tools);
    let mut decision =
        state.candidate_model_routes(&resolved, &requirements, None, &HashSet::new());

    state.apply_canary_route(
        "fast-chat",
        "always-selected",
        &HashSet::new(),
        &mut decision,
    );

    assert_eq!(decision.eligible_routes.len(), 1);
    assert_eq!(decision.eligible_routes[0].provider, "primary");
    assert_eq!(decision.exclusions.len(), 1);
    assert_eq!(decision.exclusions[0].candidate.provider, "canary");
    assert_eq!(
        decision.exclusions[0].reason,
        ModelRouteExclusionReason::MissingCapability(ModelCapability::Tools)
    );
    assert_eq!(decision.selection_reason.code(), "priority_order");
}

#[test]
fn canary_at_zero_percent_never_selects() {
    let state = state_with(Some(canary_route(0, true)), None, true);
    let mut routes = candidate_routes(&state);
    state.apply_canary_route("fast-chat", "any-key", &HashSet::new(), &mut routes);
    let providers = routes
        .iter()
        .map(|r| r.provider.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        providers,
        ["primary"],
        "0% canary must never route to canary"
    );
}

#[test]
fn canary_disabled_flag_is_ignored() {
    let state = state_with(Some(canary_route(100, false)), None, true);
    let mut routes = candidate_routes(&state);
    state.apply_canary_route("fast-chat", "any-key", &HashSet::new(), &mut routes);
    let providers = routes
        .iter()
        .map(|r| r.provider.as_str())
        .collect::<Vec<_>>();
    assert_eq!(providers, ["primary"]);
}

#[test]
fn canary_ten_percent_split_is_deterministic_and_within_tolerance() {
    let state = state_with(Some(canary_route(10, true)), None, true);
    let total = 5_000;
    let canaried = (0..total)
        .filter(|index| {
            let mut routes = candidate_routes(&state);
            state.apply_canary_route(
                "fast-chat",
                &format!("key-{index}"),
                &HashSet::new(),
                &mut routes,
            );
            routes[0].provider == "canary"
        })
        .count();
    let ratio = canaried as f64 / total as f64;
    assert!(
        (ratio - 0.10).abs() < 0.02,
        "canary ratio {ratio} not within tolerance of 0.10"
    );
    // Deterministic: the same key yields the same decision every time.
    let decide = |key: &str| {
        let mut routes = candidate_routes(&state);
        state.apply_canary_route("fast-chat", key, &HashSet::new(), &mut routes);
        routes[0].provider.clone()
    };
    assert_eq!(decide("stable-key"), decide("stable-key"));
}

#[test]
fn canary_skipped_when_provider_disabled() {
    // Fail safe: a disabled canary provider must not be inserted (dispatch
    // would hard-fail on it), so canary-bucket traffic still serves primary.
    let state = state_with(Some(canary_route(100, true)), None, false);
    let mut routes = candidate_routes(&state);
    state.apply_canary_route("fast-chat", "any-key", &HashSet::new(), &mut routes);
    let providers = routes
        .iter()
        .map(|r| r.provider.as_str())
        .collect::<Vec<_>>();
    assert_eq!(providers, ["primary"]);
}

#[test]
fn canary_respects_region_allowlist_fail_closed() {
    // Canary provider is in eu-west-1; a tenant restricted to us-east-1 must
    // not reach it.
    let state = state_with(Some(canary_route(100, true)), Some("eu-west-1"), true);
    let mut allowlist = HashSet::new();
    allowlist.insert("us-east-1".to_string());
    let mut routes =
        ModelRoutingDecision::new(ModelRouteRequirements::default(), RoutingStrategy::Priority);
    routes.eligible_routes.push(
        ModelRoute::with_routing("primary", "gpt-4o-mini", Some(1.0), Some(1.0), 0, 1)
            .with_region(Some("us-east-1".into())),
    );
    state.apply_canary_route("fast-chat", "any-key", &allowlist, &mut routes);
    let providers = routes
        .iter()
        .map(|r| r.provider.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        providers,
        ["primary"],
        "region-restricted tenant must skip out-of-region canary"
    );
}

#[test]
fn canary_allowed_when_region_matches_allowlist() {
    let state = state_with(Some(canary_route(100, true)), Some("us-east-1"), true);
    let mut allowlist = HashSet::new();
    allowlist.insert("us-east-1".to_string());
    let mut routes =
        ModelRoutingDecision::new(ModelRouteRequirements::default(), RoutingStrategy::Priority);
    routes.eligible_routes.push(
        ModelRoute::with_routing("primary", "gpt-4o-mini", Some(1.0), Some(1.0), 0, 1)
            .with_region(Some("us-east-1".into())),
    );
    state.apply_canary_route("fast-chat", "any-key", &allowlist, &mut routes);
    assert_eq!(routes[0].provider, "canary");
    assert_eq!(routes[0].region.as_deref(), Some("us-east-1"));
}

#[test]
fn shadow_budget_and_metering_counters_track_state() {
    let state = state_with(None, None, true);
    assert_eq!(state.shadow_metrics(), (0, 0));
    assert!(state.shadow_budget_try_consume("fast-chat", 1));
    assert!(
        !state.shadow_budget_try_consume("fast-chat", 1),
        "cap of 1 refuses the second"
    );
    state.record_shadow_dispatch();
    state.record_shadow_dispatch_failure();
    assert_eq!(state.shadow_metrics(), (1, 1));
}
