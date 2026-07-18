// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for routing state, kept outside business logic.

use super::*;

fn api_key_tokens_committed_or_reserved(state: &AppState, api_key_id: &str) -> anyhow::Result<u64> {
    state
        .cluster_counters
        .committed_or_reserved(api_key_id, state.api_key_total_tokens_used(api_key_id))
}

fn test_provider() -> Provider {
    Provider {
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
    }
}

#[test]
fn selects_upstream_endpoints_round_robin() {
    let upstream = Upstream {
        name: "pool".to_string(),
        url: Some("http://127.0.0.1:10001".to_string()),
        urls: vec!["http://127.0.0.1:10002".to_string()],
        enabled: true,
    };
    let config = Config {
        upstreams: vec![upstream.clone()],
        ..Config::default()
    };
    let state = AppState::new(config);

    assert_eq!(
        state.select_upstream_url(&upstream).as_deref(),
        Some("http://127.0.0.1:10001")
    );
    assert_eq!(
        state.select_upstream_url(&upstream).as_deref(),
        Some("http://127.0.0.1:10002")
    );
    assert_eq!(
        state.select_upstream_url(&upstream).as_deref(),
        Some("http://127.0.0.1:10001")
    );
}

#[test]
fn selects_runtime_upstream_endpoints_round_robin() {
    let upstream = Upstream {
        name: "pool".to_string(),
        url: Some("http://127.0.0.1:10001/base".to_string()),
        urls: vec!["https://example.com:9443/api".to_string()],
        enabled: true,
    };
    let config = Config {
        upstreams: vec![upstream],
        ..Config::default()
    };
    let state = AppState::new(config);

    let first = state
        .select_runtime_upstream_endpoint("pool")
        .expect("first endpoint");
    assert_eq!(first.endpoint.scheme, "http");
    assert_eq!(first.endpoint.authority, "127.0.0.1:10001");
    assert_eq!(first.endpoint.base_path, "/base");

    let second = state
        .select_runtime_upstream_endpoint("pool")
        .expect("second endpoint");
    assert_eq!(second.endpoint.scheme, "https");
    assert_eq!(second.endpoint.authority, "example.com:9443");
    assert_eq!(second.endpoint.base_path, "/api");
}

#[test]
fn matches_runtime_route_with_precompiled_headers() {
    let config = Config {
        routes: vec![RouteRule {
            name: "api".into(),
            upstream: "pool".into(),
            hosts: vec!["api.example.com".into()],
            path_prefixes: vec!["/v1".into()],
            match_headers: vec![crate::config::HeaderMatcher {
                name: "x-tier".into(),
                value: "gold".into(),
            }],
            strip_prefix: Some("/v1".into()),
            add_prefix: Some("/proxy".into()),
            request_headers: vec![HeaderMutation {
                name: "x-added".into(),
                value: "enabled".into(),
            }],
            response_headers: vec![HeaderMutation {
                name: "x-response-added".into(),
                value: "done".into(),
            }],
            enabled: true,
        }],
        ..Config::default()
    };
    let state = AppState::new(config);
    let mut headers = HeaderMap::new();
    headers.insert("x-tier", HeaderValue::from_static("gold"));

    let route = state
        .match_runtime_route(Some("api.example.com"), "/v1/chat", &headers)
        .expect("runtime route must match");

    assert_eq!(route.config.name, "api");
    assert_eq!(route.rewrite_path("/v1/chat"), "/proxy/chat");
    assert_eq!(route.request_headers[0].name.as_str(), "x-added");
    assert_eq!(
        route.request_headers[0].value,
        HeaderValue::from_static("enabled")
    );
    assert!(state
        .match_runtime_route(Some("api.example.com"), "/v1/chat", &HeaderMap::new())
        .is_none());
}

#[test]
fn orders_model_fallbacks_with_weighted_rotation_within_priority() {
    let config = Config {
        providers: vec![
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "primary".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "backup-a".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10002/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "backup-b".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10003/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
        ],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "primary".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![
                crate::config::ModelFallback {
                    provider: "backup-a".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    input_price_per_1m: Some(2.0),
                    output_price_per_1m: Some(2.0),
                    priority: Some(10),
                    weight: Some(1),
                    enabled: true,
                },
                crate::config::ModelFallback {
                    provider: "backup-b".into(),
                    provider_model: "gpt-4.1".into(),
                    input_price_per_1m: Some(1.0),
                    output_price_per_1m: Some(1.0),
                    priority: Some(10),
                    weight: Some(2),
                    enabled: true,
                },
            ],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let first = state
        .candidate_model_routes(&resolved, None, &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();
    let second = state
        .candidate_model_routes(&resolved, None, &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();
    let third = state
        .candidate_model_routes(&resolved, None, &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();

    assert_eq!(first, ["primary", "backup-b", "backup-a"]);
    assert_eq!(second, ["primary", "backup-b", "backup-a"]);
    assert_eq!(third, ["primary", "backup-a", "backup-b"]);
}

fn region_test_config(routing_strategy: RoutingStrategy) -> Config {
    Config {
        providers: vec![
            Provider {
                region: Some("eu-west-1".into()),
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "eu-primary".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: Some("us-east-1".into()),
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "us-fallback".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10002/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "no-region-fallback".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10003/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
        ],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "eu-primary".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy,
            fallbacks: vec![
                crate::config::ModelFallback {
                    provider: "us-fallback".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    input_price_per_1m: Some(1.0),
                    output_price_per_1m: Some(1.0),
                    priority: Some(10),
                    weight: Some(1),
                    enabled: true,
                },
                crate::config::ModelFallback {
                    provider: "no-region-fallback".into(),
                    provider_model: "gpt-4.1".into(),
                    input_price_per_1m: Some(0.5),
                    output_price_per_1m: Some(0.5),
                    priority: Some(20),
                    weight: Some(1),
                    enabled: true,
                },
            ],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: Some(2.0),
            output_price_per_1m: Some(2.0),
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    }
}

#[test]
fn candidate_model_routes_is_unrestricted_with_an_empty_region_allowlist() {
    let config = region_test_config(RoutingStrategy::Priority);
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let routes = state.candidate_model_routes(&resolved, None, &HashSet::new());
    assert_eq!(routes.len(), 3, "no region_allowlist means no filtering");
}

#[test]
fn candidate_model_routes_filters_by_region_for_priority_strategy() {
    let config = region_test_config(RoutingStrategy::Priority);
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let region_allowlist = HashSet::from(["eu-west-1".to_string()]);
    let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
    let providers: Vec<_> = routes.iter().map(|route| route.provider.as_str()).collect();
    assert_eq!(
        providers,
        ["eu-primary"],
        "us-fallback (wrong region) and no-region-fallback (undeclared region) must both \
             be excluded once a region_allowlist is set"
    );
}

#[test]
fn candidate_model_routes_region_filter_applies_to_lowest_cost_strategy_too() {
    let config = region_test_config(RoutingStrategy::LowestCost);
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();

    // no-region-fallback is the cheapest route and would normally sort
    // first under LowestCost -- it must still be excluded by the
    // region filter, proving the filter isn't strategy-specific.
    let region_allowlist = HashSet::from(["eu-west-1".to_string()]);
    let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
    let providers: Vec<_> = routes.iter().map(|route| route.provider.as_str()).collect();
    assert_eq!(providers, ["eu-primary"]);
}

#[test]
fn candidate_model_routes_fails_closed_when_no_route_satisfies_the_region_allowlist() {
    let config = region_test_config(RoutingStrategy::Priority);
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let region_allowlist = HashSet::from(["ap-southeast-1".to_string()]);
    let routes = state.candidate_model_routes(&resolved, None, &region_allowlist);
    assert!(
        routes.is_empty(),
        "no configured provider is in ap-southeast-1, so the candidate list must be empty, \
             not silently fall back to an out-of-region provider"
    );
}

#[test]
fn orders_lowest_cost_routes_by_estimated_price() {
    let config = Config {
        providers: vec![
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "primary".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10001/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "backup-a".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10002/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
            Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "backup-b".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:10003/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            },
        ],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "primary".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::LowestCost,
            fallbacks: vec![
                crate::config::ModelFallback {
                    provider: "backup-a".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    input_price_per_1m: Some(2.0),
                    output_price_per_1m: Some(2.0),
                    priority: Some(10),
                    weight: Some(1),
                    enabled: true,
                },
                crate::config::ModelFallback {
                    provider: "backup-b".into(),
                    provider_model: "gpt-4.1".into(),
                    input_price_per_1m: Some(1.0),
                    output_price_per_1m: Some(1.0),
                    priority: Some(10),
                    weight: Some(2),
                    enabled: true,
                },
            ],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: Some(5.0),
            output_price_per_1m: Some(5.0),
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };
    config.validate().unwrap();
    let state = AppState::new(config);
    let resolved = state.resolve_model("fast-chat").unwrap();
    let usage = BillingTokenUsage::new(1_000, 2_000, 3_000);

    let providers = state
        .candidate_model_routes(&resolved, Some(&usage), &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();

    assert_eq!(providers, ["backup-b", "backup-a", "primary"]);
}

#[test]
fn orders_lowest_latency_routes_by_observed_provider_latency() {
    let state = AppState::new(routing_strategy_test_config(
        RoutingStrategy::LowestLatency,
        Some(5.0),
        Some(5.0),
    ));
    record_provider_latency(&state, "primary", 200, 0, 1);
    record_provider_latency(&state, "backup-a", 200, 0, 3);
    record_provider_latency(&state, "backup-b", 200, 0, 2);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let providers = state
        .candidate_model_routes(&resolved, None, &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();

    assert_eq!(providers, ["primary", "backup-b", "backup-a"]);
}

#[test]
fn latency_routing_avoids_unhealthy_observed_provider() {
    let state = AppState::new(routing_strategy_test_config(
        RoutingStrategy::LowestLatency,
        Some(5.0),
        Some(5.0),
    ));
    record_provider_latency(&state, "primary", 500, 0, 1);
    record_provider_latency(&state, "primary", 500, 0, 1);
    record_provider_latency(&state, "primary", 200, 0, 1);
    record_provider_latency(&state, "backup-a", 200, 0, 5);
    record_provider_latency(&state, "backup-b", 200, 0, 10);
    let resolved = state.resolve_model("fast-chat").unwrap();

    let providers = state
        .candidate_model_routes(&resolved, None, &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();

    assert_eq!(providers, ["backup-a", "backup-b", "primary"]);
}

#[test]
fn provider_health_exposes_routing_observations_and_rank_reason() {
    let state = AppState::new(routing_strategy_test_config(
        RoutingStrategy::LowestLatency,
        Some(5.0),
        Some(5.0),
    ));
    record_provider_latency(&state, "primary", 500, 0, 1);
    record_provider_latency(&state, "primary", 500, 0, 1);
    record_provider_latency(&state, "primary", 200, 0, 1);

    let primary = state
        .provider_health_checks()
        .into_iter()
        .find(|check| check.name == "primary")
        .unwrap();

    assert_eq!(primary.routing.observed_requests, 3);
    assert_eq!(primary.routing.successful_requests, 1);
    assert_eq!(primary.routing.failed_requests, 2);
    assert_eq!(primary.routing.average_latency_ms, Some(1_000));
    assert!((primary.routing.failure_rate - 0.666).abs() < 0.001);
    assert_eq!(primary.routing.health_rank, 1);
    assert_eq!(primary.routing.health_reason, "observed_failure_rate");
}

#[test]
fn balanced_routing_combines_cost_latency_and_failures() {
    let state = AppState::new(routing_strategy_test_config(
        RoutingStrategy::Balanced,
        Some(5.0),
        Some(5.0),
    ));
    record_provider_latency(&state, "primary", 200, 0, 1);
    record_provider_latency(&state, "backup-a", 200, 0, 4);
    record_provider_latency(&state, "backup-b", 500, 0, 1);
    record_provider_latency(&state, "backup-b", 500, 0, 1);
    record_provider_latency(&state, "backup-b", 200, 0, 1);
    let resolved = state.resolve_model("fast-chat").unwrap();
    let usage = BillingTokenUsage::new(1_000, 1_000, 2_000);

    let providers = state
        .candidate_model_routes(&resolved, Some(&usage), &HashSet::new())
        .into_iter()
        .map(|route| route.provider)
        .collect::<Vec<_>>();

    assert_eq!(providers, ["backup-a", "primary", "backup-b"]);
}

#[test]
fn provider_circuit_opens_after_configured_failures_and_resets_on_success() {
    let config = Config {
        reliability: crate::config::ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(2),
            provider_circuit_breaker_cooldown_secs: Some(60),
            ..crate::config::ReliabilityConfig::default()
        },
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
        ..Config::default()
    };
    let state = AppState::new(config);

    assert!(state.provider_circuit_allows("openai"));
    state.record_provider_failure("openai");
    assert!(state.provider_circuit_allows("openai"));
    state.record_provider_failure("openai");
    assert!(!state.provider_circuit_allows("openai"));
    state.record_provider_success("openai");
    assert!(state.provider_circuit_allows("openai"));
}

#[test]
fn provider_circuit_is_disabled_without_reliability_config() {
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
        ..Config::default()
    });

    state.record_provider_failure("openai");
    state.record_provider_failure("openai");

    assert!(state.provider_circuit_allows("openai"));
}

#[test]
fn provider_config_prefers_resolved_secret_ref_over_api_key_env() {
    std::env::set_var("FERROGATE_STATE_TEST_SECRET_REF_KEY", "from-secret-ref");
    std::env::set_var("FERROGATE_STATE_TEST_API_KEY_ENV_KEY", "from-api-key-env");
    let mut provider = test_provider();
    provider.api_key_env = Some("FERROGATE_STATE_TEST_API_KEY_ENV_KEY".into());
    provider.secret_ref = Some("env://FERROGATE_STATE_TEST_SECRET_REF_KEY".into());
    let state = AppState::new(Config {
        providers: vec![provider.clone()],
        ..Config::default()
    });

    let config = state.provider_config(&provider);

    assert_eq!(config.api_key.as_deref(), Some("from-secret-ref"));
}

#[test]
fn provider_config_falls_back_to_api_key_env_when_secret_ref_unresolvable() {
    std::env::remove_var("FERROGATE_STATE_TEST_UNSET_SECRET_REF_KEY");
    std::env::set_var(
        "FERROGATE_STATE_TEST_FALLBACK_API_KEY_ENV",
        "fallback-value",
    );
    let mut provider = test_provider();
    provider.api_key_env = Some("FERROGATE_STATE_TEST_FALLBACK_API_KEY_ENV".into());
    provider.secret_ref = Some("env://FERROGATE_STATE_TEST_UNSET_SECRET_REF_KEY".into());
    let state = AppState::new(Config {
        providers: vec![provider.clone()],
        ..Config::default()
    });

    let config = state.provider_config(&provider);

    assert_eq!(config.api_key.as_deref(), Some("fallback-value"));
}

#[test]
fn provider_config_uses_api_key_env_when_no_secret_ref_configured() {
    std::env::set_var("FERROGATE_STATE_TEST_PLAIN_API_KEY_ENV", "plain-value");
    let mut provider = test_provider();
    provider.api_key_env = Some("FERROGATE_STATE_TEST_PLAIN_API_KEY_ENV".into());
    let state = AppState::new(Config {
        providers: vec![provider.clone()],
        ..Config::default()
    });

    let config = state.provider_config(&provider);

    assert_eq!(config.api_key.as_deref(), Some("plain-value"));
}

#[test]
fn provider_health_reports_disabled_provider_without_probe() {
    let state = AppState::new(Config {
        providers: vec![Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "disabled".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:1/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: false,
        }],
        ..Config::default()
    });

    let checks = state.provider_health_checks();

    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].status, "disabled");
    assert!(!checks[0].reachable);
}

#[test]
fn api_key_request_window_rejects_after_configured_limit() {
    let state = AppState::new(Config {
        api_keys: vec![crate::config::ApiKey {
            region_allowlist: Vec::new(),
            id: "key_dev".into(),
            name: "Development key".into(),
            key_env: None,
            key: Some("client-secret".into()),
            key_hash: None,
            enabled: true,
            scopes: vec!["chat.completions".into()],
            allowed_models: vec![],
            denied_models: vec![],
            allowed_providers: vec![],
            denied_providers: vec![],
            organization_id: None,
            team_id: None,
            project_id: None,
            workspace_id: None,
            user_id: None,
            monthly_token_budget: None,
            request_limit_per_minute: Some(1),
            expires_at_unix: None,
            log_bodies: None,
            cache_enabled: None,
        }],
        ..Config::default()
    });

    assert!(state.try_consume_api_key_request("key_dev", 1).unwrap());
    assert!(!state.try_consume_api_key_request("key_dev", 1).unwrap());
}

#[test]
fn api_key_token_reservation_counts_against_budget_until_released() {
    let state = AppState::new(Config::default());

    let reservation = state
        .try_reserve_api_key_tokens("key_dev", 10, 7)
        .unwrap()
        .expect("first reservation should fit");

    assert_eq!(
        api_key_tokens_committed_or_reserved(&state, "key_dev").unwrap(),
        7
    );
    assert!(state
        .try_reserve_api_key_tokens("key_dev", 10, 4)
        .unwrap()
        .is_none());

    drop(reservation);

    assert_eq!(
        api_key_tokens_committed_or_reserved(&state, "key_dev").unwrap(),
        0
    );
    assert!(state
        .try_reserve_api_key_tokens("key_dev", 10, 4)
        .unwrap()
        .is_some());
}

fn routing_strategy_test_config(
    routing_strategy: RoutingStrategy,
    primary_input_price: Option<f64>,
    primary_output_price: Option<f64>,
) -> Config {
    let config = Config {
        providers: vec![
            provider_config("primary", "http://127.0.0.1:10001/v1"),
            provider_config("backup-a", "http://127.0.0.1:10002/v1"),
            provider_config("backup-b", "http://127.0.0.1:10003/v1"),
        ],
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "primary".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy,
            fallbacks: vec![
                crate::config::ModelFallback {
                    provider: "backup-a".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    input_price_per_1m: Some(2.0),
                    output_price_per_1m: Some(2.0),
                    priority: Some(10),
                    weight: Some(1),
                    enabled: true,
                },
                crate::config::ModelFallback {
                    provider: "backup-b".into(),
                    provider_model: "gpt-4.1".into(),
                    input_price_per_1m: Some(1.0),
                    output_price_per_1m: Some(1.0),
                    priority: Some(10),
                    weight: Some(2),
                    enabled: true,
                },
            ],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: primary_input_price,
            output_price_per_1m: primary_output_price,
            enabled: true,
            cache_enabled: None,
        }],
        ..Config::default()
    };
    config.validate().unwrap();
    config
}

fn provider_config(name: &str, base_url: &str) -> Provider {
    Provider {
        region: None,
        aws_access_key_id: None,
        aws_secret_access_key_env: None,
        aws_session_token_env: None,
        gcp_project_id: None,
        gcp_access_token_env: None,
        name: name.into(),
        kind: "openai".into(),
        base_url: base_url.into(),
        api_key_env: None,
        secret_ref: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        enabled: true,
    }
}

fn record_provider_latency(
    state: &AppState,
    provider: &str,
    status_code: u16,
    started_at_unix: u64,
    completed_at_unix: u64,
) {
    state.record_request_log(StoredRequestLog {
        request_id: format!("fg-{provider}-{status_code}-{completed_at_unix}"),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext::default(),
        route: Some("openai.chat.completions".into()),
        provider: Some(provider.into()),
        logical_model: Some("fast-chat".into()),
        provider_model: Some("gpt-4o-mini".into()),
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code,
        error_code: (status_code >= 400).then(|| "provider_error".into()),
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(started_at_unix),
        completed_at_unix: Some(completed_at_unix),
    });
}

/// #233: the AI response cache key must rotate whenever the guardrail policy
/// set changes, so a tightened Response-stage rule immediately misses entries
/// cached under the older (looser) policy instead of serving pre-redaction
/// bodies until TTL expiry.
#[test]
fn ai_response_cache_key_rotates_when_guardrail_policy_changes() {
    fn guardrail_rule(toml: &str) -> GuardrailRule {
        toml::from_str(toml).expect("test guardrail rule must parse")
    }
    let cache_key = |state: &AppState| {
        state
            .ai_response_cache_key(
                "openai.chat.completions",
                &ferrogate_core::TenantContext::default(),
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &serde_json::json!({
                    "model": "fast-chat",
                    "messages": [{"role": "user", "content": "hello"}],
                }),
            )
            .as_str()
            .to_string()
    };

    let baseline = AppState::new(Config::default());
    let baseline_again = AppState::new(Config::default());
    let tightened = AppState::new(Config {
        guardrails: vec![guardrail_rule(
            r#"
id = "redact-secret"
name = "Redact leaked secret"
stage = "response"
keywords = ["ferro-secret-9922"]
effect = "redact"
"#,
        )],
        ..Config::default()
    });
    let tightened_further = AppState::new(Config {
        guardrails: vec![guardrail_rule(
            r#"
id = "redact-secret"
name = "Redact leaked secret"
stage = "response"
keywords = ["ferro-secret-9922", "ferro-secret-9923"]
effect = "redact"
"#,
        )],
        ..Config::default()
    });

    // Stable across identical policy sets: reload without a policy change must
    // keep hitting existing cache entries.
    assert_eq!(cache_key(&baseline), cache_key(&baseline_again));
    // Any policy change (add a rule, or edit an existing rule in place without
    // changing its id) must rotate the key.
    assert_ne!(cache_key(&baseline), cache_key(&tightened));
    assert_ne!(cache_key(&tightened), cache_key(&tightened_further));
}
