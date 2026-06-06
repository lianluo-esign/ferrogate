use super::*;
use ferrogate_providers::RoutingStrategy;

#[test]
fn rejects_model_with_unknown_provider() {
    let config = Config {
        models: vec![Model {
            name: "fast-chat".into(),
            provider: "missing".into(),
            provider_model: "gpt-4o-mini".into(),
            routing_strategy: RoutingStrategy::Priority,
            fallbacks: vec![],
            visible_organization_ids: vec![],
            visible_project_ids: vec![],
            capabilities: vec![],
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown provider"));
}

#[test]
fn rejects_model_with_unknown_fallback_provider() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "missing".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: None,
        output_price_per_1m: None,
        priority: Some(10),
        weight: Some(1),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("fallback provider missing"));
}

#[test]
fn rejects_model_fallback_with_zero_weight() {
    let mut model = model();
    model.fallbacks = vec![ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: None,
        output_price_per_1m: None,
        priority: Some(10),
        weight: Some(0),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("fallbacks[0].weight"));
}

#[test]
fn accepts_model_lowest_cost_strategy_with_prices() {
    let mut model = model();
    model.routing_strategy = RoutingStrategy::LowestCost;
    model.input_price_per_1m = Some(1.0);
    model.output_price_per_1m = Some(2.0);
    model.fallbacks = vec![ModelFallback {
        provider: "openai".into(),
        provider_model: "gpt-4.1-mini".into(),
        input_price_per_1m: Some(0.5),
        output_price_per_1m: Some(1.0),
        priority: Some(10),
        weight: Some(1),
        enabled: true,
    }];
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_latency_and_balanced_routing_strategies_without_prices() {
    for routing_strategy in [RoutingStrategy::LowestLatency, RoutingStrategy::Balanced] {
        let mut model = model();
        model.routing_strategy = routing_strategy;
        let config = Config {
            providers: vec![provider()],
            models: vec![model],
            ..Config::default()
        };

        config.validate().unwrap();
    }
}

#[test]
fn rejects_model_lowest_cost_strategy_without_prices() {
    let mut model = model();
    model.routing_strategy = RoutingStrategy::LowestCost;
    let config = Config {
        providers: vec![provider()],
        models: vec![model],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("lowest_cost requires input_price_per_1m and output_price_per_1m"));
}

#[test]
fn validates_optional_metering_export_boundary() {
    let config = Config::default();
    assert_eq!(
        config.metering.export_endpoint,
        "https://api.token4ai.cloud/v1/metering/events"
    );
    config.validate().unwrap();

    let mut enabled = Config::default();
    enabled.metering.export_enabled = true;
    let error = enabled.validate().unwrap_err().to_string();
    assert!(error.contains("metering.export_token_env"));

    enabled.metering.export_token_env = Some("FERROGATE_METERING_TOKEN".into());
    enabled.validate().unwrap();
}

#[test]
fn rejects_route_with_unknown_upstream() {
    let config = Config {
        routes: vec![route("missing", vec!["/"])],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("unknown upstream"));
}

#[test]
fn rejects_upstream_without_any_endpoint() {
    let config = Config {
        upstreams: vec![Upstream {
            name: "empty".into(),
            url: None,
            urls: vec![],
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must define url or urls"));
}

#[test]
fn rejects_invalid_endpoint_in_upstream_pool() {
    let config = Config {
        upstreams: vec![Upstream {
            name: "pool".into(),
            url: Some("http://127.0.0.1:8081".into()),
            urls: vec!["ftp://127.0.0.1:8082".into()],
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("invalid endpoint"));
}

#[test]
fn rejects_invalid_listen_address_with_field_name() {
    let config = Config {
        listen: "not-an-address".into(),
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field listen"));
    assert!(error.contains("invalid listen address"));
}

#[test]
fn rejects_invalid_admin_listen_address_with_field_name() {
    let config = Config {
        admin: AdminConfig {
            listen: Some("not-an-admin-address".into()),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field admin.listen"));
}

#[test]
fn rejects_tls_enabled_without_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some("cert.pem".into()),
            key_path: None,
            http2: false,
            acme: crate::config::TlsAcmeConfig::default(),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.key_path"));
}

#[test]
fn rejects_invalid_tls_certificate_files() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, "not a certificate").unwrap();
    std::fs::write(&key, "not a private key").unwrap();

    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some(cert.to_string_lossy().into_owned()),
            key_path: Some(key.to_string_lossy().into_owned()),
            http2: true,
            acme: crate::config::TlsAcmeConfig::default(),
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.cert_path/tls.key_path"));
}

#[test]
fn accepts_acme_dns01_tls_without_manual_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_hook_set: Some("/usr/local/bin/ferrogate-dns-set".into()),
                dns_hook_cleanup: Some("/usr/local/bin/ferrogate-dns-cleanup".into()),
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_acme_dns01_tls_without_dns_hooks() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.acme.dns_provider"));
}

#[test]
fn accepts_acme_dns01_tls_with_builtin_cloudflare_provider() {
    let mut dns_config = std::collections::BTreeMap::new();
    dns_config.insert("api_token".into(), "cf-token".into());
    dns_config.insert("zone_id".into(), "zone-123".into());
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_provider: Some("cloudflare".into()),
                dns_config,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_acme_http01_tls_without_dns_hooks() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["token4aicloud.com".into()],
                email: Some("ops@token4aicloud.com".into()),
                challenge: "http-01".into(),
                http_challenge_listen: "0.0.0.0:80".into(),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_acme_http01_for_wildcard_domains() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["*.token4aicloud.com".into()],
                email: Some("ops@token4aicloud.com".into()),
                challenge: "http-01".into(),
                terms_agreed: true,
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("wildcard domains require dns-01"));
}

#[test]
fn rejects_acme_tls_mixed_with_manual_certificate_pair() {
    let config = Config {
        tls: TlsConfig {
            enabled: true,
            cert_path: Some("cert.pem".into()),
            key_path: Some("key.pem".into()),
            acme: crate::config::TlsAcmeConfig {
                enabled: true,
                domains: vec!["api.example.com".into()],
                email: Some("ops@example.com".into()),
                terms_agreed: true,
                dns_hook_set: Some("/usr/local/bin/ferrogate-dns-set".into()),
                dns_hook_cleanup: Some("/usr/local/bin/ferrogate-dns-cleanup".into()),
                ..crate::config::TlsAcmeConfig::default()
            },
            ..TlsConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field tls.acme.enabled"));
}

#[test]
fn rejects_duplicate_api_key_id_with_field_name() {
    let config = Config {
        api_keys: vec![api_key("key_dev", "one"), api_key("key_dev", "two")],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[1].id"));
    assert!(error.contains("duplicate api key id key_dev"));
}

#[test]
fn rejects_api_key_with_unknown_allowed_model() {
    let mut key = api_key("key_dev", "Development key");
    key.allowed_models = vec!["missing-model".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].allowed_models"));
    assert!(error.contains("missing-model"));
}

#[test]
fn rejects_api_key_with_unknown_denied_model() {
    let mut key = api_key("key_dev", "Development key");
    key.denied_models = vec!["missing-model".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].denied_models"));
    assert!(error.contains("missing-model"));
}

#[test]
fn rejects_api_key_with_unknown_allowed_provider() {
    let mut key = api_key("key_dev", "Development key");
    key.allowed_providers = vec!["missing-provider".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].allowed_providers"));
    assert!(error.contains("missing-provider"));
}

#[test]
fn rejects_api_key_with_unknown_denied_provider() {
    let mut key = api_key("key_dev", "Development key");
    key.denied_providers = vec!["missing-provider".into()];
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].denied_providers"));
    assert!(error.contains("missing-provider"));
}

#[test]
fn rejects_api_key_with_unsupported_hash_format() {
    let mut key = api_key("key_dev", "Development key");
    key.key = None;
    key.key_hash = Some("sha256:not-supported".into());
    let config = Config {
        api_keys: vec![key],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field api_keys[0].key_hash"));
    assert!(error.contains("unsupported key hash format"));
}

#[test]
fn rejects_policy_with_unknown_references() {
    let config = Config {
        providers: vec![provider()],
        models: vec![model()],
        api_keys: vec![api_key("key_dev", "Development key")],
        policies: vec![PolicyRule {
            name: "deny missing".into(),
            effect: "deny".into(),
            organization_ids: vec![],
            project_ids: vec![],
            api_key_ids: vec!["missing-key".into()],
            models: vec!["missing-model".into()],
            providers: vec!["missing-provider".into()],
            code: "policy_denied".into(),
            message: "blocked".into(),
            enabled: true,
        }],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field policies[0].api_key_ids"));
    assert!(error.contains("missing-key"));
}

#[test]
fn rejects_invalid_otlp_endpoint_with_field_name() {
    let config = Config {
        telemetry: TelemetryConfig {
            service_name: "ferrogate".into(),
            log_bodies: false,
            otlp_endpoint: Some("collector:4318".into()),
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.otlp_endpoint"));
}

#[test]
fn rejects_incomplete_provider_circuit_breaker_config() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(2),
            provider_circuit_breaker_cooldown_secs: None,
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_circuit_breaker_cooldown_secs"));
}

#[test]
fn rejects_zero_provider_circuit_breaker_threshold() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(0),
            provider_circuit_breaker_cooldown_secs: Some(30),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_circuit_breaker_failure_threshold"));
}

#[test]
fn rejects_zero_provider_dispatch_timeout() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_dispatch_timeout_secs: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_dispatch_timeout_secs"));
}

#[test]
fn rejects_zero_provider_response_body_max_bytes() {
    let config = Config {
        reliability: ReliabilityConfig {
            provider_response_body_max_bytes: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.provider_response_body_max_bytes"));
}

#[test]
fn rejects_zero_graceful_shutdown_settings() {
    let config = Config {
        reliability: ReliabilityConfig {
            graceful_shutdown_grace_period_secs: Some(0),
            graceful_shutdown_timeout_secs: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_shutdown_grace_period_secs"));
}

#[test]
fn rejects_invalid_graceful_upgrade_settings() {
    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some(" ".into()),
            graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
            graceful_upgrade_sock_retries: Some(5),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_pid_file"));

    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
            graceful_upgrade_sock: Some(" ".into()),
            graceful_upgrade_sock_retries: Some(5),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_sock"));

    let config = Config {
        reliability: ReliabilityConfig {
            graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
            graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
            graceful_upgrade_sock_retries: Some(0),
            ..ReliabilityConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field reliability.graceful_upgrade_sock_retries"));
}

#[test]
fn rejects_zero_access_log_sample_rate() {
    let config = Config {
        telemetry: TelemetryConfig {
            access_log: AccessLogMode::Sampled,
            access_log_sample_rate: 0,
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.access_log_sample_rate"));
}

#[test]
fn rejects_zero_access_log_error_rate_limit() {
    let config = Config {
        telemetry: TelemetryConfig {
            access_log_error_rate_limit_per_sec: 0,
            ..TelemetryConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field telemetry.access_log_error_rate_limit_per_sec"));
}

#[test]
fn rejects_route_path_prefix_without_leading_slash() {
    let config = Config {
        upstreams: vec![upstream()],
        routes: vec![route("backend", vec!["api"])],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field routes[0].path_prefixes"));
}

#[test]
fn rejects_invalid_request_header_name_with_route_context() {
    let mut route = route("backend", vec!["/api"]);
    route.request_headers = vec![HeaderMutation {
        name: "bad header".into(),
        value: "value".into(),
    }];
    let config = Config {
        upstreams: vec![upstream()],
        routes: vec![route],
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field routes[0].request_headers[0].name"));
    assert!(error.contains("invalid header name"));
}

#[test]
fn rejects_invalid_storage_retention_and_admin_list_limits() {
    let config = Config {
        storage: StorageConfig {
            request_log_retention_records: 0,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.request_log_retention_records"));

    let config = Config {
        storage: StorageConfig {
            admin_list_default_limit: 200,
            admin_list_max_limit: 100,
            ..StorageConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field storage.admin_list_default_limit"));
}

#[test]
fn accepts_enabled_local_cluster_identity_config() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "auto".into(),
            node_region: Some("us-east-1".into()),
            node_zone: Some("us-east-1a".into()),
            state_backend: "local".into(),
            file_state_path: None,
            counter_backend: "local".into(),
            redis_url: None,
            counter_timeout_millis: 500,
            heartbeat_interval_secs: 10,
            config_poll_interval_secs: 5,
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_file_cluster_state_backend_with_path() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            state_backend: "file".into(),
            file_state_path: Some("/var/lib/ferrogate/cluster-state.json".into()),
            counter_backend: "local".into(),
            redis_url: None,
            counter_timeout_millis: 500,
            heartbeat_interval_secs: 10,
            config_poll_interval_secs: 5,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn accepts_redis_cluster_counter_backend_with_url() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            counter_backend: "redis".into(),
            redis_url: Some("redis://redis:6379/0".into()),
            counter_timeout_millis: 250,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    config.validate().unwrap();
}

#[test]
fn rejects_redis_cluster_counter_backend_without_url() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "prod-us".into(),
            node_id: "gateway-a".into(),
            counter_backend: "redis".into(),
            redis_url: None,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.redis_url"));
}

#[test]
fn rejects_invalid_enabled_cluster_config() {
    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: String::new(),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.cluster_id"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            state_backend: "postgres".into(),
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.state_backend"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            state_backend: "file".into(),
            file_state_path: None,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.file_state_path"));

    let config = Config {
        cluster: ClusterConfig {
            enabled: true,
            heartbeat_interval_secs: 0,
            ..ClusterConfig::default()
        },
        ..Config::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("field cluster.heartbeat_interval_secs"));
}

fn upstream() -> Upstream {
    Upstream {
        name: "backend".into(),
        url: Some("http://127.0.0.1:8081".into()),
        urls: vec![],
        enabled: true,
    }
}

fn provider() -> Provider {
    Provider {
        name: "openai".into(),
        kind: "openai".into(),
        base_url: "http://127.0.0.1:8081/v1".into(),
        api_key_env: None,
        openrouter_http_referer: None,
        openrouter_x_title: None,
        enabled: true,
    }
}

fn model() -> Model {
    Model {
        name: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        routing_strategy: RoutingStrategy::Priority,
        fallbacks: vec![],
        visible_organization_ids: vec![],
        visible_project_ids: vec![],
        capabilities: vec![],
        context_window: None,
        input_price_per_1m: None,
        output_price_per_1m: None,
        enabled: true,
    }
}

fn route(upstream: &str, prefixes: Vec<&str>) -> RouteRule {
    RouteRule {
        name: "api".into(),
        upstream: upstream.into(),
        hosts: vec![],
        path_prefixes: prefixes.into_iter().map(str::to_string).collect(),
        match_headers: vec![],
        strip_prefix: None,
        add_prefix: None,
        request_headers: vec![],
        response_headers: vec![],
        enabled: true,
    }
}

fn api_key(id: &str, name: &str) -> ApiKey {
    ApiKey {
        id: id.into(),
        name: name.into(),
        key_env: None,
        key: Some(format!("secret-{name}")),
        key_hash: None,
        enabled: true,
        scopes: vec![],
        allowed_models: vec![],
        denied_models: vec![],
        allowed_providers: vec![],
        denied_providers: vec![],
        organization_id: None,
        team_id: None,
        project_id: None,
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
        log_bodies: None,
    }
}
