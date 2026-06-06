use super::*;

#[test]
fn config_model_supports_serde_roundtrip() {
    let config = Config {
        listen: "127.0.0.1:9090".into(),
        admin: AdminConfig {
            listen: Some("localhost:2019".into()),
        },
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            node_region: Some("us-east-1".into()),
            node_zone: Some("us-east-1a".into()),
            state_backend: "local".into(),
            counter_backend: "local".into(),
            heartbeat_interval_secs: 11,
            config_poll_interval_secs: 3,
        },
        upstreams: vec![Upstream {
            name: "backend".into(),
            url: Some("http://127.0.0.1:8081".into()),
            urls: vec!["http://127.0.0.1:8082".into()],
            enabled: true,
        }],
        telemetry: TelemetryConfig {
            service_name: "ferrogate-test".into(),
            log_bodies: false,
            otlp_endpoint: Some("http://127.0.0.1:4318".into()),
            ..TelemetryConfig::default()
        },
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(2),
            provider_circuit_breaker_cooldown_secs: Some(30),
            provider_dispatch_timeout_secs: Some(5),
            provider_dispatch_max_retries: Some(1),
            graceful_shutdown_grace_period_secs: Some(3),
            graceful_shutdown_timeout_secs: Some(15),
            graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
            graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
            graceful_upgrade_sock_retries: Some(5),
            ..ReliabilityConfig::default()
        },
        routes: vec![RouteRule {
            name: "api".into(),
            upstream: "backend".into(),
            hosts: vec!["example.test".into()],
            path_prefixes: vec!["/api".into()],
            match_headers: vec![HeaderMatcher {
                name: "x-target".into(),
                value: "primary".into(),
            }],
            strip_prefix: Some("/api".into()),
            add_prefix: Some("/v1".into()),
            request_headers: vec![HeaderMutation {
                name: "x-request".into(),
                value: "one".into(),
            }],
            response_headers: vec![HeaderMutation {
                name: "x-response".into(),
                value: "two".into(),
            }],
            enabled: true,
        }],
        ..Config::default()
    };

    let encoded = serde_json::to_string(&config).unwrap();
    let decoded: Config = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded.listen, config.listen);
    assert_eq!(decoded.admin.listen.as_deref(), Some("localhost:2019"));
    assert_eq!(decoded.cluster, config.cluster);
    assert!(!decoded.tls.is_enabled());
    assert_eq!(
        decoded.telemetry.otlp_endpoint.as_deref(),
        Some("http://127.0.0.1:4318")
    );
    assert_eq!(
        decoded
            .reliability
            .provider_circuit_breaker_failure_threshold,
        Some(2)
    );
    assert_eq!(decoded.reliability.provider_dispatch_timeout_secs, Some(5));
    assert_eq!(decoded.reliability.provider_dispatch_max_retries, Some(1));
    assert_eq!(
        decoded.reliability.graceful_shutdown_grace_period_secs,
        Some(3)
    );
    assert_eq!(decoded.reliability.graceful_shutdown_timeout_secs, Some(15));
    assert_eq!(
        decoded.reliability.graceful_upgrade_pid_file.as_deref(),
        Some("/tmp/ferrogate.pid")
    );
    assert_eq!(
        decoded.reliability.graceful_upgrade_sock.as_deref(),
        Some("/tmp/ferrogate_upgrade.sock")
    );
    assert_eq!(decoded.reliability.graceful_upgrade_sock_retries, Some(5));
    assert_eq!(decoded.upstreams[0].endpoint_urls().len(), 2);
    assert_eq!(decoded.routes[0].request_headers[0].name, "x-request");
    decoded.validate().unwrap();
}
