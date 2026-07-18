// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;

#[test]
fn config_model_supports_serde_roundtrip() {
    let config = Config {
        listen: "127.0.0.1:9090".into(),
        admin: AdminConfig {
            listen: Some("localhost:2019".into()),
            cors_allowed_origin: Some("https://admin.example.com".into()),
        },
        cluster: ClusterConfig {
            enabled: true,
            cluster_id: "cluster-a".into(),
            node_id: "node-a".into(),
            node_region: Some("us-east-1".into()),
            node_zone: Some("us-east-1a".into()),
            state_backend: "local".into(),
            file_state_path: None,
            counter_backend: "local".into(),
            redis_url: None,
            counter_timeout_millis: 500,
            heartbeat_interval_secs: 11,
            config_poll_interval_secs: 3,
            ..ClusterConfig::default()
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
        observability: ObservabilityConfig {
            enabled: true,
            provider: ObservabilityProvider::Vector,
            otlp_endpoint: Some("http://vector:4318".into()),
            prometheus_metrics_path: "/metrics".into(),
            export_timeout_secs: 4,
        },
        reliability: ReliabilityConfig {
            provider_circuit_breaker_failure_threshold: Some(2),
            provider_circuit_breaker_cooldown_secs: Some(30),
            provider_dispatch_timeout_secs: Some(5),
            provider_dispatch_max_retries: Some(1),
            mcp_dispatch_timeout_secs: 7,
            mcp_dispatch_max_concurrency: 4,
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
        plugins: vec![ExtensionConfig {
            id: "tool.echo".into(),
            kind: ExtensionKind::ToolProvider,
            version: "0.1.0".into(),
            manifest: PluginManifest::default(),
            compatibility: PluginCompatibility::default(),
            enabled: true,
            source: "builtin".into(),
            order: 10,
            approval_policy: ferrogate_core::ApprovalPolicy::Never,
            permissions: ExtensionPermissions {
                tools: vec!["tool.echo".into()],
                network: vec![],
                filesystem: false,
                shell: false,
                tenant_scope: false,
                secrets: false,
                admin_mutation: false,
            },
            config: [("timeout_ms".into(), toml::Value::Integer(30_000))]
                .into_iter()
                .collect(),
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
        decoded.observability.provider,
        ObservabilityProvider::Vector
    );
    assert_eq!(
        decoded.observability.otlp_endpoint.as_deref(),
        Some("http://vector:4318")
    );
    assert_eq!(decoded.observability.export_timeout_secs, 4);
    assert_eq!(
        decoded
            .reliability
            .provider_circuit_breaker_failure_threshold,
        Some(2)
    );
    assert_eq!(decoded.reliability.provider_dispatch_timeout_secs, Some(5));
    assert_eq!(decoded.reliability.provider_dispatch_max_retries, Some(1));
    assert_eq!(decoded.reliability.mcp_dispatch_timeout_secs, 7);
    assert_eq!(decoded.reliability.mcp_dispatch_max_concurrency, 4);
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
    assert_eq!(decoded.plugins[0].kind, ExtensionKind::ToolProvider);
    assert_eq!(decoded.plugins[0].permissions.tools, ["tool.echo"]);
    assert_eq!(
        decoded.plugins[0].config.get("timeout_ms"),
        Some(&toml::Value::Integer(30_000))
    );
    decoded.validate().unwrap();
}
