use super::*;

#[test]
fn config_model_supports_serde_roundtrip() {
    let config = Config {
        listen: "127.0.0.1:9090".into(),
        admin: AdminConfig {
            listen: Some("localhost:2019".into()),
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
    assert_eq!(
        decoded.telemetry.otlp_endpoint.as_deref(),
        Some("http://127.0.0.1:4318")
    );
    assert_eq!(decoded.upstreams[0].endpoint_urls().len(), 2);
    assert_eq!(decoded.routes[0].request_headers[0].name, "x-request");
    decoded.validate().unwrap();
}
