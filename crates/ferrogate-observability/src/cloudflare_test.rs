// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;
use crate::otlp::OtlpAttribute;

const TOKEN: &str = "s3cr3t-collector-token";
const ENDPOINT: &str = "https://telemetry-collector.example.workers.dev";

fn backend() -> CloudflareBackend {
    CloudflareBackend::new(ENDPOINT, TOKEN)
}

fn snapshot() -> GatewayMetricsSnapshot {
    GatewayMetricsSnapshot {
        service_name: "ferrogate".to_string(),
        ..Default::default()
    }
}

fn span() -> OtlpSpanRecord {
    OtlpSpanRecord {
        trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
        span_id: "b7ad6b7169203331".to_string(),
        parent_span_id: None,
        name: "ferrogate.gateway.request".to_string(),
        start_time_unix_nano: 1,
        end_time_unix_nano: 2,
        attributes: vec![OtlpAttribute::new("tenant", "acme")],
    }
}

fn log() -> OtlpLogRecord {
    OtlpLogRecord {
        trace_id: None,
        span_id: None,
        severity_text: "INFO".to_string(),
        body: "request".to_string(),
        time_unix_nano: 1,
        attributes: Vec::new(),
    }
}

fn header<'a>(request: &'a OtlpHttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[test]
fn every_signal_carries_the_bearer_credential() {
    let backend = backend();

    let requests = [
        backend.metrics_request(&snapshot()).unwrap().unwrap(),
        backend
            .traces_request("ferrogate", &[span()])
            .unwrap()
            .unwrap(),
        backend
            .logs_request("ferrogate", &[log()])
            .unwrap()
            .unwrap(),
    ];

    for request in &requests {
        assert_eq!(
            header(request, "authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
    }
}

#[test]
fn signals_target_the_standard_otlp_paths() {
    let backend = backend();

    assert_eq!(
        backend.metrics_request(&snapshot()).unwrap().unwrap().url,
        format!("{ENDPOINT}/v1/metrics")
    );
    assert_eq!(
        backend
            .traces_request("ferrogate", &[span()])
            .unwrap()
            .unwrap()
            .url,
        format!("{ENDPOINT}/v1/traces")
    );
    assert_eq!(
        backend
            .logs_request("ferrogate", &[log()])
            .unwrap()
            .unwrap()
            .url,
        format!("{ENDPOINT}/v1/logs")
    );
}

#[test]
fn debug_output_redacts_the_credential() {
    // The export loop debug-logs its sink at startup; a derived `Debug` would
    // put the collector token in the process log.
    let rendered = format!("{:?}", backend());
    assert!(
        !rendered.contains(TOKEN),
        "credential leaked into Debug output: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "got: {rendered}");
    assert!(rendered.contains("telemetry-collector.example.workers.dev"));
}

#[test]
fn default_tenant_is_sent_only_when_configured() {
    let without = backend().metrics_request(&snapshot()).unwrap().unwrap();
    assert_eq!(header(&without, TENANT_HEADER), None);

    let with = CloudflareBackend::new(ENDPOINT, TOKEN)
        .with_default_tenant(Some("acme".to_string()))
        .metrics_request(&snapshot())
        .unwrap()
        .unwrap();
    assert_eq!(header(&with, TENANT_HEADER), Some("acme"));
}

#[test]
fn blank_default_tenant_is_treated_as_unset() {
    let backend =
        CloudflareBackend::new(ENDPOINT, TOKEN).with_default_tenant(Some("  ".to_string()));
    assert_eq!(backend.default_tenant(), None);
}

#[test]
fn empty_batches_produce_no_request() {
    let backend = backend();
    assert!(backend.traces_request("ferrogate", &[]).unwrap().is_none());
    assert!(backend.logs_request("ferrogate", &[]).unwrap().is_none());
}

#[test]
fn unsupported_signals_are_skipped() {
    let backend = CloudflareBackend::new(ENDPOINT, TOKEN)
        .with_signals(vec![ObservabilitySignal::Trace, ObservabilitySignal::Log]);
    assert!(backend.metrics_request(&snapshot()).unwrap().is_none());
    assert!(backend
        .traces_request("ferrogate", &[span()])
        .unwrap()
        .is_some());
}

#[test]
fn validate_accepts_an_https_collector() {
    assert!(backend().validate().is_ok());
}

#[test]
fn validate_refuses_plaintext_to_a_remote_collector() {
    let error = CloudflareBackend::new("http://collector.example.com", TOKEN)
        .validate()
        .unwrap_err();
    assert!(
        matches!(error, ObservabilityConfigError::InsecureEndpoint { .. }),
        "got: {error:?}"
    );
}

#[test]
fn validate_allows_plaintext_loopback_for_wrangler_dev() {
    for endpoint in [
        "http://localhost:8787",
        "http://127.0.0.1:8787",
        "http://[::1]:8787",
        "http://localhost:8787/ingest",
    ] {
        assert!(
            CloudflareBackend::new(endpoint, TOKEN).validate().is_ok(),
            "expected {endpoint} to be accepted"
        );
    }
}

#[test]
fn validate_refuses_a_host_that_merely_looks_like_loopback() {
    for endpoint in [
        "http://localhost.evil.com",
        "http://127.0.0.1.evil.com",
        "http://user@evil.com",
        "http://evil.com/localhost",
    ] {
        let error = CloudflareBackend::new(endpoint, TOKEN)
            .validate()
            .unwrap_err();
        assert!(
            matches!(error, ObservabilityConfigError::InsecureEndpoint { .. }),
            "expected {endpoint} to be refused, got: {error:?}"
        );
    }
}

#[test]
fn validate_requires_a_credential() {
    let error = CloudflareBackend::new(ENDPOINT, "   ")
        .validate()
        .unwrap_err();
    assert!(matches!(
        error,
        ObservabilityConfigError::MissingCredential { .. }
    ));
}

#[test]
fn validate_refuses_a_credential_that_could_split_the_request() {
    let error = CloudflareBackend::new(ENDPOINT, "token\r\nX-Injected: 1")
        .validate()
        .unwrap_err();
    assert!(
        matches!(error, ObservabilityConfigError::InvalidCredential { .. }),
        "got: {error:?}"
    );
}

#[test]
fn validate_still_checks_the_endpoint_shape() {
    let error = CloudflareBackend::new("", TOKEN).validate().unwrap_err();
    assert!(matches!(
        error,
        ObservabilityConfigError::MissingEndpoint { .. }
    ));
}
