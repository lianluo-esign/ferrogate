// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::*;
use crate::otlp::OtlpAttribute;

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

#[test]
fn otlp_backend_builds_a_request_per_signal() {
    let backend = OtlpBackend::new("http://collector:4318");

    let metrics = backend.metrics_request(&snapshot()).unwrap().unwrap();
    assert_eq!(metrics.url, "http://collector:4318/v1/metrics");

    let traces = backend
        .traces_request("ferrogate", &[span()])
        .unwrap()
        .unwrap();
    assert_eq!(traces.url, "http://collector:4318/v1/traces");

    let logs = backend
        .logs_request("ferrogate", &[log()])
        .unwrap()
        .unwrap();
    assert_eq!(logs.url, "http://collector:4318/v1/logs");
}

#[test]
fn otlp_backend_skips_empty_batches() {
    let backend = OtlpBackend::new("http://collector:4318");

    assert!(backend.traces_request("ferrogate", &[]).unwrap().is_none());
    assert!(backend.logs_request("ferrogate", &[]).unwrap().is_none());
}

#[test]
fn otlp_backend_skips_signals_it_does_not_carry() {
    let backend =
        OtlpBackend::new("http://collector:4318").with_signals(vec![ObservabilitySignal::Metric]);

    assert!(backend.supports(ObservabilitySignal::Metric));
    assert!(!backend.supports(ObservabilitySignal::Trace));
    assert!(backend.metrics_request(&snapshot()).unwrap().is_some());
    assert!(backend
        .traces_request("ferrogate", &[span()])
        .unwrap()
        .is_none());
    assert!(backend
        .logs_request("ferrogate", &[log()])
        .unwrap()
        .is_none());
}

#[test]
fn otlp_backend_validate_rejects_a_scheme_less_endpoint() {
    let error = OtlpBackend::new("collector:4318").validate().unwrap_err();
    assert!(matches!(
        error,
        ObservabilityConfigError::InvalidEndpoint { .. }
    ));
}

#[test]
fn otlp_backend_validate_rejects_an_empty_endpoint() {
    let error = OtlpBackend::new("   ").validate().unwrap_err();
    assert!(matches!(
        error,
        ObservabilityConfigError::MissingEndpoint { .. }
    ));
}

#[test]
fn otlp_backend_carries_no_credential_headers() {
    let backend = OtlpBackend::new("http://collector:4318");
    let metrics = backend.metrics_request(&snapshot()).unwrap().unwrap();
    assert!(metrics.headers.is_empty());
}

#[test]
fn backends_are_usable_as_trait_objects() {
    // The point of the trait: the export loop holds one of these and never
    // matches on a destination enum.
    let backends: Vec<Box<dyn TelemetryBackend>> = vec![
        Box::new(OtlpBackend::new("http://collector:4318")),
        Box::new(crate::cloudflare::CloudflareBackend::new(
            "https://collector.example.workers.dev",
            "token",
        )),
    ];

    let names = backends
        .iter()
        .map(|backend| backend.name())
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["otlp", "cloudflare"]);
    for backend in &backends {
        assert!(backend.validate().is_ok());
        assert!(backend.metrics_request(&snapshot()).unwrap().is_some());
    }
}
