// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Scenario coverage for observability exporter validation (#107).

use ferrogate_observability::{
    ObservabilityConfigError, ObservabilityExporterConfig, ObservabilityExporterKind,
    ObservabilityPipelineConfig, ObservabilitySignal,
};

#[test]
fn valid_exporter_constructors_pass_validation() {
    assert!(ObservabilityExporterConfig::stdout_logs()
        .validate()
        .is_ok());
    assert!(ObservabilityExporterConfig::otlp("http://collector:4318")
        .validate()
        .is_ok());
    assert!(ObservabilityExporterConfig::prometheus_metrics("/metrics")
        .validate()
        .is_ok());
    assert!(
        ObservabilityExporterConfig::file_logs("/var/log/ferrogate.log")
            .validate()
            .is_ok()
    );
}

#[test]
fn empty_name_and_missing_signals_fail_closed() {
    let mut exporter = ObservabilityExporterConfig::stdout_logs();
    exporter.name = "   ".into();
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingExporterName)
    ));

    let mut exporter = ObservabilityExporterConfig::stdout_logs();
    exporter.signals.clear();
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingSignals { .. })
    ));
}

#[test]
fn otlp_requires_a_non_empty_endpoint() {
    let mut exporter = ObservabilityExporterConfig::otlp("http://c:4318");
    exporter.endpoint = None;
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingEndpoint { .. })
    ));

    exporter.endpoint = Some("   ".into());
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingEndpoint { .. })
    ));
}

#[test]
fn prometheus_rejects_non_metric_signals_and_bad_paths() {
    // Prometheus only supports metrics.
    let mut exporter = ObservabilityExporterConfig::prometheus_metrics("/metrics");
    exporter.signals.push(ObservabilitySignal::Log);
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::UnsupportedSignal { .. })
    ));

    // Missing path.
    let mut exporter = ObservabilityExporterConfig::new(
        "prom",
        ObservabilityExporterKind::Prometheus,
        vec![ObservabilitySignal::Metric],
    );
    exporter.path = None;
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingPath { .. })
    ));

    // Non-absolute or root-only path.
    for bad in ["metrics", "/"] {
        let exporter = ObservabilityExporterConfig::prometheus_metrics(bad);
        assert!(
            matches!(
                exporter.validate(),
                Err(ObservabilityConfigError::InvalidHttpPath { .. })
            ),
            "path {bad} must be rejected"
        );
    }
}

#[test]
fn file_exporter_requires_a_path() {
    let mut exporter = ObservabilityExporterConfig::file_logs("/tmp/x.log");
    exporter.path = Some("  ".into());
    assert!(matches!(
        exporter.validate(),
        Err(ObservabilityConfigError::MissingPath { .. })
    ));
}

#[test]
fn pipeline_requires_service_name_and_validates_each_exporter() {
    // Empty service name fails closed.
    let pipeline = ObservabilityPipelineConfig::new("   ")
        .with_exporter(ObservabilityExporterConfig::stdout_logs());
    assert!(matches!(
        pipeline.validate(),
        Err(ObservabilityConfigError::MissingServiceName)
    ));

    // Valid service name + valid exporters passes.
    let pipeline = ObservabilityPipelineConfig::new("ferrogate")
        .with_exporter(ObservabilityExporterConfig::stdout_logs())
        .with_exporter(ObservabilityExporterConfig::prometheus_metrics("/metrics"));
    assert!(pipeline.validate().is_ok());

    // A single invalid exporter fails the whole pipeline.
    let mut bad = ObservabilityExporterConfig::prometheus_metrics("/metrics");
    bad.signals.push(ObservabilitySignal::Trace);
    let pipeline = ObservabilityPipelineConfig::new("ferrogate").with_exporter(bad);
    assert!(pipeline.validate().is_err());
}

#[test]
fn config_error_display_is_descriptive() {
    let error = ObservabilityConfigError::MissingSignals {
        exporter: "prom".into(),
    };
    assert!(error.to_string().contains("prom"));
    assert!(error.to_string().contains("signals"));
    assert!(ObservabilityConfigError::MissingServiceName
        .to_string()
        .contains("service name"));
}
