//! Logging, metrics, and tracing boundaries.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub service_name: String,
    pub traces_enabled: bool,
    pub metrics_enabled: bool,
    pub logs_enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            service_name: "ferrogate".to_string(),
            traces_enabled: true,
            metrics_enabled: true,
            logs_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilitySignal {
    Trace,
    Metric,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityExporterKind {
    Stdout,
    Otlp,
    Prometheus,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityExporterConfig {
    pub name: String,
    pub kind: ObservabilityExporterKind,
    pub signals: Vec<ObservabilitySignal>,
    pub endpoint: Option<String>,
    pub path: Option<String>,
    pub enabled: bool,
}

impl ObservabilityExporterConfig {
    pub fn new(
        name: impl Into<String>,
        kind: ObservabilityExporterKind,
        signals: Vec<ObservabilitySignal>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            signals,
            endpoint: None,
            path: None,
            enabled: true,
        }
    }

    pub fn stdout_logs() -> Self {
        Self::new(
            "stdout-logs",
            ObservabilityExporterKind::Stdout,
            vec![ObservabilitySignal::Log],
        )
    }

    pub fn otlp(endpoint: impl Into<String>) -> Self {
        let mut exporter = Self::new(
            "otlp",
            ObservabilityExporterKind::Otlp,
            vec![
                ObservabilitySignal::Trace,
                ObservabilitySignal::Metric,
                ObservabilitySignal::Log,
            ],
        );
        exporter.endpoint = Some(endpoint.into());
        exporter
    }

    pub fn prometheus_metrics(path: impl Into<String>) -> Self {
        let mut exporter = Self::new(
            "prometheus",
            ObservabilityExporterKind::Prometheus,
            vec![ObservabilitySignal::Metric],
        );
        exporter.path = Some(path.into());
        exporter
    }

    pub fn file_logs(path: impl Into<String>) -> Self {
        let mut exporter = Self::new(
            "file-logs",
            ObservabilityExporterKind::File,
            vec![ObservabilitySignal::Log],
        );
        exporter.path = Some(path.into());
        exporter
    }

    pub fn validate(&self) -> Result<(), ObservabilityConfigError> {
        validate_exporter_parts(
            &self.name,
            self.kind,
            &self.signals,
            self.endpoint.as_deref(),
            self.path.as_deref(),
        )
    }
}

pub trait ObservabilityPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> ObservabilityExporterKind;
    fn signals(&self) -> &[ObservabilitySignal];
    fn endpoint(&self) -> Option<&str> {
        None
    }
    fn path(&self) -> Option<&str> {
        None
    }
    fn validate(&self) -> Result<(), ObservabilityConfigError> {
        validate_exporter_parts(
            self.name(),
            self.kind(),
            self.signals(),
            self.endpoint(),
            self.path(),
        )
    }
}

impl ObservabilityPlugin for ObservabilityExporterConfig {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> ObservabilityExporterKind {
        self.kind
    }

    fn signals(&self) -> &[ObservabilitySignal] {
        &self.signals
    }

    fn endpoint(&self) -> Option<&str> {
        self.endpoint.as_deref()
    }

    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservabilityPipelineConfig {
    pub service_name: String,
    pub exporters: Vec<ObservabilityExporterConfig>,
}

impl ObservabilityPipelineConfig {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            exporters: Vec::new(),
        }
    }

    pub fn with_exporter(mut self, exporter: ObservabilityExporterConfig) -> Self {
        self.exporters.push(exporter);
        self
    }

    pub fn validate(&self) -> Result<(), ObservabilityConfigError> {
        if self.service_name.trim().is_empty() {
            return Err(ObservabilityConfigError::MissingServiceName);
        }

        for exporter in &self.exporters {
            exporter.validate()?;
        }

        Ok(())
    }
}

impl Default for ObservabilityPipelineConfig {
    fn default() -> Self {
        Self::new(ObservabilityConfig::default().service_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservabilityConfigError {
    MissingServiceName,
    MissingExporterName,
    MissingSignals {
        exporter: String,
    },
    MissingEndpoint {
        exporter: String,
        kind: ObservabilityExporterKind,
    },
    MissingPath {
        exporter: String,
        kind: ObservabilityExporterKind,
    },
    InvalidHttpPath {
        exporter: String,
        path: String,
    },
    UnsupportedSignal {
        exporter: String,
        kind: ObservabilityExporterKind,
        signal: ObservabilitySignal,
    },
}

impl fmt::Display for ObservabilityConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingServiceName => write!(f, "observability service name is required"),
            Self::MissingExporterName => write!(f, "observability exporter name is required"),
            Self::MissingSignals { exporter } => {
                write!(
                    f,
                    "observability exporter `{exporter}` must declare signals"
                )
            }
            Self::MissingEndpoint { exporter, kind } => write!(
                f,
                "observability exporter `{exporter}` of kind {kind:?} requires an endpoint"
            ),
            Self::MissingPath { exporter, kind } => write!(
                f,
                "observability exporter `{exporter}` of kind {kind:?} requires a path"
            ),
            Self::InvalidHttpPath { exporter, path } => write!(
                f,
                "observability exporter `{exporter}` requires an absolute HTTP path, got `{path}`"
            ),
            Self::UnsupportedSignal {
                exporter,
                kind,
                signal,
            } => write!(
                f,
                "observability exporter `{exporter}` of kind {kind:?} does not support {signal:?}"
            ),
        }
    }
}

impl std::error::Error for ObservabilityConfigError {}

fn validate_exporter_parts(
    name: &str,
    kind: ObservabilityExporterKind,
    signals: &[ObservabilitySignal],
    endpoint: Option<&str>,
    path: Option<&str>,
) -> Result<(), ObservabilityConfigError> {
    let exporter = name.trim();
    if exporter.is_empty() {
        return Err(ObservabilityConfigError::MissingExporterName);
    }

    if signals.is_empty() {
        return Err(ObservabilityConfigError::MissingSignals {
            exporter: exporter.to_string(),
        });
    }

    match kind {
        ObservabilityExporterKind::Otlp => {
            if endpoint.is_none_or(|endpoint| endpoint.trim().is_empty()) {
                return Err(ObservabilityConfigError::MissingEndpoint {
                    exporter: exporter.to_string(),
                    kind,
                });
            }
        }
        ObservabilityExporterKind::Prometheus => {
            for signal in signals {
                if *signal != ObservabilitySignal::Metric {
                    return Err(ObservabilityConfigError::UnsupportedSignal {
                        exporter: exporter.to_string(),
                        kind,
                        signal: *signal,
                    });
                }
            }

            let path = path.ok_or_else(|| ObservabilityConfigError::MissingPath {
                exporter: exporter.to_string(),
                kind,
            })?;
            if !path.starts_with('/') || path.trim() == "/" {
                return Err(ObservabilityConfigError::InvalidHttpPath {
                    exporter: exporter.to_string(),
                    path: path.to_string(),
                });
            }
        }
        ObservabilityExporterKind::File => {
            if path.is_none_or(|path| path.trim().is_empty()) {
                return Err(ObservabilityConfigError::MissingPath {
                    exporter: exporter.to_string(),
                    kind,
                });
            }
        }
        ObservabilityExporterKind::Stdout => {}
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewaySpanKind {
    GatewayRequest,
    Auth,
    Policy,
    ModelRoute,
    ProviderDispatch,
    BillingWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewaySpanTemplate {
    pub name: &'static str,
    pub kind: GatewaySpanKind,
    pub fields: &'static [&'static str],
}

impl GatewaySpanTemplate {
    pub const fn new(
        name: &'static str,
        kind: GatewaySpanKind,
        fields: &'static [&'static str],
    ) -> Self {
        Self { name, kind, fields }
    }
}

pub const GATEWAY_REQUEST_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.gateway.request",
    GatewaySpanKind::GatewayRequest,
    &[
        "request_id",
        "trace_id",
        "method",
        "path",
        "route",
        "status_code",
    ],
);

pub const AUTH_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.auth",
    GatewaySpanKind::Auth,
    &[
        "request_id",
        "api_key_id",
        "organization_id",
        "project_id",
        "scope",
        "result",
    ],
);

pub const POLICY_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.policy.evaluate",
    GatewaySpanKind::Policy,
    &[
        "request_id",
        "api_key_id",
        "organization_id",
        "project_id",
        "model",
        "provider",
        "result",
    ],
);

pub const MODEL_ROUTE_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.model.route",
    GatewaySpanKind::ModelRoute,
    &[
        "request_id",
        "logical_model",
        "provider",
        "provider_model",
        "candidate_index",
        "fallback_count",
    ],
);

pub const PROVIDER_DISPATCH_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.provider.dispatch",
    GatewaySpanKind::ProviderDispatch,
    &[
        "request_id",
        "logical_model",
        "provider",
        "provider_model",
        "stream",
        "status_code",
        "retryable",
    ],
);

pub const BILLING_WRITE_SPAN: GatewaySpanTemplate = GatewaySpanTemplate::new(
    "ferrogate.billing.write",
    GatewaySpanKind::BillingWrite,
    &[
        "request_id",
        "organization_id",
        "project_id",
        "api_key_id",
        "logical_model",
        "provider",
        "total_tokens",
        "cost",
        "result",
    ],
);

pub fn default_span_templates() -> &'static [GatewaySpanTemplate] {
    &[
        GATEWAY_REQUEST_SPAN,
        AUTH_SPAN,
        POLICY_SPAN,
        MODEL_ROUTE_SPAN,
        PROVIDER_DISPATCH_SPAN,
        BILLING_WRITE_SPAN,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_config_enables_all_signal_types() {
        let config = ObservabilityConfig::default();

        assert_eq!(config.service_name, "ferrogate");
        assert!(config.traces_enabled);
        assert!(config.metrics_enabled);
        assert!(config.logs_enabled);
    }

    #[test]
    fn span_templates_cover_prd_request_provider_and_billing_hierarchy() {
        let templates = default_span_templates();

        assert_eq!(templates[0].name, "ferrogate.gateway.request");
        assert!(templates.iter().any(|template| template.kind
            == GatewaySpanKind::ProviderDispatch
            && template.fields.contains(&"retryable")));
        assert!(templates
            .iter()
            .any(|template| template.kind == GatewaySpanKind::BillingWrite
                && template.fields.contains(&"total_tokens")
                && template.fields.contains(&"cost")));
    }

    #[test]
    fn prometheus_exporter_is_a_metrics_plugin_boundary() {
        let exporter = ObservabilityExporterConfig::prometheus_metrics("/metrics");
        let pipeline =
            ObservabilityPipelineConfig::new("ferrogate").with_exporter(exporter.clone());

        assert_eq!(exporter.kind, ObservabilityExporterKind::Prometheus);
        assert_eq!(exporter.signals, vec![ObservabilitySignal::Metric]);
        assert_eq!(exporter.path.as_deref(), Some("/metrics"));
        assert!(pipeline.validate().is_ok());
    }

    #[test]
    fn rejects_prometheus_log_plugin_misconfiguration() {
        let exporter = ObservabilityExporterConfig::new(
            "prometheus-logs",
            ObservabilityExporterKind::Prometheus,
            vec![ObservabilitySignal::Log],
        );

        assert_eq!(
            exporter.validate(),
            Err(ObservabilityConfigError::UnsupportedSignal {
                exporter: "prometheus-logs".to_string(),
                kind: ObservabilityExporterKind::Prometheus,
                signal: ObservabilitySignal::Log,
            })
        );
    }

    #[test]
    fn allows_multiple_exporters_for_different_signal_types() {
        let pipeline = ObservabilityPipelineConfig::new("ferrogate")
            .with_exporter(ObservabilityExporterConfig::stdout_logs())
            .with_exporter(ObservabilityExporterConfig::prometheus_metrics("/metrics"))
            .with_exporter(ObservabilityExporterConfig::otlp(
                "http://localhost:4318/v1/traces",
            ));

        assert!(pipeline.validate().is_ok());
        assert_eq!(pipeline.exporters.len(), 3);
    }

    #[test]
    fn validates_exporter_required_fields() {
        let empty_name = ObservabilityExporterConfig::new(
            " ",
            ObservabilityExporterKind::Stdout,
            vec![ObservabilitySignal::Log],
        );
        let empty_signals = ObservabilityExporterConfig::new(
            "empty",
            ObservabilityExporterKind::Stdout,
            Vec::new(),
        );
        let bad_prometheus_path = ObservabilityExporterConfig::prometheus_metrics("metrics");

        assert_eq!(
            empty_name.validate(),
            Err(ObservabilityConfigError::MissingExporterName)
        );
        assert_eq!(
            empty_signals.validate(),
            Err(ObservabilityConfigError::MissingSignals {
                exporter: "empty".to_string(),
            })
        );
        assert_eq!(
            bad_prometheus_path.validate(),
            Err(ObservabilityConfigError::InvalidHttpPath {
                exporter: "prometheus".to_string(),
                path: "metrics".to_string(),
            })
        );
    }
}
