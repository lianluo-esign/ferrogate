// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Observability pipeline/exporter configuration types, the exporter
//! plugin contract, and exporter validation.

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
    InvalidEndpoint {
        exporter: String,
        endpoint: String,
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
            Self::InvalidEndpoint { exporter, endpoint } => write!(
                f,
                "observability exporter `{exporter}` requires an http or https endpoint, got `{endpoint}`"
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
