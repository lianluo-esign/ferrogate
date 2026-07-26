// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The telemetry backend contract: the seam a concrete observability
//! destination plugs into (issue #520).
//!
//! Backends **build** requests; they never send them. This crate is
//! deliberately I/O-free -- its only dependencies are `serde_json` and
//! `tracing` -- so the transport stays behind `ferrogate-cli`'s
//! `dispatch_otlp_request` and every backend stays unit-testable without a
//! network, a runtime, or a mock server. That split is the whole reason this
//! trait returns [`OtlpHttpRequest`] instead of taking a client.
//!
//! It replaces the previous arrangement, where the only "plugin" trait
//! ([`crate::ObservabilityPlugin`]) validated configuration but had no way to
//! emit anything, and the actual destination was a closed two-variant enum
//! matched inline in the exporter loop. Adding a destination now means adding
//! an implementor here rather than editing a `match`.

use crate::config::{ObservabilityConfigError, ObservabilitySignal};
use crate::metrics::GatewayMetricsSnapshot;
use crate::otlp::{
    build_otlp_logs_request, build_otlp_metrics_request, build_otlp_traces_request,
    OtlpHttpRequest, OtlpLogRecord, OtlpSpanRecord,
};

/// A destination for FerroGate telemetry.
///
/// Each `*_request` method returns `Ok(None)` when there is nothing to send --
/// either because the batch is empty or because the backend does not carry
/// that signal -- so callers never have to pair a `supports()` check with an
/// emptiness check at every call site.
pub trait TelemetryBackend: Send + Sync {
    /// Stable identifier used in status output and export error messages.
    fn name(&self) -> &str;

    /// Whether this backend carries `signal` at all.
    fn supports(&self, signal: ObservabilitySignal) -> bool;

    fn metrics_request(
        &self,
        snapshot: &GatewayMetricsSnapshot,
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError>;

    fn traces_request(
        &self,
        service_name: &str,
        spans: &[OtlpSpanRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError>;

    fn logs_request(
        &self,
        service_name: &str,
        logs: &[OtlpLogRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError>;

    /// Checked once at startup so a misconfigured backend fails fast instead of
    /// failing every five seconds inside the export thread.
    fn validate(&self) -> Result<(), ObservabilityConfigError> {
        Ok(())
    }
}

/// Every signal, in the order the export loop emits them.
pub const ALL_SIGNALS: [ObservabilitySignal; 3] = [
    ObservabilitySignal::Metric,
    ObservabilitySignal::Trace,
    ObservabilitySignal::Log,
];

/// Plain OTLP/HTTP+JSON to a collector that needs no credential -- the
/// historical behaviour, kept as a first-class backend so the generic export
/// loop has no special case for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpBackend {
    endpoint: String,
    signals: Vec<ObservabilitySignal>,
}

impl OtlpBackend {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            signals: ALL_SIGNALS.to_vec(),
        }
    }

    pub fn with_signals(mut self, signals: Vec<ObservabilitySignal>) -> Self {
        self.signals = signals;
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl TelemetryBackend for OtlpBackend {
    fn name(&self) -> &str {
        "otlp"
    }

    fn supports(&self, signal: ObservabilitySignal) -> bool {
        self.signals.contains(&signal)
    }

    fn metrics_request(
        &self,
        snapshot: &GatewayMetricsSnapshot,
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError> {
        if !self.supports(ObservabilitySignal::Metric) {
            return Ok(None);
        }
        build_otlp_metrics_request(&self.endpoint, snapshot).map(Some)
    }

    fn traces_request(
        &self,
        service_name: &str,
        spans: &[OtlpSpanRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError> {
        if spans.is_empty() || !self.supports(ObservabilitySignal::Trace) {
            return Ok(None);
        }
        build_otlp_traces_request(&self.endpoint, service_name, spans).map(Some)
    }

    fn logs_request(
        &self,
        service_name: &str,
        logs: &[OtlpLogRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError> {
        if logs.is_empty() || !self.supports(ObservabilitySignal::Log) {
            return Ok(None);
        }
        build_otlp_logs_request(&self.endpoint, service_name, logs).map(Some)
    }

    fn validate(&self) -> Result<(), ObservabilityConfigError> {
        // Reuse the endpoint scheme/emptiness checks the request builders
        // already enforce, against a throwaway empty batch.
        build_otlp_traces_request(&self.endpoint, "ferrogate", &[]).map(|_| ())
    }
}

#[cfg(test)]
#[path = "backend_test.rs"]
mod backend_test;
