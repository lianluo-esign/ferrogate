// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Cloudflare telemetry backend: OTLP/HTTP+JSON to the FerroGate
//! `telemetry-collector` Worker (issue #520).
//!
//! # Why this goes through a Worker
//!
//! Cloudflare exposes **no observability ingest endpoint anywhere on the
//! platform**: there is no OTLP receiver, no Workers Logs write API, and
//! Analytics Engine's `writeDataPoint()` is a Worker *binding* -- its only HTTP
//! API is read/SQL. A Rust process in a container therefore cannot write
//! telemetry to Cloudflare directly. The collector Worker in
//! `workers/telemetry-collector/` is the ingest endpoint we deploy ourselves,
//! and it fans out to Analytics Engine + Workers Logs over bindings. This is
//! the same fronting-Worker pattern issue #413 established for agents.
//!
//! # Why OTLP/JSON and not something bespoke
//!
//! Cloudflare's own native Workers OTLP export emits OTLP/JSON (it does *not*
//! support binary protobuf), so speaking the same dialect lets one collector
//! ingest both FerroGate-side and Cloudflare-Worker-side telemetry into one
//! store, with the trace ids lining up. That is what makes a CF-hosted Worker
//! hop and a gateway request show up as a single trace.

use std::fmt;

use crate::backend::{TelemetryBackend, ALL_SIGNALS};
use crate::config::{ObservabilityConfigError, ObservabilitySignal};
use crate::metrics::GatewayMetricsSnapshot;
use crate::otlp::{
    build_otlp_logs_request, build_otlp_metrics_request, build_otlp_traces_request,
    OtlpHttpRequest, OtlpLogRecord, OtlpSpanRecord,
};

/// Header carrying the fallback tenant for records that have no tenant
/// attribute. Analytics Engine requires exactly one `index` per data point and
/// the collector uses the tenant as that index, so it needs *some* value.
pub const TENANT_HEADER: &str = "x-ferrogate-tenant";

const BACKEND_NAME: &str = "cloudflare";

/// Ships telemetry to the FerroGate collector Worker on Cloudflare.
///
/// `Debug` is implemented by hand: the export loop debug-logs its sink at
/// startup, and a derived `Debug` would print the bearer token into the
/// process log.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudflareBackend {
    collector_endpoint: String,
    token: String,
    default_tenant: Option<String>,
    signals: Vec<ObservabilitySignal>,
}

impl fmt::Debug for CloudflareBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareBackend")
            .field("collector_endpoint", &self.collector_endpoint)
            .field("token", &"<redacted>")
            .field("default_tenant", &self.default_tenant)
            .field("signals", &self.signals)
            .finish()
    }
}

impl CloudflareBackend {
    pub fn new(collector_endpoint: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            collector_endpoint: collector_endpoint.into(),
            token: token.into(),
            default_tenant: None,
            signals: ALL_SIGNALS.to_vec(),
        }
    }

    pub fn with_default_tenant(mut self, tenant: Option<String>) -> Self {
        self.default_tenant = tenant.filter(|tenant| !tenant.trim().is_empty());
        self
    }

    pub fn with_signals(mut self, signals: Vec<ObservabilitySignal>) -> Self {
        self.signals = signals;
        self
    }

    pub fn collector_endpoint(&self) -> &str {
        &self.collector_endpoint
    }

    pub fn default_tenant(&self) -> Option<&str> {
        self.default_tenant.as_deref()
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut headers = vec![(
            "Authorization".to_string(),
            format!("Bearer {}", self.token),
        )];
        if let Some(tenant) = &self.default_tenant {
            headers.push((TENANT_HEADER.to_string(), tenant.clone()));
        }
        headers
    }

    fn authorize(&self, request: OtlpHttpRequest) -> OtlpHttpRequest {
        let mut request = request;
        request.headers.extend(self.headers());
        request
    }
}

impl TelemetryBackend for CloudflareBackend {
    fn name(&self) -> &str {
        BACKEND_NAME
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
        build_otlp_metrics_request(&self.collector_endpoint, snapshot)
            .map(|request| Some(self.authorize(request)))
    }

    fn traces_request(
        &self,
        service_name: &str,
        spans: &[OtlpSpanRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError> {
        if spans.is_empty() || !self.supports(ObservabilitySignal::Trace) {
            return Ok(None);
        }
        build_otlp_traces_request(&self.collector_endpoint, service_name, spans)
            .map(|request| Some(self.authorize(request)))
    }

    fn logs_request(
        &self,
        service_name: &str,
        logs: &[OtlpLogRecord],
    ) -> Result<Option<OtlpHttpRequest>, ObservabilityConfigError> {
        if logs.is_empty() || !self.supports(ObservabilitySignal::Log) {
            return Ok(None);
        }
        build_otlp_logs_request(&self.collector_endpoint, service_name, logs)
            .map(|request| Some(self.authorize(request)))
    }

    fn validate(&self) -> Result<(), ObservabilityConfigError> {
        // Endpoint scheme/emptiness, via the shared builder checks.
        build_otlp_traces_request(&self.collector_endpoint, "ferrogate", &[])?;

        if self.token.trim().is_empty() {
            return Err(ObservabilityConfigError::MissingCredential {
                exporter: BACKEND_NAME.to_string(),
            });
        }

        // A bearer token on a plaintext connection is a credential disclosure,
        // so http:// is refused -- except to loopback, which keeps
        // `wrangler dev` usable for local collector work.
        if !endpoint_protects_credentials(&self.collector_endpoint) {
            return Err(ObservabilityConfigError::InsecureEndpoint {
                exporter: BACKEND_NAME.to_string(),
                endpoint: self.collector_endpoint.clone(),
            });
        }

        // `send_otlp_http_request` refuses CR/LF at send time; catching it here
        // turns a silent every-5s export failure into a startup error.
        for (name, value) in self.headers() {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                return Err(ObservabilityConfigError::InvalidCredential {
                    exporter: BACKEND_NAME.to_string(),
                });
            }
        }

        Ok(())
    }
}

/// True when a bearer credential can be sent to `endpoint` without exposing
/// it: any https endpoint, or plaintext http to loopback only (which keeps
/// `wrangler dev` usable for local collector work).
///
/// Public so config validation can reject a bad endpoint at startup using the
/// same rule the backend enforces at export time, instead of the two drifting
/// apart.
pub fn endpoint_protects_credentials(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.starts_with("https://") {
        return true;
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return false;
    };
    // Drop path/query/fragment, then any userinfo, leaving `host[:port]`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.strip_prefix('[') {
        // Bracketed IPv6 literal, e.g. `[::1]:8787`.
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
#[path = "cloudflare_test.rs"]
mod cloudflare_test;
