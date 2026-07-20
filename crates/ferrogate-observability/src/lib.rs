// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Logging, metrics, and tracing boundaries.

use serde_json::json;
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

#[derive(Debug, Clone, Default, PartialEq)]
pub struct GatewayMetricsSnapshot {
    pub service_name: String,
    pub request_log_total: u64,
    pub request_error_total: u64,
    pub request_status_totals: Vec<RequestStatusMetric>,
    pub cache_hits_total: u64,
    pub cache_misses_total: u64,
    /// Subset of `cache_hits_total` served by the semantic vector-similarity
    /// layer rather than an exact-match key (issue #273).
    pub semantic_cache_hits_total: u64,
    pub guardrail_match_total: u64,
    pub guardrail_denial_total: u64,
    pub guardrail_redaction_total: u64,
    pub guardrail_detector_error_total: u64,
    pub guardrail_evaluation_total: u64,
    pub guardrail_evaluation_fail_total: u64,
    pub guardrail_evaluation_error_total: u64,
    pub guardrail_evaluation_shadow_total: u64,
    pub guardrail_evidence_persistence_failure_total: u64,
    pub guardrail_policy_cas_conflict_total: u64,
    pub billing_event_total: u64,
    /// Failures durably enqueueing a settled usage event for delivery to the
    /// billing service (issue #151) — distinguishable from successful
    /// enqueues so operators can alert on silently dropped reports.
    pub billing_report_enqueue_failure_total: u64,
    pub tool_call_total: u64,
    pub tool_latency_ms_total: u64,
    pub mcp_identity_resolution_total: u64,
    pub mcp_identity_failure_total: u64,
    pub mcp_identity_refresh_total: u64,
    pub mcp_identity_revocation_total: u64,
    pub mcp_refresh_response_deadline_total: u64,
    pub mcp_refresh_storage_cancellation_total: u64,
    pub mcp_refresh_storage_outcome_unknown_total: u64,
    pub mcp_refresh_late_reconciliation_total: u64,
    pub mcp_identity_error_audit_deadline_total: u64,
    pub postgres_pool_acquire_total: u64,
    pub postgres_pool_acquire_timeout_total: u64,
    pub postgres_pool_acquire_wait_micros_total: u64,
    /// #309 bounded background evidence writer: jobs accepted into the queue.
    pub evidence_writer_enqueued_total: u64,
    /// #309: jobs the writer thread finished persisting (enqueued minus
    /// written = current queue depth).
    pub evidence_writer_written_total: u64,
    /// #309: evidence writes dropped because the queue stayed full past the
    /// bounded enqueue timeout — the alertable overflow-loss signal (billing
    /// events never route through the writer and cannot appear here).
    pub evidence_writer_dropped_total: u64,
    pub token_totals: TokenMetricTotals,
    pub model_provider_totals: Vec<ModelProviderMetricTotal>,
    /// Per-operation MCP ingress counts keyed by the `Mcp-Method`/`Mcp-Name`
    /// routing headers (falling back to the JSON-RPC body), so operators can
    /// route/alert per MCP method and tool without parsing bodies (issue #277).
    pub mcp_method_totals: Vec<McpMethodMetricTotal>,
    /// Requests rejected pre-authentication for not matching a configured
    /// `network_access.ip_allowlist` (issue #166).
    pub network_access_denied_total: u64,
    /// Requests rejected pre-authentication for exceeding
    /// `network_access.unauthenticated_rate_limit_per_minute` (issue #166).
    pub network_access_rate_limited_total: u64,
    /// Asset versions scanned by the lifecycle retention/GC sweeper (issue
    /// #263).
    pub asset_lifecycle_scanned_total: u64,
    /// Asset versions + unreferenced blobs pruned/collected by the lifecycle
    /// sweeper (issue #263). In `dry_run` mode this stays 0 (nothing deleted).
    pub asset_lifecycle_pruned_total: u64,
    /// Lifecycle prune/GC operations that failed (a bucket or registry delete
    /// error), so an operator can alert on a stuck sweeper (issue #263).
    pub asset_lifecycle_failed_total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestStatusMetric {
    pub status_code: u16,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenMetricTotals {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProviderMetricTotal {
    pub logical_model: String,
    pub provider: String,
    pub requests: u64,
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpMethodMetricTotal {
    pub method: String,
    /// Operation target (tool name for `tools/call`); empty for methods that
    /// carry no name.
    pub name: String,
    pub requests: u64,
}

pub fn render_prometheus_text(snapshot: &GatewayMetricsSnapshot) -> String {
    let mut output = String::new();
    let service = escape_label_value(&snapshot.service_name);

    push_help(
        &mut output,
        "ferrogate_info",
        "FerroGate process metadata.",
        "gauge",
    );
    output.push_str(&format!("ferrogate_info{{service=\"{service}\"}} 1\n"));

    push_help(
        &mut output,
        "ferrogate_request_logs_total",
        "Total structured request logs recorded by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_request_logs_total {}\n",
        snapshot.request_log_total
    ));

    push_help(
        &mut output,
        "ferrogate_request_errors_total",
        "Total structured request logs with errors or 4xx/5xx statuses.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_request_errors_total {}\n",
        snapshot.request_error_total
    ));

    push_help(
        &mut output,
        "ferrogate_request_status_total",
        "Structured request logs grouped by HTTP status code.",
        "counter",
    );
    for status in &snapshot.request_status_totals {
        output.push_str(&format!(
            "ferrogate_request_status_total{{status_code=\"{}\"}} {}\n",
            status.status_code, status.count
        ));
    }

    push_help(
        &mut output,
        "ferrogate_billing_events_total",
        "Total token metering events recorded by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_billing_events_total {}\n",
        snapshot.billing_event_total
    ));

    push_help(
        &mut output,
        "ferrogate_billing_report_enqueue_failures_total",
        "Total failures durably enqueueing a settled usage event for delivery to the billing service (issue #151).",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_billing_report_enqueue_failures_total {}\n",
        snapshot.billing_report_enqueue_failure_total
    ));

    push_help(
        &mut output,
        "ferrogate_mcp_tool_calls_total",
        "Total MCP tool calls executed by FerroGate.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_tool_calls_total {}\n",
        snapshot.tool_call_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_tool_latency_ms_total",
        "Total MCP tool execution latency in milliseconds.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_tool_latency_ms_total {}\n",
        snapshot.tool_latency_ms_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_resolutions_total",
        "Total per-request MCP identity resolution attempts.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_resolutions_total {}\n",
        snapshot.mcp_identity_resolution_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_failures_total",
        "Total MCP identity resolution attempts rejected before dispatch.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_failures_total {}\n",
        snapshot.mcp_identity_failure_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_refreshes_total",
        "Total successful MCP OAuth credential refreshes.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_refreshes_total {}\n",
        snapshot.mcp_identity_refresh_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_revocations_total",
        "Total locally enforced MCP identity revocations.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_revocations_total {}\n",
        snapshot.mcp_identity_revocation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_response_deadlines_total",
        "Total MCP refresh storage operations that crossed the caller response deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_response_deadlines_total {}\n",
        snapshot.mcp_refresh_response_deadline_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_storage_cancellations_total",
        "Total MCP refresh storage operations fenced before commit.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_storage_cancellations_total {}\n",
        snapshot.mcp_refresh_storage_cancellation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_storage_outcome_unknown_total",
        "Total MCP refresh storage operations whose final outcome could not be proven in time.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_storage_outcome_unknown_total {}\n",
        snapshot.mcp_refresh_storage_outcome_unknown_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_refresh_late_reconciliations_total",
        "Total MCP refresh storage outcomes reconciled after the response deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_refresh_late_reconciliations_total {}\n",
        snapshot.mcp_refresh_late_reconciliation_total
    ));
    push_help(
        &mut output,
        "ferrogate_mcp_identity_error_audit_deadlines_total",
        "Total MCP identity error audits fenced before they could delay the original response.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_mcp_identity_error_audit_deadlines_total {}\n",
        snapshot.mcp_identity_error_audit_deadline_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquires_total",
        "Total async PostgreSQL pool acquisition attempts.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquires_total {}\n",
        snapshot.postgres_pool_acquire_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquire_timeouts_total",
        "Total async PostgreSQL pool acquisition attempts that reached their Rust-side deadline.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquire_timeouts_total {}\n",
        snapshot.postgres_pool_acquire_timeout_total
    ));
    push_help(
        &mut output,
        "ferrogate_postgres_pool_acquire_wait_seconds_total",
        "Cumulative time spent waiting for async PostgreSQL pool acquisition.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_postgres_pool_acquire_wait_seconds_total {}\n",
        snapshot.postgres_pool_acquire_wait_micros_total as f64 / 1_000_000.0
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_enqueued_total",
        "Evidence writes (request logs, audit events, agent-run rows) accepted into the bounded background writer queue.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_enqueued_total {}\n",
        snapshot.evidence_writer_enqueued_total
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_written_total",
        "Evidence writes the background writer finished persisting.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_written_total {}\n",
        snapshot.evidence_writer_written_total
    ));
    push_help(
        &mut output,
        "ferrogate_evidence_writer_dropped_total",
        "Evidence writes dropped after the writer queue stayed full past the bounded enqueue timeout.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_evidence_writer_dropped_total {}\n",
        snapshot.evidence_writer_dropped_total
    ));

    push_help(
        &mut output,
        "ferrogate_ai_cache_requests_total",
        "AI response cache lookups grouped by cache status.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"hit\"}} {}\n",
        snapshot.cache_hits_total
    ));
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"miss\"}} {}\n",
        snapshot.cache_misses_total
    ));
    output.push_str(&format!(
        "ferrogate_ai_cache_requests_total{{status=\"semantic_hit\"}} {}\n",
        snapshot.semantic_cache_hits_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_matches_total",
        "Total configured guardrail rule matches.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_matches_total {}\n",
        snapshot.guardrail_match_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_denials_total",
        "Total guardrail matches that blocked a request or response.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_denials_total {}\n",
        snapshot.guardrail_denial_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_redactions_total",
        "Total guardrail matches that redacted response content.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_redactions_total {}\n",
        snapshot.guardrail_redaction_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_detector_errors_total",
        "Total external guardrail detector evaluation errors.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_detector_errors_total {}\n",
        snapshot.guardrail_detector_error_total
    ));

    push_help(
        &mut output,
        "ferrogate_guardrail_evaluations_total",
        "Guardrail policy evaluations grouped by bounded verdict class.",
        "counter",
    );
    let pass_total = snapshot
        .guardrail_evaluation_total
        .saturating_sub(snapshot.guardrail_evaluation_fail_total)
        .saturating_sub(snapshot.guardrail_evaluation_error_total);
    for (verdict, count) in [
        ("pass", pass_total),
        ("fail", snapshot.guardrail_evaluation_fail_total),
        ("error", snapshot.guardrail_evaluation_error_total),
    ] {
        output.push_str(&format!(
            "ferrogate_guardrail_evaluations_total{{verdict=\"{verdict}\"}} {count}\n"
        ));
    }
    push_help(
        &mut output,
        "ferrogate_guardrail_shadow_evaluations_total",
        "Guardrail evaluations that were shadow-only or not enforced.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_shadow_evaluations_total {}\n",
        snapshot.guardrail_evaluation_shadow_total
    ));
    push_help(
        &mut output,
        "ferrogate_guardrail_evidence_persistence_failures_total",
        "Failures persisting sanitized Guardrail evaluation evidence.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_evidence_persistence_failures_total {}\n",
        snapshot.guardrail_evidence_persistence_failure_total
    ));
    push_help(
        &mut output,
        "ferrogate_guardrail_policy_cas_conflicts_total",
        "Guardrail policy binding writes rejected by optimistic generation comparison.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_guardrail_policy_cas_conflicts_total {}\n",
        snapshot.guardrail_policy_cas_conflict_total
    ));

    push_help(
        &mut output,
        "ferrogate_network_access_denied_total",
        "Total requests rejected pre-authentication for not matching the configured IP allowlist.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_network_access_denied_total {}\n",
        snapshot.network_access_denied_total
    ));

    push_help(
        &mut output,
        "ferrogate_network_access_rate_limited_total",
        "Total requests rejected pre-authentication for exceeding the unauthenticated per-source-IP rate limit.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_network_access_rate_limited_total {}\n",
        snapshot.network_access_rate_limited_total
    ));

    // #263: asset lifecycle sweeper (version retention + unreferenced-blob GC).
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_scanned_total",
        "Total asset versions scanned by the lifecycle retention/GC sweeper.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_scanned_total {}\n",
        snapshot.asset_lifecycle_scanned_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_pruned_total",
        "Total asset versions and unreferenced blobs pruned/collected by the lifecycle sweeper.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_pruned_total {}\n",
        snapshot.asset_lifecycle_pruned_total
    ));
    push_help(
        &mut output,
        "ferrogate_asset_lifecycle_failed_total",
        "Total lifecycle prune/GC delete operations that failed.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_asset_lifecycle_failed_total {}\n",
        snapshot.asset_lifecycle_failed_total
    ));

    push_help(
        &mut output,
        "ferrogate_tokens_total",
        "Total AI provider token usage recorded by metering events.",
        "counter",
    );
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"prompt\"}} {}\n",
        snapshot.token_totals.prompt_tokens
    ));
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"completion\"}} {}\n",
        snapshot.token_totals.completion_tokens
    ));
    output.push_str(&format!(
        "ferrogate_tokens_total{{type=\"total\"}} {}\n",
        snapshot.token_totals.total_tokens
    ));

    push_help(
        &mut output,
        "ferrogate_model_provider_requests_total",
        "Billing events grouped by logical model and provider.",
        "counter",
    );
    for total in &snapshot.model_provider_totals {
        let logical_model = escape_label_value(&total.logical_model);
        let provider = escape_label_value(&total.provider);
        output.push_str(&format!(
            "ferrogate_model_provider_requests_total{{logical_model=\"{logical_model}\",provider=\"{provider}\"}} {}\n",
            total.requests
        ));
    }

    push_help(
        &mut output,
        "ferrogate_model_provider_tokens_total",
        "Billing event token usage grouped by logical model and provider.",
        "counter",
    );
    for total in &snapshot.model_provider_totals {
        let logical_model = escape_label_value(&total.logical_model);
        let provider = escape_label_value(&total.provider);
        output.push_str(&format!(
            "ferrogate_model_provider_tokens_total{{logical_model=\"{logical_model}\",provider=\"{provider}\"}} {}\n",
            total.total_tokens
        ));
    }

    push_help(
        &mut output,
        "ferrogate_mcp_requests_total",
        "MCP ingress requests grouped by Mcp-Method routing header and target name.",
        "counter",
    );
    for total in &snapshot.mcp_method_totals {
        let method = escape_label_value(&total.method);
        let name = escape_label_value(&total.name);
        output.push_str(&format!(
            "ferrogate_mcp_requests_total{{method=\"{method}\",name=\"{name}\"}} {}\n",
            total.requests
        ));
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpHttpRequest {
    pub method: &'static str,
    pub url: String,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// Extra request headers `(name, value)` emitted after the standard
    /// Host/Connection/Content-Type/Content-Length headers. Lets callers carry
    /// e.g. an HMAC signature + timestamp so a webhook receiver can authenticate
    /// the payload (issue #228). Values must not contain CR/LF.
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpAttribute {
    pub key: String,
    pub value: String,
}

impl OtlpAttribute {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpSpanRecord {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub start_time_unix_nano: u64,
    pub end_time_unix_nano: u64,
    pub attributes: Vec<OtlpAttribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpLogRecord {
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub severity_text: String,
    pub body: String,
    pub time_unix_nano: u64,
    pub attributes: Vec<OtlpAttribute>,
}

pub fn build_otlp_metrics_request(
    endpoint: &str,
    snapshot: &GatewayMetricsSnapshot,
) -> Result<OtlpHttpRequest, ObservabilityConfigError> {
    let body = json!({
        "resourceMetrics": [{
            "resource": resource_json(&snapshot.service_name),
            "scopeMetrics": [{
                "scope": instrumentation_scope_json(),
                "metrics": gateway_metrics_json(snapshot),
            }]
        }]
    });
    build_otlp_request(endpoint, "/v1/metrics", body)
}

pub fn build_otlp_traces_request(
    endpoint: &str,
    service_name: &str,
    spans: &[OtlpSpanRecord],
) -> Result<OtlpHttpRequest, ObservabilityConfigError> {
    let body = json!({
        "resourceSpans": [{
            "resource": resource_json(service_name),
            "scopeSpans": [{
                "scope": instrumentation_scope_json(),
                "spans": spans.iter().map(span_json).collect::<Vec<_>>(),
            }]
        }]
    });
    build_otlp_request(endpoint, "/v1/traces", body)
}

pub fn build_otlp_logs_request(
    endpoint: &str,
    service_name: &str,
    logs: &[OtlpLogRecord],
) -> Result<OtlpHttpRequest, ObservabilityConfigError> {
    let body = json!({
        "resourceLogs": [{
            "resource": resource_json(service_name),
            "scopeLogs": [{
                "scope": instrumentation_scope_json(),
                "logRecords": logs.iter().map(log_json).collect::<Vec<_>>(),
            }]
        }]
    });
    build_otlp_request(endpoint, "/v1/logs", body)
}

fn build_otlp_request(
    endpoint: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<OtlpHttpRequest, ObservabilityConfigError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(ObservabilityConfigError::MissingEndpoint {
            exporter: "otlp".to_string(),
            kind: ObservabilityExporterKind::Otlp,
        });
    }
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(ObservabilityConfigError::InvalidEndpoint {
            exporter: "otlp".to_string(),
            endpoint: endpoint.to_string(),
        });
    }

    Ok(OtlpHttpRequest {
        method: "POST",
        url: format!("{}{}", endpoint.trim_end_matches('/'), path),
        content_type: "application/json",
        body: serde_json::to_vec(&body).expect("OTLP JSON serialization should not fail"),
        headers: Vec::new(),
    })
}

fn resource_json(service_name: &str) -> serde_json::Value {
    json!({
        "attributes": [{
            "key": "service.name",
            "value": {"stringValue": service_name},
        }]
    })
}

fn instrumentation_scope_json() -> serde_json::Value {
    json!({
        "name": "ferrogate",
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn gateway_metrics_json(snapshot: &GatewayMetricsSnapshot) -> Vec<serde_json::Value> {
    let guardrail_pass_total = snapshot
        .guardrail_evaluation_total
        .saturating_sub(snapshot.guardrail_evaluation_fail_total)
        .saturating_sub(snapshot.guardrail_evaluation_error_total);
    let mut metrics = vec![
        sum_metric_json(
            "ferrogate.request_logs",
            "Total structured request logs recorded by FerroGate.",
            snapshot.request_log_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.request_errors",
            "Total structured request logs with errors or 4xx/5xx statuses.",
            snapshot.request_error_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.billing_events",
            "Total token metering events recorded by FerroGate.",
            snapshot.billing_event_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_tool.calls",
            "Total MCP tool calls executed by FerroGate.",
            snapshot.tool_call_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_tool.latency_ms",
            "Total MCP tool execution latency in milliseconds.",
            snapshot.tool_latency_ms_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_identity.resolutions",
            "Total per-request MCP identity resolution attempts.",
            snapshot.mcp_identity_resolution_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_identity.failures",
            "Total MCP identity resolution attempts rejected before dispatch.",
            snapshot.mcp_identity_failure_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_identity.refreshes",
            "Total successful MCP OAuth credential refreshes.",
            snapshot.mcp_identity_refresh_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_identity.revocations",
            "Total locally enforced MCP identity revocations.",
            snapshot.mcp_identity_revocation_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_refresh.response_deadlines",
            "Total MCP refresh storage operations that crossed the caller response deadline.",
            snapshot.mcp_refresh_response_deadline_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_refresh.storage_cancellations",
            "Total MCP refresh storage operations fenced before commit.",
            snapshot.mcp_refresh_storage_cancellation_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_refresh.storage_outcome_unknown",
            "Total MCP refresh storage operations whose final outcome could not be proven in time.",
            snapshot.mcp_refresh_storage_outcome_unknown_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_refresh.late_reconciliations",
            "Total MCP refresh storage outcomes reconciled after the response deadline.",
            snapshot.mcp_refresh_late_reconciliation_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.mcp_identity.error_audit_deadlines",
            "Total MCP identity error audits fenced before they could delay the original response.",
            snapshot.mcp_identity_error_audit_deadline_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.postgres.pool.acquires",
            "Total async PostgreSQL pool acquisition attempts.",
            snapshot.postgres_pool_acquire_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.postgres.pool.acquire_timeouts",
            "Total async PostgreSQL pool acquisition attempts that reached their Rust-side deadline.",
            snapshot.postgres_pool_acquire_timeout_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.postgres.pool.acquire_wait_seconds",
            "Cumulative time spent waiting for async PostgreSQL pool acquisition.",
            snapshot.postgres_pool_acquire_wait_micros_total as f64 / 1_000_000.0,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.ai_cache.requests",
            "AI response cache hits.",
            snapshot.cache_hits_total as f64,
            vec![OtlpAttribute::new("status", "hit")],
        ),
        sum_metric_json(
            "ferrogate.ai_cache.requests",
            "AI response cache misses.",
            snapshot.cache_misses_total as f64,
            vec![OtlpAttribute::new("status", "miss")],
        ),
        sum_metric_json(
            "ferrogate.ai_cache.requests",
            "AI response cache hits served by the semantic similarity layer.",
            snapshot.semantic_cache_hits_total as f64,
            vec![OtlpAttribute::new("status", "semantic_hit")],
        ),
        sum_metric_json(
            "ferrogate.guardrail.matches",
            "Total configured guardrail rule matches.",
            snapshot.guardrail_match_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.denials",
            "Total guardrail matches that blocked a request or response.",
            snapshot.guardrail_denial_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.redactions",
            "Total guardrail matches that redacted response content.",
            snapshot.guardrail_redaction_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.detector_errors",
            "Total external guardrail detector evaluation errors.",
            snapshot.guardrail_detector_error_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.evaluations",
            "Guardrail policy evaluations that passed.",
            guardrail_pass_total as f64,
            vec![OtlpAttribute::new("verdict", "pass")],
        ),
        sum_metric_json(
            "ferrogate.guardrail.evaluations",
            "Guardrail policy evaluations that failed.",
            snapshot.guardrail_evaluation_fail_total as f64,
            vec![OtlpAttribute::new("verdict", "fail")],
        ),
        sum_metric_json(
            "ferrogate.guardrail.evaluations",
            "Guardrail policy evaluations with detector errors.",
            snapshot.guardrail_evaluation_error_total as f64,
            vec![OtlpAttribute::new("verdict", "error")],
        ),
        sum_metric_json(
            "ferrogate.guardrail.shadow_evaluations",
            "Guardrail evaluations that were shadow-only or not enforced.",
            snapshot.guardrail_evaluation_shadow_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.evidence_persistence_failures",
            "Failures persisting Guardrail evaluation evidence.",
            snapshot.guardrail_evidence_persistence_failure_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.guardrail.policy_cas_conflicts",
            "Guardrail policy binding writes rejected by optimistic generation comparison.",
            snapshot.guardrail_policy_cas_conflict_total as f64,
            vec![],
        ),
        sum_metric_json(
            "ferrogate.tokens",
            "Total prompt tokens recorded by metering events.",
            snapshot.token_totals.prompt_tokens as f64,
            vec![OtlpAttribute::new("type", "prompt")],
        ),
        sum_metric_json(
            "ferrogate.tokens",
            "Total completion tokens recorded by metering events.",
            snapshot.token_totals.completion_tokens as f64,
            vec![OtlpAttribute::new("type", "completion")],
        ),
        sum_metric_json(
            "ferrogate.tokens",
            "Total tokens recorded by metering events.",
            snapshot.token_totals.total_tokens as f64,
            vec![OtlpAttribute::new("type", "total")],
        ),
    ];

    for status in &snapshot.request_status_totals {
        metrics.push(sum_metric_json(
            "ferrogate.request_status",
            "Structured request logs grouped by HTTP status code.",
            status.count as f64,
            vec![OtlpAttribute::new(
                "status_code",
                status.status_code.to_string(),
            )],
        ));
    }

    for total in &snapshot.model_provider_totals {
        let attributes = vec![
            OtlpAttribute::new("logical_model", total.logical_model.as_str()),
            OtlpAttribute::new("provider", total.provider.as_str()),
        ];
        metrics.push(sum_metric_json(
            "ferrogate.model_provider_requests",
            "Billing events grouped by logical model and provider.",
            total.requests as f64,
            attributes.clone(),
        ));
        metrics.push(sum_metric_json(
            "ferrogate.model_provider_tokens",
            "Billing event token usage grouped by logical model and provider.",
            total.total_tokens as f64,
            attributes,
        ));
    }

    metrics
}

fn sum_metric_json(
    name: &str,
    description: &str,
    value: f64,
    attributes: Vec<OtlpAttribute>,
) -> serde_json::Value {
    json!({
        "name": name,
        "description": description,
        "sum": {
            "aggregationTemporality": 2,
            "isMonotonic": true,
            "dataPoints": [{
                "asDouble": value,
                "attributes": attributes_json(&attributes),
            }]
        }
    })
}

fn span_json(span: &OtlpSpanRecord) -> serde_json::Value {
    json!({
        "traceId": span.trace_id,
        "spanId": span.span_id,
        "parentSpanId": span.parent_span_id,
        "name": span.name,
        "kind": 2,
        "startTimeUnixNano": span.start_time_unix_nano.to_string(),
        "endTimeUnixNano": span.end_time_unix_nano.to_string(),
        "attributes": attributes_json(&span.attributes),
    })
}

fn log_json(log: &OtlpLogRecord) -> serde_json::Value {
    json!({
        "timeUnixNano": log.time_unix_nano.to_string(),
        "traceId": log.trace_id,
        "spanId": log.span_id,
        "severityText": log.severity_text,
        "body": {"stringValue": log.body},
        "attributes": attributes_json(&log.attributes),
    })
}

fn attributes_json(attributes: &[OtlpAttribute]) -> Vec<serde_json::Value> {
    attributes
        .iter()
        .map(|attribute| {
            json!({
                "key": attribute.key,
                "value": {"stringValue": attribute.value},
            })
        })
        .collect()
}

fn push_help(output: &mut String, metric: &str, help: &str, kind: &str) {
    output.push_str(&format!("# HELP {metric} {help}\n"));
    output.push_str(&format!("# TYPE {metric} {kind}\n"));
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
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
    "ferrogate.metering.write",
    GatewaySpanKind::BillingWrite,
    &[
        "request_id",
        "organization_id",
        "project_id",
        "api_key_id",
        "logical_model",
        "provider",
        "total_tokens",
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
#[path = "lib_test.rs"]
mod lib_test;
