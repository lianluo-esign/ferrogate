// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! OTLP/HTTP export: span/log record types and JSON request builders for
//! metrics, traces, and logs.

use crate::config::{ObservabilityConfigError, ObservabilityExporterKind};
use crate::metrics::GatewayMetricsSnapshot;
use serde_json::json;

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
