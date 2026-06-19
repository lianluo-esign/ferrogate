// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_billing::BillingEvent;
use ferrogate_observability::{
    build_otlp_logs_request, build_otlp_metrics_request, build_otlp_traces_request, OtlpAttribute,
    OtlpHttpRequest, OtlpLogRecord, OtlpSpanRecord,
};
use ferrogate_storage::{StoredAuditEvent, StoredRequestLog, StoredUsageAggregate};
use http::{StatusCode, Uri};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::Serialize;
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, OnceLock},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, warn};

use crate::state::AppState;

const OTLP_EXPORT_INTERVAL: Duration = Duration::from_secs(5);

pub(crate) fn start_otlp_background_sender(state: AppState) -> Option<JoinHandle<()>> {
    let endpoint = state.otlp_endpoint()?;
    let timeout = Duration::from_secs(state.otlp_timeout_secs());

    Some(thread::spawn(move || {
        debug!(endpoint = %endpoint, "OTLP background sender started");
        let mut exported_request_logs = 0;
        let mut exported_audit_events = 0;
        let mut exported_billing_events = 0;
        loop {
            match export_otlp_once_since(
                &state,
                &endpoint,
                timeout,
                &mut exported_request_logs,
                &mut exported_audit_events,
                &mut exported_billing_events,
            ) {
                Ok(()) => state.record_observability_export_success(),
                Err(error) => {
                    state.record_observability_export_error(error.to_string());
                    warn!(error = ?error, "OTLP export failed");
                }
            }
            thread::sleep(OTLP_EXPORT_INTERVAL);
        }
    }))
}

pub(crate) fn start_analytics_background_sender(state: AppState) -> Option<JoinHandle<()>> {
    let sink = AnalyticsSink::from_state(&state)?;
    let timeout = Duration::from_secs(state.analytics_timeout_secs());
    let interval = Duration::from_millis(state.analytics_flush_interval_millis());
    let batch_max_events = state.analytics_batch_max_events();

    Some(thread::spawn(move || {
        debug!(sink = ?sink, "analytics sender started");
        let mut exported_request_logs = 0;
        let mut exported_audit_events = 0;
        let mut exported_billing_events = 0;
        let mut exported_usage_aggregates = 0;
        loop {
            match export_analytics_once_since(
                &state,
                &sink,
                timeout,
                batch_max_events,
                &mut exported_request_logs,
                &mut exported_audit_events,
                &mut exported_billing_events,
                &mut exported_usage_aggregates,
            ) {
                Ok(()) => state.record_analytics_export_success(),
                Err(error) => {
                    state.record_analytics_export_error(error.to_string());
                    warn!(error = ?error, "analytics export failed");
                }
            }
            thread::sleep(interval.max(Duration::from_millis(100)));
        }
    }))
}

#[cfg(test)]
pub(crate) fn export_otlp_once(state: &AppState, endpoint: &str) -> AnyResult<()> {
    let timeout = Duration::from_secs(state.otlp_timeout_secs());
    let snapshot = state.prometheus_metrics_snapshot();
    dispatch_otlp_request(&build_otlp_metrics_request(endpoint, &snapshot)?, timeout)?;

    let request_logs = state.request_logs();
    let audit_events = state.audit_events();
    let billing_events = state.metering_events();
    let log_records = runtime_events_as_otlp_logs(&request_logs, &audit_events, &billing_events);
    if !log_records.is_empty() {
        dispatch_otlp_request(
            &build_otlp_logs_request(endpoint, &snapshot.service_name, &log_records)?,
            timeout,
        )?;
    }
    if !request_logs.is_empty() {
        dispatch_otlp_request(
            &build_otlp_traces_request(
                endpoint,
                &snapshot.service_name,
                &request_logs_as_otlp_spans(&request_logs),
            )?,
            timeout,
        )?;
    }

    Ok(())
}

fn export_otlp_once_since(
    state: &AppState,
    endpoint: &str,
    timeout: Duration,
    exported_request_logs: &mut usize,
    exported_audit_events: &mut usize,
    exported_billing_events: &mut usize,
) -> AnyResult<()> {
    let snapshot = state.prometheus_metrics_snapshot();
    dispatch_otlp_request(&build_otlp_metrics_request(endpoint, &snapshot)?, timeout)?;

    let request_logs = state.request_logs();
    let new_logs = request_logs
        .get(*exported_request_logs..)
        .unwrap_or_default()
        .to_vec();
    let audit_events = state.audit_events();
    let new_audit_events = audit_events
        .get(*exported_audit_events..)
        .unwrap_or_default()
        .to_vec();
    let billing_events = state.metering_events();
    let new_billing_events = billing_events
        .get(*exported_billing_events..)
        .unwrap_or_default()
        .to_vec();
    let log_records =
        runtime_events_as_otlp_logs(&new_logs, &new_audit_events, &new_billing_events);
    if !log_records.is_empty() {
        dispatch_otlp_request(
            &build_otlp_logs_request(endpoint, &snapshot.service_name, &log_records)?,
            timeout,
        )?;
        *exported_audit_events = audit_events.len();
        *exported_billing_events = billing_events.len();
    }
    if !new_logs.is_empty() {
        dispatch_otlp_request(
            &build_otlp_traces_request(
                endpoint,
                &snapshot.service_name,
                &request_logs_as_otlp_spans(&new_logs),
            )?,
            timeout,
        )?;
        *exported_request_logs = request_logs.len();
    }

    Ok(())
}

fn export_analytics_once_since(
    state: &AppState,
    sink: &AnalyticsSink,
    timeout: Duration,
    batch_max_events: usize,
    exported_request_logs: &mut usize,
    exported_audit_events: &mut usize,
    exported_billing_events: &mut usize,
    exported_usage_aggregates: &mut usize,
) -> AnyResult<()> {
    let request_logs = state.request_logs();
    let audit_events = state.audit_events();
    let billing_events = state.metering_events();
    let usage_aggregates = state.usage_aggregates();

    let mut records = Vec::new();
    records.extend(
        request_logs
            .get(*exported_request_logs..)
            .unwrap_or_default()
            .iter()
            .flat_map(|log| {
                [
                    AnalyticsRecord::from_request_log(log),
                    AnalyticsRecord::from_trace_span(log),
                ]
            }),
    );
    records.extend(
        audit_events
            .get(*exported_audit_events..)
            .unwrap_or_default()
            .iter()
            .map(AnalyticsRecord::from_audit_event),
    );
    records.extend(
        billing_events
            .get(*exported_billing_events..)
            .unwrap_or_default()
            .iter()
            .map(AnalyticsRecord::from_billing_event),
    );
    records.extend(
        usage_aggregates
            .get(*exported_usage_aggregates..)
            .unwrap_or_default()
            .iter()
            .map(AnalyticsRecord::from_usage_aggregate),
    );

    if records.is_empty() {
        return Ok(());
    }

    for chunk in records.chunks(batch_max_events.max(1)) {
        dispatch_analytics_records(sink, chunk, timeout)?;
    }
    *exported_request_logs = request_logs.len();
    *exported_audit_events = audit_events.len();
    *exported_billing_events = billing_events.len();
    *exported_usage_aggregates = usage_aggregates.len();
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AnalyticsSink {
    Vector { endpoint: String },
    Clickhouse { base_url: String },
}

impl AnalyticsSink {
    fn from_state(state: &AppState) -> Option<Self> {
        state
            .analytics_vector_endpoint()
            .map(|endpoint| Self::Vector { endpoint })
            .or_else(|| {
                state
                    .analytics_clickhouse_url()
                    .map(|base_url| Self::Clickhouse { base_url })
            })
    }
}

fn dispatch_analytics_records(
    sink: &AnalyticsSink,
    records: &[AnalyticsRecord],
    timeout: Duration,
) -> AnyResult<()> {
    match sink {
        AnalyticsSink::Vector { endpoint } => dispatch_ndjson_request(endpoint, records, timeout),
        AnalyticsSink::Clickhouse { base_url } => {
            for table in CLICKHOUSE_ANALYTICS_TABLES {
                let table_records = records
                    .iter()
                    .filter(|record| record.clickhouse_table() == *table)
                    .collect::<Vec<_>>();
                if table_records.is_empty() {
                    continue;
                }
                dispatch_ndjson_request(
                    &clickhouse_insert_url(base_url, table),
                    &table_records,
                    timeout,
                )?;
            }
            Ok(())
        }
    }
}

const CLICKHOUSE_ANALYTICS_TABLES: &[&str] = &[
    "ferrogate.ferrogate_request_logs",
    "ferrogate.ferrogate_trace_spans",
    "ferrogate.ferrogate_audit_timeline",
    "ferrogate.ferrogate_billing_metering_events",
    "ferrogate.ferrogate_usage_metrics",
];

fn clickhouse_insert_url(base_url: &str, table: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let query = format!("INSERT INTO {table} FORMAT JSONEachRow");
    format!(
        "{base}/?input_format_skip_unknown_fields=1&query={}",
        percent_encode_query_value(&query)
    )
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[derive(Debug, Serialize)]
struct AnalyticsRecord {
    event_kind: &'static str,
    event_time_unix: u64,
    request_id: String,
    trace_id: String,
    tenant_id: String,
    organization_id: String,
    project_id: String,
    api_key_id: String,
    route: String,
    provider: String,
    logical_model: String,
    provider_model: String,
    method: String,
    path: String,
    status_code: u16,
    latency_ms: u64,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    request_count: u64,
    error_count: u64,
    cost_microusd: u64,
    cache_status: String,
    error_code: String,
    event_id: String,
    subject: String,
    action: String,
    target_kind: String,
    target_id: String,
    outcome: String,
    service_name: String,
    span_name: String,
    span_kind: String,
    span_id: String,
    parent_span_id: String,
    duration_ms: u64,
    idempotency_key: String,
    document_json: String,
}

impl AnalyticsRecord {
    fn clickhouse_table(&self) -> &'static str {
        match self.event_kind {
            "request_log" => "ferrogate.ferrogate_request_logs",
            "trace_span" => "ferrogate.ferrogate_trace_spans",
            "audit_event" => "ferrogate.ferrogate_audit_timeline",
            "billing_metering_event" => "ferrogate.ferrogate_billing_metering_events",
            "usage_metric" => "ferrogate.ferrogate_usage_metrics",
            _ => "ferrogate.ferrogate_request_logs",
        }
    }

    fn from_request_log(log: &StoredRequestLog) -> Self {
        let started = log.started_at_unix.unwrap_or_else(now_unix_seconds);
        let completed = log.completed_at_unix.unwrap_or(started);
        let tenant_id = tenant_id(
            log.tenant.organization_id.as_deref(),
            log.tenant.project_id.as_deref(),
            log.tenant.api_key_id.as_deref(),
        );
        Self {
            event_kind: "request_log",
            event_time_unix: completed,
            request_id: log.request_id.clone(),
            trace_id: log.trace_id.clone().unwrap_or_default(),
            tenant_id,
            organization_id: log.tenant.organization_id.clone().unwrap_or_default(),
            project_id: log.tenant.project_id.clone().unwrap_or_default(),
            api_key_id: log.tenant.api_key_id.clone().unwrap_or_default(),
            route: log.route.clone().unwrap_or_default(),
            provider: log.provider.clone().unwrap_or_default(),
            logical_model: log.logical_model.clone().unwrap_or_default(),
            provider_model: log.provider_model.clone().unwrap_or_default(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status_code: log.status_code,
            latency_ms: completed.saturating_sub(started).saturating_mul(1_000),
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            request_count: 1,
            error_count: u64::from(log.status_code >= 400 || log.error_code.is_some()),
            cost_microusd: 0,
            cache_status: log.cache_status.clone().unwrap_or_default(),
            error_code: log.error_code.clone().unwrap_or_default(),
            event_id: log.request_id.clone(),
            subject: log.tenant.api_key_id.clone().unwrap_or_default(),
            action: String::new(),
            target_kind: String::new(),
            target_id: String::new(),
            outcome: if log.status_code >= 400 {
                "error"
            } else {
                "success"
            }
            .into(),
            service_name: "ferrogate".into(),
            span_name: "ferrogate.gateway.request".into(),
            span_kind: "server".into(),
            span_id: stable_span_id(&log.request_id),
            parent_span_id: String::new(),
            duration_ms: completed.saturating_sub(started).saturating_mul(1_000),
            idempotency_key: log.request_id.clone(),
            document_json: sanitized_request_log_json(log),
        }
    }

    fn from_trace_span(log: &StoredRequestLog) -> Self {
        let started = log.started_at_unix.unwrap_or_else(now_unix_seconds);
        let completed = log.completed_at_unix.unwrap_or(started);
        let tenant_id = tenant_id(
            log.tenant.organization_id.as_deref(),
            log.tenant.project_id.as_deref(),
            log.tenant.api_key_id.as_deref(),
        );
        Self {
            event_kind: "trace_span",
            event_time_unix: started,
            request_id: log.request_id.clone(),
            trace_id: stable_trace_id(log.trace_id.as_deref().unwrap_or(&log.request_id)),
            tenant_id,
            organization_id: log.tenant.organization_id.clone().unwrap_or_default(),
            project_id: log.tenant.project_id.clone().unwrap_or_default(),
            api_key_id: log.tenant.api_key_id.clone().unwrap_or_default(),
            route: log.route.clone().unwrap_or_default(),
            provider: log.provider.clone().unwrap_or_default(),
            logical_model: log.logical_model.clone().unwrap_or_default(),
            provider_model: log.provider_model.clone().unwrap_or_default(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status_code: log.status_code,
            latency_ms: completed.saturating_sub(started).saturating_mul(1_000),
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            request_count: 1,
            error_count: u64::from(log.status_code >= 400 || log.error_code.is_some()),
            cost_microusd: 0,
            cache_status: log.cache_status.clone().unwrap_or_default(),
            error_code: log.error_code.clone().unwrap_or_default(),
            event_id: log.request_id.clone(),
            subject: log.tenant.api_key_id.clone().unwrap_or_default(),
            action: String::new(),
            target_kind: String::new(),
            target_id: String::new(),
            outcome: if log.status_code >= 400 {
                "error"
            } else {
                "success"
            }
            .into(),
            service_name: "ferrogate".into(),
            span_name: "ferrogate.gateway.request".into(),
            span_kind: "server".into(),
            span_id: stable_span_id(&log.request_id),
            parent_span_id: String::new(),
            duration_ms: completed.saturating_sub(started).saturating_mul(1_000),
            idempotency_key: log.request_id.clone(),
            document_json: sanitized_request_log_json(log),
        }
    }

    fn from_audit_event(event: &StoredAuditEvent) -> Self {
        let event_time = event.occurred_at_unix.unwrap_or_else(now_unix_seconds);
        let (target_kind, target_id) = split_target(&event.target);
        let tenant_id = tenant_id(
            event.tenant.organization_id.as_deref(),
            event.tenant.project_id.as_deref(),
            event.tenant.api_key_id.as_deref(),
        );
        Self {
            event_kind: "audit_event",
            event_time_unix: event_time,
            request_id: event.request_id.clone(),
            trace_id: event.trace_id.clone().unwrap_or_default(),
            tenant_id,
            organization_id: event.tenant.organization_id.clone().unwrap_or_default(),
            project_id: event.tenant.project_id.clone().unwrap_or_default(),
            api_key_id: event.tenant.api_key_id.clone().unwrap_or_default(),
            route: String::new(),
            provider: String::new(),
            logical_model: String::new(),
            provider_model: String::new(),
            method: String::new(),
            path: String::new(),
            status_code: 0,
            latency_ms: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
            request_count: 0,
            error_count: 0,
            cost_microusd: 0,
            cache_status: String::new(),
            error_code: String::new(),
            event_id: event.id.clone(),
            subject: event.actor_api_key_id.clone().unwrap_or_default(),
            action: event.action.clone(),
            target_kind,
            target_id,
            outcome: event.outcome.clone(),
            service_name: "ferrogate".into(),
            span_name: String::new(),
            span_kind: String::new(),
            span_id: String::new(),
            parent_span_id: String::new(),
            duration_ms: 0,
            idempotency_key: event.id.clone(),
            document_json: serde_json::to_string(event).unwrap_or_default(),
        }
    }

    fn from_billing_event(event: &BillingEvent) -> Self {
        let event_time = event.occurred_at_unix.unwrap_or_else(now_unix_seconds);
        let tenant_id = tenant_id(
            event.tenant.organization_id.as_deref(),
            event.tenant.project_id.as_deref(),
            event.tenant.api_key_id.as_deref(),
        );
        let idempotency_key = format!(
            "{}:{}:{}",
            event.request_id, event.logical_model, event.provider
        );
        Self {
            event_kind: "billing_metering_event",
            event_time_unix: event_time,
            request_id: event.request_id.clone(),
            trace_id: event.trace_id.clone().unwrap_or_default(),
            tenant_id,
            organization_id: event.tenant.organization_id.clone().unwrap_or_default(),
            project_id: event.tenant.project_id.clone().unwrap_or_default(),
            api_key_id: event.tenant.api_key_id.clone().unwrap_or_default(),
            route: String::new(),
            provider: event.provider.clone(),
            logical_model: event.logical_model.clone(),
            provider_model: event.provider_model.clone(),
            method: String::new(),
            path: String::new(),
            status_code: event.status_code,
            latency_ms: 0,
            prompt_tokens: event.usage.prompt_tokens,
            completion_tokens: event.usage.completion_tokens,
            total_tokens: event.usage.total_tokens,
            request_count: 1,
            error_count: u64::from(event.status_code >= 400),
            cost_microusd: 0,
            cache_status: String::new(),
            error_code: String::new(),
            event_id: idempotency_key.clone(),
            subject: event.tenant.api_key_id.clone().unwrap_or_default(),
            action: String::new(),
            target_kind: String::new(),
            target_id: String::new(),
            outcome: if event.status_code >= 400 {
                "error"
            } else {
                "success"
            }
            .into(),
            service_name: "ferrogate".into(),
            span_name: String::new(),
            span_kind: String::new(),
            span_id: String::new(),
            parent_span_id: String::new(),
            duration_ms: 0,
            idempotency_key,
            document_json: serde_json::to_string(event).unwrap_or_default(),
        }
    }

    fn from_usage_aggregate(aggregate: &StoredUsageAggregate) -> Self {
        let event_time = now_unix_seconds();
        let tenant_id = tenant_id(
            aggregate.organization_id.as_deref(),
            aggregate.project_id.as_deref(),
            aggregate.api_key_id.as_deref(),
        );
        Self {
            event_kind: "usage_metric",
            event_time_unix: event_time,
            request_id: aggregate.id.clone(),
            trace_id: String::new(),
            tenant_id,
            organization_id: aggregate.organization_id.clone().unwrap_or_default(),
            project_id: aggregate.project_id.clone().unwrap_or_default(),
            api_key_id: aggregate.api_key_id.clone().unwrap_or_default(),
            route: String::new(),
            provider: aggregate.provider.clone(),
            logical_model: aggregate.logical_model.clone(),
            provider_model: String::new(),
            method: String::new(),
            path: String::new(),
            status_code: 0,
            latency_ms: 0,
            prompt_tokens: aggregate.usage.prompt_tokens,
            completion_tokens: aggregate.usage.completion_tokens,
            total_tokens: aggregate.usage.total_tokens,
            request_count: 1,
            error_count: 0,
            cost_microusd: 0,
            cache_status: String::new(),
            error_code: String::new(),
            event_id: aggregate.id.clone(),
            subject: aggregate.api_key_id.clone().unwrap_or_default(),
            action: String::new(),
            target_kind: String::new(),
            target_id: String::new(),
            outcome: "success".into(),
            service_name: "ferrogate".into(),
            span_name: String::new(),
            span_kind: String::new(),
            span_id: String::new(),
            parent_span_id: String::new(),
            duration_ms: 0,
            idempotency_key: aggregate.id.clone(),
            document_json: serde_json::to_string(aggregate).unwrap_or_default(),
        }
    }
}

fn runtime_events_as_otlp_logs(
    request_logs: &[StoredRequestLog],
    audit_events: &[StoredAuditEvent],
    billing_events: &[BillingEvent],
) -> Vec<OtlpLogRecord> {
    let mut records = Vec::with_capacity(
        request_logs
            .len()
            .saturating_add(audit_events.len())
            .saturating_add(billing_events.len()),
    );
    records.extend(request_logs_as_otlp_logs(request_logs));
    records.extend(audit_events_as_otlp_logs(audit_events));
    records.extend(billing_events_as_otlp_logs(billing_events));
    records
}

fn request_logs_as_otlp_logs(logs: &[StoredRequestLog]) -> Vec<OtlpLogRecord> {
    logs.iter()
        .map(|log| OtlpLogRecord {
            trace_id: Some(stable_trace_id(
                log.trace_id.as_deref().unwrap_or(&log.request_id),
            )),
            span_id: Some(stable_span_id(&log.request_id)),
            severity_text: if log.status_code >= 500 {
                "ERROR"
            } else if log.status_code >= 400 {
                "WARN"
            } else {
                "INFO"
            }
            .to_string(),
            body: if let Some(error_code) = &log.error_code {
                format!("request failed: {error_code}")
            } else {
                "request completed".to_string()
            },
            time_unix_nano: unix_seconds_to_nanos(
                log.completed_at_unix
                    .or(log.started_at_unix)
                    .unwrap_or_else(now_unix_seconds),
            ),
            attributes: request_log_attributes(log),
        })
        .collect()
}

fn audit_events_as_otlp_logs(events: &[StoredAuditEvent]) -> Vec<OtlpLogRecord> {
    events
        .iter()
        .map(|event| OtlpLogRecord {
            trace_id: Some(stable_trace_id(
                event.trace_id.as_deref().unwrap_or(&event.request_id),
            )),
            span_id: Some(stable_span_id(&event.id)),
            severity_text: if event.outcome == "success" {
                "INFO"
            } else {
                "WARN"
            }
            .to_string(),
            body: format!("audit event: {}", event.action),
            time_unix_nano: unix_seconds_to_nanos(
                event.occurred_at_unix.unwrap_or_else(now_unix_seconds),
            ),
            attributes: audit_event_attributes(event),
        })
        .collect()
}

fn billing_events_as_otlp_logs(events: &[BillingEvent]) -> Vec<OtlpLogRecord> {
    events
        .iter()
        .map(|event| OtlpLogRecord {
            trace_id: Some(stable_trace_id(
                event.trace_id.as_deref().unwrap_or(&event.request_id),
            )),
            span_id: Some(stable_span_id(&format!(
                "{}:{}:{}",
                event.request_id, event.logical_model, event.provider
            ))),
            severity_text: if event.status_code >= 400 {
                "WARN"
            } else {
                "INFO"
            }
            .to_string(),
            body: "billing event observed".to_string(),
            time_unix_nano: unix_seconds_to_nanos(
                event.occurred_at_unix.unwrap_or_else(now_unix_seconds),
            ),
            attributes: billing_event_attributes(event),
        })
        .collect()
}

fn request_logs_as_otlp_spans(logs: &[StoredRequestLog]) -> Vec<OtlpSpanRecord> {
    logs.iter()
        .map(|log| {
            let start = log.started_at_unix.unwrap_or_else(now_unix_seconds);
            let end = log.completed_at_unix.unwrap_or(start);
            OtlpSpanRecord {
                trace_id: stable_trace_id(log.trace_id.as_deref().unwrap_or(&log.request_id)),
                span_id: stable_span_id(&log.request_id),
                parent_span_id: None,
                name: "ferrogate.gateway.request".to_string(),
                start_time_unix_nano: unix_seconds_to_nanos(start),
                end_time_unix_nano: unix_seconds_to_nanos(end.max(start)),
                attributes: request_log_attributes(log),
            }
        })
        .collect()
}

fn request_log_attributes(log: &StoredRequestLog) -> Vec<OtlpAttribute> {
    let mut attributes = vec![
        OtlpAttribute::new("event_family", "request"),
        OtlpAttribute::new("request_id", log.request_id.as_str()),
        OtlpAttribute::new("status_code", log.status_code.to_string()),
        OtlpAttribute::new("prompt_recorded", log.prompt_recorded.to_string()),
        OtlpAttribute::new("response_recorded", log.response_recorded.to_string()),
    ];

    push_optional_attribute(&mut attributes, "trace_id", log.trace_id.as_deref());
    push_optional_attribute(&mut attributes, "cluster_id", log.cluster_id.as_deref());
    push_optional_attribute(&mut attributes, "node_id", log.node_id.as_deref());
    push_optional_attribute(
        &mut attributes,
        "organization_id",
        log.tenant.organization_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "project_id",
        log.tenant.project_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "api_key_id",
        log.tenant.api_key_id.as_deref(),
    );
    push_optional_attribute(&mut attributes, "route", log.route.as_deref());
    push_optional_attribute(&mut attributes, "provider", log.provider.as_deref());
    push_optional_attribute(
        &mut attributes,
        "logical_model",
        log.logical_model.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "provider_model",
        log.provider_model.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "gateway_config_id",
        log.gateway_config_id.as_deref(),
    );
    if let Some(revision) = log.gateway_config_revision {
        attributes.push(OtlpAttribute::new(
            "gateway_config_revision",
            revision.to_string(),
        ));
    }
    push_optional_attribute(&mut attributes, "error_code", log.error_code.as_deref());

    attributes
}

fn audit_event_attributes(event: &StoredAuditEvent) -> Vec<OtlpAttribute> {
    let mut attributes = vec![
        OtlpAttribute::new("event_family", "audit"),
        OtlpAttribute::new("request_id", event.request_id.as_str()),
        OtlpAttribute::new("audit_action", event.action.as_str()),
        OtlpAttribute::new("audit_target", event.target.as_str()),
        OtlpAttribute::new("audit_outcome", event.outcome.as_str()),
        OtlpAttribute::new("audit_message", event.message.as_str()),
    ];
    push_optional_attribute(&mut attributes, "trace_id", event.trace_id.as_deref());
    push_optional_attribute(&mut attributes, "cluster_id", event.cluster_id.as_deref());
    push_optional_attribute(&mut attributes, "node_id", event.node_id.as_deref());
    push_optional_attribute(
        &mut attributes,
        "api_key_id",
        event.actor_api_key_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "organization_id",
        event.tenant.organization_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "project_id",
        event.tenant.project_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "tenant_api_key_id",
        event.tenant.api_key_id.as_deref(),
    );
    attributes
}

fn billing_event_attributes(event: &BillingEvent) -> Vec<OtlpAttribute> {
    let mut attributes = vec![
        OtlpAttribute::new("event_family", "billing_event_observed"),
        OtlpAttribute::new("request_id", event.request_id.as_str()),
        OtlpAttribute::new("status_code", event.status_code.to_string()),
        OtlpAttribute::new("logical_model", event.logical_model.as_str()),
        OtlpAttribute::new("provider", event.provider.as_str()),
        OtlpAttribute::new("provider_model", event.provider_model.as_str()),
        OtlpAttribute::new("prompt_tokens", event.usage.prompt_tokens.to_string()),
        OtlpAttribute::new(
            "completion_tokens",
            event.usage.completion_tokens.to_string(),
        ),
        OtlpAttribute::new("total_tokens", event.usage.total_tokens.to_string()),
        OtlpAttribute::new("usage_source", format!("{:?}", event.usage_source)),
    ];
    push_optional_attribute(&mut attributes, "trace_id", event.trace_id.as_deref());
    push_optional_attribute(&mut attributes, "cluster_id", event.cluster_id.as_deref());
    push_optional_attribute(&mut attributes, "node_id", event.node_id.as_deref());
    push_optional_attribute(
        &mut attributes,
        "organization_id",
        event.tenant.organization_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "project_id",
        event.tenant.project_id.as_deref(),
    );
    push_optional_attribute(
        &mut attributes,
        "api_key_id",
        event.tenant.api_key_id.as_deref(),
    );
    attributes
}

fn push_optional_attribute(
    attributes: &mut Vec<OtlpAttribute>,
    key: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        attributes.push(OtlpAttribute::new(key, value));
    }
}

fn dispatch_otlp_request(request: &OtlpHttpRequest, timeout: Duration) -> AnyResult<()> {
    let target = parse_otlp_target(&request.url)?;
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .with_context(|| format!("failed to connect OTLP collector {}", target.authority))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    match target.scheme {
        OtlpScheme::Http => send_otlp_http_request(&mut stream, &target, request),
        OtlpScheme::Https => {
            let server_name = ServerName::try_from(target.host.clone())
                .with_context(|| format!("invalid OTLP TLS server name {}", target.host))?;
            let connection = ClientConnection::new(tls_client_config()?, server_name)
                .context("failed to initialize OTLP TLS client")?;
            let mut tls_stream = StreamOwned::new(connection, stream);
            send_otlp_http_request(&mut tls_stream, &target, request)
        }
    }
}

fn send_otlp_http_request<S: Read + Write>(
    stream: &mut S,
    target: &OtlpTarget,
    request: &OtlpHttpRequest,
) -> AnyResult<()> {
    write!(
        stream,
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n",
        request.method,
        target.path_query,
        target.authority,
        request.content_type,
        request.body.len()
    )?;
    stream.write_all(&request.body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let status = parse_response_status(&raw)?;
    if !status.is_success() {
        bail!("OTLP collector returned HTTP {status}");
    }
    Ok(())
}

fn dispatch_ndjson_request<T: Serialize>(
    endpoint: &str,
    records: &[T],
    timeout: Duration,
) -> AnyResult<()> {
    let mut body = Vec::new();
    for record in records {
        serde_json::to_writer(&mut body, record)?;
        body.push(b'\n');
    }
    let request = OtlpHttpRequest {
        method: "POST",
        url: endpoint.to_string(),
        content_type: "application/x-ndjson",
        body,
    };
    dispatch_otlp_request(&request, timeout)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OtlpTarget {
    scheme: OtlpScheme,
    host: String,
    port: u16,
    authority: String,
    path_query: String,
}

fn parse_otlp_target(raw: &str) -> AnyResult<OtlpTarget> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid OTLP endpoint {raw}"))?;
    let scheme = match uri.scheme_str() {
        Some("http") => OtlpScheme::Http,
        Some("https") => OtlpScheme::Https,
        Some(other) => bail!("OTLP exporter supports http and https endpoints only, got {other}"),
        None => bail!("OTLP endpoint must include scheme"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("OTLP endpoint must include authority"))?;
    let host = authority.host().to_string();
    let default_port = match scheme {
        OtlpScheme::Http => 80,
        OtlpScheme::Https => 443,
    };
    let port = authority.port_u16().unwrap_or(default_port);
    let authority = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    Ok(OtlpTarget {
        scheme,
        host,
        port,
        authority,
        path_query,
    })
}

fn parse_response_status(raw: &[u8]) -> AnyResult<StatusCode> {
    let split = raw
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| anyhow::anyhow!("OTLP collector response missing status line"))?;
    let status_line = String::from_utf8_lossy(&raw[..split]);
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("OTLP collector response missing status code"))?
        .parse::<u16>()
        .context("OTLP collector response has invalid status code")?;
    StatusCode::from_u16(status_code).context("OTLP collector returned invalid status")
}

fn tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS_CLIENT_CONFIG.get() {
        return Ok(Arc::clone(config));
    }

    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        anyhow::bail!(
            "failed to load platform native certificates: {:?}",
            native_certs.errors
        );
    }
    for cert in native_certs.certs {
        roots
            .add(cert)
            .context("failed to add platform native certificate")?;
    }

    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let _ = TLS_CLIENT_CONFIG.set(Arc::clone(&config));
    Ok(TLS_CLIENT_CONFIG.get().map(Arc::clone).unwrap_or(config))
}

fn stable_trace_id(value: &str) -> String {
    format!(
        "{:016x}{:016x}",
        fnv1a64(value.as_bytes(), 0),
        fnv1a64(value.as_bytes(), 1)
    )
}

fn stable_span_id(value: &str) -> String {
    format!("{:016x}", fnv1a64(value.as_bytes(), 2))
}

fn fnv1a64(bytes: &[u8], salt: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64 ^ salt;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn unix_seconds_to_nanos(seconds: u64) -> u64 {
    seconds.saturating_mul(1_000_000_000)
}

fn tenant_id(
    organization_id: Option<&str>,
    project_id: Option<&str>,
    api_key_id: Option<&str>,
) -> String {
    organization_id
        .or(project_id)
        .or(api_key_id)
        .unwrap_or("")
        .to_string()
}

fn split_target(target: &str) -> (String, String) {
    target
        .split_once(':')
        .map(|(kind, id)| (kind.to_string(), id.to_string()))
        .unwrap_or_else(|| (target.to_string(), String::new()))
}

fn sanitized_request_log_json(log: &StoredRequestLog) -> String {
    let mut sanitized = log.clone();
    sanitized.prompt_body = None;
    sanitized.response_body = None;
    serde_json::to_string(&sanitized).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, state::AppState};
    use ferrogate_core::TenantContext;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    #[test]
    fn otlp_export_once_posts_metrics_logs_and_traces_without_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_bodies = Arc::clone(&bodies);

        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut raw = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(body) = http_body_if_complete(&raw) {
                        server_bodies
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(body).to_string());
                        break;
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            }
        });

        let state = AppState::new(Config::default());
        state.record_request_log(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: true,
            response_recorded: true,
            prompt_body: Some("client-secret prompt".into()),
            response_body: Some("provider-secret response".into()),
            cache_status: None,
            started_at_unix: Some(1),
            completed_at_unix: Some(2),
        });
        state.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            actor_api_key_id: Some("key".into()),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            action: "policy.deny".into(),
            target: "policy:block-secret".into(),
            outcome: "error".into(),
            message: "policy denied request".into(),
        });
        state
            .record_estimated_billing_event(
                &ferrogate_core::RequestContext {
                    request_id: "fg-1".into(),
                    trace_id: Some("fg-1".into()),
                    tenant: TenantContext {
                        organization_id: Some("org".into()),
                        project_id: Some("project".into()),
                        api_key_id: Some("key".into()),
                        ..TenantContext::default()
                    },
                    ..ferrogate_core::RequestContext::default()
                },
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ferrogate_billing::TokenUsage::new(1, 2, 3),
                200,
            )
            .unwrap();

        export_otlp_once(&state, &endpoint).unwrap();
        server.join().unwrap();

        let bodies = bodies.lock().unwrap().join("\n");
        assert!(bodies.contains("resourceMetrics"));
        assert!(bodies.contains("resourceLogs"));
        assert!(bodies.contains("resourceSpans"));
        assert!(bodies.contains("ferrogate.gateway.request"));
        assert!(bodies.contains("event_family"));
        assert!(bodies.contains("request"));
        assert!(bodies.contains("audit"));
        assert!(bodies.contains("billing_event_observed"));
        assert!(bodies.contains("policy.deny"));
        assert!(bodies.contains("total_tokens"));
        assert!(bodies.contains("fast-chat"));
        assert!(!bodies.contains("client-secret prompt"));
        assert!(!bodies.contains("provider-secret response"));
    }

    #[test]
    fn analytics_export_posts_flat_ndjson_events_without_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_bodies = Arc::clone(&bodies);

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
                if let Some(body) = http_body_if_complete(&raw) {
                    server_bodies
                        .lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(body).to_string());
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });

        let state = AppState::new(Config::default());
        state.record_request_log(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: true,
            response_recorded: true,
            prompt_body: Some("client-secret prompt".into()),
            response_body: Some("provider-secret response".into()),
            cache_status: None,
            started_at_unix: Some(1),
            completed_at_unix: Some(2),
        });
        state.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            actor_api_key_id: Some("key".into()),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            action: "policy.deny".into(),
            target: "policy:block-secret".into(),
            outcome: "error".into(),
            message: "policy denied request".into(),
        });
        state
            .record_estimated_billing_event(
                &ferrogate_core::RequestContext {
                    request_id: "fg-1".into(),
                    trace_id: Some("fg-1".into()),
                    tenant: TenantContext {
                        organization_id: Some("org".into()),
                        project_id: Some("project".into()),
                        api_key_id: Some("key".into()),
                        ..TenantContext::default()
                    },
                    ..ferrogate_core::RequestContext::default()
                },
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ferrogate_billing::TokenUsage::new(1, 2, 3),
                200,
            )
            .unwrap();

        let mut exported_request_logs = 0;
        let mut exported_audit_events = 0;
        let mut exported_billing_events = 0;
        let mut exported_usage_aggregates = 0;
        export_analytics_once_since(
            &state,
            &AnalyticsSink::Vector { endpoint },
            Duration::from_secs(3),
            128,
            &mut exported_request_logs,
            &mut exported_audit_events,
            &mut exported_billing_events,
            &mut exported_usage_aggregates,
        )
        .unwrap();
        server.join().unwrap();

        let bodies = bodies.lock().unwrap().join("\n");
        assert!(bodies.contains("\"event_kind\":\"request_log\""));
        assert!(bodies.contains("\"event_kind\":\"trace_span\""));
        assert!(bodies.contains("\"event_kind\":\"audit_event\""));
        assert!(bodies.contains("\"event_kind\":\"billing_metering_event\""));
        assert!(bodies.contains("\"event_kind\":\"usage_metric\""));
        assert!(bodies.contains("\"span_name\":\"ferrogate.gateway.request\""));
        assert!(bodies.contains("\"logical_model\":\"fast-chat\""));
        assert!(bodies.contains("\"provider\":\"openai\""));
        assert!(!bodies.contains("client-secret prompt"));
        assert!(!bodies.contains("provider-secret response"));
    }

    #[test]
    fn analytics_clickhouse_export_routes_events_to_table_inserts_without_bodies() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let server_requests = Arc::clone(&requests);

        let server = thread::spawn(move || {
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut raw = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    if http_body_if_complete(&raw).is_some() {
                        server_requests
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&raw).to_string());
                        break;
                    }
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            }
        });

        let state = analytics_test_state();
        let mut exported_request_logs = 0;
        let mut exported_audit_events = 0;
        let mut exported_billing_events = 0;
        let mut exported_usage_aggregates = 0;
        export_analytics_once_since(
            &state,
            &AnalyticsSink::Clickhouse { base_url: endpoint },
            Duration::from_secs(3),
            128,
            &mut exported_request_logs,
            &mut exported_audit_events,
            &mut exported_billing_events,
            &mut exported_usage_aggregates,
        )
        .unwrap();
        server.join().unwrap();

        let requests = requests
            .lock()
            .unwrap()
            .join("\n---clickhouse-request---\n");
        assert!(requests.contains("INSERT%20INTO%20ferrogate.ferrogate_request_logs"));
        assert!(requests.contains("INSERT%20INTO%20ferrogate.ferrogate_trace_spans"));
        assert!(requests.contains("INSERT%20INTO%20ferrogate.ferrogate_audit_timeline"));
        assert!(requests.contains("INSERT%20INTO%20ferrogate.ferrogate_billing_metering_events"));
        assert!(requests.contains("INSERT%20INTO%20ferrogate.ferrogate_usage_metrics"));
        assert!(requests.contains("input_format_skip_unknown_fields=1"));
        assert!(requests.contains("\"logical_model\":\"fast-chat\""));
        assert!(requests.contains("\"provider\":\"openai\""));
        assert!(!requests.contains("client-secret prompt"));
        assert!(!requests.contains("provider-secret response"));
    }

    #[test]
    fn clickhouse_insert_url_encodes_json_each_row_query() {
        assert_eq!(
            clickhouse_insert_url("http://clickhouse:8123/", "ferrogate.ferrogate_request_logs"),
            "http://clickhouse:8123/?input_format_skip_unknown_fields=1&query=INSERT%20INTO%20ferrogate.ferrogate_request_logs%20FORMAT%20JSONEachRow"
        );
    }

    #[test]
    fn parses_otlp_http_and_https_targets() {
        let http = parse_otlp_target("http://collector:4318/v1/metrics").unwrap();
        assert_eq!(http.scheme, OtlpScheme::Http);
        assert_eq!(http.authority, "collector:4318");
        assert_eq!(http.path_query, "/v1/metrics");

        let https = parse_otlp_target("https://collector.example/v1/logs").unwrap();
        assert_eq!(https.scheme, OtlpScheme::Https);
        assert_eq!(https.authority, "collector.example");
        assert_eq!(https.port, 443);
    }

    fn http_body_if_complete(raw: &[u8]) -> Option<&[u8]> {
        let split = raw.windows(4).position(|window| window == b"\r\n\r\n")?;
        let headers = String::from_utf8_lossy(&raw[..split]);
        let content_length = headers.lines().find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })?;
        let body_start = split + 4;
        if raw.len() < body_start + content_length {
            return None;
        }
        Some(&raw[body_start..body_start + content_length])
    }

    fn analytics_test_state() -> AppState {
        let state = AppState::new(Config::default());
        state.record_request_log(StoredRequestLog {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            route: Some("openai.chat.completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: true,
            response_recorded: true,
            prompt_body: Some("client-secret prompt".into()),
            response_body: Some("provider-secret response".into()),
            cache_status: None,
            started_at_unix: Some(1),
            completed_at_unix: Some(2),
        });
        state.record_admin_audit_event(crate::state::AdminAuditEventDraft {
            request_id: "fg-1".into(),
            trace_id: Some("fg-1".into()),
            agent_run_id: None,
            actor_api_key_id: Some("key".into()),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                project_id: Some("project".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            action: "policy.deny".into(),
            target: "policy:block-secret".into(),
            outcome: "error".into(),
            message: "policy denied request".into(),
        });
        state
            .record_estimated_billing_event(
                &ferrogate_core::RequestContext {
                    request_id: "fg-1".into(),
                    trace_id: Some("fg-1".into()),
                    tenant: TenantContext {
                        organization_id: Some("org".into()),
                        project_id: Some("project".into()),
                        api_key_id: Some("key".into()),
                        ..TenantContext::default()
                    },
                    ..ferrogate_core::RequestContext::default()
                },
                "fast-chat",
                "openai",
                "gpt-4o-mini",
                &ferrogate_billing::TokenUsage::new(1, 2, 3),
                200,
            )
            .unwrap();
        state
    }
}
