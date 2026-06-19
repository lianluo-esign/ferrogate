-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-19
-- description: FerroGate analytics warehouse schema for request, trace, usage, and metering data.

CREATE DATABASE IF NOT EXISTS ferrogate;

CREATE TABLE IF NOT EXISTS ferrogate.ferrogate_request_logs (
    event_date Date DEFAULT toDate(toDateTime(event_time_unix, 'UTC')),
    event_time_unix UInt64,
    request_id String,
    trace_id String,
    tenant_id String,
    organization_id String,
    project_id String,
    api_key_id String,
    route String,
    provider String,
    logical_model String,
    provider_model String,
    method LowCardinality(String),
    path String,
    status_code UInt16,
    latency_ms UInt64,
    prompt_tokens UInt64,
    completion_tokens UInt64,
    total_tokens UInt64,
    cache_status LowCardinality(String),
    error_code String,
    document_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, event_time_unix, request_id);

CREATE TABLE IF NOT EXISTS ferrogate.ferrogate_trace_spans (
    event_date Date DEFAULT toDate(toDateTime(event_time_unix, 'UTC')),
    event_time_unix UInt64,
    trace_id String,
    span_id String,
    parent_span_id String,
    request_id String,
    tenant_id String,
    service_name LowCardinality(String),
    span_name String,
    span_kind LowCardinality(String),
    status_code UInt16,
    duration_ms UInt64,
    document_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, trace_id, event_time_unix, span_id);

CREATE TABLE IF NOT EXISTS ferrogate.ferrogate_usage_metrics (
    event_date Date DEFAULT toDate(toDateTime(event_time_unix, 'UTC')),
    event_time_unix UInt64,
    tenant_id String,
    subject String,
    organization_id String,
    project_id String,
    api_key_id String,
    provider String,
    logical_model String,
    provider_model String,
    prompt_tokens UInt64,
    completion_tokens UInt64,
    total_tokens UInt64,
    request_count UInt64,
    error_count UInt64,
    cost_microusd UInt64,
    document_json String
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, subject, provider, logical_model, event_time_unix);

CREATE TABLE IF NOT EXISTS ferrogate.ferrogate_billing_metering_events (
    event_date Date DEFAULT toDate(toDateTime(event_time_unix, 'UTC')),
    event_time_unix UInt64,
    event_id String,
    request_id String,
    trace_id String,
    tenant_id String,
    subject String,
    organization_id String,
    project_id String,
    api_key_id String,
    provider String,
    logical_model String,
    provider_model String,
    prompt_tokens UInt64,
    completion_tokens UInt64,
    total_tokens UInt64,
    cost_microusd UInt64,
    idempotency_key String,
    document_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, event_time_unix, event_id);

CREATE TABLE IF NOT EXISTS ferrogate.ferrogate_audit_timeline (
    event_date Date DEFAULT toDate(toDateTime(event_time_unix, 'UTC')),
    event_time_unix UInt64,
    event_id String,
    trace_id String,
    tenant_id String,
    subject String,
    action String,
    target_kind String,
    target_id String,
    outcome LowCardinality(String),
    document_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, event_time_unix, event_id);
