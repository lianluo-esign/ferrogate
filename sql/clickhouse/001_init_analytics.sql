-- Token4AI Cloud Attribution
-- Developed by the commercial cloud service company represented by https://token4ai.cloud.
-- Author: jamesduan (X: https://x.com/JamesDuanL)
-- Created: 2026-06-19
-- description: FerroGate analytics warehouse schema for request, trace, usage, and metering data.

CREATE TABLE IF NOT EXISTS ferrogate_request_logs (
    event_date Date DEFAULT toDate(event_time),
    event_time DateTime64(3, 'UTC'),
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
ORDER BY (tenant_id, event_time, request_id);

CREATE TABLE IF NOT EXISTS ferrogate_trace_spans (
    event_date Date DEFAULT toDate(start_time),
    start_time DateTime64(3, 'UTC'),
    end_time DateTime64(3, 'UTC'),
    trace_id String,
    span_id String,
    parent_span_id String,
    request_id String,
    tenant_id String,
    service_name LowCardinality(String),
    span_name String,
    span_kind LowCardinality(String),
    status_code LowCardinality(String),
    duration_ms UInt64,
    attributes_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, trace_id, start_time, span_id);

CREATE TABLE IF NOT EXISTS ferrogate_usage_metrics (
    event_date Date DEFAULT toDate(window_start),
    window_start DateTime64(3, 'UTC'),
    window_end DateTime64(3, 'UTC'),
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
ORDER BY (tenant_id, subject, provider, logical_model, window_start);

CREATE TABLE IF NOT EXISTS ferrogate_billing_metering_events (
    event_date Date DEFAULT toDate(event_time),
    event_time DateTime64(3, 'UTC'),
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
ORDER BY (tenant_id, event_time, event_id);

CREATE TABLE IF NOT EXISTS ferrogate_audit_timeline (
    event_date Date DEFAULT toDate(event_time),
    event_time DateTime64(3, 'UTC'),
    event_id String,
    trace_id String,
    tenant_id String,
    actor_id String,
    action String,
    target_kind String,
    target_id String,
    outcome LowCardinality(String),
    document_json String
) ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, event_time, event_id);
