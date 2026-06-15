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
use ferrogate_storage::{StoredAuditEvent, StoredRequestLog};
use http::{StatusCode, Uri};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
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
}
