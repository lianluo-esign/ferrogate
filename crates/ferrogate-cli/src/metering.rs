// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use http::{HeaderValue, StatusCode, Uri};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrogate_billing::BillingEvent;
use serde::Serialize;
use tokio::task;

use crate::config::{MeteringConfig, MeteringExportProvider, MeteringExportSubject};

#[derive(Debug, Clone)]
pub(crate) struct MeteringExporter {
    endpoint: String,
    bearer_token: String,
    timeout: Duration,
    provider: MeteringExportProvider,
    event_type: String,
    source: String,
    subject: MeteringExportSubject,
    statuses: Arc<Mutex<VecDeque<MeteringExportStatus>>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MeteringExportStatus {
    pub(crate) request_id: String,
    pub(crate) trace_id: Option<String>,
    pub(crate) provider: MeteringExportProvider,
    pub(crate) endpoint: String,
    pub(crate) success: bool,
    pub(crate) status: String,
    pub(crate) error: Option<String>,
    pub(crate) occurred_at_unix: u64,
}

#[derive(Debug, Serialize)]
struct MeteringExportEnvelope<'a> {
    object: &'static str,
    idempotency_key: String,
    event: &'a BillingEvent,
}

trait MeteringProviderAdapter {
    fn encode_event(&self, event: &BillingEvent) -> AnyResult<Vec<u8>>;
}

#[derive(Debug)]
struct LegacyMeteringAdapter;

#[derive(Debug)]
struct OpenMeteringAdapter {
    event_type: String,
    source: String,
    subject: MeteringExportSubject,
}

#[derive(Debug, Serialize)]
struct OpenMeterCloudEvent<'a> {
    specversion: &'static str,
    id: String,
    source: &'a str,
    #[serde(rename = "type")]
    event_type: &'a str,
    subject: String,
    data: OpenMeterUsageData<'a>,
}

#[derive(Debug, Serialize)]
struct OpenMeterUsageData<'a> {
    request_id: &'a str,
    trace_id: Option<&'a str>,
    tenant: &'a ferrogate_core::TenantContext,
    logical_model: &'a str,
    provider: &'a str,
    provider_model: &'a str,
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
    usage_source: ferrogate_billing::BillingUsageSource,
    status_code: u16,
    cluster_id: Option<&'a str>,
    node_id: Option<&'a str>,
    occurred_at_unix: Option<u64>,
}

impl MeteringExporter {
    pub(crate) fn from_config(config: &MeteringConfig) -> anyhow::Result<Option<Self>> {
        if !config.export_enabled {
            return Ok(None);
        }
        let bearer_token = match config.export_token.as_deref() {
            Some(token) if !token.trim().is_empty() => token.trim().to_string(),
            _ => {
                let env_name = config
                    .export_token_env
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("metering.export_token_env is required"))?;
                std::env::var(env_name).with_context(|| {
                    format!("failed to read metering export token env {env_name}")
                })?
            }
        };
        Ok(Some(Self {
            endpoint: config.export_endpoint.clone(),
            bearer_token,
            timeout: Duration::from_secs(config.export_timeout_secs),
            provider: config.export_provider,
            event_type: config.export_event_type.trim().to_string(),
            source: config.export_source.trim().to_string(),
            subject: config.export_subject,
            statuses: Arc::new(Mutex::new(VecDeque::new())),
        }))
    }

    pub(crate) fn export_event(&self, event: BillingEvent) {
        let exporter = self.clone();
        tokio::spawn(async move {
            match exporter.export_event_async(&event).await {
                Ok(()) => exporter.record_status(&event, true, "exported", None),
                Err(error) => {
                    let error = error.to_string();
                    exporter.record_status(&event, false, "failed", Some(error.clone()));
                    tracing::warn!(
                        request_id = %event.request_id,
                        error = %error,
                        "token metering export failed"
                    );
                }
            }
        });
    }

    pub(crate) fn statuses(&self) -> Vec<MeteringExportStatus> {
        self.statuses
            .lock()
            .map(|statuses| statuses.iter().cloned().collect())
            .unwrap_or_default()
    }

    async fn export_event_async(&self, event: &BillingEvent) -> AnyResult<()> {
        let endpoint = self.endpoint.clone();
        let bearer_token = self.bearer_token.clone();
        let timeout = self.timeout;
        let adapter = metering_provider_adapter(
            self.provider,
            self.event_type.clone(),
            self.source.clone(),
            self.subject,
        );
        let event = event.clone();
        task::spawn_blocking(move || {
            let body = adapter.encode_event(&event)?;
            post_json(&endpoint, &bearer_token, &body, timeout)
        })
        .await
        .context("metering export task failed")?
    }

    fn record_status(
        &self,
        event: &BillingEvent,
        success: bool,
        status: &'static str,
        error: Option<String>,
    ) {
        let Ok(mut statuses) = self.statuses.lock() else {
            return;
        };
        statuses.push_back(MeteringExportStatus {
            request_id: event.request_id.clone(),
            trace_id: event.trace_id.clone(),
            provider: self.provider,
            endpoint: self.endpoint.clone(),
            success,
            status: status.into(),
            error,
            occurred_at_unix: now_unix_seconds(),
        });
        while statuses.len() > 128 {
            statuses.pop_front();
        }
    }
}

impl MeteringProviderAdapter for LegacyMeteringAdapter {
    fn encode_event(&self, event: &BillingEvent) -> AnyResult<Vec<u8>> {
        serde_json::to_vec(&MeteringExportEnvelope {
            object: "token_metering_event",
            idempotency_key: metering_idempotency_key(event),
            event,
        })
        .context("failed to serialize legacy metering event")
    }
}

impl MeteringProviderAdapter for OpenMeteringAdapter {
    fn encode_event(&self, event: &BillingEvent) -> AnyResult<Vec<u8>> {
        serde_json::to_vec(&openmeter_event(
            event,
            &self.event_type,
            &self.source,
            self.subject,
        ))
        .context("failed to serialize OpenMeter metering event")
    }
}

fn metering_provider_adapter(
    provider: MeteringExportProvider,
    event_type: String,
    source: String,
    subject: MeteringExportSubject,
) -> Box<dyn MeteringProviderAdapter + Send + Sync> {
    match provider {
        MeteringExportProvider::Legacy => Box::new(LegacyMeteringAdapter),
        MeteringExportProvider::Openmeter => Box::new(OpenMeteringAdapter {
            event_type,
            source,
            subject,
        }),
    }
}

fn openmeter_event<'a>(
    event: &'a BillingEvent,
    event_type: &'a str,
    source: &'a str,
    subject: MeteringExportSubject,
) -> OpenMeterCloudEvent<'a> {
    OpenMeterCloudEvent {
        specversion: "1.0",
        id: metering_idempotency_key(event),
        source,
        event_type,
        subject: metering_subject(event, subject),
        data: OpenMeterUsageData {
            request_id: &event.request_id,
            trace_id: event.trace_id.as_deref(),
            tenant: &event.tenant,
            logical_model: &event.logical_model,
            provider: &event.provider,
            provider_model: &event.provider_model,
            prompt_tokens: event.usage.prompt_tokens,
            completion_tokens: event.usage.completion_tokens,
            total_tokens: event.usage.total_tokens,
            usage_source: event.usage_source,
            status_code: event.status_code,
            cluster_id: event.cluster_id.as_deref(),
            node_id: event.node_id.as_deref(),
            occurred_at_unix: event.occurred_at_unix,
        },
    }
}

fn metering_idempotency_key(event: &BillingEvent) -> String {
    event
        .trace_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|trace_id| format!("ferrogate:{trace_id}:{}", event.request_id))
        .unwrap_or_else(|| format!("ferrogate:{}", event.request_id))
}

fn metering_subject(event: &BillingEvent, subject: MeteringExportSubject) -> String {
    let tenant = &event.tenant;
    let configured = match subject {
        MeteringExportSubject::ApiKey => tenant.api_key_id.as_deref(),
        MeteringExportSubject::Organization => tenant.organization_id.as_deref(),
        MeteringExportSubject::Project => tenant.project_id.as_deref(),
        MeteringExportSubject::User => tenant.user_id.as_deref(),
    };
    configured
        .or(tenant.api_key_id.as_deref())
        .or(tenant.organization_id.as_deref())
        .or(tenant.project_id.as_deref())
        .or(tenant.user_id.as_deref())
        .unwrap_or("unknown")
        .to_string()
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

pub(crate) fn post_json(
    endpoint: &str,
    bearer_token: &str,
    body: &[u8],
    timeout: Duration,
) -> AnyResult<()> {
    let target = parse_target(endpoint)?;
    let mut stream = connect(&target, timeout)?;
    match target.scheme {
        Scheme::Http => send_request(&mut stream, &target, bearer_token, body),
        Scheme::Https => {
            let server_name = ServerName::try_from(target.host.clone())
                .with_context(|| format!("invalid metering TLS server name {}", target.host))?;
            let connection = ClientConnection::new(tls_client_config()?, server_name)
                .context("failed to initialize metering TLS client")?;
            let mut tls_stream = StreamOwned::new(connection, stream);
            send_request(&mut tls_stream, &target, bearer_token, body)
        }
    }
}

fn send_request<S: Read + Write>(
    stream: &mut S,
    target: &Target,
    bearer_token: &str,
    body: &[u8],
) -> AnyResult<()> {
    let bearer_header = HeaderValue::from_str(bearer_token)
        .context("metering export token is not a valid header")?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\n\r\n",
        target.path_query,
        target.authority,
        bearer_header.to_str().unwrap_or_default(),
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;

    let (status, _) = read_response_head(stream)?;
    if status.is_success() {
        Ok(())
    } else {
        bail!("metering service returned status {status}");
    }
}

fn connect(target: &Target, timeout: Duration) -> AnyResult<TcpStream> {
    let address = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve metering endpoint {}", target.authority))?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "metering endpoint {} resolved no addresses",
                target.authority
            )
        })?;
    let stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect metering endpoint {}", target.authority))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn read_response_head<S: Read>(stream: &mut S) -> AnyResult<(StatusCode, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 1024];
    let split = loop {
        let read = stream
            .read(&mut buffer)
            .context("failed to read metering response head")?;
        if read == 0 {
            bail!("metering response missing header terminator");
        }
        raw.extend_from_slice(&buffer[..read]);
        if raw.len() > 64 * 1024 {
            bail!("metering response headers exceed 64KiB");
        }
        if let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break split;
        }
    };

    let headers = String::from_utf8_lossy(&raw[..split]);
    let status_line = headers
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("metering response missing status line"))?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("metering response missing status code"))?
        .parse::<u16>()
        .context("metering response has invalid status code")?;
    Ok((
        StatusCode::from_u16(status_code).context("metering service returned invalid status")?,
        raw[split + 4..].to_vec(),
    ))
}

/// See the identical helper in `telemetry.rs` for why this is needed:
/// rustls panics if more than one crypto backend is compiled in and no
/// process-wide default has been installed explicitly (issue #163).
fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS_CLIENT_CONFIG.get() {
        return Ok(Arc::clone(config));
    }
    ensure_rustls_crypto_provider();

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    scheme: Scheme,
    host: String,
    port: u16,
    authority: String,
    path_query: String,
}

fn parse_target(raw: &str) -> AnyResult<Target> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid metering endpoint {raw}"))?;
    let scheme = match uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        Some(other) => bail!("metering export supports http and https endpoints only, got {other}"),
        None => bail!("metering endpoint must include scheme"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("metering endpoint must include authority"))?;
    let host = authority.host().to_string();
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
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
    Ok(Target {
        scheme,
        host,
        port,
        authority,
        path_query,
    })
}

#[cfg(test)]
mod tests {
    use ferrogate_billing::{BillingUsageSource, TokenUsage};

    use super::*;

    #[test]
    fn openmeter_event_maps_billing_event_to_cloud_event() {
        let event = sample_billing_event();

        let payload = serde_json::to_value(openmeter_event(
            &event,
            "ai.tokens",
            "ferrogate",
            MeteringExportSubject::ApiKey,
        ))
        .unwrap();

        assert_eq!(payload["specversion"], "1.0");
        assert_eq!(payload["id"], "ferrogate:trace_456:req_123");
        assert_eq!(payload["source"], "ferrogate");
        assert_eq!(payload["type"], "ai.tokens");
        assert_eq!(payload["subject"], "client");
        assert_eq!(payload["data"]["logical_model"], "fast-chat");
        assert_eq!(payload["data"]["provider"], "openai");
        assert_eq!(payload["data"]["provider_model"], "gpt-4o-mini");
        assert_eq!(payload["data"]["prompt_tokens"], 3);
        assert_eq!(payload["data"]["completion_tokens"], 5);
        assert_eq!(payload["data"]["total_tokens"], 8);
        assert_eq!(payload["data"]["tenant"]["organization_id"], "org_demo");
    }

    #[test]
    fn legacy_metering_adapter_encodes_provider_envelope() {
        let adapter = LegacyMeteringAdapter;
        let payload: serde_json::Value = serde_json::from_slice(
            &adapter
                .encode_event(&sample_billing_event())
                .expect("legacy payload"),
        )
        .expect("legacy json");

        assert_eq!(payload["object"], "token_metering_event");
        assert_eq!(payload["idempotency_key"], "ferrogate:trace_456:req_123");
        assert_eq!(payload["event"]["logical_model"], "fast-chat");
        assert_eq!(payload["event"]["provider"], "openai");
        assert_eq!(payload["event"]["usage"]["total_tokens"], 8);
    }

    #[test]
    fn openmeter_adapter_encodes_cloud_event_payload() {
        let adapter = OpenMeteringAdapter {
            event_type: "ai.tokens".into(),
            source: "ferrogate-test".into(),
            subject: MeteringExportSubject::Project,
        };
        let payload: serde_json::Value = serde_json::from_slice(
            &adapter
                .encode_event(&sample_billing_event())
                .expect("openmeter payload"),
        )
        .expect("openmeter json");

        assert_eq!(payload["specversion"], "1.0");
        assert_eq!(payload["source"], "ferrogate-test");
        assert_eq!(payload["type"], "ai.tokens");
        assert_eq!(payload["subject"], "project_gateway");
        assert_eq!(payload["data"]["request_id"], "req_123");
        assert_eq!(payload["data"]["trace_id"], "trace_456");
        assert_eq!(payload["data"]["logical_model"], "fast-chat");
        assert_eq!(payload["data"]["provider_model"], "gpt-4o-mini");
        assert_eq!(payload["data"]["total_tokens"], 8);
        assert_eq!(payload["data"]["status_code"], 200);
    }

    #[test]
    fn metering_subject_falls_back_to_available_tenant_identity() {
        let event = BillingEvent {
            request_id: "req_123".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("org_demo".into()),
                ..Default::default()
            },
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(0, 0, 0),
            usage_source: BillingUsageSource::GatewayEstimate,
            status_code: 200,
            occurred_at_unix: None,
            cost_usd: None,
            latency_ms: None,
            metadata: std::collections::BTreeMap::new(),
        };

        assert_eq!(
            metering_subject(&event, MeteringExportSubject::ApiKey),
            "org_demo"
        );
        assert_eq!(metering_idempotency_key(&event), "ferrogate:req_123");
    }

    fn sample_billing_event() -> BillingEvent {
        BillingEvent {
            request_id: "req_123".into(),
            trace_id: Some("trace_456".into()),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: Some("cluster-a".into()),
            node_id: Some("node-a".into()),
            tenant: ferrogate_core::TenantContext {
                workspace_id: None,
                organization_id: Some("org_demo".into()),
                team_id: None,
                project_id: Some("project_gateway".into()),
                user_id: None,
                api_key_id: Some("client".into()),
            },
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(3, 5, 8),
            usage_source: BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1_800_000_000),
            cost_usd: Some(0.0012),
            latency_ms: Some(430),
            metadata: std::collections::BTreeMap::new(),
        }
    }
}
