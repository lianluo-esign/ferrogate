// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod agent_runs;
mod body;
mod chat;
mod dispatch;
mod handlers;
mod local;
mod mcp_rpc;
mod proxy;
mod responses_stream;

use anyhow::{Context, Result as AnyResult};
use http::HeaderMap;
use pingora::{
    listeners::tls::TlsSettings,
    proxy::http_proxy_service,
    server::{
        configuration::{Opt as PingoraOpt, ServerConf},
        Server,
    },
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tracing::info;

use crate::{
    acme::{
        ensure_certificate, start_renewal_scheduler, AcmeCertificatePaths, AcmeCertificateReloader,
        AcmeRenewalHandle, SharedAcmeRenewalState,
    },
    config::{Config, Upstream},
    lifecycle::execute_graceful_upgrade_reload,
    routing::UpstreamEndpoint,
    state::{RuntimeRoute, SharedAppState},
    telemetry::{start_analytics_background_sender, start_otlp_background_sender},
};

#[derive(Debug, Default, Clone)]
pub(crate) struct ProxyContext {
    request_id: String,
    trace_id: Option<String>,
    traceparent: Option<String>,
    tracestate: Option<String>,
    tenant_id: Option<String>,
    route: Option<RuntimeRoute>,
    upstream: Option<Upstream>,
    upstream_endpoint: Option<UpstreamEndpoint>,
    target_uri: Option<http::Uri>,
    original_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IngressTraceContext {
    trace_id: String,
    traceparent: Option<String>,
    tracestate: Option<String>,
}

pub(crate) fn ingress_trace_context(
    headers: &HeaderMap,
    fallback_trace_id: &str,
) -> IngressTraceContext {
    let traceparent = headers
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| valid_traceparent(value).map(str::to_string));
    let trace_id = traceparent
        .as_deref()
        .and_then(trace_id_from_traceparent)
        .unwrap_or(fallback_trace_id)
        .to_string();
    let tracestate = traceparent.as_ref().and_then(|_| {
        headers
            .get("tracestate")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .map(str::to_string)
    });

    IngressTraceContext {
        trace_id,
        traceparent,
        tracestate,
    }
}

fn valid_traceparent(value: &str) -> Option<&str> {
    let mut parts = value.split('-');
    let version = parts.next()?;
    let trace_id = parts.next()?;
    let parent_id = parts.next()?;
    let flags = parts.next()?;
    if parts.next().is_some()
        || version.len() != 2
        || trace_id.len() != 32
        || parent_id.len() != 16
        || flags.len() != 2
        || version == "ff"
        || !is_lower_hex(version)
        || !is_lower_hex(trace_id)
        || !is_lower_hex(parent_id)
        || !is_lower_hex(flags)
        || trace_id.chars().all(|character| character == '0')
        || parent_id.chars().all(|character| character == '0')
    {
        return None;
    }
    Some(value)
}

fn trace_id_from_traceparent(value: &str) -> Option<&str> {
    value.split('-').nth(1)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone)]
pub(crate) struct FerroGateway {
    state: SharedAppState,
}

pub(crate) fn serve(config: Config, source_path: Option<PathBuf>, upgrade: bool) -> AnyResult<()> {
    let listen = config.listen.clone();
    let tls = config.tls.clone();
    write_runtime_pid_file(&config)?;
    let server_conf = pingora_server_conf(&config);
    let resolved_tls = resolve_tls_certificate_paths(&tls)?;
    let acme_renewal_state = resolved_tls.as_ref().and_then(|paths| {
        tls.acme
            .enabled
            .then(|| Arc::new(SharedAcmeRenewalState::new(&tls.acme, paths)))
    });
    let state = SharedAppState::try_with_source_path(config, source_path)?
        .with_acme_renewal_state(acme_renewal_state.clone());
    let _otlp_sender = start_otlp_background_sender(state.current());
    let _analytics_sender = start_analytics_background_sender(state.current());
    let _acme_renewal =
        start_acme_renewal_if_configured(&tls, resolved_tls.as_ref(), acme_renewal_state, &state);
    let _mcp_health = start_mcp_health_scheduler(&state);
    let gateway = FerroGateway { state };

    let pingora_opt = PingoraOpt {
        upgrade,
        ..PingoraOpt::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), server_conf);
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, gateway);
    if let Some(paths) = resolved_tls {
        let mut tls_settings = TlsSettings::intermediate(&paths.cert_path, &paths.key_path)
            .context("failed to configure TLS listener")?;
        if tls.http2 {
            tls_settings.enable_h2();
        }
        service.add_tls_with_settings(&listen, None, tls_settings);
        info!(
            listen = %listen,
            runtime = "pingora",
            tls = true,
            http2 = tls.http2,
            upgrade,
            "FerroGate Pingora gateway listening with TLS"
        );
    } else {
        service.add_tcp(&listen);
        info!(
            listen = %listen,
            runtime = "pingora",
            tls = false,
            upgrade,
            "FerroGate Pingora gateway listening"
        );
    }
    server.add_service(service);

    server.run_forever();
}

#[derive(Debug)]
struct McpHealthHandle {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for McpHealthHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn start_mcp_health_scheduler(state: &SharedAppState) -> Option<McpHealthHandle> {
    if state.current().config.mcp_servers.is_empty() {
        return None;
    }
    Some(start_mcp_health_scheduler_with_interval(
        state.clone(),
        Duration::from_secs(10),
    ))
}

fn start_mcp_health_scheduler_with_interval(
    state: SharedAppState,
    interval: Duration,
) -> McpHealthHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            thread::sleep(interval);
            if thread_stop.load(Ordering::Relaxed) {
                break;
            }
            state.current().mcp_health_check_and_reconnect();
        }
    });
    McpHealthHandle {
        stop,
        handle: Some(handle),
    }
}

fn start_acme_renewal_if_configured(
    tls: &crate::config::TlsConfig,
    paths: Option<&AcmeCertificatePaths>,
    state: Option<Arc<SharedAcmeRenewalState>>,
    app_state: &SharedAppState,
) -> Option<AcmeRenewalHandle> {
    let paths = paths?.clone();
    let state = state?;
    if !tls.acme.enabled {
        return None;
    }
    let reloader: Arc<dyn AcmeCertificateReloader> = Arc::new(GracefulUpgradeAcmeReloader {
        config: app_state.current().config.as_ref().clone(),
        source_path: app_state.source_path().cloned(),
    });
    Some(start_renewal_scheduler(
        tls.acme.clone(),
        paths,
        state,
        reloader,
    ))
}

#[derive(Debug, Clone)]
struct GracefulUpgradeAcmeReloader {
    config: Config,
    source_path: Option<PathBuf>,
}

impl AcmeCertificateReloader for GracefulUpgradeAcmeReloader {
    fn reload(&self) -> AnyResult<()> {
        let source_path = self
            .source_path
            .as_deref()
            .context("runtime was not started from a config file")?;
        if self.config.reliability.graceful_upgrade_pid_file.is_none()
            || self.config.reliability.graceful_upgrade_sock.is_none()
        {
            anyhow::bail!(
                "automatic ACME certificate reload requires reliability.graceful_upgrade_pid_file and reliability.graceful_upgrade_sock"
            );
        }
        execute_graceful_upgrade_reload(source_path, &self.config).map(|_| ())
    }
}

fn resolve_tls_certificate_paths(
    tls: &crate::config::TlsConfig,
) -> AnyResult<Option<AcmeCertificatePaths>> {
    if !tls.is_enabled() {
        return Ok(None);
    }
    if tls.acme.enabled {
        return ensure_certificate(&tls.acme).map(Some);
    }
    let (cert_path, key_path) = tls
        .manual_cert_and_key()
        .context("TLS is enabled but cert_path or key_path is missing")?;
    Ok(Some(AcmeCertificatePaths {
        cert_path: cert_path.to_string(),
        key_path: key_path.to_string(),
    }))
}

fn write_runtime_pid_file(config: &Config) -> AnyResult<()> {
    if let Some(path) = config.reliability.graceful_upgrade_pid_file.as_deref() {
        std::fs::write(path, std::process::id().to_string())?;
    }
    Ok(())
}

fn pingora_server_conf(config: &Config) -> ServerConf {
    let mut server_conf = ServerConf {
        grace_period_seconds: config.reliability.graceful_shutdown_grace_period_secs,
        graceful_shutdown_timeout_seconds: config.reliability.graceful_shutdown_timeout_secs,
        ..ServerConf::default()
    };
    if let Some(pid_file) = config.reliability.graceful_upgrade_pid_file.as_deref() {
        server_conf.pid_file = pid_file.to_string();
    }
    if let Some(upgrade_sock) = config.reliability.graceful_upgrade_sock.as_deref() {
        server_conf.upgrade_sock = upgrade_sock.to_string();
    }
    server_conf.upgrade_sock_connect_accept_max_retries =
        config.reliability.graceful_upgrade_sock_retries;
    server_conf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReliabilityConfig;

    #[test]
    fn pingora_server_conf_uses_graceful_shutdown_settings() {
        let config = Config {
            reliability: ReliabilityConfig {
                graceful_shutdown_grace_period_secs: Some(3),
                graceful_shutdown_timeout_secs: Some(11),
                graceful_upgrade_pid_file: Some("/tmp/ferrogate.pid".into()),
                graceful_upgrade_sock: Some("/tmp/ferrogate_upgrade.sock".into()),
                graceful_upgrade_sock_retries: Some(9),
                ..ReliabilityConfig::default()
            },
            ..Config::default()
        };

        let server_conf = pingora_server_conf(&config);

        assert_eq!(server_conf.grace_period_seconds, Some(3));
        assert_eq!(server_conf.graceful_shutdown_timeout_seconds, Some(11));
        assert_eq!(server_conf.pid_file, "/tmp/ferrogate.pid");
        assert_eq!(server_conf.upgrade_sock, "/tmp/ferrogate_upgrade.sock");
        assert_eq!(server_conf.upgrade_sock_connect_accept_max_retries, Some(9));
    }

    #[test]
    fn write_runtime_pid_file_uses_graceful_upgrade_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("ferrogate.pid");
        let config = Config {
            reliability: ReliabilityConfig {
                graceful_upgrade_pid_file: Some(pid_file.to_string_lossy().into_owned()),
                ..ReliabilityConfig::default()
            },
            ..Config::default()
        };

        write_runtime_pid_file(&config).unwrap();

        let pid = std::fs::read_to_string(pid_file).unwrap();
        assert_eq!(pid, std::process::id().to_string());
    }

    #[test]
    fn ingress_trace_context_accepts_valid_traceparent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.insert("tracestate", "vendor=value".parse().unwrap());

        let trace = ingress_trace_context(&headers, "fg-1");

        assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            trace.traceparent.as_deref(),
            Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
        );
        assert_eq!(trace.tracestate.as_deref(), Some("vendor=value"));
    }

    #[test]
    fn ingress_trace_context_falls_back_for_invalid_traceparent() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );

        let trace = ingress_trace_context(&headers, "fg-1");

        assert_eq!(trace.trace_id, "fg-1");
        assert!(trace.traceparent.is_none());
    }
}
