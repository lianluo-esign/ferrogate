// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod agent_runs;
mod agent_schedules;
mod api_contract;
pub(crate) mod asset_bucket;
mod asset_presign;
mod asset_publish_gate;
mod asset_registry;
mod asset_scan;
mod asset_security;
mod asset_signature;
mod assets;
mod billing_outbox;
mod body;
mod chat;
mod dispatch;
mod embeddings;
mod external_actions;
mod function_egress;
mod guardrail_policies;
mod handlers;
mod local;
mod managed_action_guardrail;
mod mcp_identity;
mod mcp_rpc;
pub(crate) mod payments;
mod plans;
mod proxy;
mod quota_policies;
mod rbac;
mod responses_stream;
mod route_groups;
mod sites;
mod usage_reports;
mod virtual_keys;
mod wallets;

use anyhow::{Context, Result as AnyResult};
use http::HeaderMap;
use pingora::{
    listeners::tls::TlsSettings,
    proxy::http_proxy_service_with_name,
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

use self::external_actions::{
    serve_gateway_external_action_authorizer_unix, GatewayExternalActionAuthorizerService,
};

/// Operator-facing label for the Pingora HTTP proxy service: used as the
/// [`pingora::proxy::Service`] name (surfaced in Pingora's own "Starting
/// service: ..." lifecycle log) and in FerroGate's own startup log line, so
/// both name the product rather than the underlying Pingora framework.
const GATEWAY_SERVICE_NAME: &str = "FerroGate Gateway";

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
    crate::responses::set_cors_allowed_origin(config.admin.cors_allowed_origin.clone());
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
    let _external_action_authorizer = start_external_action_authorizer_if_configured(&state);
    let _billing_outbox_sweeper = start_billing_outbox_sweeper(&state);
    let _agent_schedule_sweeper = start_agent_schedule_sweeper(&state);
    let gateway = FerroGateway { state };

    let pingora_opt = PingoraOpt {
        upgrade,
        ..PingoraOpt::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), server_conf);
    server.bootstrap();

    let mut service =
        http_proxy_service_with_name(&server.configuration, gateway, GATEWAY_SERVICE_NAME);
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
            "{GATEWAY_SERVICE_NAME} listening with TLS"
        );
    } else {
        service.add_tcp(&listen);
        info!(
            listen = %listen,
            runtime = "pingora",
            tls = false,
            upgrade,
            "{GATEWAY_SERVICE_NAME} listening"
        );
    }
    server.add_service(service);

    server.run_forever();
}

fn start_external_action_authorizer_if_configured(
    state: &SharedAppState,
) -> Option<JoinHandle<()>> {
    let current = state.current();
    let config = &current.config.agent_runtime;
    if !config.enabled || config.provider != crate::config::AgentRuntimeProvider::ManagedWorker {
        return None;
    }
    let max_requests = config
        .managed_worker
        .external_action_authorizer_max_requests;
    let service = GatewayExternalActionAuthorizerService::new(state.clone());

    #[cfg(unix)]
    let socket_path = config
        .managed_worker
        .external_action_authorizer_socket
        .as_deref()
        .map(PathBuf::from)?;

    #[cfg(unix)]
    return Some(thread::spawn(move || {
        if let Err(error) =
            serve_gateway_external_action_authorizer_unix(&socket_path, service, max_requests)
        {
            tracing::warn!("gateway external action authorizer exited: {error}");
        }
    }));

    #[cfg(not(unix))]
    None
}

fn managed_worker_capability_policy(
    config: &crate::config::AgentRuntimeManagedWorkerConfig,
) -> ferrogate_runtime::CapabilityPolicy {
    ferrogate_runtime::CapabilityPolicy {
        allowed_actions: config
            .allowed_actions
            .iter()
            .map(|action| action.as_policy_action())
            .collect(),
        approval_required_actions: config
            .approval_required_actions
            .iter()
            .map(|action| action.as_policy_action())
            .collect(),
        allow_direct_network_egress: config.allow_direct_network_egress,
        target_grants: config
            .target_grants
            .iter()
            .map(|grant| ferrogate_runtime::CapabilityTargetGrant {
                action: grant.action.as_policy_action(),
                selector_id: grant.selector_id.clone(),
                selector: grant.selector.clone(),
            })
            .collect(),
        class_only_policy_mode: config.class_only_policy_mode,
        revision: config.policy_revision.clone(),
    }
}

fn managed_worker_capability_policy_for_tenant(
    state: &crate::state::AppState,
    tenant_id: &str,
) -> anyhow::Result<ferrogate_runtime::CapabilityPolicy> {
    let config = &state.config.agent_runtime.managed_worker;
    let mut policy = managed_worker_capability_policy(config);
    let mut effective_grants = Vec::with_capacity(config.target_grants.len());
    for (configured, runtime) in config.target_grants.iter().zip(policy.target_grants) {
        // The RBAC permission read is async (issue #221's rbac slice), but
        // this authorizer runs on a plain std::thread::spawn worker with no
        // tokio runtime (see start_external_action_authorizer_if_configured)
        // -- bridge with the same block_on pattern used for agent tool
        // dispatch (agent_runs.rs::block_on_agent_tool_dispatch) rather than
        // restructuring the Unix-socket authorizer server into async.
        if block_on_sync_bridge(
            state.tenant_has_permission_result(tenant_id, &configured.permission_key),
        )? {
            effective_grants.push(runtime);
        }
    }
    policy.target_grants = effective_grants;
    Ok(policy)
}

pub(crate) fn block_on_sync_bridge<T>(future: impl std::future::Future<Output = T> + Send) -> T
where
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("sync-bridge runtime should build")
                    .block_on(future)
            })
            .join()
            .expect("sync-bridge runtime thread should not panic")
    })
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

/// Background sweeper that durably delivers queued billing reports to the
/// billing service (issue #137).
struct BillingOutboxSweeperHandle {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for BillingOutboxSweeperHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Always spawns the sweeper thread, unconditionally, regardless of whether
/// billing reporting is enabled in the boot-time config snapshot (issue #144):
/// checking whether billing was enabled only once before deciding whether to
/// spawn meant enabling `billing_service` later via the admin hot config-reload
/// path never started a drain thread, silently stranding enqueued reports.
/// `sweep_billing_outbox_once` re-reads `state.current()` and no-ops when
/// billing is disabled, so this thread costs one 1s sleep-wake per tick and
/// picks up a config change on the very next tick with no extra logic needed
/// here.
fn start_billing_outbox_sweeper(state: &SharedAppState) -> BillingOutboxSweeperHandle {
    let state = state.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
            if thread_stop.load(Ordering::Relaxed) {
                break;
            }
            block_on_sync_bridge(state.current().sweep_billing_outbox_once());
        }
    });
    BillingOutboxSweeperHandle {
        stop,
        handle: Some(handle),
    }
}

/// Background loop that fires due time-based agent schedules (issue #246).
struct AgentScheduleSweeperHandle {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for AgentScheduleSweeperHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Always spawns the scheduler tick loop, unconditionally, exactly like
/// `start_billing_outbox_sweeper` (issue #144): `sweep_agent_schedules_once`
/// re-reads `state.current()` and no-ops when `scheduler.enabled = false`, so
/// enabling the scheduler later via the admin hot config-reload path starts
/// firing on the next tick with no restart. The tick interval is re-read each
/// iteration so a reload of `scheduler.tick_interval_secs` also takes effect
/// live. Firing is at-most-once per (schedule, slot) via the
/// `agent_schedule_fires` unique constraint, so this loop is safe to run on
/// every gateway instance concurrently.
fn start_agent_schedule_sweeper(state: &SharedAppState) -> AgentScheduleSweeperHandle {
    let state = state.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            let current = state.current();
            let tick_secs = current.config.scheduler.tick_interval_secs.clamp(1, 3_600);
            thread::sleep(Duration::from_secs(tick_secs));
            if thread_stop.load(Ordering::Relaxed) {
                break;
            }
            block_on_sync_bridge(state.current().sweep_agent_schedules_once());
        }
    });
    AgentScheduleSweeperHandle {
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
    use crate::config::{
        AgentRuntimeManagedWorkerConfig, ManagedWorkerCapabilityActionConfig, ReliabilityConfig,
    };

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
    fn managed_worker_capability_policy_uses_operator_config() {
        let policy = managed_worker_capability_policy(&AgentRuntimeManagedWorkerConfig {
            allowed_actions: vec![
                ManagedWorkerCapabilityActionConfig::Tool,
                ManagedWorkerCapabilityActionConfig::NetworkEgress,
            ],
            approval_required_actions: vec![ManagedWorkerCapabilityActionConfig::Cli],
            allow_direct_network_egress: true,
            ..AgentRuntimeManagedWorkerConfig::default()
        });

        assert!(policy
            .allowed_actions
            .contains(&ferrogate_runtime::CapabilityAction::Tool));
        assert!(policy
            .allowed_actions
            .contains(&ferrogate_runtime::CapabilityAction::NetworkEgress));
        assert!(policy
            .approval_required_actions
            .contains(&ferrogate_runtime::CapabilityAction::Cli));
        assert!(policy.allow_direct_network_egress);
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
