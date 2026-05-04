mod body;
mod chat;
mod dispatch;
mod handlers;
mod local;
mod proxy;

use anyhow::{Context, Result as AnyResult};
use pingora::{
    listeners::tls::TlsSettings,
    proxy::http_proxy_service,
    server::{
        configuration::{Opt as PingoraOpt, ServerConf},
        Server,
    },
};
use std::path::PathBuf;
use tracing::info;

use crate::{
    acme::{ensure_certificate, AcmeCertificatePaths},
    config::{Config, RouteRule, Upstream},
    state::SharedAppState,
    telemetry::start_otlp_background_sender,
};

#[derive(Debug, Default, Clone)]
pub(crate) struct ProxyContext {
    request_id: String,
    trace_id: Option<String>,
    tenant_id: Option<String>,
    route: Option<RouteRule>,
    upstream: Option<Upstream>,
    upstream_url: Option<String>,
    target_path_query: Option<String>,
    original_host: Option<String>,
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
    let state = SharedAppState::with_source_path(config, source_path);
    let _otlp_sender = start_otlp_background_sender(state.current());
    let gateway = FerroGateway { state };

    let pingora_opt = PingoraOpt {
        upgrade,
        ..PingoraOpt::default()
    };
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), server_conf);
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, gateway);
    if let Some(paths) = resolve_tls_certificate_paths(&tls)? {
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
}
