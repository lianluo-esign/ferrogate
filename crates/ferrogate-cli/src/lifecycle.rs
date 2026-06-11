// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::config::{config_snapshot_id, Config};
use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_config::is_caddyfile_path;
use ferrogate_runtime::{ReloadCoordinator, ReloadOutcome};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

pub(crate) fn format_validate_report(config: &Config) -> String {
    let summary = ConfigSummary::from_config(config);
    format!(
        "FerroGate config OK: listen={}, admin={}, runtime=pingora, tls={}, http2={}, snapshot={}, upstreams={}, routes={}, providers={}, models={}, api_keys={}, auth_required={}",
        summary.listen,
        summary.admin,
        summary.tls,
        summary.http2,
        summary.snapshot,
        summary.upstreams,
        summary.routes,
        summary.providers,
        summary.models,
        summary.api_keys,
        summary.auth_required
    )
}

pub(crate) fn format_reload_report(config: &Config) -> String {
    let summary = ConfigSummary::from_config(config);
    let report = ReloadReport::validate_only(summary.snapshot.clone());
    format!(
        "FerroGate reload config OK: listen={}, admin={}, runtime=pingora, tls={}, http2={}, snapshot={}, mode=validate-only, swap=false, routes={}, upstreams={}. Use --admin-url/--admin-token for process-local reload or --graceful-upgrade for listener-level reload.",
        summary.listen, summary.admin, summary.tls, summary.http2, report.candidate_snapshot, summary.routes, summary.upstreams
    )
}

pub(crate) fn execute_admin_reload(
    admin_url: &str,
    admin_token: Option<&str>,
    config_path: &Path,
    config: &Config,
) -> AnyResult<String> {
    let token = admin_token.context(
        "admin reload requires --admin-token or FERROGATE_ADMIN_TOKEN when --admin-url is set",
    )?;
    let endpoint = AdminEndpoint::parse(admin_url)?;
    let request_body = admin_reload_request_body(config_path)?;
    let response = post_admin_json(&endpoint, token, &request_body)?;
    if !(200..300).contains(&response.status) {
        bail!(
            "admin reload failed: status={} body={}",
            response.status,
            response.body
        );
    }

    let payload: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("admin reload returned invalid JSON: {}", response.body))?;
    let valid = payload
        .get("valid")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let committed = payload
        .get("committed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mode = payload
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let active_snapshot = payload
        .get("active_snapshot")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let candidate_snapshot = payload
        .get("candidate_snapshot")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| config_snapshot_id(config));
    let error = payload
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("none");

    Ok(format!(
        "FerroGate reload request OK: admin={}, valid={}, committed={}, mode={}, active_snapshot={}, candidate_snapshot={}, error={}",
        endpoint.base_url(),
        valid,
        committed,
        mode,
        active_snapshot,
        candidate_snapshot,
        error
    ))
}

pub(crate) fn execute_graceful_upgrade_reload(
    config_path: &Path,
    config: &Config,
) -> AnyResult<String> {
    let pid_file = config
        .reliability
        .graceful_upgrade_pid_file
        .as_deref()
        .context("graceful upgrade reload requires reliability.graceful_upgrade_pid_file")?;
    if config.reliability.graceful_upgrade_sock.is_none() {
        bail!("graceful upgrade reload requires reliability.graceful_upgrade_sock");
    }
    let old_pid = read_pid_file(pid_file)?;
    let child = spawn_upgrade_process(config_path)?;
    send_sigquit(old_pid)?;
    Ok(format!(
        "FerroGate graceful upgrade requested: old_pid={}, new_pid={}, config={}, mode=listener-level, signal=SIGQUIT",
        old_pid,
        child.id(),
        config_path.display()
    ))
}

fn read_pid_file(path: &str) -> AnyResult<u32> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read graceful upgrade pid file {path}"))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid in graceful upgrade pid file {path}"))
}

fn spawn_upgrade_process(config_path: &Path) -> AnyResult<std::process::Child> {
    let executable = std::env::current_exe().context("failed to locate current executable")?;
    Command::new(executable)
        .args(["run", "--config"])
        .arg(config_path)
        .arg("--upgrade")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start graceful upgrade process")
}

#[cfg(unix)]
fn send_sigquit(pid: u32) -> AnyResult<()> {
    let status = Command::new("kill")
        .args(["-QUIT", &pid.to_string()])
        .status()
        .with_context(|| format!("failed to send SIGQUIT to process {pid}"))?;
    if !status.success() {
        bail!("failed to send SIGQUIT to process {pid}: kill exited with {status}");
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_sigquit(_pid: u32) -> AnyResult<()> {
    bail!("graceful upgrade reload is only supported on Unix platforms")
}

fn admin_reload_request_body(config_path: &Path) -> AnyResult<String> {
    let raw = std::fs::read_to_string(config_path).with_context(|| {
        format!(
            "admin reload requires a readable candidate config file: {}",
            config_path.display()
        )
    })?;
    if is_caddyfile_path(config_path) {
        Ok(serde_json::json!({
            "config_caddyfile": raw,
            "filename": config_path.file_name().and_then(|name| name.to_str()).unwrap_or("candidate.Caddyfile")
        })
        .to_string())
    } else {
        Ok(serde_json::json!({ "config_toml": raw }).to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdminEndpoint {
    host: String,
    port: u16,
    base_path: String,
}

impl AdminEndpoint {
    fn parse(raw: &str) -> AnyResult<Self> {
        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("--admin-url currently supports only http:// URLs"))?;
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            bail!("--admin-url must include a host");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (
                host.to_string(),
                port.parse()
                    .with_context(|| format!("invalid admin URL port: {port}"))?,
            ),
            _ => (authority.to_string(), 80),
        };
        let base_path = if path.is_empty() {
            String::new()
        } else {
            format!("/{}", path.trim_end_matches('/'))
        };
        Ok(Self {
            host,
            port,
            base_path,
        })
    }

    fn connect_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn host_header(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            self.connect_addr()
        }
    }

    fn reload_path(&self) -> String {
        format!("{}/admin/v1/config/reload", self.base_path)
    }

    fn base_url(&self) -> String {
        format!("http://{}{}", self.host_header(), self.base_path)
    }
}

#[derive(Debug, Clone)]
struct AdminHttpResponse {
    status: u16,
    body: String,
}

fn post_admin_json(
    endpoint: &AdminEndpoint,
    token: &str,
    body: &str,
) -> AnyResult<AdminHttpResponse> {
    let mut stream = TcpStream::connect(endpoint.connect_addr())
        .with_context(|| format!("failed to connect to admin API at {}", endpoint.base_url()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("failed to set admin API read timeout")?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        endpoint.reload_path(),
        endpoint.host_header(),
        token,
        body.len(),
        body
    )
    .context("failed to write admin reload request")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("failed to read admin reload response")?;
    parse_admin_http_response(&response)
}

fn parse_admin_http_response(raw: &str) -> AnyResult<AdminHttpResponse> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("admin API returned malformed HTTP response"))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("admin API returned malformed HTTP status"))?;
    Ok(AdminHttpResponse {
        status,
        body: body.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReloadReport {
    pub(crate) candidate_snapshot: String,
    pub(crate) active_snapshot: String,
    pub(crate) committed: bool,
    pub(crate) mode: &'static str,
}

impl ReloadReport {
    fn validate_only(candidate_snapshot: String) -> Self {
        let coordinator = ReloadCoordinator::new("unmanaged-active");
        let candidate = coordinator.prepare(candidate_snapshot);
        Self::from_outcome(coordinator.reject(candidate, "validate-only"))
    }

    fn from_outcome(outcome: ReloadOutcome) -> Self {
        Self {
            candidate_snapshot: outcome.candidate.id,
            active_snapshot: outcome.active.id,
            committed: outcome.committed,
            mode: "validate-only",
        }
    }
}

#[derive(Debug, Clone)]
struct ConfigSummary {
    listen: String,
    admin: String,
    tls: bool,
    http2: bool,
    snapshot: String,
    upstreams: usize,
    routes: usize,
    providers: usize,
    models: usize,
    api_keys: usize,
    auth_required: bool,
}

impl ConfigSummary {
    fn from_config(config: &Config) -> Self {
        Self {
            listen: config.listen.clone(),
            admin: config
                .admin
                .listen
                .clone()
                .unwrap_or_else(|| "off".to_string()),
            tls: config.tls.is_enabled(),
            http2: config.tls.http2,
            snapshot: config_snapshot_id(config),
            upstreams: config.upstreams.len(),
            routes: config.routes.len(),
            providers: config.providers.len(),
            models: config.models.len(),
            api_keys: config.api_keys.len(),
            auth_required: !config.api_keys.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::RuntimeSnapshot;

    #[test]
    fn validate_report_is_metadata_only() {
        let config = Config::default();

        let report = format_validate_report(&config);

        assert!(report.contains("FerroGate config OK"));
        assert!(report.contains("snapshot="));
        assert!(report.contains("auth_required=false"));
    }

    #[test]
    fn reload_report_declares_validate_only_no_swap_mode() {
        let config = Config::default();

        let report = format_reload_report(&config);

        assert!(report.contains("FerroGate reload config OK"));
        assert!(report.contains("mode=validate-only"));
        assert!(report.contains("swap=false"));
        assert!(report.contains("--graceful-upgrade"));
    }

    #[test]
    fn admin_endpoint_parses_http_base_url() {
        let endpoint = AdminEndpoint::parse("http://127.0.0.1:18080").unwrap();

        assert_eq!(endpoint.connect_addr(), "127.0.0.1:18080");
        assert_eq!(endpoint.host_header(), "127.0.0.1:18080");
        assert_eq!(endpoint.reload_path(), "/admin/v1/config/reload");
        assert_eq!(endpoint.base_url(), "http://127.0.0.1:18080");
    }

    #[test]
    fn admin_endpoint_preserves_base_path() {
        let endpoint = AdminEndpoint::parse("http://localhost:8080/ferrogate/").unwrap();

        assert_eq!(endpoint.connect_addr(), "localhost:8080");
        assert_eq!(endpoint.reload_path(), "/ferrogate/admin/v1/config/reload");
        assert_eq!(endpoint.base_url(), "http://localhost:8080/ferrogate");
    }

    #[test]
    fn admin_reload_request_body_uses_caddyfile_or_toml_payload_key() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("ferrogate.toml");
        std::fs::write(&toml_path, "listen = \"127.0.0.1:8080\"\n").unwrap();
        let caddyfile_path = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile_path, "127.0.0.1:8080 {\n}\n").unwrap();

        let toml_body: serde_json::Value =
            serde_json::from_str(&admin_reload_request_body(&toml_path).unwrap()).unwrap();
        let caddyfile_body: serde_json::Value =
            serde_json::from_str(&admin_reload_request_body(&caddyfile_path).unwrap()).unwrap();

        assert!(toml_body.get("config_toml").is_some());
        assert!(toml_body.get("config_caddyfile").is_none());
        assert!(caddyfile_body.get("config_caddyfile").is_some());
        assert_eq!(
            caddyfile_body.get("filename").and_then(Value::as_str),
            Some("Caddyfile")
        );
    }

    #[test]
    fn read_pid_file_rejects_missing_or_invalid_pid() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.pid");
        let invalid = dir.path().join("invalid.pid");
        std::fs::write(&invalid, "not-a-pid\n").unwrap();

        assert!(read_pid_file(&missing.to_string_lossy()).is_err());
        assert!(read_pid_file(&invalid.to_string_lossy()).is_err());
    }

    #[test]
    fn read_pid_file_accepts_numeric_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrogate.pid");
        std::fs::write(&path, "12345\n").unwrap();

        assert_eq!(read_pid_file(&path.to_string_lossy()).unwrap(), 12345);
    }

    #[test]
    fn reload_report_uses_runtime_reject_without_publishing_candidate() {
        let config = Config::default();
        let candidate = config_snapshot_id(&config);

        let report = ReloadReport::validate_only(candidate.clone());

        assert_eq!(report.candidate_snapshot, candidate);
        assert_eq!(report.active_snapshot, "unmanaged-active");
        assert!(!report.committed);
        assert_eq!(report.mode, "validate-only");
    }

    #[test]
    fn reload_report_projects_committed_outcome_as_active_candidate() {
        let outcome = ReloadOutcome {
            active: RuntimeSnapshot {
                id: "candidate-b".to_string(),
                generation: 2,
            },
            candidate: RuntimeSnapshot {
                id: "candidate-b".to_string(),
                generation: 2,
            },
            committed: true,
            reason: None,
        };

        let report = ReloadReport::from_outcome(outcome);

        assert_eq!(report.active_snapshot, "candidate-b");
        assert_eq!(report.candidate_snapshot, "candidate-b");
        assert!(report.committed);
    }
}
