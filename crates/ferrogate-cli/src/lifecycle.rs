// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_config::is_caddyfile_path;
use ferrogate_config::{config_snapshot_id, Config};
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

/// Startup gate for the deployment's authentication posture (issue #542).
///
/// Two configs are refused before the gateway ever binds a listener, both
/// because they mean something the operator almost certainly did not intend and
/// neither can be resolved safely at request time:
///
/// 1. **Nothing to authenticate against.** `[auth] disabled` is false (the
///    default) but the config has no credential source at all. This is exactly
///    the deployment that ran in the implicit open posture before #542. It does
///    not silently flip to "refuse every request", and it emphatically does not
///    keep admitting everyone as platform root: it stops, and the error names
///    the switch that restores the old behaviour. Same fail-closed shape, and
///    the same message spirit, as `execute_control_api_serve`.
/// 2. **A contradiction.** `[auth] disabled = true` alongside a declared static
///    credential source (`[[api_keys]]` or an enabled `[auth_service]`). Those
///    credentials would be silently ignored and every request admitted as root
///    -- an operator who wrote both is protected by neither, and which one they
///    meant is not ours to guess.
///
/// A durable `[storage]` backend is not part of case 2: a virtual key can be
/// minted into a shared control plane by anyone, at any time, including long
/// after this deployment chose its posture, so its presence is not a statement
/// this deployment made. Case 1 accepts it as a credential *source* (the keys
/// can be resolved) without letting it override a named `disabled = true`.
pub(crate) fn ensure_auth_posture_is_declared(config: &Config) -> AnyResult<()> {
    if config.auth.disabled {
        let mut declared: Vec<&str> = Vec::new();
        if !config.api_keys.is_empty() {
            declared.push("[[api_keys]]");
        }
        if config.auth_service.enabled {
            declared.push("[auth_service] enabled = true");
        }
        if !declared.is_empty() {
            bail!(
                "refusing to start: [auth] disabled = true switches authentication off for every \
                 request, but this config also declares a credential source ({}) that would then \
                 never be consulted -- every caller, credentialed or not, would be admitted as an \
                 unrestricted platform operator; remove [auth] disabled or remove the credential \
                 source",
                declared.join(", ")
            );
        }
        return Ok(());
    }

    if !config.has_credential_source() {
        bail!(
            "refusing to start: authentication is required (the default) but this config has no \
             credential source -- no [[api_keys]], no enabled [auth_service], and no durable \
             postgres/supabase [storage] backend to hold virtual keys -- so every request would \
             be refused; add a credential source, or, if this gateway is genuinely meant to be \
             open to anyone who can reach it, say so by name with:\n\n[auth]\ndisabled = true\n\n\
             (before FerroGate #542 that open posture was what an empty [[api_keys]] section \
             silently landed on, and it admitted every unauthenticated request as an unrestricted \
             platform operator)"
        );
    }

    Ok(())
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
            // #542: the one predicate, not a third hand-copied expression.
            // This one had drifted furthest -- it ignored `[auth_service]`
            // entirely, so `ferrogate check` reported `auth_required=false` for
            // a deployment that authenticated every request against an external
            // service.
            auth_required: config.auth_required(),
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
        // #542: an empty config REQUIRES authentication. This line read
        // `auth_required=false` before, and the report was computed from
        // `!config.api_keys.is_empty()` -- a third copy of the predicate that
        // did not even consult `[auth_service]`.
        assert!(report.contains("auth_required=true"));
    }

    /// #542: the report tracks the one predicate, including through the named
    /// switch. Re-derive it from `[[api_keys]]` (the pre-#542 expression) and
    /// the `disabled` case below still says `true`.
    #[test]
    fn validate_report_tracks_the_named_auth_switch() {
        let mut config = Config::default();
        config.auth.disabled = true;

        assert!(format_validate_report(&config).contains("auth_required=false"));

        let mut with_external_auth = Config::default();
        with_external_auth.auth_service.enabled = true;
        with_external_auth.auth.disabled = false;

        assert!(format_validate_report(&with_external_auth).contains("auth_required=true"));
    }

    /// #542 migration: the deployment that used to run in the implicit open
    /// posture -- no `[[api_keys]]`, no `[auth_service]`, no durable backend --
    /// does not start silently and does not flip silently. It stops, and the
    /// error names the switch that restores the old behaviour.
    ///
    /// Delete the `has_credential_source` branch and this goes red.
    #[test]
    fn a_config_with_no_credential_source_refuses_to_start_and_names_the_switch() {
        let config = Config::default();

        let error = ensure_auth_posture_is_declared(&config)
            .expect_err("an implicitly-open gateway must not start")
            .to_string();

        assert!(error.contains("no credential source"), "{error}");
        assert!(
            error.contains("[auth]") && error.contains("disabled = true"),
            "the error must name the switch verbatim so an operator can paste it: {error}"
        );
    }

    /// #542: each credential source, on its own, is enough to start. The durable
    /// backend case is the whole point of the issue -- a deployment whose keys
    /// are all virtual must boot, and must boot REQUIRING authentication.
    #[test]
    fn any_credential_source_starts_with_authentication_required() {
        let with_static_key =
            Config::from_toml_str("[[api_keys]]\nid = \"k1\"\nname = \"k1\"\nkey = \"secret\"\n")
                .expect("a config with one static key");
        assert!(ensure_auth_posture_is_declared(&with_static_key).is_ok());
        assert!(with_static_key.auth_required());

        let mut with_auth_service = Config::default();
        with_auth_service.auth_service.enabled = true;
        assert!(ensure_auth_posture_is_declared(&with_auth_service).is_ok());
        assert!(with_auth_service.auth_required());

        let mut with_durable_keys = Config::default();
        with_durable_keys.storage.provider = ferrogate_storage::StorageProviderKind::Supabase;
        assert!(
            ensure_auth_posture_is_declared(&with_durable_keys).is_ok(),
            "#542: a deployment whose credentials are all virtual keys must start"
        );
        assert!(
            with_durable_keys.auth_required(),
            "#542: ...and it must start REQUIRING authentication, which is the whole bug"
        );
    }

    /// #542 ask 2: the open posture is opted into by name, and saying so is
    /// enough on its own -- no credential source needed, because there is
    /// nothing to authenticate.
    #[test]
    fn auth_disabled_by_name_starts_without_a_credential_source() {
        let mut config = Config::default();
        config.auth.disabled = true;

        assert!(ensure_auth_posture_is_declared(&config).is_ok());
        assert!(!config.auth_required());
    }

    /// #542: `[auth] disabled = true` next to a declared static credential is a
    /// contradiction whose quiet resolution is "the keys are ignored and
    /// everyone is platform root" -- the exact outcome the issue exists to
    /// prevent. Refused, with both halves named.
    #[test]
    fn auth_disabled_alongside_a_declared_credential_source_refuses_to_start() {
        let mut config = Config::default();
        config.auth.disabled = true;
        config.auth_service.enabled = true;

        let error = ensure_auth_posture_is_declared(&config)
            .expect_err("a config that both disables and configures authentication is refused")
            .to_string();

        assert!(error.contains("[auth] disabled = true"), "{error}");
        assert!(error.contains("[auth_service]"), "{error}");
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
