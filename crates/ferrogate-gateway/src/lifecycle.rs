// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_config::is_caddyfile_path;
use ferrogate_config::{config_snapshot_id, Config};
use ferrogate_control_plane_client::action_identity::{
    ClientActionIdentity, ACTION_TIME_PREFLIGHT_PATH, TIME_TOKEN_HEADER,
};
use ferrogate_runtime::{ReloadCoordinator, ReloadOutcome};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

/// The `ferrogate check` / `ferrogate validate` pre-flight report.
///
/// Fallible since the #542 rework: it runs
/// [`ensure_auth_posture_is_declared`] -- the same gate `ferrogate run` runs --
/// BEFORE printing anything, so the documented pre-flight cannot report
/// `FerroGate config OK ... auth_required=true` for a config the gateway will
/// then refuse to boot. #542 intentionally stops deployments that never stated
/// their posture; the one place an operator must be able to find that out is
/// before the restart, not during it. Any non-fatal posture warning the gate
/// produces is appended to the report for the same reason.
///
/// #540 rework adds the tenancy posture to the same list, on the same argument.
/// `[tenancy] implicit_platform_operator = true` reverts #540 for every
/// undeclared key the deployment holds, and it exists only as a temporary way
/// past an upgrade -- but it was reported nowhere a human looks: a bare
/// `tracing::warn!` at startup, and `ferrogate check` printing `FerroGate
/// config OK` and exiting 0 forever after. See
/// `Config::tenancy_posture_warnings`.
pub fn format_validate_report(config: &Config) -> AnyResult<String> {
    let mut warnings = ensure_auth_posture_is_declared(config)?;
    warnings.extend(config.tenancy_posture_warnings());
    let summary = ConfigSummary::from_config(config);
    let mut report = format!(
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
    );
    for warning in warnings {
        report.push_str("\nwarning: ");
        report.push_str(&warning);
    }
    Ok(report)
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
/// A durable `[storage]` backend is not part of case 2, but it is not silent
/// either. `[auth] disabled = true` next to a configured Postgres/Supabase/D1
/// control plane is not a contradiction the way an inline `[[api_keys]]` entry
/// is -- that backend also holds request logs, audit events, tenants and
/// routes, so an operator can legitimately run an open laptop gateway against
/// one, and refusing it would break a third deployment shape this issue has no
/// quarrel with. What it IS, though, is a key store this deployment named and
/// then switched off: every virtual key in it is ignored and every caller is
/// admitted as platform root against a control plane that may be shared and
/// multi-tenant. So it is returned as a WARNING naming the store (returned, not
/// logged in here, so `ferrogate check` can print it and a test can assert it),
/// and case 1 still accepts the same backend as a credential *source*.
///
/// Returns the warnings the caller must surface. Refusals are `Err`.
pub(crate) fn ensure_auth_posture_is_declared(config: &Config) -> AnyResult<Vec<String>> {
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
        // Deliberately allowed, loudly (#542 rework, review finding 4): this is
        // a decision, not the oversight it was indistinguishable from before.
        let mut warnings = Vec::new();
        if let Some(store) = config.durable_api_key_store() {
            warnings.push(format!(
                "[auth] disabled = true switches authentication off for every request, but \
                 [storage] provider = \"{}\" is a durable control plane that holds virtual API \
                 keys: every key in it is IGNORED and every caller -- credentialed or not -- is \
                 admitted as an unrestricted platform operator over whatever that control plane \
                 contains. This is allowed because a durable backend also stores request logs, \
                 audit events and routes, so having one is not by itself a statement about \
                 authentication; if that control plane is shared with anything you care about, \
                 remove [auth] disabled",
                store.as_str()
            ));
        }
        return Ok(warnings);
    }

    if !config.has_credential_source() {
        bail!(
            "refusing to start: authentication is required (the default) but this config has no \
             credential source -- no [[api_keys]], no enabled [auth_service], and no durable \
             [storage] backend (postgres, supabase or cloudflare_d1) to hold virtual keys -- so \
             every request would be refused; add a credential source, or, if this gateway is \
             genuinely meant to be open to anyone who can reach it, say so by name.\n\nIn TOML or \
             YAML:\n\n[auth]\ndisabled = true\n\nIn a Caddyfile, in the global options block at \
             the top of the file:\n\n{{\n    auth off\n}}\n\n(before FerroGate #542 that open \
             posture was what an empty [[api_keys]] section silently landed on, and it admitted \
             every unauthenticated request as an unrestricted platform operator)"
        );
    }

    Ok(Vec::new())
}

pub fn format_reload_report(config: &Config) -> String {
    let summary = ConfigSummary::from_config(config);
    let report = ReloadReport::validate_only(summary.snapshot.clone());
    format!(
        "FerroGate reload config OK: listen={}, admin={}, runtime=pingora, tls={}, http2={}, snapshot={}, mode=validate-only, swap=false, routes={}, upstreams={}. Use --admin-url/--admin-token for process-local reload or --graceful-upgrade for listener-level reload.",
        summary.listen, summary.admin, summary.tls, summary.http2, report.candidate_snapshot, summary.routes, summary.upstreams
    )
}

pub fn execute_admin_reload(
    admin_url: &str,
    admin_token: Option<&str>,
    config_path: &Path,
    config: &Config,
    action_identity: &ClientActionIdentity,
) -> AnyResult<String> {
    let token = admin_token.context(
        "admin reload requires --admin-token or FERROGATE_ADMIN_TOKEN when --admin-url is set",
    )?;
    let endpoint = AdminEndpoint::parse(admin_url)?;
    let request_body = admin_reload_request_body(config_path)?;
    let response = post_admin_json(&endpoint, token, &request_body, action_identity)?;
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

pub fn execute_graceful_upgrade_reload(config_path: &Path, config: &Config) -> AnyResult<String> {
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

    fn action_time_preflight_path(&self) -> String {
        format!("{}{}", self.base_path, ACTION_TIME_PREFLIGHT_PATH)
    }

    fn base_url(&self) -> String {
        format!("http://{}{}", self.host_header(), self.base_path)
    }
}

#[derive(Debug, Clone)]
struct AdminHttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl AdminHttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn post_admin_json(
    endpoint: &AdminEndpoint,
    token: &str,
    body: &str,
    action_identity: &ClientActionIdentity,
) -> AnyResult<AdminHttpResponse> {
    ensure_admin_action_time(endpoint, token, action_identity)?;
    send_admin_request(
        endpoint,
        "POST",
        &endpoint.reload_path(),
        token,
        Some("application/json"),
        body,
        action_identity,
    )
}

fn ensure_admin_action_time(
    endpoint: &AdminEndpoint,
    token: &str,
    action_identity: &ClientActionIdentity,
) -> AnyResult<()> {
    if action_identity.server_issued_time().is_some() {
        return Ok(());
    }
    let response = send_admin_request(
        endpoint,
        "GET",
        &endpoint.action_time_preflight_path(),
        token,
        None,
        "",
        action_identity,
    )?;
    if !(200..300).contains(&response.status) {
        bail!(
            "client action time challenge failed: status={} body={}",
            response.status,
            response.body
        );
    }
    let server_time = response.header(TIME_TOKEN_HEADER).ok_or_else(|| {
        anyhow::anyhow!(
            "server did not issue {TIME_TOKEN_HEADER}; refusing admin reload without an authoritative timestamp"
        )
    })?;
    action_identity
        .accept_server_time(server_time)
        .map_err(|error| anyhow::anyhow!("server issued an unusable action time token: {error}"))?;
    Ok(())
}

fn send_admin_request(
    endpoint: &AdminEndpoint,
    method: &str,
    path: &str,
    token: &str,
    content_type: Option<&str>,
    body: &str,
    action_identity: &ClientActionIdentity,
) -> AnyResult<AdminHttpResponse> {
    let action_identity_headers = render_action_identity_headers(&action_identity.headers())?;
    let mut stream = TcpStream::connect(endpoint.connect_addr())
        .with_context(|| format!("failed to connect to admin API at {}", endpoint.base_url()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("failed to set admin API read timeout")?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n{action_identity_headers}",
        endpoint.host_header(),
    )
    .context("failed to write admin reload request")?;
    if let Some(content_type) = content_type {
        write!(stream, "Content-Type: {content_type}\r\n")
            .context("failed to write admin reload content type")?;
    }
    write!(stream, "Content-Length: {}\r\n\r\n{body}", body.len())
        .context("failed to write admin reload body")?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("failed to read admin reload response")?;
    parse_admin_http_response(&response)
}

fn render_action_identity_headers(headers: &[(String, String)]) -> AnyResult<String> {
    let mut rendered = String::new();
    for (name, value) in headers {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ' || byte == b'\t')
        {
            bail!(
                "refusing to write a client action identity header that could split the admin reload request"
            );
        }
        rendered.push_str(name);
        rendered.push_str(": ");
        rendered.push_str(value);
        rendered.push_str("\r\n");
    }
    Ok(rendered)
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
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();
    Ok(AdminHttpResponse {
        status,
        headers,
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
#[path = "lifecycle_admin_reload_test.rs"]
mod lifecycle_admin_reload_test;

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_runtime::RuntimeSnapshot;

    #[test]
    fn validate_report_is_metadata_only() {
        // #542 rework: a config with no credential source no longer reports OK
        // at all (see `check_refuses_the_same_config_run_refuses`), so the
        // metadata case needs a stated posture. `disabled = true` is the
        // migration answer for exactly this deployment shape.
        let mut config = Config::default();
        config.auth.disabled = true;

        let report = format_validate_report(&config).expect("a config with a stated posture");

        assert!(report.contains("FerroGate config OK"));
        assert!(report.contains("snapshot="));
        assert!(report.contains("auth_required=false"));

        let mut with_external_auth = Config::default();
        with_external_auth.auth_service.enabled = true;
        let report = format_validate_report(&with_external_auth)
            .expect("an externally-authenticated config");
        // #542: this line read `auth_required=false` before, because the report
        // was computed from `!config.api_keys.is_empty()` -- a third copy of the
        // predicate that did not even consult `[auth_service]`.
        assert!(report.contains("auth_required=true"));
    }

    /// #542: the report tracks the one predicate, including through the named
    /// switch. Re-derive it from `[[api_keys]]` (the pre-#542 expression) and
    /// the `disabled` case below still says `true`.
    #[test]
    fn validate_report_tracks_the_named_auth_switch() {
        let mut config = Config::default();
        config.auth.disabled = true;

        assert!(format_validate_report(&config)
            .expect("stated open posture")
            .contains("auth_required=false"));

        let mut with_external_auth = Config::default();
        with_external_auth.auth_service.enabled = true;
        with_external_auth.auth.disabled = false;

        assert!(format_validate_report(&with_external_auth)
            .expect("external auth is a credential source")
            .contains("auth_required=true"));
    }

    /// #542 rework, finding 3: the documented pre-flight refuses exactly what
    /// `ferrogate run` refuses.
    ///
    /// Pins the `ensure_auth_posture_is_declared(config)?` call at the top of
    /// `format_validate_report`. Delete it and `ferrogate check` goes back to
    /// printing `FerroGate config OK ... auth_required=true` for a config the
    /// gateway then refuses to boot -- which, for a release that intentionally
    /// stops existing deployments, means the operator finds out at restart.
    /// Asserting only the rendered string (what the previous version of this
    /// test did) cannot catch that.
    #[test]
    fn check_refuses_the_same_config_run_refuses() {
        let implicitly_open = Config::default();

        let report_error = format_validate_report(&implicitly_open)
            .expect_err("the pre-flight must refuse a config the gateway will not boot")
            .to_string();
        let run_error = ensure_auth_posture_is_declared(&implicitly_open)
            .expect_err("...and it must be the same refusal, not a second opinion")
            .to_string();

        assert_eq!(report_error, run_error);
        assert!(
            report_error.contains("no credential source"),
            "{report_error}"
        );
    }

    /// #542 rework, finding 4: the pre-flight prints the durable-key-store
    /// warning, so an operator running `ferrogate check` before a restart sees
    /// that `[auth] disabled = true` is ignoring a control plane full of keys.
    ///
    /// Pins the `for warning in warnings` loop in `format_validate_report`.
    #[test]
    fn check_prints_the_ignored_key_store_warning() {
        let mut config = Config::default();
        config.auth.disabled = true;
        config.storage.provider = ferrogate_storage::StorageProviderKind::CloudflareD1;

        let report = format_validate_report(&config).expect("a stated open posture still starts");

        assert!(report.contains("FerroGate config OK"), "{report}");
        assert!(report.contains("warning: "), "{report}");
        assert!(report.contains("cloudflare_d1"), "{report}");
    }

    /// #540 rework 2, review minor 2: the previous round moved the tenancy
    /// posture into `ferrogate check` and then pinned it with three assertions
    /// that called `Config::tenancy_posture_warnings()` directly, inside
    /// `ferrogate-config`. None of them could see this file, so deleting
    /// `warnings.extend(config.tenancy_posture_warnings())` above re-created --
    /// untested -- the exact defect that finding named: an operator holding the
    /// legacy opt-in reads `FerroGate config OK`, exit 0, forever.
    ///
    /// Pins that one line. Delete it and the first two assertions red. It
    /// cannot be satisfied by annotating a fixture: the input IS an
    /// un-annotated key under the opt-in, and the third assertion holds the
    /// other direction, so a build that simply printed every warning always
    /// would red too.
    #[test]
    fn check_prints_the_tenancy_posture_an_operator_would_otherwise_never_see() {
        let opted_in = Config::from_toml_str(
            r#"
listen = "127.0.0.1:8080"

[tenancy]
implicit_platform_operator = true

# #540-undeclared-on-purpose: the key the pre-flight has to name
[[api_keys]]
id = "bootstrap"
name = "Bootstrap"
key = "bootstrap-secret"
"#,
        )
        .expect("the documented escape hatch loads");

        let report =
            format_validate_report(&opted_in).expect("the opt-in is a warning, not a refusal");
        assert!(report.contains("FerroGate config OK"), "{report}");
        assert!(
            report.contains("warning: ") && report.contains("implicit_platform_operator"),
            "`ferrogate check` must name the switch that reverts #540 for this deployment: \
             {report}"
        );
        assert!(
            report.contains("bootstrap"),
            "...and every key it is silently promoting to platform root: {report}"
        );

        // The other direction: a deployment that declared its keys gets no
        // tenancy warning at all, so this is not a banner every operator learns
        // to skip.
        let declared = Config::from_toml_str(
            r#"
listen = "127.0.0.1:8080"

[[api_keys]]
id = "operator"
name = "Operator"
key = "operator-secret"
platform_operator = true
"#,
        )
        .expect("a fully declared config");
        let report = format_validate_report(&declared).expect("a declared config reports OK");
        assert!(!report.contains("implicit_platform_operator"), "{report}");
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

    /// #542 rework, finding 1: a gateway whose keys all live in a Cloudflare D1
    /// control plane -- the hosted-on-Cloudflare posture this project is heading
    /// toward -- starts, and starts REQUIRING authentication.
    ///
    /// Pins the `CloudflareD1` arm of `Config::durable_api_key_store`
    /// (`ferrogate-config/src/config/types.rs`). The shipped predicate spelled
    /// this `matches!(provider, Postgres | Supabase)`: a D1 deployment was told
    /// it had "no credential source" and pointed at `[auth] disabled = true`,
    /// i.e. at switching authentication off, which is the outcome #542 exists to
    /// prevent. Restore that spelling and this reds. Its sibling in
    /// `config/tests.rs` (`credential_sources_cover_every_storage_provider`)
    /// catches the review's other named mutation -- deleting `Postgres |` and
    /// keeping `Supabase` -- by pinning the whole set.
    #[test]
    fn a_cloudflare_d1_control_plane_is_a_credential_source() {
        let mut config = Config::default();
        config.storage.provider = ferrogate_storage::StorageProviderKind::CloudflareD1;

        let warnings = ensure_auth_posture_is_declared(&config)
            .expect("a D1 gateway whose credentials are all virtual keys must start");

        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(config.auth_required());
        assert_eq!(
            config.durable_api_key_store(),
            Some(ferrogate_storage::StorageProviderKind::CloudflareD1)
        );
    }

    /// #542 rework, finding 4: `[auth] disabled = true` next to a durable
    /// `[storage]` backend is ALLOWED -- deliberately, not by oversight -- and
    /// says so out loud, naming the key store it is ignoring.
    ///
    /// Pins the `durable_api_key_store()` warning branch in
    /// `ensure_auth_posture_is_declared`. Delete it and the deployment goes back
    /// to admitting every caller as platform root against a shared control plane
    /// with nothing said about it, and this test reds. Deleting the `declared`
    /// accumulation for `[auth_service]` (the review's second named surviving
    /// mutation) is caught by
    /// `auth_disabled_alongside_a_declared_credential_source_refuses_to_start`
    /// below and by the `is_err()` assertion here: the two cases are asserted to
    /// have DIFFERENT outcomes on the same field, so collapsing either into the
    /// other cannot stay green.
    #[test]
    fn auth_disabled_next_to_a_durable_key_store_is_allowed_but_warned_about() {
        for provider in [
            ferrogate_storage::StorageProviderKind::Postgres,
            ferrogate_storage::StorageProviderKind::Supabase,
            ferrogate_storage::StorageProviderKind::CloudflareD1,
        ] {
            let mut config = Config::default();
            config.auth.disabled = true;
            config.storage.provider = provider;

            let warnings = ensure_auth_posture_is_declared(&config).unwrap_or_else(|error| {
                panic!(
                    "a durable [storage] backend is not a declared credential the way \
                     [[api_keys]] is, so it must not refuse: {error}"
                )
            });

            assert_eq!(warnings.len(), 1, "{warnings:?}");
            assert!(
                warnings[0].contains(provider.as_str()),
                "the warning must name the ignored key store: {}",
                warnings[0]
            );
            assert!(
                warnings[0].contains("IGNORED"),
                "...and say what happens to the keys in it: {}",
                warnings[0]
            );

            // The static contradiction on the SAME config is still a refusal:
            // the two cases are decided separately and deliberately.
            let mut with_static_credential = config.clone();
            with_static_credential.auth_service.enabled = true;
            assert!(
                ensure_auth_posture_is_declared(&with_static_credential).is_err(),
                "a declared [auth_service] next to [auth] disabled is still refused"
            );
        }

        // ...and a memory-backed open gateway has no store to warn about, so the
        // warning is about the named backend, not about `disabled` itself.
        let mut memory = Config::default();
        memory.auth.disabled = true;
        assert!(ensure_auth_posture_is_declared(&memory)
            .expect("a laptop gateway starts")
            .is_empty());
    }

    /// #542 rework, finding 2: a Caddyfile-bridged reverse proxy has an
    /// expressible remedy, and the refusal names it.
    ///
    /// This is the config shape the original slice broke: a Caddy-migrated pure
    /// L7 reverse proxy with no `ai_gateway` block, whose format has no
    /// `[[api_keys]]`, no `[auth_service]` and (before this rework) no way at
    /// all to say "this gateway is open" -- it was refused at boot and told to
    /// write a TOML section a Caddyfile cannot contain.
    ///
    /// Pins the `"auth"` arm of `Parser::parse_global_options`, the
    /// `auth: AuthConfig { disabled: config.auth_disabled }` mapping in
    /// `config/loader.rs`, and the Caddyfile spelling inside the refusal text.
    /// Hard-code the bridge back to `AuthConfig::default()` and the second half
    /// reds; drop the spelling from the error and the first half reds.
    #[test]
    fn a_keyless_caddyfile_reverse_proxy_is_refused_with_a_caddyfile_remedy() {
        let keyless = r#"
:8080 {
    reverse_proxy https://httpbin.org
}
"#;

        let refused = Config::from_caddyfile_str(keyless, "Caddyfile")
            .expect("a keyless reverse proxy is a valid Caddyfile");
        let error = ensure_auth_posture_is_declared(&refused)
            .expect_err("it has no credential source and has not stated a posture")
            .to_string();
        assert!(error.contains("no credential source"), "{error}");
        assert!(
            error.contains("Caddyfile") && error.contains("auth off"),
            "the remedy must be one a Caddyfile can actually express: {error}"
        );

        let stated = Config::from_caddyfile_str(
            r#"
{
    auth off
}

:8080 {
    reverse_proxy https://httpbin.org
}
"#,
            "Caddyfile",
        )
        .expect("`auth off` is part of the grammar");
        assert!(ensure_auth_posture_is_declared(&stated)
            .expect("a stated open posture starts")
            .is_empty());
        assert!(!stated.auth_required());

        // ...and the bridge does not hand out the open posture for free: the
        // same file without the directive still requires authentication.
        assert!(refused.auth_required());
    }

    /// #542: each credential source, on its own, is enough to start. The durable
    /// backend case is the whole point of the issue -- a deployment whose keys
    /// are all virtual must boot, and must boot REQUIRING authentication.
    #[test]
    fn any_credential_source_starts_with_authentication_required() {
        let with_static_key =
            Config::from_toml_str(
                "[[api_keys]]\nid = \"k1\"\nname = \"k1\"\nkey = \"secret\"\nplatform_operator = true\n",
            )
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
