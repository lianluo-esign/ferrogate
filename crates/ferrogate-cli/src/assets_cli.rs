// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: `ferrogate assets push/pull/list/delete` (issue #178) --
// the CLI entry point for /v1/assets/* (#176/#177), the "deploy once"
// self-serve path the static-asset-hosting epic (#175) is built around.
// Uses a hand-rolled raw-TCP HTTP client (mirroring lifecycle.rs's
// AdminEndpoint, generalized to arbitrary methods/binary bodies) rather
// than adding a new HTTP client dependency -- ferrogate-cli's main() is a
// sync binary entrypoint, same constraint execute_admin_reload already
// works within.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_control_plane_client::action_identity::{ClientActionIdentity, FingerprintEnv};
use ferrogate_control_plane_client::auth::AuthSource;
use ferrogate_control_plane_client::context::{EffectiveContext, DEFAULT_TIMEOUT_MILLIS};
use ferrogate_control_plane_client::output::OutputFormat;

use crate::cli::{AssetsCommands, AssetsIdentityArgs, AssetsListArgs, AssetsPushArgs};

pub(crate) fn execute_assets_command(command: AssetsCommands) -> AnyResult<()> {
    match command {
        AssetsCommands::Push(args) => execute_push(args),
        AssetsCommands::Pull(args) => execute_pull(args),
        AssetsCommands::List(args) => execute_list(args),
        AssetsCommands::Delete(args) => execute_delete(args),
    }
}

/// Mint the action identity for one invocation of a raw-TCP command
/// (issue #548).
///
/// These command groups predate the typed client and have no context store: the
/// operator hands them a `--gateway-url` and an `--api-key` directly. So the
/// [`EffectiveContext`] is assembled from exactly what the invocation knows,
/// rather than inventing scope it does not have — `context_name` is `None`
/// because no named context was selected, and the credential is
/// [`AuthSource::Inline`] because it arrived as a value rather than as a
/// variable name to read later. Neither carries material into the fingerprint:
/// `AuthSource::audit_source` maps `Inline` to the string `inline`.
///
/// Minted **once per invocation**, at the command-group entry point, so all of
/// an invocation's requests share one `action_id` — the same rule the typed
/// client follows.
pub(crate) fn mint_action_identity(
    gateway_url: &str,
    api_key: &str,
) -> AnyResult<ClientActionIdentity> {
    let context = EffectiveContext {
        context_name: None,
        endpoint: gateway_url.to_string(),
        tenant: None,
        project: None,
        workspace: None,
        ca_bundle_path: None,
        tls_insecure_skip_verify: false,
        timeout_millis: DEFAULT_TIMEOUT_MILLIS,
        auth: AuthSource::Inline {
            token: api_key.to_string(),
        },
        output: OutputFormat::Json,
        non_interactive: true,
    };
    ClientActionIdentity::mint(&context, &FingerprintEnv::from_process())
        .map_err(|error| anyhow::anyhow!("{error}"))
}

fn execute_push(args: AssetsPushArgs) -> AnyResult<()> {
    let content = std::fs::read(&args.path)
        .with_context(|| format!("failed to read {}", args.path.display()))?;
    let content_type = args
        .content_type
        .unwrap_or_else(|| guess_content_type(&args.path));
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let identity = mint_action_identity(&args.connection.gateway_url, &args.connection.api_key)?;
    let query = build_query(&[("platform", &args.platform), ("channel", &args.channel)]);
    let path = format!(
        "/v1/assets/{}/{}/{}{query}",
        args.asset_type, args.name, args.version
    );
    let response = send_request(
        &endpoint,
        "PUT",
        &path,
        &args.connection.api_key,
        Some(&content_type),
        &content,
        &identity,
    )?;
    print_asset_push_response(&response)
}

fn execute_pull(args: AssetsIdentityArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let identity = mint_action_identity(&args.connection.gateway_url, &args.connection.api_key)?;
    let query = build_query(&[("platform", &args.platform)]);
    let path = format!(
        "/v1/assets/{}/{}/{}{query}",
        args.asset_type, args.name, args.version
    );
    let response = send_request(
        &endpoint,
        "GET",
        &path,
        &args.connection.api_key,
        None,
        &[],
        &identity,
    )?;
    if !(200..300).contains(&response.status) {
        bail!(
            "pull failed: status={} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }
    match args.output.filter(|path| path.as_os_str() != "-") {
        Some(path) => {
            std::fs::write(&path, &response.body)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("wrote {} bytes to {}", response.body.len(), path.display());
        }
        None => {
            std::io::stdout()
                .write_all(&response.body)
                .context("failed to write asset content to stdout")?;
        }
    }
    Ok(())
}

fn execute_list(args: AssetsListArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let identity = mint_action_identity(&args.connection.gateway_url, &args.connection.api_key)?;
    let path = match args.asset_type {
        Some(asset_type) => format!("/v1/assets/{asset_type}"),
        None => "/v1/assets".to_string(),
    };
    let response = send_request(
        &endpoint,
        "GET",
        &path,
        &args.connection.api_key,
        None,
        &[],
        &identity,
    )?;
    print_json_or_raise(&response, "list")
}

fn execute_delete(args: AssetsIdentityArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let identity = mint_action_identity(&args.connection.gateway_url, &args.connection.api_key)?;
    let query = build_query(&[("platform", &args.platform)]);
    let path = format!(
        "/v1/assets/{}/{}/{}{query}",
        args.asset_type, args.name, args.version
    );
    let response = send_request(
        &endpoint,
        "DELETE",
        &path,
        &args.connection.api_key,
        None,
        &[],
        &identity,
    )?;
    print_json_or_raise(&response, "delete")
}

/// Assemble a `?a=b&c=d` query string from the set `Some` options, or an empty
/// string when none are set (#260 `--platform`/`--channel`).
fn build_query(params: &[(&str, &Option<String>)]) -> String {
    let parts: Vec<String> = params
        .iter()
        .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

pub(crate) fn print_json_or_raise(response: &RawHttpResponse, action: &str) -> AnyResult<()> {
    if !(200..300).contains(&response.status) {
        bail!(
            "{action} failed: status={} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }
    println!("{}", String::from_utf8_lossy(&response.body));
    Ok(())
}

fn print_asset_push_response(response: &RawHttpResponse) -> AnyResult<()> {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    write_asset_push_response(response, &mut stdout.lock(), &mut stderr.lock())
}

fn write_asset_push_response(
    response: &RawHttpResponse,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> AnyResult<()> {
    if !(200..300).contains(&response.status) {
        bail!(
            "push failed: status={} body={}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }
    // #528: 202 is the asset push's "stored, but WITHHELD" terminal. Keep the
    // warning on this command-specific writer: the shared JSON printer is also
    // used by asset list/delete and every plans command, where this statement
    // would be false if one of those operations ever gained a 202 terminal.
    if response.status == 202 {
        writeln!(
            stderr,
            "warning: push was ACCEPTED but the asset is WITHHELD pending screening; \
             it is not downloadable until promoted (see asset.visibility below)"
        )
        .context("failed to write withheld asset warning")?;
    }
    writeln!(stdout, "{}", String::from_utf8_lossy(&response.body))
        .context("failed to write asset push response")?;
    Ok(())
}

fn guess_content_type(path: &std::path::Path) -> String {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => "application/json",
        Some("html" | "htm") => "text/html",
        Some("js" | "mjs") => "application/javascript",
        Some("css") => "text/css",
        Some("md") => "text/markdown",
        Some("sh" | "py" | "txt" | "toml" | "yaml" | "yml") => "text/plain",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Parses a `--gateway-url`/`FERROGATE_GATEWAY_URL` value and connects a raw
/// TCP client to it. Shared by every `ferrogate-cli` subcommand that talks
/// to a running gateway's admin/data-plane HTTP surface without pulling in
/// `reqwest` (`ferrogate-cli`'s `main()` is a sync binary entrypoint) --
/// originally built for `assets push/pull/list/delete` (issue #178), reused
/// as-is by `plans_cli` (issue #168) rather than duplicating it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayEndpoint {
    host: String,
    port: u16,
}

impl GatewayEndpoint {
    pub(crate) fn parse(raw: &str) -> AnyResult<Self> {
        let rest = raw
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("--gateway-url currently supports only http:// URLs"))?;
        let authority = rest.split('/').next().unwrap_or(rest);
        if authority.is_empty() {
            bail!("--gateway-url must include a host");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (
                host.to_string(),
                port.parse()
                    .with_context(|| format!("invalid gateway URL port: {port}"))?,
            ),
            _ => (authority.to_string(), 80),
        };
        Ok(Self { host, port })
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
}

pub(crate) struct RawHttpResponse {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// The `Name: value\r\n` block for a list of headers.
///
/// Refuses, rather than strips, a name or value that is not printable ASCII.
/// Stripping would let a hostile value quietly change what is sent; refusing
/// makes it an error an operator sees.
///
/// Takes the header list rather than the [`ClientActionIdentity`] on purpose, so
/// this boundary check is reachable by a test with a hostile pair in hand.
/// Nothing an identity produces can trip it today — its own
/// `encode_header_value` percent-escapes everything outside `32..=126`, and
/// `ServerIssuedTime::parse` refuses a token carrying anything else — but that
/// is a guarantee made in another crate, and this is where a raw string meets a
/// socket with no `http::HeaderValue` in between.
pub(crate) fn render_header_block(headers: Vec<(String, String)>) -> AnyResult<String> {
    let mut rendered = String::new();
    for (name, value) in headers {
        for (kind, text) in [("name", &name), ("value", &value)] {
            if let Some(offending) = text.chars().find(|ch| !matches!(*ch as u32, 0x20..=0x7E)) {
                bail!(
                    "refusing to send the audit identity: header {kind} '{text}' carries \
                     {offending:?}, which would split this request into two"
                );
            }
        }
        rendered.push_str(&format!("{name}: {value}\r\n"));
    }
    Ok(rendered)
}

/// Issue one request over the hand-rolled raw-TCP client.
///
/// # The second audit chokepoint (issue #548)
///
/// `identity` is a **required** argument for exactly the reason
/// `ferrogate_control_plane_client::transport::prepare_request` takes one: this
/// is the single function that materializes the seven requests the `assets` and
/// `plans` command groups issue — four mutations (`plans create`,
/// `plans assign`, `assets push`, `assets delete`), the first two of them
/// Control Plane mutations with no registry family to route through instead,
/// and three reads (`assets pull`, `assets list`, `plans list`), which this
/// issue asks for too. A required argument of a type with no public
/// constructor other than `mint` makes "this request is attributed" a compile
/// error rather than a convention, and `ClientActionIdentity` is that type.
///
/// It used to take six arguments and no identity, with a doc that recommended
/// reuse and no marker that it went around the typed client's chokepoint. The
/// result was that ~4% of the CLI's verbs — including two unattributable
/// control-plane mutations with no registry family to route through instead —
/// issued requests carrying no `action_id` at all.
///
/// **There is no `http::HeaderValue` between these strings and the socket.** The
/// identity's values are printable-ASCII by construction
/// (`encode_header_value` percent-escapes everything else, and
/// `ServerIssuedTime::parse` refuses a token carrying anything else), but that
/// is a property of another crate, so it is re-checked here: a value that could
/// carry a CR or an LF would splice a header of an attacker's choosing into this
/// request, and the refusal is loud rather than a silent strip.
pub(crate) fn send_request(
    endpoint: &GatewayEndpoint,
    method: &str,
    path: &str,
    api_key: &str,
    content_type: Option<&str>,
    body: &[u8],
    identity: &ClientActionIdentity,
) -> AnyResult<RawHttpResponse> {
    let identity_headers = render_header_block(identity.headers())?;

    let mut stream = TcpStream::connect(endpoint.connect_addr()).with_context(|| {
        format!(
            "failed to connect to gateway at {}",
            endpoint.connect_addr()
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to set gateway read timeout")?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {api_key}\r\nConnection: close\r\n",
        endpoint.host_header(),
    );
    request.push_str(&identity_headers);
    if let Some(content_type) = content_type {
        request.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

    stream
        .write_all(request.as_bytes())
        .context("failed to write request headers")?;
    stream
        .write_all(body)
        .context("failed to write request body")?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .context("failed to read gateway response")?;
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> AnyResult<RawHttpResponse> {
    let separator = b"\r\n\r\n";
    let split_at = raw
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| anyhow::anyhow!("gateway returned a malformed HTTP response"))?;
    let (head, rest) = raw.split_at(split_at);
    let body = rest[separator.len()..].to_vec();
    let head = String::from_utf8_lossy(head);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("gateway returned a malformed HTTP status line"))?;
    Ok(RawHttpResponse { status, body })
}

#[cfg(test)]
#[path = "assets_cli_test.rs"]
mod assets_cli_test;
