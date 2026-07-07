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

use crate::cli::{AssetsCommands, AssetsIdentityArgs, AssetsListArgs, AssetsPushArgs};

pub(crate) fn execute_assets_command(command: AssetsCommands) -> AnyResult<()> {
    match command {
        AssetsCommands::Push(args) => execute_push(args),
        AssetsCommands::Pull(args) => execute_pull(args),
        AssetsCommands::List(args) => execute_list(args),
        AssetsCommands::Delete(args) => execute_delete(args),
    }
}

fn execute_push(args: AssetsPushArgs) -> AnyResult<()> {
    let content = std::fs::read(&args.path)
        .with_context(|| format!("failed to read {}", args.path.display()))?;
    let content_type = args
        .content_type
        .unwrap_or_else(|| guess_content_type(&args.path));
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let path = format!("/v1/assets/{}/{}/{}", args.asset_type, args.name, args.version);
    let response = send_request(
        &endpoint,
        "PUT",
        &path,
        &args.connection.api_key,
        Some(&content_type),
        &content,
    )?;
    print_json_or_raise(&response, "push")
}

fn execute_pull(args: AssetsIdentityArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let path = format!("/v1/assets/{}/{}/{}", args.asset_type, args.name, args.version);
    let response = send_request(&endpoint, "GET", &path, &args.connection.api_key, None, &[])?;
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
    let path = match args.asset_type {
        Some(asset_type) => format!("/v1/assets/{asset_type}"),
        None => "/v1/assets".to_string(),
    };
    let response = send_request(&endpoint, "GET", &path, &args.connection.api_key, None, &[])?;
    print_json_or_raise(&response, "list")
}

fn execute_delete(args: AssetsIdentityArgs) -> AnyResult<()> {
    let endpoint = GatewayEndpoint::parse(&args.connection.gateway_url)?;
    let path = format!("/v1/assets/{}/{}/{}", args.asset_type, args.name, args.version);
    let response = send_request(&endpoint, "DELETE", &path, &args.connection.api_key, None, &[])?;
    print_json_or_raise(&response, "delete")
}

fn print_json_or_raise(response: &RawHttpResponse, action: &str) -> AnyResult<()> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct GatewayEndpoint {
    host: String,
    port: u16,
}

impl GatewayEndpoint {
    fn parse(raw: &str) -> AnyResult<Self> {
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

struct RawHttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn send_request(
    endpoint: &GatewayEndpoint,
    method: &str,
    path: &str,
    api_key: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> AnyResult<RawHttpResponse> {
    let mut stream = TcpStream::connect(endpoint.connect_addr())
        .with_context(|| format!("failed to connect to gateway at {}", endpoint.connect_addr()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to set gateway read timeout")?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {api_key}\r\nConnection: close\r\n",
        endpoint.host_header(),
    );
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
