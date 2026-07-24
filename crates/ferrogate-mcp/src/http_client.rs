// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Streamable HTTP / SSE MCP client: JSON-RPC over one-shot HTTP(S) requests,
//! including the raw HTTP plumbing, response-size caps, and SSE parsing.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ToolDef;
use http::Uri;
use rustls::{pki_types::ServerName, ClientConnection, StreamOwned};
use serde_json::{json, Value};

use crate::config::{resolved_headers, McpServerConfig, McpTlsConfig, McpTransport};
use crate::jsonrpc::{
    call_tool_params, ensure_no_jsonrpc_error, parse_call_result, parse_tools_list,
};
use crate::manager::{McpDispatchHeaders, McpToolExecutionResult};
use crate::protocol::{
    resolve_negotiated_version, MCP_METHOD_HEADER, MCP_NAME_HEADER, MCP_PROTOCOL_VERSION,
};
use crate::tls::mcp_tls_client_config;

#[derive(Debug)]
pub(crate) struct HttpMcpClient {
    endpoint: String,
    timeout: Duration,
    headers: Vec<(String, String)>,
    tls: McpTlsConfig,
    transport: McpTransport,
    next_id: u64,
    /// Protocol revision negotiated with this upstream in `initialize`
    /// (issue #277). Starts at the fallback and is upgraded to 2026-07-28 when
    /// the server echoes it.
    protocol_version: String,
}

impl HttpMcpClient {
    pub(crate) fn new(config: &McpServerConfig) -> AnyResult<Self> {
        let endpoint = config
            .url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("MCP server {} requires url", config.name))?;
        validate_http_endpoint(&endpoint)?;
        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(config.timeout_ms),
            headers: resolved_headers(config)?,
            tls: config.tls.clone(),
            transport: config.transport.clone(),
            next_id: 1,
            protocol_version: crate::protocol::MCP_PROTOCOL_VERSION_FALLBACK.to_string(),
        })
    }

    pub(crate) fn initialize(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ferrogate", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let response = self.post_rpc(&body, &McpDispatchHeaders::empty(), "initialize", None)?;
        ensure_no_jsonrpc_error(&response)?;
        self.protocol_version = resolve_negotiated_version(
            response
                .get("result")
                .and_then(|result| result.get("protocolVersion"))
                .and_then(Value::as_str),
        )
        .to_string();
        Ok(())
    }

    pub(crate) fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}});
        let response = self.post_rpc(&body, &McpDispatchHeaders::empty(), "tools/list", None)?;
        parse_tools_list(&response)
    }

    pub(crate) fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        identity_headers: &McpDispatchHeaders,
    ) -> Result<McpToolExecutionResult, String> {
        let id = self.next_jsonrpc_id();
        let params = call_tool_params(name, arguments).map_err(|error| error.to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params
        });
        let response = self
            .post_rpc(&body, identity_headers, "tools/call", Some(name))
            .map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    pub(crate) fn ping(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "ping", "params": {}});
        let response = self.post_rpc(&body, &McpDispatchHeaders::empty(), "ping", None)?;
        ensure_no_jsonrpc_error(&response)
    }

    /// The 2026-07-28 `Mcp-Method` / `Mcp-Name` routing headers for an outbound
    /// request. Defined for Streamable HTTP only, so other transports emit
    /// nothing.
    fn routing_headers(&self, method: &str, name: Option<&str>) -> Vec<(String, String)> {
        if self.transport != McpTransport::StreamableHttp {
            return Vec::new();
        }
        let mut headers = vec![(MCP_METHOD_HEADER.to_string(), method.to_string())];
        if let Some(name) = name {
            headers.push((MCP_NAME_HEADER.to_string(), name.to_string()));
        }
        headers
    }

    fn post_rpc(
        &self,
        body: &Value,
        identity_headers: &McpDispatchHeaders,
        method: &str,
        name: Option<&str>,
    ) -> AnyResult<Value> {
        let mut headers = self.headers.clone();
        headers.extend(self.routing_headers(method, name));
        headers.extend(identity_headers.0.iter().cloned());
        post_http_json(
            &self.endpoint,
            self.timeout,
            &headers,
            &self.tls,
            &self.transport,
            body,
        )
    }

    fn next_jsonrpc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    pub(crate) fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
}

pub(crate) fn validate_http_endpoint(raw: &str) -> AnyResult<()> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid MCP endpoint {raw}"))?;
    match uri.scheme_str() {
        Some("http") | Some("https") => Ok(()),
        _ => bail!("MCP network transports require http or https url"),
    }
}

fn post_http_json(
    endpoint: &str,
    timeout: Duration,
    headers: &[(String, String)],
    tls: &McpTlsConfig,
    transport: &McpTransport,
    body: &Value,
) -> AnyResult<Value> {
    let target = parse_http_target(endpoint)?;
    let body = serde_json::to_vec(body)?;
    let accept = match transport {
        McpTransport::Sse => "text/event-stream, application/json",
        _ => "application/json",
    };
    let tcp = TcpStream::connect_timeout(&target.address, timeout)
        .with_context(|| format!("failed to connect MCP endpoint {}", target.authority))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    match target.scheme {
        HttpScheme::Http => {
            let mut stream = tcp;
            send_mcp_http_request(&mut stream, &target, headers, accept, &body)
        }
        HttpScheme::Https => {
            let server_name = ServerName::try_from(target.host.clone())
                .with_context(|| format!("invalid MCP TLS server name {}", target.host))?;
            let config = mcp_tls_client_config(tls)?;
            let connection = ClientConnection::new(config, server_name)
                .context("failed to initialize MCP TLS client")?;
            let mut tls_stream = StreamOwned::new(connection, tcp);
            send_mcp_http_request(&mut tls_stream, &target, headers, accept, &body)
        }
    }
}

fn send_mcp_http_request<S: Read + Write>(
    stream: &mut S,
    target: &HttpTarget,
    headers: &[(String, String)],
    accept: &str,
    body: &[u8],
) -> AnyResult<Value> {
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        target.path_query,
        target.authority,
        accept,
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let head = read_http_response_head(&mut reader)?;
    if head.status == 401 {
        bail!("mcp_upstream_unauthorized");
    }
    if !(200..300).contains(&head.status) {
        bail!("MCP upstream returned HTTP {}", head.status);
    }
    if head
        .content_type
        .to_ascii_lowercase()
        .contains("text/event-stream")
    {
        read_sse_json_response(&mut reader)
    } else {
        read_json_body(&mut reader, head.content_length)
    }
}

/// `Content-Type` and `Content-Length` parsed from a response's headers.
struct HttpResponseHead {
    status: u16,
    content_type: String,
    content_length: Option<usize>,
}

/// Reads HTTP response status + headers up to the blank line. The connection
/// remains positioned at the start of the response body afterward.
fn read_http_response_head<R: BufRead>(reader: &mut R) -> AnyResult<HttpResponseHead> {
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        bail!("MCP endpoint closed the connection before sending a response");
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid MCP HTTP response status line"))?;
    let mut content_type = String::new();
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_string();
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }
    Ok(HttpResponseHead {
        status,
        content_type,
        content_length,
    })
}

/// Upper bound on an MCP HTTP response body. An upstream MCP server is a
/// separate trust domain (and `tls.insecure_skip_verify` permits a network
/// MITM); without this cap an attacker-controlled `Content-Length` drove
/// `vec![0u8; len]` to a process-fatal allocation (`handle_alloc_error` ->
/// `abort`, killing the whole multi-tenant gateway). 16 MiB is far above any
/// legitimate JSON-RPC tool result.
const MAX_MCP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Reads the response body as a single JSON value (the `application/json`
/// response shape most `StreamableHttp` MCP servers use). Prefers an exact
/// `Content-Length`-bounded read over `read_to_end` so a well-formed
/// response doesn't require the peer to close (and send a TLS
/// `close_notify`) before we can parse it. The body is capped at
/// [`MAX_MCP_RESPONSE_BYTES`] so a lying/oversized upstream `Content-Length`
/// yields a bounded error instead of a fatal allocation.
fn read_json_body<R: BufRead>(reader: &mut R, content_length: Option<usize>) -> AnyResult<Value> {
    if let Some(len) = content_length {
        if len > MAX_MCP_RESPONSE_BYTES {
            bail!(
                "MCP JSON response Content-Length {len} exceeds the {MAX_MCP_RESPONSE_BYTES}-byte maximum"
            );
        }
        let mut raw = vec![0u8; len];
        reader.read_exact(&mut raw)?;
        return serde_json::from_slice(&raw).context("invalid MCP JSON response");
    }
    // No Content-Length: read at most the cap (+1 to detect overflow) so a
    // streaming/lying peer cannot grow the buffer without bound.
    let mut raw = Vec::new();
    reader
        .take(MAX_MCP_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_MCP_RESPONSE_BYTES {
        bail!("MCP JSON response exceeds the {MAX_MCP_RESPONSE_BYTES}-byte maximum");
    }
    serde_json::from_slice(&raw).context("invalid MCP JSON response")
}

/// Incrementally parses a `text/event-stream` response, returning as soon as
/// one `data:` field assembles into a complete JSON value — rather than
/// blocking on connection close, which a real SSE stream may not do
/// promptly (issue #167).
fn read_sse_json_response<R: BufRead>(reader: &mut R) -> AnyResult<Value> {
    let mut data_buf = String::new();
    loop {
        let mut line = String::new();
        // Bound each line read so a peer streaming a huge line without a
        // newline cannot grow `line` without limit (same DoS class as the
        // Content-Length body read).
        let read = (&mut *reader)
            .take(MAX_MCP_RESPONSE_BYTES as u64 + 1)
            .read_line(&mut line)?;
        if read == 0 {
            bail!("MCP SSE stream closed before a JSON-RPC response arrived");
        }
        if line.len() > MAX_MCP_RESPONSE_BYTES || data_buf.len() > MAX_MCP_RESPONSE_BYTES {
            bail!("MCP SSE response exceeds the {MAX_MCP_RESPONSE_BYTES}-byte maximum");
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            if let Ok(value) = serde_json::from_str::<Value>(&data_buf) {
                return Ok(value);
            }
            data_buf.clear();
            continue;
        }
        if let Some(data) = trimmed.strip_prefix("data:") {
            if !data_buf.is_empty() {
                data_buf.push('\n');
            }
            data_buf.push_str(data.trim_start());
        }
        // Other SSE fields (`event:`, `id:`, `retry:`) and `:`-prefixed
        // comment/keep-alive lines are not needed for JSON-RPC correlation.
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpScheme {
    Http,
    Https,
}

#[derive(Debug)]
struct HttpTarget {
    scheme: HttpScheme,
    host: String,
    authority: String,
    path_query: String,
    address: std::net::SocketAddr,
}

fn parse_http_target(raw: &str) -> AnyResult<HttpTarget> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid MCP endpoint {raw}"))?;
    let scheme = match uri.scheme_str() {
        Some("http") => HttpScheme::Http,
        Some("https") => HttpScheme::Https,
        _ => bail!("MCP network transports require http or https url"),
    };
    let default_port = match scheme {
        HttpScheme::Http => 80,
        HttpScheme::Https => 443,
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint must include authority"))?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(default_port);
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint resolved no addresses"))?;
    let authority = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(HttpTarget {
        scheme,
        host,
        authority,
        path_query,
        address,
    })
}

#[cfg(test)]
#[path = "http_client_test.rs"]
mod tests;
