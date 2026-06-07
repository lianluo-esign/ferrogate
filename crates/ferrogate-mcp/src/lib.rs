//! MCP host/client manager for FerroGate.
//!
//! The crate depends on the official `rmcp` SDK and keeps FerroGate's runtime
//! boundary explicit: long-lived server sessions are owned by `McpManager`,
//! while the gateway applies auth, policy, billing, and audit before calling it.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    net::{TcpStream, ToSocketAddrs},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ToolDef;
use http::Uri;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use rmcp::model::{CallToolRequestParams, CallToolResult, ListToolsResult};

pub const DEFAULT_HEALTH_PING_INTERVAL_SECS: u64 = 10;
pub const DEFAULT_MAX_RECONNECT_ATTEMPTS: u32 = 5;
pub const DEFAULT_MIN_RECONNECT_BACKOFF_SECS: u64 = 1;
pub const DEFAULT_MAX_RECONNECT_BACKOFF_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    StreamableHttp,
    Sse,
    Stdio,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpAuthType {
    #[default]
    None,
    Headers,
    Oauth,
    PerUserOauth,
    PerUserHeaders,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: McpTransport,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub auth_type: McpAuthType,
    #[serde(default)]
    pub headers: Vec<McpHeaderConfig>,
    #[serde(default)]
    pub tools_to_execute: Vec<String>,
    #[serde(default)]
    pub tools_to_auto_execute: Vec<String>,
    #[serde(default)]
    pub tool_include: Vec<String>,
    #[serde(default)]
    pub tool_regex: Vec<String>,
    #[serde(default)]
    pub tls: McpTlsConfig,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_ping_interval_secs")]
    pub health_ping_interval_secs: u64,
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,
    #[serde(default = "default_min_reconnect_backoff_secs")]
    pub min_reconnect_backoff_secs: u64,
    #[serde(default = "default_max_reconnect_backoff_secs")]
    pub max_reconnect_backoff_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpHeaderConfig {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub value_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpTlsConfig {
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_health_ping_interval_secs() -> u64 {
    DEFAULT_HEALTH_PING_INTERVAL_SECS
}

fn default_max_reconnect_attempts() -> u32 {
    DEFAULT_MAX_RECONNECT_ATTEMPTS
}

fn default_min_reconnect_backoff_secs() -> u64 {
    DEFAULT_MIN_RECONNECT_BACKOFF_SECS
}

fn default_max_reconnect_backoff_secs() -> u64 {
    DEFAULT_MAX_RECONNECT_BACKOFF_SECS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpServerStatus {
    pub name: String,
    pub transport: McpTransport,
    pub connected: bool,
    pub health: String,
    pub tools: usize,
    pub reconnect_attempts: u32,
    pub last_error: Option<String>,
    pub last_connected_at_unix: Option<u64>,
    pub next_reconnect_backoff_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct McpTool {
    pub name: String,
    pub server_name: String,
    pub remote_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub auto_execute: bool,
}

impl McpTool {
    pub fn as_tool_def(&self) -> ToolDef {
        ToolDef {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: self.input_schema.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpToolExecutionRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct McpToolExecutionResult {
    pub content: Value,
    pub is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpExecutionError {
    Denied(String),
    NotFound(String),
    Unavailable(String),
    Failed(String),
}

impl McpExecutionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Denied(_) => "tool_denied",
            Self::NotFound(_) => "tool_not_found",
            Self::Unavailable(_) => "mcp_server_unavailable",
            Self::Failed(_) => "tool_execution_failed",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Denied(message)
            | Self::NotFound(message)
            | Self::Unavailable(message)
            | Self::Failed(message) => message,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct McpManager {
    inner: Arc<Mutex<McpManagerState>>,
}

#[derive(Debug, Default)]
struct McpManagerState {
    sessions: HashMap<String, McpSession>,
}

#[derive(Debug)]
struct McpSession {
    config: McpServerConfig,
    tools: Vec<McpTool>,
    client: Option<McpClient>,
    connected: bool,
    last_error: Option<String>,
    reconnect_attempts: u32,
    last_connected_at_unix: Option<u64>,
    next_reconnect_backoff_secs: u64,
}

#[derive(Debug)]
enum McpClient {
    Http(HttpMcpClient),
    Stdio(StdioMcpClient),
}

impl McpManager {
    pub fn from_configs(configs: &[McpServerConfig]) -> Self {
        let manager = Self::default();
        manager.reconfigure(configs);
        manager
    }

    pub fn reconfigure(&self, configs: &[McpServerConfig]) {
        let mut sessions = HashMap::new();
        for config in configs {
            let mut session = McpSession::new(config.clone());
            session.connect_or_record_error();
            sessions.insert(config.name.clone(), session);
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.sessions = sessions;
        }
    }

    pub fn statuses(&self) -> Vec<McpServerStatus> {
        self.inner
            .lock()
            .map(|inner| inner.sessions.values().map(McpSession::status).collect())
            .unwrap_or_default()
    }

    pub fn tools(&self) -> Vec<McpTool> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .sessions
                    .values()
                    .flat_map(|session| session.tools.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn health_check_and_reconnect(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            for session in inner.sessions.values_mut() {
                session.health_check_and_reconnect();
            }
        }
    }

    pub fn execute_tool(
        &self,
        request: McpToolExecutionRequest,
    ) -> Result<McpToolExecutionResult, McpExecutionError> {
        let mut inner = self.inner.lock().map_err(|_| {
            McpExecutionError::Unavailable("MCP manager lock is unavailable".into())
        })?;
        let (server_name, remote_name) = namespaced_tool_parts(&request.name).ok_or_else(|| {
            McpExecutionError::NotFound(format!(
                "MCP tool {} must use serverName-toolName namespace",
                request.name
            ))
        })?;
        let session = inner.sessions.get_mut(server_name).ok_or_else(|| {
            McpExecutionError::NotFound(format!("MCP server {server_name} is not configured"))
        })?;
        session.execute(remote_name, request.arguments)
    }
}

impl McpSession {
    fn new(config: McpServerConfig) -> Self {
        Self {
            next_reconnect_backoff_secs: config.min_reconnect_backoff_secs,
            config,
            tools: Vec::new(),
            client: None,
            connected: false,
            last_error: None,
            reconnect_attempts: 0,
            last_connected_at_unix: None,
        }
    }

    fn status(&self) -> McpServerStatus {
        McpServerStatus {
            name: self.config.name.clone(),
            transport: self.config.transport.clone(),
            connected: self.connected,
            health: if self.connected { "ok" } else { "degraded" }.into(),
            tools: self.tools.len(),
            reconnect_attempts: self.reconnect_attempts,
            last_error: self.last_error.clone(),
            last_connected_at_unix: self.last_connected_at_unix,
            next_reconnect_backoff_secs: self.next_reconnect_backoff_secs,
        }
    }

    fn connect_or_record_error(&mut self) {
        match self.connect() {
            Ok(()) => {
                self.connected = true;
                self.last_error = None;
                self.reconnect_attempts = 0;
                self.next_reconnect_backoff_secs = self.config.min_reconnect_backoff_secs;
                self.last_connected_at_unix = now_unix_seconds();
            }
            Err(error) => {
                self.connected = false;
                self.last_error = Some(error.to_string());
                self.client = None;
                self.tools.clear();
            }
        }
    }

    fn connect(&mut self) -> AnyResult<()> {
        let mut client = match self.config.transport {
            McpTransport::StreamableHttp | McpTransport::Sse => {
                McpClient::Http(HttpMcpClient::new(&self.config)?)
            }
            McpTransport::Stdio => McpClient::Stdio(StdioMcpClient::new(&self.config)?),
        };
        client.initialize()?;
        let defs = client.list_tools()?;
        self.tools = defs
            .into_iter()
            .filter(|tool| tool_selected(&self.config, &tool.name))
            .filter(|tool| tool_allowlisted(&self.config.tools_to_execute, &tool.name))
            .map(|tool| {
                let remote_name = tool.name;
                McpTool {
                    name: format!("{}-{remote_name}", self.config.name),
                    server_name: self.config.name.clone(),
                    remote_name: remote_name.clone(),
                    description: tool.description,
                    input_schema: tool.input_schema,
                    auto_execute: tool_allowlisted(
                        &self.config.tools_to_auto_execute,
                        &remote_name,
                    ),
                }
            })
            .collect();
        self.client = Some(client);
        Ok(())
    }

    fn execute(
        &mut self,
        remote_name: &str,
        arguments: Value,
    ) -> Result<McpToolExecutionResult, McpExecutionError> {
        if !tool_allowlisted(&self.config.tools_to_execute, remote_name) {
            return Err(McpExecutionError::Denied(format!(
                "MCP tool {}-{} is not allowlisted for execution",
                self.config.name, remote_name
            )));
        }
        if !self.connected {
            self.try_reconnect();
        }
        let Some(client) = self.client.as_mut() else {
            return Err(McpExecutionError::Unavailable(format!(
                "MCP server {} is not connected",
                self.config.name
            )));
        };
        client.call_tool(remote_name, arguments).map_err(|error| {
            self.connected = false;
            self.last_error = Some(error.clone());
            McpExecutionError::Failed(error)
        })
    }

    fn health_check_and_reconnect(&mut self) {
        if self.connected {
            let healthy = self
                .client
                .as_mut()
                .map(|client| client.ping().is_ok())
                .unwrap_or(false);
            if healthy {
                return;
            }
            self.connected = false;
            self.last_error = Some("MCP health ping failed".into());
        }
        self.try_reconnect();
    }

    fn try_reconnect(&mut self) {
        for _ in 0..self.config.max_reconnect_attempts {
            self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
            match self.connect() {
                Ok(()) => {
                    self.connected = true;
                    self.last_error = None;
                    self.next_reconnect_backoff_secs = self.config.min_reconnect_backoff_secs;
                    self.last_connected_at_unix = now_unix_seconds();
                    return;
                }
                Err(error) => {
                    self.connected = false;
                    self.client = None;
                    self.tools.clear();
                    self.last_error = Some(error.to_string());
                    self.next_reconnect_backoff_secs = (self.next_reconnect_backoff_secs * 2)
                        .min(self.config.max_reconnect_backoff_secs);
                }
            }
        }
    }
}

impl McpClient {
    fn initialize(&mut self) -> AnyResult<()> {
        match self {
            Self::Http(client) => client.initialize(),
            Self::Stdio(client) => client.initialize(),
        }
    }

    fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        match self {
            Self::Http(client) => client.list_tools(),
            Self::Stdio(client) => client.list_tools(),
        }
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<McpToolExecutionResult, String> {
        match self {
            Self::Http(client) => client.call_tool(name, arguments),
            Self::Stdio(client) => client.call_tool(name, arguments),
        }
    }

    fn ping(&mut self) -> AnyResult<()> {
        match self {
            Self::Http(client) => client.ping(),
            Self::Stdio(client) => client.ping(),
        }
    }
}

#[derive(Debug)]
struct HttpMcpClient {
    endpoint: String,
    timeout: Duration,
    headers: Vec<(String, String)>,
    next_id: u64,
}

impl HttpMcpClient {
    fn new(config: &McpServerConfig) -> AnyResult<Self> {
        let endpoint = config
            .url
            .clone()
            .ok_or_else(|| anyhow::anyhow!("MCP server {} requires url", config.name))?;
        validate_http_endpoint(&endpoint)?;
        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(config.timeout_ms),
            headers: resolved_headers(config)?,
            next_id: 1,
        })
    }

    fn initialize(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ferrogate", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let response = self.post_json(&body)?;
        ensure_no_jsonrpc_error(&response)?;
        Ok(())
    }

    fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}});
        let response = self.post_json(&body)?;
        parse_tools_list(&response)
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<McpToolExecutionResult, String> {
        let id = self.next_jsonrpc_id();
        let params = call_tool_params(name, arguments).map_err(|error| error.to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params
        });
        let response = self.post_json(&body).map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    fn ping(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "ping", "params": {}});
        let response = self.post_json(&body)?;
        ensure_no_jsonrpc_error(&response)
    }

    fn post_json(&self, body: &Value) -> AnyResult<Value> {
        post_http_json(&self.endpoint, self.timeout, &self.headers, body)
    }

    fn next_jsonrpc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }
}

#[derive(Debug)]
struct StdioMcpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl StdioMcpClient {
    fn new(config: &McpServerConfig) -> AnyResult<Self> {
        let command = config
            .command
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MCP stdio server {} requires command", config.name))?;
        let mut child = Command::new(command)
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn MCP stdio server {}", config.name))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("MCP stdio stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("MCP stdio stdout unavailable"))?;
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        })
    }

    fn initialize(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "ferrogate", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let response = self.send_json(&body)?;
        ensure_no_jsonrpc_error(&response)?;
        Ok(())
    }

    fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}});
        let response = self.send_json(&body)?;
        parse_tools_list(&response)
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<McpToolExecutionResult, String> {
        let id = self.next_jsonrpc_id();
        let params = call_tool_params(name, arguments).map_err(|error| error.to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params
        });
        let response = self.send_json(&body).map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    fn ping(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "ping", "params": {}});
        let response = self.send_json(&body)?;
        ensure_no_jsonrpc_error(&response)
    }

    fn send_json(&mut self, body: &Value) -> AnyResult<Value> {
        let line = serde_json::to_string(body)?;
        writeln!(self.stdin, "{line}")?;
        self.stdin.flush()?;
        let mut response = String::new();
        self.stdout.read_line(&mut response)?;
        if response.trim().is_empty() {
            bail!("MCP stdio server closed stdout");
        }
        serde_json::from_str(&response).context("invalid MCP stdio JSON response")
    }

    fn next_jsonrpc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn validate_http_endpoint(raw: &str) -> AnyResult<()> {
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
    body: &Value,
) -> AnyResult<Value> {
    let target = parse_http_target(endpoint)?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect_timeout(&target.address, timeout)
        .with_context(|| format!("failed to connect MCP endpoint {}", target.authority))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        target.path_query,
        target.authority,
        body.len()
    )?;
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut stream, &mut raw)?;
    let response = String::from_utf8_lossy(&raw);
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid MCP HTTP response"))?;
    serde_json::from_str(body).context("invalid MCP JSON response")
}

#[derive(Debug)]
struct HttpTarget {
    authority: String,
    path_query: String,
    address: std::net::SocketAddr,
}

fn parse_http_target(raw: &str) -> AnyResult<HttpTarget> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid MCP endpoint {raw}"))?;
    if uri.scheme_str() != Some("http") {
        bail!("MCP test HTTP client supports http endpoints; configure HTTPS through rmcp transport in production");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint must include authority"))?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(80);
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint resolved no addresses"))?;
    let authority = if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(HttpTarget {
        authority,
        path_query,
        address,
    })
}

fn parse_tools_list(response: &Value) -> AnyResult<Vec<ToolDef>> {
    ensure_no_jsonrpc_error(response)?;
    let result: ListToolsResult = serde_json::from_value(
        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("MCP tools/list response missing result"))?,
    )
    .context("invalid MCP tools/list result")?;
    Ok(result
        .tools
        .into_iter()
        .map(|tool| {
            let input_schema = Value::Object((*tool.input_schema).clone());
            ToolDef {
                name: tool.name.into_owned(),
                description: tool.description.map(|description| description.into_owned()),
                input_schema,
            }
        })
        .collect())
}

fn parse_call_result(response: &Value) -> AnyResult<McpToolExecutionResult> {
    ensure_no_jsonrpc_error(response)?;
    let result_value = response.get("result").cloned().unwrap_or(Value::Null);
    let result: CallToolResult =
        serde_json::from_value(result_value.clone()).context("invalid MCP tools/call result")?;
    Ok(McpToolExecutionResult {
        content: result_value,
        is_error: result.is_error.unwrap_or(false),
    })
}

fn call_tool_params(name: &str, arguments: Value) -> AnyResult<Value> {
    let mut params = CallToolRequestParams::new(name.to_string());
    if let Value::Object(arguments) = arguments {
        params = params.with_arguments(arguments);
    } else if !arguments.is_null() {
        bail!("MCP tool arguments must be a JSON object");
    }
    serde_json::to_value(params).context("failed to serialize MCP tools/call params")
}

fn ensure_no_jsonrpc_error(response: &Value) -> AnyResult<()> {
    if let Some(error) = response.get("error") {
        bail!("MCP JSON-RPC error: {error}");
    }
    Ok(())
}

fn resolved_headers(config: &McpServerConfig) -> AnyResult<Vec<(String, String)>> {
    config
        .headers
        .iter()
        .map(|header| {
            let value = match (&header.value, &header.value_env) {
                (Some(value), _) => value.clone(),
                (None, Some(env_name)) => std::env::var(env_name).with_context(|| {
                    format!("missing MCP header environment variable {env_name}")
                })?,
                (None, None) => String::new(),
            };
            Ok((header.name.clone(), value))
        })
        .collect()
}

fn tool_selected(config: &McpServerConfig, remote_name: &str) -> bool {
    (config.tool_include.is_empty()
        || config
            .tool_include
            .iter()
            .any(|pattern| selector_matches(pattern, remote_name)))
        && (config.tool_regex.is_empty()
            || config
                .tool_regex
                .iter()
                .any(|pattern| selector_matches(pattern, remote_name)))
}

fn tool_allowlisted(allowlist: &[String], remote_name: &str) -> bool {
    allowlist
        .iter()
        .any(|allowed| allowed == "*" || selector_matches(allowed, remote_name))
}

fn selector_matches(pattern: &str, value: &str) -> bool {
    pattern == value
        || pattern == "*"
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| value.starts_with(prefix))
        || pattern
            .strip_prefix('/')
            .and_then(|rest| rest.strip_suffix('/'))
            .is_some_and(|needle| value.contains(needle))
}

fn namespaced_tool_parts(name: &str) -> Option<(&str, &str)> {
    name.split_once('-')
        .filter(|(server, tool)| !server.trim().is_empty() && !tool.trim().is_empty())
}

fn now_unix_seconds() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub fn validate_mcp_server_config(config: &McpServerConfig) -> AnyResult<()> {
    if config.name.trim().is_empty() {
        bail!("MCP server name cannot be empty");
    }
    if config.name.contains('-') {
        bail!("MCP server name cannot contain '-' because tool names use serverName-toolName");
    }
    if config.tools_to_execute.is_empty() {
        bail!(
            "MCP server {} must set tools_to_execute; execution is deny-by-default",
            config.name
        );
    }
    if config.max_reconnect_attempts == 0 {
        bail!(
            "MCP server {} max_reconnect_attempts must be greater than 0",
            config.name
        );
    }
    if config.min_reconnect_backoff_secs == 0 || config.max_reconnect_backoff_secs == 0 {
        bail!(
            "MCP server {} reconnect backoff values must be greater than 0",
            config.name
        );
    }
    if config.min_reconnect_backoff_secs > config.max_reconnect_backoff_secs {
        bail!(
            "MCP server {} min reconnect backoff cannot exceed max",
            config.name
        );
    }
    match config.transport {
        McpTransport::StreamableHttp | McpTransport::Sse => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("MCP network server {} requires url", config.name)
            })?;
            validate_http_endpoint(url)?;
        }
        McpTransport::Stdio => {
            if config.command.as_deref().is_none_or(str::is_empty) {
                bail!("MCP stdio server {} requires command", config.name);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_by_default_requires_execute_allowlist() {
        let config = McpServerConfig {
            name: "github".into(),
            transport: McpTransport::StreamableHttp,
            url: Some("http://127.0.0.1/mcp".into()),
            command: None,
            args: Vec::new(),
            auth_type: McpAuthType::None,
            headers: Vec::new(),
            tools_to_execute: Vec::new(),
            tools_to_auto_execute: Vec::new(),
            tool_include: Vec::new(),
            tool_regex: Vec::new(),
            tls: McpTlsConfig::default(),
            timeout_ms: 1000,
            health_ping_interval_secs: 10,
            max_reconnect_attempts: 5,
            min_reconnect_backoff_secs: 1,
            max_reconnect_backoff_secs: 30,
        };

        let error = validate_mcp_server_config(&config).unwrap_err().to_string();

        assert!(error.contains("tools_to_execute"));
    }

    #[test]
    fn namespaces_and_filters_tools() {
        let config = McpServerConfig {
            name: "github".into(),
            transport: McpTransport::StreamableHttp,
            url: Some("http://127.0.0.1/mcp".into()),
            command: None,
            args: Vec::new(),
            auth_type: McpAuthType::None,
            headers: Vec::new(),
            tools_to_execute: vec!["search".into()],
            tools_to_auto_execute: vec!["search".into()],
            tool_include: vec!["sea*".into()],
            tool_regex: Vec::new(),
            tls: McpTlsConfig::default(),
            timeout_ms: 1000,
            health_ping_interval_secs: 10,
            max_reconnect_attempts: 5,
            min_reconnect_backoff_secs: 1,
            max_reconnect_backoff_secs: 30,
        };

        assert!(tool_selected(&config, "search"));
        assert!(!tool_selected(&config, "write"));
        assert!(tool_allowlisted(&config.tools_to_execute, "search"));
        assert!(!tool_allowlisted(&config.tools_to_execute, "write"));
    }

    #[test]
    fn parses_tools_list_with_rmcp_model() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{
                    "name": "search",
                    "description": "Search repos",
                    "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}}
                }]
            }
        });

        let tools = parse_tools_list(&response).unwrap();

        assert_eq!(tools[0].name, "search");
        assert_eq!(tools[0].description.as_deref(), Some("Search repos"));
        assert_eq!(tools[0].input_schema["type"], "object");
    }
}
