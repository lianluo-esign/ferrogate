// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP host/client manager for FerroGate.
//!
//! The crate depends on the official `rmcp` SDK and keeps FerroGate's runtime
//! boundary explicit: long-lived server sessions are owned by `McpManager`,
//! while the gateway applies auth, policy, billing, and audit before calling it.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::{ApprovalPolicy, ToolDef};
use http::{header::HeaderName, HeaderValue, Uri};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
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
    #[serde(alias = "headers")]
    SharedHeaders,
    Oauth,
    PerUserOauth,
    PerUserHeaders,
    OriginalBearer,
    FerrogateSignedJwt,
}

impl McpAuthType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SharedHeaders => "shared_headers",
            Self::Oauth => "oauth",
            Self::PerUserOauth => "per_user_oauth",
            Self::PerUserHeaders => "per_user_headers",
            Self::OriginalBearer => "original_bearer",
            Self::FerrogateSignedJwt => "ferrogate_signed_jwt",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpOauthConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default = "default_oauth_scopes")]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub allow_insecure_http: bool,
}

fn default_oauth_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
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
    pub oauth: Option<McpOauthConfig>,
    #[serde(default)]
    pub signed_jwt_audience: Option<String>,
    #[serde(default)]
    pub tools_to_execute: Vec<String>,
    #[serde(default)]
    pub tools_to_auto_execute: Vec<String>,
    #[serde(default)]
    pub approval_policy: ApprovalPolicy,
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
    pub approval_policy: ApprovalPolicy,
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
    Unauthorized(String),
    Failed(String),
}

impl McpExecutionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Denied(_) => "tool_denied",
            Self::NotFound(_) => "tool_not_found",
            Self::Unavailable(_) => "mcp_server_unavailable",
            Self::Unauthorized(_) => "mcp_upstream_unauthorized",
            Self::Failed(_) => "tool_execution_failed",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Denied(message)
            | Self::NotFound(message)
            | Self::Unavailable(message)
            | Self::Unauthorized(message)
            | Self::Failed(message) => message,
        }
    }
}

#[derive(Clone, Default)]
pub struct McpDispatchHeaders(Vec<(String, String)>);

impl std::fmt::Debug for McpDispatchHeaders {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpDispatchHeaders")
            .field("count", &self.0.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl McpDispatchHeaders {
    pub fn bearer(token: String) -> AnyResult<Self> {
        let value = format!("Bearer {token}");
        HeaderValue::from_str(&value)
            .context("MCP bearer token is not a valid HTTP header value")?;
        Ok(Self(vec![("Authorization".into(), value)]))
    }

    pub fn empty() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct McpManager {
    inner: Arc<Mutex<McpManagerState>>,
}

#[derive(Debug, Clone)]
pub struct McpDispatchCleanup {
    server_name: String,
    tool_name: String,
    session: Arc<Mutex<McpSession>>,
    stdio_child: Arc<Mutex<Child>>,
}

#[derive(Debug, Default)]
struct McpManagerState {
    sessions: HashMap<String, Arc<Mutex<McpSession>>>,
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
            sessions.insert(config.name.clone(), Arc::new(Mutex::new(session)));
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.sessions = sessions;
        }
    }

    pub fn statuses(&self) -> Vec<McpServerStatus> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .sessions
                    .values()
                    .filter_map(|session| session.try_lock().ok().map(|session| session.status()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn tools(&self) -> Vec<McpTool> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .sessions
                    .values()
                    .filter_map(|session| {
                        session.try_lock().ok().map(|session| session.tools.clone())
                    })
                    .flatten()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn tool_by_name(&self, name: &str) -> Option<McpTool> {
        self.inner.lock().ok().and_then(|inner| {
            inner.sessions.values().find_map(|session| {
                session.lock().ok().and_then(|session| {
                    session.tools.iter().find(|tool| tool.name == name).cloned()
                })
            })
        })
    }

    pub fn health_check_and_reconnect(&self) {
        let sessions = self
            .inner
            .lock()
            .map(|inner| inner.sessions.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for session in sessions {
            if let Ok(mut session) = session.try_lock() {
                session.health_check_and_reconnect();
            }
        }
    }

    pub fn execute_tool(
        &self,
        request: McpToolExecutionRequest,
    ) -> Result<McpToolExecutionResult, McpExecutionError> {
        self.execute_tool_with_headers(request, McpDispatchHeaders::empty())
    }

    pub fn execute_tool_with_headers(
        &self,
        request: McpToolExecutionRequest,
        identity_headers: McpDispatchHeaders,
    ) -> Result<McpToolExecutionResult, McpExecutionError> {
        let (server_name, remote_name, session) = {
            let inner = self.inner.lock().map_err(|_| {
                McpExecutionError::Unavailable("MCP manager lock is unavailable".into())
            })?;
            match resolve_namespaced_session(&inner.sessions, &request.name) {
                Some(resolved) => resolved,
                None => {
                    return Err(McpExecutionError::NotFound(if request.name.contains('-') {
                        format!(
                            "MCP tool {} did not match any configured MCP server",
                            request.name
                        )
                    } else {
                        format!(
                            "MCP tool {} must use serverName-toolName namespace",
                            request.name
                        )
                    }));
                }
            }
        };
        let mut session = session.lock().map_err(|_| {
            McpExecutionError::Unavailable(format!("MCP server {server_name} lock is unavailable"))
        })?;
        session.execute(&remote_name, request.arguments, &identity_headers)
    }

    pub fn dispatch_cleanup_handle(&self, namespaced_tool: &str) -> Option<McpDispatchCleanup> {
        let (server_name, tool_name, session) = {
            let inner = self.inner.lock().ok()?;
            resolve_namespaced_session(&inner.sessions, namespaced_tool)?
        };
        let stdio_child = session
            .try_lock()
            .ok()
            .and_then(|session| session.client.as_ref().and_then(McpClient::stdio_child));
        let stdio_child = stdio_child?;
        Some(McpDispatchCleanup {
            server_name,
            tool_name,
            session,
            stdio_child,
        })
    }
}

impl McpDispatchCleanup {
    pub fn cleanup_after_timeout(&self, timeout: Duration) -> bool {
        if let Ok(mut child) = self.stdio_child.lock() {
            let _ = child.kill();
            let _ = child.try_wait();
        }
        let message = format!(
            "MCP tool {}-{} timed out after {} seconds; session cleanup requested",
            self.server_name,
            self.tool_name,
            timeout.as_secs()
        );
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if let Ok(mut session) = self.session.try_lock() {
                session.mark_unavailable(message);
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
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
                    approval_policy: self.config.approval_policy,
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
        identity_headers: &McpDispatchHeaders,
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
        client
            .call_tool(remote_name, arguments, identity_headers)
            .map_err(|error| {
                self.connected = false;
                self.last_error = Some(error.clone());
                if error == "mcp_upstream_unauthorized" {
                    McpExecutionError::Unauthorized(
                        "MCP upstream rejected the resolved user identity".into(),
                    )
                } else {
                    McpExecutionError::Failed(error)
                }
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

    fn mark_unavailable(&mut self, message: String) {
        self.connected = false;
        self.client = None;
        self.tools.clear();
        self.last_error = Some(message);
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
        identity_headers: &McpDispatchHeaders,
    ) -> Result<McpToolExecutionResult, String> {
        match self {
            Self::Http(client) => client.call_tool(name, arguments, identity_headers),
            Self::Stdio(client) => client.call_tool(name, arguments),
        }
    }

    fn ping(&mut self) -> AnyResult<()> {
        match self {
            Self::Http(client) => client.ping(),
            Self::Stdio(client) => client.ping(),
        }
    }

    fn stdio_child(&self) -> Option<Arc<Mutex<Child>>> {
        match self {
            Self::Http(_) => None,
            Self::Stdio(client) => Some(Arc::clone(&client.child)),
        }
    }
}

#[derive(Debug)]
struct HttpMcpClient {
    endpoint: String,
    timeout: Duration,
    headers: Vec<(String, String)>,
    tls: McpTlsConfig,
    transport: McpTransport,
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
            tls: config.tls.clone(),
            transport: config.transport.clone(),
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
            .post_json_with_headers(&body, identity_headers)
            .map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    fn ping(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "ping", "params": {}});
        let response = self.post_json(&body)?;
        ensure_no_jsonrpc_error(&response)
    }

    fn post_json(&self, body: &Value) -> AnyResult<Value> {
        self.post_json_with_headers(body, &McpDispatchHeaders::empty())
    }

    fn post_json_with_headers(
        &self,
        body: &Value,
        identity_headers: &McpDispatchHeaders,
    ) -> AnyResult<Value> {
        let mut headers = self.headers.clone();
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
}

#[derive(Debug)]
struct StdioMcpClient {
    child: Arc<Mutex<Child>>,
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
            child: Arc::new(Mutex::new(child)),
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
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
        }
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

/// Validates that `tls.ca_cert_path`, if set, points at a file that exists
/// and parses as at least one PEM certificate (issue #167). Called from
/// `validate_mcp_server_config` so a bad path fails config validation
/// instead of failing silently at first connection attempt.
fn validate_mcp_tls_config(tls: &McpTlsConfig) -> AnyResult<()> {
    if let Some(path) = tls.ca_cert_path.as_deref() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read tls.ca_cert_path {path}"))?;
        let certs = rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse tls.ca_cert_path {path} as PEM"))?;
        if certs.is_empty() {
            bail!("tls.ca_cert_path {path} contains no PEM certificates");
        }
    }
    Ok(())
}

/// Builds (and does not cache, since each `McpTlsConfig` can differ per
/// server) the rustls client config used to dial `https://` MCP endpoints.
/// rustls 0.23 requires selecting a process-wide default `CryptoProvider`
/// once more than one crypto backend is compiled into the binary — which
/// happens here because `ferrogate-auth` depends on `rustls` with the
/// `ring` feature while this crate uses the default `aws-lc-rs` backend.
/// Installing the default explicitly and idempotently avoids the "Could not
/// automatically determine the process-level CryptoProvider" panic in any
/// binary/test that links both (issue #163/#167).
fn ensure_rustls_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn mcp_tls_client_config(tls: &McpTlsConfig) -> AnyResult<Arc<ClientConfig>> {
    ensure_rustls_crypto_provider();
    if tls.insecure_skip_verify {
        tracing::warn!(
            "MCP server configured with tls.insecure_skip_verify=true; certificate validation is disabled"
        );
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerCertVerification))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        bail!(
            "failed to load platform native certificates: {:?}",
            native_certs.errors
        );
    }
    for cert in native_certs.certs {
        let _ = roots.add(cert);
    }
    if let Some(path) = tls.ca_cert_path.as_deref() {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read tls.ca_cert_path {path}"))?;
        let certs = rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("failed to parse tls.ca_cert_path {path} as PEM"))?;
        for cert in certs {
            roots
                .add(cert)
                .with_context(|| format!("failed to trust certificate from {path}"))?;
        }
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A `rustls` server-certificate verifier that accepts everything, used only
/// when an operator explicitly sets `tls.insecure_skip_verify = true`.
#[derive(Debug)]
struct NoServerCertVerification;

impl ServerCertVerifier for NoServerCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
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

/// Resolve a namespaced `serverName-toolName` string to its configured server.
///
/// Tool names are built as `{server_name}-{remote_name}`, and both server and
/// remote names may themselves contain hyphens, so a naive `split_once('-')`
/// mis-routes (e.g. server `my-fs` tool `read` -> `my-fs-read` would resolve to
/// server `my`). Match against the actual configured server names and prefer
/// the longest match, so hyphenated server names still route correctly.
fn resolve_namespaced_session(
    sessions: &HashMap<String, Arc<Mutex<McpSession>>>,
    name: &str,
) -> Option<(String, String, Arc<Mutex<McpSession>>)> {
    sessions
        .iter()
        .filter_map(|(server_name, session)| {
            name.strip_prefix(server_name.as_str())
                .and_then(|rest| rest.strip_prefix('-'))
                .filter(|remote| !remote.trim().is_empty())
                .map(|remote| (server_name.clone(), remote.to_string(), Arc::clone(session)))
        })
        .max_by_key(|(server_name, _, _)| server_name.len())
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
    match config.auth_type {
        McpAuthType::Oauth => bail!(
            "MCP auth_type oauth is not implemented; use per_user_oauth for user-isolated OAuth or shared_headers for shared credentials"
        ),
        McpAuthType::PerUserHeaders => bail!(
            "MCP auth_type per_user_headers is not implemented; use per_user_oauth, original_bearer, or ferrogate_signed_jwt"
        ),
        McpAuthType::SharedHeaders if config.headers.is_empty() => {
            bail!("MCP auth_type shared_headers requires at least one static header")
        }
        McpAuthType::None if !config.headers.is_empty() => {
            bail!("MCP static headers require auth_type shared_headers")
        }
        McpAuthType::PerUserOauth | McpAuthType::OriginalBearer => {
            let oauth = config.oauth.as_ref().ok_or_else(|| {
                anyhow::anyhow!("MCP auth_type {} requires oauth configuration", config.auth_type.as_str())
            })?;
            validate_oauth_config(oauth, matches!(config.auth_type, McpAuthType::PerUserOauth))?;
        }
        McpAuthType::FerrogateSignedJwt => {
            if config.signed_jwt_audience.as_deref().is_none_or(str::is_empty) {
                bail!("MCP auth_type ferrogate_signed_jwt requires signed_jwt_audience");
            }
        }
        McpAuthType::None | McpAuthType::SharedHeaders => {}
    }
    for header in &config.headers {
        validate_static_header(header)?;
    }
    if !matches!(config.auth_type, McpAuthType::SharedHeaders) && !config.headers.is_empty() {
        bail!("per-user MCP identity modes cannot define static headers");
    }
    match config.transport {
        McpTransport::StreamableHttp | McpTransport::Sse => {
            let url = config.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!("MCP network server {} requires url", config.name)
            })?;
            validate_http_endpoint(url)?;
            validate_mcp_tls_config(&config.tls)
                .with_context(|| format!("MCP server {}", config.name))?;
        }
        McpTransport::Stdio => {
            if config.command.as_deref().is_none_or(str::is_empty) {
                bail!("MCP stdio server {} requires command", config.name);
            }
        }
    }
    Ok(())
}

fn validate_oauth_config(config: &McpOauthConfig, authorization_code: bool) -> AnyResult<()> {
    let issuer: Uri = config
        .issuer
        .parse()
        .context("MCP oauth.issuer is invalid")?;
    if !matches!(issuer.scheme_str(), Some("http" | "https")) || issuer.authority().is_none() {
        bail!("MCP oauth.issuer must be an http or https URL");
    }
    if issuer.scheme_str() == Some("http") && !config.allow_insecure_http {
        bail!("MCP oauth.issuer must use https unless allow_insecure_http is explicitly enabled");
    }
    if config.client_id.trim().is_empty() {
        bail!("MCP oauth.client_id cannot be empty");
    }
    if config.scopes.is_empty() || config.scopes.iter().any(|scope| scope.trim().is_empty()) {
        bail!("MCP oauth.scopes must contain non-empty values");
    }
    if authorization_code {
        if config
            .client_secret_ref
            .as_deref()
            .is_none_or(str::is_empty)
        {
            bail!("MCP per_user_oauth requires oauth.client_secret_ref");
        }
        if config.redirect_uri.as_deref().is_none_or(str::is_empty) {
            bail!("MCP per_user_oauth requires oauth.redirect_uri");
        }
    }
    Ok(())
}

fn validate_static_header(header: &McpHeaderConfig) -> AnyResult<()> {
    HeaderName::from_bytes(header.name.as_bytes()).context("MCP static header name is invalid")?;
    match (&header.value, &header.value_env) {
        (Some(value), None) => {
            HeaderValue::from_str(value).context("MCP static header value is invalid")?;
        }
        (None, Some(name)) if !name.trim().is_empty() => {}
        _ => bail!("MCP static header must set exactly one of value or value_env"),
    }
    Ok(())
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
