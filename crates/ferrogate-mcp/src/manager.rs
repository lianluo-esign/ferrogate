// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! MCP host: `McpManager` owns the long-lived upstream server sessions and
//! exposes tool listing, deny-by-default execution, health/reconnect, and
//! timeout cleanup to the gateway.

use std::{
    collections::HashMap,
    process::Child,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result as AnyResult};
use ferrogate_core::{ApprovalPolicy, ToolDef};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{tool_allowlisted, tool_selected, McpServerConfig, McpTransport};
use crate::http_client::HttpMcpClient;
use crate::protocol::{McpNegotiatedProtocol, McpProtocolDowngradeReason, McpProtocolMode};
use crate::stdio_client::StdioMcpClient;

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
    /// MCP protocol revision negotiated with this upstream (issue #277).
    /// `None` while disconnected.
    pub protocol_version: Option<String>,
    /// Candidate per-request metadata mode or initialize-based legacy mode.
    pub protocol_mode: Option<McpProtocolMode>,
    /// Bounded reason for selecting legacy mode after a modern probe.
    pub protocol_downgrade_reason: Option<McpProtocolDowngradeReason>,
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
pub struct McpDispatchHeaders(pub(crate) Vec<(String, String)>);

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
        let protocol = self
            .connected
            .then(|| {
                self.client
                    .as_ref()
                    .and_then(McpClient::negotiated_protocol)
            })
            .flatten();
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
            protocol_version: protocol.map(|protocol| protocol.version.to_string()),
            protocol_mode: protocol.map(|protocol| protocol.mode),
            protocol_downgrade_reason: protocol.and_then(|protocol| protocol.downgrade_reason),
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
        client.negotiate()?;
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
                .map(|client| client.health_check().is_ok())
                .unwrap_or(false);
            if healthy {
                return;
            }
            self.connected = false;
            self.last_error = Some("MCP health check failed".into());
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
    fn negotiate(&mut self) -> AnyResult<()> {
        match self {
            Self::Http(client) => client.negotiate(),
            Self::Stdio(client) => client.negotiate(),
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

    fn health_check(&mut self) -> AnyResult<()> {
        match self {
            Self::Http(client) => client.health_check(),
            Self::Stdio(client) => client.health_check(),
        }
    }

    fn stdio_child(&self) -> Option<Arc<Mutex<Child>>> {
        match self {
            Self::Http(_) => None,
            Self::Stdio(client) => Some(Arc::clone(&client.child)),
        }
    }

    fn negotiated_protocol(&self) -> Option<McpNegotiatedProtocol> {
        match self {
            Self::Http(client) => client.negotiated_protocol(),
            Self::Stdio(client) => client.negotiated_protocol(),
        }
    }
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

#[cfg(test)]
#[path = "manager_test.rs"]
mod tests;
