// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Stdio MCP client: JSON-RPC over a spawned child process's stdin/stdout.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ToolDef;
use serde_json::{json, Value};

use crate::config::McpServerConfig;
use crate::jsonrpc::{
    call_tool_params, ensure_no_jsonrpc_error, parse_call_result, parse_tools_list,
};
use crate::manager::McpToolExecutionResult;
use crate::protocol::{
    discover_supports_current_version, is_recognized_modern_error, jsonrpc_error_code,
    modern_discover_params, modern_request_params, resolve_legacy_protocol_version,
    McpClientNegotiation, McpNegotiatedProtocol, McpProtocolDowngradeReason,
    MCP_LEGACY_PROTOCOL_VERSION,
};

#[derive(Debug)]
enum StdioRead {
    Line(String),
    Error(String),
    Closed,
}

#[derive(Debug)]
enum StdioRequestError {
    Write(String),
    Timeout,
    Closed,
    Read(String),
    InvalidJson(String),
}

impl std::fmt::Display for StdioRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Write(error) => write!(formatter, "failed to write MCP stdio request: {error}"),
            Self::Timeout => formatter.write_str("MCP stdio response timed out"),
            Self::Closed => formatter.write_str("MCP stdio server closed stdout"),
            Self::Read(error) => write!(formatter, "failed to read MCP stdio response: {error}"),
            Self::InvalidJson(error) => {
                write!(formatter, "invalid MCP stdio JSON response: {error}")
            }
        }
    }
}

impl std::error::Error for StdioRequestError {}

#[derive(Debug)]
struct SpawnedStdioProcess {
    child: Arc<Mutex<Child>>,
    stdin: ChildStdin,
    responses: Receiver<StdioRead>,
    reader_thread: JoinHandle<()>,
    reader_done: Receiver<()>,
}

#[derive(Debug)]
pub(crate) struct StdioMcpClient {
    pub(crate) child: Arc<Mutex<Child>>,
    stdin: Option<ChildStdin>,
    responses: Receiver<StdioRead>,
    reader_thread: Option<JoinHandle<()>>,
    reader_done: Option<Receiver<()>>,
    command: String,
    args: Vec<String>,
    server_name: String,
    timeout: Duration,
    pub(crate) next_id: u64,
    pub(crate) negotiation: McpClientNegotiation,
}

impl StdioMcpClient {
    pub(crate) fn new(config: &McpServerConfig) -> AnyResult<Self> {
        let command = config
            .command
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MCP stdio server {} requires command", config.name))?;
        let process = spawn_process(command, &config.args, &config.name)?;
        Ok(Self {
            child: process.child,
            stdin: Some(process.stdin),
            responses: process.responses,
            reader_thread: Some(process.reader_thread),
            reader_done: Some(process.reader_done),
            command: command.to_string(),
            args: config.args.clone(),
            server_name: config.name.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            next_id: 1,
            negotiation: McpClientNegotiation::Pending,
        })
    }

    pub(crate) fn negotiate(&mut self) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "server/discover",
            "params": modern_discover_params()
        });
        let response = match self.send_json(&body) {
            Ok(response) => response,
            Err(StdioRequestError::Timeout) => {
                self.restart_process()?;
                return self.initialize_legacy(Some(McpProtocolDowngradeReason::StdioProbeTimeout));
            }
            Err(
                StdioRequestError::Write(_)
                | StdioRequestError::Closed
                | StdioRequestError::Read(_),
            ) => {
                self.restart_process()?;
                return self
                    .initialize_legacy(Some(McpProtocolDowngradeReason::StdioProbeProcessExit));
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(code) = jsonrpc_error_code(&response) {
            if is_recognized_modern_error(&response) {
                bail!("MCP modern discovery returned JSON-RPC error code {code}");
            }
            let reason = if code == -32601 {
                McpProtocolDowngradeReason::StdioMethodNotFound
            } else {
                McpProtocolDowngradeReason::StdioUnrecognizedError
            };
            return self.initialize_legacy(Some(reason));
        }
        if !discover_supports_current_version(&response) {
            bail!("MCP modern discovery did not advertise the requested protocol version");
        }
        self.negotiation = McpClientNegotiation::modern();
        Ok(())
    }

    fn initialize_legacy(
        &mut self,
        downgrade_reason: Option<McpProtocolDowngradeReason>,
    ) -> AnyResult<()> {
        let id = self.next_jsonrpc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "ferrogate", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let response = self.send_json(&body)?;
        ensure_no_jsonrpc_error(&response)?;
        let version = resolve_legacy_protocol_version(
            response
                .get("result")
                .and_then(|result| result.get("protocolVersion"))
                .and_then(Value::as_str),
        )
        .ok_or_else(|| {
            anyhow::anyhow!("MCP initialize returned an invalid legacy protocol version")
        })?;
        self.negotiation = McpClientNegotiation::legacy(version, downgrade_reason);
        Ok(())
    }

    pub(crate) fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        let id = self.next_jsonrpc_id();
        let params = self.request_params(json!({}))?;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params});
        let response = self.send_json(&body)?;
        parse_tools_list(&response)
    }

    pub(crate) fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
    ) -> Result<McpToolExecutionResult, String> {
        let id = self.next_jsonrpc_id();
        let params = call_tool_params(name, arguments).map_err(|error| error.to_string())?;
        let params = self
            .request_params(params)
            .map_err(|error| error.to_string())?;
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params
        });
        let response = self.send_json(&body).map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    pub(crate) fn health_check(&mut self) -> AnyResult<()> {
        if self.negotiation.is_modern() {
            let id = self.next_jsonrpc_id();
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "server/discover",
                "params": modern_discover_params()
            });
            let response = self.send_json(&body)?;
            if !discover_supports_current_version(&response) {
                bail!("MCP modern health discovery did not advertise the negotiated version");
            }
            return Ok(());
        }

        let id = self.next_jsonrpc_id();
        let params = self.request_params(json!({}))?;
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "ping", "params": params});
        let response = self.send_json(&body)?;
        ensure_no_jsonrpc_error(&response)
    }

    fn request_params(&self, params: Value) -> AnyResult<Value> {
        let protocol = self
            .negotiation
            .negotiated()
            .ok_or_else(|| anyhow::anyhow!("MCP request attempted before protocol negotiation"))?;
        if protocol.mode == crate::protocol::McpProtocolMode::Modern {
            modern_request_params(params).map_err(anyhow::Error::msg)
        } else {
            Ok(params)
        }
    }

    pub(crate) fn negotiated_protocol(&self) -> Option<McpNegotiatedProtocol> {
        self.negotiation.negotiated()
    }

    fn send_json(&mut self, body: &Value) -> Result<Value, StdioRequestError> {
        let expected_id = body.get("id").cloned();
        let line = serde_json::to_string(body)
            .map_err(|error| StdioRequestError::Write(error.to_string()))?;
        let stdin = self.stdin.as_mut().ok_or(StdioRequestError::Closed)?;
        writeln!(stdin, "{line}").map_err(|error| StdioRequestError::Write(error.to_string()))?;
        stdin
            .flush()
            .map_err(|error| StdioRequestError::Write(error.to_string()))?;

        let started = Instant::now();
        loop {
            let remaining = self
                .timeout
                .checked_sub(started.elapsed())
                .ok_or(StdioRequestError::Timeout)?;
            match self.responses.recv_timeout(remaining) {
                Ok(StdioRead::Line(response)) => {
                    let value: Value = serde_json::from_str(&response)
                        .map_err(|error| StdioRequestError::InvalidJson(error.to_string()))?;
                    if expected_id
                        .as_ref()
                        .is_some_and(|id| value.get("id") == Some(id))
                    {
                        return Ok(value);
                    }
                    // Notifications and late responses share stdout. Keep
                    // waiting for the response correlated to this request ID.
                }
                Ok(StdioRead::Error(error)) => return Err(StdioRequestError::Read(error)),
                Ok(StdioRead::Closed) => return Err(StdioRequestError::Closed),
                Err(RecvTimeoutError::Timeout) => return Err(StdioRequestError::Timeout),
                Err(RecvTimeoutError::Disconnected) => return Err(StdioRequestError::Closed),
            }
        }
    }

    fn restart_process(&mut self) -> AnyResult<()> {
        self.stop_process();
        let process = spawn_process(&self.command, &self.args, &self.server_name)?;
        self.child = process.child;
        self.stdin = Some(process.stdin);
        self.responses = process.responses;
        self.reader_thread = Some(process.reader_thread);
        self.reader_done = Some(process.reader_done);
        Ok(())
    }

    fn stop_process(&mut self) {
        self.stdin.take();
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let reader_stopped = self.reader_done.take().is_some_and(|reader_done| {
            reader_done.recv_timeout(Duration::from_millis(100)).is_ok()
        });
        if let Some(reader_thread) = self.reader_thread.take() {
            if reader_stopped {
                let _ = reader_thread.join();
            }
            // A descendant that inherited stdout can keep the read blocked
            // after the direct child exits. Dropping the handle detaches that
            // reader instead of turning cleanup into another unbounded wait.
        }
    }

    fn next_jsonrpc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }
}

impl Drop for StdioMcpClient {
    fn drop(&mut self) {
        self.stop_process();
    }
}

fn spawn_process(
    command: &str,
    args: &[String],
    server_name: &str,
) -> AnyResult<SpawnedStdioProcess> {
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("failed to spawn MCP stdio server {server_name}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("MCP stdio stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("MCP stdio stdout unavailable"))?;
    let child = Arc::new(Mutex::new(child));
    let (sender, responses) = mpsc::channel();
    let (done_sender, reader_done) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        read_responses(stdout, sender);
        let _ = done_sender.send(());
    });
    Ok(SpawnedStdioProcess {
        child,
        stdin,
        responses,
        reader_thread,
        reader_done,
    })
}

fn read_responses(stdout: ChildStdout, sender: mpsc::Sender<StdioRead>) {
    let mut stdout = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        match stdout.read_line(&mut line) {
            Ok(0) => {
                let _ = sender.send(StdioRead::Closed);
                return;
            }
            Ok(_) => {
                if sender.send(StdioRead::Line(line)).is_err() {
                    return;
                }
            }
            Err(error) => {
                let _ = sender.send(StdioRead::Error(error.to_string()));
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "stdio_client_test.rs"]
mod tests;
