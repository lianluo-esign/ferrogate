// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Stdio MCP client: JSON-RPC over a spawned child process's stdin/stdout.

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ToolDef;
use serde_json::{json, Value};

use crate::config::McpServerConfig;
use crate::jsonrpc::{
    call_tool_params, ensure_no_jsonrpc_error, parse_call_result, parse_tools_list,
};
use crate::manager::McpToolExecutionResult;
use crate::protocol::MCP_PROTOCOL_VERSION;

#[derive(Debug)]
pub(crate) struct StdioMcpClient {
    pub(crate) child: Arc<Mutex<Child>>,
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: BufReader<ChildStdout>,
    pub(crate) next_id: u64,
}

impl StdioMcpClient {
    pub(crate) fn new(config: &McpServerConfig) -> AnyResult<Self> {
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
        let response = self.send_json(&body)?;
        ensure_no_jsonrpc_error(&response)?;
        Ok(())
    }

    pub(crate) fn list_tools(&mut self) -> AnyResult<Vec<ToolDef>> {
        let id = self.next_jsonrpc_id();
        let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}});
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
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": params
        });
        let response = self.send_json(&body).map_err(|error| error.to_string())?;
        parse_call_result(&response).map_err(|error| error.to_string())
    }

    pub(crate) fn ping(&mut self) -> AnyResult<()> {
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
