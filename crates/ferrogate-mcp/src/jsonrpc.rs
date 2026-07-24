// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! JSON-RPC helpers shared by the HTTP and stdio MCP clients: `tools/list` /
//! `tools/call` payload construction and response parsing via the `rmcp`
//! model types.

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::ToolDef;
use rmcp::model::{CallToolRequestParams, CallToolResult, ListToolsResult};
use serde_json::Value;

use crate::manager::McpToolExecutionResult;

pub(crate) fn parse_tools_list(response: &Value) -> AnyResult<Vec<ToolDef>> {
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

pub(crate) fn parse_call_result(response: &Value) -> AnyResult<McpToolExecutionResult> {
    ensure_no_jsonrpc_error(response)?;
    let result_value = response.get("result").cloned().unwrap_or(Value::Null);
    let result: CallToolResult =
        serde_json::from_value(result_value.clone()).context("invalid MCP tools/call result")?;
    Ok(McpToolExecutionResult {
        content: result_value,
        is_error: result.is_error.unwrap_or(false),
    })
}

pub(crate) fn call_tool_params(name: &str, arguments: Value) -> AnyResult<Value> {
    let mut params = CallToolRequestParams::new(name.to_string());
    if let Value::Object(arguments) = arguments {
        params = params.with_arguments(arguments);
    } else if !arguments.is_null() {
        bail!("MCP tool arguments must be a JSON object");
    }
    serde_json::to_value(params).context("failed to serialize MCP tools/call params")
}

pub(crate) fn ensure_no_jsonrpc_error(response: &Value) -> AnyResult<()> {
    if let Some(error) = response.get("error") {
        bail!("MCP JSON-RPC error: {error}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "jsonrpc_test.rs"]
mod tests;
