// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

use crate::{
    auth::AuthContext,
    extensions::ToolExecutionRequest,
    gateway::ProxyContext,
    state::{AdminAuditEventDraft, AppState},
};

use super::local::{
    tool_execution_entitlement_denial, validate_skill_tool_capability, SkillExecutionContext,
    ToolExecuteBackend, ToolExecutionContext,
};
use super::FerroGateway;

#[derive(Debug, Deserialize)]
pub(super) struct McpJsonRpcRequest {
    #[serde(default)]
    pub(super) jsonrpc: Option<String>,
    #[serde(default)]
    pub(super) id: Option<Value>,
    pub(super) method: String,
    #[serde(default)]
    pub(super) params: Value,
}

#[derive(Debug, Serialize)]
pub(super) struct McpJsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpJsonRpcError>,
}

#[derive(Debug, Serialize)]
struct McpJsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct MissingScopeMapping {
    method: String,
}

impl fmt::Display for MissingScopeMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "runtime API contract has no MCP scope mapping for method {}",
            self.method
        )
    }
}

pub(super) fn required_scope(method: &str) -> Result<&'static str, MissingScopeMapping> {
    super::api_contract::method_dependent_scope(&http::Method::POST, "/v1/mcp", method).ok_or_else(
        || MissingScopeMapping {
            method: method.to_string(),
        },
    )
}

pub(super) async fn handle_request(
    gateway: &FerroGateway,
    state: &AppState,
    ctx: &ProxyContext,
    auth: &AuthContext,
    skill_context: Option<&SkillExecutionContext>,
    original_bearer: Option<&str>,
    rpc: McpJsonRpcRequest,
) -> McpJsonRpcResponse {
    match rpc.method.as_str() {
        "initialize" => result(rpc.id, initialize_result()),
        "ping" => result(rpc.id, json!({})),
        "tools/list" => tools_list(state, ctx, auth, skill_context, rpc.id),
        "tools/call" => {
            tools_call(
                gateway,
                state,
                ctx,
                auth,
                skill_context,
                original_bearer,
                rpc.id,
                &rpc.params,
            )
            .await
        }
        _ => error(
            rpc.id,
            -32601,
            format!("MCP method {} is not supported", rpc.method),
        ),
    }
}

pub(super) fn result(id: Option<Value>, result: Value) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

pub(super) fn error(
    id: Option<Value>,
    code: i64,
    message: impl Into<String>,
) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(McpJsonRpcError {
            code,
            message: message.into(),
        }),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "tools": {
                "listChanged": false
            }
        },
        "instructions": "Use FerroGate as a governed MCP gateway. Follow the server's auth, policy, approval, and billing rules for all tool calls.",
        "serverInfo": {
            "name": "ferrogate",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tools_list(
    state: &AppState,
    ctx: &ProxyContext,
    auth: &AuthContext,
    skill_context: Option<&SkillExecutionContext>,
    id: Option<Value>,
) -> McpJsonRpcResponse {
    let tools = state.mcp_tools_for(
        &auth.tenant_context(),
        auth.api_key_id.as_deref(),
        Some("/v1/mcp"),
    );
    state.record_admin_audit_event(audit_event(
        ctx,
        auth,
        skill_context,
        "tool.list",
        "mcp",
        "success",
        format!(
            "listed {} MCP tools through native MCP endpoint",
            tools.len()
        ),
    ));
    result(
        id,
        json!({
            "tools": tools
                .into_iter()
                .map(|tool| {
                    json!({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": tool.input_schema
                    })
                })
                .collect::<Vec<_>>()
        }),
    )
}

#[allow(clippy::too_many_arguments)]
async fn tools_call(
    gateway: &FerroGateway,
    state: &AppState,
    ctx: &ProxyContext,
    auth: &AuthContext,
    skill_context: Option<&SkillExecutionContext>,
    original_bearer: Option<&str>,
    id: Option<Value>,
    params: &Value,
) -> McpJsonRpcResponse {
    // Plan/RBAC entitlement gate (issues #182/#183): this JSON-RPC
    // transport executes the exact same MCP tools as `POST
    // /v1/mcp/tool/execute`, discovered by a follow-up audit to be a
    // third call site that bypassed the gate those two REST endpoints
    // both enforce. See `tool_execution_entitlement_denial`'s doc
    // comment.
    if let Some((error_code, error_message)) =
        tool_execution_entitlement_denial(state, auth, ToolExecuteBackend::Mcp).await
    {
        return error(id, mcp_error_code(error_code), error_message.to_string());
    }

    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return error(id, -32602, "tools/call params.name is required");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let request = ToolExecutionRequest {
        name: name.to_string(),
        arguments,
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    if let Some(skill_context) = skill_context {
        if let Err(error_response) = validate_skill_tool_capability(
            state,
            skill_context,
            ToolExecuteBackend::Mcp,
            &request.name,
        ) {
            let audit_target = tool_audit_details(&request.name)
                .map(|(server_name, tool_name)| tool_audit_target(&server_name, &tool_name))
                .unwrap_or_else(|| request.name.clone());
            state.record_admin_audit_event(audit_event(
                ctx,
                auth,
                Some(skill_context),
                "tool.execute",
                audit_target,
                "rejected",
                error_response.message.clone(),
            ));
            return error(
                id,
                mcp_error_code(error_response.code),
                error_response.message,
            );
        }
    }
    // Route execution through the SAME governed chokepoint that the REST
    // endpoint `POST /v1/mcp/tool/execute` uses. A follow-up adversarial audit
    // found that this JSON-RPC transport executed MCP tools directly via
    // `execute_mcp_tool`, bypassing the #200/#204 managed-action guardrails
    // (input block/quarantine, output redaction/withhold) and the approval gate
    // that `execute_tool_request_with_governance` enforces for every other
    // in-process tool backend. Delegating here closes that bypass so the
    // JSON-RPC path inherits the input guardrail, approval, MCP identity
    // resolution, and output guardrail identically to REST.
    //
    // The chokepoint owns the allowlist (`tool_by_name`) check, the approval
    // gate, `resolve_mcp_identity` (fed the original bearer via
    // `mcp_original_bearer`), execution, and the tool.execute / guardrail /
    // approval / identity audit events. Those are therefore intentionally NOT
    // repeated here — doing so would double-govern and double-audit. The
    // entitlement gate and skill-capability check above run before governance,
    // matching the REST handler which performs them prior to the chokepoint.
    let execution = ToolExecutionContext {
        skill_package_id: skill_context.map(|context| context.id.as_str()),
        skill_package_version: skill_context.map(|context| context.version.as_str()),
        mcp_original_bearer: original_bearer,
        ..ToolExecutionContext::default()
    };
    match gateway
        .execute_tool_request_with_governance(
            ctx,
            auth,
            execution,
            request,
            ToolExecuteBackend::Mcp,
        )
        .await
    {
        Ok(response) => {
            let content = response
                .content
                .get("content")
                .cloned()
                .unwrap_or_else(|| response.content.clone());
            result(
                id,
                json!({
                    "content": content,
                    "isError": response.is_error
                }),
            )
        }
        Err(error_response) => error(
            id,
            mcp_error_code(error_response.code),
            error_response.message,
        ),
    }
}

pub(super) fn tool_session_audit_target(session_id: &str) -> String {
    format!("tool_session:{session_id}")
}

pub(super) fn tool_session_mcp_audit_target(
    session_id: &str,
    server_name: &str,
    tool_name: &str,
) -> String {
    format!(
        "{}/{}",
        tool_session_audit_target(session_id),
        tool_audit_target(server_name, tool_name)
    )
}

pub(super) fn tool_audit_details(name: &str) -> Option<(String, String)> {
    let (server_name, tool_name) = name.split_once('-')?;
    Some((server_name.into(), tool_name.into()))
}

pub(super) fn tool_audit_target(server_name: &str, tool_name: &str) -> String {
    format!("mcp:{server_name}/tool:{tool_name}")
}

pub(super) fn tool_audit_message(
    details: Option<&(String, String)>,
    tool_name: &str,
    action: &str,
    latency_ms: Option<u64>,
) -> String {
    match details {
        Some((server_name, upstream_tool_name)) => {
            let latency = latency_ms
                .map(|latency_ms| format!(" in {latency_ms}ms"))
                .unwrap_or_default();
            format!("MCP upstream mcp:{server_name} tool {upstream_tool_name} {action}{latency}")
        }
        None => match latency_ms {
            Some(latency_ms) => format!("tool {tool_name} {action} in {latency_ms}ms"),
            None => format!("tool {tool_name} {action}"),
        },
    }
}

pub(super) fn tool_audit_failure_message(
    details: Option<&(String, String)>,
    tool_name: &str,
    code: &str,
    message: &str,
) -> String {
    match details {
        Some((server_name, upstream_tool_name)) => format!(
            "MCP upstream mcp:{server_name} tool {upstream_tool_name} failed: {code}: {message}"
        ),
        None => format!("tool {tool_name} failed: {code}: {message}"),
    }
}

fn audit_event(
    ctx: &ProxyContext,
    auth: &AuthContext,
    skill_context: Option<&SkillExecutionContext>,
    action: impl Into<String>,
    target: impl Into<String>,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    let (target, message) = decorate_skill_audit(skill_context, target.into(), message.into());
    AdminAuditEventDraft {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        actor_api_key_id: auth.api_key_id.clone(),
        tenant: auth.tenant_context(),
        action: action.into(),
        target,
        outcome: outcome.into(),
        message,
    }
}

fn decorate_skill_audit(
    skill_context: Option<&SkillExecutionContext>,
    target: String,
    message: String,
) -> (String, String) {
    let Some(skill_context) = skill_context else {
        return (target, message);
    };
    let skill = format!("{}@{}", skill_context.id, skill_context.version);
    (
        format!("skill_package:{skill}/{target}"),
        format!("skill_package={skill} {message}"),
    )
}

fn mcp_error_code(code: &str) -> i64 {
    match code {
        "tool_denied" => -32001,
        "tool_not_found" => -32602,
        "mcp_server_unavailable" => -32002,
        _ => -32000,
    }
}

#[cfg(test)]
#[path = "mcp_rpc_test.rs"]
mod mcp_rpc_test;
