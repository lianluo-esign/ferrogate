// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::approval::ApprovalStatus;
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
    ToolExecuteBackend,
};

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

async fn tools_call(
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
    let audit_details = tool_audit_details(&request.name);
    let audit_target = audit_details
        .as_ref()
        .map(|(server_name, tool_name)| tool_audit_target(server_name, tool_name))
        .unwrap_or_else(|| request.name.clone());
    if let Some(skill_context) = skill_context {
        if let Err(error_response) = validate_skill_tool_capability(
            state,
            skill_context,
            ToolExecuteBackend::Mcp,
            &request.name,
        ) {
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
    let Some(tool) = state.tool_by_name(&request.name) else {
        let (code, message) = if audit_details.is_some() {
            (
                "tool_denied",
                format!("MCP tool {} is not allowlisted for execution", request.name),
            )
        } else {
            (
                "tool_not_found",
                format!("tool {} is not registered", request.name),
            )
        };
        state.record_admin_audit_event(audit_event(
            ctx,
            auth,
            skill_context,
            "tool.execute",
            audit_target,
            "error",
            tool_audit_failure_message(audit_details.as_ref(), name, code, &message),
        ));
        return error(id, mcp_error_code(code), message);
    };

    if tool.approval_policy == ferrogate_core::ApprovalPolicy::Always {
        let approval = match state.create_tool_approval(crate::state::ToolApprovalCreateRequest {
            tool: &request,
            request_id: &ctx.request_id,
            trace_id: ctx.trace_id.clone(),
            tenant: auth.tenant_context(),
            actor_api_key_id: auth.api_key_id.clone(),
            server_name: audit_details
                .as_ref()
                .map(|(server, _)| server.clone())
                .or_else(|| Some(tool.extension_id.clone())),
            approval_policy: tool.approval_policy,
            can_log_bodies: auth.can_record_bodies(state.config.telemetry.log_bodies),
        }) {
            Ok(approval) => approval,
            Err(error_response) => {
                state.record_admin_audit_event(audit_event(
                    ctx,
                    auth,
                    skill_context,
                    "tool.approval_requested",
                    format!("tool:{name}"),
                    "error",
                    format!("tool approval persistence failed: {error_response}"),
                ));
                return error(
                    id,
                    -32003,
                    "tool approval could not be persisted".to_string(),
                );
            }
        };
        state.record_admin_audit_event(audit_event(
            ctx,
            auth,
            skill_context,
            "tool.approval_requested",
            format!("tool_approval:{}", approval.id),
            "pending",
            format!(
                "approval {} fingerprint={} tool={} expires_at_unix={}",
                approval.id, approval.fingerprint, approval.tool_name, approval.expires_at_unix
            ),
        ));
        match state.wait_for_tool_approval(&approval).await {
            Ok(resolved) => {
                state.record_admin_audit_event(audit_event(
                    ctx,
                    auth,
                    skill_context,
                    "tool.approval_granted",
                    format!("tool_approval:{}", resolved.id),
                    "approved",
                    format!(
                        "approval {} fingerprint={} tool={} granted before execution",
                        resolved.id, resolved.fingerprint, resolved.tool_name
                    ),
                ));
            }
            Err(error_response) => {
                let latest = state.tool_approval(&approval.id).unwrap_or(approval);
                let action = match latest.status {
                    ApprovalStatus::Denied => "tool.approval_denied",
                    ApprovalStatus::Expired => "tool.approval_expired",
                    _ => "tool.approval_rejected",
                };
                state.record_admin_audit_event(audit_event(
                    ctx,
                    auth,
                    skill_context,
                    action,
                    format!("tool_approval:{}", latest.id),
                    "rejected",
                    format!(
                        "approval {} fingerprint={} tool={} ended before execution: {}",
                        latest.id,
                        latest.fingerprint,
                        latest.tool_name,
                        error_response.message()
                    ),
                ));
                return error(
                    id,
                    mcp_error_code(error_response.code()),
                    error_response.message(),
                );
            }
        }
    }
    let Some((server_name, _)) = audit_details.as_ref() else {
        return error(
            id,
            -32602,
            "MCP tool name must use serverName-toolName namespace",
        );
    };
    let identity = match state
        .resolve_mcp_identity(auth, server_name, original_bearer)
        .await
    {
        Ok(identity) => identity,
        Err(identity_error) => {
            state.record_mcp_identity_resolution_metric(false);
            state.record_admin_audit_event(audit_event(
                ctx,
                auth,
                skill_context,
                "mcp.identity.resolve",
                audit_target,
                "rejected",
                format!(
                    "server={server_name} tool={name} decision=deny code={}",
                    identity_error.code
                ),
            ));
            return error(
                id,
                mcp_error_code(identity_error.code),
                identity_error.message,
            );
        }
    };
    state.record_mcp_identity_resolution_metric(true);
    state.record_admin_audit_event(audit_event(
        ctx,
        auth,
        skill_context,
        "mcp.identity.resolve",
        audit_target.clone(),
        "allowed",
        format!(
            "server={server_name} tool={name} source={} subject={} decision=allow",
            identity.credential_source,
            identity.subject.as_deref().unwrap_or("none")
        ),
    ));
    match state
        .execute_mcp_tool(
            request,
            ctx.request_id.clone(),
            ctx.trace_id.clone(),
            auth.tenant_context(),
            identity.headers,
        )
        .await
    {
        Ok(response) => {
            state.record_admin_audit_event(audit_event(
                ctx,
                auth,
                skill_context,
                "tool.execute",
                audit_target,
                "success",
                tool_audit_message(
                    audit_details.as_ref(),
                    &response.name,
                    "executed through native MCP endpoint",
                    Some(response.latency_ms),
                ),
            ));
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
        Err(error_response) => {
            state.record_admin_audit_event(audit_event(
                ctx,
                auth,
                skill_context,
                "tool.execute",
                audit_target,
                "error",
                tool_audit_failure_message(
                    audit_details.as_ref(),
                    name,
                    error_response.code(),
                    error_response.message(),
                ),
            ));
            error(
                id,
                mcp_error_code(error_response.code()),
                error_response.message(),
            )
        }
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
mod tests {
    use super::*;

    #[test]
    fn missing_method_scope_mapping_fails_closed() {
        let error = required_scope("unmapped/method").expect_err("missing mapping must fail");
        assert_eq!(error.method, "unmapped/method");
        assert!(error.to_string().contains("no MCP scope mapping"));
    }
}
