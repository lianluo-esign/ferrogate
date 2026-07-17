// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ferrogate_core::{RequestContext, ToolResult};
use ferrogate_runtime::{
    AgentHarness, AgentHarnessConfig, AgentProvider, AgentRunEvent, AgentRunEventKind,
    AgentRunEventSink, AgentRunInput, AgentRunOutcome, AgentRunStatus, AgentRuntimeError,
    AgentToolDispatchRequest, CapabilityAction, ExternalAgentProvider, ExternalAgentProviderConfig,
    GovernedAgentToolDispatcher, NormalizedFrameworkEvent,
};
use http::{HeaderMap, Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    auth::{authenticate, AuthContext},
    config::{
        AgentRuntimeConfig, AgentRuntimeExternalConfig, AgentRuntimeProvider,
        AgentWorkflowNodeKind, AgentWorkflowPolicy,
    },
    extensions::ToolExecutionRequest,
    responses::{write_json_error, write_json_error_and_close, write_json_response},
    state::{AdminAuditEventDraft, AppState},
};
use ferrogate_storage::{StoredAgentRun, StoredAgentRunEvent};

use super::{
    body::read_request_body,
    local::{ToolExecuteBackend, ToolExecutionContext, ToolExecutionHttpError},
    FerroGateway, ProxyContext,
};

const AGENT_RUN_ID_HEADER: &str = "x-ferrogate-agent-run-id";
const WORKFLOW_ID_HEADER: &str = "x-ferrogate-workflow-id";
const WORKFLOW_VERSION_HEADER: &str = "x-ferrogate-workflow-version";
const WORKFLOW_NODE_ID_HEADER: &str = "x-ferrogate-workflow-node-id";
const AGENT_RUN_BODY_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
struct AgentRunCreateRequest {
    input: String,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    max_turns: Option<u32>,
    #[serde(default)]
    timeout_millis: Option<u64>,
    #[serde(default)]
    tool_calls: Vec<AgentRunToolCallRequest>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentRunToolCallRequest {
    name: String,
    #[serde(default)]
    arguments: Value,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct AgentRunCreateResponse {
    object: &'static str,
    id: String,
    status: &'static str,
    turns_executed: u32,
    output: Option<String>,
    tool_results: Vec<ToolResult>,
    request_id: String,
}

#[derive(Debug, Clone)]
struct AgentWorkflowUse {
    id: String,
    version: u32,
    node_id: String,
    /// The tool this workflow node is restricted to, if any (`node.tool`).
    /// Enforced fail-closed against the tool that is ACTUALLY dispatched, not
    /// just the caller-declared `tool_calls`.
    node_tool: Option<String>,
}

impl FerroGateway {
    pub(super) async fn handle_agent_run_create(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "agent run creation requires POST",
                &ctx.request_id,
            )
            .await;
        }

        let state = self.state.current();
        if !state.config.agent_runtime.enabled {
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "agent_runtime_disabled",
                "agent runtime is disabled by operator config",
                &ctx.request_id,
            )
            .await;
        }

        let auth = match authenticate(&state, &headers, "agent.runs.create", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let body = match read_request_body(session, AGENT_RUN_BODY_MAX_BYTES).await? {
            Ok(body) => body,
            Err(limit) => {
                return write_json_error_and_close(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        };
        let request: AgentRunCreateRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid agent run JSON: {error}"),
                    &ctx.request_id,
                )
                .await;
            }
        };
        if request.input.trim().is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_agent_run_input",
                "agent run input must not be empty",
                &ctx.request_id,
            )
            .await;
        }

        let run_id =
            match requested_agent_run_id(&headers, request.run_id.as_deref(), &ctx.request_id) {
                Ok(run_id) => run_id,
                Err(message) => {
                    return write_json_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        "invalid_agent_run_id",
                        message,
                        &ctx.request_id,
                    )
                    .await;
                }
            };
        if let Some(tool_call) = request
            .tool_calls
            .iter()
            .find(|tool_call| tool_call.name.trim().is_empty())
        {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_agent_tool_call",
                format!("agent tool call name must not be empty: {tool_call:?}"),
                &ctx.request_id,
            )
            .await;
        }

        let workflow_use = match agent_workflow_use(&state, &headers, &auth, &run_id, &request) {
            Ok(workflow_use) => workflow_use,
            Err((status, code, message)) => {
                return write_json_error(session, status, code, message, &ctx.request_id).await;
            }
        };

        let harness_config = match harness_config(&state, &request) {
            Ok(config) => config,
            Err((code, message)) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    code,
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let harness = match AgentHarness::new(harness_config) {
            Ok(harness) => harness,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_agent_runtime_config",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };

        let request_context = RequestContext {
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            agent_run_id: Some(run_id.clone()),
            workflow_id: workflow_use.as_ref().map(|workflow| workflow.id.clone()),
            workflow_version: workflow_use.as_ref().map(|workflow| workflow.version),
            workflow_node_id: workflow_use
                .as_ref()
                .map(|workflow| workflow.node_id.clone()),
            route: Some("agent.run".to_string()),
            upstream: None,
            tenant: auth.tenant_context(),
        };
        let started_at_unix = now_unix_seconds();
        let provider_name = agent_provider_name(&state.config.agent_runtime).to_string();
        state.record_agent_run(StoredAgentRun {
            id: run_id.clone(),
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant: auth.tenant_context(),
            status: "running".to_string(),
            provider: provider_name.clone(),
            turns_executed: 0,
            output_recorded: false,
            started_at_unix: Some(started_at_unix),
            completed_at_unix: None,
        });
        let tool_calls = request.tool_calls;
        let mut provider = match agent_provider(
            &state.config.agent_runtime,
            AgentProviderContext {
                input: request.input,
            },
        ) {
            Ok(provider) => provider,
            Err((code, message)) => {
                state.record_agent_run(StoredAgentRun {
                    id: run_id.clone(),
                    request_id: ctx.request_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    tenant: auth.tenant_context(),
                    status: "failed".to_string(),
                    provider: provider_name,
                    turns_executed: 0,
                    output_recorded: false,
                    started_at_unix: Some(started_at_unix),
                    completed_at_unix: Some(now_unix_seconds()),
                });
                let status = if code == "agent_worker_transport_unavailable" {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return write_json_error(session, status, code, message, &ctx.request_id).await;
            }
        };
        let mut dispatcher = GatewayAgentToolDispatcher::new(
            self.clone(),
            ctx,
            auth.clone(),
            tool_calls,
            workflow_use.clone(),
        );
        let mut event_sink = AuditEventSink::new(state.clone(), ctx, &auth, workflow_use.clone());
        let outcome = match harness.run(
            AgentRunInput::new(request_context),
            provider.as_mut(),
            &mut dispatcher,
            &mut event_sink,
        ) {
            Ok(outcome) => outcome,
            Err(AgentRuntimeError::RunFailed { outcome, .. }) => *outcome,
            Err(error) => {
                state.record_agent_run(StoredAgentRun {
                    id: run_id.clone(),
                    request_id: ctx.request_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    tenant: auth.tenant_context(),
                    status: "failed".to_string(),
                    provider: provider_name.clone(),
                    turns_executed: 0,
                    output_recorded: false,
                    started_at_unix: Some(started_at_unix),
                    completed_at_unix: Some(now_unix_seconds()),
                });
                state.record_admin_audit_event(agent_audit_event(AgentAuditEventContext {
                    ctx,
                    auth: &auth,
                    agent_run_id: Some(run_id),
                    workflow_use: workflow_use.as_ref(),
                    action: "agent.run_failed",
                    target: "agent_run",
                    outcome: "error",
                    message: error.to_string(),
                }));
                return write_json_error(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "agent_run_failed",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };

        let status_code = outcome_status_code(&outcome);
        state.record_agent_run(StoredAgentRun {
            id: outcome.run_id.clone(),
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant: auth.tenant_context(),
            status: agent_status(&outcome.status).to_string(),
            provider: provider_name,
            turns_executed: outcome.turns_executed,
            output_recorded: outcome.output.is_some(),
            started_at_unix: Some(started_at_unix),
            completed_at_unix: Some(now_unix_seconds()),
        });
        let response = AgentRunCreateResponse {
            object: "agent_run",
            id: outcome.run_id,
            status: agent_status(&outcome.status),
            turns_executed: outcome.turns_executed,
            output: outcome.output,
            tool_results: outcome.tool_results,
            request_id: ctx.request_id.clone(),
        };
        write_json_response(session, status_code, &response, &ctx.request_id).await
    }
}

fn requested_agent_run_id(
    headers: &HeaderMap,
    body_run_id: Option<&str>,
    request_id: &str,
) -> Result<String, String> {
    let value = match headers.get(AGENT_RUN_ID_HEADER) {
        Some(value) => Some(value.to_str().map_err(|_| {
            format!("{AGENT_RUN_ID_HEADER} must be valid visible ASCII/UTF-8 header text")
        })?),
        None => body_run_id,
    };
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(format!("run-{request_id}"));
    };
    if value.len() > 128 {
        return Err("agent run id must be at most 128 characters".to_string());
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return Err("agent run id may only contain letters, numbers, _, -, ., or :".to_string());
    }
    Ok(value.to_string())
}

fn requested_optional_id_header<'a>(
    headers: &'a HeaderMap,
    header: &'static str,
) -> Result<Option<&'a str>, String> {
    let Some(value) = headers.get(header) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| format!("{header} must be valid visible ASCII/UTF-8 header text"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        return Err(format!("{header} must be at most 128 characters"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return Err(format!(
            "{header} may only contain letters, numbers, _, -, ., or :"
        ));
    }
    Ok(Some(value))
}

fn requested_optional_u32_header(
    headers: &HeaderMap,
    header: &'static str,
) -> Result<Option<u32>, String> {
    let Some(value) = headers.get(header) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| format!("{header} must be valid visible ASCII/UTF-8 header text"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{header} must be an unsigned integer"))?;
    if parsed == 0 {
        return Err(format!("{header} must be greater than zero"));
    }
    Ok(Some(parsed))
}

fn agent_workflow_use(
    state: &AppState,
    headers: &HeaderMap,
    auth: &AuthContext,
    run_id: &str,
    request: &AgentRunCreateRequest,
) -> Result<Option<AgentWorkflowUse>, (StatusCode, &'static str, String)> {
    let workflow_id = requested_optional_id_header(headers, WORKFLOW_ID_HEADER)
        .map_err(|message| (StatusCode::BAD_REQUEST, "invalid_workflow_header", message))?;
    let workflow_version = requested_optional_u32_header(headers, WORKFLOW_VERSION_HEADER)
        .map_err(|message| (StatusCode::BAD_REQUEST, "invalid_workflow_header", message))?;
    let workflow_node_id = requested_optional_id_header(headers, WORKFLOW_NODE_ID_HEADER)
        .map_err(|message| (StatusCode::BAD_REQUEST, "invalid_workflow_header", message))?;

    if workflow_id.is_none() && (workflow_version.is_some() || workflow_node_id.is_some()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid_workflow_header",
            format!(
                "{WORKFLOW_ID_HEADER} is required when workflow version or node headers are set"
            ),
        ));
    }
    let Some(workflow_id) = workflow_id else {
        return Ok(None);
    };
    let Some(workflow) = crate::state::select_agent_workflow(
        &state.config.agent_workflows,
        workflow_id,
        workflow_version,
    ) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "workflow_not_found",
            match workflow_version {
                Some(version) => format!("agent workflow {workflow_id}@{version} was not found"),
                None => format!("agent workflow {workflow_id} was not found"),
            },
        ));
    };
    if !workflow.enabled {
        return Err((
            StatusCode::FORBIDDEN,
            "workflow_disabled",
            format!(
                "agent workflow {}@{} is disabled",
                workflow.id, workflow.version
            ),
        ));
    }
    if !can_use_workflow(auth, workflow) {
        return Err((
            StatusCode::FORBIDDEN,
            "workflow_not_allowed",
            format!(
                "API key or tenant is not allowed to use agent workflow {}@{}",
                workflow.id, workflow.version
            ),
        ));
    }
    let Some(node_id) = workflow_node_id else {
        return Err((
            StatusCode::BAD_REQUEST,
            "workflow_node_required",
            format!("{WORKFLOW_NODE_ID_HEADER} is required when {WORKFLOW_ID_HEADER} is set"),
        ));
    };
    let Some(node) = workflow.nodes.iter().find(|node| node.id == node_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "workflow_node_not_found",
            format!(
                "agent workflow {}@{} does not contain node {}",
                workflow.id, workflow.version, node_id
            ),
        ));
    };
    if !request.tool_calls.is_empty() {
        if node.kind != AgentWorkflowNodeKind::Tool {
            return Err((
                StatusCode::FORBIDDEN,
                "workflow_node_not_tool",
                format!("workflow node {node_id} is not allowed to dispatch tool traffic"),
            ));
        }
        if let Some(tool) = node.tool.as_deref() {
            if request.tool_calls.iter().any(|call| call.name != tool) {
                return Err((
                    StatusCode::FORBIDDEN,
                    "workflow_tool_not_allowed",
                    format!("workflow node {node_id} is not allowed to use requested tool"),
                ));
            }
        }
    }
    if let Some(message) = state.workflow_edge_transition_error(workflow, run_id, node_id) {
        return Err((StatusCode::FORBIDDEN, "workflow_edge_not_allowed", message));
    }
    if workflow.max_parallelism.is_some_and(|limit| {
        request.tool_calls.len() > 1 && request.tool_calls.len() as u32 > limit
    }) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "workflow_parallelism_limit_exceeded",
            format!(
                "agent workflow {}@{} declared {} tool call(s), exceeding configured parallelism limit",
                workflow.id,
                workflow.version,
                request.tool_calls.len()
            ),
        ));
    }
    if workflow
        .max_tool_calls
        .is_some_and(|limit| request.tool_calls.len() as u32 > limit)
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "workflow_tool_call_limit_exceeded",
            format!(
                "agent workflow {}@{} tool call limit is exhausted",
                workflow.id, workflow.version
            ),
        ));
    }
    let required_turns = request.tool_calls.len().saturating_add(1) as u32;
    if workflow
        .max_iterations
        .or(node.max_iterations)
        .is_some_and(|limit| required_turns > limit)
    {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "workflow_iteration_limit_exceeded",
            format!(
                "agent workflow {}@{} requires {} turn(s), exceeding configured iteration limit",
                workflow.id, workflow.version, required_turns
            ),
        ));
    }
    if let Some(timeout_millis) = workflow.timeout_millis {
        if let Some(started_at_unix) =
            state.workflow_run_started_at(&workflow.id, workflow.version, run_id)
        {
            let elapsed_millis = now_unix_seconds()
                .saturating_sub(started_at_unix)
                .saturating_mul(1_000);
            if elapsed_millis > timeout_millis {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "workflow_timeout_exceeded",
                    format!(
                        "agent workflow {}@{} elapsed time exceeded configured timeout",
                        workflow.id, workflow.version
                    ),
                ));
            }
        }
    }
    Ok(Some(AgentWorkflowUse {
        id: workflow.id.clone(),
        version: workflow.version,
        node_id: node_id.to_string(),
        // Capture the node's declared tool restriction unconditionally (even
        // when `request.tool_calls` is empty) so the dispatcher can enforce it
        // against the tool that is actually dispatched at runtime.
        node_tool: node.tool.clone(),
    }))
}

/// Fail-closed enforcement of a workflow node's declared tool allowlist against
/// the tool that is ACTUALLY dispatched, rather than the caller-declared
/// `tool_calls` metadata.
///
/// Returns `Some(denial_message)` when the dispatch is bound to a workflow node
/// (`workflow_use` present) that restricts execution to a specific tool
/// (`node_tool` is `Some`) and the dispatched tool name differs. Non-workflow
/// dispatches (`workflow_use` absent) and nodes without a declared tool
/// restriction (`node_tool` is `None`) are always allowed, preserving existing
/// behaviour.
fn workflow_node_tool_denial(
    workflow_use: Option<&AgentWorkflowUse>,
    dispatched_tool: &str,
) -> Option<String> {
    let workflow_use = workflow_use?;
    let node_tool = workflow_use.node_tool.as_deref()?;
    if dispatched_tool == node_tool {
        return None;
    }
    Some(format!(
        "scope_denied: workflow node {} is restricted to tool {node_tool}; dispatch of tool {dispatched_tool} is not allowed",
        workflow_use.node_id
    ))
}

fn can_use_workflow(auth: &AuthContext, workflow: &AgentWorkflowPolicy) -> bool {
    if !workflow.api_key_ids.is_empty()
        && !auth
            .api_key_id
            .as_deref()
            .is_some_and(|api_key_id| workflow.api_key_ids.iter().any(|id| id == api_key_id))
    {
        return false;
    }
    if !workflow.organization_ids.is_empty()
        && !auth
            .organization_id
            .as_deref()
            .is_some_and(|organization_id| {
                workflow
                    .organization_ids
                    .iter()
                    .any(|id| id == organization_id)
            })
    {
        return false;
    }
    if !workflow.project_ids.is_empty()
        && !auth
            .project_id
            .as_deref()
            .is_some_and(|project_id| workflow.project_ids.iter().any(|id| id == project_id))
    {
        return false;
    }
    true
}

fn harness_config(
    state: &AppState,
    request: &AgentRunCreateRequest,
) -> Result<AgentHarnessConfig, (&'static str, String)> {
    let max_turns = request
        .max_turns
        .unwrap_or(state.config.agent_runtime.max_turns);
    if max_turns == 0 || max_turns > state.config.agent_runtime.max_turns {
        return Err((
            "invalid_agent_run_max_turns",
            format!(
                "agent run max_turns must be between 1 and operator limit {}",
                state.config.agent_runtime.max_turns
            ),
        ));
    }
    let required_turns = request.tool_calls.len().saturating_add(1);
    if required_turns > max_turns as usize {
        return Err((
            "invalid_agent_run_max_turns",
            format!(
                "agent run max_turns must allow {} scripted tool call(s) plus one final turn",
                request.tool_calls.len()
            ),
        ));
    }
    let timeout_millis = request
        .timeout_millis
        .unwrap_or(state.config.agent_runtime.timeout_millis);
    if timeout_millis == 0 || timeout_millis > state.config.agent_runtime.timeout_millis {
        return Err((
            "invalid_agent_run_timeout",
            format!(
                "agent run timeout_millis must be between 1 and operator limit {}",
                state.config.agent_runtime.timeout_millis
            ),
        ));
    }
    Ok(AgentHarnessConfig {
        max_turns,
        timeout: Some(Duration::from_millis(timeout_millis)),
    })
}

fn agent_provider_name(config: &AgentRuntimeConfig) -> &'static str {
    match config.provider {
        AgentRuntimeProvider::ManagedWorker => "ferrogate.agent-worker",
        AgentRuntimeProvider::External => "ferrogate.external",
    }
}

struct AgentProviderContext {
    input: String,
}

fn agent_provider(
    config: &AgentRuntimeConfig,
    context: AgentProviderContext,
) -> Result<Box<dyn AgentProvider + Send>, (&'static str, String)> {
    match config.provider {
        AgentRuntimeProvider::ManagedWorker => Err((
            "agent_worker_transport_unavailable",
            "managed agent runtime requires the external agent-worker Firecracker microVM transport, which is not implemented yet".to_string(),
        )),
        AgentRuntimeProvider::External => external_agent_provider(&config.external, context.input)
            .map(|provider| Box::new(provider) as Box<dyn AgentProvider + Send>)
            .map_err(|error| ("invalid_agent_runtime_provider", error.to_string())),
    }
}

fn external_agent_provider(
    config: &AgentRuntimeExternalConfig,
    input: String,
) -> Result<ExternalAgentProvider, AgentRuntimeError> {
    let timeout = config.timeout_millis.map(Duration::from_millis);
    ExternalAgentProvider::with_input(
        ExternalAgentProviderConfig {
            command: config.command.clone(),
            args: config.args.clone(),
            timeout,
        },
        input,
    )
}

struct GatewayAgentToolDispatcher {
    gateway: FerroGateway,
    ctx: ProxyContext,
    auth: AuthContext,
    state: AppState,
    scripted_tool_calls: Vec<AgentRunToolCallRequest>,
    workflow_use: Option<AgentWorkflowUse>,
}

impl GatewayAgentToolDispatcher {
    fn new(
        gateway: FerroGateway,
        ctx: &ProxyContext,
        auth: AuthContext,
        scripted_tool_calls: Vec<AgentRunToolCallRequest>,
        workflow_use: Option<AgentWorkflowUse>,
    ) -> Self {
        let state = gateway.state.current();
        Self {
            gateway,
            ctx: ctx.clone(),
            auth,
            state,
            scripted_tool_calls,
            workflow_use,
        }
    }

    fn record_capability_event(
        &self,
        request: &AgentToolDispatchRequest<'_>,
        outcome: &'static str,
        message: impl Into<String>,
    ) {
        self.state.record_agent_run_event(stored_timeline_event(
            TimelineEventContext::new(
                self.ctx.request_id.clone(),
                self.ctx.trace_id.clone(),
                self.auth.tenant_context(),
                request.turn,
            ),
            TimelineEventRecord {
                id: format!(
                    "agent-capability:{}:{}:{}:{}:{}",
                    request.run_id,
                    request.turn,
                    CapabilityAction::Tool.as_str().replace('.', "_"),
                    outcome,
                    sanitize_timeline_id_part(&request.tool_call.id)
                ),
                run_id: request.run_id.to_string(),
                kind: format!("capability.{outcome}"),
                target: request.tool_call.name.clone(),
                outcome: outcome.to_string(),
                tool_call_id: Some(request.tool_call.id.clone()),
                message: Some(message.into()),
            },
        ));
    }
}

impl GovernedAgentToolDispatcher for GatewayAgentToolDispatcher {
    fn dispatch_tool(
        &mut self,
        request: AgentToolDispatchRequest<'_>,
    ) -> Result<ToolResult, AgentRuntimeError> {
        if !self.auth.has_scope("tools.execute") {
            self.record_capability_event(
                &request,
                "denied",
                "tool capability denied before dispatch: missing tools.execute scope",
            );
            return Err(AgentRuntimeError::ToolDispatch(
                "scope_denied: API key does not have required scope tools.execute".to_string(),
            ));
        }
        // Fail closed: a workflow node restricted to a specific tool must never
        // dispatch a different tool, regardless of what the caller declared in
        // `tool_calls` (which may be empty or mismatched vs. the model's actual
        // tool call). This is the authoritative allowlist gate.
        if let Some(message) =
            workflow_node_tool_denial(self.workflow_use.as_ref(), &request.tool_call.name)
        {
            self.record_capability_event(&request, "denied", message.clone());
            return Err(AgentRuntimeError::ToolDispatch(message));
        }
        let scripted = self
            .scripted_tool_calls
            .get(request.turn.saturating_sub(1) as usize)
            .filter(|tool_call| tool_call.name == request.tool_call.name);
        let tool_request = ToolExecutionRequest {
            name: request.tool_call.name.clone(),
            arguments: scripted
                .map(|tool_call| tool_call.arguments.clone())
                .unwrap_or_else(|| request.tool_call.arguments.clone()),
            route: scripted.and_then(|tool_call| tool_call.route.clone()),
            session_id: scripted
                .and_then(|tool_call| tool_call.session_id.clone())
                .or_else(|| Some(format!("agent_run:{}", request.run_id))),
        };
        let tool_name = tool_request.name.clone();
        if self
            .state
            .tool_by_name(&tool_name)
            .is_some_and(|tool| tool.approval_policy == ferrogate_core::ApprovalPolicy::Always)
        {
            self.record_capability_event(
                &request,
                "requested",
                format!(
                    "tool capability requires approval before gateway-mediated dispatch: {tool_name}"
                ),
            );
        }
        let response =
            match block_on_agent_tool_dispatch(self.gateway.execute_tool_request_with_governance(
                &self.ctx,
                &self.auth,
                tool_execution_context(request.run_id, self.workflow_use.as_ref()),
                tool_request,
                ToolExecuteBackend::Extension,
            )) {
                Ok(response) => response,
                Err(error) => {
                    self.record_capability_event(
                        &request,
                        "denied",
                        format!(
                            "tool capability failed in gateway-mediated governance: {}: {}",
                            error.code, error.message
                        ),
                    );
                    return Err(tool_dispatch_error(error));
                }
            };
        self.record_capability_event(
            &request,
            "allowed",
            format!("tool capability routed through gateway-mediated governance: {tool_name}"),
        );
        Ok(ToolResult {
            tool_call_id: request.tool_call.id.clone(),
            content: response.content,
            is_error: response.is_error,
        })
    }
}

fn block_on_agent_tool_dispatch<T>(future: impl std::future::Future<Output = T> + Send) -> T
where
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| handle.block_on(future));
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("agent tool dispatch runtime should build")
                    .block_on(future)
            })
            .join()
            .expect("agent tool dispatch runtime thread should not panic")
    })
}

fn tool_dispatch_error(error: ToolExecutionHttpError) -> AgentRuntimeError {
    AgentRuntimeError::ToolDispatch(format!("{}: {}", error.code, error.message))
}

fn tool_execution_context<'a>(
    run_id: &'a str,
    workflow_use: Option<&'a AgentWorkflowUse>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        agent_run_id: Some(run_id),
        workflow_id: workflow_use.map(|workflow| workflow.id.as_str()),
        workflow_version: workflow_use.map(|workflow| workflow.version),
        workflow_node_id: workflow_use.map(|workflow| workflow.node_id.as_str()),
        skill_package_id: None,
        skill_package_version: None,
        mcp_original_bearer: None,
    }
}

struct AuditEventSink {
    state: AppState,
    request_id: String,
    trace_id: Option<String>,
    actor_api_key_id: Option<String>,
    tenant: ferrogate_core::TenantContext,
    workflow_use: Option<AgentWorkflowUse>,
}

impl AuditEventSink {
    fn new(
        state: AppState,
        ctx: &ProxyContext,
        auth: &AuthContext,
        workflow_use: Option<AgentWorkflowUse>,
    ) -> Self {
        Self {
            state,
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            actor_api_key_id: auth.api_key_id.clone(),
            tenant: auth.tenant_context(),
            workflow_use,
        }
    }

    #[allow(dead_code)]
    fn record_framework_event(&self, event: NormalizedFrameworkEvent) -> Result<(), String> {
        let record = event.timeline_record().map_err(|error| error.to_string())?;
        self.state.record_agent_run_event(stored_timeline_event(
            TimelineEventContext::new(
                self.request_id.clone(),
                self.trace_id.clone(),
                self.tenant.clone(),
                0,
            ),
            TimelineEventRecord {
                id: record.event_id,
                run_id: record.run_id,
                kind: record.kind,
                target: record.target,
                outcome: record.outcome,
                tool_call_id: None,
                message: record.message,
            },
        ));
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TimelineEventContext {
    request_id: String,
    trace_id: Option<String>,
    tenant: ferrogate_core::TenantContext,
    turn: u32,
    occurred_at_unix: Option<u64>,
}

impl TimelineEventContext {
    fn new(
        request_id: impl Into<String>,
        trace_id: Option<String>,
        tenant: ferrogate_core::TenantContext,
        turn: u32,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            trace_id,
            tenant,
            turn,
            occurred_at_unix: Some(now_unix_seconds()),
        }
    }
}

#[derive(Debug, Clone)]
struct TimelineEventRecord {
    id: String,
    run_id: String,
    kind: String,
    target: String,
    outcome: String,
    tool_call_id: Option<String>,
    message: Option<String>,
}

fn stored_timeline_event(
    context: TimelineEventContext,
    record: TimelineEventRecord,
) -> StoredAgentRunEvent {
    StoredAgentRunEvent {
        id: record.id,
        run_id: record.run_id,
        request_id: context.request_id,
        trace_id: context.trace_id,
        tenant: context.tenant,
        turn: context.turn,
        kind: record.kind,
        target: record.target,
        outcome: record.outcome,
        tool_call_id: record.tool_call_id,
        message: record.message,
        occurred_at_unix: context.occurred_at_unix,
    }
}

fn sanitize_timeline_id_part(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

impl AgentRunEventSink for AuditEventSink {
    fn record(&mut self, event: AgentRunEvent) {
        let (action, outcome) = match event.kind {
            AgentRunEventKind::RunStarted => ("agent.run_started", "started"),
            AgentRunEventKind::TurnStarted => ("agent.turn_started", "started"),
            AgentRunEventKind::ToolCallRequested => ("agent.tool_call_requested", "pending"),
            AgentRunEventKind::ToolCallCompleted => ("agent.tool_call_completed", "success"),
            AgentRunEventKind::RunCompleted => ("agent.run_completed", "success"),
            AgentRunEventKind::RunStopped => ("agent.run_stopped", "stopped"),
        };
        let target = event
            .tool_call_id
            .as_deref()
            .map(|tool_call_id| format!("agent_run:{}/tool_call:{tool_call_id}", event.run_id))
            .unwrap_or_else(|| format!("agent_run:{}", event.run_id));
        let message = event.message.unwrap_or_else(|| {
            format!(
                "agent event {} turn {}",
                agent_event_kind(&event.kind),
                event.turn
            )
        });
        self.state.record_agent_run_event(stored_timeline_event(
            TimelineEventContext::new(
                self.request_id.clone(),
                self.trace_id.clone(),
                self.tenant.clone(),
                event.turn,
            ),
            TimelineEventRecord {
                id: event.id,
                run_id: event.run_id.clone(),
                kind: agent_event_kind(&event.kind).to_string(),
                target: target.clone(),
                outcome: outcome.to_string(),
                tool_call_id: event.tool_call_id,
                message: Some(message.clone()),
            },
        ));
        self.state.record_admin_audit_event(AdminAuditEventDraft {
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            agent_run_id: Some(event.run_id),
            workflow_id: self
                .workflow_use
                .as_ref()
                .map(|workflow| workflow.id.clone()),
            workflow_version: self.workflow_use.as_ref().map(|workflow| workflow.version),
            workflow_node_id: self
                .workflow_use
                .as_ref()
                .map(|workflow| workflow.node_id.clone()),
            actor_api_key_id: self.actor_api_key_id.clone(),
            tenant: self.tenant.clone(),
            action: action.to_string(),
            target,
            outcome: outcome.to_string(),
            message,
        });
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

struct AgentAuditEventContext<'a> {
    ctx: &'a ProxyContext,
    auth: &'a AuthContext,
    agent_run_id: Option<String>,
    workflow_use: Option<&'a AgentWorkflowUse>,
    action: &'a str,
    target: &'a str,
    outcome: &'a str,
    message: String,
}

fn agent_audit_event(context: AgentAuditEventContext<'_>) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        request_id: context.ctx.request_id.clone(),
        trace_id: context.ctx.trace_id.clone(),
        agent_run_id: context.agent_run_id,
        workflow_id: context.workflow_use.map(|workflow| workflow.id.clone()),
        workflow_version: context.workflow_use.map(|workflow| workflow.version),
        workflow_node_id: context
            .workflow_use
            .map(|workflow| workflow.node_id.clone()),
        actor_api_key_id: context.auth.api_key_id.clone(),
        tenant: context.auth.tenant_context(),
        action: context.action.into(),
        target: context.target.into(),
        outcome: context.outcome.into(),
        message: context.message,
    }
}

fn outcome_status_code(outcome: &AgentRunOutcome) -> StatusCode {
    match outcome.status {
        AgentRunStatus::Completed => StatusCode::CREATED,
        AgentRunStatus::MaxTurnsExceeded | AgentRunStatus::Cancelled | AgentRunStatus::TimedOut => {
            StatusCode::ACCEPTED
        }
        AgentRunStatus::Failed => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn agent_status(status: &AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Completed => "completed",
        AgentRunStatus::MaxTurnsExceeded => "max_turns_exceeded",
        AgentRunStatus::Cancelled => "cancelled",
        AgentRunStatus::TimedOut => "timed_out",
        AgentRunStatus::Failed => "failed",
    }
}

fn agent_event_kind(kind: &AgentRunEventKind) -> &'static str {
    match kind {
        AgentRunEventKind::RunStarted => "run_started",
        AgentRunEventKind::TurnStarted => "turn_started",
        AgentRunEventKind::ToolCallRequested => "tool_call_requested",
        AgentRunEventKind::ToolCallCompleted => "tool_call_completed",
        AgentRunEventKind::RunCompleted => "run_completed",
        AgentRunEventKind::RunStopped => "run_stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_core::TenantContext;
    use ferrogate_runtime::{
        authorize_framework_capability, CapabilityAction, FrameworkAdapter,
        FrameworkAdapterCapabilities, FrameworkAdapterMode, FrameworkAdapterSessionRequest,
        FrameworkCapabilityRequest, NativeHarnessAdapter, SimpleCapabilityAuthorizer,
    };

    #[test]
    fn managed_framework_capability_event_converts_to_stored_timeline_event() {
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter
            .start_session(FrameworkAdapterSessionRequest {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "worker-1".to_string(),
                isolation_backend: "firecracker".to_string(),
                mode: FrameworkAdapterMode::Managed,
                required_capabilities: FrameworkAdapterCapabilities {
                    tools: true,
                    ..FrameworkAdapterCapabilities::default()
                },
            })
            .unwrap();
        let (_, event) = authorize_framework_capability(
            &SimpleCapabilityAuthorizer::default(),
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Cli,
                target: "bash".to_string(),
                canonical_target: None,
                high_risk: false,
            },
        )
        .unwrap();
        let record = event.timeline_record().unwrap();
        let mut context = TimelineEventContext::new(
            "fg-1",
            Some("trace-1".to_string()),
            TenantContext {
                workspace_id: None,
                organization_id: Some("org".to_string()),
                team_id: None,
                project_id: Some("project".to_string()),
                user_id: None,
                api_key_id: Some("key".to_string()),
            },
            0,
        );
        context.occurred_at_unix = Some(42);
        let stored = stored_timeline_event(
            context,
            TimelineEventRecord {
                id: record.event_id,
                run_id: record.run_id,
                kind: record.kind,
                target: record.target,
                outcome: record.outcome,
                tool_call_id: None,
                message: record.message,
            },
        );

        assert!(stored
            .id
            .starts_with("framework:run-1:session-1:native-harness:capability.denied:"));
        assert_eq!(stored.run_id, "run-1");
        assert_eq!(stored.request_id, "fg-1");
        assert_eq!(stored.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(stored.kind, "capability.denied");
        assert_eq!(stored.target, "bash");
        assert_eq!(stored.outcome, "denied");
        assert_eq!(stored.turn, 0);
        assert_eq!(stored.occurred_at_unix, Some(42));
        assert!(stored
            .message
            .as_deref()
            .unwrap()
            .contains("not allowed by capability policy"));
    }

    #[test]
    fn audit_sink_records_managed_framework_capability_event_into_timeline() {
        let state = AppState::new(crate::config::Config::default());
        let sink = AuditEventSink {
            state: state.clone(),
            request_id: "fg-1".to_string(),
            trace_id: Some("trace-1".to_string()),
            actor_api_key_id: Some("key".to_string()),
            tenant: TenantContext {
                workspace_id: None,
                organization_id: Some("tenant-1".to_string()),
                team_id: None,
                project_id: Some("workspace-1".to_string()),
                user_id: None,
                api_key_id: Some("key".to_string()),
            },
            workflow_use: None,
        };
        let mut adapter = NativeHarnessAdapter::default();
        let (session, _) = adapter
            .start_session(FrameworkAdapterSessionRequest {
                session_id: "session-1".to_string(),
                run_id: "run-1".to_string(),
                tenant_id: "tenant-1".to_string(),
                workspace_id: "workspace-1".to_string(),
                worker_id: "agent-worker-1".to_string(),
                isolation_backend: "firecracker".to_string(),
                mode: FrameworkAdapterMode::Managed,
                required_capabilities: FrameworkAdapterCapabilities {
                    tools: true,
                    ..FrameworkAdapterCapabilities::default()
                },
            })
            .unwrap();
        let (_, event) = authorize_framework_capability(
            &SimpleCapabilityAuthorizer::default(),
            FrameworkCapabilityRequest {
                session,
                action: CapabilityAction::Cli,
                target: "bash".to_string(),
                canonical_target: None,
                high_risk: false,
            },
        )
        .unwrap();

        sink.record_framework_event(event).unwrap();

        let timeline = state
            .agent_run_timeline("run-1", crate::state::AgentRunFilter::default())
            .expect("framework event should create a run timeline");
        assert_eq!(timeline.agent_events.len(), 1);
        let stored = &timeline.agent_events[0];
        assert!(stored
            .id
            .starts_with("framework:run-1:session-1:native-harness:capability.denied:"));
        assert_eq!(stored.request_id, "fg-1");
        assert_eq!(stored.trace_id.as_deref(), Some("trace-1"));
        assert_eq!(stored.tenant.organization_id.as_deref(), Some("tenant-1"));
        assert_eq!(stored.tenant.project_id.as_deref(), Some("workspace-1"));
        assert_eq!(stored.kind, "capability.denied");
        assert_eq!(stored.target, "bash");
        assert_eq!(stored.outcome, "denied");
        assert!(stored
            .message
            .as_deref()
            .unwrap()
            .contains("not allowed by capability policy"));
    }

    fn workflow_use_with_tool(node_tool: Option<&str>) -> AgentWorkflowUse {
        AgentWorkflowUse {
            id: "wf-tool-guard".to_string(),
            version: 1,
            node_id: "node-tool".to_string(),
            node_tool: node_tool.map(str::to_string),
        }
    }

    #[test]
    fn workflow_node_tool_allowlist_is_enforced_against_the_dispatched_tool() {
        let restricted = workflow_use_with_tool(Some("allowed_tool"));

        // The declared allowlist tool is permitted.
        assert!(
            workflow_node_tool_denial(Some(&restricted), "allowed_tool").is_none(),
            "the tool the node is restricted to must be allowed to dispatch"
        );

        // A DIFFERENT tool than the node's declared allowlist must fail closed,
        // even though the caller-declared tool_calls check may have passed (or
        // been empty). This is the authorization-bypass fix.
        let denial = workflow_node_tool_denial(Some(&restricted), "other_tool")
            .expect("dispatching a tool other than the node's restricted tool must be denied");
        assert!(
            denial.starts_with("scope_denied:"),
            "denial must be a fail-closed scope_denied message, got: {denial}"
        );
        assert!(
            denial.contains("allowed_tool") && denial.contains("other_tool"),
            "denial must name both the restricted tool and the rejected tool, got: {denial}"
        );
    }

    #[test]
    fn workflow_node_tool_denial_ignores_non_workflow_and_unrestricted_nodes() {
        // Non-workflow dispatch (no workflow_use) is unaffected.
        assert!(
            workflow_node_tool_denial(None, "any_tool").is_none(),
            "non-workflow dispatches must not be gated by node.tool"
        );

        // A workflow node without a declared tool restriction is unaffected.
        let unrestricted = workflow_use_with_tool(None);
        assert!(
            workflow_node_tool_denial(Some(&unrestricted), "any_tool").is_none(),
            "nodes without a declared tool restriction must allow any dispatched tool"
        );
    }
}
