// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::time::Duration;

use ferrogate_core::{RequestContext, ToolResult};
use ferrogate_runtime::{
    AgentContext, AgentHarness, AgentHarnessConfig, AgentProvider, AgentRunEvent,
    AgentRunEventKind, AgentRunEventSink, AgentRunInput, AgentRunOutcome, AgentRunStatus,
    AgentRuntimeError, AgentStep, AgentToolDispatchRequest, GovernedAgentToolDispatcher,
};
use http::{HeaderMap, Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{authenticate, AuthContext},
    responses::{write_json_error, write_json_error_and_close, write_json_response},
    state::{AdminAuditEventDraft, AppState},
};

use super::{body::read_request_body, FerroGateway, ProxyContext};

const AGENT_RUN_ID_HEADER: &str = "x-ferrogate-agent-run-id";
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
            route: Some("agent.run".to_string()),
            upstream: None,
            tenant: auth.tenant_context(),
        };
        let mut provider = EchoAgentProvider::new(request.input);
        let mut dispatcher = FailClosedToolDispatcher;
        let mut event_sink = AuditEventSink::new(state.clone(), ctx, &auth);
        let outcome = match harness.run(
            AgentRunInput::new(request_context),
            &mut provider,
            &mut dispatcher,
            &mut event_sink,
        ) {
            Ok(outcome) => outcome,
            Err(AgentRuntimeError::RunFailed { outcome, .. }) => *outcome,
            Err(error) => {
                state.record_admin_audit_event(agent_audit_event(
                    ctx,
                    &auth,
                    Some(run_id),
                    "agent.run_failed",
                    "agent_run",
                    "error",
                    error.to_string(),
                ));
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

struct EchoAgentProvider {
    output: Option<String>,
}

impl EchoAgentProvider {
    fn new(input: String) -> Self {
        Self {
            output: Some(input),
        }
    }
}

impl AgentProvider for EchoAgentProvider {
    fn next_step(&mut self, _context: &AgentContext<'_>) -> Result<AgentStep, AgentRuntimeError> {
        Ok(match self.output.take() {
            Some(output) => AgentStep::Finish { output },
            None => AgentStep::Continue,
        })
    }
}

struct FailClosedToolDispatcher;

impl GovernedAgentToolDispatcher for FailClosedToolDispatcher {
    fn dispatch_tool(
        &mut self,
        request: AgentToolDispatchRequest<'_>,
    ) -> Result<ToolResult, AgentRuntimeError> {
        Err(AgentRuntimeError::ToolDispatch(format!(
            "agent run {} turn {} requested tool {}, but gateway tool dispatch bridge is not enabled",
            request.run_id, request.turn, request.tool_call.name
        )))
    }
}

struct AuditEventSink {
    state: AppState,
    request_id: String,
    trace_id: Option<String>,
    actor_api_key_id: Option<String>,
    tenant: ferrogate_core::TenantContext,
}

impl AuditEventSink {
    fn new(state: AppState, ctx: &ProxyContext, auth: &AuthContext) -> Self {
        Self {
            state,
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            actor_api_key_id: auth.api_key_id.clone(),
            tenant: auth.tenant_context(),
        }
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
        self.state.record_admin_audit_event(AdminAuditEventDraft {
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            agent_run_id: Some(event.run_id),
            actor_api_key_id: self.actor_api_key_id.clone(),
            tenant: self.tenant.clone(),
            action: action.to_string(),
            target,
            outcome: outcome.to_string(),
            message,
        });
    }
}

fn agent_audit_event(
    ctx: &ProxyContext,
    auth: &AuthContext,
    agent_run_id: Option<String>,
    action: impl Into<String>,
    target: impl Into<String>,
    outcome: impl Into<String>,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        agent_run_id,
        actor_api_key_id: auth.api_key_id.clone(),
        tenant: auth.tenant_context(),
        action: action.into(),
        target: target.into(),
        outcome: outcome.into(),
        message: message.into(),
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
