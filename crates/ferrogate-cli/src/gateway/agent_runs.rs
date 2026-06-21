// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ferrogate_core::{RequestContext, ToolCall, ToolResult};
use ferrogate_runtime::{
    AgentContext, AgentHarness, AgentHarnessConfig, AgentProvider, AgentRunEvent,
    AgentRunEventKind, AgentRunEventSink, AgentRunInput, AgentRunOutcome, AgentRunStatus,
    AgentRuntimeError, AgentStep, AgentToolDispatchRequest, ExternalAgentProvider,
    ExternalAgentProviderConfig, GovernedAgentToolDispatcher, WasmHostAbi, WasmSandboxConfig,
    WasmSandboxExecutor,
};
use http::{HeaderMap, Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    auth::{authenticate, AuthContext},
    config::{
        AgentRuntimeConfig, AgentRuntimeExternalConfig, AgentRuntimeProvider,
        AgentRuntimeWasmConfig,
    },
    extensions::ToolExecutionRequest,
    responses::{write_json_error, write_json_error_and_close, write_json_response},
    state::{AdminAuditEventDraft, AppState},
};
use ferrogate_storage::{StoredAgentRun, StoredAgentRunEvent};

use super::{
    body::read_request_body,
    local::{ToolExecuteBackend, ToolExecutionHttpError},
    FerroGateway, ProxyContext,
};

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
                format!("agent tool call name must not be empty: {:?}", tool_call),
                &ctx.request_id,
            )
            .await;
        }

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
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
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
            request.input,
            tool_calls.clone(),
            self.clone(),
            ctx,
            auth.clone(),
            run_id.clone(),
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
        let mut dispatcher =
            GatewayAgentToolDispatcher::new(self.clone(), ctx, auth.clone(), tool_calls);
        let mut event_sink = AuditEventSink::new(state.clone(), ctx, &auth);
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
        AgentRuntimeProvider::Wasm if config.wasm.module_path.is_some() => "ferrogate.wasm",
        AgentRuntimeProvider::Wasm => "ferrogate.default",
        AgentRuntimeProvider::External => "ferrogate.external",
    }
}

fn agent_provider(
    config: &AgentRuntimeConfig,
    input: String,
    tool_calls: Vec<AgentRunToolCallRequest>,
    gateway: FerroGateway,
    ctx: &ProxyContext,
    auth: AuthContext,
    run_id: String,
) -> Result<Box<dyn AgentProvider + Send>, (&'static str, String)> {
    match config.provider {
        AgentRuntimeProvider::Wasm if config.wasm.module_path.is_some() => wasm_agent_provider(
            &config.wasm,
            input,
            config.timeout_millis,
            gateway,
            ctx,
            auth,
            run_id,
            tool_calls,
        )
        .map(|provider| Box::new(provider) as Box<dyn AgentProvider + Send>)
        .map_err(|error| ("invalid_agent_runtime_provider", error.to_string())),
        AgentRuntimeProvider::Wasm => Ok(Box::new(DefaultAgentProvider::new(input, tool_calls))),
        AgentRuntimeProvider::External => external_agent_provider(&config.external, input)
            .map(|provider| Box::new(provider) as Box<dyn AgentProvider + Send>)
            .map_err(|error| ("invalid_agent_runtime_provider", error.to_string())),
    }
}

fn wasm_agent_provider(
    config: &AgentRuntimeWasmConfig,
    input: String,
    timeout_millis: u64,
    gateway: FerroGateway,
    ctx: &ProxyContext,
    auth: AuthContext,
    run_id: String,
    tool_calls: Vec<AgentRunToolCallRequest>,
) -> Result<WasmAgentProvider, AgentRuntimeError> {
    let module_path = config.module_path.clone().ok_or_else(|| {
        AgentRuntimeError::InvalidConfig("agent_runtime.wasm.module_path is required".into())
    })?;
    let host = config
        .host_abi
        .then(|| WasmAgentHost::new(gateway, ctx, auth, run_id, tool_calls));
    WasmAgentProvider::new(
        module_path,
        config.export_name.clone(),
        config.max_fuel,
        timeout_millis,
        input,
        host,
    )
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

struct DefaultAgentProvider {
    output: Option<String>,
    tool_calls: Vec<AgentRunToolCallRequest>,
    next_tool_call: usize,
}

impl DefaultAgentProvider {
    fn new(input: String, tool_calls: Vec<AgentRunToolCallRequest>) -> Self {
        Self {
            output: Some(input),
            tool_calls,
            next_tool_call: 0,
        }
    }
}

impl AgentProvider for DefaultAgentProvider {
    fn next_step(&mut self, context: &AgentContext<'_>) -> Result<AgentStep, AgentRuntimeError> {
        if let Some(tool_call) = self.tool_calls.get(self.next_tool_call).cloned() {
            self.next_tool_call += 1;
            return Ok(AgentStep::ToolCall(ToolCall {
                id: format!("{}:tool-call-{}", context.run_id, self.next_tool_call),
                name: tool_call.name,
                arguments: tool_call.arguments,
            }));
        }
        let output = self.output.take().unwrap_or_else(|| {
            format!(
                "agent run completed after {} governed tool result(s)",
                context.tool_results.len()
            )
        });
        Ok(AgentStep::Finish { output })
    }
}

struct WasmAgentProvider {
    module_path: String,
    export_name: String,
    max_fuel: u64,
    timeout: Option<Duration>,
    pending: bool,
    host: Option<WasmAgentHost>,
}

impl WasmAgentProvider {
    fn new(
        module_path: String,
        export_name: String,
        max_fuel: u64,
        timeout_millis: u64,
        _input: String,
        host: Option<WasmAgentHost>,
    ) -> Result<Self, AgentRuntimeError> {
        if module_path.trim().is_empty() {
            return Err(AgentRuntimeError::InvalidConfig(
                "agent_runtime.wasm.module_path is required".into(),
            ));
        }
        if export_name.trim().is_empty() {
            return Err(AgentRuntimeError::InvalidConfig(
                "agent_runtime.wasm.export_name must not be empty".into(),
            ));
        }
        Ok(Self {
            module_path,
            export_name,
            max_fuel,
            timeout: Some(Duration::from_millis(timeout_millis)),
            pending: true,
            host,
        })
    }
}

impl AgentProvider for WasmAgentProvider {
    fn next_step(&mut self, _context: &AgentContext<'_>) -> Result<AgentStep, AgentRuntimeError> {
        if !self.pending {
            return Ok(AgentStep::Continue);
        }
        self.pending = false;
        let module = std::fs::read(&self.module_path).map_err(|error| {
            AgentRuntimeError::Provider(format!(
                "failed to read WASM agent module {}: {error}",
                self.module_path
            ))
        })?;
        let executor = WasmSandboxExecutor::new(WasmSandboxConfig {
            max_fuel: self.max_fuel,
            timeout: self.timeout,
        })
        .map_err(|error| AgentRuntimeError::Provider(error.to_string()))?;
        let outcome = match self.host.take() {
            Some(host) => {
                let run = executor
                    .execute_export_i32_with_host(&module, &self.export_name, host)
                    .map_err(|error| AgentRuntimeError::Provider(error.to_string()))?;
                self.host = Some(run.host);
                run.outcome
            }
            None => executor
                .execute_export_i32(&module, &self.export_name)
                .map_err(|error| AgentRuntimeError::Provider(error.to_string()))?,
        };
        Ok(AgentStep::Finish {
            output: format!("wasm:{} result={}", outcome.export_name, outcome.result),
        })
    }
}

struct WasmAgentHost {
    gateway: FerroGateway,
    ctx: ProxyContext,
    auth: AuthContext,
    run_id: String,
    state: BTreeMap<i32, i32>,
    tool_calls: Vec<AgentRunToolCallRequest>,
}

impl WasmAgentHost {
    fn new(
        gateway: FerroGateway,
        ctx: &ProxyContext,
        auth: AuthContext,
        run_id: String,
        tool_calls: Vec<AgentRunToolCallRequest>,
    ) -> Self {
        Self {
            gateway,
            ctx: ctx.clone(),
            auth,
            run_id,
            state: BTreeMap::new(),
            tool_calls,
        }
    }

    fn record(&self, action: &str, target: String, outcome: &str, message: String) {
        self.gateway
            .state
            .current()
            .record_admin_audit_event(agent_audit_event(
                &self.ctx,
                &self.auth,
                Some(self.run_id.clone()),
                action,
                target,
                outcome,
                message,
            ));
    }
}

impl WasmHostAbi for WasmAgentHost {
    fn log(&mut self, code: i32) {
        self.record(
            "agent.wasm.log",
            format!("agent_run:{}", self.run_id),
            "recorded",
            format!("wasm log code={code}"),
        );
    }

    fn state_get(&mut self, key: i32) -> i32 {
        let value = self.state.get(&key).copied().unwrap_or_default();
        self.record(
            "agent.wasm.state_get",
            format!("agent_run:{}/state:{key}", self.run_id),
            "success",
            format!("wasm state get key={key} value={value}"),
        );
        value
    }

    fn state_set(&mut self, key: i32, value: i32) -> i32 {
        self.state.insert(key, value);
        self.record(
            "agent.wasm.state_set",
            format!("agent_run:{}/state:{key}", self.run_id),
            "success",
            format!("wasm state set key={key} value={value}"),
        );
        0
    }

    fn tool_dispatch(&mut self, tool_handle: i32) -> i32 {
        if tool_handle <= 0 {
            self.record(
                "agent.wasm.tool_dispatch",
                format!("agent_run:{}/tool_handle:{tool_handle}", self.run_id),
                "error",
                format!("invalid wasm tool handle {tool_handle}"),
            );
            return -1;
        }
        let Some(tool_call) = self.tool_calls.get((tool_handle - 1) as usize).cloned() else {
            self.record(
                "agent.wasm.tool_dispatch",
                format!("agent_run:{}/tool_handle:{tool_handle}", self.run_id),
                "error",
                format!("wasm tool handle {tool_handle} is not mapped"),
            );
            return -1;
        };
        let tool_request = ToolExecutionRequest {
            name: tool_call.name,
            arguments: tool_call.arguments,
            route: tool_call.route,
            session_id: tool_call
                .session_id
                .or_else(|| Some(format!("agent_run:{}", self.run_id))),
        };
        match block_on_agent_tool_dispatch(self.gateway.execute_tool_request_with_governance(
            &self.ctx,
            &self.auth,
            Some(&self.run_id),
            tool_request,
            ToolExecuteBackend::Extension,
        )) {
            Ok(response) if !response.is_error => {
                self.record(
                    "agent.wasm.tool_dispatch",
                    format!("agent_run:{}/tool_handle:{tool_handle}", self.run_id),
                    "success",
                    format!("wasm tool handle {tool_handle} executed {}", response.name),
                );
                0
            }
            Ok(response) => {
                self.record(
                    "agent.wasm.tool_dispatch",
                    format!("agent_run:{}/tool_handle:{tool_handle}", self.run_id),
                    "error",
                    format!(
                        "wasm tool handle {tool_handle} returned tool error {}",
                        response.name
                    ),
                );
                -1
            }
            Err(error) => {
                self.record(
                    "agent.wasm.tool_dispatch",
                    format!("agent_run:{}/tool_handle:{tool_handle}", self.run_id),
                    "error",
                    format!("wasm tool handle {tool_handle} failed: {}", error.message),
                );
                -1
            }
        }
    }
}

struct GatewayAgentToolDispatcher {
    gateway: FerroGateway,
    ctx: ProxyContext,
    auth: AuthContext,
    scripted_tool_calls: Vec<AgentRunToolCallRequest>,
}

impl GatewayAgentToolDispatcher {
    fn new(
        gateway: FerroGateway,
        ctx: &ProxyContext,
        auth: AuthContext,
        scripted_tool_calls: Vec<AgentRunToolCallRequest>,
    ) -> Self {
        Self {
            gateway,
            ctx: ctx.clone(),
            auth,
            scripted_tool_calls,
        }
    }
}

impl GovernedAgentToolDispatcher for GatewayAgentToolDispatcher {
    fn dispatch_tool(
        &mut self,
        request: AgentToolDispatchRequest<'_>,
    ) -> Result<ToolResult, AgentRuntimeError> {
        if !self.auth.has_scope("tools.execute") {
            return Err(AgentRuntimeError::ToolDispatch(
                "scope_denied: API key does not have required scope tools.execute".to_string(),
            ));
        }
        let scripted = self
            .scripted_tool_calls
            .get(request.turn.saturating_sub(1) as usize);
        let tool_request = ToolExecutionRequest {
            name: request.tool_call.name.clone(),
            arguments: request.tool_call.arguments.clone(),
            route: scripted.and_then(|tool_call| tool_call.route.clone()),
            session_id: scripted
                .and_then(|tool_call| tool_call.session_id.clone())
                .or_else(|| Some(format!("agent_run:{}", request.run_id))),
        };
        let response =
            block_on_agent_tool_dispatch(self.gateway.execute_tool_request_with_governance(
                &self.ctx,
                &self.auth,
                Some(request.run_id),
                tool_request,
                ToolExecuteBackend::Extension,
            ))
            .map_err(tool_dispatch_error)?;
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
        self.state.record_agent_run_event(StoredAgentRunEvent {
            id: event.id,
            run_id: event.run_id.clone(),
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            tenant: self.tenant.clone(),
            turn: event.turn,
            kind: agent_event_kind(&event.kind).to_string(),
            target: target.clone(),
            outcome: outcome.to_string(),
            tool_call_id: event.tool_call_id,
            message: Some(message.clone()),
            occurred_at_unix: Some(now_unix_seconds()),
        });
        self.state.record_admin_audit_event(AdminAuditEventDraft {
            request_id: self.request_id.clone(),
            trace_id: self.trace_id.clone(),
            agent_run_id: Some(event.run_id),
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
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
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
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
