use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_core::{TenantContext, ToolDef};
use http::{StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{ExtensionConfig, ExtensionKind};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ExtensionStatus {
    pub(crate) id: String,
    pub(crate) kind: ExtensionKind,
    pub(crate) source: String,
    pub(crate) enabled: bool,
    pub(crate) active: bool,
    pub(crate) health: &'static str,
    pub(crate) order: u32,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct RegisteredTool {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) input_schema: Value,
    pub(crate) extension_id: String,
    pub(crate) tenant_allowlist: Vec<String>,
    pub(crate) api_key_allowlist: Vec<String>,
    pub(crate) route_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ToolExecutionRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) arguments: Value,
    #[serde(default)]
    pub(crate) route: Option<String>,
    #[serde(default)]
    pub(crate) session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(crate) struct ToolExecutionResponse {
    pub(crate) object: &'static str,
    pub(crate) name: String,
    pub(crate) content: Value,
    pub(crate) is_error: bool,
    pub(crate) request_id: String,
    pub(crate) session_id: Option<String>,
    pub(crate) latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolExecutionError {
    Denied(String),
    NotFound(String),
    Failed(String),
}

impl ToolExecutionError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Failed(_) => StatusCode::BAD_GATEWAY,
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Denied(_) => "tool_denied",
            Self::NotFound(_) => "tool_not_found",
            Self::Failed(_) => "tool_execution_failed",
        }
    }

    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Denied(message) | Self::NotFound(message) | Self::Failed(message) => message,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct GatewayEvent {
    pub(crate) request_id: String,
    pub(crate) tenant: TenantContext,
    pub(crate) extension_id: String,
    pub(crate) tool_name: Option<String>,
    pub(crate) status: String,
    pub(crate) latency_ms: u64,
    pub(crate) error_code: Option<String>,
    pub(crate) session_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExtensionRegistry {
    statuses: Arc<Mutex<Vec<ExtensionStatus>>>,
    tools: Arc<Vec<RegisteredTool>>,
    tool_providers: Arc<HashMap<String, ToolProvider>>,
    hooks: Arc<Vec<RequestHook>>,
    event_sinks: Arc<Vec<EventSink>>,
}

impl ExtensionRegistry {
    pub(crate) fn from_config(configs: &[ExtensionConfig]) -> Self {
        let mut statuses = Vec::new();
        let mut tools = Vec::new();
        let mut tool_providers = HashMap::new();
        let mut hooks = Vec::new();
        let mut event_sinks = Vec::new();

        let mut sorted: Vec<_> = configs.iter().collect();
        sorted.sort_by_key(|extension| extension.order);

        for extension in sorted {
            if !extension.enabled {
                statuses.push(status(extension, false, "disabled", None));
                continue;
            }

            match build_builtin_extension(extension) {
                Ok(BuiltinExtension::ToolProvider(provider)) => {
                    tools.extend(provider.tools());
                    tool_providers.insert(extension.id.clone(), provider);
                    statuses.push(status(extension, true, "ok", None));
                }
                Ok(BuiltinExtension::RequestHook(hook)) => {
                    hooks.push(hook);
                    statuses.push(status(extension, true, "ok", None));
                }
                Ok(BuiltinExtension::EventSink(sink)) => {
                    event_sinks.push(sink);
                    statuses.push(status(extension, true, "ok", None));
                }
                Err(error) => {
                    statuses.push(status(extension, false, "error", Some(error.to_string())));
                }
            }
        }

        Self {
            statuses: Arc::new(Mutex::new(statuses)),
            tools: Arc::new(tools),
            tool_providers: Arc::new(tool_providers),
            hooks: Arc::new(hooks),
            event_sinks: Arc::new(event_sinks),
        }
    }

    pub(crate) fn statuses(&self) -> Vec<ExtensionStatus> {
        self.statuses
            .lock()
            .map(|statuses| statuses.clone())
            .unwrap_or_default()
    }

    pub(crate) fn tools_for(
        &self,
        tenant: &TenantContext,
        api_key_id: Option<&str>,
        route: Option<&str>,
    ) -> Vec<RegisteredTool> {
        self.tools
            .iter()
            .filter(|tool| tool_visible(tool, tenant, api_key_id, route))
            .cloned()
            .collect()
    }

    pub(crate) fn all_tools(&self) -> Vec<RegisteredTool> {
        self.tools.as_ref().clone()
    }

    #[cfg(test)]
    fn captured_events(&self, sink_id: &str) -> Vec<GatewayEvent> {
        self.event_sinks
            .iter()
            .find(|sink| sink.id() == sink_id)
            .map(EventSink::events)
            .unwrap_or_default()
    }

    pub(crate) async fn execute_tool(
        &self,
        request: ToolExecutionRequest,
        request_id: String,
        tenant: TenantContext,
        api_key_id: Option<&str>,
    ) -> Result<ToolExecutionResponse, ToolExecutionError> {
        let Some(tool) = self.tools.iter().find(|tool| tool.name == request.name) else {
            let error =
                ToolExecutionError::NotFound(format!("tool {} is not registered", request.name));
            let _ = self.emit_tool_event(ToolEventDraft {
                request_id: request_id.clone(),
                tenant: tenant.clone(),
                extension_id: "tool_registry".into(),
                tool_name: Some(request.name.clone()),
                status: "error".into(),
                latency_ms: 0,
                error_code: Some(error.code().into()),
                session_id: request.session_id.clone(),
            });
            return Err(error);
        };
        if !tool_visible(tool, &tenant, api_key_id, request.route.as_deref()) {
            let error = ToolExecutionError::Denied(format!(
                "tool {} is not allowlisted for this tenant, API key, or route",
                request.name
            ));
            let _ = self.emit_tool_event(ToolEventDraft {
                request_id: request_id.clone(),
                tenant: tenant.clone(),
                extension_id: tool.extension_id.clone(),
                tool_name: Some(request.name.clone()),
                status: "error".into(),
                latency_ms: 0,
                error_code: Some(error.code().into()),
                session_id: request.session_id.clone(),
            });
            return Err(error);
        }

        for hook in self.hooks.iter() {
            if let Err(error) = hook.pre_tool_call(&request) {
                self.record_extension_error(hook.id(), error.message());
                if hook.blocking() {
                    let _ = self.emit_tool_event(ToolEventDraft {
                        request_id: request_id.clone(),
                        tenant: tenant.clone(),
                        extension_id: hook.id().into(),
                        tool_name: Some(request.name.clone()),
                        status: "error".into(),
                        latency_ms: 0,
                        error_code: Some(error.code().into()),
                        session_id: request.session_id.clone(),
                    });
                    return Err(error);
                }
            }
        }

        let started = Instant::now();
        let provider = self
            .tool_providers
            .get(&tool.extension_id)
            .ok_or_else(|| ToolExecutionError::Failed("tool provider is not active".into()))?;
        let content = match provider.execute(&request).await {
            Ok(content) => content,
            Err(error) => {
                self.record_extension_error(&tool.extension_id, error.message());
                let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                let _ = self.emit_tool_event(ToolEventDraft {
                    request_id: request_id.clone(),
                    tenant: tenant.clone(),
                    extension_id: tool.extension_id.clone(),
                    tool_name: Some(request.name.clone()),
                    status: "error".into(),
                    latency_ms,
                    error_code: Some(error.code().into()),
                    session_id: request.session_id.clone(),
                });
                return Err(error);
            }
        };
        let latency_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

        for hook in self.hooks.iter().rev() {
            if let Err(error) = hook.post_tool_call(&request) {
                self.record_extension_error(hook.id(), error.message());
                if hook.blocking() {
                    let _ = self.emit_tool_event(ToolEventDraft {
                        request_id: request_id.clone(),
                        tenant: tenant.clone(),
                        extension_id: hook.id().into(),
                        tool_name: Some(request.name.clone()),
                        status: "error".into(),
                        latency_ms,
                        error_code: Some(error.code().into()),
                        session_id: request.session_id.clone(),
                    });
                    return Err(error);
                }
            }
        }

        let response = ToolExecutionResponse {
            object: "tool_execution",
            name: request.name.clone(),
            content,
            is_error: false,
            request_id: request_id.clone(),
            session_id: request.session_id.clone(),
            latency_ms,
        };
        self.emit_tool_event(ToolEventDraft {
            request_id,
            tenant,
            extension_id: tool.extension_id.clone(),
            tool_name: Some(request.name),
            status: "success".into(),
            latency_ms,
            error_code: None,
            session_id: response.session_id.clone(),
        })?;
        Ok(response)
    }

    pub(crate) fn pre_request(
        &self,
        request_id: &str,
        path: &str,
    ) -> Result<(), ToolExecutionError> {
        for hook in self.hooks.iter() {
            if let Err(error) = hook.pre_request(request_id, path) {
                self.record_extension_error(hook.id(), error.message());
                if hook.blocking() {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn post_response(&self, request_id: &str, status: u16) {
        for hook in self.hooks.iter().rev() {
            if let Err(error) = hook.post_response(request_id, status) {
                self.record_extension_error(hook.id(), error.message());
            }
        }
    }

    pub(crate) fn emit(&self, event: GatewayEvent) -> Result<(), ToolExecutionError> {
        for sink in self.event_sinks.iter() {
            if let Err(error) = sink.emit(event.clone()) {
                self.record_extension_error(sink.id(), error.message());
                if sink.blocking() {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn record_extension_error(&self, extension_id: &str, message: &str) {
        if let Ok(mut statuses) = self.statuses.lock() {
            if let Some(status) = statuses.iter_mut().find(|status| status.id == extension_id) {
                status.health = "degraded";
                status.last_error = Some(message.to_string());
            }
        }
    }

    fn emit_tool_event(&self, draft: ToolEventDraft) -> Result<(), ToolExecutionError> {
        self.emit(GatewayEvent {
            request_id: draft.request_id,
            tenant: draft.tenant,
            extension_id: draft.extension_id,
            tool_name: draft.tool_name,
            status: draft.status,
            latency_ms: draft.latency_ms,
            error_code: draft.error_code,
            session_id: draft.session_id,
        })
    }
}

struct ToolEventDraft {
    request_id: String,
    tenant: TenantContext,
    extension_id: String,
    tool_name: Option<String>,
    status: String,
    latency_ms: u64,
    error_code: Option<String>,
    session_id: Option<String>,
}

fn status(
    extension: &ExtensionConfig,
    active: bool,
    health: &'static str,
    last_error: Option<String>,
) -> ExtensionStatus {
    ExtensionStatus {
        id: extension.id.clone(),
        kind: extension.kind.clone(),
        source: extension.source.clone(),
        enabled: extension.enabled,
        active,
        health,
        order: extension.order,
        last_error,
    }
}

enum BuiltinExtension {
    ToolProvider(ToolProvider),
    RequestHook(RequestHook),
    EventSink(EventSink),
}

fn build_builtin_extension(extension: &ExtensionConfig) -> AnyResult<BuiltinExtension> {
    match extension.kind {
        ExtensionKind::ToolProvider => {
            build_tool_provider(extension).map(BuiltinExtension::ToolProvider)
        }
        ExtensionKind::RequestHook => {
            if extension.id == "hook.noop" || extension.id.starts_with("hook.noop.") {
                Ok(BuiltinExtension::RequestHook(RequestHook::Noop(
                    HookConfig::from_extension(extension),
                )))
            } else {
                bail!("unsupported builtin request hook {}", extension.id)
            }
        }
        ExtensionKind::EventSink => match extension.id.as_str() {
            "event.audit_log" => Ok(BuiltinExtension::EventSink(EventSink::AuditLog(
                AuditLogSink {
                    id: extension.id.clone(),
                    blocking: bool_value(&extension.config, "blocking"),
                    fail_emit: bool_value(&extension.config, "fail_emit"),
                    events: Arc::new(Mutex::new(Vec::new())),
                },
            ))),
            _ => bail!("unsupported builtin event sink {}", extension.id),
        },
    }
}

fn build_tool_provider(extension: &ExtensionConfig) -> AnyResult<ToolProvider> {
    match extension.id.as_str() {
        "tool.echo" => Ok(ToolProvider::Echo(ToolProviderConfig::from_extension(
            extension,
        ))),
        "tool.health_check" => Ok(ToolProvider::HealthCheck(
            ToolProviderConfig::from_extension(extension),
        )),
        "mcp.http" => Ok(ToolProvider::McpHttp(McpHttpToolProvider::from_extension(
            extension,
        )?)),
        _ => bail!("unsupported builtin tool provider {}", extension.id),
    }
}

#[derive(Debug, Clone)]
struct ToolProviderConfig {
    extension_id: String,
    allowed_tools: HashSet<String>,
    tenant_allowlist: Vec<String>,
    api_key_allowlist: Vec<String>,
    route_allowlist: Vec<String>,
}

impl ToolProviderConfig {
    fn from_extension(extension: &ExtensionConfig) -> Self {
        Self {
            extension_id: extension.id.clone(),
            allowed_tools: extension.permissions.tools.iter().cloned().collect(),
            tenant_allowlist: string_list(&extension.config, "tenant_allowlist"),
            api_key_allowlist: string_list(&extension.config, "api_key_allowlist"),
            route_allowlist: string_list(&extension.config, "route_allowlist"),
        }
    }

    fn allows_tool(&self, name: &str) -> bool {
        self.allowed_tools
            .iter()
            .any(|tool| tool == "*" || tool == name)
    }

    fn registered_tool(&self, def: ToolDef) -> Option<RegisteredTool> {
        self.allows_tool(&def.name).then(|| RegisteredTool {
            name: def.name,
            description: def.description,
            input_schema: def.input_schema,
            extension_id: self.extension_id.clone(),
            tenant_allowlist: self.tenant_allowlist.clone(),
            api_key_allowlist: self.api_key_allowlist.clone(),
            route_allowlist: self.route_allowlist.clone(),
        })
    }
}

#[derive(Debug, Clone)]
enum ToolProvider {
    Echo(ToolProviderConfig),
    HealthCheck(ToolProviderConfig),
    McpHttp(McpHttpToolProvider),
}

impl ToolProvider {
    fn tools(&self) -> Vec<RegisteredTool> {
        match self {
            Self::Echo(config) => config
                .registered_tool(ToolDef {
                    name: "tool.echo".into(),
                    description: Some("Echoes the JSON arguments supplied to the tool.".into()),
                    input_schema: json!({
                        "type": "object",
                        "additionalProperties": true
                    }),
                })
                .into_iter()
                .collect(),
            Self::HealthCheck(config) => config
                .registered_tool(ToolDef {
                    name: "tool.health_check".into(),
                    description: Some("Returns FerroGate builtin tool-provider health.".into()),
                    input_schema: json!({"type": "object", "additionalProperties": false}),
                })
                .into_iter()
                .collect(),
            Self::McpHttp(provider) => provider.tools.clone(),
        }
    }

    async fn execute(&self, request: &ToolExecutionRequest) -> Result<Value, ToolExecutionError> {
        match self {
            Self::Echo(_) => Ok(json!({"echo": request.arguments})),
            Self::HealthCheck(_) => Ok(json!({"status": "ok"})),
            Self::McpHttp(provider) => provider.execute(request).await,
        }
    }
}

#[derive(Debug, Clone)]
struct McpHttpToolProvider {
    endpoint: String,
    timeout: Duration,
    tools: Vec<RegisteredTool>,
}

impl McpHttpToolProvider {
    fn from_extension(extension: &ExtensionConfig) -> AnyResult<Self> {
        let endpoint = string_value(&extension.config, "endpoint")
            .ok_or_else(|| anyhow::anyhow!("mcp.http requires config.endpoint"))?;
        let timeout_ms = integer_value(&extension.config, "timeout_ms").unwrap_or(30_000);
        let config = ToolProviderConfig::from_extension(extension);
        let defs = mcp_tools_list(&endpoint, Duration::from_millis(timeout_ms))
            .with_context(|| format!("failed to list MCP tools for {}", extension.id))?;
        let tools = defs
            .into_iter()
            .filter_map(|def| config.registered_tool(def))
            .collect();
        Ok(Self {
            endpoint,
            timeout: Duration::from_millis(timeout_ms),
            tools,
        })
    }

    async fn execute(&self, request: &ToolExecutionRequest) -> Result<Value, ToolExecutionError> {
        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;
        let name = request.name.clone();
        let arguments = request.arguments.clone();
        tokio::task::spawn_blocking(move || mcp_tools_call(&endpoint, timeout, &name, arguments))
            .await
            .map_err(|error| ToolExecutionError::Failed(format!("MCP task failed: {error}")))?
    }
}

#[derive(Debug, Clone)]
enum RequestHook {
    Noop(HookConfig),
}

impl RequestHook {
    fn id(&self) -> &str {
        match self {
            Self::Noop(config) => &config.id,
        }
    }

    fn blocking(&self) -> bool {
        match self {
            Self::Noop(config) => config.blocking,
        }
    }

    fn pre_request(&self, request_id: &str, path: &str) -> Result<(), ToolExecutionError> {
        match self {
            Self::Noop(config) => {
                if config.fail_pre_request {
                    return Err(ToolExecutionError::Denied(format!(
                        "{} denied pre_request",
                        config.id
                    )));
                }
                if request_id.trim().is_empty() {
                    return Err(ToolExecutionError::Denied(
                        "request id cannot be empty".into(),
                    ));
                }
                if path.trim().is_empty() {
                    return Err(ToolExecutionError::Denied(
                        "request path cannot be empty".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn post_response(&self, _request_id: &str, _status: u16) -> Result<(), ToolExecutionError> {
        match self {
            Self::Noop(config) => {
                if config.fail_post_response {
                    return Err(ToolExecutionError::Denied(format!(
                        "{} failed post_response",
                        config.id
                    )));
                }
                Ok(())
            }
        }
    }

    fn pre_tool_call(&self, request: &ToolExecutionRequest) -> Result<(), ToolExecutionError> {
        match self {
            Self::Noop(config) => {
                if config.fail_pre_tool_call {
                    return Err(ToolExecutionError::Denied(format!(
                        "{} denied pre_tool_call",
                        config.id
                    )));
                }
                if request.name.trim().is_empty() {
                    return Err(ToolExecutionError::Denied(
                        "tool name cannot be empty".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    fn post_tool_call(&self, _request: &ToolExecutionRequest) -> Result<(), ToolExecutionError> {
        match self {
            Self::Noop(config) => {
                if config.fail_post_tool_call {
                    return Err(ToolExecutionError::Denied(format!(
                        "{} failed post_tool_call",
                        config.id
                    )));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
struct HookConfig {
    id: String,
    blocking: bool,
    fail_pre_request: bool,
    fail_post_response: bool,
    fail_pre_tool_call: bool,
    fail_post_tool_call: bool,
}

impl HookConfig {
    fn from_extension(extension: &ExtensionConfig) -> Self {
        Self {
            id: extension.id.clone(),
            blocking: bool_value(&extension.config, "blocking"),
            fail_pre_request: bool_value(&extension.config, "fail_pre_request"),
            fail_post_response: bool_value(&extension.config, "fail_post_response"),
            fail_pre_tool_call: bool_value(&extension.config, "fail_pre_tool_call"),
            fail_post_tool_call: bool_value(&extension.config, "fail_post_tool_call"),
        }
    }
}

#[derive(Debug, Clone)]
enum EventSink {
    AuditLog(AuditLogSink),
}

impl EventSink {
    fn id(&self) -> &str {
        match self {
            Self::AuditLog(sink) => &sink.id,
        }
    }

    fn blocking(&self) -> bool {
        match self {
            Self::AuditLog(sink) => sink.blocking,
        }
    }

    fn emit(&self, event: GatewayEvent) -> Result<(), ToolExecutionError> {
        match self {
            Self::AuditLog(sink) => {
                if sink.fail_emit {
                    return Err(ToolExecutionError::Failed(format!(
                        "{} failed to emit event",
                        sink.id
                    )));
                }
                if let Ok(mut events) = sink.events.lock() {
                    events.push(event);
                    if events.len() > 1_000 {
                        events.remove(0);
                    }
                }
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn events(&self) -> Vec<GatewayEvent> {
        match self {
            Self::AuditLog(sink) => sink
                .events
                .lock()
                .map(|events| events.clone())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone)]
struct AuditLogSink {
    id: String,
    blocking: bool,
    fail_emit: bool,
    events: Arc<Mutex<Vec<GatewayEvent>>>,
}

fn tool_visible(
    tool: &RegisteredTool,
    tenant: &TenantContext,
    api_key_id: Option<&str>,
    route: Option<&str>,
) -> bool {
    list_allows_tenant(&tool.tenant_allowlist, tenant)
        && list_allows(&tool.api_key_allowlist, api_key_id)
        && list_allows(&tool.route_allowlist, route)
}

fn list_allows(list: &[String], value: Option<&str>) -> bool {
    list.is_empty()
        || list.iter().any(|item| item == "*")
        || value.is_some_and(|value| list.iter().any(|item| item == value))
}

fn list_allows_tenant(list: &[String], tenant: &TenantContext) -> bool {
    list.is_empty()
        || list.iter().any(|item| item == "*")
        || tenant
            .organization_id
            .as_deref()
            .is_some_and(|id| list.iter().any(|item| item == id))
        || tenant
            .project_id
            .as_deref()
            .is_some_and(|id| list.iter().any(|item| item == id))
}

fn string_value(config: &BTreeMap<String, toml::Value>, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
}

fn integer_value(config: &BTreeMap<String, toml::Value>, key: &str) -> Option<u64> {
    config
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u64::try_from(value).ok())
}

fn bool_value(config: &BTreeMap<String, toml::Value>, key: &str) -> bool {
    config
        .get(key)
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

fn string_list(config: &BTreeMap<String, toml::Value>, key: &str) -> Vec<String> {
    config
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn mcp_tools_list(endpoint: &str, timeout: Duration) -> AnyResult<Vec<ToolDef>> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let response = post_json(endpoint, timeout, &body)?;
    let tools = response
        .get("result")
        .and_then(|result| result.get("tools"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("MCP tools/list response missing result.tools"))?;

    let mut defs = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("MCP tool is missing name"))?;
        defs.push(ToolDef {
            name: name.to_string(),
            description: tool
                .get("description")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            input_schema: tool
                .get("inputSchema")
                .or_else(|| tool.get("input_schema"))
                .cloned()
                .unwrap_or_else(|| json!({"type": "object"})),
        });
    }
    Ok(defs)
}

fn mcp_tools_call(
    endpoint: &str,
    timeout: Duration,
    name: &str,
    arguments: Value,
) -> Result<Value, ToolExecutionError> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    });
    let response = post_json(endpoint, timeout, &body)
        .map_err(|error| ToolExecutionError::Failed(error.to_string()))?;
    if let Some(error) = response.get("error") {
        return Err(ToolExecutionError::Failed(error.to_string()));
    }
    Ok(response.get("result").cloned().unwrap_or(Value::Null))
}

fn post_json(endpoint: &str, timeout: Duration, body: &Value) -> AnyResult<Value> {
    let target = parse_http_target(endpoint)?;
    let body = serde_json::to_vec(body)?;
    let mut stream = TcpStream::connect_timeout(&target.address, timeout)
        .with_context(|| format!("failed to connect MCP endpoint {}", target.authority))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        target.path_query,
        target.authority,
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let response = String::from_utf8_lossy(&raw);
    let (_, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("invalid MCP HTTP response"))?;
    serde_json::from_str(body).context("invalid MCP JSON response")
}

#[derive(Debug)]
struct HttpTarget {
    authority: String,
    path_query: String,
    address: std::net::SocketAddr,
}

fn parse_http_target(raw: &str) -> AnyResult<HttpTarget> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid MCP endpoint {raw}"))?;
    if uri.scheme_str() != Some("http") {
        bail!("MCP HTTP provider supports http endpoints only in this phase");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint must include authority"))?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(80);
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("MCP endpoint resolved no addresses"))?;
    let authority = if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|path| path.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(HttpTarget {
        authority,
        path_query,
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExtensionPermissions;

    fn extension(id: &str, kind: ExtensionKind) -> ExtensionConfig {
        ExtensionConfig {
            id: id.into(),
            kind,
            enabled: true,
            source: "builtin".into(),
            order: 10,
            permissions: ExtensionPermissions {
                tools: vec!["*".into()],
                network: vec![],
                filesystem: false,
                shell: false,
            },
            config: BTreeMap::new(),
        }
    }

    #[test]
    fn registry_loads_enabled_builtin_extensions_and_skips_disabled() {
        let mut disabled = extension("tool.health_check", ExtensionKind::ToolProvider);
        disabled.enabled = false;
        let registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            extension("hook.noop", ExtensionKind::RequestHook),
            extension("event.audit_log", ExtensionKind::EventSink),
            disabled,
        ]);

        assert_eq!(registry.statuses().len(), 4);
        assert!(registry
            .statuses()
            .iter()
            .any(|status| status.id == "tool.echo" && status.active));
        assert!(registry
            .statuses()
            .iter()
            .any(|status| status.id == "tool.health_check" && !status.active));
        assert_eq!(
            registry.tools_for(&TenantContext::default(), None, None)[0].name,
            "tool.echo"
        );
    }

    #[tokio::test]
    async fn echo_tool_executes_and_emits_event() {
        let registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            extension("event.audit_log", ExtensionKind::EventSink),
        ]);
        let response = registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.echo".into(),
                    arguments: json!({"message": "hello"}),
                    route: None,
                    session_id: Some("session-1".into()),
                },
                "req-1".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(response.name, "tool.echo");
        assert_eq!(response.content, json!({"echo": {"message": "hello"}}));
    }

    #[tokio::test]
    async fn non_blocking_extension_failures_are_isolated_and_visible() {
        let mut hook = extension("hook.noop", ExtensionKind::RequestHook);
        hook.config
            .insert("fail_pre_tool_call".into(), toml::Value::Boolean(true));
        let mut sink = extension("event.audit_log", ExtensionKind::EventSink);
        sink.config
            .insert("fail_emit".into(), toml::Value::Boolean(true));
        let registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            hook,
            sink,
        ]);

        let response = registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.echo".into(),
                    arguments: json!({"message": "hello"}),
                    route: None,
                    session_id: None,
                },
                "req-1".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(response.name, "tool.echo");
        let statuses = registry.statuses();
        assert!(statuses.iter().any(|status| {
            status.id == "hook.noop"
                && status.health == "degraded"
                && status
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.contains("pre_tool_call"))
        }));
        assert!(statuses.iter().any(|status| {
            status.id == "event.audit_log"
                && status.health == "degraded"
                && status
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.contains("emit event"))
        }));
    }

    #[tokio::test]
    async fn blocking_extension_failures_stop_tool_execution() {
        let mut hook = extension("hook.noop", ExtensionKind::RequestHook);
        hook.config
            .insert("blocking".into(), toml::Value::Boolean(true));
        hook.config
            .insert("fail_pre_tool_call".into(), toml::Value::Boolean(true));
        let registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            hook,
        ]);

        let error = registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.echo".into(),
                    arguments: json!({"message": "hello"}),
                    route: None,
                    session_id: None,
                },
                "req-1".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "tool_denied");
        assert!(registry.statuses().iter().any(|status| {
            status.id == "hook.noop"
                && status.health == "degraded"
                && status.last_error.as_deref() == Some("hook.noop denied pre_tool_call")
        }));
    }

    #[tokio::test]
    async fn tool_hooks_run_pre_in_order_and_post_in_reverse_order() {
        let mut first_pre = extension("hook.noop.first", ExtensionKind::RequestHook);
        first_pre.order = 10;
        first_pre
            .config
            .insert("blocking".into(), toml::Value::Boolean(true));
        first_pre
            .config
            .insert("fail_pre_tool_call".into(), toml::Value::Boolean(true));
        let mut second_pre = extension("hook.noop.second", ExtensionKind::RequestHook);
        second_pre.order = 20;
        second_pre
            .config
            .insert("blocking".into(), toml::Value::Boolean(true));
        second_pre
            .config
            .insert("fail_pre_tool_call".into(), toml::Value::Boolean(true));
        let pre_registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            second_pre,
            first_pre,
        ]);

        let pre_error = pre_registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.echo".into(),
                    arguments: json!({}),
                    route: None,
                    session_id: None,
                },
                "req-1".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(pre_error.message(), "hook.noop.first denied pre_tool_call");

        let mut first_post = extension("hook.noop.first", ExtensionKind::RequestHook);
        first_post.order = 10;
        first_post
            .config
            .insert("blocking".into(), toml::Value::Boolean(true));
        first_post
            .config
            .insert("fail_post_tool_call".into(), toml::Value::Boolean(true));
        let mut second_post = extension("hook.noop.second", ExtensionKind::RequestHook);
        second_post.order = 20;
        second_post
            .config
            .insert("blocking".into(), toml::Value::Boolean(true));
        second_post
            .config
            .insert("fail_post_tool_call".into(), toml::Value::Boolean(true));
        let post_registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            first_post,
            second_post,
        ]);

        let post_error = post_registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.echo".into(),
                    arguments: json!({}),
                    route: None,
                    session_id: None,
                },
                "req-2".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            post_error.message(),
            "hook.noop.second failed post_tool_call"
        );
    }

    #[tokio::test]
    async fn tool_execution_failures_emit_audit_events() {
        let registry = ExtensionRegistry::from_config(&[
            extension("tool.echo", ExtensionKind::ToolProvider),
            extension("event.audit_log", ExtensionKind::EventSink),
        ]);

        let error = registry
            .execute_tool(
                ToolExecutionRequest {
                    name: "tool.missing".into(),
                    arguments: json!({}),
                    route: None,
                    session_id: Some("session-1".into()),
                },
                "req-1".into(),
                TenantContext::default(),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code(), "tool_not_found");
        let events = registry.captured_events("event.audit_log");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, "req-1");
        assert_eq!(events[0].extension_id, "tool_registry");
        assert_eq!(events[0].tool_name.as_deref(), Some("tool.missing"));
        assert_eq!(events[0].status, "error");
        assert_eq!(events[0].error_code.as_deref(), Some("tool_not_found"));
        assert_eq!(events[0].session_id.as_deref(), Some("session-1"));
    }
}
