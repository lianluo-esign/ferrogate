// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::dashboard::ADMIN_DASHBOARD_HTML;
use bytes::Bytes;
use ferrogate_observability::render_prometheus_text;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use std::collections::BTreeMap;

use crate::{
    approval::{ApprovalDecisionError, ApprovalStatus, ToolApprovalDecisionRequest},
    auth::{authenticate, AuthContext},
    config::{
        config_snapshot_id, ApiKey, Config, PolicyRule, PromptTemplate, PromptTemplateStatus,
        PromptTemplateTarget, PromptTemplateVersion, PromptTemplateVersionStatus, Provider,
    },
    extensions::{ToolExecutionRequest, ToolExecutionResponse},
    responses::{
        write_empty_response, write_json_error, write_json_error_and_close, write_json_response,
        write_raw_response, AdminAcmeStatus, AdminApiKey, AdminApiKeyMutation,
        AdminApiKeyMutationResponse, AdminConfigReloadResponse, AdminConfigValidateRequest,
        AdminConfigValidateResponse, AdminDeleteResponse, AdminDrainRequest, AdminDrainResponse,
        AdminGatewayConfigMutation, AdminGatewayConfigMutationResponse, AdminGatewayConfigProfile,
        AdminList, AdminMcpServerMutationResponse, AdminPlugin, AdminPluginMutation,
        AdminPluginMutationResponse, AdminPolicyMutation, AdminPolicyMutationResponse,
        AdminPromptTemplate, AdminPromptTemplateMutation, AdminPromptTemplateMutationResponse,
        AdminProvider, AdminProviderModelCandidate, AdminProviderModelCatalog, AdminStatus,
        HealthResponse, OpenAiModel, OpenAiModelList, PromptTemplateRenderRequest,
        ReadinessResponse,
    },
    state::{AdminAuditEventDraft, RequestLogExportFilter, RequestLogExportRecord},
};
use ferrogate_providers::provider_compatibility_kind;

use super::body::read_request_body;
use super::dispatch::dispatch_provider_catalog_request;
use super::mcp_rpc;
use super::{FerroGateway, ProxyContext};

const PROVIDER_CATALOG_BODY_MAX_BYTES: usize = 2 * 1024 * 1024;

const SERVICE_NAME: &str = "ferrogate";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolExecuteBackend {
    Extension,
    Mcp,
}

#[derive(Debug)]
pub(super) struct ToolExecutionHttpError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl FerroGateway {
    pub(super) async fn handle_healthz(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
    ) -> PingoraResult<()> {
        let body = HealthResponse {
            status: "ok",
            service: SERVICE_NAME,
            version: env!("CARGO_PKG_VERSION"),
            runtime: "pingora",
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    pub(super) async fn handle_readyz(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let cluster = state.cluster_status();
        let status = if cluster.ready { "ready" } else { "not_ready" };
        let status_code = if cluster.ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let body = ReadinessResponse {
            status,
            service: SERVICE_NAME,
            version: env!("CARGO_PKG_VERSION"),
            runtime: "pingora",
            cluster,
        };
        write_json_response(session, status_code, &body, &ctx.request_id).await
    }

    pub(super) async fn handle_admin_dashboard(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
    ) -> PingoraResult<()> {
        write_raw_response(
            session,
            StatusCode::OK,
            "text/html; charset=utf-8",
            Bytes::from_static(ADMIN_DASHBOARD_HTML.as_bytes()),
            &ctx.request_id,
        )
        .await
    }

    pub(super) async fn handle_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "models.read", &ctx.request_id) {
            Ok(_) => {
                let data = state
                    .config
                    .models
                    .iter()
                    .filter(|model| model.enabled)
                    .map(|model| OpenAiModel {
                        id: model.name.clone(),
                        object: "model",
                        created: 0,
                        owned_by: model.provider.clone(),
                    })
                    .collect();
                write_json_response(
                    session,
                    StatusCode::OK,
                    &OpenAiModelList {
                        object: "list",
                        data,
                    },
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_status(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let status = AdminStatus {
                    service: SERVICE_NAME,
                    version: env!("CARGO_PKG_VERSION"),
                    runtime: "pingora",
                    snapshot: config_snapshot_id(&state.config),
                    providers: state.config.providers.len(),
                    enabled_providers: state.config.providers.iter().filter(|p| p.enabled).count(),
                    models: state.config.models.len(),
                    enabled_models: state.config.models.iter().filter(|m| m.enabled).count(),
                    api_keys: state.config.api_keys.len(),
                    prompt_templates: state.config.prompt_templates.len(),
                    upstreams: state.config.upstreams.len(),
                    enabled_upstreams: state.config.upstreams.iter().filter(|u| u.enabled).count(),
                    routes: state.config.routes.len(),
                    enabled_routes: state.config.routes.iter().filter(|r| r.enabled).count(),
                    plugins: state.config.plugin_registrations().len(),
                    active_plugins: state
                        .extension_statuses()
                        .iter()
                        .filter(|extension| extension.active)
                        .count(),
                    extensions: state.config.plugin_registrations().len(),
                    active_extensions: state
                        .extension_statuses()
                        .iter()
                        .filter(|extension| extension.active)
                        .count(),
                    tools: state.all_tools().len(),
                    auth_required: state.auth_required(),
                    storage: state.storage_status(),
                    analytics: state.analytics_status(),
                    cluster: state.cluster_status(),
                    observability: state.observability_status(),
                    acme: state.acme_renewal_status().map(|status| AdminAcmeStatus {
                        enabled: status.enabled,
                        domains: status.domains,
                        cert_path: status.cert_path,
                        key_path: status.key_path,
                        certificate_expires_at_unix: status.certificate_expires_at_unix,
                        renewal_window_secs: status.renewal_window_secs,
                        renewal_due: status.renewal_due,
                        last_renewal_status: status.last_renewal_status,
                        last_renewal_at_unix: status.last_renewal_at_unix,
                        last_renewal_error: status.last_renewal_error,
                        next_check_at_unix: status.next_check_at_unix,
                        reload_required: status.reload_required,
                        reload_mode: status.reload_mode,
                    }),
                };
                write_json_response(session, StatusCode::OK, &status, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_observability(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.observability_status());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_mcp_servers(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => match (method, path.strip_prefix("/admin/v1/mcp-servers/")) {
                (&Method::GET, None) => {
                    state.mcp_health_check_and_reconnect();
                    let statuses = state.mcp_statuses();
                    let total = statuses.len();
                    let body = AdminList::paginated(statuses, total, 0, total);
                    write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                }
                (&Method::POST, None) => {
                    self.handle_admin_mcp_server_upsert(session, ctx, headers, None)
                        .await
                }
                (&Method::GET, Some(name)) if !name.contains('/') => {
                    state.mcp_health_check_and_reconnect();
                    if let Some(status) = state
                        .mcp_statuses()
                        .into_iter()
                        .find(|status| status.name == name)
                    {
                        return write_json_response(
                            session,
                            StatusCode::OK,
                            &status,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "mcp_server_not_found",
                        format!("MCP server {name} was not found"),
                        &ctx.request_id,
                    )
                    .await
                }
                (&Method::PUT | &Method::PATCH, Some(name)) if !name.contains('/') => {
                    self.handle_admin_mcp_server_upsert(session, ctx, headers, Some(name))
                        .await
                }
                (&Method::DELETE, Some(name)) if !name.contains('/') => {
                    self.handle_admin_mcp_server_delete(session, ctx, headers, name)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "MCP server endpoint supports GET, POST, PUT, PATCH, and DELETE",
                        &ctx.request_id,
                    )
                    .await
                }
            },
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_mcp_server_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_name: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.upsert",
                    path_name.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let server = match serde_json::from_slice::<crate::config::McpServerConfig>(&body) {
            Ok(server) => {
                if path_name.is_some_and(|path_name| path_name != server.name.as_str()) {
                    let message = "request path name and body name must match";
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "mcp_server.upsert",
                        path_name.unwrap_or("new"),
                        "rejected",
                        message,
                    ));
                    return write_json_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        "invalid_mcp_server",
                        message,
                        &ctx.request_id,
                    )
                    .await;
                }
                server
            }
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.upsert",
                    path_name.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON MCP server config object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let server_name = server.name.clone();
        match self.state.upsert_mcp_server(server) {
            Ok(outcome) if outcome.committed => {
                let current = self.state.current();
                current.mcp_health_check_and_reconnect();
                let Some(status) = current
                    .mcp_statuses()
                    .into_iter()
                    .find(|status| status.name == server_name)
                else {
                    return write_json_error(
                        session,
                        StatusCode::CONFLICT,
                        "mcp_server_reload_rejected",
                        format!("MCP server {server_name} was not visible after reload"),
                        &ctx.request_id,
                    )
                    .await;
                };
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.upsert",
                    &server_name,
                    "committed",
                    format!(
                        "MCP server {server_name} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminMcpServerMutationResponse {
                    object: "mcp_server",
                    server: status,
                };
                write_json_response(
                    session,
                    if path_name.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate MCP server config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.upsert",
                    &server_name,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "mcp_server_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.upsert",
                    &server_name,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_mcp_server",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_mcp_server_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        name: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.delete_mcp_server(name) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.delete",
                    name,
                    "committed",
                    format!(
                        "MCP server {name} deleted: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "mcp_server",
                    id: name.to_string(),
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate MCP server config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.delete",
                    name,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "mcp_server_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "mcp_server_not_found",
                    format!("MCP server {name} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "mcp_server.delete",
                    name,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_mcp_server_delete",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_gateway_configs(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let id = path.strip_prefix("/admin/v1/gateway-configs/");
        match (method, id) {
            (&Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let data = state
                            .config
                            .gateway_configs
                            .iter()
                            .map(admin_gateway_config)
                            .collect();
                        write_json_response(
                            session,
                            StatusCode::OK,
                            &AdminList::new(data),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::GET, Some(id)) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let Some(profile) = find_gateway_config(&state, id) else {
                            return write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "gateway_config_not_found",
                                format!("gateway config profile {id} was not found"),
                                &ctx.request_id,
                            )
                            .await;
                        };
                        let body = AdminGatewayConfigMutationResponse {
                            object: "gateway_config",
                            gateway_config: admin_gateway_config(profile),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::POST, None) => {
                self.handle_admin_gateway_config_upsert(session, ctx, headers, None)
                    .await
            }
            (&Method::PUT | &Method::PATCH, Some(id)) => {
                self.handle_admin_gateway_config_upsert(session, ctx, headers, Some(id))
                    .await
            }
            (&Method::DELETE, Some(id)) => {
                self.handle_admin_gateway_config_delete(session, ctx, headers, id)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "gateway config endpoint supports GET, POST, PUT, PATCH, and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_gateway_config_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminGatewayConfigMutation>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON gateway config object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let profile = match gateway_config_from_mutation(path_id, payload) {
            Ok(profile) => profile,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    path_id.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_gateway_config",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let profile_id = profile.id.clone();
        let response_profile = admin_gateway_config(&profile);
        match self.state.upsert_gateway_config(profile) {
            Ok(outcome) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    &profile_id,
                    "committed",
                    format!(
                        "gateway config {profile_id} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminGatewayConfigMutationResponse {
                    object: "gateway_config",
                    gateway_config: response_profile,
                };
                write_json_response(
                    session,
                    if path_id.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate gateway config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    &profile_id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "gateway_config_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.upsert",
                    &profile_id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_gateway_config",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_gateway_config_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.delete_gateway_config(id) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.delete",
                    id,
                    "committed",
                    format!(
                        "gateway config {id} deleted: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "gateway_config",
                    id: id.to_string(),
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate gateway config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.delete",
                    id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "gateway_config_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "gateway_config_not_found",
                    format!("gateway config profile {id} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "gateway_config.delete",
                    id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_gateway_config_delete",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_prompt_templates(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let id = path.strip_prefix("/admin/v1/prompt-templates/");
        match (method, id) {
            (&Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let data = state
                            .config
                            .prompt_templates
                            .iter()
                            .map(admin_prompt_template)
                            .collect();
                        write_json_response(
                            session,
                            StatusCode::OK,
                            &AdminList::new(data),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::GET, Some(id)) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let Some(template) = find_prompt_template(&state, id) else {
                            return write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "prompt_template_not_found",
                                format!("prompt template {id} was not found"),
                                &ctx.request_id,
                            )
                            .await;
                        };
                        let body = AdminPromptTemplateMutationResponse {
                            object: "prompt_template",
                            prompt_template: admin_prompt_template(template),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::POST, None) => {
                self.handle_admin_prompt_template_upsert(session, ctx, headers, None)
                    .await
            }
            (&Method::PUT | &Method::PATCH, Some(id)) => {
                self.handle_admin_prompt_template_upsert(session, ctx, headers, Some(id))
                    .await
            }
            (&Method::DELETE, Some(id)) => {
                self.handle_admin_prompt_template_archive(session, ctx, headers, id)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "prompt template endpoint supports GET, POST, PUT, PATCH, and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_prompt_template_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminPromptTemplateMutation>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON prompt template object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let existing = path_id.and_then(|id| find_prompt_template(&state, id));
        let template = match prompt_template_from_mutation(path_id, existing, payload) {
            Ok(template) => template,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    path_id.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_prompt_template",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let template_id = template.id.clone();
        let response_template = admin_prompt_template(&template);
        match self.state.upsert_prompt_template(template) {
            Ok(outcome) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    &template_id,
                    "committed",
                    format!(
                        "prompt template {template_id} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminPromptTemplateMutationResponse {
                    object: "prompt_template",
                    prompt_template: response_template,
                };
                write_json_response(
                    session,
                    if path_id.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate prompt template".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    &template_id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "prompt_template_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.upsert",
                    &template_id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_prompt_template",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_prompt_template_archive(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.archive_prompt_template(id) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.archive",
                    id,
                    "committed",
                    format!(
                        "prompt template {id} archived: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "prompt_template",
                    id: id.to_string(),
                    deleted: false,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected prompt template archive".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.archive",
                    id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "prompt_template_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "prompt_template_not_found",
                    format!("prompt template {id} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.archive",
                    id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_prompt_template_archive",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_prompt_template_render(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "prompt template render requires POST",
                &ctx.request_id,
            )
            .await;
        }
        let Some(id) = prompt_template_id_from_render_path(path) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "prompt_template_not_found",
                "prompt template render path must be /v1/prompts/{prompt_id}/render",
                &ctx.request_id,
            )
            .await;
        };

        let state = self.state.current();
        let auth = match authenticate(&state, &headers, "prompts.render", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.render",
                    id,
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let request = if body.is_empty() {
            PromptTemplateRenderRequest {
                variables: BTreeMap::new(),
                revision: None,
            }
        } else {
            match serde_json::from_slice::<PromptTemplateRenderRequest>(&body) {
                Ok(request) => request,
                Err(error) => {
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "prompt_template.render",
                        id,
                        "error",
                        format!("invalid request body: {error}"),
                    ));
                    return write_json_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        "invalid_request_body",
                        "request body must be JSON with variables and optional revision",
                        &ctx.request_id,
                    )
                    .await;
                }
            }
        };

        let Some(template) = find_prompt_template(&state, id) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "prompt_template_not_found",
                format!("prompt template {id} was not found"),
                &ctx.request_id,
            )
            .await;
        };
        if !auth.can_use_model(&template.model) {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "prompt_template.render",
                id,
                "rejected",
                format!(
                    "API key is not allowed to render prompt template model {}",
                    template.model
                ),
            ));
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!("API key is not allowed to use model {}", template.model),
                &ctx.request_id,
            )
            .await;
        }
        let model = match state.resolve_model(&template.model) {
            Ok(model) => model,
            Err(ferrogate_providers::ModelRegistryError::ModelDisabled { .. }) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.render",
                    id,
                    "rejected",
                    format!("model {} is disabled", template.model),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "model_disabled",
                    format!("model {} is disabled", template.model),
                    &ctx.request_id,
                )
                .await;
            }
            Err(_) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.render",
                    id,
                    "rejected",
                    format!("unknown model {}", template.model),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "model_not_found",
                    format!("unknown model {}", template.model),
                    &ctx.request_id,
                )
                .await;
            }
        };
        if !state.can_tenant_use_model(
            &template.model,
            auth.organization_id.as_deref(),
            auth.project_id.as_deref(),
        ) {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "prompt_template.render",
                id,
                "rejected",
                format!("model {} is not visible to this tenant", template.model),
            ));
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_visible",
                format!("model {} is not visible to this tenant", template.model),
                &ctx.request_id,
            )
            .await;
        }
        let routes = state.candidate_model_routes(&model, None);
        if !routes
            .iter()
            .any(|route| auth.can_use_provider(&route.provider))
        {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "prompt_template.render",
                id,
                "rejected",
                format!(
                    "API key is not allowed to use any provider for model {}",
                    template.model
                ),
            ));
            return write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "provider_not_allowed",
                format!(
                    "API key is not allowed to use any provider for model {}",
                    template.model
                ),
                &ctx.request_id,
            )
            .await;
        }
        if template.status != PromptTemplateStatus::Active {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "prompt_template.render",
                id,
                "rejected",
                "prompt template is not active",
            ));
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "prompt_template_inactive",
                format!("prompt template {id} is not active"),
                &ctx.request_id,
            )
            .await;
        }

        let version = match find_prompt_template_version(template, request.revision) {
            Some(version) => version,
            None => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "prompt_template_version_not_found",
                    "prompt template version was not found",
                    &ctx.request_id,
                )
                .await;
            }
        };
        if version.status != PromptTemplateVersionStatus::Active {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "prompt_template.render",
                id,
                "rejected",
                format!("prompt template version {} is not active", version.revision),
            ));
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "prompt_template_version_inactive",
                format!("prompt template version {} is not active", version.revision),
                &ctx.request_id,
            )
            .await;
        }

        let rendered = match render_prompt_template(template, version, &request.variables) {
            Ok(rendered) => rendered,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "prompt_template.render",
                    id,
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "prompt_template_render_failed",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        state.record_admin_audit_event(admin_audit_event_draft_for_target(
            ctx,
            &auth,
            "prompt_template.render",
            id,
            "success",
            format!(
                "prompt template render accepted revision={} target={} model={} variable_count={} variable_schema_hash={} api_key_id={}",
                version.revision,
                prompt_template_target_name(template.target),
                template.model,
                request.variables.len(),
                prompt_template_variable_schema_hash(template),
                auth.api_key_id.as_deref().unwrap_or("anonymous")
            ),
        ));
        write_json_response(session, StatusCode::OK, &rendered, &ctx.request_id).await
    }

    pub(super) async fn handle_tools(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "tools.read", &ctx.request_id) {
            Ok(auth) => {
                let route = query
                    .and_then(|query| parse_query_param(query, "route"))
                    .map(str::to_string);
                let tools = state.tools_for(
                    &auth.tenant_context(),
                    auth.api_key_id.as_deref(),
                    route.as_deref(),
                );
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "tool.list",
                    route
                        .as_deref()
                        .map(|route| format!("route:{route}"))
                        .unwrap_or_else(|| "tools".into()),
                    "success",
                    format!("listed {} tools", tools.len()),
                ));
                let body = AdminList::new(tools);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_tool_execute(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        self.handle_tool_execute_with_backend(
            session,
            ctx,
            headers,
            method,
            ToolExecuteBackend::Extension,
        )
        .await
    }

    pub(super) async fn handle_mcp_tool_execute(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        self.handle_tool_execute_with_backend(
            session,
            ctx,
            headers,
            method,
            ToolExecuteBackend::Mcp,
        )
        .await
    }

    pub(super) async fn handle_mcp_rpc(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "MCP JSON-RPC endpoint requires POST",
                &ctx.request_id,
            )
            .await;
        }

        let body = match read_request_body(session, 64 * 1024).await? {
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
        let rpc: mcp_rpc::McpJsonRpcRequest = match serde_json::from_slice(&body) {
            Ok(rpc) => rpc,
            Err(error) => {
                let response = mcp_rpc::error(None, -32700, format!("parse error: {error}"));
                return write_json_response(session, StatusCode::OK, &response, &ctx.request_id)
                    .await;
            }
        };
        if rpc
            .jsonrpc
            .as_deref()
            .is_some_and(|version| version != "2.0")
        {
            let response = mcp_rpc::error(rpc.id, -32600, "invalid JSON-RPC version");
            return write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await;
        }

        let required_scope = mcp_rpc::required_scope(&rpc.method);
        let state = self.state.current();
        let auth = match authenticate(&state, &headers, required_scope, &ctx.request_id) {
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

        if rpc.id.is_none() {
            return write_empty_response(session, StatusCode::ACCEPTED, &ctx.request_id).await;
        }

        let response = mcp_rpc::handle_request(&state, ctx, &auth, rpc).await;
        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    async fn handle_tool_execute_with_backend(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: http::HeaderMap,
        method: &Method,
        backend: ToolExecuteBackend,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "tool execution requires POST",
                &ctx.request_id,
            )
            .await;
        }

        let state = self.state.current();
        let auth = match authenticate(&state, &headers, "tools.execute", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
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
        let request: ToolExecutionRequest = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid tool execution JSON: {error}"),
                    &ctx.request_id,
                )
                .await;
            }
        };
        match self
            .execute_tool_request_with_governance(ctx, &auth, None, request, backend)
            .await
        {
            Ok(response) => {
                write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn execute_tool_request_with_governance(
        &self,
        ctx: &ProxyContext,
        auth: &AuthContext,
        agent_run_id: Option<&str>,
        request: ToolExecutionRequest,
        backend: ToolExecuteBackend,
    ) -> Result<ToolExecutionResponse, ToolExecutionHttpError> {
        let state = self.state.current();
        let mcp_audit_details = (backend == ToolExecuteBackend::Mcp)
            .then(|| mcp_rpc::tool_audit_details(&request.name))
            .flatten();
        let audit_target = request
            .session_id
            .as_ref()
            .map(|session_id| {
                mcp_audit_details
                    .as_ref()
                    .map(|(server_name, tool_name)| {
                        mcp_rpc::tool_session_mcp_audit_target(session_id, server_name, tool_name)
                    })
                    .unwrap_or_else(|| mcp_rpc::tool_session_audit_target(session_id))
            })
            .unwrap_or_else(|| {
                mcp_audit_details
                    .as_ref()
                    .map(|(server_name, tool_name)| {
                        mcp_rpc::tool_audit_target(server_name, tool_name)
                    })
                    .unwrap_or_else(|| request.name.clone())
            });

        let Some(tool) = state.tool_by_name(&request.name) else {
            let (status, code, message) =
                if backend == ToolExecuteBackend::Mcp && mcp_audit_details.is_some() {
                    (
                        StatusCode::FORBIDDEN,
                        "tool_denied",
                        format!("MCP tool {} is not allowlisted for execution", request.name),
                    )
                } else {
                    (
                        StatusCode::NOT_FOUND,
                        "tool_not_found",
                        format!("tool {} is not registered", request.name),
                    )
                };
            state.record_admin_audit_event(tool_audit_event_draft_for_target(
                ctx,
                auth,
                agent_run_id,
                "tool.execute",
                audit_target,
                "error",
                mcp_rpc::tool_audit_failure_message(
                    mcp_audit_details.as_ref(),
                    &request.name,
                    code,
                    &message,
                ),
            ));
            return Err(ToolExecutionHttpError {
                status,
                code,
                message,
            });
        };

        if tool.approval_policy == ferrogate_core::ApprovalPolicy::Always {
            let approval = match state.create_tool_approval(
                &request,
                &ctx.request_id,
                ctx.trace_id.clone(),
                auth.tenant_context(),
                auth.api_key_id.clone(),
                mcp_audit_details
                    .as_ref()
                    .map(|(server, _)| server.clone())
                    .or_else(|| Some(tool.extension_id.clone())),
                tool.approval_policy,
                auth.can_record_bodies(state.config.telemetry.log_bodies),
            ) {
                Ok(approval) => approval,
                Err(error) => {
                    state.record_admin_audit_event(tool_audit_event_draft_for_target(
                        ctx,
                        auth,
                        agent_run_id,
                        "tool.approval_requested",
                        format!("tool:{}", request.name),
                        "error",
                        format!("tool approval persistence failed: {error}"),
                    ));
                    return Err(ToolExecutionHttpError {
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        code: "tool_approval_storage_unavailable",
                        message: "tool approval could not be persisted".to_string(),
                    });
                }
            };
            state.record_admin_audit_event(tool_audit_event_draft_for_target(
                ctx,
                auth,
                agent_run_id,
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
                    state.record_admin_audit_event(tool_audit_event_draft_for_target(
                        ctx,
                        auth,
                        agent_run_id,
                        "tool.approval_granted",
                        format!("tool_approval:{}", resolved.id),
                        "approved",
                        format!(
                            "approval {} fingerprint={} tool={} granted before execution",
                            resolved.id, resolved.fingerprint, resolved.tool_name
                        ),
                    ));
                }
                Err(error) => {
                    let latest = state.tool_approval(&approval.id).unwrap_or(approval);
                    let action = match latest.status {
                        ApprovalStatus::Denied => "tool.approval_denied",
                        ApprovalStatus::Expired => "tool.approval_expired",
                        _ => "tool.approval_rejected",
                    };
                    state.record_admin_audit_event(tool_audit_event_draft_for_target(
                        ctx,
                        auth,
                        agent_run_id,
                        action,
                        format!("tool_approval:{}", latest.id),
                        "rejected",
                        format!(
                            "approval {} fingerprint={} tool={} ended before execution: {}",
                            latest.id,
                            latest.fingerprint,
                            latest.tool_name,
                            error.message()
                        ),
                    ));
                    return Err(ToolExecutionHttpError {
                        status: error.status(),
                        code: error.code(),
                        message: error.message().to_string(),
                    });
                }
            }
        }

        let result = match backend {
            ToolExecuteBackend::Extension => {
                state
                    .execute_tool(
                        request.clone(),
                        ctx.request_id.clone(),
                        auth.tenant_context(),
                        auth.api_key_id.as_deref(),
                    )
                    .await
            }
            ToolExecuteBackend::Mcp => {
                state
                    .execute_mcp_tool(
                        request.clone(),
                        ctx.request_id.clone(),
                        auth.tenant_context(),
                    )
                    .await
            }
        };

        match result {
            Ok(response) => {
                state.record_admin_audit_event(tool_audit_event_draft_for_target(
                    ctx,
                    auth,
                    agent_run_id,
                    "tool.execute",
                    audit_target,
                    "success",
                    mcp_rpc::tool_audit_message(
                        mcp_audit_details.as_ref(),
                        &response.name,
                        "executed",
                        Some(response.latency_ms),
                    ),
                ));
                Ok(response)
            }
            Err(error) => {
                state.record_admin_audit_event(tool_audit_event_draft_for_target(
                    ctx,
                    auth,
                    agent_run_id,
                    "tool.execute",
                    audit_target,
                    "error",
                    mcp_rpc::tool_audit_failure_message(
                        mcp_audit_details.as_ref(),
                        &request.name,
                        error.code(),
                        error.message(),
                    ),
                ));
                Err(ToolExecutionHttpError {
                    status: error.status(),
                    code: error.code(),
                    message: error.message().to_string(),
                })
            }
        }
    }

    pub(super) async fn handle_admin_tool_session(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path: &str,
    ) -> PingoraResult<()> {
        let Some(session_id) = path.strip_prefix("/admin/v1/tool-sessions/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "tool session endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        if session_id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_tool_session",
                "tool session id is required",
                &ctx.request_id,
            )
            .await;
        }

        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let events = state.tool_session_events(session_id);
                let total = events.len();
                let body = AdminList::paginated(events, total, 0, total);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_metrics(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = render_prometheus_text(&state.prometheus_metrics_snapshot());
                write_raw_response(
                    session,
                    StatusCode::OK,
                    "text/plain; version=0.0.4; charset=utf-8",
                    Bytes::from(body),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_request_logs(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let page = state.request_logs_page(state.admin_pagination(query));
                let body = AdminList::paginated(page.data, page.total, page.offset, page.limit);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_request_log_export(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let records =
                    state.request_log_export_records(RequestLogExportFilter::from_query(query));
                let body = render_request_log_export_jsonl(&records);
                write_raw_response(
                    session,
                    StatusCode::OK,
                    "application/x-ndjson; charset=utf-8",
                    Bytes::from(body),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_agent_runs(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                if path == "/admin/v1/agent-runs" {
                    let page = state.agent_runs_page(
                        state.admin_pagination(query),
                        crate::state::AgentRunFilter::from_query(query),
                    );
                    let body = AdminList::paginated(page.data, page.total, page.offset, page.limit);
                    return write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                        .await;
                }
                let run_id = path.trim_start_matches("/admin/v1/agent-runs/");
                if run_id.is_empty() || run_id.contains('/') {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "agent_run_endpoint_not_found",
                        "agent run endpoint not found",
                        &ctx.request_id,
                    )
                    .await;
                }
                let Some(timeline) = state
                    .agent_run_timeline(run_id, crate::state::AgentRunFilter::from_query(query))
                else {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "agent_run_not_found",
                        format!("agent run {run_id} was not found"),
                        &ctx.request_id,
                    )
                    .await;
                };
                write_json_response(session, StatusCode::OK, &timeline, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_audit_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let page = state.audit_events_page(state.admin_pagination(query));
                let body = AdminList::paginated(page.data, page.total, page.offset, page.limit);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_config_validate(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "config validation requires POST",
                &ctx.request_id,
            )
            .await;
        }

        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 256 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminConfigValidateRequest>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be JSON with config_toml, config_yaml, config_caddyfile, or source=file",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let response = match config_from_admin_payload(&payload, &self.state) {
            Ok(candidate) => {
                let snapshot = config_snapshot_id(&candidate);
                let reload_plan = self.state.reload_plan_for_candidate(&candidate);
                state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "accepted",
                    format!(
                        "candidate config valid: snapshot={snapshot} reload_mode={}",
                        reload_plan.mode
                    ),
                ));
                AdminConfigValidateResponse {
                    valid: true,
                    snapshot: Some(snapshot),
                    reload_mode: Some(reload_plan.mode),
                    listener_reload_required: reload_plan.listener_reload_required,
                    reload_reason: reload_plan.reason,
                    error: None,
                }
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "rejected",
                    message.clone(),
                ));
                AdminConfigValidateResponse {
                    valid: false,
                    snapshot: None,
                    reload_mode: None,
                    listener_reload_required: false,
                    reload_reason: None,
                    error: Some(message),
                }
            }
        };

        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    pub(super) async fn handle_admin_config_reload(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "config reload requires POST",
                &ctx.request_id,
            )
            .await;
        }

        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 256 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_action(
                    ctx,
                    &auth,
                    "config.reload",
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminConfigValidateRequest>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_action(
                    ctx,
                    &auth,
                    "config.reload",
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be JSON with config_toml, config_yaml, config_caddyfile, or source=file",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let response = match reload_from_admin_payload(&payload, &self.state) {
            Ok(outcome) => {
                let outcome_message = if outcome.committed {
                    format!(
                        "candidate config committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    )
                } else {
                    format!(
                        "candidate config rejected: active_snapshot={} candidate_snapshot={} reason={}",
                        outcome.active_snapshot,
                        outcome.candidate_snapshot,
                        outcome.reason.as_deref().unwrap_or("unknown")
                    )
                };
                state.record_admin_audit_event(admin_audit_event_draft_for_action(
                    ctx,
                    &auth,
                    "config.reload",
                    if outcome.committed {
                        "committed"
                    } else {
                        "rejected"
                    },
                    outcome_message,
                ));

                AdminConfigReloadResponse {
                    valid: true,
                    committed: outcome.committed,
                    mode: outcome.mode,
                    active_snapshot: Some(outcome.active_snapshot),
                    candidate_snapshot: Some(outcome.candidate_snapshot),
                    error: outcome.reason,
                }
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_action(
                    ctx,
                    &auth,
                    "config.reload",
                    "rejected",
                    message.clone(),
                ));
                AdminConfigReloadResponse {
                    valid: false,
                    committed: false,
                    mode: "process-local",
                    active_snapshot: Some(config_snapshot_id(&state.config)),
                    candidate_snapshot: None,
                    error: Some(message),
                }
            }
        };

        write_json_response(session, StatusCode::OK, &response, &ctx.request_id).await
    }

    pub(super) async fn handle_admin_drain(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        match *method {
            Method::GET => {
                let state = self.state.current();
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let drain = state.drain_status();
                        let body = AdminDrainResponse {
                            object: "drain_status",
                            draining: drain.draining,
                            accepting_new_requests: drain.accepting_new_requests,
                            drain_reason: drain.drain_reason,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            Method::POST => {
                let state = self.state.current();
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

                let body = match read_request_body(session, 16 * 1024).await? {
                    Ok(body) => body,
                    Err(limit) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "drain.set",
                            "node",
                            "error",
                            format!(
                                "request body exceeds maximum size of {} bytes",
                                limit.max_bytes
                            ),
                        ));
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
                let payload = match serde_json::from_slice::<AdminDrainRequest>(&body) {
                    Ok(payload) => payload,
                    Err(error) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "drain.set",
                            "node",
                            "error",
                            format!("invalid request body: {error}"),
                        ));
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_json",
                            format!("invalid request body: {error}"),
                            &ctx.request_id,
                        )
                        .await;
                    }
                };

                let drain = self.state.set_drain(payload.drain);
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "drain.set",
                    "node",
                    "success",
                    format!("draining={}", drain.draining),
                ));
                let body = AdminDrainResponse {
                    object: "drain_status",
                    draining: drain.draining,
                    accepting_new_requests: drain.accepting_new_requests,
                    drain_reason: drain.drain_reason,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "drain endpoint supports GET and POST",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_providers(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(
                    state
                        .config
                        .providers
                        .iter()
                        .map(|provider| AdminProvider {
                            name: provider.name.clone(),
                            kind: provider.kind.clone(),
                            compatibility: provider_compatibility_kind(&provider.kind),
                            base_url: provider.base_url.clone(),
                            has_api_key: provider.api_key_env.is_some(),
                            enabled: provider.enabled,
                        })
                        .collect(),
                );
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_provider_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let provider_filter = query_provider_filter(query);
                let providers = state
                    .config
                    .providers
                    .iter()
                    .filter(|provider| {
                        provider_filter
                            .as_deref()
                            .is_none_or(|name| provider.name == name)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let mut catalogs = Vec::new();
                for provider in &providers {
                    if !provider.enabled {
                        catalogs.push(AdminProviderModelCatalog {
                            provider: provider.name.clone(),
                            kind: provider.kind.clone(),
                            base_url: provider.base_url.clone(),
                            enabled: false,
                            status: "disabled".into(),
                            models: Vec::new(),
                            error: None,
                        });
                        continue;
                    }

                    let catalog = match state.prepare_model_catalog(provider) {
                        Ok(request) => {
                            match dispatch_provider_catalog_request(
                                request,
                                state.provider_dispatch_timeout(),
                                PROVIDER_CATALOG_BODY_MAX_BYTES,
                            )
                            .await
                            {
                                Ok(response) if response.status.is_success() => {
                                    match state.parse_model_catalog(&provider.kind, &response.body)
                                    {
                                        Ok(models) => AdminProviderModelCatalog {
                                            provider: provider.name.clone(),
                                            kind: provider.kind.clone(),
                                            base_url: provider.base_url.clone(),
                                            enabled: true,
                                            status: "ok".into(),
                                            models: models
                                                .into_iter()
                                                .map(|model| AdminProviderModelCandidate {
                                                    id: model.id,
                                                    owned_by: model.owned_by,
                                                    created: model.created,
                                                    context_window: model.context_window,
                                                    capabilities: model.capabilities,
                                                })
                                                .collect(),
                                            error: None,
                                        },
                                        Err(error) => provider_catalog_error(provider, error),
                                    }
                                }
                                Ok(response) => AdminProviderModelCatalog {
                                    provider: provider.name.clone(),
                                    kind: provider.kind.clone(),
                                    base_url: provider.base_url.clone(),
                                    enabled: true,
                                    status: "error".into(),
                                    models: Vec::new(),
                                    error: Some(format!(
                                        "provider catalog returned HTTP {}",
                                        response.status.as_u16()
                                    )),
                                },
                                Err(error) => AdminProviderModelCatalog {
                                    provider: provider.name.clone(),
                                    kind: provider.kind.clone(),
                                    base_url: provider.base_url.clone(),
                                    enabled: true,
                                    status: "error".into(),
                                    models: Vec::new(),
                                    error: Some(error.to_string()),
                                },
                            }
                        }
                        Err(error) => provider_catalog_error(provider, error),
                    };
                    catalogs.push(catalog);
                }

                if provider_filter.is_some() && catalogs.is_empty() {
                    write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "provider_not_found",
                        "provider was not found",
                        &ctx.request_id,
                    )
                    .await
                } else {
                    let body = AdminList::new(catalogs);
                    write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                }
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_provider_health(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.provider_health_checks());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_plugins(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                if path == "/admin/v1/extensions" {
                    if method != &Method::GET {
                        return write_json_error(
                            session,
                            StatusCode::METHOD_NOT_ALLOWED,
                            "method_not_allowed",
                            "legacy extensions alias supports GET only",
                            &ctx.request_id,
                        )
                        .await;
                    }
                    let body = AdminList::new(state.extension_statuses());
                    return write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                        .await;
                }
                if path == "/admin/v1/plugins" {
                    if method == &Method::GET {
                        let body = AdminList::new(state.extension_statuses());
                        return write_json_response(
                            session,
                            StatusCode::OK,
                            &body,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    if method == &Method::POST {
                        return self
                            .handle_admin_plugin_upsert(session, ctx, headers, None)
                            .await;
                    }
                    return write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "plugin list endpoint supports GET and POST",
                        &ctx.request_id,
                    )
                    .await;
                }
                let plugin_path = path.trim_start_matches("/admin/v1/plugins/");
                if let Some(plugin_id) = plugin_path.strip_suffix("/tools") {
                    let Some(_) = state.plugin_status(plugin_id) else {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "plugin_not_found",
                            format!("plugin {plugin_id} is not registered"),
                            &ctx.request_id,
                        )
                        .await;
                    };
                    let body = AdminList::new(state.plugin_tools(plugin_id));
                    return write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                        .await;
                }
                if !plugin_path.contains('/') {
                    match method {
                        &Method::GET => {
                            if let Some(plugin) = state.plugin_status(plugin_path) {
                                return write_json_response(
                                    session,
                                    StatusCode::OK,
                                    &plugin,
                                    &ctx.request_id,
                                )
                                .await;
                            }
                            return write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "plugin_not_found",
                                format!("plugin {plugin_path} is not registered"),
                                &ctx.request_id,
                            )
                            .await;
                        }
                        &Method::POST => {
                            return self
                                .handle_admin_plugin_upsert(
                                    session,
                                    ctx,
                                    headers,
                                    Some(plugin_path),
                                )
                                .await;
                        }
                        &Method::PUT | &Method::PATCH => {
                            return self
                                .handle_admin_plugin_upsert(
                                    session,
                                    ctx,
                                    headers,
                                    Some(plugin_path),
                                )
                                .await;
                        }
                        &Method::DELETE => {
                            return self
                                .handle_admin_plugin_delete(session, ctx, headers, plugin_path)
                                .await;
                        }
                        _ => {}
                    }
                }
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "plugin_endpoint_not_found",
                    "plugin endpoint not found",
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_plugin_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminPluginMutation>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON plugin object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let plugin = match plugin_from_mutation(path_id, payload) {
            Ok(plugin) => plugin,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    path_id.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_plugin",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let plugin_id = plugin.id.clone();
        let response_plugin_source = plugin.clone();
        match self.state.upsert_plugin_registration(plugin) {
            Ok(outcome) if outcome.committed => {
                let current = self.state.current();
                let response_plugin = current
                    .plugin_status(&plugin_id)
                    .map(|status| admin_plugin(&response_plugin_source, Some(status)))
                    .unwrap_or_else(|| admin_plugin(&response_plugin_source, None));
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    &plugin_id,
                    "committed",
                    format!(
                        "plugin {plugin_id} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminPluginMutationResponse {
                    object: "plugin",
                    plugin: response_plugin,
                };
                write_json_response(
                    session,
                    if path_id.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate plugin config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    &plugin_id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "plugin_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.upsert",
                    &plugin_id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_plugin",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_plugin_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.delete_plugin_registration(id) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.delete",
                    id,
                    "committed",
                    format!(
                        "plugin {id} deleted: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "plugin",
                    id: id.to_string(),
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate plugin config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.delete",
                    id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "plugin_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "plugin_not_found",
                    format!("plugin {id} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "plugin.delete",
                    id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_plugin_delete",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_tools(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.all_tools());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_tool_approvals(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if path == "/admin/v1/tool-approvals" {
            if *method != Method::GET {
                return write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "tool approvals collection supports GET",
                    &ctx.request_id,
                )
                .await;
            }
            return match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => {
                    let approvals = state.tool_approvals();
                    let total = approvals.len();
                    write_json_response(
                        session,
                        StatusCode::OK,
                        &AdminList::paginated(approvals, total, 0, total),
                        &ctx.request_id,
                    )
                    .await
                }
                Err(error) => {
                    write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(rest) = path.strip_prefix("/admin/v1/tool-approvals/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "tool approval endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        let (id, action) = rest
            .split_once('/')
            .map_or((rest, None), |(id, action)| (id, Some(action)));
        if id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_tool_approval",
                "tool approval id is required",
                &ctx.request_id,
            )
            .await;
        }

        match (method.clone(), action) {
            (Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.tool_approval(id) {
                        Some(approval) => {
                            write_json_response(session, StatusCode::OK, &approval, &ctx.request_id)
                                .await
                        }
                        None => {
                            write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "tool_approval_not_found",
                                format!("tool approval {id} was not found"),
                                &ctx.request_id,
                            )
                            .await
                        }
                    },
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (Method::POST, Some("approve" | "deny" | "expire")) => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
                let body = match read_request_body(session, 16 * 1024).await? {
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
                let payload = match serde_json::from_slice::<ToolApprovalDecisionRequest>(&body) {
                    Ok(payload) => payload,
                    Err(error) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_json",
                            format!("invalid approval decision JSON: {error}"),
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let result = match action {
                    Some("approve") => {
                        state.approve_tool_approval(id, payload, auth.api_key_id.clone())
                    }
                    Some("deny") => state.deny_tool_approval(id, payload, auth.api_key_id.clone()),
                    Some("expire") => {
                        state.expire_tool_approval(id, payload, auth.api_key_id.clone())
                    }
                    _ => unreachable!("approval action match is constrained above"),
                };
                match result {
                    Ok(record) => {
                        let (audit_action, audit_outcome) = match action {
                            Some("approve") => ("tool.approval_granted", "approved"),
                            Some("deny") => ("tool.approval_denied", "denied"),
                            Some("expire") => ("tool.approval_expired", "expired"),
                            _ => unreachable!("approval action match is constrained above"),
                        };
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            audit_action,
                            format!("tool_approval:{id}"),
                            audit_outcome,
                            format!(
                                "approval {} fingerprint={} tool={}",
                                record.id, record.fingerprint, record.tool_name
                            ),
                        ));
                        write_json_response(session, StatusCode::OK, &record, &ctx.request_id).await
                    }
                    Err(ApprovalDecisionError::NotFound(message)) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "tool_approval_not_found",
                            message,
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(ApprovalDecisionError::FingerprintMismatch {
                        id,
                        expected,
                        provided,
                    }) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "tool.approval_denied",
                            format!("tool_approval:{id}"),
                            "rejected",
                            format!(
                                "approval fingerprint mismatch expected={expected} provided={provided}"
                            ),
                        ));
                        write_json_error(
                            session,
                            StatusCode::CONFLICT,
                            "tool_approval_fingerprint_mismatch",
                            "approval fingerprint does not match pending tool action",
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(ApprovalDecisionError::Terminal(record)) => {
                        write_json_error(
                            session,
                            StatusCode::CONFLICT,
                            "tool_approval_terminal",
                            format!(
                                "tool approval {} is already terminal with status {:?}",
                                record.id, record.status
                            ),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "tool approval endpoint supports GET, POST approve, and POST deny",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.config.models.clone());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_api_keys(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let id = path.strip_prefix("/admin/v1/api-keys/");
        match (method, id) {
            (&Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let body = AdminList::new(
                            state.config.api_keys.iter().map(admin_api_key).collect(),
                        );
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::GET, Some(id)) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let Some(key) = find_api_key(&state, id) else {
                            return write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "api_key_not_found",
                                format!("api key {id} was not found"),
                                &ctx.request_id,
                            )
                            .await;
                        };
                        let body = AdminApiKeyMutationResponse {
                            object: "api_key",
                            key: admin_api_key(key),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::POST, None) => {
                self.handle_admin_api_key_upsert(session, ctx, headers, None)
                    .await
            }
            (&Method::PUT | &Method::PATCH, Some(id)) => {
                self.handle_admin_api_key_upsert(session, ctx, headers, Some(id))
                    .await
            }
            (&Method::DELETE, Some(id)) => {
                self.handle_admin_api_key_delete(session, ctx, headers, id)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "api key endpoint supports GET, POST, PUT, PATCH, and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_api_key_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_id: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminApiKeyMutation>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    path_id.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON API key object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let key = match api_key_from_mutation(path_id, payload) {
            Ok(key) => key,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    path_id.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_api_key",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let key_id = key.id.clone();
        let response_key = admin_api_key(&key);
        match self.state.upsert_api_key(key) {
            Ok(outcome) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    &key_id,
                    "committed",
                    format!(
                        "api key {key_id} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminApiKeyMutationResponse {
                    object: "api_key",
                    key: response_key,
                };
                write_json_response(
                    session,
                    if path_id.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate API key config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    &key_id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "api_key_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.upsert",
                    &key_id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_api_key",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_api_key_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.delete_api_key(id) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.delete",
                    id,
                    "committed",
                    format!(
                        "api key {id} deleted: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "api_key",
                    id: id.to_string(),
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate API key config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.delete",
                    id,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "api_key_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "api_key_not_found",
                    format!("api key {id} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "api_key.delete",
                    id,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_api_key_delete",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_policies(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let name = path.strip_prefix("/admin/v1/policies/");
        match (method, name) {
            (&Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let body = AdminList::new(state.config.policies.clone());
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::GET, Some(name)) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => {
                        let Some(policy) = find_policy(&state, name) else {
                            return write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "policy_not_found",
                                format!("policy {name} was not found"),
                                &ctx.request_id,
                            )
                            .await;
                        };
                        let body = AdminPolicyMutationResponse {
                            object: "policy",
                            policy: policy.clone(),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::POST, None) => {
                self.handle_admin_policy_upsert(session, ctx, headers, None)
                    .await
            }
            (&Method::PUT | &Method::PATCH, Some(name)) => {
                self.handle_admin_policy_upsert(session, ctx, headers, Some(name))
                    .await
            }
            (&Method::DELETE, Some(name)) => {
                self.handle_admin_policy_delete(session, ctx, headers, name)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "policy endpoint supports GET, POST, PUT, PATCH, and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_policy_upsert(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        path_name: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        let body = match read_request_body(session, 64 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    path_name.unwrap_or("new"),
                    "error",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                ));
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
        let payload = match serde_json::from_slice::<AdminPolicyMutation>(&body) {
            Ok(payload) => payload,
            Err(error) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    path_name.unwrap_or("new"),
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be a JSON policy object",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let policy = match policy_from_mutation(path_name, payload) {
            Ok(policy) => policy,
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    path_name.unwrap_or("new"),
                    "rejected",
                    message.clone(),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_policy",
                    message,
                    &ctx.request_id,
                )
                .await;
            }
        };

        let policy_name = policy.name.clone();
        let response_policy = policy.clone();
        match self.state.upsert_policy(policy) {
            Ok(outcome) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    &policy_name,
                    "committed",
                    format!(
                        "policy {policy_name} committed: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminPolicyMutationResponse {
                    object: "policy",
                    policy: response_policy,
                };
                write_json_response(
                    session,
                    if path_name.is_some() {
                        StatusCode::OK
                    } else {
                        StatusCode::CREATED
                    },
                    &body,
                    &ctx.request_id,
                )
                .await
            }
            Ok(outcome) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate policy config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    &policy_name,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "policy_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.upsert",
                    &policy_name,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_policy",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_policy_delete(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        name: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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

        match self.state.delete_policy(name) {
            Ok(Some(outcome)) if outcome.committed => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.delete",
                    name,
                    "committed",
                    format!(
                        "policy {name} deleted: active_snapshot={} candidate_snapshot={}",
                        outcome.active_snapshot, outcome.candidate_snapshot
                    ),
                ));
                let body = AdminDeleteResponse {
                    object: "policy",
                    id: name.to_string(),
                    deleted: true,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(Some(outcome)) => {
                let reason = outcome
                    .reason
                    .unwrap_or_else(|| "runtime rejected candidate policy config".into());
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.delete",
                    name,
                    "rejected",
                    reason.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "policy_reload_rejected",
                    reason,
                    &ctx.request_id,
                )
                .await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "policy_not_found",
                    format!("policy {name} was not found"),
                    &ctx.request_id,
                )
                .await
            }
            Err(error) => {
                let message = error.to_string();
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "policy.delete",
                    name,
                    "rejected",
                    message.clone(),
                ));
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_policy_delete",
                    message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_tenants(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.tenant_refs());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_metering_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let page = state.metering_events_page(state.admin_pagination(query));
                let body = AdminList::paginated(page.data, page.total, page.offset, page.limit);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_billing_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        self.handle_admin_metering_events(session, ctx, headers, query)
            .await
    }

    pub(super) async fn handle_admin_metering_export_status(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.metering_export_status());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_usage_aggregates(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList::new(state.usage_aggregates());
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

fn api_key_source(key: &crate::config::ApiKey) -> &'static str {
    if key.key_env.is_some() {
        "env"
    } else if key.key_hash.is_some() {
        "hash"
    } else if key.key.is_some() {
        "inline"
    } else {
        "none"
    }
}

fn admin_api_key(key: &crate::config::ApiKey) -> AdminApiKey {
    AdminApiKey {
        id: key.id.clone(),
        name: key.name.clone(),
        enabled: key.enabled,
        key_source: api_key_source(key),
        scopes: key.scopes.clone(),
        allowed_models: key.allowed_models.clone(),
        denied_models: key.denied_models.clone(),
        allowed_providers: key.allowed_providers.clone(),
        denied_providers: key.denied_providers.clone(),
        organization_id: key.organization_id.clone(),
        team_id: key.team_id.clone(),
        project_id: key.project_id.clone(),
        user_id: key.user_id.clone(),
        monthly_token_budget: key.monthly_token_budget,
        request_limit_per_minute: key.request_limit_per_minute,
        expires_at_unix: key.expires_at_unix,
        log_bodies: key.log_bodies.unwrap_or(false),
        cache_enabled: key.cache_enabled,
    }
}

fn admin_gateway_config(
    profile: &crate::config::GatewayConfigProfile,
) -> AdminGatewayConfigProfile {
    AdminGatewayConfigProfile {
        id: profile.id.clone(),
        name: profile.name.clone(),
        revision: profile.revision,
        enabled: profile.enabled,
        api_key_ids: profile.api_key_ids.clone(),
        cache_enabled: profile.cache_enabled,
    }
}

fn admin_plugin(
    plugin: &crate::config::PluginConfig,
    status: Option<crate::extensions::ExtensionStatus>,
) -> AdminPlugin {
    let status = status.unwrap_or(crate::extensions::ExtensionStatus {
        id: plugin.id.clone(),
        kind: plugin.kind.clone(),
        version: plugin.version.clone(),
        manifest: plugin.manifest.clone(),
        compatibility: plugin.compatibility.clone(),
        source: plugin.source.clone(),
        capabilities: Vec::new(),
        tools: Vec::new(),
        enabled: plugin.enabled,
        active: false,
        health: "unknown",
        order: plugin.order,
        last_error: Some("plugin is not loaded".into()),
    });
    AdminPlugin {
        id: plugin.id.clone(),
        kind: plugin.kind.clone(),
        version: status.version.clone(),
        manifest: status.manifest.clone(),
        compatibility: status.compatibility.clone(),
        enabled: plugin.enabled,
        source: plugin.source.clone(),
        order: plugin.order,
        approval_policy: plugin.approval_policy,
        permissions: plugin.permissions.clone(),
        config: redact_plugin_config(&plugin.config),
        capabilities: status.capabilities.clone(),
        tools: status.tools.clone(),
        active: status.active,
        lifecycle: plugin_lifecycle(&status),
        health: status.health,
        last_error: status.last_error.clone(),
    }
}

fn plugin_lifecycle(status: &crate::extensions::ExtensionStatus) -> &'static str {
    if !status.enabled {
        return "disabled";
    }
    if status.active {
        return "enabled";
    }
    match status.health {
        "version_incompatible" => "version_incompatible",
        "failed" => "failed",
        "degraded" => "degraded",
        _ => "registered",
    }
}

fn redact_plugin_config(config: &BTreeMap<String, toml::Value>) -> BTreeMap<String, toml::Value> {
    config
        .iter()
        .map(|(key, value)| {
            let value = if is_plugin_secret_key(key) {
                toml::Value::String("[redacted]".into())
            } else {
                redact_plugin_config_value(value)
            };
            (key.clone(), value)
        })
        .collect()
}

fn redact_plugin_config_value(value: &toml::Value) -> toml::Value {
    match value {
        toml::Value::Array(values) => {
            toml::Value::Array(values.iter().map(redact_plugin_config_value).collect())
        }
        toml::Value::Table(table) => toml::Value::Table(
            table
                .iter()
                .map(|(key, value)| {
                    let value = if is_plugin_secret_key(key) {
                        toml::Value::String("[redacted]".into())
                    } else {
                        redact_plugin_config_value(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn is_plugin_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "secret",
        "token",
        "password",
        "credential",
        "api_key",
        "auth",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn admin_prompt_template(template: &PromptTemplate) -> AdminPromptTemplate {
    AdminPromptTemplate {
        id: template.id.clone(),
        name: template.name.clone(),
        status: template.status,
        target: template.target,
        model: template.model.clone(),
        variables: template.variables.clone(),
        active_revision: active_prompt_template_version(template).map(|version| version.revision),
        versions: template.versions.clone(),
    }
}

fn query_provider_filter(query: Option<&str>) -> Option<String> {
    query.and_then(|query| {
        query.split('&').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == "provider" && !value.trim().is_empty()).then(|| value.to_string())
        })
    })
}

fn provider_catalog_error(
    provider: &Provider,
    error: impl std::fmt::Display,
) -> AdminProviderModelCatalog {
    AdminProviderModelCatalog {
        provider: provider.name.clone(),
        kind: provider.kind.clone(),
        base_url: provider.base_url.clone(),
        enabled: provider.enabled,
        status: "error".into(),
        models: Vec::new(),
        error: Some(error.to_string()),
    }
}

fn find_api_key<'a>(
    state: &'a crate::state::AppState,
    id: &str,
) -> Option<&'a crate::config::ApiKey> {
    state.config.api_keys.iter().find(|key| key.id == id)
}

fn find_gateway_config<'a>(
    state: &'a crate::state::AppState,
    id: &str,
) -> Option<&'a crate::config::GatewayConfigProfile> {
    state
        .config
        .gateway_configs
        .iter()
        .find(|profile| profile.id == id)
}

fn find_prompt_template<'a>(
    state: &'a crate::state::AppState,
    id: &str,
) -> Option<&'a PromptTemplate> {
    state
        .config
        .prompt_templates
        .iter()
        .find(|template| template.id == id)
}

fn prompt_template_id_from_render_path(path: &str) -> Option<&str> {
    let id = path
        .strip_prefix("/v1/prompts/")?
        .strip_suffix("/render")?
        .trim_matches('/');
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some(id)
}

fn api_key_from_mutation(
    path_id: Option<&str>,
    payload: AdminApiKeyMutation,
) -> anyhow::Result<ApiKey> {
    let id = payload
        .id
        .or_else(|| path_id.map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("field id is required"))?;
    if path_id.is_some_and(|path_id| path_id != id) {
        anyhow::bail!("request path id and body id must match");
    }

    Ok(ApiKey {
        id,
        name: payload
            .name
            .ok_or_else(|| anyhow::anyhow!("field name is required"))?,
        key_env: payload.key_env,
        key: payload.key,
        key_hash: payload.key_hash,
        enabled: payload.enabled.unwrap_or(true),
        scopes: payload.scopes.unwrap_or_default(),
        allowed_models: payload.allowed_models.unwrap_or_default(),
        denied_models: payload.denied_models.unwrap_or_default(),
        allowed_providers: payload.allowed_providers.unwrap_or_default(),
        denied_providers: payload.denied_providers.unwrap_or_default(),
        organization_id: payload.organization_id,
        team_id: payload.team_id,
        project_id: payload.project_id,
        user_id: payload.user_id,
        monthly_token_budget: payload.monthly_token_budget,
        request_limit_per_minute: payload.request_limit_per_minute,
        expires_at_unix: payload.expires_at_unix,
        log_bodies: payload.log_bodies,
        cache_enabled: payload.cache_enabled,
    })
}

fn gateway_config_from_mutation(
    path_id: Option<&str>,
    payload: AdminGatewayConfigMutation,
) -> anyhow::Result<crate::config::GatewayConfigProfile> {
    let id = payload
        .id
        .or_else(|| path_id.map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("field id is required"))?;
    if path_id.is_some_and(|path_id| path_id != id) {
        anyhow::bail!("request path id and body id must match");
    }

    Ok(crate::config::GatewayConfigProfile {
        id,
        name: payload
            .name
            .ok_or_else(|| anyhow::anyhow!("field name is required"))?,
        revision: payload.revision.unwrap_or(1),
        enabled: payload.enabled.unwrap_or(true),
        api_key_ids: payload.api_key_ids.unwrap_or_default(),
        cache_enabled: payload.cache_enabled,
    })
}

fn plugin_from_mutation(
    path_id: Option<&str>,
    payload: AdminPluginMutation,
) -> anyhow::Result<crate::config::PluginConfig> {
    let id = payload
        .id
        .or_else(|| path_id.map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("field id is required"))?;
    if path_id.is_some_and(|path_id| path_id != id) {
        anyhow::bail!("request path id and body id must match");
    }

    Ok(crate::config::PluginConfig {
        id,
        kind: payload.kind,
        version: payload.version.unwrap_or_else(|| "0.1.0".into()),
        manifest: payload.manifest.unwrap_or_default(),
        compatibility: payload.compatibility.unwrap_or_default(),
        enabled: payload.enabled.unwrap_or(true),
        source: payload.source.unwrap_or_else(|| "builtin".into()),
        order: payload.order.unwrap_or(10),
        approval_policy: payload.approval_policy.unwrap_or_default(),
        permissions: payload.permissions.unwrap_or_default(),
        config: payload.config.unwrap_or_default(),
    })
}

fn prompt_template_from_mutation(
    path_id: Option<&str>,
    existing: Option<&PromptTemplate>,
    payload: AdminPromptTemplateMutation,
) -> anyhow::Result<PromptTemplate> {
    let id = payload
        .id
        .or_else(|| path_id.map(ToOwned::to_owned))
        .or_else(|| existing.map(|template| template.id.clone()))
        .ok_or_else(|| anyhow::anyhow!("field id is required"))?;
    if path_id.is_some_and(|path_id| path_id != id) {
        anyhow::bail!("request path id and body id must match");
    }

    let mut versions = if let Some(existing) = existing {
        existing.versions.clone()
    } else {
        Vec::new()
    };
    if let Some(mut version) = payload.version {
        normalize_appended_prompt_template_revision(existing, &mut version);
        if versions
            .iter()
            .any(|existing| existing.revision == version.revision)
        {
            anyhow::bail!(
                "prompt template revision {} already exists",
                version.revision
            );
        }
        versions.push(version);
    }
    if let Some(mut replacement_versions) = payload.versions {
        if existing.is_some() {
            for version in &mut replacement_versions {
                normalize_appended_prompt_template_revision(existing, version);
                if versions
                    .iter()
                    .any(|existing| existing.revision == version.revision)
                {
                    anyhow::bail!(
                        "prompt template revision {} already exists",
                        version.revision
                    );
                }
            }
            versions.extend(replacement_versions);
        } else {
            versions = replacement_versions;
        }
    }
    if versions.is_empty() {
        anyhow::bail!("field version or versions is required");
    }

    Ok(PromptTemplate {
        id,
        name: payload
            .name
            .or_else(|| existing.map(|template| template.name.clone()))
            .ok_or_else(|| anyhow::anyhow!("field name is required"))?,
        status: payload
            .status
            .or_else(|| existing.map(|template| template.status))
            .unwrap_or(PromptTemplateStatus::Active),
        target: payload
            .target
            .or_else(|| existing.map(|template| template.target))
            .unwrap_or(PromptTemplateTarget::ChatCompletions),
        model: payload
            .model
            .or_else(|| existing.map(|template| template.model.clone()))
            .ok_or_else(|| anyhow::anyhow!("field model is required"))?,
        variables: payload
            .variables
            .or_else(|| existing.map(|template| template.variables.clone()))
            .unwrap_or_default(),
        versions,
    })
}

fn normalize_appended_prompt_template_revision(
    existing: Option<&PromptTemplate>,
    version: &mut PromptTemplateVersion,
) {
    let Some(existing) = existing else {
        return;
    };
    let max_revision = existing
        .versions
        .iter()
        .map(|version| version.revision)
        .max()
        .unwrap_or(0);
    if version.revision <= max_revision {
        version.revision = max_revision.saturating_add(1);
    }
}

fn find_prompt_template_version(
    template: &PromptTemplate,
    revision: Option<u32>,
) -> Option<&PromptTemplateVersion> {
    if let Some(revision) = revision {
        return template
            .versions
            .iter()
            .find(|version| version.revision == revision);
    }
    active_prompt_template_version(template)
}

fn active_prompt_template_version(template: &PromptTemplate) -> Option<&PromptTemplateVersion> {
    template
        .versions
        .iter()
        .filter(|version| version.status == PromptTemplateVersionStatus::Active)
        .max_by_key(|version| version.revision)
        .or_else(|| {
            template
                .versions
                .iter()
                .max_by_key(|version| version.revision)
        })
}

fn render_prompt_template(
    template: &PromptTemplate,
    version: &PromptTemplateVersion,
    variables: &BTreeMap<String, serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let mut rendered_messages = Vec::with_capacity(version.messages.len());
    for message in &version.messages {
        rendered_messages.push(serde_json::json!({
            "role": message.role,
            "content": render_prompt_template_text(template, &message.content, variables)?,
        }));
    }

    let mut request = serde_json::Map::new();
    request.insert("model".into(), serde_json::json!(template.model));
    match template.target {
        PromptTemplateTarget::ChatCompletions => {
            request.insert(
                "messages".into(),
                serde_json::Value::Array(rendered_messages),
            );
        }
        PromptTemplateTarget::Responses => {
            request.insert("input".into(), serde_json::Value::Array(rendered_messages));
        }
    }
    if let Some(temperature) = version.temperature {
        request.insert("temperature".into(), serde_json::json!(temperature));
    }
    if let Some(top_p) = version.top_p {
        request.insert("top_p".into(), serde_json::json!(top_p));
    }
    if let Some(max_tokens) = version.max_tokens {
        request.insert("max_tokens".into(), serde_json::json!(max_tokens));
    }
    Ok(serde_json::Value::Object(request))
}

fn render_prompt_template_text(
    template: &PromptTemplate,
    content: &str,
    variables: &BTreeMap<String, serde_json::Value>,
) -> anyhow::Result<String> {
    let mut rendered = String::with_capacity(content.len());
    let mut cursor = 0;
    while let Some(start) = content[cursor..].find("{{") {
        let literal_end = cursor + start;
        rendered.push_str(&content[cursor..literal_end]);
        let placeholder_start = literal_end + 2;
        let Some(end) = content[placeholder_start..].find("}}") else {
            anyhow::bail!("unclosed prompt variable");
        };
        let placeholder_end = placeholder_start + end;
        let name = content[placeholder_start..placeholder_end].trim();
        let value = prompt_template_variable_value(template, name, variables)?;
        rendered.push_str(&value);
        cursor = placeholder_end + 2;
    }
    rendered.push_str(&content[cursor..]);
    Ok(rendered)
}

fn prompt_template_variable_value(
    template: &PromptTemplate,
    name: &str,
    variables: &BTreeMap<String, serde_json::Value>,
) -> anyhow::Result<String> {
    let declaration = template
        .variables
        .iter()
        .find(|variable| variable.name == name)
        .ok_or_else(|| anyhow::anyhow!("prompt variable {name} is not declared"))?;
    if let Some(value) = variables.get(name) {
        return Ok(prompt_template_json_value_to_string(value));
    }
    if let Some(default) = &declaration.default {
        return Ok(default.clone());
    }
    if declaration.required {
        anyhow::bail!("required prompt variable {name} is missing");
    }
    Ok(String::new())
}

fn prompt_template_json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => value.to_string(),
    }
}

fn prompt_template_target_name(target: PromptTemplateTarget) -> &'static str {
    match target {
        PromptTemplateTarget::ChatCompletions => "chat_completions",
        PromptTemplateTarget::Responses => "responses",
    }
}

fn prompt_template_variable_schema_hash(template: &PromptTemplate) -> String {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for variable in &template.variables {
        fnv1a64_update(&mut hash, variable.name.as_bytes());
        fnv1a64_update(&mut hash, &[0]);
        fnv1a64_update(
            &mut hash,
            if variable.required {
                b"required"
            } else {
                b"optional"
            },
        );
        fnv1a64_update(&mut hash, &[0]);
        fnv1a64_update(
            &mut hash,
            if variable.default.is_some() {
                b"default"
            } else {
                b"no_default"
            },
        );
        fnv1a64_update(&mut hash, &[0xff]);
    }
    format!("fnv1a64:{hash:016x}")
}

fn fnv1a64_update(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

fn find_policy<'a>(
    state: &'a crate::state::AppState,
    name: &str,
) -> Option<&'a crate::config::PolicyRule> {
    state
        .config
        .policies
        .iter()
        .find(|policy| policy.name == name)
}

fn policy_from_mutation(
    path_name: Option<&str>,
    payload: AdminPolicyMutation,
) -> anyhow::Result<PolicyRule> {
    let name = payload
        .name
        .or_else(|| path_name.map(ToOwned::to_owned))
        .ok_or_else(|| anyhow::anyhow!("field name is required"))?;
    if path_name.is_some_and(|path_name| path_name != name) {
        anyhow::bail!("request path name and body name must match");
    }

    Ok(PolicyRule {
        name,
        effect: payload.effect.unwrap_or_else(|| "deny".into()),
        organization_ids: payload.organization_ids.unwrap_or_default(),
        project_ids: payload.project_ids.unwrap_or_default(),
        api_key_ids: payload.api_key_ids.unwrap_or_default(),
        models: payload.models.unwrap_or_default(),
        providers: payload.providers.unwrap_or_default(),
        code: payload.code.unwrap_or_else(|| "policy_denied".into()),
        message: payload
            .message
            .unwrap_or_else(|| "request denied by policy".into()),
        enabled: payload.enabled.unwrap_or(true),
    })
}

fn config_from_admin_payload(
    payload: &AdminConfigValidateRequest,
    state: &crate::state::SharedAppState,
) -> anyhow::Result<Config> {
    if let Some(raw) = payload.config_toml.as_deref() {
        return Config::from_toml_str(raw);
    }
    if let Some(raw) = payload.config_yaml.as_deref() {
        return Config::from_yaml_str(raw);
    }
    if let Some(raw) = payload.config_caddyfile.as_deref() {
        let file = payload.filename.as_deref().unwrap_or("candidate.Caddyfile");
        return Config::from_caddyfile_str(raw, file);
    }
    if payload.source.as_deref() == Some("file") {
        let path = state
            .source_path()
            .ok_or_else(|| anyhow::anyhow!("runtime was not started from a config file"))?;
        return Config::load(path);
    }
    anyhow::bail!(
        "request body must include config_toml, config_yaml, config_caddyfile, or source=file"
    )
}

fn reload_from_admin_payload(
    payload: &AdminConfigValidateRequest,
    state: &crate::state::SharedAppState,
) -> anyhow::Result<crate::state::RuntimeReloadResult> {
    if payload.source.as_deref() == Some("file") {
        return state.reload_from_source_path();
    }
    Ok(state.reload_process_local(config_from_admin_payload(payload, state)?))
}

fn admin_audit_event_draft(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    admin_audit_event_draft_for_action(ctx, auth, "config.validate", outcome, message)
}

fn parse_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(name, value)| (name == key).then_some(value))
}

fn render_request_log_export_jsonl(records: &[RequestLogExportRecord]) -> String {
    let mut output = String::new();
    for record in records {
        if let Ok(line) = serde_json::to_string(record) {
            output.push_str(&line);
            output.push('\n');
        }
    }
    output
}

fn admin_audit_event_draft_for_action(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    action: impl Into<String>,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    admin_audit_event_draft_for_target(ctx, auth, action, "candidate_config", outcome, message)
}

fn admin_audit_event_draft_for_target(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    action: impl Into<String>,
    target: impl Into<String>,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        agent_run_id: None,
        actor_api_key_id: auth.api_key_id.clone(),
        tenant: auth.tenant_context(),
        action: action.into(),
        target: target.into(),
        outcome: outcome.into(),
        message: message.into(),
    }
}

fn tool_audit_event_draft_for_target(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    agent_run_id: Option<&str>,
    action: impl Into<String>,
    target: impl Into<String>,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    let mut event = admin_audit_event_draft_for_target(ctx, auth, action, target, outcome, message);
    event.agent_run_id = agent_run_id.map(str::to_string);
    event
}
