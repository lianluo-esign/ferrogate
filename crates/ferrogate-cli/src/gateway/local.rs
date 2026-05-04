use crate::dashboard::ADMIN_DASHBOARD_HTML;
use bytes::Bytes;
use ferrogate_observability::render_prometheus_text;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    auth::authenticate,
    config::{config_snapshot_id, Config},
    responses::{
        write_json_error, write_json_response, write_raw_response, AdminApiKey,
        AdminConfigReloadResponse, AdminConfigValidateRequest, AdminConfigValidateResponse,
        AdminList, AdminProvider, AdminStatus, AdminTenantRef, HealthResponse, OpenAiModel,
        OpenAiModelList,
    },
    state::AdminAuditEventDraft,
};

use super::body::read_request_body;
use super::{FerroGateway, ProxyContext};

impl FerroGateway {
    pub(super) async fn handle_healthz(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
    ) -> PingoraResult<()> {
        let body = HealthResponse {
            status: "ok",
            service: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            runtime: "pingora",
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
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
                    service: env!("CARGO_PKG_NAME"),
                    version: env!("CARGO_PKG_VERSION"),
                    runtime: "pingora",
                    snapshot: config_snapshot_id(&state.config),
                    providers: state.config.providers.len(),
                    enabled_providers: state.config.providers.iter().filter(|p| p.enabled).count(),
                    models: state.config.models.len(),
                    enabled_models: state.config.models.iter().filter(|m| m.enabled).count(),
                    api_keys: state.config.api_keys.len(),
                    upstreams: state.config.upstreams.len(),
                    enabled_upstreams: state.config.upstreams.iter().filter(|u| u.enabled).count(),
                    routes: state.config.routes.len(),
                    enabled_routes: state.config.routes.iter().filter(|r| r.enabled).count(),
                    auth_required: state.auth_required(),
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
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.request_logs(),
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

    pub(super) async fn handle_admin_audit_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.audit_events(),
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

        let body = read_request_body(session, 256 * 1024).await?;
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
                    "request body must be JSON with config_toml, config_caddyfile, or source=file",
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

        let body = read_request_body(session, 256 * 1024).await?;
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
                    "request body must be JSON with config_toml, config_caddyfile, or source=file",
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

    pub(super) async fn handle_admin_providers(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state
                        .config
                        .providers
                        .iter()
                        .map(|provider| AdminProvider {
                            name: provider.name.clone(),
                            kind: provider.kind.clone(),
                            base_url: provider.base_url.clone(),
                            has_api_key: provider.api_key_env.is_some(),
                            enabled: provider.enabled,
                        })
                        .collect(),
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

    pub(super) async fn handle_admin_provider_health(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.provider_health_checks(),
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

    pub(super) async fn handle_admin_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.config.models.clone(),
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

    pub(super) async fn handle_admin_api_keys(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state
                        .config
                        .api_keys
                        .iter()
                        .map(|key| AdminApiKey {
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
                        })
                        .collect(),
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

    pub(super) async fn handle_admin_policies(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.config.policies.clone(),
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

    pub(super) async fn handle_admin_tenants(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state
                        .config
                        .api_keys
                        .iter()
                        .filter(|key| {
                            key.organization_id.is_some()
                                || key.team_id.is_some()
                                || key.project_id.is_some()
                                || key.user_id.is_some()
                        })
                        .map(|key| AdminTenantRef {
                            organization_id: key.organization_id.clone(),
                            team_id: key.team_id.clone(),
                            project_id: key.project_id.clone(),
                            user_id: key.user_id.clone(),
                            api_key_id: key.id.clone(),
                        })
                        .collect(),
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

    pub(super) async fn handle_admin_billing_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.billing_events(),
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

    pub(super) async fn handle_admin_usage_aggregates(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: state.usage_aggregates(),
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

fn config_from_admin_payload(
    payload: &AdminConfigValidateRequest,
    state: &crate::state::SharedAppState,
) -> anyhow::Result<Config> {
    if let Some(raw) = payload.config_toml.as_deref() {
        return Config::from_toml_str(raw);
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
    anyhow::bail!("request body must include config_toml, config_caddyfile, or source=file")
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

fn admin_audit_event_draft_for_action(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    action: impl Into<String>,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        actor_api_key_id: auth.api_key_id.clone(),
        action: action.into(),
        target: "candidate_config".into(),
        outcome: outcome.into(),
        message: message.into(),
    }
}
