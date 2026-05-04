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
        AdminConfigValidateRequest, AdminConfigValidateResponse, AdminList, AdminProvider,
        AdminStatus, AdminTenantRef, HealthResponse, OpenAiModel, OpenAiModelList,
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
        match authenticate(&self.state, headers, "models.read", &ctx.request_id) {
            Ok(_) => {
                let data = self
                    .state
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let status = AdminStatus {
                    service: env!("CARGO_PKG_NAME"),
                    version: env!("CARGO_PKG_VERSION"),
                    runtime: "pingora",
                    snapshot: config_snapshot_id(&self.state.config),
                    providers: self.state.config.providers.len(),
                    enabled_providers: self
                        .state
                        .config
                        .providers
                        .iter()
                        .filter(|p| p.enabled)
                        .count(),
                    models: self.state.config.models.len(),
                    enabled_models: self
                        .state
                        .config
                        .models
                        .iter()
                        .filter(|m| m.enabled)
                        .count(),
                    api_keys: self.state.config.api_keys.len(),
                    upstreams: self.state.config.upstreams.len(),
                    enabled_upstreams: self
                        .state
                        .config
                        .upstreams
                        .iter()
                        .filter(|u| u.enabled)
                        .count(),
                    routes: self.state.config.routes.len(),
                    enabled_routes: self
                        .state
                        .config
                        .routes
                        .iter()
                        .filter(|r| r.enabled)
                        .count(),
                    auth_required: self.state.auth_required(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = render_prometheus_text(&self.state.prometheus_metrics_snapshot());
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.request_logs(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.audit_events(),
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

        let auth = match authenticate(&self.state, headers, "admin.write", &ctx.request_id) {
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
                self.state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "error",
                    format!("invalid request body: {error}"),
                ));
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "request body must be JSON with config_toml",
                    &ctx.request_id,
                )
                .await;
            }
        };

        let response = match Config::from_toml_str(&payload.config_toml) {
            Ok(candidate) => {
                let snapshot = config_snapshot_id(&candidate);
                self.state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "accepted",
                    format!("candidate config valid: snapshot={snapshot}"),
                ));
                AdminConfigValidateResponse {
                    valid: true,
                    snapshot: Some(snapshot),
                    error: None,
                }
            }
            Err(error) => {
                let message = error.to_string();
                self.state.record_admin_audit_event(admin_audit_event_draft(
                    ctx,
                    &auth,
                    "rejected",
                    message.clone(),
                ));
                AdminConfigValidateResponse {
                    valid: false,
                    snapshot: None,
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self
                        .state
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

    pub(super) async fn handle_admin_models(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.config.models.clone(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self
                        .state
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
                            allowed_providers: key.allowed_providers.clone(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.config.policies.clone(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self
                        .state
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.billing_events(),
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
        match authenticate(&self.state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let body = AdminList {
                    object: "list",
                    data: self.state.usage_aggregates(),
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

fn admin_audit_event_draft(
    ctx: &ProxyContext,
    auth: &crate::auth::AuthContext,
    outcome: &str,
    message: impl Into<String>,
) -> AdminAuditEventDraft {
    AdminAuditEventDraft {
        request_id: ctx.request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        actor_api_key_id: auth.api_key_id.clone(),
        action: "config.validate".into(),
        target: "candidate_config".into(),
        outcome: outcome.into(),
        message: message.into(),
    }
}
