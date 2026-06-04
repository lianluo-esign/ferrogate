use crate::dashboard::ADMIN_DASHBOARD_HTML;
use bytes::Bytes;
use ferrogate_observability::render_prometheus_text;
use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use crate::{
    auth::authenticate,
    config::{config_snapshot_id, ApiKey, Config, PolicyRule},
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, write_raw_response,
        AdminAcmeStatus, AdminApiKey, AdminApiKeyMutation, AdminApiKeyMutationResponse,
        AdminConfigReloadResponse, AdminConfigValidateRequest, AdminConfigValidateResponse,
        AdminDeleteResponse, AdminList, AdminPolicyMutation, AdminPolicyMutationResponse,
        AdminProvider, AdminStatus, AdminTenantRef, HealthResponse, OpenAiModel, OpenAiModelList,
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
                let body = AdminList::new(
                    state
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
                let body = AdminList::new(
                    state
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

    pub(super) async fn handle_admin_billing_events(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(_) => {
                let page = state.billing_events_page(state.admin_pagination(query));
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
    }
}

fn find_api_key<'a>(
    state: &'a crate::state::AppState,
    id: &str,
) -> Option<&'a crate::config::ApiKey> {
    state.config.api_keys.iter().find(|key| key.id == id)
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
    })
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
        actor_api_key_id: auth.api_key_id.clone(),
        action: action.into(),
        target: target.into(),
        outcome: outcome.into(),
        message: message.into(),
    }
}
