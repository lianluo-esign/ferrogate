use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use std::io::Read;
use tracing::{info, warn};

use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_response, write_raw_response, write_streaming_response,
    },
};
use ferrogate_core::RequestContext;
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::ModelRegistryError;
use ferrogate_storage::StoredRequestLog;

use super::{
    body::read_request_body,
    dispatch::{dispatch_provider_request, dispatch_provider_streaming_request},
    FerroGateway, ProxyContext,
};

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    #[serde(default)]
    stream: bool,
}

impl FerroGateway {
    pub(super) async fn handle_chat_completions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let auth = match authenticate(&self.state, &headers, "chat.completions", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        let body = read_request_body(session, 1024 * 1024).await?;
        let body_json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    format!("invalid JSON body: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };
        let request: ChatCompletionRequest = match serde_json::from_value(body_json.clone()) {
            Ok(request) => request,
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("invalid chat completion request: {error}"),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if !auth.can_use_model(&request.model) {
            write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_allowed",
                format!("API key is not allowed to use model {}", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let model = match self.state.resolve_model(&request.model) {
            Ok(model) => model,
            Err(ModelRegistryError::ModelDisabled { .. }) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "model_disabled",
                    format!("model {} is disabled", request.model),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
            Err(_) => {
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "model_not_found",
                    format!("unknown model {}", request.model),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if !self.state.can_tenant_use_model(
            &request.model,
            auth.organization_id.as_deref(),
            auth.project_id.as_deref(),
        ) {
            write_json_error(
                session,
                StatusCode::FORBIDDEN,
                "model_not_visible",
                format!("model {} is not visible to this tenant", request.model),
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let routes = self.state.candidate_model_routes(&model);
        let route_count = routes.len();

        for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = self.state.providers.get(&model_route.provider) else {
                write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "provider_not_found",
                    format!("provider {} not found", model_route.provider),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            };

            if !auth.can_use_provider(&provider.name) {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    "provider_not_allowed",
                    format!("API key is not allowed to use provider {}", provider.name),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }

            let policy_request = RequestContext {
                request_id: ctx.request_id.clone(),
                trace_id: ctx.trace_id.clone(),
                route: Some("openai.chat.completions".into()),
                upstream: Some(provider.name.clone()),
                tenant: auth.tenant_context(),
            };
            if let PolicyDecision::Deny { code, message } = self.state.evaluate_policy(
                &policy_request,
                Some(&request.model),
                Some(&provider.name),
            ) {
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    code,
                    message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }

            let prepared = match self.state.prepare_chat_completions(
                provider,
                model_route,
                request.model.clone(),
                request.stream,
                body_json.clone(),
            ) {
                Ok(prepared) => prepared,
                Err(error) if has_next_candidate(candidate_index, route_count) => {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        provider_model = %model_route.provider_model,
                        candidate_index,
                        fallback_count = route_count.saturating_sub(1),
                        error = ?error,
                        "provider adapter failed; trying fallback route"
                    );
                    continue;
                }
                Err(error) => {
                    write_json_error(
                        session,
                        StatusCode::BAD_GATEWAY,
                        "provider_adapter_error",
                        format!("provider adapter failed: {error:?}"),
                        &ctx.request_id,
                    )
                    .await?;
                    return Ok(());
                }
            };

            info!(
                request_id = %ctx.request_id,
                api_key_id = ?auth.api_key_id,
                organization_id = ?auth.organization_id,
                project_id = ?auth.project_id,
                monthly_token_budget = ?auth.monthly_token_budget,
                request_limit_per_minute = ?auth.request_limit_per_minute,
                logical_model = %request.model,
                provider = %provider.name,
                provider_model = %model_route.provider_model,
                candidate_index,
                fallback_count = route_count.saturating_sub(1),
                stream = request.stream,
                "chat completion route planned"
            );

            if request.stream {
                match dispatch_provider_streaming_request(&prepared) {
                    Ok(mut response) => {
                        if response.status.is_client_error() || response.status.is_server_error() {
                            let mut body = response.initial_body;
                            if let Err(error) = response.body.read_to_end(&mut body) {
                                write_json_error(
                                    session,
                                    StatusCode::BAD_GATEWAY,
                                    "provider_dispatch_error",
                                    format!("provider dispatch failed: {error}"),
                                    &ctx.request_id,
                                )
                                .await?;
                                return Ok(());
                            }
                            if self
                                .state
                                .is_provider_status_retryable(
                                    &provider.kind,
                                    response.status.as_u16(),
                                )
                                .unwrap_or(false)
                                && has_next_candidate(candidate_index, route_count)
                            {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    provider_status = response.status.as_u16(),
                                    candidate_index,
                                    "streaming provider returned server error; trying fallback route"
                                );
                                continue;
                            }
                            let normalized = match self.state.normalize_provider_error(
                                &provider.kind,
                                response.status.as_u16(),
                                &response.content_type,
                                &body,
                                &ctx.request_id,
                            ) {
                                Ok(normalized) => normalized,
                                Err(error) => {
                                    write_json_error(
                                        session,
                                        StatusCode::BAD_GATEWAY,
                                        "provider_adapter_error",
                                        format!("provider adapter failed: {error:?}"),
                                        &ctx.request_id,
                                    )
                                    .await?;
                                    return Ok(());
                                }
                            };
                            return write_json_response(
                                session,
                                response.status,
                                &normalized.body,
                                &ctx.request_id,
                            )
                            .await;
                        }

                        return write_streaming_response(
                            session,
                            response.status,
                            &response.content_type,
                            response.initial_body,
                            response.body,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) if has_next_candidate(candidate_index, route_count) => {
                        warn!(
                            request_id = %ctx.request_id,
                            logical_model = %request.model,
                            provider = %provider.name,
                            provider_model = %model_route.provider_model,
                            candidate_index,
                            error = %error,
                            "streaming provider dispatch failed; trying fallback route"
                        );
                        continue;
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::BAD_GATEWAY,
                            "provider_dispatch_error",
                            format!("provider dispatch failed: {error}"),
                            &ctx.request_id,
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }

            match dispatch_provider_request(&prepared) {
                Ok(response) => {
                    if response.status.is_client_error() || response.status.is_server_error() {
                        if self
                            .state
                            .is_provider_status_retryable(&provider.kind, response.status.as_u16())
                            .unwrap_or(false)
                            && has_next_candidate(candidate_index, route_count)
                        {
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                provider_status = response.status.as_u16(),
                                candidate_index,
                                "provider returned server error; trying fallback route"
                            );
                            continue;
                        }
                        let normalized = match self.state.normalize_provider_error(
                            &provider.kind,
                            response.status.as_u16(),
                            &response.content_type,
                            &response.body,
                            &ctx.request_id,
                        ) {
                            Ok(normalized) => normalized,
                            Err(error) => {
                                write_json_error(
                                    session,
                                    StatusCode::BAD_GATEWAY,
                                    "provider_adapter_error",
                                    format!("provider adapter failed: {error:?}"),
                                    &ctx.request_id,
                                )
                                .await?;
                                return Ok(());
                            }
                        };
                        return write_json_response(
                            session,
                            response.status,
                            &normalized.body,
                            &ctx.request_id,
                        )
                        .await;
                    }

                    if let Ok(Some(usage)) = self
                        .state
                        .extract_provider_usage(&provider.kind, &response.body)
                    {
                        info!(
                            request_id = %ctx.request_id,
                            logical_model = %request.model,
                            provider = %provider.name,
                            provider_model = %model_route.provider_model,
                            prompt_tokens = ?usage.prompt_tokens,
                            completion_tokens = ?usage.completion_tokens,
                            total_tokens = ?usage.total_tokens,
                            "provider usage extracted"
                        );
                        if let Err(error) = self.state.record_billing_event(
                            &policy_request,
                            &request.model,
                            &provider.name,
                            &model_route.provider_model,
                            &usage,
                            response.status.as_u16(),
                        ) {
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                error_code = %error.code,
                                "billing event write failed"
                            );
                        }
                    }
                    self.state.record_request_log(StoredRequestLog {
                        request_id: ctx.request_id.clone(),
                        trace_id: ctx.trace_id.clone(),
                        tenant: policy_request.tenant.clone(),
                        route: policy_request.route.clone(),
                        provider: Some(provider.name.clone()),
                        logical_model: Some(request.model.clone()),
                        provider_model: Some(model_route.provider_model.clone()),
                        status_code: response.status.as_u16(),
                        error_code: None,
                        prompt_recorded: false,
                        response_recorded: false,
                        started_at_unix: None,
                        completed_at_unix: None,
                    });

                    return write_raw_response(
                        session,
                        response.status,
                        &response.content_type,
                        response.body.into(),
                        &ctx.request_id,
                    )
                    .await;
                }
                Err(error) if has_next_candidate(candidate_index, route_count) => {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        provider_model = %model_route.provider_model,
                        candidate_index,
                        error = %error,
                        "provider dispatch failed; trying fallback route"
                    );
                    continue;
                }
                Err(error) => {
                    write_json_error(
                        session,
                        StatusCode::BAD_GATEWAY,
                        "provider_dispatch_error",
                        format!("provider dispatch failed: {error}"),
                        &ctx.request_id,
                    )
                    .await?;
                    return Ok(());
                }
            };
        }

        write_json_error(
            session,
            StatusCode::BAD_GATEWAY,
            "provider_dispatch_error",
            "provider dispatch failed for all model routes",
            &ctx.request_id,
        )
        .await
    }
}

fn has_next_candidate(candidate_index: usize, route_count: usize) -> bool {
    candidate_index + 1 < route_count
}
