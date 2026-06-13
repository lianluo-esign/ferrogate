// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use std::io::Read;
use tracing::{info, warn};

use crate::{
    auth::authenticate,
    config::Provider,
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, write_raw_response,
        write_streaming_response,
    },
    state::{AppState, GatewayConfigResolveError, ToolInjectionContext},
};
use ferrogate_billing::TokenUsage as BillingTokenUsage;
use ferrogate_core::{RequestContext, TenantContext};
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::{ModelRegistryError, ModelRoute, ProviderHttpRequest};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AiEndpoint {
    ChatCompletions,
    Responses,
}

impl AiEndpoint {
    fn scope(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat.completions",
            Self::Responses => "responses.create",
        }
    }

    fn route(self) -> &'static str {
        match self {
            Self::ChatCompletions => "openai.chat.completions",
            Self::Responses => "openai.responses",
        }
    }

    fn invalid_request_label(self) -> &'static str {
        match self {
            Self::ChatCompletions => "invalid chat completion request",
            Self::Responses => "invalid responses request",
        }
    }
}

const DEFAULT_COMPLETION_TOKEN_RESERVATION: u64 = 512;
const GATEWAY_CONFIG_HEADER: &str = "x-ferrogate-config";

impl FerroGateway {
    pub(super) async fn handle_chat_completions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        self.handle_ai_request(session, ctx, headers, AiEndpoint::ChatCompletions)
            .await
    }

    pub(super) async fn handle_responses(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        self.handle_ai_request(session, ctx, headers, AiEndpoint::Responses)
            .await
    }

    async fn handle_ai_request(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
        endpoint: AiEndpoint,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, &headers, endpoint.scope(), &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: TenantContext::default(),
                        logical_model: None,
                        provider: None,
                        status: error.status,
                        error_code: error.code,
                    },
                );
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
        let gateway_config = match requested_gateway_config_id(&headers) {
            Ok(profile_id) => {
                match state.resolve_gateway_config_profile(profile_id, auth.api_key_id.as_deref()) {
                    Ok(profile) => profile,
                    Err(error) => {
                        let (status, code, message) = gateway_config_error_response(error);
                        self.record_ai_error_log(
                            endpoint,
                            ctx,
                            AiErrorLog {
                                tenant: auth.tenant_context(),
                                logical_model: None,
                                provider: None,
                                status,
                                error_code: code,
                            },
                        );
                        write_json_error(session, status, code, message, &ctx.request_id).await?;
                        return Ok(());
                    }
                }
            }
            Err(message) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: None,
                        provider: None,
                        status: StatusCode::BAD_REQUEST,
                        error_code: "invalid_gateway_config_header",
                    },
                );
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_gateway_config_header",
                    message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if state.is_draining() {
            self.record_ai_error_log(
                endpoint,
                ctx,
                AiErrorLog {
                    tenant: auth.tenant_context(),
                    logical_model: None,
                    provider: None,
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    error_code: "node_draining",
                },
            );
            write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "node_draining",
                "gateway node is draining and is not accepting new AI requests",
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let body = match read_request_body(session, 1024 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: None,
                        provider: None,
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        error_code: "payload_too_large",
                    },
                );
                write_json_error_and_close(
                    session,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!(
                        "request body exceeds maximum size of {} bytes",
                        limit.max_bytes
                    ),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };
        let body_json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: None,
                        provider: None,
                        status: StatusCode::BAD_REQUEST,
                        error_code: "invalid_json",
                    },
                );
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
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: None,
                        provider: None,
                        status: StatusCode::BAD_REQUEST,
                        error_code: "invalid_request",
                    },
                );
                write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    format!("{}: {error}", endpoint.invalid_request_label()),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };

        if !auth.can_use_model(&request.model) {
            self.record_ai_error_log(
                endpoint,
                ctx,
                AiErrorLog {
                    tenant: auth.tenant_context(),
                    logical_model: Some(&request.model),
                    provider: None,
                    status: StatusCode::FORBIDDEN,
                    error_code: "model_not_allowed",
                },
            );
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

        let model = match state.resolve_model(&request.model) {
            Ok(model) => model,
            Err(ModelRegistryError::ModelDisabled { .. }) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: Some(&request.model),
                        provider: None,
                        status: StatusCode::BAD_REQUEST,
                        error_code: "model_disabled",
                    },
                );
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
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: Some(&request.model),
                        provider: None,
                        status: StatusCode::BAD_REQUEST,
                        error_code: "model_not_found",
                    },
                );
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

        if !state.can_tenant_use_model(
            &request.model,
            auth.organization_id.as_deref(),
            auth.project_id.as_deref(),
        ) {
            self.record_ai_error_log(
                endpoint,
                ctx,
                AiErrorLog {
                    tenant: auth.tenant_context(),
                    logical_model: Some(&request.model),
                    provider: None,
                    status: StatusCode::FORBIDDEN,
                    error_code: "model_not_visible",
                },
            );
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

        let estimated_usage = estimate_chat_completion_usage(&body_json);
        let routes = state.candidate_model_routes(&model, Some(&estimated_usage));
        let route_count = routes.len();
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let provider_response_body_max_bytes = state.provider_response_body_max_bytes();
        let body_text = body_json.to_string();
        let mut token_reservation = None;

        'routes: for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = state.providers.get(&model_route.provider) else {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: Some(&request.model),
                        provider: Some(&model_route.provider),
                        status: StatusCode::BAD_GATEWAY,
                        error_code: "provider_not_found",
                    },
                );
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

            if !state.provider_circuit_allows(&provider.name) {
                if has_next_candidate(candidate_index, route_count) {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        provider_model = %model_route.provider_model,
                        candidate_index,
                        "provider circuit breaker is open; trying fallback route"
                    );
                    continue;
                }

                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: Some(&request.model),
                        provider: Some(&provider.name),
                        status: StatusCode::SERVICE_UNAVAILABLE,
                        error_code: "provider_circuit_open",
                    },
                );
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_circuit_open",
                    format!("provider {} circuit breaker is open", provider.name),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }

            if !auth.can_use_provider(&provider.name) {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: auth.tenant_context(),
                        logical_model: Some(&request.model),
                        provider: Some(&provider.name),
                        status: StatusCode::FORBIDDEN,
                        error_code: "provider_not_allowed",
                    },
                );
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
                route: Some(endpoint.route().into()),
                upstream: Some(provider.name.clone()),
                tenant: auth.tenant_context(),
            };
            if let Some(guardrail) = state.match_request_guardrail(
                &policy_request.tenant,
                Some(&request.model),
                Some(&provider.name),
                &body_text,
            ) {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: policy_request.tenant.clone(),
                        logical_model: Some(&request.model),
                        provider: Some(&provider.name),
                        status: StatusCode::FORBIDDEN,
                        error_code: &guardrail.code,
                    },
                );
                state.record_admin_audit_event(crate::state::AdminAuditEventDraft {
                    request_id: ctx.request_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    actor_api_key_id: auth.api_key_id.clone(),
                    tenant: auth.tenant_context(),
                    action: "guardrail.deny".into(),
                    target: guardrail.rule_id.clone(),
                    outcome: "blocked".into(),
                    message: format!(
                        "guardrail {} blocked model {} provider {} via keyword {}",
                        guardrail.rule_name, request.model, provider.name, guardrail.keyword
                    ),
                });
                write_json_error(
                    session,
                    StatusCode::FORBIDDEN,
                    &guardrail.code,
                    &guardrail.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
            if let PolicyDecision::Deny { code, message } =
                state.evaluate_policy(&policy_request, Some(&request.model), Some(&provider.name))
            {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: policy_request.tenant.clone(),
                        logical_model: Some(&request.model),
                        provider: Some(&provider.name),
                        status: StatusCode::FORBIDDEN,
                        error_code: &code,
                    },
                );
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

            let cache_key = if request.stream {
                None
            } else {
                state
                    .ai_cache_enabled(
                        auth.api_key_id.as_deref(),
                        &request.model,
                        &provider.name,
                        gateway_config.as_ref(),
                    )
                    .then(|| {
                        state.ai_response_cache_key(
                            endpoint.route(),
                            &policy_request.tenant,
                            &request.model,
                            &provider.name,
                            &model_route.provider_model,
                            &body_json,
                        )
                    })
            };
            if let Some(cache_key) = cache_key.as_ref() {
                if let Some(cached) = state.lookup_ai_response_cache(cache_key) {
                    state.record_ai_cache_hit();
                    let record_bodies = auth.can_record_bodies(state.config.telemetry.log_bodies);
                    state.record_request_log(StoredRequestLog {
                        request_id: ctx.request_id.clone(),
                        trace_id: ctx.trace_id.clone(),
                        cluster_id: None,
                        node_id: None,
                        tenant: policy_request.tenant.clone(),
                        route: policy_request.route.clone(),
                        provider: Some(provider.name.clone()),
                        logical_model: Some(request.model.clone()),
                        provider_model: Some(model_route.provider_model.clone()),
                        gateway_config_id: gateway_config
                            .as_ref()
                            .map(|profile| profile.id.clone()),
                        gateway_config_revision: gateway_config
                            .as_ref()
                            .map(|profile| profile.revision),
                        status_code: cached.status_code,
                        error_code: None,
                        prompt_recorded: record_bodies,
                        response_recorded: record_bodies,
                        prompt_body: record_bodies.then(|| body_json.to_string()),
                        response_body: record_bodies.then(|| {
                            String::from_utf8_lossy(&cached.body)
                                .chars()
                                .take(16 * 1024)
                                .collect()
                        }),
                        cache_status: Some("hit".into()),
                        started_at_unix: None,
                        completed_at_unix: None,
                    });
                    return write_raw_response(
                        session,
                        StatusCode::from_u16(cached.status_code).unwrap_or(StatusCode::OK),
                        &cached.content_type,
                        cached.body.into(),
                        &ctx.request_id,
                    )
                    .await;
                }
                state.record_ai_cache_miss();
            }

            if token_reservation.is_none() {
                if let (Some(api_key_id), Some(budget)) =
                    (auth.api_key_id.as_deref(), auth.monthly_token_budget)
                {
                    match state.try_reserve_api_key_tokens(
                        api_key_id,
                        budget,
                        estimated_usage.total_tokens,
                    ) {
                        Ok(Some(reservation)) => {
                            info!(
                                request_id = %ctx.request_id,
                                api_key_id = %api_key_id,
                                logical_model = %request.model,
                                estimated_tokens = reservation.tokens(),
                                "API key token budget reserved"
                            );
                            token_reservation = Some(reservation);
                        }
                        Ok(None) => {
                            self.record_ai_error_log(
                                endpoint,
                                ctx,
                                AiErrorLog {
                                    tenant: policy_request.tenant.clone(),
                                    logical_model: Some(&request.model),
                                    provider: Some(&provider.name),
                                    status: StatusCode::TOO_MANY_REQUESTS,
                                    error_code: "token_budget_exceeded",
                                },
                            );
                            write_json_error(
                                session,
                                StatusCode::TOO_MANY_REQUESTS,
                                "token_budget_exceeded",
                                "API key token budget cannot cover the estimated request usage",
                                &ctx.request_id,
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(error) => {
                            self.record_ai_error_log(
                                endpoint,
                                ctx,
                                AiErrorLog {
                                    tenant: policy_request.tenant.clone(),
                                    logical_model: Some(&request.model),
                                    provider: Some(&provider.name),
                                    status: StatusCode::SERVICE_UNAVAILABLE,
                                    error_code: "governance_counter_unavailable",
                                },
                            );
                            write_json_error(
                                session,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "governance_counter_unavailable",
                                format!("gateway counter backend is unavailable: {error}"),
                                &ctx.request_id,
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                }
            }

            let prepared = match prepare_ai_provider_request(
                &state,
                AiProviderRequestInput {
                    endpoint,
                    provider,
                    model_route,
                    tenant: &policy_request.tenant,
                    api_key_id: auth.api_key_id.as_deref(),
                    route: policy_request.route.as_deref(),
                    logical_model: request.model.clone(),
                    stream: request.stream,
                    body: body_json.clone(),
                },
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
                    self.record_ai_error_log(
                        endpoint,
                        ctx,
                        AiErrorLog {
                            tenant: policy_request.tenant.clone(),
                            logical_model: Some(&request.model),
                            provider: Some(&provider.name),
                            status: StatusCode::BAD_GATEWAY,
                            error_code: "provider_adapter_error",
                        },
                    );
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

            match endpoint {
                AiEndpoint::ChatCompletions => info!(
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
                    provider_dispatch_timeout_secs = dispatch_timeout.as_secs(),
                    provider_dispatch_max_retries = max_dispatch_retries,
                    stream = request.stream,
                    "chat completion route planned"
                ),
                AiEndpoint::Responses => info!(
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
                    provider_dispatch_timeout_secs = dispatch_timeout.as_secs(),
                    provider_dispatch_max_retries = max_dispatch_retries,
                    stream = request.stream,
                    "responses route planned"
                ),
            }

            if request.stream {
                let mut attempt = 0;
                loop {
                    match dispatch_provider_streaming_request(prepared.clone(), dispatch_timeout)
                        .await
                    {
                        Ok(mut response) => {
                            if response.status.is_client_error()
                                || response.status.is_server_error()
                            {
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
                                let retryable_status = state
                                    .is_provider_status_retryable(
                                        &provider.kind,
                                        response.status.as_u16(),
                                    )
                                    .unwrap_or(false);
                                if retryable_status {
                                    state.record_provider_failure(&provider.name);
                                }
                                if retryable_status && attempt < max_dispatch_retries {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_model = %model_route.provider_model,
                                        provider_status = response.status.as_u16(),
                                        attempt,
                                        max_retries = max_dispatch_retries,
                                        "streaming provider returned retryable status; retrying provider"
                                    );
                                    attempt += 1;
                                    continue;
                                }
                                if retryable_status
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
                                    continue 'routes;
                                }
                                let normalized = match state.normalize_provider_error(
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

                            state.record_provider_success(&provider.name);
                            if let Err(error) = state.record_estimated_billing_event(
                                &policy_request,
                                &request.model,
                                &provider.name,
                                &model_route.provider_model,
                                &estimated_usage,
                                response.status.as_u16(),
                            ) {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    error_code = %error.code,
                                    "estimated streaming billing event write failed"
                                );
                            }
                            if let Some(reservation) = token_reservation.take() {
                                reservation.settle();
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
                        Err(error) => {
                            state.record_provider_failure(&provider.name);
                            if attempt < max_dispatch_retries {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    attempt,
                                    max_retries = max_dispatch_retries,
                                    error = %error,
                                    "streaming provider dispatch failed; retrying provider"
                                );
                                attempt += 1;
                                continue;
                            }
                            if has_next_candidate(candidate_index, route_count) {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    candidate_index,
                                    error = %error,
                                    "streaming provider dispatch failed; trying fallback route"
                                );
                                continue 'routes;
                            }
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
            }

            let mut attempt = 0;
            loop {
                match dispatch_provider_request(
                    prepared.clone(),
                    dispatch_timeout,
                    provider_response_body_max_bytes,
                )
                .await
                {
                    Ok(response) => {
                        if response.status.is_client_error() || response.status.is_server_error() {
                            let retryable_status = state
                                .is_provider_status_retryable(
                                    &provider.kind,
                                    response.status.as_u16(),
                                )
                                .unwrap_or(false);
                            if retryable_status {
                                state.record_provider_failure(&provider.name);
                            }
                            if retryable_status && attempt < max_dispatch_retries {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    provider_status = response.status.as_u16(),
                                    attempt,
                                    max_retries = max_dispatch_retries,
                                    "provider returned retryable status; retrying provider"
                                );
                                attempt += 1;
                                continue;
                            }
                            if retryable_status && has_next_candidate(candidate_index, route_count)
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
                                continue 'routes;
                            }
                            let normalized = match state.normalize_provider_error(
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

                        state.record_provider_success(&provider.name);
                        if let Ok(Some(usage)) =
                            state.extract_provider_usage(&provider.kind, &response.body)
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
                            if let Err(error) = state.record_billing_event(
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
                        } else if let Err(error) = state.record_estimated_billing_event(
                            &policy_request,
                            &request.model,
                            &provider.name,
                            &model_route.provider_model,
                            &estimated_usage,
                            response.status.as_u16(),
                        ) {
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                error_code = %error.code,
                                "estimated billing event write failed"
                            );
                        }
                        if let Some(reservation) = token_reservation.take() {
                            reservation.settle();
                        }
                        let record_bodies =
                            auth.can_record_bodies(state.config.telemetry.log_bodies);
                        state.record_request_log(StoredRequestLog {
                            request_id: ctx.request_id.clone(),
                            trace_id: ctx.trace_id.clone(),
                            cluster_id: None,
                            node_id: None,
                            tenant: policy_request.tenant.clone(),
                            route: policy_request.route.clone(),
                            provider: Some(provider.name.clone()),
                            logical_model: Some(request.model.clone()),
                            provider_model: Some(model_route.provider_model.clone()),
                            gateway_config_id: gateway_config
                                .as_ref()
                                .map(|profile| profile.id.clone()),
                            gateway_config_revision: gateway_config
                                .as_ref()
                                .map(|profile| profile.revision),
                            status_code: response.status.as_u16(),
                            error_code: None,
                            prompt_recorded: record_bodies,
                            response_recorded: record_bodies,
                            prompt_body: record_bodies.then(|| body_json.to_string()),
                            response_body: record_bodies.then(|| {
                                String::from_utf8_lossy(&response.body)
                                    .chars()
                                    .take(16 * 1024)
                                    .collect()
                            }),
                            cache_status: cache_key.as_ref().map(|_| "miss".to_string()),
                            started_at_unix: None,
                            completed_at_unix: None,
                        });
                        if let Some(cache_key) = cache_key {
                            state.store_ai_response_cache(
                                cache_key,
                                crate::state::AiCachedResponse {
                                    status_code: response.status.as_u16(),
                                    content_type: response.content_type.clone(),
                                    body: response.body.clone(),
                                },
                            );
                        }

                        return write_raw_response(
                            session,
                            response.status,
                            &response.content_type,
                            response.body.into(),
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) => {
                        state.record_provider_failure(&provider.name);
                        if attempt < max_dispatch_retries {
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                attempt,
                                max_retries = max_dispatch_retries,
                                error = %error,
                                "provider dispatch failed; retrying provider"
                            );
                            attempt += 1;
                            continue;
                        }
                        if has_next_candidate(candidate_index, route_count) {
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                candidate_index,
                                error = %error,
                                "provider dispatch failed; trying fallback route"
                            );
                            continue 'routes;
                        }
                        self.record_ai_error_log(
                            endpoint,
                            ctx,
                            AiErrorLog {
                                tenant: auth.tenant_context(),
                                logical_model: Some(&request.model),
                                provider: None,
                                status: StatusCode::BAD_GATEWAY,
                                error_code: "provider_dispatch_error",
                            },
                        );
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

    fn record_ai_error_log(&self, endpoint: AiEndpoint, ctx: &ProxyContext, log: AiErrorLog<'_>) {
        self.state.record_request_log(StoredRequestLog {
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            cluster_id: None,
            node_id: None,
            tenant: log.tenant,
            route: Some(endpoint.route().into()),
            provider: log.provider.map(ToOwned::to_owned),
            logical_model: log.logical_model.map(ToOwned::to_owned),
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: log.status.as_u16(),
            error_code: Some(log.error_code.to_string()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: None,
            completed_at_unix: None,
        });
    }
}

struct AiErrorLog<'a> {
    tenant: TenantContext,
    logical_model: Option<&'a str>,
    provider: Option<&'a str>,
    status: StatusCode,
    error_code: &'a str,
}

struct AiProviderRequestInput<'a> {
    endpoint: AiEndpoint,
    provider: &'a Provider,
    model_route: &'a ModelRoute,
    tenant: &'a TenantContext,
    api_key_id: Option<&'a str>,
    route: Option<&'a str>,
    logical_model: String,
    stream: bool,
    body: serde_json::Value,
}

fn has_next_candidate(candidate_index: usize, route_count: usize) -> bool {
    candidate_index + 1 < route_count
}

fn requested_gateway_config_id(headers: &HeaderMap) -> Result<Option<&str>, String> {
    let Some(value) = headers.get(GATEWAY_CONFIG_HEADER) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        format!("{GATEWAY_CONFIG_HEADER} must be valid visible ASCII/UTF-8 header text")
    })?;
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn gateway_config_error_response(
    error: GatewayConfigResolveError,
) -> (StatusCode, &'static str, String) {
    match error {
        GatewayConfigResolveError::NotFound(id) => (
            StatusCode::BAD_REQUEST,
            "gateway_config_not_found",
            format!("gateway config profile {id} was not found"),
        ),
        GatewayConfigResolveError::Disabled { id, revision } => (
            StatusCode::FORBIDDEN,
            "gateway_config_disabled",
            format!("gateway config profile {id} revision {revision} is disabled"),
        ),
        GatewayConfigResolveError::NotAllowed { id, revision } => (
            StatusCode::FORBIDDEN,
            "gateway_config_not_allowed",
            format!(
                "API key is not allowed to use gateway config profile {id} revision {revision}"
            ),
        ),
    }
}

fn prepare_ai_provider_request(
    state: &AppState,
    input: AiProviderRequestInput<'_>,
) -> Result<ProviderHttpRequest, ferrogate_providers::AdapterError> {
    match input.endpoint {
        AiEndpoint::ChatCompletions => state.prepare_chat_completions(
            input.provider,
            input.model_route,
            ToolInjectionContext {
                tenant: input.tenant,
                api_key_id: input.api_key_id,
                route: input.route,
            },
            input.logical_model,
            input.stream,
            input.body,
        ),
        AiEndpoint::Responses => state.prepare_responses(
            input.provider,
            input.model_route,
            input.logical_model,
            input.stream,
            input.body,
        ),
    }
}

fn estimate_chat_completion_usage(body: &serde_json::Value) -> BillingTokenUsage {
    let prompt_tokens = estimate_prompt_tokens(body);
    let completion_tokens = requested_completion_tokens(body)
        .unwrap_or(DEFAULT_COMPLETION_TOKEN_RESERVATION)
        .saturating_mul(requested_choice_count(body));
    BillingTokenUsage::new(
        prompt_tokens,
        completion_tokens,
        prompt_tokens.saturating_add(completion_tokens),
    )
}

fn estimate_prompt_tokens(body: &serde_json::Value) -> u64 {
    let chars = prompt_character_count(body, None) as u64;
    let text_tokens = chars.saturating_add(3) / 4;
    text_tokens.saturating_add(message_overhead_tokens(body))
}

fn prompt_character_count(value: &serde_json::Value, key: Option<&str>) -> usize {
    if key.is_some_and(is_non_prompt_request_field) {
        return 0;
    }

    match value {
        serde_json::Value::String(text) => text.chars().count(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| prompt_character_count(item, None))
            .sum(),
        serde_json::Value::Object(object) => object
            .iter()
            .map(|(key, value)| prompt_character_count(value, Some(key)))
            .sum(),
        _ => 0,
    }
}

fn is_non_prompt_request_field(key: &str) -> bool {
    matches!(
        key,
        "model"
            | "stream"
            | "max_tokens"
            | "max_completion_tokens"
            | "temperature"
            | "top_p"
            | "n"
            | "presence_penalty"
            | "frequency_penalty"
            | "seed"
            | "user"
    )
}

fn message_overhead_tokens(body: &serde_json::Value) -> u64 {
    body.get("messages")
        .and_then(serde_json::Value::as_array)
        .map(|messages| messages.len() as u64 * 4)
        .unwrap_or_default()
}

fn requested_completion_tokens(body: &serde_json::Value) -> Option<u64> {
    body.get("max_completion_tokens")
        .or_else(|| body.get("max_tokens"))
        .and_then(serde_json::Value::as_u64)
}

fn requested_choice_count(body: &serde_json::Value) -> u64 {
    body.get("n")
        .and_then(serde_json::Value::as_u64)
        .filter(|count| *count > 0)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_prompt_and_requested_completion_tokens() {
        let body = serde_json::json!({
            "model": "fast-chat",
            "messages": [{"role": "user", "content": "hello world"}],
            "max_tokens": 7,
            "n": 2
        });

        let usage = estimate_chat_completion_usage(&body);

        assert_eq!(usage.completion_tokens, 14);
        assert!(usage.prompt_tokens >= 7);
        assert_eq!(
            usage.total_tokens,
            usage.prompt_tokens + usage.completion_tokens
        );
    }

    #[test]
    fn reserves_default_completion_tokens_when_unbounded() {
        let body = serde_json::json!({
            "model": "fast-chat",
            "messages": []
        });

        let usage = estimate_chat_completion_usage(&body);

        assert_eq!(
            usage.completion_tokens,
            DEFAULT_COMPLETION_TOKEN_RESERVATION
        );
        assert_eq!(usage.total_tokens, DEFAULT_COMPLETION_TOKEN_RESERVATION);
    }
}
