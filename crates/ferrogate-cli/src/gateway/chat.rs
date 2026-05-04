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
use ferrogate_billing::TokenUsage as BillingTokenUsage;
use ferrogate_core::{RequestContext, TenantContext};
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

const DEFAULT_COMPLETION_TOKEN_RESERVATION: u64 = 512;

impl FerroGateway {
    pub(super) async fn handle_chat_completions(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, &headers, "chat.completions", &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                self.record_chat_error_log(
                    ctx,
                    TenantContext::default(),
                    None,
                    None,
                    error.status,
                    error.code,
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

        let body = read_request_body(session, 1024 * 1024).await?;
        let body_json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(error) => {
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
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
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    None,
                    None,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                );
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
            self.record_chat_error_log(
                ctx,
                auth.tenant_context(),
                Some(&request.model),
                None,
                StatusCode::FORBIDDEN,
                "model_not_allowed",
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
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    Some(&request.model),
                    None,
                    StatusCode::BAD_REQUEST,
                    "model_disabled",
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
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    Some(&request.model),
                    None,
                    StatusCode::BAD_REQUEST,
                    "model_not_found",
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
            self.record_chat_error_log(
                ctx,
                auth.tenant_context(),
                Some(&request.model),
                None,
                StatusCode::FORBIDDEN,
                "model_not_visible",
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

        let routes = state.candidate_model_routes(&model);
        let route_count = routes.len();
        let estimated_usage = estimate_chat_completion_usage(&body_json);
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let mut token_reservation = None;

        'routes: for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = state.providers.get(&model_route.provider) else {
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    Some(&request.model),
                    Some(&model_route.provider),
                    StatusCode::BAD_GATEWAY,
                    "provider_not_found",
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

                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_circuit_open",
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
                self.record_chat_error_log(
                    ctx,
                    auth.tenant_context(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::FORBIDDEN,
                    "provider_not_allowed",
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
                route: Some("openai.chat.completions".into()),
                upstream: Some(provider.name.clone()),
                tenant: auth.tenant_context(),
            };
            if let PolicyDecision::Deny { code, message } =
                state.evaluate_policy(&policy_request, Some(&request.model), Some(&provider.name))
            {
                self.record_chat_error_log(
                    ctx,
                    policy_request.tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::FORBIDDEN,
                    &code,
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

            if token_reservation.is_none() {
                if let (Some(api_key_id), Some(budget)) =
                    (auth.api_key_id.as_deref(), auth.monthly_token_budget)
                {
                    match state.try_reserve_api_key_tokens(
                        api_key_id,
                        budget,
                        estimated_usage.total_tokens,
                    ) {
                        Some(reservation) => {
                            info!(
                                request_id = %ctx.request_id,
                                api_key_id = %api_key_id,
                                logical_model = %request.model,
                                estimated_tokens = reservation.tokens(),
                                "API key token budget reserved"
                            );
                            token_reservation = Some(reservation);
                        }
                        None => {
                            self.record_chat_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::TOO_MANY_REQUESTS,
                                "token_budget_exceeded",
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
                    }
                }
            }

            let prepared = match state.prepare_chat_completions(
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
                    self.record_chat_error_log(
                        ctx,
                        policy_request.tenant.clone(),
                        Some(&request.model),
                        Some(&provider.name),
                        StatusCode::BAD_GATEWAY,
                        "provider_adapter_error",
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
                provider_dispatch_timeout_secs = dispatch_timeout.as_secs(),
                provider_dispatch_max_retries = max_dispatch_retries,
                stream = request.stream,
                "chat completion route planned"
            );

            if request.stream {
                let mut attempt = 0;
                loop {
                    match dispatch_provider_streaming_request(&prepared, dispatch_timeout) {
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
                match dispatch_provider_request(&prepared, dispatch_timeout) {
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
                            tenant: policy_request.tenant.clone(),
                            route: policy_request.route.clone(),
                            provider: Some(provider.name.clone()),
                            logical_model: Some(request.model.clone()),
                            provider_model: Some(model_route.provider_model.clone()),
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
                        self.record_chat_error_log(
                            ctx,
                            auth.tenant_context(),
                            Some(&request.model),
                            None,
                            StatusCode::BAD_GATEWAY,
                            "provider_dispatch_error",
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

    fn record_chat_error_log(
        &self,
        ctx: &ProxyContext,
        tenant: TenantContext,
        logical_model: Option<&str>,
        provider: Option<&str>,
        status: StatusCode,
        error_code: &str,
    ) {
        self.state.record_request_log(StoredRequestLog {
            request_id: ctx.request_id.clone(),
            trace_id: ctx.trace_id.clone(),
            tenant,
            route: Some("openai.chat.completions".into()),
            provider: provider.map(ToOwned::to_owned),
            logical_model: logical_model.map(ToOwned::to_owned),
            provider_model: None,
            status_code: status.as_u16(),
            error_code: Some(error_code.to_string()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            started_at_unix: None,
            completed_at_unix: None,
        });
    }
}

fn has_next_candidate(candidate_index: usize, route_count: usize) -> bool {
    candidate_index + 1 < route_count
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
