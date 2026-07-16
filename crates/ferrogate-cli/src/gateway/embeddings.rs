// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Governed OpenAI-compatible POST /v1/embeddings (issue #207).
// A leaner sibling of chat.rs's shared AI request pipeline: embeddings never
// stream, never call tools, never participate in workflow policy, and carry
// no model-generated text -- so there is no output-side Guardrail stage and
// no fallback-route workflow-provider-constraint step. Everything else
// (auth, model resolution, provider allow/deny, region fail-closed routing,
// request-stage Guardrail, policy engine, budget/TPM quotas, provider
// dispatch with retry/fallback, usage settlement, request logging) mirrors
// chat.rs's conventions exactly so the two pipelines stay auditable side by
// side.

use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::{
    auth::{authenticate, authorize_external_rbac, AuthContext},
    responses::{write_json_error, write_json_response, write_raw_response},
    state::{AdminAuditEventDraft, AppState, BillingEventDraft, GuardrailEvaluationContext},
};
use ferrogate_billing::{ProviderAttempt, TokenUsage as BillingTokenUsage};
use ferrogate_core::TenantContext;
use ferrogate_guardrails::{normalize_request as normalize_guardrail_request, GuardrailProtocol};
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::{ModelRegistryError, ModelRoute, ProviderHeader, ProviderHttpRequest};
use ferrogate_storage::StoredRequestLog;

use super::{
    body::read_request_body, dispatch::dispatch_provider_request, FerroGateway, ProxyContext,
};

#[cfg(test)]
#[path = "embeddings_test.rs"]
mod embeddings_test;

const EMBEDDINGS_SCOPE: &str = "embeddings.create";
const EMBEDDINGS_ROUTE: &str = "openai.embeddings";

#[derive(Debug, Deserialize)]
struct EmbeddingsRequest {
    model: String,
    #[serde(default)]
    metadata: Option<std::collections::BTreeMap<String, String>>,
}

impl FerroGateway {
    pub(super) async fn handle_embeddings(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        let auth = match authenticate(&state, &headers, EMBEDDINGS_SCOPE, &ctx.request_id) {
            Ok(auth) => auth,
            Err(error) => {
                self.record_embeddings_error_log(
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
        let tenant = auth.tenant_context();

        if state.is_draining() {
            self.record_embeddings_error_log(
                ctx,
                tenant,
                None,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "node_draining",
            );
            write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "node_draining",
                "gateway node is draining and is not accepting new requests",
                &ctx.request_id,
            )
            .await?;
            return Ok(());
        }

        let body = match read_request_body(session, 1024 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                self.record_embeddings_error_log(
                    ctx,
                    tenant,
                    None,
                    None,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                );
                write_json_error(
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

        let plan = match build_embeddings_request_plan(&state, &auth, &body) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.record_embeddings_error_log(
                    ctx,
                    tenant,
                    rejection.logical_model.as_deref(),
                    None,
                    rejection.status,
                    rejection.code,
                );
                write_json_error(
                    session,
                    rejection.status,
                    rejection.code,
                    rejection.message,
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }
        };
        let EmbeddingsRequestPlan {
            request,
            body_json,
            estimated_usage,
            routes,
            guardrail_envelope,
        } = plan;

        let request_started_at_unix = now_unix_seconds();
        let route_count = routes.len();
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let provider_response_body_max_bytes = state.provider_response_body_max_bytes();
        let mut token_reservation = None;
        let mut tpm_checked = false;
        let mut provider_attempt_index: u32 = 0;

        'routes: for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = state.providers.get(&model_route.provider) else {
                self.record_embeddings_error_log(
                    ctx,
                    tenant.clone(),
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
                        "embeddings provider circuit open; trying fallback route"
                    );
                    continue;
                }
                self.record_embeddings_error_log(
                    ctx,
                    tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_circuit_open",
                );
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_circuit_open",
                    format!("provider {} circuit is open", provider.name),
                    &ctx.request_id,
                )
                .await?;
                return Ok(());
            }

            if !auth.can_use_provider(&provider.name) {
                self.record_embeddings_error_log(
                    ctx,
                    tenant.clone(),
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

            let policy_request = ferrogate_core::RequestContext {
                request_id: ctx.request_id.clone(),
                trace_id: ctx.trace_id.clone(),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                route: Some(EMBEDDINGS_ROUTE.into()),
                upstream: Some(provider.name.clone()),
                tenant: tenant.clone(),
            };

            if let Some(guardrail) = state
                .match_guardrail(
                    crate::config::GuardrailStage::Request,
                    GuardrailEvaluationContext {
                        request_id: &ctx.request_id,
                        trace_id: ctx.trace_id.as_deref(),
                        agent_run_id: None,
                        workflow_id: None,
                        workflow_version: None,
                        workflow_node_id: None,
                        actor_api_key_id: auth.api_key_id.as_deref(),
                        tenant: &policy_request.tenant,
                        service_account_id: auth.service_account_id(),
                        gateway_config_id: None,
                        model: Some(&request.model),
                        provider: Some(&provider.name),
                        streaming: false,
                        envelope: &guardrail_envelope,
                    },
                )
                .await
            {
                state.record_guardrail_match(&guardrail);
                self.record_embeddings_error_log(
                    ctx,
                    policy_request.tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::FORBIDDEN,
                    &guardrail.code,
                );
                state.record_admin_audit_event(AdminAuditEventDraft {
                    request_id: ctx.request_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    agent_run_id: None,
                    workflow_id: None,
                    workflow_version: None,
                    workflow_node_id: None,
                    actor_api_key_id: auth.api_key_id.clone(),
                    tenant: auth.tenant_context(),
                    action: "guardrail.deny".into(),
                    target: guardrail.evidence_target(),
                    outcome: "blocked".into(),
                    message: format!(
                        "guardrail {} blocked embeddings request for model {} provider {} at {}",
                        guardrail.rule_name,
                        request.model,
                        provider.name,
                        guardrail.evidence_location()
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
                self.record_embeddings_error_log(
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
                        Ok(Some(reservation)) => {
                            token_reservation = Some(reservation);
                        }
                        Ok(None) => {
                            self.record_embeddings_error_log(
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
                        Err(error) => {
                            self.record_embeddings_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::SERVICE_UNAVAILABLE,
                                "governance_counter_unavailable",
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

            if !tpm_checked {
                tpm_checked = true;
                if let (Some(api_key_id), Some(limit)) =
                    (auth.api_key_id.as_deref(), auth.effective_quota.tpm_limit)
                {
                    match state.try_consume_api_key_tokens_per_minute(
                        api_key_id,
                        limit,
                        estimated_usage.total_tokens,
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            self.record_embeddings_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::TOO_MANY_REQUESTS,
                                "tpm_limit_exceeded",
                            );
                            write_json_error(
                                session,
                                StatusCode::TOO_MANY_REQUESTS,
                                "tpm_limit_exceeded",
                                "quota policy tokens-per-minute limit is exhausted for this request",
                                &ctx.request_id,
                            )
                            .await?;
                            return Ok(());
                        }
                        Err(error) => {
                            self.record_embeddings_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::SERVICE_UNAVAILABLE,
                                "governance_counter_unavailable",
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

            let mut prepared = match state.prepare_embeddings(
                provider,
                model_route,
                request.model.clone(),
                body_json.clone(),
            ) {
                Ok(prepared) => prepared,
                Err(error) if has_next_candidate(candidate_index, route_count) => {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        error = ?error,
                        "embeddings provider adapter failed; trying fallback route"
                    );
                    continue;
                }
                Err(error) => {
                    self.record_embeddings_error_log(
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
            add_trace_context_headers(&mut prepared, ctx);

            let mut attempt = 0;
            loop {
                let provider_attempt =
                    ProviderAttempt::for_request(&ctx.request_id, provider_attempt_index);
                provider_attempt_index = provider_attempt_index.saturating_add(1);
                let attempt_started_at = Instant::now();
                let attempt_request = provider_request_for_attempt(&prepared, &provider_attempt);
                match dispatch_provider_request(
                    attempt_request,
                    dispatch_timeout,
                    provider_response_body_max_bytes,
                )
                .await
                {
                    Ok(response) => {
                        if response.status.is_client_error() || response.status.is_server_error() {
                            if let Ok(Some(usage)) =
                                state.extract_provider_usage(&provider.kind, &response.body)
                            {
                                if let Err(error) = state
                                    .record_provider_attempt_billing_event(
                                        BillingEventDraft {
                                            request: &policy_request,
                                            logical_model: &request.model,
                                            provider: &provider.name,
                                            provider_model: &model_route.provider_model,
                                            status_code: response.status.as_u16(),
                                            latency_ms: Some(
                                                attempt_started_at.elapsed().as_millis() as u64,
                                            ),
                                            metadata: request.metadata.as_ref(),
                                        },
                                        &provider_attempt,
                                        &usage,
                                    )
                                    .await
                                {
                                    write_json_error(
                                        session,
                                        StatusCode::BAD_GATEWAY,
                                        error.code,
                                        error.message,
                                        &ctx.request_id,
                                    )
                                    .await?;
                                    return Ok(());
                                }
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
                            match embeddings_attempt_decision(
                                retryable_status,
                                attempt,
                                max_dispatch_retries,
                                candidate_index,
                                route_count,
                            ) {
                                EmbeddingsAttemptDecision::RetryProvider => {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_status = response.status.as_u16(),
                                        attempt,
                                        "embeddings provider returned retryable status; retrying provider"
                                    );
                                    attempt += 1;
                                    continue;
                                }
                                EmbeddingsAttemptDecision::TryFallbackRoute => {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_status = response.status.as_u16(),
                                        candidate_index,
                                        "embeddings provider returned server error; trying fallback route"
                                    );
                                    continue 'routes;
                                }
                                EmbeddingsAttemptDecision::ReturnError => {}
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
                                prompt_tokens = ?usage.prompt_tokens,
                                total_tokens = ?usage.total_tokens,
                                "embeddings provider usage extracted"
                            );
                            if let Err(error) = state
                                .record_provider_attempt_billing_event(
                                    BillingEventDraft {
                                        request: &policy_request,
                                        logical_model: &request.model,
                                        provider: &provider.name,
                                        provider_model: &model_route.provider_model,
                                        status_code: response.status.as_u16(),
                                        latency_ms: Some(
                                            attempt_started_at.elapsed().as_millis() as u64
                                        ),
                                        metadata: request.metadata.as_ref(),
                                    },
                                    &provider_attempt,
                                    &usage,
                                )
                                .await
                            {
                                write_json_error(
                                    session,
                                    StatusCode::BAD_GATEWAY,
                                    error.code,
                                    error.message,
                                    &ctx.request_id,
                                )
                                .await?;
                                return Ok(());
                            }
                        } else if let Err(error) = state
                            .record_estimated_provider_attempt_billing_event(
                                BillingEventDraft {
                                    request: &policy_request,
                                    logical_model: &request.model,
                                    provider: &provider.name,
                                    provider_model: &model_route.provider_model,
                                    status_code: response.status.as_u16(),
                                    latency_ms: Some(
                                        attempt_started_at.elapsed().as_millis() as u64
                                    ),
                                    metadata: request.metadata.as_ref(),
                                },
                                &provider_attempt,
                                &estimated_usage,
                            )
                            .await
                        {
                            write_json_error(
                                session,
                                StatusCode::BAD_GATEWAY,
                                error.code,
                                error.message,
                                &ctx.request_id,
                            )
                            .await?;
                            return Ok(());
                        }
                        if let Some(reservation) = token_reservation.take() {
                            reservation.settle();
                        }

                        let record_bodies =
                            auth.can_record_bodies(state.config.telemetry.log_bodies);
                        state.record_request_log(StoredRequestLog {
                            request_id: ctx.request_id.clone(),
                            trace_id: ctx.trace_id.clone(),
                            agent_run_id: None,
                            workflow_id: None,
                            workflow_version: None,
                            workflow_node_id: None,
                            cluster_id: None,
                            node_id: None,
                            tenant: policy_request.tenant.clone(),
                            route: policy_request.route.clone(),
                            provider: Some(provider.name.clone()),
                            logical_model: Some(request.model.clone()),
                            provider_model: Some(model_route.provider_model.clone()),
                            gateway_config_id: None,
                            gateway_config_revision: None,
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
                            cache_status: None,
                            started_at_unix: Some(request_started_at_unix),
                            completed_at_unix: Some(now_unix_seconds()),
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
                        match embeddings_attempt_decision(
                            false,
                            attempt,
                            max_dispatch_retries,
                            candidate_index,
                            route_count,
                        ) {
                            EmbeddingsAttemptDecision::RetryProvider => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    attempt,
                                    error = %error,
                                    "embeddings provider dispatch failed; retrying provider"
                                );
                                attempt += 1;
                                continue;
                            }
                            EmbeddingsAttemptDecision::TryFallbackRoute => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    candidate_index,
                                    error = %error,
                                    "embeddings provider dispatch failed; trying fallback route"
                                );
                                continue 'routes;
                            }
                            EmbeddingsAttemptDecision::ReturnError => {}
                        }
                        self.record_embeddings_error_log(
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

    fn record_embeddings_error_log(
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
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant,
            route: Some(EMBEDDINGS_ROUTE.into()),
            provider: provider.map(ToOwned::to_owned),
            logical_model: logical_model.map(ToOwned::to_owned),
            provider_model: None,
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: status.as_u16(),
            error_code: Some(error_code.to_string()),
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

#[derive(Debug)]
struct EmbeddingsRequestPlan {
    request: EmbeddingsRequest,
    body_json: serde_json::Value,
    estimated_usage: BillingTokenUsage,
    routes: Vec<ModelRoute>,
    guardrail_envelope: ferrogate_guardrails::GuardrailEnvelope,
}

#[derive(Debug)]
struct EmbeddingsRejection {
    logical_model: Option<String>,
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn build_embeddings_request_plan(
    state: &AppState,
    auth: &AuthContext,
    body: &[u8],
) -> Result<EmbeddingsRequestPlan, EmbeddingsRejection> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| EmbeddingsRejection {
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_json",
            message: format!("invalid JSON body: {error}"),
        })?;
    let request: EmbeddingsRequest =
        serde_json::from_value(body_json.clone()).map_err(|error| EmbeddingsRejection {
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: format!("invalid embeddings request: {error}"),
        })?;
    if !body_json
        .get("input")
        .is_some_and(|input| input.is_string() || input.is_array())
    {
        return Err(EmbeddingsRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "embeddings request must include a string or array \"input\" field".into(),
        });
    }
    if let Some(metadata) = &request.metadata {
        if let Err(reason) = ferrogate_billing::validate_request_metadata(metadata) {
            return Err(EmbeddingsRejection {
                logical_model: Some(request.model.clone()),
                status: StatusCode::BAD_REQUEST,
                code: "invalid_request_metadata",
                message: reason,
            });
        }
    }

    if !auth.can_use_model(&request.model) {
        return Err(EmbeddingsRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "model_not_allowed",
            message: format!("API key is not allowed to use model {}", request.model),
        });
    }

    let model = state.resolve_model(&request.model).map_err(|error| {
        let (code, message) = match error {
            ModelRegistryError::ModelDisabled { .. } => (
                "model_disabled",
                format!("model {} is disabled", request.model),
            ),
            _ => (
                "model_not_found",
                format!("unknown model {}", request.model),
            ),
        };
        EmbeddingsRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    })?;

    authorize_external_rbac(
        state,
        auth,
        EMBEDDINGS_SCOPE,
        &format!("model:{}", request.model),
    )
    .map_err(|error| EmbeddingsRejection {
        logical_model: Some(request.model.clone()),
        status: error.status,
        code: error.code,
        message: error.message,
    })?;

    if !state.can_tenant_use_model(
        &request.model,
        auth.organization_id.as_deref(),
        auth.project_id.as_deref(),
    ) {
        return Err(EmbeddingsRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "model_not_visible",
            message: format!("model {} is not visible to this tenant", request.model),
        });
    }

    let estimated_usage = estimate_embeddings_usage(&body_json);
    let routes =
        state.candidate_model_routes(&model, Some(&estimated_usage), &auth.region_allowlist);
    // Fail closed (mirrors chat.rs's #173 region behavior): a region-constrained
    // tenant with zero surviving candidates is rejected with a specific reason
    // rather than silently returning "no route" downstream.
    if routes.is_empty() && !auth.region_allowlist.is_empty() {
        return Err(EmbeddingsRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "region_not_allowed",
            message: format!(
                "no candidate route for model {} satisfies this tenant's region allowlist",
                request.model
            ),
        });
    }
    let guardrail_envelope = normalize_guardrail_request(GuardrailProtocol::Embeddings, &body_json);

    Ok(EmbeddingsRequestPlan {
        request,
        body_json,
        estimated_usage,
        routes,
        guardrail_envelope,
    })
}

enum EmbeddingsAttemptDecision {
    RetryProvider,
    TryFallbackRoute,
    ReturnError,
}

fn embeddings_attempt_decision(
    retryable: bool,
    attempt: u32,
    max_dispatch_retries: u32,
    candidate_index: usize,
    route_count: usize,
) -> EmbeddingsAttemptDecision {
    if retryable && attempt < max_dispatch_retries {
        EmbeddingsAttemptDecision::RetryProvider
    } else if retryable && has_next_candidate(candidate_index, route_count) {
        EmbeddingsAttemptDecision::TryFallbackRoute
    } else {
        EmbeddingsAttemptDecision::ReturnError
    }
}

fn has_next_candidate(candidate_index: usize, route_count: usize) -> bool {
    candidate_index + 1 < route_count
}

fn add_trace_context_headers(request: &mut ProviderHttpRequest, ctx: &ProxyContext) {
    if let Some(traceparent) = &ctx.traceparent {
        push_provider_header_if_absent(request, "traceparent", traceparent);
    }
    if let Some(tracestate) = &ctx.tracestate {
        push_provider_header_if_absent(request, "tracestate", tracestate);
    }
}

fn push_provider_header_if_absent(request: &mut ProviderHttpRequest, name: &str, value: &str) {
    if request
        .headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case(name))
    {
        return;
    }
    request.headers.push(ProviderHeader {
        name: name.to_string(),
        value: ferrogate_providers::SecretValue::new(value),
    });
}

fn provider_request_for_attempt(
    prepared: &ProviderHttpRequest,
    provider_attempt: &ProviderAttempt,
) -> ProviderHttpRequest {
    let mut request = prepared.clone();
    set_canonical_provider_header(
        &mut request,
        "x-ferrogate-provider-attempt-id",
        &provider_attempt.provider_attempt_id,
    );
    set_canonical_provider_header(
        &mut request,
        "x-ferrogate-provider-attempt-index",
        &provider_attempt.provider_attempt_index.to_string(),
    );
    request
}

fn set_canonical_provider_header(request: &mut ProviderHttpRequest, name: &str, value: &str) {
    request
        .headers
        .retain(|header| !header.name.eq_ignore_ascii_case(name));
    request.headers.push(ProviderHeader {
        name: name.to_string(),
        value: ferrogate_providers::SecretValue::new(value),
    });
}

/// Embeddings requests have no completion side and no `max_tokens`/`n`
/// fields, so the estimate is just a char-count heuristic over the `input`
/// field (mirrors chat.rs's `estimate_prompt_tokens`, issue #207).
fn estimate_embeddings_usage(body: &serde_json::Value) -> BillingTokenUsage {
    let chars = embeddings_input_character_count(body.get("input")) as u64;
    let prompt_tokens = chars.saturating_add(3) / 4;
    BillingTokenUsage::new(prompt_tokens, 0, prompt_tokens)
}

fn embeddings_input_character_count(input: Option<&serde_json::Value>) -> usize {
    match input {
        Some(serde_json::Value::String(text)) => text.chars().count(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(|text| text.chars().count())
            .sum(),
        _ => 0,
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
