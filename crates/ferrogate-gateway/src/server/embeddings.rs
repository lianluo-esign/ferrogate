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

use crate::auth::{authorize_external_rbac, AuthContext};
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, write_raw_response},
    state::{AdminAuditEventDraft, AppState, BillingEventDraft, GuardrailEvaluationContext},
};
use ferrogate_billing::{ProviderAttempt, TokenUsage as BillingTokenUsage};
use ferrogate_core::TenantContext;
use ferrogate_guardrails::{normalize_request as normalize_guardrail_request, GuardrailProtocol};
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::{ModelRegistryError, ProviderHeader, ProviderHttpRequest};
use ferrogate_storage::StoredRequestLog;

use crate::model_routing::{
    ModelEndpointKind, ModelRouteRequirements, ModelRoutingAuditContext, ModelRoutingDecision,
};

use super::{
    body::read_request_body,
    dispatch::{dispatch_provider_request, provider_endpoint_origin},
    FerroGateway, ProxyContext,
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

        let auth = match authenticate(&state, &headers, EMBEDDINGS_SCOPE, &ctx.request_id).await {
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

        let body =
            match read_request_body(session, state.limits().inference_body_max_bytes()).await? {
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
            routing,
            guardrail_envelope,
        } = plan;
        state.record_model_routing_decision(
            ModelRoutingAuditContext {
                request_id: &ctx.request_id,
                trace_id: ctx.trace_id.as_deref(),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                actor_api_key_id: auth.api_key_id.as_deref(),
                tenant: &tenant,
                logical_model: &request.model,
            },
            &routing,
        );
        if let Some((status, code, message)) = routing.rejection(&request.model) {
            self.record_embeddings_error_log(ctx, tenant, Some(&request.model), None, status, code);
            write_json_error(session, status, code, message, &ctx.request_id).await?;
            return Ok(());
        }
        let routes = routing.eligible_routes;

        let request_started_at_unix = now_unix_seconds();
        let route_count = routes.len();
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let provider_response_body_max_bytes = state.provider_response_body_max_bytes();
        let mut token_reservation = None;
        // Prepaid-wallet credit hold for the whole request (issue #169
        // concurrent-overdraft fix); see the matching comment in
        // `chat.rs`. Held until this handler returns, its `Drop` releasing
        // the reservation so a cancelled/errored request never leaks credits.
        let mut wallet_reservation = None;
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
                    ferrogate_config::GuardrailStage::Request,
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
                        managed_action: None,
                        action_fingerprint: None,
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
                    action_identity: Default::default(),
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
                    match state
                        .try_reserve_api_key_tokens(
                            api_key_id,
                            budget,
                            estimated_usage.total_tokens,
                        )
                        .await
                    {
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
                if let Some((counter_key, limit)) = auth.tpm_window() {
                    match state.try_consume_api_key_tokens_per_minute(
                        &counter_key,
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

            // Prepaid-wallet credit reservation (issue #169
            // concurrent-overdraft fix): last gate before dispatch, reserved
            // once per request against `balance - outstanding_reservations`.
            // A no-op for tenants without a wallet or an unpriced route.
            if wallet_reservation.is_none() {
                let estimated_credits =
                    crate::state::estimated_request_credits(model_route, &estimated_usage);
                match state
                    .try_reserve_wallet_credits(&policy_request.tenant, estimated_credits)
                    .await
                {
                    Ok(crate::state::WalletReservationOutcome::NotApplicable) => {}
                    Ok(crate::state::WalletReservationOutcome::Reserved(reservation)) => {
                        wallet_reservation = Some(reservation);
                    }
                    Ok(crate::state::WalletReservationOutcome::Insufficient) => {
                        self.record_embeddings_error_log(
                            ctx,
                            policy_request.tenant.clone(),
                            Some(&request.model),
                            Some(&provider.name),
                            StatusCode::TOO_MANY_REQUESTS,
                            "wallet_balance_exhausted",
                        );
                        write_json_error(
                            session,
                            StatusCode::TOO_MANY_REQUESTS,
                            "wallet_balance_exhausted",
                            "prepaid credit balance cannot cover the estimated request cost",
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
                            "wallet_reservation_unavailable",
                        );
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "wallet_reservation_unavailable",
                            format!("wallet balance reservation failed: {error}"),
                            &ctx.request_id,
                        )
                        .await?;
                        return Ok(());
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
                            parent_action_fingerprint: None,
                        });

                        // Non-OpenAI adapter families (Gemini, Vertex,
                        // Bedrock) return a native embeddings envelope; the
                        // adapter normalizes it into the OpenAI-shaped body
                        // clients expect. `None` means the upstream body is
                        // already canonical and passes through byte-for-byte
                        // (the OpenAI-compatible family), preserving the
                        // previous behavior exactly (issue #274).
                        match state.translate_embeddings_response(
                            &provider.kind,
                            &response.body,
                            &request.model,
                        ) {
                            Ok(Some(normalized)) => {
                                return write_json_response(
                                    session,
                                    response.status,
                                    &normalized,
                                    &ctx.request_id,
                                )
                                .await;
                            }
                            Ok(None) => {
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
                                    format!(
                                        "provider embeddings response translation failed: {error:?}"
                                    ),
                                    &ctx.request_id,
                                )
                                .await?;
                                return Ok(());
                            }
                        }
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
                                    error = ?error,
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
                                    error = ?error,
                                    "embeddings provider dispatch failed; trying fallback route"
                                );
                                continue 'routes;
                            }
                            EmbeddingsAttemptDecision::ReturnError => {}
                        }
                        // #384: never return the terminal 502 without a log
                        // naming the failure class, the full source chain and
                        // the upstream origin the gateway dialled.
                        warn!(
                            request_id = %ctx.request_id,
                            logical_model = %request.model,
                            provider = %provider.name,
                            provider_endpoint = %provider_endpoint_origin(&prepared.endpoint),
                            candidate_index,
                            attempt,
                            max_retries = max_dispatch_retries,
                            provider_dispatch_timeout_secs = dispatch_timeout.as_secs(),
                            error = ?error,
                            "embeddings provider dispatch failed; returning provider_dispatch_error"
                        );
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
            parent_action_fingerprint: None,
        });
    }
}

#[derive(Debug)]
struct EmbeddingsRequestPlan {
    request: EmbeddingsRequest,
    body_json: serde_json::Value,
    estimated_usage: BillingTokenUsage,
    routing: ModelRoutingDecision,
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
        &state.config.auth_service,
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

    let estimated_usage = estimate_embeddings_usage(&body_json, &request.model);
    let requirements = ModelRouteRequirements::from_request(
        ModelEndpointKind::Embeddings,
        &body_json,
        false,
        0,
        0,
    );
    let routing = state.candidate_model_routes(
        &model,
        &requirements,
        Some(&estimated_usage),
        &auth.region_allowlist,
    );
    // Fail closed (mirrors chat.rs's #173 region behavior): a region-constrained
    // tenant with zero surviving candidates is rejected with a specific reason
    // rather than silently returning "no route" downstream.
    let guardrail_envelope = normalize_guardrail_request(GuardrailProtocol::Embeddings, &body_json);

    Ok(EmbeddingsRequestPlan {
        request,
        body_json,
        estimated_usage,
        routing,
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
/// fields, so the estimate is a heuristic over the `input` field (mirrors
/// chat.rs's `estimate_prompt_tokens`, issue #207). Handles BOTH the text
/// shapes (string / array-of-strings, char/4) and the pre-tokenized shapes
/// OpenAI accepts -- a flat integer array of token ids, or an array of such
/// arrays for a batch -- which a char-only count estimated at 0, letting a
/// caller bypass the token-budget / TPM / prepaid-wallet gates entirely.
fn estimate_embeddings_usage(body: &serde_json::Value, model: &str) -> BillingTokenUsage {
    let prompt_tokens = estimate_embeddings_input_tokens(model, body.get("input"));
    BillingTokenUsage::new(prompt_tokens, 0, prompt_tokens)
}

fn estimate_embeddings_input_tokens(model: &str, input: Option<&serde_json::Value>) -> u64 {
    let tokens = match input {
        Some(value @ (serde_json::Value::String(_) | serde_json::Value::Array(_))) => {
            embeddings_element_tokens(model, value)
        }
        _ => 0,
    };
    // Floor a present, non-empty input to at least one token so a tiny or odd
    // input still engages the pre-dispatch gates (mirrors the chat path's
    // non-zero floor), while an explicitly-empty input stays 0.
    match input {
        Some(serde_json::Value::String(text)) if !text.is_empty() => tokens.max(1),
        Some(serde_json::Value::Array(items)) if !items.is_empty() => tokens.max(1),
        _ => tokens,
    }
}

/// Token estimate for one `input` element: text is counted with the local BPE
/// tokenizer when the model has one (issue #282), else the chars/4 heuristic; a
/// pre-tokenized id (a JSON number) is already one token; an array is summed
/// element-wise (a batch of strings, or a single/batch pre-tokenized input).
fn embeddings_element_tokens(model: &str, element: &serde_json::Value) -> u64 {
    match element {
        serde_json::Value::String(text) => crate::tokenizer::count_tokens(model, text)
            .unwrap_or_else(|| (text.chars().count() as u64).saturating_add(3) / 4),
        serde_json::Value::Number(_) => 1,
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| embeddings_element_tokens(model, item))
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
