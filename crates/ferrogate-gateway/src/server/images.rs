// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Governed OpenAI-compatible POST /v1/images/generations (issue
// #275). A multimodal sibling of embeddings.rs: image generation never
// streams, never calls tools, and carries no model-generated *text* on the
// output side -- so, like embeddings, there is no output-stage Guardrail step.
// The one text surface a request-stage Guardrail can inspect is the caller's
// `prompt`, normalized through `GuardrailProtocol::Images`. Everything else
// (auth, model resolution, provider allow/deny, region fail-closed routing,
// request-stage Guardrail, policy engine, budget/TPM quotas, prepaid-wallet
// reservation, provider dispatch with retry/fallback, usage settlement,
// request logging) mirrors embeddings.rs exactly so the pipelines stay
// auditable side by side.
//
// Metering uses a NON-TOKEN unit (issue #275): the billed quantity is the
// number of generated images, carried in the completion-token dimension of the
// settlement usage. A route's `output_price_per_1m` is therefore interpreted,
// for an image model, as USD per 1,000,000 generated images -- so the existing
// token-priced ledger/wallet path settles a priced image charge with no schema
// change. Only the OpenAI-compatible provider family exposes image generation;
// every other family fails closed at request-preparation time with a
// normalized `image_generation_unsupported` error.

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
use ferrogate_providers::{AdapterError, ModelRegistryError, ProviderHeader, ProviderHttpRequest};
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
#[path = "images_test.rs"]
mod images_test;

const IMAGES_SCOPE: &str = "images.generate";
const IMAGES_ROUTE: &str = "openai.images";
/// Default `n` (images per request) when the caller omits it, matching the
/// OpenAI images API default.
const DEFAULT_IMAGE_COUNT: u64 = 1;
/// Upper bound on the estimated image count used to pre-size quota/wallet
/// reservations, so a hostile `n` can't request an unbounded pre-charge. The
/// authoritative settled count is always taken from the upstream response.
const MAX_ESTIMATED_IMAGE_COUNT: u64 = 100;

#[derive(Debug, Deserialize)]
struct ImagesRequest {
    model: String,
    #[serde(default)]
    metadata: Option<std::collections::BTreeMap<String, String>>,
}

impl FerroGateway {
    pub(super) async fn handle_images(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        let auth = match authenticate(&state, &headers, IMAGES_SCOPE, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                self.record_images_error_log(
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
            self.record_images_error_log(
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
                    self.record_images_error_log(
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

        let plan = match build_images_request_plan(&state, &auth, &body) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.record_images_error_log(
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
        let ImagesRequestPlan {
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
            self.record_images_error_log(ctx, tenant, Some(&request.model), None, status, code);
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
        // concurrent-overdraft fix); see the matching comment in chat.rs /
        // embeddings.rs. Held until this handler returns, its `Drop` releasing
        // the reservation so a cancelled/errored request never leaks credits.
        let mut wallet_reservation = None;
        let mut tpm_checked = false;
        let mut provider_attempt_index: u32 = 0;

        'routes: for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = state.providers.get(&model_route.provider) else {
                self.record_images_error_log(
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
                        "images provider circuit open; trying fallback route"
                    );
                    continue;
                }
                self.record_images_error_log(
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
                self.record_images_error_log(
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
                route: Some(IMAGES_ROUTE.into()),
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
                self.record_images_error_log(
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
                        "guardrail {} blocked images request for model {} provider {} at {}",
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
                self.record_images_error_log(
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
                            self.record_images_error_log(
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
                            self.record_images_error_log(
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
                            self.record_images_error_log(
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
                            self.record_images_error_log(
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
                        self.record_images_error_log(
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
                        self.record_images_error_log(
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

            let mut prepared = match state.prepare_images(
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
                        "images provider adapter failed; trying fallback route"
                    );
                    continue;
                }
                // Fail closed with a precise capability error (issue #275)
                // when the resolved model's provider family cannot serve image
                // generation and no fallback remains -- distinct from a generic
                // adapter fault so a client sees *why* the request was refused.
                Err(AdapterError::UnsupportedCapability { .. }) => {
                    self.record_images_error_log(
                        ctx,
                        policy_request.tenant.clone(),
                        Some(&request.model),
                        Some(&provider.name),
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "image_generation_unsupported",
                    );
                    write_json_error(
                        session,
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "image_generation_unsupported",
                        format!(
                            "model {} resolves to provider family {} which does not support image generation",
                            request.model, provider.kind
                        ),
                        &ctx.request_id,
                    )
                    .await?;
                    return Ok(());
                }
                Err(error) => {
                    self.record_images_error_log(
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
                            let retryable_status = state
                                .is_provider_status_retryable(
                                    &provider.kind,
                                    response.status.as_u16(),
                                )
                                .unwrap_or(false);
                            if retryable_status {
                                state.record_provider_failure(&provider.name);
                            }
                            match images_attempt_decision(
                                retryable_status,
                                attempt,
                                max_dispatch_retries,
                                candidate_index,
                                route_count,
                            ) {
                                ImagesAttemptDecision::RetryProvider => {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_status = response.status.as_u16(),
                                        attempt,
                                        "images provider returned retryable status; retrying provider"
                                    );
                                    attempt += 1;
                                    continue;
                                }
                                ImagesAttemptDecision::TryFallbackRoute => {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_status = response.status.as_u16(),
                                        candidate_index,
                                        "images provider returned server error; trying fallback route"
                                    );
                                    continue 'routes;
                                }
                                ImagesAttemptDecision::ReturnError => {}
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

                        // Non-token settlement (issue #275): the billed unit is
                        // the count of generated images taken from the upstream
                        // response envelope (authoritative), falling back to the
                        // request estimate if the body carries no `data` array.
                        // The count rides the completion-token dimension so the
                        // token-priced ledger/wallet path settles a priced image
                        // charge (route `output_price_per_1m` == USD per 1M
                        // images) with no schema change.
                        let image_usage = image_settlement_usage(&response.body, &estimated_usage);
                        info!(
                            request_id = %ctx.request_id,
                            logical_model = %request.model,
                            provider = %provider.name,
                            images = image_usage.total_tokens,
                            "images provider usage settled by generated-image count"
                        );
                        if let Err(error) = state
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
                                &image_usage,
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

                        // Image responses are already the canonical OpenAI
                        // `{"created":..,"data":[{"url"|"b64_json":..}]}` shape;
                        // only the OpenAI-compatible family serves them, so pass
                        // the upstream body through byte-for-byte.
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
                        match images_attempt_decision(
                            false,
                            attempt,
                            max_dispatch_retries,
                            candidate_index,
                            route_count,
                        ) {
                            ImagesAttemptDecision::RetryProvider => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    attempt,
                                    error = ?error,
                                    "images provider dispatch failed; retrying provider"
                                );
                                attempt += 1;
                                continue;
                            }
                            ImagesAttemptDecision::TryFallbackRoute => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    candidate_index,
                                    error = ?error,
                                    "images provider dispatch failed; trying fallback route"
                                );
                                continue 'routes;
                            }
                            ImagesAttemptDecision::ReturnError => {}
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
                            "images provider dispatch failed; returning provider_dispatch_error"
                        );
                        self.record_images_error_log(
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

    fn record_images_error_log(
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
            route: Some(IMAGES_ROUTE.into()),
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
struct ImagesRequestPlan {
    request: ImagesRequest,
    body_json: serde_json::Value,
    estimated_usage: BillingTokenUsage,
    routing: ModelRoutingDecision,
    guardrail_envelope: ferrogate_guardrails::GuardrailEnvelope,
}

#[derive(Debug)]
struct ImagesRejection {
    logical_model: Option<String>,
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn build_images_request_plan(
    state: &AppState,
    auth: &AuthContext,
    body: &[u8],
) -> Result<ImagesRequestPlan, ImagesRejection> {
    let body_json: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| ImagesRejection {
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_json",
            message: format!("invalid JSON body: {error}"),
        })?;
    let request: ImagesRequest =
        serde_json::from_value(body_json.clone()).map_err(|error| ImagesRejection {
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: format!("invalid image generation request: {error}"),
        })?;
    if body_json
        .get("prompt")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|prompt| prompt.trim().is_empty())
    {
        return Err(ImagesRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "image generation request must include a non-empty string \"prompt\" field"
                .into(),
        });
    }
    if let Some(metadata) = &request.metadata {
        if let Err(reason) = ferrogate_billing::validate_request_metadata(metadata) {
            return Err(ImagesRejection {
                logical_model: Some(request.model.clone()),
                status: StatusCode::BAD_REQUEST,
                code: "invalid_request_metadata",
                message: reason,
            });
        }
    }

    if !auth.can_use_model(&request.model) {
        return Err(ImagesRejection {
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
        ImagesRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    })?;

    authorize_external_rbac(
        &state.config.auth_service,
        auth,
        IMAGES_SCOPE,
        &format!("model:{}", request.model),
    )
    .map_err(|error| ImagesRejection {
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
        return Err(ImagesRejection {
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "model_not_visible",
            message: format!("model {} is not visible to this tenant", request.model),
        });
    }

    let estimated_usage = estimate_images_usage(&body_json);
    let requirements =
        ModelRouteRequirements::from_request(ModelEndpointKind::Images, &body_json, false, 0, 0);
    let routing = state.candidate_model_routes(
        &model,
        &requirements,
        Some(&estimated_usage),
        &auth.region_allowlist,
    );
    // Fail closed (mirrors chat.rs's #173 region behavior): a region-constrained
    // tenant with zero surviving candidates is rejected with a specific reason
    // rather than silently returning "no route" downstream.
    let guardrail_envelope = normalize_guardrail_request(GuardrailProtocol::Images, &body_json);

    Ok(ImagesRequestPlan {
        request,
        body_json,
        estimated_usage,
        routing,
        guardrail_envelope,
    })
}

enum ImagesAttemptDecision {
    RetryProvider,
    TryFallbackRoute,
    ReturnError,
}

fn images_attempt_decision(
    retryable: bool,
    attempt: u32,
    max_dispatch_retries: u32,
    candidate_index: usize,
    route_count: usize,
) -> ImagesAttemptDecision {
    if retryable && attempt < max_dispatch_retries {
        ImagesAttemptDecision::RetryProvider
    } else if retryable && has_next_candidate(candidate_index, route_count) {
        ImagesAttemptDecision::TryFallbackRoute
    } else {
        ImagesAttemptDecision::ReturnError
    }
}

fn has_next_candidate(candidate_index: usize, route_count: usize) -> bool {
    candidate_index + 1 < route_count
}

/// Pre-dispatch estimate of the billed image count (issue #275). The unit is
/// generated images, carried on the completion-token dimension: the request's
/// `n` (default 1, clamped to [`MAX_ESTIMATED_IMAGE_COUNT`]) so the
/// token-budget / TPM / prepaid-wallet gates engage against the same non-token
/// quantity the ledger later settles.
fn estimate_images_usage(body: &serde_json::Value) -> BillingTokenUsage {
    let images = requested_image_count(body);
    BillingTokenUsage::new(0, images, images)
}

fn requested_image_count(body: &serde_json::Value) -> u64 {
    body.get("n")
        .and_then(serde_json::Value::as_u64)
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_IMAGE_COUNT)
        .min(MAX_ESTIMATED_IMAGE_COUNT)
}

/// Authoritative settled image count from the upstream response's `data`
/// array, falling back to the pre-dispatch estimate when the body carries no
/// countable envelope (issue #275). Returned as a [`BillingTokenUsage`] with
/// the count on the completion-token dimension so [`ModelPrice::estimate`]
/// prices it via the route's `output_price_per_1m`.
fn image_settlement_usage(body: &[u8], estimated_usage: &BillingTokenUsage) -> BillingTokenUsage {
    let count = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("data")
                .and_then(serde_json::Value::as_array)
                .map(|data| data.len() as u64)
        })
        .filter(|count| *count > 0)
        .unwrap_or(estimated_usage.total_tokens);
    BillingTokenUsage::new(0, count, count)
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

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
