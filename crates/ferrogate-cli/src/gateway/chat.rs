// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use std::{
    collections::VecDeque,
    fmt,
    io::{Cursor, Error as IoError, Read},
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

use crate::{
    auth::{authenticate, authorize_external_rbac, AuthContext},
    config::{
        AgentWorkflowNodeKind, AgentWorkflowPolicy, GuardrailEffect, GuardrailStage, Provider,
    },
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, write_raw_response,
        write_streaming_bytes_response, write_streaming_response,
    },
    state::{
        AppState, BillingEventDraft, GatewayConfigResolveError, GatewayConfigUse,
        GuardrailEvaluationContext, ToolInjectionContext,
    },
};
use ferrogate_billing::{ProviderAttempt, TokenUsage as BillingTokenUsage};
use ferrogate_core::{RequestContext, TenantContext};
use ferrogate_guardrails::{
    normalize_request as normalize_guardrail_request,
    normalize_response as normalize_guardrail_response, GuardrailEnvelope, GuardrailProtocol,
    PolicySelectionContext,
};
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::{
    ModelRegistryError, ModelRoute, ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
};
use ferrogate_storage::StoredRequestLog;

use super::{
    body::read_request_body,
    dispatch::{dispatch_provider_request, dispatch_provider_streaming_request},
    responses_stream::{ResponsesStreamNormalizer, ResponsesStreamProviderKind},
    FerroGateway, ProxyContext,
};

#[derive(Debug, Deserialize)]
struct ChatCompletionRequest {
    model: String,
    #[serde(default)]
    stream: bool,
    /// Arbitrary caller-supplied request tags (issue #171) -- shared by
    /// both chat completions and the Responses API, since both endpoints
    /// deserialize into this same struct. Bounded by
    /// `ferrogate_billing::validate_request_metadata` at parse time
    /// (see `parse_ai_request`), so by the time this reaches billing it's
    /// already within the size/count limits.
    #[serde(default)]
    metadata: Option<std::collections::BTreeMap<String, String>>,
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

    fn guardrail_protocol(self) -> GuardrailProtocol {
        match self {
            Self::ChatCompletions => GuardrailProtocol::ChatCompletions,
            Self::Responses => GuardrailProtocol::Responses,
        }
    }
}

const DEFAULT_COMPLETION_TOKEN_RESERVATION: u64 = 512;
const GATEWAY_CONFIG_HEADER: &str = "x-ferrogate-config";
const AGENT_RUN_ID_HEADER: &str = "x-ferrogate-agent-run-id";
const WORKFLOW_ID_HEADER: &str = "x-ferrogate-workflow-id";
const WORKFLOW_VERSION_HEADER: &str = "x-ferrogate-workflow-version";
const WORKFLOW_NODE_ID_HEADER: &str = "x-ferrogate-workflow-node-id";
const WORKFLOW_ITERATION_HEADER: &str = "x-ferrogate-workflow-iteration";

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
        let ingress_plan = match build_ai_ingress_plan(&state, &headers, endpoint, ctx) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: rejection.tenant,
                        logical_model: rejection.logical_model.as_deref(),
                        provider: None,
                        status: rejection.status,
                        error_code: rejection.code,
                    },
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
        let body = match read_request_body(session, 1024 * 1024).await? {
            Ok(body) => body,
            Err(limit) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: ingress_plan.auth.tenant_context(),
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
        let request_plan = match build_ai_request_plan(&state, ingress_plan, &body, endpoint) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.record_ai_error_log(
                    endpoint,
                    ctx,
                    AiErrorLog {
                        tenant: rejection.tenant,
                        logical_model: rejection.logical_model.as_deref(),
                        provider: None,
                        status: rejection.status,
                        error_code: rejection.code,
                    },
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
        let AiRequestPlan {
            auth,
            agent_run_id,
            workflow_id,
            workflow_version,
            workflow_node_id,
            workflow_iteration,
            gateway_config,
            request,
            body_json,
            estimated_usage,
            mut routes,
            guardrail_envelope,
        } = request_plan;
        // Shadow/mirror rollout (issue #276): fire-and-forget a sampled,
        // budget-capped duplicate of this request to a secondary provider.
        // Spawned here (before the primary dispatch) so it adds no client
        // latency and is fully isolated from the primary path -- its response
        // is discarded, it is metered as shadow but never billed, and any
        // failure is swallowed. A no-op for models without a shadow target.
        super::shadow::spawn_shadow_mirror(
            &state,
            super::shadow::ShadowMirrorParams {
                endpoint,
                request_id: ctx.request_id.clone(),
                route: endpoint.route(),
                logical_model: request.model.clone(),
                tenant: auth.tenant_context(),
                api_key_id: auth.api_key_id.clone(),
                sticky_key: rollout_sticky_key(&auth, &request.model),
                body: body_json.clone(),
            },
        );
        let request_started_at_unix = now_unix_seconds();
        let workflow_provider_constraint = match enforce_ai_workflow_policy(
            &state,
            AiWorkflowRequestContext {
                auth: &auth,
                agent_run_id: &agent_run_id,
                workflow_id: workflow_id.as_deref(),
                workflow_version,
                workflow_node_id: workflow_node_id.as_deref(),
                workflow_iteration,
                logical_model: &request.model,
                estimated_usage: &estimated_usage,
                now_unix: request_started_at_unix,
            },
        ) {
            Ok(constraint) => constraint,
            Err(rejection) => {
                self.record_ai_workflow_rejection(
                    session,
                    AiWorkflowRejectionContext {
                        endpoint,
                        ctx,
                        agent_run_id: &agent_run_id,
                        workflow_id: workflow_id.as_deref(),
                        workflow_version,
                        workflow_node_id: workflow_node_id.as_deref(),
                        auth: &auth,
                        gateway_config: gateway_config.as_ref(),
                        logical_model: &request.model,
                        now_unix: request_started_at_unix,
                        rejection,
                    },
                )
                .await?;
                return Ok(());
            }
        };
        if let Err(rejection) = apply_workflow_provider_constraint(
            workflow_provider_constraint.as_ref(),
            &request.model,
            &mut routes,
        ) {
            self.record_ai_workflow_rejection(
                session,
                AiWorkflowRejectionContext {
                    endpoint,
                    ctx,
                    agent_run_id: &agent_run_id,
                    workflow_id: workflow_id.as_deref(),
                    workflow_version,
                    workflow_node_id: workflow_node_id.as_deref(),
                    auth: &auth,
                    gateway_config: gateway_config.as_ref(),
                    logical_model: &request.model,
                    now_unix: request_started_at_unix,
                    rejection,
                },
            )
            .await?;
            return Ok(());
        }
        let route_count = routes.len();
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let provider_response_body_max_bytes = state.provider_response_body_max_bytes();
        let mut token_reservation = None;
        // Prepaid-wallet credit hold for the whole request (issue #169
        // concurrent-overdraft fix). Reserved once, just before the first
        // dispatch, and held (across any fallback routes) until this handler
        // returns -- its `Drop` releases the hold, so a cancelled or errored
        // request never leaks credits, and the hold always outlives the
        // settlement debit on the success path.
        let mut wallet_reservation = None;
        let mut tpm_checked = false;

        let mut provider_attempt_sequence = ProviderAttemptSequence::default();
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
                agent_run_id: Some(agent_run_id.clone()),
                workflow_id: workflow_id.clone(),
                workflow_version,
                workflow_node_id: workflow_node_id.clone(),
                route: Some(endpoint.route().into()),
                upstream: Some(provider.name.clone()),
                tenant: auth.tenant_context(),
            };
            if let Some(guardrail) = state
                .match_guardrail(
                    GuardrailStage::Request,
                    GuardrailEvaluationContext {
                        request_id: &ctx.request_id,
                        trace_id: ctx.trace_id.as_deref(),
                        agent_run_id: Some(&agent_run_id),
                        workflow_id: workflow_id.as_deref(),
                        workflow_version,
                        workflow_node_id: workflow_node_id.as_deref(),
                        actor_api_key_id: auth.api_key_id.as_deref(),
                        tenant: &policy_request.tenant,
                        service_account_id: auth.service_account_id(),
                        gateway_config_id: gateway_config
                            .as_ref()
                            .map(|profile| profile.id.as_str()),
                        model: Some(&request.model),
                        provider: Some(&provider.name),
                        streaming: request.stream,
                        envelope: &guardrail_envelope,
                        managed_action: None,
                        action_fingerprint: None,
                    },
                )
                .await
            {
                state.record_guardrail_match(&guardrail);
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
                    action_identity: Default::default(),
                    request_id: ctx.request_id.clone(),
                    trace_id: ctx.trace_id.clone(),
                    agent_run_id: Some(agent_run_id.clone()),
                    workflow_id: workflow_id.clone(),
                    workflow_version,
                    workflow_node_id: workflow_node_id.clone(),
                    actor_api_key_id: auth.api_key_id.clone(),
                    tenant: auth.tenant_context(),
                    action: "guardrail.deny".into(),
                    target: guardrail.evidence_target(),
                    outcome: "blocked".into(),
                    message: format!(
                        "guardrail {} blocked request for model {} provider {} at {}",
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
            // Semantic layer (#273) sits behind the same seam: only built when
            // an exact cache_key exists (so it inherits the enabled/non-stream
            // + per-model/key/profile gating) and `cache.mode = "semantic"`.
            let semantic_ctx = cache_key.as_ref().and_then(|_| {
                state.semantic_cache_context(
                    endpoint.route(),
                    &policy_request.tenant,
                    &request.model,
                    &provider.name,
                    &model_route.provider_model,
                    &body_json,
                )
            });
            if let Some(cache_key) = cache_key.as_ref() {
                let cached = state.lookup_ai_response_cache(cache_key).or_else(|| {
                    semantic_ctx
                        .as_ref()
                        .and_then(|context| state.lookup_semantic_response_cache(context))
                });
                if let Some(cached) = cached {
                    state.record_ai_cache_hit();
                    let record_bodies = auth.can_record_bodies(state.config.telemetry.log_bodies);
                    state.record_request_log(StoredRequestLog {
                        request_id: ctx.request_id.clone(),
                        trace_id: ctx.trace_id.clone(),
                        agent_run_id: Some(agent_run_id.clone()),
                        workflow_id: workflow_id.clone(),
                        workflow_version,
                        workflow_node_id: workflow_node_id.clone(),
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
                        started_at_unix: Some(request_started_at_unix),
                        completed_at_unix: Some(now_unix_seconds()),
                        parent_action_fingerprint: None,
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

            // P1-3 tokens-per-minute quota: checked once per logical request
            // (not once per fallback route candidate), using the effective
            // quota resolved once in `auth::finalize_auth`. Independent of
            // the monthly token budget above -- a key can have a TPM limit
            // without a monthly budget, or vice versa.
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
                            self.record_ai_error_log(
                                endpoint,
                                ctx,
                                AiErrorLog {
                                    tenant: policy_request.tenant.clone(),
                                    logical_model: Some(&request.model),
                                    provider: Some(&provider.name),
                                    status: StatusCode::TOO_MANY_REQUESTS,
                                    error_code: "tpm_limit_exceeded",
                                },
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

            // Prepaid-wallet credit reservation (issue #169
            // concurrent-overdraft fix): the last gate before dispatch, so
            // rate/budget rejections above never take a hold. Reserved once
            // per request (against `balance - outstanding_reservations`) so
            // concurrent requests from one tenant can't all pass a bare
            // `balance > 0` read and settle afterward into a negative balance.
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
                        self.record_ai_error_log(
                            endpoint,
                            ctx,
                            AiErrorLog {
                                tenant: policy_request.tenant.clone(),
                                logical_model: Some(&request.model),
                                provider: Some(&provider.name),
                                status: StatusCode::TOO_MANY_REQUESTS,
                                error_code: "wallet_balance_exhausted",
                            },
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
                        self.record_ai_error_log(
                            endpoint,
                            ctx,
                            AiErrorLog {
                                tenant: policy_request.tenant.clone(),
                                logical_model: Some(&request.model),
                                provider: Some(&provider.name),
                                status: StatusCode::SERVICE_UNAVAILABLE,
                                error_code: "wallet_reservation_unavailable",
                            },
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

            let mut prepared = match prepare_ai_provider_request(
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
            add_trace_context_headers(&mut prepared, ctx);

            let attempt_plan = AiProviderAttemptPlan {
                endpoint,
                request_id: &ctx.request_id,
                api_key_id: auth.api_key_id.as_deref(),
                organization_id: auth.organization_id.as_deref(),
                project_id: auth.project_id.as_deref(),
                monthly_token_budget: auth.monthly_token_budget,
                request_limit_per_minute: auth.request_limit_per_minute,
                logical_model: &request.model,
                provider: &provider.name,
                provider_model: &model_route.provider_model,
                candidate_index,
                route_count,
                dispatch_timeout,
                max_dispatch_retries,
                stream: request.stream,
            };
            attempt_plan.log_planned_route();

            if request.stream {
                let mut attempt = 0;
                loop {
                    let provider_attempt = provider_attempt_sequence.next(&ctx.request_id);
                    attempt_plan.log_dispatch_attempt(&provider_attempt, attempt);
                    let attempt_started_at = Instant::now();
                    let attempt_request =
                        provider_request_for_attempt(&prepared, &provider_attempt);
                    match dispatch_provider_streaming_request(attempt_request, dispatch_timeout)
                        .await
                    {
                        Ok(response) => {
                            if response.status.is_client_error()
                                || response.status.is_server_error()
                            {
                                let body = match read_provider_streaming_body(
                                    response.initial_body,
                                    response.body,
                                    provider_response_body_max_bytes,
                                    dispatch_timeout,
                                )
                                .await
                                {
                                    Ok(body) => body,
                                    Err(error) => {
                                        let (status, code) = error.status_and_code();
                                        let empty_envelope = normalize_guardrail_response(
                                            endpoint.guardrail_protocol(),
                                            &[],
                                            true,
                                        );
                                        let policy_failure = state
                                            .guardrail_streaming_buffer_failure(
                                                GuardrailEvaluationContext {
                                                    request_id: &ctx.request_id,
                                                    trace_id: ctx.trace_id.as_deref(),
                                                    agent_run_id: Some(&agent_run_id),
                                                    workflow_id: workflow_id.as_deref(),
                                                    workflow_version,
                                                    workflow_node_id: workflow_node_id.as_deref(),
                                                    actor_api_key_id: auth.api_key_id.as_deref(),
                                                    tenant: &policy_request.tenant,
                                                    service_account_id: auth.service_account_id(),
                                                    gateway_config_id: gateway_config
                                                        .as_ref()
                                                        .map(|profile| profile.id.as_str()),
                                                    model: Some(&request.model),
                                                    provider: Some(&provider.name),
                                                    streaming: true,
                                                    envelope: &empty_envelope,
                                                    managed_action: None,
                                                    action_fingerprint: None,
                                                },
                                                code,
                                            )
                                            .await;
                                        let (status, code, message) = match policy_failure {
                                            Some(guardrail) => {
                                                state.record_guardrail_match(&guardrail);
                                                (
                                                    StatusCode::FORBIDDEN,
                                                    guardrail.code,
                                                    guardrail.message,
                                                )
                                            }
                                            None => (status, code.to_string(), error.to_string()),
                                        };
                                        write_json_error(
                                            session,
                                            status,
                                            &code,
                                            message,
                                            &ctx.request_id,
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                };
                                // A provider error can report real usage even when this
                                // dispatch will be retried or followed by a fallback. Settle
                                // the concrete attempt before making that routing decision.
                                if let Ok(Some(usage)) =
                                    state.extract_provider_usage(&provider.kind, &body)
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
                                match ProviderAttemptDecision::from_retryable_status(
                                    retryable_status,
                                    attempt,
                                    &attempt_plan,
                                ) {
                                    ProviderAttemptDecision::RetryProvider => {
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
                                    ProviderAttemptDecision::TryFallbackRoute => {
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
                                    ProviderAttemptDecision::ReturnError => {}
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
                            // Do NOT settle the token reservation here. Settling
                            // at stream-header arrival released the reserved
                            // budget while the stream was still generating (and
                            // billing real tokens), and the stream's actual usage
                            // is only recorded at completion (record_stream_usage
                            // below) -- so between header arrival and stream end
                            // the request counted as neither reserved nor used,
                            // letting concurrent streams overrun the monthly
                            // budget. The reservation is RAII (Drop releases the
                            // reserved counter on every exit path, including
                            // mid-stream error/disconnect), so keeping it in
                            // `token_reservation` holds the budget for the stream
                            // and releases it when the handler returns -- after
                            // the usage has been recorded. Non-streaming settles
                            // similarly (record billing, then settle).
                            let record_bodies =
                                auth.can_record_bodies(state.config.telemetry.log_bodies);
                            let record_stream_usage = async |stream_body: Option<&[u8]>| {
                                // Responses streaming normalizes the provider stream to the
                                // OpenAI/Responses shape (top-level `usage.{prompt_tokens,
                                // completion_tokens,total_tokens}`) BEFORE this billing closure
                                // sees it. Parsing that with the ORIGIN provider's native
                                // extractor (Anthropic `usage.input_tokens`, Gemini
                                // `usageMetadata`) finds nothing, so billing silently fell back
                                // to the 512-token estimate -- letting a tenant stream unbounded
                                // real tokens billed as ~512 (token-budget / TPM / prepaid-wallet
                                // bypass). Extract from the normalized OpenAI shape for Responses;
                                // chat-completions streams the raw native SSE, so keep the native
                                // extractor.
                                let usage_provider_kind: &str = if endpoint == AiEndpoint::Responses
                                {
                                    "openai"
                                } else {
                                    provider.kind.as_str()
                                };
                                let reported_usage = stream_body.and_then(|body| {
                                    extract_last_provider_stream_usage(body, |payload| {
                                        state
                                            .extract_provider_usage(usage_provider_kind, payload)
                                            .ok()
                                            .flatten()
                                    })
                                });
                                let result = if let Some(usage) = reported_usage {
                                    state
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
                                } else {
                                    state
                                        .record_estimated_provider_attempt_billing_event(
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
                                            &estimated_usage,
                                        )
                                        .await
                                };
                                if let Err(error) = result {
                                    warn!(
                                        request_id = %ctx.request_id,
                                        logical_model = %request.model,
                                        provider = %provider.name,
                                        provider_model = %model_route.provider_model,
                                        error_code = %error.code,
                                        "streaming billing event write failed"
                                    );
                                }
                            };
                            let streaming_guardrail_plan =
                                state.streaming_guardrail_plan(PolicySelectionContext {
                                    organization_id: policy_request
                                        .tenant
                                        .organization_id
                                        .as_deref(),
                                    project_id: policy_request.tenant.project_id.as_deref(),
                                    workspace_id: policy_request.tenant.workspace_id.as_deref(),
                                    api_key_id: policy_request.tenant.api_key_id.as_deref(),
                                    service_account_id: auth.service_account_id(),
                                    gateway_config_id: gateway_config
                                        .as_ref()
                                        .map(|profile| profile.id.as_str()),
                                    model: Some(&request.model),
                                    provider: Some(&provider.name),
                                    managed_action: None,
                                });
                            if streaming_guardrail_plan
                                == crate::state::StreamingGuardrailPlan::BufferAndEnforce
                            {
                                let response_status = response.status;
                                let response_content_type = response.content_type;
                                let (buffer_initial, buffer_reader, client_content_type): (
                                    Vec<u8>,
                                    Box<dyn Read + Send>,
                                    String,
                                ) = if endpoint == AiEndpoint::Responses {
                                    let provider_kind =
                                        responses_stream_provider_kind(&provider.kind);
                                    let raw =
                                        Cursor::new(response.initial_body).chain(response.body);
                                    (
                                        Vec::new(),
                                        Box::new(ResponsesStreamNormalizer::new(
                                            raw,
                                            provider_kind,
                                            ctx.request_id.clone(),
                                            response_content_type.clone(),
                                        )),
                                        "text/event-stream".to_string(),
                                    )
                                } else {
                                    (
                                        response.initial_body,
                                        Box::new(response.body),
                                        response_content_type,
                                    )
                                };
                                let mut final_body = match read_provider_streaming_body(
                                    buffer_initial,
                                    buffer_reader,
                                    provider_response_body_max_bytes,
                                    dispatch_timeout,
                                )
                                .await
                                {
                                    Ok(body) => body,
                                    Err(error) => {
                                        record_stream_usage(None).await;
                                        let (status, code) = error.status_and_code();
                                        let empty_envelope = normalize_guardrail_response(
                                            endpoint.guardrail_protocol(),
                                            &[],
                                            true,
                                        );
                                        let policy_failure = state
                                            .guardrail_streaming_buffer_failure(
                                                GuardrailEvaluationContext {
                                                    request_id: &ctx.request_id,
                                                    trace_id: ctx.trace_id.as_deref(),
                                                    agent_run_id: Some(&agent_run_id),
                                                    workflow_id: workflow_id.as_deref(),
                                                    workflow_version,
                                                    workflow_node_id: workflow_node_id.as_deref(),
                                                    actor_api_key_id: auth.api_key_id.as_deref(),
                                                    tenant: &policy_request.tenant,
                                                    service_account_id: auth.service_account_id(),
                                                    gateway_config_id: gateway_config
                                                        .as_ref()
                                                        .map(|profile| profile.id.as_str()),
                                                    model: Some(&request.model),
                                                    provider: Some(&provider.name),
                                                    streaming: true,
                                                    envelope: &empty_envelope,
                                                    managed_action: None,
                                                    action_fingerprint: None,
                                                },
                                                code,
                                            )
                                            .await;
                                        let (status, code, message) = match policy_failure {
                                            Some(guardrail) => {
                                                state.record_guardrail_match(&guardrail);
                                                (
                                                    StatusCode::FORBIDDEN,
                                                    guardrail.code,
                                                    guardrail.message,
                                                )
                                            }
                                            None => (status, code.to_string(), error.to_string()),
                                        };
                                        self.record_ai_error_log(
                                            endpoint,
                                            ctx,
                                            AiErrorLog {
                                                tenant: policy_request.tenant.clone(),
                                                logical_model: Some(&request.model),
                                                provider: Some(&provider.name),
                                                status,
                                                error_code: &code,
                                            },
                                        );
                                        write_json_error(
                                            session,
                                            status,
                                            &code,
                                            message,
                                            &ctx.request_id,
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                };
                                record_stream_usage(Some(&final_body)).await;
                                let mut final_status = response_status;
                                let mut final_content_type = client_content_type;
                                let mut final_error_code = None;
                                let guardrail_envelope = normalize_guardrail_response(
                                    endpoint.guardrail_protocol(),
                                    &final_body,
                                    true,
                                );
                                if let Some(guardrail) = state
                                    .match_guardrail(
                                        GuardrailStage::Response,
                                        GuardrailEvaluationContext {
                                            request_id: &ctx.request_id,
                                            trace_id: ctx.trace_id.as_deref(),
                                            agent_run_id: Some(&agent_run_id),
                                            workflow_id: workflow_id.as_deref(),
                                            workflow_version,
                                            workflow_node_id: workflow_node_id.as_deref(),
                                            actor_api_key_id: auth.api_key_id.as_deref(),
                                            tenant: &policy_request.tenant,
                                            service_account_id: auth.service_account_id(),
                                            gateway_config_id: gateway_config
                                                .as_ref()
                                                .map(|profile| profile.id.as_str()),
                                            model: Some(&request.model),
                                            provider: Some(&provider.name),
                                            streaming: true,
                                            envelope: &guardrail_envelope,
                                            managed_action: None,
                                            action_fingerprint: None,
                                        },
                                    )
                                    .await
                                {
                                    state.record_guardrail_match(&guardrail);
                                    match guardrail.effect {
                                        GuardrailEffect::Deny => {
                                            final_status = StatusCode::FORBIDDEN;
                                            final_content_type = "application/json".into();
                                            final_error_code = Some(guardrail.code.clone());
                                            state.record_admin_audit_event(
                                                crate::state::AdminAuditEventDraft { action_identity: Default::default(),
                                                    request_id: ctx.request_id.clone(),
                                                    trace_id: ctx.trace_id.clone(),
                                                    agent_run_id: Some(agent_run_id.clone()),
                                                    workflow_id: workflow_id.clone(),
                                                    workflow_version,
                                                    workflow_node_id: workflow_node_id.clone(),
                                                    actor_api_key_id: auth.api_key_id.clone(),
                                                    tenant: auth.tenant_context(),
                                                    action: "guardrail.deny".into(),
                                                    target: guardrail.evidence_target(),
                                                    outcome: "blocked".into(),
                                                    message: format!(
                                                        "guardrail {} blocked streaming response for model {} provider {} at {}",
                                                        guardrail.rule_name,
                                                        request.model,
                                                        provider.name,
                                                        guardrail.evidence_location()
                                                    ),
                                                },
                                            );
                                            final_body = serde_json::json!({
                                                "error": {
                                                    "message": guardrail.message,
                                                    "type": "ferrogate_error",
                                                    "code": guardrail.code,
                                                    "request_id": ctx.request_id.as_str(),
                                                }
                                            })
                                            .to_string()
                                            .into_bytes();
                                        }
                                        GuardrailEffect::Redact => {
                                            let redacted_body = guardrail
                                                .redact_text(&String::from_utf8_lossy(&final_body));
                                            state.record_admin_audit_event(
                                                crate::state::AdminAuditEventDraft { action_identity: Default::default(),
                                                    request_id: ctx.request_id.clone(),
                                                    trace_id: ctx.trace_id.clone(),
                                                    agent_run_id: Some(agent_run_id.clone()),
                                                    workflow_id: workflow_id.clone(),
                                                    workflow_version,
                                                    workflow_node_id: workflow_node_id.clone(),
                                                    actor_api_key_id: auth.api_key_id.clone(),
                                                    tenant: auth.tenant_context(),
                                                    action: "guardrail.redact".into(),
                                                    target: guardrail.evidence_target(),
                                                    outcome: "redacted".into(),
                                                    message: format!(
                                                        "guardrail {} redacted streaming response for model {} provider {} at {}",
                                                        guardrail.rule_name,
                                                        request.model,
                                                        provider.name,
                                                        guardrail.evidence_location()
                                                    ),
                                                },
                                            );
                                            final_body = redacted_body.into_bytes();
                                        }
                                    }
                                }
                                state.record_request_log(StoredRequestLog {
                                    request_id: ctx.request_id.clone(),
                                    trace_id: ctx.trace_id.clone(),
                                    agent_run_id: Some(agent_run_id.clone()),
                                    workflow_id: workflow_id.clone(),
                                    workflow_version,
                                    workflow_node_id: workflow_node_id.clone(),
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
                                    status_code: final_status.as_u16(),
                                    error_code: final_error_code,
                                    prompt_recorded: record_bodies,
                                    response_recorded: record_bodies,
                                    prompt_body: record_bodies.then(|| body_json.to_string()),
                                    response_body: record_bodies.then(|| {
                                        String::from_utf8_lossy(&final_body)
                                            .chars()
                                            .take(16 * 1024)
                                            .collect()
                                    }),
                                    cache_status: None,
                                    started_at_unix: Some(request_started_at_unix),
                                    completed_at_unix: Some(now_unix_seconds()),
                                    parent_action_fingerprint: None,
                                });
                                return write_streaming_bytes_response(
                                    session,
                                    final_status,
                                    &final_content_type,
                                    final_body,
                                    &ctx.request_id,
                                )
                                .await;
                            }
                            let record_pass_through_completion =
                                async |stream_body: Option<&[u8]>| {
                                    record_stream_usage(stream_body).await;
                                    state.record_request_log(StoredRequestLog {
                                        request_id: ctx.request_id.clone(),
                                        trace_id: ctx.trace_id.clone(),
                                        agent_run_id: Some(agent_run_id.clone()),
                                        workflow_id: workflow_id.clone(),
                                        workflow_version,
                                        workflow_node_id: workflow_node_id.clone(),
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
                                        response_recorded: false,
                                        prompt_body: record_bodies.then(|| body_json.to_string()),
                                        response_body: None,
                                        cache_status: None,
                                        started_at_unix: Some(request_started_at_unix),
                                        completed_at_unix: Some(now_unix_seconds()),
                                        parent_action_fingerprint: None,
                                    });
                                };
                            if streaming_guardrail_plan
                                == crate::state::StreamingGuardrailPlan::ShadowAfterComplete
                            {
                                let (stream_result, capture, usage_capture) =
                                    if endpoint == AiEndpoint::Responses {
                                        let provider_kind =
                                            responses_stream_provider_kind(&provider.kind);
                                        let raw =
                                            Cursor::new(response.initial_body).chain(response.body);
                                        let normalized = ResponsesStreamNormalizer::new(
                                            raw,
                                            provider_kind,
                                            ctx.request_id.clone(),
                                            response.content_type.clone(),
                                        );
                                        let (usage_capturing, usage_capture) =
                                            StreamingUsageCapturingReader::new(normalized, &[]);
                                        let (capturing, capture) = CapturingReader::new(
                                            usage_capturing,
                                            &[],
                                            provider_response_body_max_bytes,
                                        );
                                        let result = write_streaming_response(
                                            session,
                                            response.status,
                                            "text/event-stream",
                                            Vec::new(),
                                            capturing,
                                            &ctx.request_id,
                                        )
                                        .await;
                                        (result, capture, usage_capture)
                                    } else {
                                        let (usage_capturing, usage_capture) =
                                            StreamingUsageCapturingReader::new(
                                                response.body,
                                                &response.initial_body,
                                            );
                                        let (capturing, capture) = CapturingReader::new(
                                            usage_capturing,
                                            &response.initial_body,
                                            provider_response_body_max_bytes,
                                        );
                                        let result = write_streaming_response(
                                            session,
                                            response.status,
                                            &response.content_type,
                                            response.initial_body,
                                            capturing,
                                            &ctx.request_id,
                                        )
                                        .await;
                                        (result, capture, usage_capture)
                                    };
                                let usage_body = usage_capture
                                    .lock()
                                    .map(|capture| capture.body())
                                    .unwrap_or_default();
                                let captured = capture
                                    .lock()
                                    .map(|capture| capture.clone())
                                    .unwrap_or(StreamingCapture {
                                        body: Vec::new(),
                                        truncated: true,
                                    });
                                record_pass_through_completion(Some(&usage_body)).await;
                                if stream_result.is_ok() {
                                    let guardrail_envelope = normalize_guardrail_response(
                                        endpoint.guardrail_protocol(),
                                        &captured.body,
                                        true,
                                    );
                                    let evaluation_context = GuardrailEvaluationContext {
                                        request_id: &ctx.request_id,
                                        trace_id: ctx.trace_id.as_deref(),
                                        agent_run_id: Some(&agent_run_id),
                                        workflow_id: workflow_id.as_deref(),
                                        workflow_version,
                                        workflow_node_id: workflow_node_id.as_deref(),
                                        actor_api_key_id: auth.api_key_id.as_deref(),
                                        tenant: &policy_request.tenant,
                                        service_account_id: auth.service_account_id(),
                                        gateway_config_id: gateway_config
                                            .as_ref()
                                            .map(|profile| profile.id.as_str()),
                                        model: Some(&request.model),
                                        provider: Some(&provider.name),
                                        streaming: true,
                                        envelope: &guardrail_envelope,
                                        managed_action: None,
                                        action_fingerprint: None,
                                    };
                                    if captured.truncated {
                                        state
                                            .record_guardrail_stream_capture_overflow(
                                                evaluation_context,
                                            )
                                            .await;
                                    } else {
                                        let _ = state
                                            .match_guardrail(
                                                GuardrailStage::Response,
                                                evaluation_context,
                                            )
                                            .await;
                                    }
                                }
                                return stream_result;
                            }
                            let (stream_result, usage_capture) = if endpoint
                                == AiEndpoint::Responses
                            {
                                let provider_kind = responses_stream_provider_kind(&provider.kind);
                                let normalized = ResponsesStreamNormalizer::new(
                                    response.body,
                                    provider_kind,
                                    ctx.request_id.clone(),
                                    response.content_type.clone(),
                                );
                                let (capturing, usage_capture) = StreamingUsageCapturingReader::new(
                                    normalized,
                                    &response.initial_body,
                                );
                                let result = write_streaming_response(
                                    session,
                                    response.status,
                                    "text/event-stream",
                                    response.initial_body,
                                    capturing,
                                    &ctx.request_id,
                                )
                                .await;
                                (result, usage_capture)
                            } else {
                                let (capturing, usage_capture) = StreamingUsageCapturingReader::new(
                                    response.body,
                                    &response.initial_body,
                                );
                                let result = write_streaming_response(
                                    session,
                                    response.status,
                                    &response.content_type,
                                    response.initial_body,
                                    capturing,
                                    &ctx.request_id,
                                )
                                .await;
                                (result, usage_capture)
                            };
                            let captured = usage_capture
                                .lock()
                                .map(|capture| capture.body())
                                .unwrap_or_default();
                            record_pass_through_completion(Some(&captured)).await;
                            return stream_result;
                        }
                        Err(error) => {
                            state.record_provider_failure(&provider.name);
                            match ProviderAttemptDecision::from_dispatch_error(
                                attempt,
                                &attempt_plan,
                            ) {
                                ProviderAttemptDecision::RetryProvider => {
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
                                ProviderAttemptDecision::TryFallbackRoute => {
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
                                ProviderAttemptDecision::ReturnError => {}
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
                let provider_attempt = provider_attempt_sequence.next(&ctx.request_id);
                attempt_plan.log_dispatch_attempt(&provider_attempt, attempt);
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
                            // Reported usage belongs to this concrete dispatch even when
                            // routing continues to a retry or fallback.
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
                            match ProviderAttemptDecision::from_retryable_status(
                                retryable_status,
                                attempt,
                                &attempt_plan,
                            ) {
                                ProviderAttemptDecision::RetryProvider => {
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
                                ProviderAttemptDecision::TryFallbackRoute => {
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
                                ProviderAttemptDecision::ReturnError => {}
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
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    error_code = %error.code,
                                    "billing event write failed"
                                );
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
                            warn!(
                                request_id = %ctx.request_id,
                                logical_model = %request.model,
                                provider = %provider.name,
                                provider_model = %model_route.provider_model,
                                error_code = %error.code,
                                "estimated billing event write failed"
                            );
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
                        let mut final_status = response.status;
                        let mut final_body = response.body;
                        let mut final_content_type = response.content_type;
                        let mut final_error_code = None;
                        let guardrail_envelope = normalize_guardrail_response(
                            endpoint.guardrail_protocol(),
                            &final_body,
                            false,
                        );
                        if let Some(guardrail) = state
                            .match_guardrail(
                                GuardrailStage::Response,
                                GuardrailEvaluationContext {
                                    request_id: &ctx.request_id,
                                    trace_id: ctx.trace_id.as_deref(),
                                    agent_run_id: Some(&agent_run_id),
                                    workflow_id: workflow_id.as_deref(),
                                    workflow_version,
                                    workflow_node_id: workflow_node_id.as_deref(),
                                    actor_api_key_id: auth.api_key_id.as_deref(),
                                    tenant: &policy_request.tenant,
                                    service_account_id: auth.service_account_id(),
                                    gateway_config_id: gateway_config
                                        .as_ref()
                                        .map(|profile| profile.id.as_str()),
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
                            match guardrail.effect {
                                GuardrailEffect::Deny => {
                                    final_status = StatusCode::FORBIDDEN;
                                    final_content_type = "application/json".into();
                                    final_error_code = Some(guardrail.code.clone());
                                    state.record_admin_audit_event(
                                        crate::state::AdminAuditEventDraft { action_identity: Default::default(),
                                            request_id: ctx.request_id.clone(),
                                            trace_id: ctx.trace_id.clone(),
                                            agent_run_id: Some(agent_run_id.clone()),
            workflow_id: workflow_id.clone(),
            workflow_version,
            workflow_node_id: workflow_node_id.clone(),
                                            actor_api_key_id: auth.api_key_id.clone(),
                                            tenant: auth.tenant_context(),
                                            action: "guardrail.deny".into(),
                                            target: guardrail.evidence_target(),
                                            outcome: "blocked".into(),
                                            message: format!(
                                                "guardrail {} blocked response for model {} provider {} at {}",
                                                guardrail.rule_name,
                                                request.model,
                                                provider.name,
                                                guardrail.evidence_location()
                                            ),
                                        },
                                    );
                                    final_body = serde_json::json!({
                                        "error": {
                                            "message": guardrail.message,
                                            "type": "ferrogate_error",
                                            "code": guardrail.code,
                                            "request_id": ctx.request_id.as_str(),
                                        }
                                    })
                                    .to_string()
                                    .into_bytes();
                                }
                                GuardrailEffect::Redact => {
                                    let redacted_body = guardrail
                                        .redact_text(&String::from_utf8_lossy(&final_body));
                                    state.record_admin_audit_event(
                                        crate::state::AdminAuditEventDraft { action_identity: Default::default(),
                                            request_id: ctx.request_id.clone(),
                                            trace_id: ctx.trace_id.clone(),
                                            agent_run_id: Some(agent_run_id.clone()),
            workflow_id: workflow_id.clone(),
            workflow_version,
            workflow_node_id: workflow_node_id.clone(),
                                            actor_api_key_id: auth.api_key_id.clone(),
                                            tenant: auth.tenant_context(),
                                            action: "guardrail.redact".into(),
                                            target: guardrail.evidence_target(),
                                            outcome: "redacted".into(),
                                            message: format!(
                                                "guardrail {} redacted response for model {} provider {} at {}",
                                                guardrail.rule_name,
                                                request.model,
                                                provider.name,
                                                guardrail.evidence_location()
                                            ),
                                        },
                                    );
                                    final_body = redacted_body.into_bytes();
                                }
                            }
                        }
                        let record_bodies =
                            auth.can_record_bodies(state.config.telemetry.log_bodies);
                        state.record_request_log(StoredRequestLog {
                            request_id: ctx.request_id.clone(),
                            trace_id: ctx.trace_id.clone(),
                            agent_run_id: Some(agent_run_id.clone()),
                            workflow_id: workflow_id.clone(),
                            workflow_version,
                            workflow_node_id: workflow_node_id.clone(),
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
                            status_code: final_status.as_u16(),
                            error_code: final_error_code,
                            prompt_recorded: record_bodies,
                            response_recorded: record_bodies,
                            prompt_body: record_bodies.then(|| body_json.to_string()),
                            response_body: record_bodies.then(|| {
                                String::from_utf8_lossy(&final_body)
                                    .chars()
                                    .take(16 * 1024)
                                    .collect()
                            }),
                            cache_status: cache_key.as_ref().map(|_| "miss".to_string()),
                            started_at_unix: Some(request_started_at_unix),
                            completed_at_unix: Some(now_unix_seconds()),
                            parent_action_fingerprint: None,
                        });
                        if let Some(cache_key) = cache_key {
                            if final_status.is_success() {
                                state.store_ai_response_cache(
                                    cache_key,
                                    crate::state::AiCachedResponse {
                                        status_code: final_status.as_u16(),
                                        content_type: final_content_type.clone(),
                                        body: final_body.clone(),
                                    },
                                );
                                // Mirror the store into the semantic layer so a
                                // later paraphrase can match this embedding.
                                if let Some(context) = semantic_ctx {
                                    state.store_semantic_response_cache(
                                        context,
                                        crate::state::AiCachedResponse {
                                            status_code: final_status.as_u16(),
                                            content_type: final_content_type.clone(),
                                            body: final_body.clone(),
                                        },
                                    );
                                }
                            }
                        }

                        return write_raw_response(
                            session,
                            final_status,
                            &final_content_type,
                            final_body.into(),
                            &ctx.request_id,
                        )
                        .await;
                    }
                    Err(error) => {
                        state.record_provider_failure(&provider.name);
                        match ProviderAttemptDecision::from_dispatch_error(attempt, &attempt_plan) {
                            ProviderAttemptDecision::RetryProvider => {
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
                            ProviderAttemptDecision::TryFallbackRoute => {
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
                            ProviderAttemptDecision::ReturnError => {}
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
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
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
            parent_action_fingerprint: None,
        });
    }

    async fn record_ai_workflow_rejection(
        &self,
        session: &mut Session,
        context: AiWorkflowRejectionContext<'_>,
    ) -> PingoraResult<()> {
        self.state.record_request_log(StoredRequestLog {
            request_id: context.ctx.request_id.clone(),
            trace_id: context.ctx.trace_id.clone(),
            agent_run_id: Some(context.agent_run_id.to_string()),
            workflow_id: context.workflow_id.map(ToOwned::to_owned),
            workflow_version: context.workflow_version,
            workflow_node_id: context.workflow_node_id.map(ToOwned::to_owned),
            cluster_id: None,
            node_id: None,
            tenant: context.auth.tenant_context(),
            route: Some(context.endpoint.route().into()),
            provider: None,
            logical_model: Some(context.logical_model.to_string()),
            provider_model: None,
            gateway_config_id: context.gateway_config.map(|profile| profile.id.clone()),
            gateway_config_revision: context.gateway_config.map(|profile| profile.revision),
            status_code: context.rejection.status.as_u16(),
            error_code: Some(context.rejection.code.to_string()),
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(context.now_unix),
            completed_at_unix: Some(context.now_unix),
            parent_action_fingerprint: None,
        });
        write_json_error(
            session,
            context.rejection.status,
            context.rejection.code,
            context.rejection.message,
            &context.ctx.request_id,
        )
        .await
    }
}

struct AiWorkflowRejectionContext<'a> {
    endpoint: AiEndpoint,
    ctx: &'a ProxyContext,
    agent_run_id: &'a str,
    workflow_id: Option<&'a str>,
    workflow_version: Option<u32>,
    workflow_node_id: Option<&'a str>,
    auth: &'a AuthContext,
    gateway_config: Option<&'a GatewayConfigUse>,
    logical_model: &'a str,
    now_unix: u64,
    rejection: AiWorkflowRejection,
}

fn responses_stream_provider_kind(provider_kind: &str) -> ResponsesStreamProviderKind {
    match provider_kind.trim().to_ascii_lowercase().as_str() {
        "openai" | "openai-compatible" | "deepseek" | "newapi" | "sub2api" | "cliproxyapi"
        | "cli-proxy-api" | "vllm" | "llama.cpp" | "llama-cpp" | "llamacpp" | "tgi" | "ollama"
        | "ollama-compatible" => ResponsesStreamProviderKind::OpenAiCompatible,
        "anthropic" => ResponsesStreamProviderKind::Anthropic,
        "gemini" => ResponsesStreamProviderKind::Gemini,
        _ => ResponsesStreamProviderKind::Other,
    }
}

struct AiErrorLog<'a> {
    tenant: TenantContext,
    logical_model: Option<&'a str>,
    provider: Option<&'a str>,
    status: StatusCode,
    error_code: &'a str,
}

#[derive(Debug)]
struct AiRequestPlan {
    auth: AuthContext,
    agent_run_id: String,
    workflow_id: Option<String>,
    workflow_version: Option<u32>,
    workflow_node_id: Option<String>,
    workflow_iteration: Option<u32>,
    gateway_config: Option<GatewayConfigUse>,
    request: ChatCompletionRequest,
    body_json: serde_json::Value,
    estimated_usage: BillingTokenUsage,
    routes: Vec<ModelRoute>,
    guardrail_envelope: GuardrailEnvelope,
}

#[derive(Debug)]
struct AiIngressPlan {
    auth: AuthContext,
    agent_run_id: String,
    workflow_id: Option<String>,
    workflow_version: Option<u32>,
    workflow_node_id: Option<String>,
    workflow_iteration: Option<u32>,
    gateway_config: Option<GatewayConfigUse>,
}

#[derive(Debug)]
struct AiRequestRejection {
    tenant: TenantContext,
    logical_model: Option<String>,
    status: StatusCode,
    code: &'static str,
    message: String,
}

type AiPlanResult<T> = Result<T, Box<AiRequestRejection>>;

fn reject_ai_request(rejection: AiRequestRejection) -> Box<AiRequestRejection> {
    Box::new(rejection)
}

#[derive(Debug)]
pub(super) enum StreamingBodyReadError {
    Io(IoError),
    TooLarge { max_bytes: usize },
    Timeout { timeout: std::time::Duration },
}

impl StreamingBodyReadError {
    pub(super) fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Io(_) => (StatusCode::BAD_GATEWAY, "provider_dispatch_error"),
            Self::TooLarge { .. } => (
                StatusCode::BAD_GATEWAY,
                "guardrail_stream_buffer_limit_exceeded",
            ),
            Self::Timeout { .. } => (
                StatusCode::GATEWAY_TIMEOUT,
                "guardrail_stream_buffer_timeout",
            ),
        }
    }
}

impl fmt::Display for StreamingBodyReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "provider stream read failed: {error}"),
            Self::TooLarge { max_bytes } => write!(
                formatter,
                "guarded provider stream exceeds the {max_bytes}-byte buffer limit"
            ),
            Self::Timeout { timeout } => write!(
                formatter,
                "guarded provider stream did not complete within {} milliseconds",
                timeout.as_millis()
            ),
        }
    }
}

impl std::error::Error for StreamingBodyReadError {}

pub(super) fn extract_last_provider_stream_usage(
    body: &[u8],
    mut extract: impl FnMut(&[u8]) -> Option<ProviderUsage>,
) -> Option<ProviderUsage> {
    let mut event_data = Vec::new();
    let mut merged_usage: Option<ProviderUsage> = None;

    let mut finish_event = |event_data: &mut Vec<u8>| {
        if !event_data.is_empty() && event_data.as_slice() != b"[DONE]" {
            if let Some(usage) = extract(event_data) {
                let previous = merged_usage.take().unwrap_or_default();
                let prompt_tokens = usage.prompt_tokens.or(previous.prompt_tokens);
                let completion_tokens = usage.completion_tokens.or(previous.completion_tokens);
                let total_tokens = usage
                    .total_tokens
                    .or_else(|| {
                        prompt_tokens
                            .zip(completion_tokens)
                            .map(|(prompt, completion)| prompt.saturating_add(completion))
                    })
                    .or(previous.total_tokens);
                merged_usage = Some(ProviderUsage {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                });
            }
        }
        event_data.clear();
    };

    for raw_line in body.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            finish_event(&mut event_data);
            continue;
        }
        let Some(data) = line.strip_prefix(b"data:") else {
            continue;
        };
        let data = data.strip_prefix(b" ").unwrap_or(data);
        if !event_data.is_empty() {
            event_data.push(b'\n');
        }
        event_data.extend_from_slice(data);
    }
    finish_event(&mut event_data);
    merged_usage
}

const STREAMING_USAGE_CAPTURE_MAX_BYTES: usize = 64 * 1024;
const STREAMING_USAGE_CAPTURE_PREFIX_MAX_BYTES: usize = 8 * 1024;
const STREAMING_USAGE_CAPTURE_SEPARATOR: &[u8] = b"\n\n";
const STREAMING_USAGE_CAPTURE_TAIL_MAX_BYTES: usize = STREAMING_USAGE_CAPTURE_MAX_BYTES
    - STREAMING_USAGE_CAPTURE_PREFIX_MAX_BYTES
    - STREAMING_USAGE_CAPTURE_SEPARATOR.len();

#[derive(Debug, Default)]
pub(super) struct StreamingUsageCapture {
    prefix: Vec<u8>,
    body: VecDeque<u8>,
    total_bytes: usize,
}

impl StreamingUsageCapture {
    fn append(&mut self, bytes: &[u8]) {
        let prefix_remaining = STREAMING_USAGE_CAPTURE_PREFIX_MAX_BYTES - self.prefix.len();
        self.prefix
            .extend_from_slice(&bytes[..bytes.len().min(prefix_remaining)]);
        self.total_bytes = self.total_bytes.saturating_add(bytes.len());

        let body_limit = if self.total_bytes > STREAMING_USAGE_CAPTURE_MAX_BYTES {
            STREAMING_USAGE_CAPTURE_TAIL_MAX_BYTES
        } else {
            STREAMING_USAGE_CAPTURE_MAX_BYTES
        };
        if bytes.len() >= body_limit {
            self.body.clear();
            self.body
                .extend(bytes[bytes.len() - body_limit..].iter().copied());
            return;
        }
        let overflow = self
            .body
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(body_limit);
        self.body.drain(..overflow);
        self.body.extend(bytes.iter().copied());
    }

    pub(super) fn body(&self) -> Vec<u8> {
        if self.total_bytes <= STREAMING_USAGE_CAPTURE_MAX_BYTES {
            return self.body.iter().copied().collect();
        }
        let mut body = Vec::with_capacity(STREAMING_USAGE_CAPTURE_MAX_BYTES);
        body.extend_from_slice(&self.prefix);
        body.extend_from_slice(STREAMING_USAGE_CAPTURE_SEPARATOR);
        body.extend(self.body.iter().copied());
        body
    }
}

pub(super) struct StreamingUsageCapturingReader<R> {
    reader: R,
    capture: Arc<Mutex<StreamingUsageCapture>>,
}

impl<R> StreamingUsageCapturingReader<R> {
    pub(super) fn new(reader: R, initial_body: &[u8]) -> (Self, Arc<Mutex<StreamingUsageCapture>>) {
        let mut state = StreamingUsageCapture::default();
        state.append(initial_body);
        let capture = Arc::new(Mutex::new(state));
        (
            Self {
                reader,
                capture: Arc::clone(&capture),
            },
            capture,
        )
    }
}

impl<R: Read> Read for StreamingUsageCapturingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buffer)?;
        if read > 0 {
            if let Ok(mut capture) = self.capture.lock() {
                capture.append(&buffer[..read]);
            }
        }
        Ok(read)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct StreamingCapture {
    pub(super) body: Vec<u8>,
    pub(super) truncated: bool,
}

impl StreamingCapture {
    fn append(&mut self, bytes: &[u8], max_bytes: usize) {
        let remaining = max_bytes.saturating_sub(self.body.len());
        let captured = bytes.len().min(remaining);
        self.body.extend_from_slice(&bytes[..captured]);
        if captured < bytes.len() {
            self.truncated = true;
        }
    }
}

pub(super) struct CapturingReader<R> {
    reader: R,
    capture: Arc<Mutex<StreamingCapture>>,
    max_bytes: usize,
}

impl<R> CapturingReader<R> {
    pub(super) fn new(
        reader: R,
        initial_body: &[u8],
        max_bytes: usize,
    ) -> (Self, Arc<Mutex<StreamingCapture>>) {
        let mut state = StreamingCapture::default();
        state.append(initial_body, max_bytes);
        let capture = Arc::new(Mutex::new(state));
        (
            Self {
                reader,
                capture: Arc::clone(&capture),
                max_bytes,
            },
            capture,
        )
    }
}

impl<R: Read> Read for CapturingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(buffer)?;
        if read > 0 {
            if let Ok(mut capture) = self.capture.lock() {
                capture.append(&buffer[..read], self.max_bytes);
            }
        }
        Ok(read)
    }
}

pub(super) async fn read_provider_streaming_body<R: Read + Send + 'static>(
    initial_body: Vec<u8>,
    mut reader: R,
    max_bytes: usize,
    timeout: std::time::Duration,
) -> Result<Vec<u8>, StreamingBodyReadError> {
    if initial_body.len() > max_bytes {
        return Err(StreamingBodyReadError::TooLarge { max_bytes });
    }
    let read_task = tokio::task::spawn_blocking(move || {
        let mut body = initial_body;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(StreamingBodyReadError::Io)?;
            if read == 0 {
                return Ok(body);
            }
            if body.len().saturating_add(read) > max_bytes {
                return Err(StreamingBodyReadError::TooLarge { max_bytes });
            }
            body.extend_from_slice(&buffer[..read]);
        }
    });
    match tokio::time::timeout(timeout, read_task).await {
        Ok(result) => result.map_err(|error| StreamingBodyReadError::Io(IoError::other(error)))?,
        Err(_) => Err(StreamingBodyReadError::Timeout { timeout }),
    }
}

pub(super) struct AiProviderRequestInput<'a> {
    pub(super) endpoint: AiEndpoint,
    pub(super) provider: &'a Provider,
    pub(super) model_route: &'a ModelRoute,
    pub(super) tenant: &'a TenantContext,
    pub(super) api_key_id: Option<&'a str>,
    pub(super) route: Option<&'a str>,
    pub(super) logical_model: String,
    pub(super) stream: bool,
    pub(super) body: serde_json::Value,
}

fn build_ai_ingress_plan(
    state: &AppState,
    headers: &HeaderMap,
    endpoint: AiEndpoint,
    ctx: &ProxyContext,
) -> AiPlanResult<AiIngressPlan> {
    let auth =
        authenticate(state, headers, endpoint.scope(), &ctx.request_id).map_err(|error| {
            reject_ai_request(AiRequestRejection {
                tenant: TenantContext::default(),
                logical_model: None,
                status: error.status,
                code: error.code,
                message: error.message,
            })
        })?;
    let tenant = auth.tenant_context();

    let agent_run_id = requested_agent_run_id(headers, &ctx.request_id).map_err(|message| {
        reject_ai_request(AiRequestRejection {
            tenant: tenant.clone(),
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_agent_run_id_header",
            message,
        })
    })?;

    let workflow_id =
        requested_optional_id_header(headers, WORKFLOW_ID_HEADER).map_err(|message| {
            reject_ai_request(AiRequestRejection {
                tenant: tenant.clone(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_workflow_header",
                message,
            })
        })?;
    let workflow_version = requested_optional_u32_header(headers, WORKFLOW_VERSION_HEADER)
        .map_err(|message| {
            reject_ai_request(AiRequestRejection {
                tenant: tenant.clone(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_workflow_header",
                message,
            })
        })?;
    let workflow_node_id =
        requested_optional_id_header(headers, WORKFLOW_NODE_ID_HEADER).map_err(|message| {
            reject_ai_request(AiRequestRejection {
                tenant: tenant.clone(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_workflow_header",
                message,
            })
        })?;
    let workflow_iteration = requested_optional_u32_header(headers, WORKFLOW_ITERATION_HEADER)
        .map_err(|message| {
            reject_ai_request(AiRequestRejection {
                tenant: tenant.clone(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_workflow_header",
                message,
            })
        })?;

    if workflow_id.is_none()
        && (workflow_version.is_some()
            || workflow_node_id.is_some()
            || workflow_iteration.is_some())
    {
        return Err(reject_ai_request(AiRequestRejection {
            tenant: tenant.clone(),
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_workflow_header",
            message: format!("{WORKFLOW_ID_HEADER} is required when workflow version, node, or iteration headers are set"),
        }));
    }

    let gateway_config = requested_gateway_config_id(headers)
        .map_err(|message| {
            reject_ai_request(AiRequestRejection {
                tenant: tenant.clone(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_gateway_config_header",
                message,
            })
        })
        .and_then(|profile_id| {
            state
                .resolve_gateway_config_profile(profile_id, auth.api_key_id.as_deref())
                .map_err(|error| {
                    let (status, code, message) = gateway_config_error_response(error);
                    reject_ai_request(AiRequestRejection {
                        tenant: tenant.clone(),
                        logical_model: None,
                        status,
                        code,
                        message,
                    })
                })
        })?;

    if state.is_draining() {
        return Err(reject_ai_request(AiRequestRejection {
            tenant,
            logical_model: None,
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "node_draining",
            message: "gateway node is draining and is not accepting new AI requests".into(),
        }));
    }

    Ok(AiIngressPlan {
        auth,
        agent_run_id,
        workflow_id: workflow_id.map(ToOwned::to_owned),
        workflow_version,
        workflow_node_id: workflow_node_id.map(ToOwned::to_owned),
        workflow_iteration,
        gateway_config,
    })
}

/// Caller-stable key for sticky canary/shadow rollout splits (issue #276):
/// api key first, then tenant identifiers, falling back to the logical model
/// so the split is always deterministic even for unauthenticated-shaped
/// contexts. A given caller consistently lands on (or off) a rollout.
fn rollout_sticky_key(auth: &AuthContext, logical_model: &str) -> String {
    auth.api_key_id
        .clone()
        .or_else(|| auth.organization_id.clone())
        .or_else(|| auth.project_id.clone())
        .unwrap_or_else(|| logical_model.to_string())
}

fn build_ai_request_plan(
    state: &AppState,
    ingress: AiIngressPlan,
    body: &[u8],
    endpoint: AiEndpoint,
) -> AiPlanResult<AiRequestPlan> {
    let AiIngressPlan {
        auth,
        agent_run_id,
        workflow_id,
        workflow_version,
        workflow_node_id,
        workflow_iteration,
        gateway_config,
    } = ingress;

    let body_json: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
        reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: None,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_json",
            message: format!("invalid JSON body: {error}"),
        })
    })?;
    let request: ChatCompletionRequest =
        serde_json::from_value(body_json.clone()).map_err(|error| {
            reject_ai_request(AiRequestRejection {
                tenant: auth.tenant_context(),
                logical_model: None,
                status: StatusCode::BAD_REQUEST,
                code: "invalid_request",
                message: format!("{}: {error}", endpoint.invalid_request_label()),
            })
        })?;
    if let Some(metadata) = &request.metadata {
        if let Err(reason) = ferrogate_billing::validate_request_metadata(metadata) {
            return Err(reject_ai_request(AiRequestRejection {
                tenant: auth.tenant_context(),
                logical_model: Some(request.model.clone()),
                status: StatusCode::BAD_REQUEST,
                code: "invalid_request_metadata",
                message: reason,
            }));
        }
    }

    if !auth.can_use_model(&request.model) {
        return Err(reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "model_not_allowed",
            message: format!("API key is not allowed to use model {}", request.model),
        }));
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
        reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: Some(request.model.clone()),
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        })
    })?;

    authorize_external_rbac(
        state,
        &auth,
        endpoint.scope(),
        &format!("model:{}", request.model),
    )
    .map_err(|error| {
        reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: Some(request.model.clone()),
            status: error.status,
            code: error.code,
            message: error.message,
        })
    })?;

    if !state.can_tenant_use_model(
        &request.model,
        auth.organization_id.as_deref(),
        auth.project_id.as_deref(),
    ) {
        return Err(reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "model_not_visible",
            message: format!("model {} is not visible to this tenant", request.model),
        }));
    }

    let estimated_usage = estimate_chat_completion_usage(&body_json, &request.model);
    let mut routes =
        state.candidate_model_routes(&model, Some(&estimated_usage), &auth.region_allowlist);
    // Canary rollout (issue #276): when the caller's sticky key falls in the
    // canary bucket, promote the configured canary route to the front of the
    // candidate list so it is evaluated exactly like the primary (fully
    // governed/billed/guarded) yet still falls back to the primary on error.
    // A no-op for models without a canary, so unconfigured behavior is
    // unchanged. Applied before the region-empty check so a canary that is
    // the only region-eligible route still serves.
    state.apply_canary_route(
        &request.model,
        &rollout_sticky_key(&auth, &request.model),
        &auth.region_allowlist,
        &mut routes,
    );
    // Fail closed (issue #173): a region-constrained tenant with zero
    // surviving candidates is rejected with a specific, logged reason
    // rather than silently falling through to whatever routes remained
    // (there are none) or an opaque downstream failure.
    if routes.is_empty() && !auth.region_allowlist.is_empty() {
        return Err(reject_ai_request(AiRequestRejection {
            tenant: auth.tenant_context(),
            logical_model: Some(request.model.clone()),
            status: StatusCode::FORBIDDEN,
            code: "region_not_allowed",
            message: format!(
                "no candidate route for model {} satisfies this tenant's region allowlist",
                request.model
            ),
        }));
    }
    let guardrail_envelope = normalize_guardrail_request(endpoint.guardrail_protocol(), &body_json);
    Ok(AiRequestPlan {
        auth,
        agent_run_id,
        workflow_id,
        workflow_version,
        workflow_node_id,
        workflow_iteration,
        gateway_config,
        request,
        body_json,
        estimated_usage,
        routes,
        guardrail_envelope,
    })
}

struct AiProviderAttemptPlan<'a> {
    endpoint: AiEndpoint,
    request_id: &'a str,
    api_key_id: Option<&'a str>,
    organization_id: Option<&'a str>,
    project_id: Option<&'a str>,
    monthly_token_budget: Option<u64>,
    request_limit_per_minute: Option<u64>,
    logical_model: &'a str,
    provider: &'a str,
    provider_model: &'a str,
    candidate_index: usize,
    route_count: usize,
    dispatch_timeout: std::time::Duration,
    max_dispatch_retries: u32,
    stream: bool,
}

#[derive(Debug, Default)]
struct ProviderAttemptSequence {
    next_index: u32,
}

impl ProviderAttemptSequence {
    fn next(&mut self, request_id: &str) -> ProviderAttempt {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        ProviderAttempt::for_request(request_id, index)
    }
}

impl AiProviderAttemptPlan<'_> {
    fn fallback_count(&self) -> usize {
        self.route_count.saturating_sub(1)
    }

    fn has_next_candidate(&self) -> bool {
        has_next_candidate(self.candidate_index, self.route_count)
    }

    fn log_dispatch_attempt(&self, provider_attempt: &ProviderAttempt, route_attempt: u32) {
        info!(
            request_id = %self.request_id,
            provider_attempt_id = %provider_attempt.provider_attempt_id,
            provider_attempt_index = provider_attempt.provider_attempt_index,
            route_attempt,
            candidate_index = self.candidate_index,
            logical_model = %self.logical_model,
            provider = %self.provider,
            provider_model = %self.provider_model,
            stream = self.stream,
            "provider dispatch attempt started"
        );
    }

    fn log_planned_route(&self) {
        match self.endpoint {
            AiEndpoint::ChatCompletions => info!(
                request_id = %self.request_id,
                api_key_id = ?self.api_key_id,
                organization_id = ?self.organization_id,
                project_id = ?self.project_id,
                monthly_token_budget = ?self.monthly_token_budget,
                request_limit_per_minute = ?self.request_limit_per_minute,
                logical_model = %self.logical_model,
                provider = %self.provider,
                provider_model = %self.provider_model,
                candidate_index = self.candidate_index,
                fallback_count = self.fallback_count(),
                provider_dispatch_timeout_secs = self.dispatch_timeout.as_secs(),
                provider_dispatch_max_retries = self.max_dispatch_retries,
                stream = self.stream,
                "chat completion route planned"
            ),
            AiEndpoint::Responses => info!(
                request_id = %self.request_id,
                api_key_id = ?self.api_key_id,
                organization_id = ?self.organization_id,
                project_id = ?self.project_id,
                monthly_token_budget = ?self.monthly_token_budget,
                request_limit_per_minute = ?self.request_limit_per_minute,
                logical_model = %self.logical_model,
                provider = %self.provider,
                provider_model = %self.provider_model,
                candidate_index = self.candidate_index,
                fallback_count = self.fallback_count(),
                provider_dispatch_timeout_secs = self.dispatch_timeout.as_secs(),
                provider_dispatch_max_retries = self.max_dispatch_retries,
                stream = self.stream,
                "responses route planned"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderAttemptDecision {
    RetryProvider,
    TryFallbackRoute,
    ReturnError,
}

impl ProviderAttemptDecision {
    fn from_retryable_status(
        retryable_status: bool,
        attempt: u32,
        plan: &AiProviderAttemptPlan<'_>,
    ) -> Self {
        if retryable_status && attempt < plan.max_dispatch_retries {
            Self::RetryProvider
        } else if retryable_status && plan.has_next_candidate() {
            Self::TryFallbackRoute
        } else {
            Self::ReturnError
        }
    }

    fn from_dispatch_error(attempt: u32, plan: &AiProviderAttemptPlan<'_>) -> Self {
        if attempt < plan.max_dispatch_retries {
            Self::RetryProvider
        } else if plan.has_next_candidate() {
            Self::TryFallbackRoute
        } else {
            Self::ReturnError
        }
    }
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

fn requested_agent_run_id(headers: &HeaderMap, request_id: &str) -> Result<String, String> {
    let Some(value) = headers.get(AGENT_RUN_ID_HEADER) else {
        return Ok(format!("run-{request_id}"));
    };
    let value = value.to_str().map_err(|_| {
        format!("{AGENT_RUN_ID_HEADER} must be valid visible ASCII/UTF-8 header text")
    })?;
    let value = value.trim();
    if value.is_empty() {
        return Ok(format!("run-{request_id}"));
    }
    if value.len() > 128 {
        return Err(format!(
            "{AGENT_RUN_ID_HEADER} must be at most 128 characters"
        ));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return Err(format!(
            "{AGENT_RUN_ID_HEADER} may only contain letters, numbers, _, -, ., or :"
        ));
    }
    Ok(value.to_string())
}

fn requested_optional_id_header<'a>(
    headers: &'a HeaderMap,
    header: &'static str,
) -> Result<Option<&'a str>, String> {
    let Some(value) = headers.get(header) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| format!("{header} must be valid visible ASCII/UTF-8 header text"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        return Err(format!("{header} must be at most 128 characters"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
    {
        return Err(format!(
            "{header} may only contain letters, numbers, _, -, ., or :"
        ));
    }
    Ok(Some(value))
}

fn requested_optional_u32_header(
    headers: &HeaderMap,
    header: &'static str,
) -> Result<Option<u32>, String> {
    let Some(value) = headers.get(header) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| format!("{header} must be valid visible ASCII/UTF-8 header text"))?
        .trim();
    if value.is_empty() {
        return Ok(None);
    }
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{header} must be an unsigned integer"))?;
    if parsed == 0 {
        return Err(format!("{header} must be greater than zero"));
    }
    Ok(Some(parsed))
}

struct AiWorkflowRequestContext<'a> {
    auth: &'a AuthContext,
    agent_run_id: &'a str,
    workflow_id: Option<&'a str>,
    workflow_version: Option<u32>,
    workflow_node_id: Option<&'a str>,
    workflow_iteration: Option<u32>,
    logical_model: &'a str,
    estimated_usage: &'a BillingTokenUsage,
    now_unix: u64,
}

struct AiWorkflowRejection {
    status: StatusCode,
    code: &'static str,
    message: String,
}

struct AiWorkflowProviderConstraint {
    node_id: String,
    providers: Vec<String>,
}

fn enforce_ai_workflow_policy(
    state: &AppState,
    request: AiWorkflowRequestContext<'_>,
) -> Result<Option<AiWorkflowProviderConstraint>, AiWorkflowRejection> {
    let Some(workflow_id) = request.workflow_id else {
        return Ok(None);
    };
    let Some(workflow) = crate::state::select_agent_workflow(
        &state.config.agent_workflows,
        workflow_id,
        request.workflow_version,
    ) else {
        return Err(AiWorkflowRejection {
            status: StatusCode::BAD_REQUEST,
            code: "workflow_not_found",
            message: match request.workflow_version {
                Some(version) => format!("agent workflow {workflow_id}@{version} was not found"),
                None => format!("agent workflow {workflow_id} was not found"),
            },
        });
    };
    if !workflow.enabled {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_disabled",
            message: format!(
                "agent workflow {}@{} is disabled",
                workflow.id, workflow.version
            ),
        });
    }
    if !can_use_workflow(request.auth, workflow) {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_not_allowed",
            message: format!(
                "API key or tenant is not allowed to use agent workflow {}@{}",
                workflow.id, workflow.version
            ),
        });
    }
    let Some(node_id) = request.workflow_node_id else {
        return Err(AiWorkflowRejection {
            status: StatusCode::BAD_REQUEST,
            code: "workflow_node_required",
            message: format!(
                "{WORKFLOW_NODE_ID_HEADER} is required when {WORKFLOW_ID_HEADER} is set"
            ),
        });
    };
    let Some(node) = workflow.nodes.iter().find(|node| node.id == node_id) else {
        return Err(AiWorkflowRejection {
            status: StatusCode::BAD_REQUEST,
            code: "workflow_node_not_found",
            message: format!(
                "agent workflow {}@{} does not contain node {}",
                workflow.id, workflow.version, node_id
            ),
        });
    };
    if node.kind != AgentWorkflowNodeKind::Model {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_node_not_model",
            message: format!("workflow node {node_id} is not allowed to dispatch model traffic"),
        });
    }
    if node
        .model
        .as_deref()
        .is_some_and(|model| model != request.logical_model)
    {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_model_not_allowed",
            message: format!(
                "workflow node {node_id} is not allowed to use model {}",
                request.logical_model
            ),
        });
    }
    if let Some(message) = state.workflow_edge_transition_error(
        workflow,
        request.agent_run_id,
        node_id,
        request.auth.organization_id.as_deref(),
    ) {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_edge_not_allowed",
            message,
        });
    }
    if workflow.max_model_calls.is_some_and(|limit| {
        workflow_model_call_count(state, &workflow.id, workflow.version) >= u64::from(limit)
    }) {
        return Err(AiWorkflowRejection {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "workflow_model_call_limit_exceeded",
            message: format!(
                "agent workflow {}@{} model call limit is exhausted",
                workflow.id, workflow.version
            ),
        });
    }
    if let Some(iteration) = request.workflow_iteration {
        if workflow
            .max_iterations
            .or(node.max_iterations)
            .is_some_and(|limit| iteration > limit)
        {
            return Err(AiWorkflowRejection {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "workflow_iteration_limit_exceeded",
                message: format!(
                    "agent workflow {}@{} iteration {} exceeds configured limit",
                    workflow.id, workflow.version, iteration
                ),
            });
        }
    }
    if let Some(timeout_millis) = workflow.timeout_millis {
        if let Some(started_at_unix) = state.workflow_run_started_at(
            &workflow.id,
            workflow.version,
            request.agent_run_id,
            request.auth.organization_id.as_deref(),
        ) {
            let elapsed_millis = request
                .now_unix
                .saturating_sub(started_at_unix)
                .saturating_mul(1_000);
            if elapsed_millis > timeout_millis {
                return Err(AiWorkflowRejection {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    code: "workflow_timeout_exceeded",
                    message: format!(
                        "agent workflow {}@{} elapsed time exceeded configured timeout",
                        workflow.id, workflow.version
                    ),
                });
            }
        }
    }
    if workflow.token_budget.is_some_and(|budget| {
        workflow_token_usage(state, &workflow.id, workflow.version, None)
            .saturating_add(request.estimated_usage.total_tokens)
            > budget
    }) {
        return Err(AiWorkflowRejection {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "workflow_token_budget_exceeded",
            message: format!(
                "agent workflow {}@{} token budget cannot cover the estimated request usage",
                workflow.id, workflow.version
            ),
        });
    }
    if node.token_budget.is_some_and(|budget| {
        workflow_token_usage(state, &workflow.id, workflow.version, Some(node_id))
            .saturating_add(request.estimated_usage.total_tokens)
            > budget
    }) {
        return Err(AiWorkflowRejection {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "workflow_token_budget_exceeded",
            message: format!(
                "workflow node {node_id} token budget cannot cover the estimated request usage"
            ),
        });
    }
    if node.providers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(AiWorkflowProviderConstraint {
            node_id: node.id.clone(),
            providers: node.providers.clone(),
        }))
    }
}

fn apply_workflow_provider_constraint(
    constraint: Option<&AiWorkflowProviderConstraint>,
    logical_model: &str,
    routes: &mut Vec<ModelRoute>,
) -> Result<(), AiWorkflowRejection> {
    let Some(constraint) = constraint else {
        return Ok(());
    };
    routes.retain(|route| {
        constraint
            .providers
            .iter()
            .any(|provider| provider == &route.provider)
    });
    if routes.is_empty() {
        return Err(AiWorkflowRejection {
            status: StatusCode::FORBIDDEN,
            code: "workflow_provider_not_allowed",
            message: format!(
                "workflow node {} is not allowed to use any configured provider route for model {}",
                constraint.node_id, logical_model
            ),
        });
    }
    Ok(())
}

fn workflow_model_call_count(state: &AppState, workflow_id: &str, workflow_version: u32) -> u64 {
    state
        .metering_events()
        .into_iter()
        .filter(|event| {
            event.workflow_id.as_deref() == Some(workflow_id)
                && event.workflow_version == Some(workflow_version)
        })
        .count() as u64
}

fn workflow_token_usage(
    state: &AppState,
    workflow_id: &str,
    workflow_version: u32,
    workflow_node_id: Option<&str>,
) -> u64 {
    state
        .metering_events()
        .into_iter()
        .filter(|event| {
            event.workflow_id.as_deref() == Some(workflow_id)
                && event.workflow_version == Some(workflow_version)
                && workflow_node_id
                    .is_none_or(|node_id| event.workflow_node_id.as_deref() == Some(node_id))
        })
        .fold(0_u64, |total, event| {
            total.saturating_add(event.usage.total_tokens)
        })
}

fn can_use_workflow(auth: &AuthContext, workflow: &AgentWorkflowPolicy) -> bool {
    if !workflow.api_key_ids.is_empty()
        && !auth
            .api_key_id
            .as_deref()
            .is_some_and(|api_key_id| workflow.api_key_ids.iter().any(|id| id == api_key_id))
    {
        return false;
    }
    if !workflow.organization_ids.is_empty()
        && !auth
            .organization_id
            .as_deref()
            .is_some_and(|organization_id| {
                workflow
                    .organization_ids
                    .iter()
                    .any(|id| id == organization_id)
            })
    {
        return false;
    }
    if !workflow.project_ids.is_empty()
        && !auth
            .project_id
            .as_deref()
            .is_some_and(|project_id| workflow.project_ids.iter().any(|id| id == project_id))
    {
        return false;
    }
    true
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

pub(super) fn prepare_ai_provider_request(
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
        value: SecretValue::new(value),
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
        value: SecretValue::new(value),
    });
}

fn estimate_chat_completion_usage(body: &serde_json::Value, model: &str) -> BillingTokenUsage {
    let prompt_tokens = estimate_prompt_tokens(body, model);
    let completion_tokens = requested_completion_tokens(body)
        .unwrap_or(DEFAULT_COMPLETION_TOKEN_RESERVATION)
        .saturating_mul(requested_choice_count(body));
    BillingTokenUsage::new(
        prompt_tokens,
        completion_tokens,
        prompt_tokens.saturating_add(completion_tokens),
    )
}

/// Pre-dispatch prompt-token estimate. Prefers a local BPE count (issue #282)
/// for model families with a bundled tokenizer, falling back to the `chars/4`
/// heuristic for models without one. The per-message structural overhead is
/// added in both cases (it approximates the ChatML role/format tokens the BPE
/// text count does not include).
fn estimate_prompt_tokens(body: &serde_json::Value, model: &str) -> u64 {
    let text_tokens = match crate::tokenizer::count_tokens(model, &collect_prompt_text(body, None))
    {
        Some(tokens) => tokens,
        None => {
            let chars = prompt_character_count(body, None) as u64;
            chars.saturating_add(3) / 4
        }
    };
    text_tokens.saturating_add(message_overhead_tokens(body))
}

/// Concatenate the prompt-bearing text of a request body (newline-separated so
/// BPE tokens don't merge across field boundaries), mirroring the field filter
/// of [`prompt_character_count`] so the tokenizer sees exactly the text the
/// heuristic would have measured.
fn collect_prompt_text(value: &serde_json::Value, key: Option<&str>) -> String {
    let mut out = String::new();
    append_prompt_text(value, key, &mut out);
    out
}

fn append_prompt_text(value: &serde_json::Value, key: Option<&str>, out: &mut String) {
    if key.is_some_and(is_non_prompt_request_field) {
        return;
    }
    match value {
        serde_json::Value::String(text) => {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(text);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                append_prompt_text(item, None, out);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                append_prompt_text(value, Some(key), out);
            }
        }
        _ => {}
    }
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
#[path = "chat_provider_attempt_test.rs"]
mod provider_attempt_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, Config, GatewayConfigProfile, Model, Provider};
    use std::time::Duration;

    // Round-12 audit regression: a streaming /v1/responses request to a
    // non-OpenAI provider is normalized to the OpenAI/Responses shape before
    // billing. Billing must read usage from THAT shape (via the OpenAI
    // extractor) -- reading it with the origin provider's native extractor
    // finds nothing and falls back to the 512-token estimate, letting a tenant
    // stream unbounded real tokens billed as ~512 (budget/TPM/wallet bypass).
    #[test]
    fn streaming_responses_usage_reads_the_normalized_openai_shape_not_native() {
        use ferrogate_providers::ProviderAdapter;
        // A normalized `response.completed` event exactly as
        // ResponsesStreamNormalizer::finish_stream emits it: OpenAI-shaped usage
        // at the top level, regardless of the origin provider (here Anthropic).
        let normalized = concat!(
            "event: response.completed\n",
            "data: {\"request_id\":\"r\",\"content_type\":\"application/json\",",
            "\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":90000,\"total_tokens\":91000}}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();

        // OLD behavior: the Anthropic native extractor (usage.input_tokens) finds
        // nothing on the normalized body -> None -> 512 estimate (the bug).
        let anthropic = ferrogate_providers::AnthropicAdapter;
        assert!(
            extract_last_provider_stream_usage(normalized, |payload| anthropic
                .extract_usage(payload))
            .is_none(),
            "native extractor must NOT find usage in the normalized body (this is the bug path)",
        );

        // FIXED behavior (endpoint == Responses -> "openai"): real usage extracted.
        let openai = ferrogate_providers::OpenAiCompatibleAdapter;
        let usage =
            extract_last_provider_stream_usage(normalized, |payload| openai.extract_usage(payload))
                .expect("normalized usage must be extractable via the OpenAI shape");
        assert_eq!(usage.prompt_tokens, Some(1000));
        assert_eq!(usage.completion_tokens, Some(90000));
        assert_eq!(usage.total_tokens, Some(91000));
    }

    #[test]
    fn estimates_prompt_and_requested_completion_tokens() {
        let body = serde_json::json!({
            "model": "fast-chat",
            "messages": [{"role": "user", "content": "hello world"}],
            "max_tokens": 7,
            "n": 2
        });

        let usage = estimate_chat_completion_usage(&body, "fast-chat");

        assert_eq!(usage.completion_tokens, 14);
        assert!(usage.prompt_tokens >= 7);
        assert_eq!(
            usage.total_tokens,
            usage.prompt_tokens + usage.completion_tokens
        );
    }

    // Issue #282: for a model with a local tokenizer the pre-request prompt
    // estimate is the real BPE count (plus per-message overhead), not chars/4.
    // The BPE count for this natural-language prompt is strictly below the
    // chars/4 upper bound the unknown-model path would have reserved.
    #[test]
    fn known_model_prompt_estimate_uses_the_local_tokenizer() {
        let content = "The quick brown fox jumps over the lazy dog.";
        let body = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 16,
        });

        let bpe_usage = estimate_chat_completion_usage(&body, "gpt-4o");
        let heuristic_usage = estimate_chat_completion_usage(&body, "unknown-model");

        // Same structural overhead (1 message * 4) applies to both paths, so the
        // difference is purely the prompt text: BPE is tighter than chars/4.
        assert!(
            bpe_usage.prompt_tokens < heuristic_usage.prompt_tokens,
            "bpe prompt {} should be tighter than heuristic prompt {}",
            bpe_usage.prompt_tokens,
            heuristic_usage.prompt_tokens,
        );
        // The prompt side is exactly the BPE count over the collected prompt
        // text (role + content, matching the heuristic's field filter) plus the
        // single-message ChatML overhead (1 * 4) -- i.e. the tokenizer path ran.
        let expected_prompt =
            crate::tokenizer::count_tokens("gpt-4o", &collect_prompt_text(&body, None))
                .expect("gpt-4o has a local encoding")
                + 4;
        assert_eq!(bpe_usage.prompt_tokens, expected_prompt);
    }

    #[test]
    fn reserves_default_completion_tokens_when_unbounded() {
        let body = serde_json::json!({
            "model": "fast-chat",
            "messages": []
        });

        let usage = estimate_chat_completion_usage(&body, "fast-chat");

        assert_eq!(
            usage.completion_tokens,
            DEFAULT_COMPLETION_TOKEN_RESERVATION
        );
        assert_eq!(usage.total_tokens, DEFAULT_COMPLETION_TOKEN_RESERVATION);
    }

    #[test]
    fn provider_attempt_retries_before_fallback_for_retryable_status() {
        let plan = provider_attempt_plan(0, 2, 1);

        let decision = ProviderAttemptDecision::from_retryable_status(true, 0, &plan);

        assert_eq!(decision, ProviderAttemptDecision::RetryProvider);
    }

    #[test]
    fn provider_attempt_falls_back_after_retries_are_exhausted() {
        let plan = provider_attempt_plan(0, 2, 1);

        let decision = ProviderAttemptDecision::from_retryable_status(true, 1, &plan);

        assert_eq!(decision, ProviderAttemptDecision::TryFallbackRoute);
    }

    #[test]
    fn provider_attempt_returns_error_when_no_fallback_remains() {
        let plan = provider_attempt_plan(1, 2, 1);

        let decision = ProviderAttemptDecision::from_dispatch_error(1, &plan);

        assert_eq!(decision, ProviderAttemptDecision::ReturnError);
    }

    #[test]
    fn ai_ingress_plan_rejects_missing_api_key_before_body_planning() {
        let state = AppState::new(ai_plan_config());
        let headers = HeaderMap::new();
        let ctx = proxy_context();

        let rejection =
            build_ai_ingress_plan(&state, &headers, AiEndpoint::ChatCompletions, &ctx).unwrap_err();

        assert_eq!(rejection.status, StatusCode::UNAUTHORIZED);
        assert_eq!(rejection.code, "missing_api_key");
        assert_eq!(rejection.logical_model, None);
    }

    #[test]
    fn ai_request_plan_resolves_gateway_config_model_and_routes() {
        let state = AppState::new(ai_plan_config());
        let headers = ai_plan_headers(Some("profile-fast"));
        let ctx = proxy_context();
        let ingress =
            build_ai_ingress_plan(&state, &headers, AiEndpoint::ChatCompletions, &ctx).unwrap();
        let body = br#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}],"stream":true}"#;

        let plan =
            build_ai_request_plan(&state, ingress, body, AiEndpoint::ChatCompletions).unwrap();

        assert_eq!(plan.auth.api_key_id.as_deref(), Some("key_dev"));
        assert_eq!(
            plan.gateway_config
                .as_ref()
                .map(|profile| profile.id.as_str()),
            Some("profile-fast")
        );
        assert_eq!(plan.request.model, "fast-chat");
        assert!(plan.request.stream);
        assert_eq!(plan.routes.len(), 1);
        assert_eq!(plan.routes[0].provider, "openai");
        assert_eq!(plan.routes[0].provider_model, "gpt-test");
        assert!(plan.estimated_usage.total_tokens > 0);
        assert!(plan.guardrail_envelope.flattened_text().contains("hello"));
    }

    #[test]
    fn ai_request_plan_rejects_model_outside_tenant_visibility() {
        let mut config = ai_plan_config();
        config.models[0].visible_project_ids = vec!["project-other".into()];
        let state = AppState::new(config);
        let headers = ai_plan_headers(None);
        let ctx = proxy_context();
        let ingress =
            build_ai_ingress_plan(&state, &headers, AiEndpoint::ChatCompletions, &ctx).unwrap();
        let body = br#"{"model":"fast-chat","messages":[]}"#;

        let rejection =
            build_ai_request_plan(&state, ingress, body, AiEndpoint::ChatCompletions).unwrap_err();

        assert_eq!(rejection.status, StatusCode::FORBIDDEN);
        assert_eq!(rejection.code, "model_not_visible");
        assert_eq!(rejection.logical_model.as_deref(), Some("fast-chat"));
    }

    fn provider_attempt_plan(
        candidate_index: usize,
        route_count: usize,
        max_dispatch_retries: u32,
    ) -> AiProviderAttemptPlan<'static> {
        AiProviderAttemptPlan {
            endpoint: AiEndpoint::ChatCompletions,
            request_id: "fg-test",
            api_key_id: Some("key_dev"),
            organization_id: Some("org_demo"),
            project_id: Some("project_gateway"),
            monthly_token_budget: Some(1024),
            request_limit_per_minute: Some(60),
            logical_model: "fast-chat",
            provider: "openai",
            provider_model: "gpt-test",
            candidate_index,
            route_count,
            dispatch_timeout: Duration::from_secs(2),
            max_dispatch_retries,
            stream: false,
        }
    }

    fn ai_plan_config() -> Config {
        Config {
            providers: vec![Provider {
                region: None,
                aws_access_key_id: None,
                aws_secret_access_key_env: None,
                aws_session_token_env: None,
                gcp_project_id: None,
                gcp_access_token_env: None,
                name: "openai".into(),
                kind: "openai".into(),
                base_url: "http://127.0.0.1:9999/v1".into(),
                api_key_env: None,
                secret_ref: None,
                openrouter_http_referer: None,
                openrouter_x_title: None,
                enabled: true,
            }],
            models: vec![Model {
                name: "fast-chat".into(),
                provider: "openai".into(),
                provider_model: "gpt-test".into(),
                routing_strategy: ferrogate_providers::RoutingStrategy::Priority,
                canary: None,
                shadow: None,
                fallbacks: Vec::new(),
                visible_organization_ids: Vec::new(),
                visible_project_ids: vec!["project_gateway".into()],
                capabilities: vec!["chat".into(), "streaming".into()],
                context_window: Some(8192),
                input_price_per_1m: None,
                output_price_per_1m: None,
                enabled: true,
                cache_enabled: None,
            }],
            api_keys: vec![ApiKey {
                region_allowlist: Vec::new(),
                id: "key_dev".into(),
                name: "Development key".into(),
                key_env: None,
                key: Some("secret".into()),
                key_hash: None,
                enabled: true,
                scopes: vec!["chat.completions".into(), "responses.create".into()],
                allowed_models: Vec::new(),
                denied_models: Vec::new(),
                allowed_providers: Vec::new(),
                denied_providers: Vec::new(),
                organization_id: Some("org_demo".into()),
                team_id: None,
                project_id: Some("project_gateway".into()),
                workspace_id: None,
                user_id: None,
                monthly_token_budget: Some(1024),
                request_limit_per_minute: None,
                expires_at_unix: None,
                log_bodies: Some(true),
                cache_enabled: None,
            }],
            gateway_configs: vec![GatewayConfigProfile {
                id: "profile-fast".into(),
                name: "Fast profile".into(),
                revision: 7,
                enabled: true,
                api_key_ids: vec!["key_dev".into()],
                cache_enabled: Some(true),
            }],
            ..Config::default()
        }
    }

    fn ai_plan_headers(profile_id: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer secret"),
        );
        if let Some(profile_id) = profile_id {
            headers.insert(
                GATEWAY_CONFIG_HEADER,
                http::HeaderValue::from_str(profile_id).unwrap(),
            );
        }
        headers
    }

    fn proxy_context() -> ProxyContext {
        ProxyContext {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            ..ProxyContext::default()
        }
    }

    #[test]
    fn add_trace_context_headers_preserves_provider_header_precedence() {
        let mut request = ProviderHttpRequest {
            provider: "openai".into(),
            endpoint: "http://provider.test/v1/chat/completions".into(),
            body: serde_json::json!({}),
            stream: false,
            headers: vec![ProviderHeader {
                name: "traceparent".into(),
                value: SecretValue::new("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"),
            }],
        };
        let ctx = ProxyContext {
            traceparent: Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into()),
            tracestate: Some("token4ai=ingress".into()),
            ..proxy_context()
        };

        add_trace_context_headers(&mut request, &ctx);

        let traceparent_headers = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("traceparent"))
            .collect::<Vec<_>>();
        assert_eq!(traceparent_headers.len(), 1);
        assert_eq!(
            traceparent_headers[0].value.expose_secret(),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        );
        assert!(request.headers.iter().any(|header| {
            header.name == "tracestate" && header.value.expose_secret() == "token4ai=ingress"
        }));
    }

    #[tokio::test]
    async fn guarded_stream_buffer_enforces_byte_and_time_limits() {
        let too_large = read_provider_streaming_body(
            Vec::new(),
            Cursor::new(b"12345".to_vec()),
            4,
            std::time::Duration::from_secs(1),
        )
        .await
        .expect_err("oversized guarded stream must fail before response write");
        assert!(matches!(
            too_large,
            StreamingBodyReadError::TooLarge { max_bytes: 4 }
        ));

        struct SlowReader;
        impl Read for SlowReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(100));
                Ok(0)
            }
        }
        let timed_out = read_provider_streaming_body(
            Vec::new(),
            SlowReader,
            1024,
            std::time::Duration::from_millis(10),
        )
        .await
        .expect_err("slow guarded stream must hit its deadline");
        assert!(matches!(timed_out, StreamingBodyReadError::Timeout { .. }));
    }

    #[test]
    fn shadow_capture_never_interrupts_pass_through_when_capture_is_full() {
        let (mut reader, capture) =
            CapturingReader::new(Cursor::new(b"full-stream".to_vec()), b"pre-", 6);
        let mut forwarded = Vec::new();
        reader.read_to_end(&mut forwarded).unwrap();
        assert_eq!(forwarded, b"full-stream");
        let capture = capture.lock().unwrap();
        assert_eq!(capture.body, b"pre-fu");
        assert!(capture.truncated);
    }
}
