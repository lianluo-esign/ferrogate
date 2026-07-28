// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Anthropic-native `POST /v1/messages` ingress (issue #272).
// Claude-protocol clients (Claude Code and the wider coding-agent ecosystem)
// point at FerroGate directly. The Anthropic Messages request is translated
// into an OpenAI chat-completions request and driven through the SAME governed
// chokepoint the `/v1/chat/completions` ingress uses -- auth, model/provider
// resolution, region fail-closed routing, request-stage guardrail, policy
// engine, budget/TPM/prepaid-wallet quotas, provider dispatch with
// retry/fallback, response-stage guardrail (block/redact), usage metering, and
// request logging. Only the wire framing differs: the provider's chat-completion
// response is translated back into an Anthropic Messages object (non-streaming)
// or Anthropic event frames (streaming). No governance bypass; the pipeline
// mirrors `chat.rs`/`embeddings.rs` so the three stay auditable side by side.
//
// Scope note (issue #310): streaming requests now flow through the SAME
// incremental streaming machinery chat completions uses. The provider's chat
// SSE stream is translated frame-by-frame into Anthropic event frames by
// `MessagesStreamNormalizer` and written to the client as it arrives; usage is
// captured from the RAW provider SSE and settled at stream end with the origin
// provider's native extractor (the #213 lesson: extract from the shape that
// actually flows through the capture point). Streaming guardrail semantics
// mirror `chat.rs`: a matching BufferAndEnforce response policy buffers the
// whole stream and enforces block/redact before first-byte release (the
// pre-#310 behaviour), ShadowAfterComplete evaluates the captured stream after
// pass-through delivery, and the RAII token-budget reservation is held until
// the stream completes and its usage is recorded. Non-streaming requests keep
// the buffered path unchanged. Translation targets OpenAI-compatible upstreams
// (the acceptance path); native-Anthropic-upstream SSE remains a follow-up.

use http::{HeaderMap, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Deserialize;
use std::{
    io::{Cursor, Read},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tracing::warn;

use crate::auth::{authorize_external_rbac, AuthContext};
use crate::{
    auth::authenticate,
    responses::{
        streaming_body_channel, write_json_error, write_raw_response,
        write_streaming_bytes_response, write_streaming_response,
    },
    state::{
        AdminAuditEventDraft, AppState, BillingEventDraft, GuardrailEvaluationContext,
        StreamingGuardrailPlan, ToolInjectionContext,
    },
};
use ferrogate_billing::{ProviderAttempt, TokenUsage as BillingTokenUsage};
use ferrogate_config::{GuardrailEffect, GuardrailStage};
use ferrogate_core::{RequestContext, TenantContext};
use ferrogate_guardrails::{
    normalize_request as normalize_guardrail_request,
    normalize_response as normalize_guardrail_response, GuardrailEnvelope, GuardrailProtocol,
    PolicySelectionContext,
};
use ferrogate_policy::PolicyDecision;
use ferrogate_providers::{
    anthropic_messages, ModelRegistryError, ProviderHeader, ProviderHttpRequest, SecretValue,
};
use ferrogate_storage::StoredRequestLog;

use crate::model_routing::{
    conservative_input_token_upper_bound, ModelEndpointKind, ModelRouteRequirements,
    ModelRoutingAuditContext, ModelRoutingDecision,
};

use super::{
    body::read_request_body,
    chat::{
        extract_last_provider_stream_usage, read_provider_streaming_body, CapturingReader,
        StreamingBodyReadError, StreamingCapture, StreamingUsageCapturingReader,
    },
    dispatch::{
        dispatch_provider_request, dispatch_provider_streaming_request, provider_endpoint_origin,
        ProviderStreamingResponse,
    },
    messages_stream::{
        chat_sse_to_completion, error_sse, message_to_anthropic_sse, MessagesStreamNormalizer,
    },
    FerroGateway, ProxyContext,
};

#[cfg(test)]
#[path = "messages_test.rs"]
mod messages_test;

const MESSAGES_SCOPE: &str = "messages.create";
const MESSAGES_ROUTE: &str = "anthropic.messages";
const DEFAULT_COMPLETION_TOKEN_RESERVATION: u64 = 512;

#[derive(Debug, Deserialize)]
struct AnthropicMessagesRequest {
    model: String,
    #[serde(default)]
    stream: bool,
}

impl FerroGateway {
    pub(super) async fn handle_messages(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        let auth = match authenticate(&state, &headers, MESSAGES_SCOPE, &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                self.record_messages_error_log(
                    ctx,
                    TenantContext::default(),
                    None,
                    None,
                    error.status,
                    error.code,
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        false,
                        error.status,
                        error.code,
                        error.message,
                    )
                    .await;
            }
        };
        let tenant = auth.tenant_context();

        if state.is_draining() {
            self.record_messages_error_log(
                ctx,
                tenant,
                None,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "node_draining",
            );
            return self
                .write_messages_error(
                    session,
                    ctx,
                    false,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "node_draining",
                    "gateway node is draining and is not accepting new requests".to_string(),
                )
                .await;
        }

        let body =
            match read_request_body(session, state.limits().inference_body_max_bytes()).await? {
                Ok(body) => body,
                Err(limit) => {
                    self.record_messages_error_log(
                        ctx,
                        tenant,
                        None,
                        None,
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "payload_too_large",
                    );
                    return self
                        .write_messages_error(
                            session,
                            ctx,
                            false,
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "payload_too_large",
                            format!(
                                "request body exceeds maximum size of {} bytes",
                                limit.max_bytes
                            ),
                        )
                        .await;
                }
            };

        let plan = match build_messages_request_plan(&state, &auth, &body) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.record_messages_error_log(
                    ctx,
                    tenant,
                    rejection.logical_model.as_deref(),
                    None,
                    rejection.status,
                    rejection.code,
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        rejection.stream,
                        rejection.status,
                        rejection.code,
                        rejection.message,
                    )
                    .await;
            }
        };
        let MessagesRequestPlan {
            request,
            chat_body,
            estimated_usage,
            routing,
            guardrail_envelope,
        } = plan;
        let stream = request.stream;
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
            self.record_messages_error_log(ctx, tenant, Some(&request.model), None, status, code);
            return self
                .write_messages_error(session, ctx, stream, status, code, message)
                .await;
        }
        let routes = routing.eligible_routes;

        let request_started_at_unix = now_unix_seconds();
        let route_count = routes.len();
        let dispatch_timeout = state.provider_dispatch_timeout();
        let max_dispatch_retries = state.provider_dispatch_max_retries();
        let provider_response_body_max_bytes = state.provider_response_body_max_bytes();
        let mut token_reservation = None;
        let mut wallet_reservation = None;
        let mut tpm_checked = false;
        let mut provider_attempt_index: u32 = 0;

        'routes: for (candidate_index, model_route) in routes.iter().enumerate() {
            let Some(provider) = state.providers.get(&model_route.provider) else {
                self.record_messages_error_log(
                    ctx,
                    tenant.clone(),
                    Some(&request.model),
                    Some(&model_route.provider),
                    StatusCode::BAD_GATEWAY,
                    "provider_not_found",
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        stream,
                        StatusCode::BAD_GATEWAY,
                        "provider_not_found",
                        format!("provider {} not found", model_route.provider),
                    )
                    .await;
            };

            if !state.provider_circuit_allows(&provider.name) {
                if has_next_candidate(candidate_index, route_count) {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        "messages provider circuit open; trying fallback route"
                    );
                    continue;
                }
                self.record_messages_error_log(
                    ctx,
                    tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "provider_circuit_open",
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        stream,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "provider_circuit_open",
                        format!("provider {} circuit is open", provider.name),
                    )
                    .await;
            }

            if !auth.can_use_provider(&provider.name) {
                self.record_messages_error_log(
                    ctx,
                    tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::FORBIDDEN,
                    "provider_not_allowed",
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        stream,
                        StatusCode::FORBIDDEN,
                        "provider_not_allowed",
                        format!("API key is not allowed to use provider {}", provider.name),
                    )
                    .await;
            }

            let policy_request = RequestContext {
                request_id: ctx.request_id.clone(),
                trace_id: ctx.trace_id.clone(),
                agent_run_id: None,
                workflow_id: None,
                workflow_version: None,
                workflow_node_id: None,
                route: Some(MESSAGES_ROUTE.into()),
                upstream: Some(provider.name.clone()),
                tenant: tenant.clone(),
            };

            if let Some(guardrail) = state
                .match_guardrail(
                    GuardrailStage::Request,
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
                        streaming: stream,
                        envelope: &guardrail_envelope,
                        managed_action: None,
                        action_fingerprint: None,
                    },
                )
                .await
            {
                state.record_guardrail_match(&guardrail);
                self.record_messages_error_log(
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
                        "guardrail {} blocked messages request for model {} provider {} at {}",
                        guardrail.rule_name,
                        request.model,
                        provider.name,
                        guardrail.evidence_location()
                    ),
                });
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        stream,
                        StatusCode::FORBIDDEN,
                        &guardrail.code,
                        guardrail.message.clone(),
                    )
                    .await;
            }

            if let PolicyDecision::Deny { code, message } =
                state.evaluate_policy(&policy_request, Some(&request.model), Some(&provider.name))
            {
                self.record_messages_error_log(
                    ctx,
                    policy_request.tenant.clone(),
                    Some(&request.model),
                    Some(&provider.name),
                    StatusCode::FORBIDDEN,
                    &code,
                );
                return self
                    .write_messages_error(
                        session,
                        ctx,
                        stream,
                        StatusCode::FORBIDDEN,
                        &code,
                        message,
                    )
                    .await;
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
                            self.record_messages_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::TOO_MANY_REQUESTS,
                                "token_budget_exceeded",
                            );
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::TOO_MANY_REQUESTS,
                                    "token_budget_exceeded",
                                    "API key token budget cannot cover the estimated request usage"
                                        .to_string(),
                                )
                                .await;
                        }
                        Err(error) => {
                            self.record_messages_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::SERVICE_UNAVAILABLE,
                                "governance_counter_unavailable",
                            );
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "governance_counter_unavailable",
                                    format!("gateway counter backend is unavailable: {error}"),
                                )
                                .await;
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
                            self.record_messages_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::TOO_MANY_REQUESTS,
                                "tpm_limit_exceeded",
                            );
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::TOO_MANY_REQUESTS,
                                    "tpm_limit_exceeded",
                                    "quota policy tokens-per-minute limit is exhausted for this request"
                                        .to_string(),
                                )
                                .await;
                        }
                        Err(error) => {
                            self.record_messages_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::SERVICE_UNAVAILABLE,
                                "governance_counter_unavailable",
                            );
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "governance_counter_unavailable",
                                    format!("gateway counter backend is unavailable: {error}"),
                                )
                                .await;
                        }
                    }
                }
            }

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
                        self.record_messages_error_log(
                            ctx,
                            policy_request.tenant.clone(),
                            Some(&request.model),
                            Some(&provider.name),
                            StatusCode::TOO_MANY_REQUESTS,
                            "wallet_balance_exhausted",
                        );
                        return self
                            .write_messages_error(
                                session,
                                ctx,
                                stream,
                                StatusCode::TOO_MANY_REQUESTS,
                                "wallet_balance_exhausted",
                                "prepaid credit balance cannot cover the estimated request cost"
                                    .to_string(),
                            )
                            .await;
                    }
                    Err(error) => {
                        self.record_messages_error_log(
                            ctx,
                            policy_request.tenant.clone(),
                            Some(&request.model),
                            Some(&provider.name),
                            StatusCode::SERVICE_UNAVAILABLE,
                            "wallet_reservation_unavailable",
                        );
                        return self
                            .write_messages_error(
                                session,
                                ctx,
                                stream,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "wallet_reservation_unavailable",
                                format!("wallet balance reservation failed: {error}"),
                            )
                            .await;
                    }
                }
            }

            let mut prepared = match state.prepare_chat_completions(
                provider,
                model_route,
                ToolInjectionContext {
                    tenant: &policy_request.tenant,
                    api_key_id: auth.api_key_id.as_deref(),
                    route: Some(MESSAGES_ROUTE),
                },
                request.model.clone(),
                stream,
                chat_body.clone(),
            ) {
                Ok(prepared) => prepared,
                Err(error) if has_next_candidate(candidate_index, route_count) => {
                    warn!(
                        request_id = %ctx.request_id,
                        logical_model = %request.model,
                        provider = %provider.name,
                        error = ?error,
                        "messages provider adapter failed; trying fallback route"
                    );
                    continue;
                }
                Err(error) => {
                    self.record_messages_error_log(
                        ctx,
                        policy_request.tenant.clone(),
                        Some(&request.model),
                        Some(&provider.name),
                        StatusCode::BAD_GATEWAY,
                        "provider_adapter_error",
                    );
                    return self
                        .write_messages_error(
                            session,
                            ctx,
                            stream,
                            StatusCode::BAD_GATEWAY,
                            "provider_adapter_error",
                            format!("provider adapter failed: {error:?}"),
                        )
                        .await;
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

                let outcome = if stream {
                    dispatch_provider_streaming_request(attempt_request, dispatch_timeout)
                        .await
                        .map(MessagesProviderResponse::Streaming)
                } else {
                    dispatch_provider_request(
                        attempt_request,
                        dispatch_timeout,
                        provider_response_body_max_bytes,
                    )
                    .await
                    .map(|response| {
                        MessagesProviderResponse::Buffered(BufferedProviderResponse {
                            status: response.status,
                            content_type: response.content_type,
                            body: response.body,
                        })
                    })
                };

                let provider_response = match outcome {
                    Ok(response) => response,
                    Err(error) => {
                        state.record_provider_failure(&provider.name);
                        match messages_attempt_decision(
                            true,
                            attempt,
                            max_dispatch_retries,
                            candidate_index,
                            route_count,
                        ) {
                            MessagesAttemptDecision::RetryProvider => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    attempt,
                                    error = ?error,
                                    "messages provider dispatch failed; retrying provider"
                                );
                                attempt += 1;
                                continue;
                            }
                            MessagesAttemptDecision::TryFallbackRoute => {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    candidate_index,
                                    error = ?error,
                                    "messages provider dispatch failed; trying fallback route"
                                );
                                continue 'routes;
                            }
                            MessagesAttemptDecision::ReturnError => {}
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
                            stream,
                            error = ?error,
                            "messages provider dispatch failed; returning provider_dispatch_error"
                        );
                        self.record_messages_error_log(
                            ctx,
                            auth.tenant_context(),
                            Some(&request.model),
                            None,
                            StatusCode::BAD_GATEWAY,
                            "provider_dispatch_error",
                        );
                        return self
                            .write_messages_error(
                                session,
                                ctx,
                                stream,
                                StatusCode::BAD_GATEWAY,
                                "provider_dispatch_error",
                                format!("provider dispatch failed: {error}"),
                            )
                            .await;
                    }
                };

                let response = match provider_response {
                    MessagesProviderResponse::Buffered(response) => response,
                    MessagesProviderResponse::Streaming(streaming) => {
                        let status = streaming.status;
                        let is_error_status = status.is_client_error() || status.is_server_error();
                        // Mirror chat.rs streaming guardrail semantics: only a
                        // matching Enforce+BufferAndEnforce response policy
                        // forces whole-stream buffering before first-byte
                        // release; otherwise the stream passes through
                        // incrementally (with ShadowAfterComplete evaluating
                        // the captured stream afterwards).
                        let streaming_guardrail_plan =
                            state.streaming_guardrail_plan(PolicySelectionContext {
                                organization_id: policy_request.tenant.organization_id.as_deref(),
                                project_id: policy_request.tenant.project_id.as_deref(),
                                workspace_id: policy_request.tenant.workspace_id.as_deref(),
                                api_key_id: policy_request.tenant.api_key_id.as_deref(),
                                service_account_id: auth.service_account_id(),
                                gateway_config_id: None,
                                model: Some(&request.model),
                                provider: Some(&provider.name),
                                managed_action: None,
                            });
                        if is_error_status
                            || streaming_guardrail_plan == StreamingGuardrailPlan::BufferAndEnforce
                        {
                            // Buffer to completion: provider errors so the
                            // shared error handling below governs (and bills)
                            // them, BufferAndEnforce so the response guardrail
                            // can block/redact before any byte reaches the
                            // client -- the pre-#310 governed path.
                            let content_type = streaming.content_type;
                            let (upstream, feed_reader) = streaming_body_channel(streaming.body);
                            match read_provider_streaming_body(
                                streaming.initial_body,
                                upstream,
                                feed_reader,
                                provider_response_body_max_bytes,
                                dispatch_timeout,
                            )
                            .await
                            {
                                Ok(body) => BufferedProviderResponse {
                                    status,
                                    content_type,
                                    body,
                                },
                                Err(error) => {
                                    return self
                                        .write_messages_stream_buffer_failure(
                                            session,
                                            ctx,
                                            &state,
                                            &auth,
                                            &policy_request.tenant,
                                            &request.model,
                                            &provider.name,
                                            error,
                                        )
                                        .await;
                                }
                            }
                        } else {
                            state.record_provider_success(&provider.name);
                            // Do NOT settle the token reservation here: it is
                            // RAII (Drop releases on every exit path), and
                            // holding it in `token_reservation` keeps the
                            // budget reserved for the whole stream -- released
                            // only when this handler returns, after the
                            // stream's usage has been recorded below (the
                            // round-7 chat.rs lesson). The wallet reservation
                            // is held the same way.
                            let record_bodies =
                                auth.can_record_bodies(state.config.telemetry.log_bodies);
                            let shadow = streaming_guardrail_plan
                                == StreamingGuardrailPlan::ShadowAfterComplete;
                            let (upstream, feed_reader) = streaming_body_channel(streaming.body);
                            let raw = Cursor::new(streaming.initial_body).chain(feed_reader);
                            let (usage_reader, usage_capture) =
                                StreamingUsageCapturingReader::new(raw, &[]);
                            let (reader, shadow_capture): (Box<dyn Read + Send>, _) = if shadow {
                                let (capturing, capture) = CapturingReader::new(
                                    usage_reader,
                                    &[],
                                    provider_response_body_max_bytes,
                                );
                                (Box::new(capturing), Some(capture))
                            } else {
                                (Box::new(usage_reader), None)
                            };
                            let normalizer =
                                MessagesStreamNormalizer::new(reader, request.model.clone());
                            let stream_result = write_streaming_response(
                                session,
                                status,
                                "text/event-stream",
                                Vec::new(),
                                upstream,
                                normalizer,
                                &ctx.request_id,
                            )
                            .await;

                            // Usage settlement (#213/round-12 lesson): the
                            // capture point sits on the RAW provider SSE,
                            // BEFORE the Anthropic-frame translation reshapes
                            // it, so the ORIGIN provider's native extractor is
                            // the correct one -- the same shape whose usage the
                            // buffered path's reconstructed completion carries.
                            let usage_body = usage_capture
                                .lock()
                                .map(|capture| capture.body())
                                .unwrap_or_default();
                            let reported_usage =
                                extract_last_provider_stream_usage(&usage_body, |payload| {
                                    state
                                        .extract_provider_usage(&provider.kind, payload)
                                        .ok()
                                        .flatten()
                                });
                            let billed = if let Some(usage) = reported_usage {
                                state
                                    .record_provider_attempt_billing_event(
                                        BillingEventDraft {
                                            request: &policy_request,
                                            logical_model: &request.model,
                                            provider: &provider.name,
                                            provider_model: &model_route.provider_model,
                                            status_code: status.as_u16(),
                                            latency_ms: Some(
                                                attempt_started_at.elapsed().as_millis() as u64,
                                            ),
                                            metadata: None,
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
                                            status_code: status.as_u16(),
                                            latency_ms: Some(
                                                attempt_started_at.elapsed().as_millis() as u64,
                                            ),
                                            metadata: None,
                                        },
                                        &provider_attempt,
                                        &estimated_usage,
                                    )
                                    .await
                            };
                            if let Err(error) = billed {
                                warn!(
                                    request_id = %ctx.request_id,
                                    logical_model = %request.model,
                                    provider = %provider.name,
                                    provider_model = %model_route.provider_model,
                                    error_code = %error.code,
                                    "messages streaming billing event write failed"
                                );
                            }

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
                                status_code: status.as_u16(),
                                error_code: None,
                                prompt_recorded: record_bodies,
                                response_recorded: false,
                                prompt_body: record_bodies.then(|| chat_body.to_string()),
                                response_body: None,
                                cache_status: None,
                                started_at_unix: Some(request_started_at_unix),
                                completed_at_unix: Some(now_unix_seconds()),
                                parent_action_fingerprint: None,
                            });

                            if let Some(capture) = shadow_capture {
                                let captured = capture
                                    .lock()
                                    .map(|capture| capture.clone())
                                    .unwrap_or(StreamingCapture {
                                        body: Vec::new(),
                                        truncated: true,
                                    });
                                if stream_result.is_ok() {
                                    // Shadow evaluation runs on the RAW chat
                                    // SSE capture with the ChatCompletions
                                    // protocol -- the same envelope chat.rs
                                    // streaming uses.
                                    let guardrail_envelope = normalize_guardrail_response(
                                        GuardrailProtocol::ChatCompletions,
                                        &captured.body,
                                        true,
                                    );
                                    let evaluation_context = GuardrailEvaluationContext {
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
                            }
                            return stream_result;
                        }
                    }
                };

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
                                        attempt_started_at.elapsed().as_millis() as u64
                                    ),
                                    metadata: None,
                                },
                                &provider_attempt,
                                &usage,
                            )
                            .await
                        {
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::BAD_GATEWAY,
                                    &error.code,
                                    error.message,
                                )
                                .await;
                        }
                    }
                    let retryable_status = state
                        .is_provider_status_retryable(&provider.kind, response.status.as_u16())
                        .unwrap_or(false);
                    if retryable_status {
                        state.record_provider_failure(&provider.name);
                    }
                    match messages_attempt_decision(
                        retryable_status,
                        attempt,
                        max_dispatch_retries,
                        candidate_index,
                        route_count,
                    ) {
                        MessagesAttemptDecision::RetryProvider => {
                            attempt += 1;
                            continue;
                        }
                        MessagesAttemptDecision::TryFallbackRoute => continue 'routes,
                        MessagesAttemptDecision::ReturnError => {}
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
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::BAD_GATEWAY,
                                    "provider_adapter_error",
                                    format!("provider adapter failed: {error:?}"),
                                )
                                .await;
                        }
                    };
                    let message = normalized.body["error"]["message"]
                        .as_str()
                        .unwrap_or("provider returned an error")
                        .to_string();
                    let code = normalized.body["error"]["code"]
                        .as_str()
                        .unwrap_or("provider_error")
                        .to_string();
                    self.record_messages_error_log(
                        ctx,
                        policy_request.tenant.clone(),
                        Some(&request.model),
                        Some(&provider.name),
                        response.status,
                        &code,
                    );
                    return self
                        .write_messages_error(session, ctx, stream, response.status, &code, message)
                        .await;
                }

                state.record_provider_success(&provider.name);

                // Reconstruct a single chat-completion object from the provider
                // response (buffered SSE for a streaming request, JSON for a
                // non-streaming one) so metering, the response-stage guardrail,
                // and Anthropic translation all operate on one governed body.
                let completion = if stream {
                    chat_sse_to_completion(&response.body)
                } else {
                    serde_json::from_slice::<serde_json::Value>(&response.body)
                        .unwrap_or_else(|_| serde_json::json!({}))
                };
                let completion_bytes = serde_json::to_vec(&completion).unwrap_or_default();

                let billed = match state.extract_provider_usage(&provider.kind, &completion_bytes) {
                    Ok(Some(usage)) => {
                        state
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
                                    metadata: None,
                                },
                                &provider_attempt,
                                &usage,
                            )
                            .await
                    }
                    _ => {
                        state
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
                                    metadata: None,
                                },
                                &provider_attempt,
                                &estimated_usage,
                            )
                            .await
                    }
                };
                if let Err(error) = billed {
                    return self
                        .write_messages_error(
                            session,
                            ctx,
                            stream,
                            StatusCode::BAD_GATEWAY,
                            &error.code,
                            error.message,
                        )
                        .await;
                }
                if let Some(reservation) = token_reservation.take() {
                    reservation.settle();
                }

                // Response-stage guardrail (block/redact) on the reconstructed
                // completion -- identical enforcement for streaming and
                // non-streaming, since streaming was buffered above.
                let mut final_completion = completion;
                // Redact keeps the upstream 200; Deny returns early below, so
                // the status/error framing for the success path never changes.
                let final_status = response.status;
                let response_envelope = normalize_guardrail_response(
                    GuardrailProtocol::ChatCompletions,
                    &completion_bytes,
                    false,
                );
                if let Some(guardrail) = state
                    .match_guardrail(
                        GuardrailStage::Response,
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
                            streaming: stream,
                            envelope: &response_envelope,
                            managed_action: None,
                            action_fingerprint: None,
                        },
                    )
                    .await
                {
                    state.record_guardrail_match(&guardrail);
                    match guardrail.effect {
                        GuardrailEffect::Deny => {
                            state.record_admin_audit_event(AdminAuditEventDraft { action_identity: Default::default(),
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
                                    "guardrail {} blocked messages response for model {} provider {} at {}",
                                    guardrail.rule_name,
                                    request.model,
                                    provider.name,
                                    guardrail.evidence_location()
                                ),
                            });
                            self.record_messages_error_log(
                                ctx,
                                policy_request.tenant.clone(),
                                Some(&request.model),
                                Some(&provider.name),
                                StatusCode::FORBIDDEN,
                                &guardrail.code,
                            );
                            return self
                                .write_messages_error(
                                    session,
                                    ctx,
                                    stream,
                                    StatusCode::FORBIDDEN,
                                    &guardrail.code,
                                    guardrail.message.clone(),
                                )
                                .await;
                        }
                        GuardrailEffect::Redact => {
                            let redacted =
                                guardrail.redact_text(&String::from_utf8_lossy(&completion_bytes));
                            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&redacted)
                            {
                                final_completion = value;
                            }
                            state.record_admin_audit_event(AdminAuditEventDraft { action_identity: Default::default(),
                                request_id: ctx.request_id.clone(),
                                trace_id: ctx.trace_id.clone(),
                                agent_run_id: None,
                                workflow_id: None,
                                workflow_version: None,
                                workflow_node_id: None,
                                actor_api_key_id: auth.api_key_id.clone(),
                                tenant: auth.tenant_context(),
                                action: "guardrail.redact".into(),
                                target: guardrail.evidence_target(),
                                outcome: "redacted".into(),
                                message: format!(
                                    "guardrail {} redacted messages response for model {} provider {} at {}",
                                    guardrail.rule_name,
                                    request.model,
                                    provider.name,
                                    guardrail.evidence_location()
                                ),
                            });
                        }
                    }
                }

                let anthropic_message = anthropic_messages::chat_completion_to_message(
                    &final_completion,
                    &request.model,
                );
                let response_bytes = if stream {
                    message_to_anthropic_sse(&anthropic_message)
                } else {
                    serde_json::to_vec(&anthropic_message).unwrap_or_default()
                };

                let record_bodies = auth.can_record_bodies(state.config.telemetry.log_bodies);
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
                    status_code: final_status.as_u16(),
                    error_code: None,
                    prompt_recorded: record_bodies,
                    response_recorded: record_bodies,
                    prompt_body: record_bodies.then(|| chat_body.to_string()),
                    response_body: record_bodies.then(|| {
                        String::from_utf8_lossy(&response_bytes)
                            .chars()
                            .take(16 * 1024)
                            .collect()
                    }),
                    cache_status: None,
                    started_at_unix: Some(request_started_at_unix),
                    completed_at_unix: Some(now_unix_seconds()),
                    parent_action_fingerprint: None,
                });

                if stream {
                    return write_streaming_bytes_response(
                        session,
                        final_status,
                        "text/event-stream",
                        response_bytes,
                        &ctx.request_id,
                    )
                    .await;
                }
                return write_raw_response(
                    session,
                    final_status,
                    "application/json",
                    response_bytes.into(),
                    &ctx.request_id,
                )
                .await;
            }
        }

        self.write_messages_error(
            session,
            ctx,
            stream,
            StatusCode::BAD_GATEWAY,
            "provider_dispatch_error",
            "provider dispatch failed for all model routes".to_string(),
        )
        .await
    }

    /// Emit an error in the Anthropic error shape -- an `error` SSE frame for a
    /// streaming request, a JSON `{"type":"error",...}` body otherwise -- so a
    /// Claude-native client parses gateway rejections the same way it parses
    /// upstream ones. Governance errors are still recorded via the caller.
    async fn write_messages_error(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        stream: bool,
        status: StatusCode,
        code: &str,
        message: impl Into<String>,
    ) -> PingoraResult<()> {
        let message = message.into();
        if stream {
            return write_streaming_bytes_response(
                session,
                status,
                "text/event-stream",
                error_sse(code, &message),
                &ctx.request_id,
            )
            .await;
        }
        write_json_error(session, status, code, message, &ctx.request_id).await
    }

    /// A guarded provider stream (an error-status body being buffered for the
    /// shared error handling, or a BufferAndEnforce plan buffering the whole
    /// stream before first-byte release) failed to buffer. Mirror chat.rs:
    /// give matching BufferAndEnforce guardrail policies their on_error say
    /// via `guardrail_streaming_buffer_failure` before emitting the failure in
    /// the Anthropic streaming error framing.
    #[allow(clippy::too_many_arguments)]
    async fn write_messages_stream_buffer_failure(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        state: &AppState,
        auth: &AuthContext,
        tenant: &TenantContext,
        logical_model: &str,
        provider_name: &str,
        error: StreamingBodyReadError,
    ) -> PingoraResult<()> {
        let (status, code) = error.status_and_code();
        let empty_envelope =
            normalize_guardrail_response(GuardrailProtocol::ChatCompletions, &[], true);
        let policy_failure = state
            .guardrail_streaming_buffer_failure(
                GuardrailEvaluationContext {
                    request_id: &ctx.request_id,
                    trace_id: ctx.trace_id.as_deref(),
                    agent_run_id: None,
                    workflow_id: None,
                    workflow_version: None,
                    workflow_node_id: None,
                    actor_api_key_id: auth.api_key_id.as_deref(),
                    tenant,
                    service_account_id: auth.service_account_id(),
                    gateway_config_id: None,
                    model: Some(logical_model),
                    provider: Some(provider_name),
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
                (StatusCode::FORBIDDEN, guardrail.code, guardrail.message)
            }
            None => (status, code.to_string(), error.to_string()),
        };
        self.record_messages_error_log(
            ctx,
            tenant.clone(),
            Some(logical_model),
            Some(provider_name),
            status,
            &code,
        );
        self.write_messages_error(session, ctx, true, status, &code, message)
            .await
    }

    fn record_messages_error_log(
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
            route: Some(MESSAGES_ROUTE.into()),
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

struct BufferedProviderResponse {
    status: StatusCode,
    content_type: String,
    body: Vec<u8>,
}

/// The two shapes a provider dispatch can hand back to the messages pipeline:
/// a fully-buffered body (non-streaming requests) or a live streaming response
/// (streaming requests) that is either passed through incrementally or -- for
/// provider errors and BufferAndEnforce guardrail plans -- buffered into the
/// governed [`BufferedProviderResponse`] path.
enum MessagesProviderResponse {
    Buffered(BufferedProviderResponse),
    Streaming(ProviderStreamingResponse),
}

#[derive(Debug)]
struct MessagesRequestPlan {
    request: AnthropicMessagesRequest,
    chat_body: serde_json::Value,
    estimated_usage: BillingTokenUsage,
    routing: ModelRoutingDecision,
    guardrail_envelope: GuardrailEnvelope,
}

#[derive(Debug)]
struct MessagesRejection {
    logical_model: Option<String>,
    stream: bool,
    status: StatusCode,
    code: &'static str,
    message: String,
}

fn build_messages_request_plan(
    state: &AppState,
    auth: &AuthContext,
    body: &[u8],
) -> Result<MessagesRequestPlan, MessagesRejection> {
    let anthropic_body: serde_json::Value =
        serde_json::from_slice(body).map_err(|error| MessagesRejection {
            logical_model: None,
            stream: false,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_json",
            message: format!("invalid JSON body: {error}"),
        })?;
    let request: AnthropicMessagesRequest = serde_json::from_value(anthropic_body.clone())
        .map_err(|error| MessagesRejection {
            logical_model: None,
            stream: false,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: format!("invalid Anthropic messages request: {error}"),
        })?;
    let stream = request.stream;
    if !anthropic_body
        .get("messages")
        .is_some_and(serde_json::Value::is_array)
    {
        return Err(MessagesRejection {
            logical_model: Some(request.model.clone()),
            stream,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "Anthropic messages request must include a \"messages\" array".into(),
        });
    }

    let chat_body = anthropic_messages::to_chat_completions(anthropic_body).map_err(|error| {
        MessagesRejection {
            logical_model: Some(request.model.clone()),
            stream,
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: format!("could not translate Anthropic messages request: {error:?}"),
        }
    })?;

    if !auth.can_use_model(&request.model) {
        return Err(MessagesRejection {
            logical_model: Some(request.model.clone()),
            stream,
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
        MessagesRejection {
            logical_model: Some(request.model.clone()),
            stream,
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    })?;

    authorize_external_rbac(
        &state.config.auth_service,
        auth,
        MESSAGES_SCOPE,
        &format!("model:{}", request.model),
    )
    .map_err(|error| MessagesRejection {
        logical_model: Some(request.model.clone()),
        stream,
        status: error.status,
        code: error.code,
        message: error.message,
    })?;

    if !state.can_tenant_use_model(
        &request.model,
        auth.organization_id.as_deref(),
        auth.project_id.as_deref(),
    ) {
        return Err(MessagesRejection {
            logical_model: Some(request.model.clone()),
            stream,
            status: StatusCode::FORBIDDEN,
            code: "model_not_visible",
            message: format!("model {} is not visible to this tenant", request.model),
        });
    }

    let estimated_usage = estimate_messages_usage(&chat_body, &request.model);
    let gateway_tools = state.tools_for(
        &auth.tenant_context(),
        auth.api_key_id.as_deref(),
        Some(MESSAGES_ROUTE),
    );
    let injected_tool_token_upper_bound = (!gateway_tools.is_empty())
        .then(|| conservative_input_token_upper_bound(&gateway_tools))
        .unwrap_or_default();
    let requirements = ModelRouteRequirements::from_request(
        ModelEndpointKind::AnthropicMessages,
        &chat_body,
        stream,
        conservative_input_token_upper_bound(&chat_body),
        injected_tool_token_upper_bound,
    );
    let routing = state.candidate_model_routes(
        &model,
        &requirements,
        Some(&estimated_usage),
        &auth.region_allowlist,
    );
    let guardrail_envelope =
        normalize_guardrail_request(GuardrailProtocol::ChatCompletions, &chat_body);

    Ok(MessagesRequestPlan {
        request,
        chat_body,
        estimated_usage,
        routing,
        guardrail_envelope,
    })
}

enum MessagesAttemptDecision {
    RetryProvider,
    TryFallbackRoute,
    ReturnError,
}

fn messages_attempt_decision(
    retryable: bool,
    attempt: u32,
    max_dispatch_retries: u32,
    candidate_index: usize,
    route_count: usize,
) -> MessagesAttemptDecision {
    if retryable && attempt < max_dispatch_retries {
        MessagesAttemptDecision::RetryProvider
    } else if retryable && has_next_candidate(candidate_index, route_count) {
        MessagesAttemptDecision::TryFallbackRoute
    } else {
        MessagesAttemptDecision::ReturnError
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

/// Prompt/completion estimate over the translated chat body so the budget /
/// TPM / prepaid-wallet gates engage before dispatch (mirrors
/// `chat.rs::estimate_chat_completion_usage`). The prompt side prefers a local
/// BPE count for model families with a bundled tokenizer (issue #282) and falls
/// back to the `chars/4` heuristic otherwise.
fn estimate_messages_usage(chat_body: &serde_json::Value, model: &str) -> BillingTokenUsage {
    let message_overhead = chat_body
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .map(|messages| messages.len() as u64 * 4)
        .unwrap_or_default();
    let text_tokens = match crate::tokenizer::count_tokens(
        model,
        &collect_prompt_text(chat_body.get("messages")),
    ) {
        Some(tokens) => tokens,
        None => prompt_character_count(chat_body.get("messages")).saturating_add(3) / 4,
    };
    let prompt_tokens = text_tokens.saturating_add(message_overhead);
    let completion_tokens = chat_body
        .get("max_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(DEFAULT_COMPLETION_TOKEN_RESERVATION);
    BillingTokenUsage::new(
        prompt_tokens,
        completion_tokens,
        prompt_tokens.saturating_add(completion_tokens),
    )
}

fn prompt_character_count(value: Option<&serde_json::Value>) -> u64 {
    match value {
        Some(serde_json::Value::String(text)) => text.chars().count() as u64,
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| prompt_character_count(Some(item)))
            .sum(),
        Some(serde_json::Value::Object(object)) => object
            .iter()
            .filter(|(key, _)| key.as_str() != "type")
            .map(|(_, value)| prompt_character_count(Some(value)))
            .sum(),
        _ => 0,
    }
}

/// Newline-separated prompt text mirroring [`prompt_character_count`]'s field
/// filter, so the BPE tokenizer measures exactly the text the heuristic would.
fn collect_prompt_text(value: Option<&serde_json::Value>) -> String {
    let mut out = String::new();
    append_prompt_text(value, &mut out);
    out
}

fn append_prompt_text(value: Option<&serde_json::Value>, out: &mut String) {
    match value {
        Some(serde_json::Value::String(text)) => {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(text);
        }
        Some(serde_json::Value::Array(items)) => {
            for item in items {
                append_prompt_text(Some(item), out);
            }
        }
        Some(serde_json::Value::Object(object)) => {
            for (_, value) in object.iter().filter(|(key, _)| key.as_str() != "type") {
                append_prompt_text(Some(value), out);
            }
        }
        _ => {}
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
