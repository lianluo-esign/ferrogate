// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Shadow/mirror traffic dispatch for model rollouts (issue
// #276). Duplicates a sampled, budget-capped fraction of AI requests to a
// secondary provider fire-and-forget: it adds no client latency, its
// response is discarded (never returned to the client), it is metered as
// shadow but never billed, and any failure is swallowed so it can never
// affect the primary request.

use serde_json::{json, Value};
use tracing::{info, warn};

use ferrogate_core::TenantContext;
use ferrogate_providers::ModelRoute;

use super::chat::{prepare_ai_provider_request, AiEndpoint, AiProviderRequestInput};
use super::dispatch::dispatch_provider_request;
use crate::config::Provider;
use crate::state::AppState;

/// Owned inputs for a shadow-mirror attempt, gathered on the primary
/// request path and moved into the fire-and-forget task.
pub(super) struct ShadowMirrorParams {
    pub(super) endpoint: AiEndpoint,
    pub(super) request_id: String,
    /// Canonical route label for the endpoint (`endpoint.route()`), passed in
    /// so the shadow module needn't reach into `AiEndpoint`'s private mapping.
    pub(super) route: &'static str,
    pub(super) logical_model: String,
    pub(super) tenant: TenantContext,
    pub(super) api_key_id: Option<String>,
    /// Sticky key (api key / tenant) used for the shadow sampling decision.
    pub(super) sticky_key: String,
    /// The client request body to mirror.
    pub(super) body: Value,
}

/// Resolved shadow target after the config lookup + sampling + budget gates
/// pass. Only produced when a mirror should actually fire.
struct ShadowTarget {
    provider: Provider,
    provider_model: String,
    input_price_per_1m: Option<f64>,
    output_price_per_1m: Option<f64>,
}

/// Decide whether to mirror this request and, if so, charge the per-model
/// shadow budget. Returns `None` (no mirror) when: no shadow is configured
/// or it is disabled; the caller is not in the sampled bucket; the shadow
/// provider is unknown or disabled; or the budget cap is reached. Isolated
/// from dispatch so the gate is unit-testable without any network.
fn shadow_decision(
    state: &AppState,
    logical_model: &str,
    sticky_key: &str,
) -> Option<ShadowTarget> {
    let model = state
        .config
        .models
        .iter()
        .find(|model| model.name == logical_model)?;
    let shadow = model.shadow.as_ref().filter(|shadow| {
        shadow.enabled
            && !shadow.provider.trim().is_empty()
            && !shadow.provider_model.trim().is_empty()
    })?;
    if !ferrogate_routing::shadow_sampled(sticky_key, shadow.sample_percent) {
        return None;
    }
    let provider = state
        .providers
        .get(&shadow.provider)
        .filter(|provider| provider.enabled)?;
    // Charge the budget last, only once we know we would actually dispatch,
    // so a disabled provider or an unsampled caller never consumes budget.
    if !state.shadow_budget_try_consume(logical_model, shadow.max_requests) {
        return None;
    }
    Some(ShadowTarget {
        provider: provider.clone(),
        provider_model: shadow.provider_model.clone(),
        input_price_per_1m: model.input_price_per_1m,
        output_price_per_1m: model.output_price_per_1m,
    })
}

/// Fire-and-forget entry point called from the primary request handler.
/// Runs the (cheap, synchronous) sampling/budget gate inline, then spawns
/// the actual dispatch so the primary path never awaits it -- adding zero
/// client latency. A no-op when no mirror should fire.
pub(super) fn spawn_shadow_mirror(state: &AppState, params: ShadowMirrorParams) {
    let Some(target) = shadow_decision(state, &params.logical_model, &params.sticky_key) else {
        return;
    };
    let state = state.clone();
    tokio::spawn(async move {
        execute_shadow_dispatch(state, target, params).await;
    });
}

/// Perform the shadow dispatch and discard the response. All error paths are
/// swallowed (logged + metered as a shadow failure) so nothing here can ever
/// surface to, or delay, the client. Never records provider circuit-breaker
/// success/failure, so shadow traffic never influences primary routing.
async fn execute_shadow_dispatch(
    state: AppState,
    target: ShadowTarget,
    params: ShadowMirrorParams,
) {
    let ShadowMirrorParams {
        endpoint,
        request_id,
        route,
        logical_model,
        tenant,
        api_key_id,
        body,
        ..
    } = params;

    // Mirror as a non-streaming call regardless of the client's `stream`
    // flag: the response is discarded, so a bounded body is simpler and
    // safer than a streamed one, and usage still comes back in the body.
    let mut body = body;
    if let Some(object) = body.as_object_mut() {
        object.insert("stream".to_string(), json!(false));
    }

    let route_model = ModelRoute::with_routing(
        target.provider.name.clone(),
        target.provider_model.clone(),
        target.input_price_per_1m,
        target.output_price_per_1m,
        0,
        1,
    );

    let prepared = match prepare_ai_provider_request(
        &state,
        AiProviderRequestInput {
            endpoint,
            provider: &target.provider,
            model_route: &route_model,
            tenant: &tenant,
            api_key_id: api_key_id.as_deref(),
            route: Some(route),
            logical_model: logical_model.clone(),
            stream: false,
            body,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            state.record_shadow_dispatch_failure();
            warn!(
                shadow = true,
                request_id = %request_id,
                logical_model = %logical_model,
                provider = %target.provider.name,
                provider_model = %target.provider_model,
                error = ?error,
                "shadow mirror adapter preparation failed (swallowed)"
            );
            return;
        }
    };

    let timeout = state.provider_dispatch_timeout();
    let max_bytes = state.provider_response_body_max_bytes();
    match dispatch_provider_request(prepared, timeout, max_bytes).await {
        Ok(response) if response.status.is_success() => {
            state.record_shadow_dispatch();
            let usage = state
                .extract_provider_usage(&target.provider.kind, &response.body)
                .ok()
                .flatten();
            info!(
                shadow = true,
                request_id = %request_id,
                logical_model = %logical_model,
                provider = %target.provider.name,
                provider_model = %target.provider_model,
                status = response.status.as_u16(),
                prompt_tokens = usage.as_ref().and_then(|usage| usage.prompt_tokens),
                completion_tokens = usage.as_ref().and_then(|usage| usage.completion_tokens),
                total_tokens = usage.as_ref().and_then(|usage| usage.total_tokens),
                "shadow mirror completed (metered as shadow, not billed)"
            );
        }
        Ok(response) => {
            state.record_shadow_dispatch_failure();
            warn!(
                shadow = true,
                request_id = %request_id,
                logical_model = %logical_model,
                provider = %target.provider.name,
                provider_model = %target.provider_model,
                status = response.status.as_u16(),
                "shadow mirror returned a non-success status (swallowed)"
            );
        }
        Err(error) => {
            state.record_shadow_dispatch_failure();
            warn!(
                shadow = true,
                request_id = %request_id,
                logical_model = %logical_model,
                provider = %target.provider.name,
                provider_model = %target.provider_model,
                error = ?error,
                "shadow mirror dispatch failed (swallowed)"
            );
        }
    }
}

#[cfg(test)]
#[path = "shadow_test.rs"]
mod shadow_test;
