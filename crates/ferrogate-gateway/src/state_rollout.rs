// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: AppState methods for canary + shadow/mirror traffic rollouts
// (issue #276): sticky canary route promotion (fully governed like the
// primary) and shadow-mirror budget/metering hooks (metered as shadow,
// never billed, never affects the client response).

use super::*;

impl AppState {
    /// Promote this model's configured canary route to the front of the
    /// candidate list when the caller's sticky key falls in the canary
    /// bucket (issue #276). A no-op when no canary is configured, the split
    /// does not select this caller, or the canary provider is unknown/
    /// disabled -- so unconfigured models behave exactly as before and a
    /// misconfigured canary never breaks canary-bucket traffic.
    ///
    /// The canary is inserted as the leading candidate with the existing
    /// routes kept behind it as fallbacks, so it is evaluated exactly like a
    /// primary route (governance, billing, guardrails) yet still fails over
    /// to the primary on error -- the safe-rollout property. Flipping the
    /// canary to primary is then a config-only change (`percent = 100`).
    pub(crate) fn apply_canary_route(
        &self,
        logical_model: &str,
        sticky_key: &str,
        region_allowlist: &HashSet<String>,
        decision: &mut ModelRoutingDecision,
    ) {
        let Some(model) = self
            .config
            .models
            .iter()
            .find(|model| model.name == logical_model)
        else {
            return;
        };
        let Some(canary) = model.canary.as_ref().filter(|canary| {
            canary.enabled
                && !canary.provider.trim().is_empty()
                && !canary.provider_model.trim().is_empty()
        }) else {
            return;
        };
        if !ferrogate_routing::canary_selected(sticky_key, canary.percent) {
            return;
        }
        // Fail safe: an unknown or disabled canary provider must not break
        // canary-bucket traffic. `provider_not_found` is terminal in the
        // dispatch loop (it does not fall back), so rather than insert a
        // route that would hard-fail every canary request, skip the canary.
        let Some(provider) = self
            .providers
            .get(&canary.provider)
            .filter(|provider| provider.enabled)
        else {
            return;
        };
        let region = provider.region.clone();
        let route = ModelRoute::with_routing(
            canary.provider.clone(),
            canary.provider_model.clone(),
            canary.input_price_per_1m.or(model.input_price_per_1m),
            canary.output_price_per_1m.or(model.output_price_per_1m),
            0,
            1,
        )
        .with_capabilities_and_context(canary.capabilities.clone(), canary.context_window)
        .with_region(region);
        // Canary candidates cross the same capability/context/region filter as
        // primary and fallback routes before they can lead. `consider` also
        // appends bounded typed exclusion evidence on refusal (#582).
        if !decision.consider(route.clone(), region_allowlist) {
            return;
        }
        let inserted = decision
            .eligible_routes
            .pop()
            .expect("an eligible canary was appended by consider");
        // Dedup, then lead with the canary while keeping every other route as
        // a fallback behind it.
        decision.eligible_routes.retain(|existing| {
            !(existing.provider == route.provider
                && existing.provider_model == route.provider_model)
        });
        decision.eligible_routes.insert(0, inserted);
        decision.selection_reason = ModelRouteSelectionReason::CanaryBucket;
    }

    /// Admit one shadow-mirror dispatch against the per-model budget (issue
    /// #276), returning `true` when within `limit` (`0` = uncapped).
    pub(crate) fn shadow_budget_try_consume(&self, logical_model: &str, limit: u64) -> bool {
        self.shadow_budget.try_consume(logical_model, limit)
    }

    /// Record a completed shadow-mirror dispatch (metered as shadow, never
    /// billed to the tenant).
    pub(crate) fn record_shadow_dispatch(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_shadow_dispatch();
        }
    }

    /// Record a swallowed shadow-mirror failure -- it never affects the
    /// primary response.
    pub(crate) fn record_shadow_dispatch_failure(&self) {
        if let Ok(mut metrics) = self.metrics.lock() {
            metrics.record_shadow_dispatch_failure();
        }
    }

    #[cfg(test)]
    pub(crate) fn shadow_metrics(&self) -> (u64, u64) {
        let metrics = self
            .metrics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            metrics.shadow_dispatch_total,
            metrics.shadow_dispatch_failure_total,
        )
    }
}

#[cfg(test)]
#[path = "state_rollout_test.rs"]
mod state_rollout_test;
