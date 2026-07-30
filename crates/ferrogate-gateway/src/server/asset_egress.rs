// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Asset egress (download bandwidth) governance for /v1/assets/*
// (issue #262): a self-contained per-download hook that meters + settles the
// transferred bytes through the existing billing outbox, emits a symmetric
// pull-side audit event, accumulates the monthly egress byte counter, and a
// fail-closed pre-serve deny gate for the egress byte budget + download RPM
// caps resolved by `resolve_effective_quota`. Kept out of `assets.rs` so the
// pull/presign paths hook it with a single surgical call.

use ferrogate_policy::EffectiveQuota;
use ferrogate_storage::stored_asset_id;

use super::local::admin_audit_event_draft_for_target_with_run_id;
use super::ProxyContext;
use crate::auth::AuthContext;
use crate::state::AppState;

/// The process-local monthly-egress-counter key for the scope that owns the
/// egress byte budget (#262). Namespaced with an `egress:` prefix so it never
/// collides with any other counter, and derived identically on the deny side
/// (`asset_egress_quota_denial`) and the record side (`record_asset_egress`)
/// so a served download is counted against exactly the budget it was checked
/// against. Falls back to the tenant scope when the budget carries no recorded
/// winning scope (a legacy/plan-less path).
fn egress_byte_counter_key(
    quota: &EffectiveQuota,
    api_key_id: &str,
    organization_id: Option<&str>,
) -> String {
    let scope_key = quota
        .monthly_egress_bytes_scope
        .as_ref()
        .map(|scope| scope.counter_key(api_key_id))
        .unwrap_or_else(|| format!("tenant:{}", organization_id.unwrap_or("")));
    format!("egress:{scope_key}")
}

/// Fail-closed pre-serve deny gate for asset downloads (#262). Returns
/// `Some((error_code, message))` when this download must be rejected, or `None`
/// when it may proceed. Enforces, in order:
///
/// 1. the resolved monthly egress **byte budget** (read-only: compares the
///    scope's cumulative month-to-date egress + this object's size against the
///    `min`-across-the-chain budget), and
/// 2. the resolved **download RPM** cap (a per-minute request counter consumed
///    on the winning scope, the download-side analogue of inference RPM).
///
/// The byte-budget check runs first and read-only so a budget-exhausted
/// download never consumes an RPM token. Both denials carry a distinct error
/// code so a client can tell "out of bandwidth budget" from "downloading too
/// fast", separate from the token-side `rate_limit_exceeded`.
pub(super) fn asset_egress_quota_denial(
    state: &AppState,
    auth: &AuthContext,
    bytes: u64,
) -> Option<(&'static str, String)> {
    let quota = &auth.effective_quota;
    let api_key_id = auth.api_key_id.as_deref().unwrap_or("");

    if let Some(budget) = quota.monthly_egress_bytes_budget {
        let counter_key =
            egress_byte_counter_key(quota, api_key_id, auth.organization_id.as_deref());
        let used = state.asset_egress_bytes_used(&counter_key);
        if used.saturating_add(bytes) > budget {
            return Some((
                "asset_egress_quota_exceeded",
                format!(
                    "monthly asset egress budget of {budget} bytes is exhausted for this scope \
                     ({used} used, {bytes} requested)"
                ),
            ));
        }
    }

    if let Some(limit) = quota.download_rpm_limit {
        let scope_key = quota
            .download_rpm_limit_scope
            .as_ref()
            .map(|scope| scope.counter_key(api_key_id))
            .unwrap_or_else(|| format!("key:{api_key_id}"));
        let counter_key = format!("asset_egress_rpm:{scope_key}");
        match state.try_consume_api_key_request(&counter_key, limit) {
            Ok(true) => {}
            Ok(false) => {
                return Some((
                    "asset_download_rate_limit_exceeded",
                    format!("asset download rate limit of {limit}/min is exhausted for this scope"),
                ));
            }
            Err(_) => {
                return Some((
                    "governance_counter_unavailable",
                    "gateway counter backend is unavailable for asset download rate limiting"
                        .into(),
                ));
            }
        }
    }

    None
}

/// The single per-download egress hook (#262): meter + settle the transferred
/// bytes through the durable billing outbox, accumulate the monthly egress
/// counter that backs the byte-budget deny gate, and emit a pull-side audit
/// event symmetric with the existing push/delete audit. Best-effort side
/// effects: a metering failure is logged, never propagated, so serving the
/// download the client already received is never turned into an error.
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_asset_egress(
    state: &AppState,
    ctx: &ProxyContext,
    auth: &AuthContext,
    agent_run_id: Option<&str>,
    asset_type: &str,
    name: &str,
    version: &str,
    bytes: u64,
) {
    let tenant = auth.tenant_context();
    if let Err(error) = state
        .record_asset_egress_event(
            &ctx.request_id,
            ctx.trace_id.as_deref(),
            &tenant,
            asset_type,
            name,
            version,
            bytes,
        )
        .await
    {
        tracing::warn!(
            request_id = %ctx.request_id,
            error = %error.message,
            "failed to record asset egress metering event"
        );
    }

    let api_key_id = auth.api_key_id.as_deref().unwrap_or("");
    let counter_key = egress_byte_counter_key(
        &auth.effective_quota,
        api_key_id,
        auth.organization_id.as_deref(),
    );
    state.record_asset_egress_bytes(&counter_key, bytes);

    let id = stored_asset_id(
        auth.organization_id.as_deref().unwrap_or(""),
        asset_type,
        name,
        version,
    );
    state.record_admin_audit_event(admin_audit_event_draft_for_target_with_run_id(
        ctx,
        auth,
        agent_run_id,
        "asset.pull",
        &id,
        "served",
        format!("asset {id} downloaded ({bytes} bytes)"),
    ));
}

#[cfg(test)]
#[path = "asset_egress_test.rs"]
mod tests;
