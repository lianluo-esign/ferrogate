// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Outbound webhook dispatch for proactive budget-threshold
// alerting (issue #170). Threshold-crossing detection and idempotency
// live in `AppState` (state.rs) / `ferrogate-storage`; this module is
// only the "POST a JSON payload to the configured webhook_url" transport,
// reusing `telemetry::dispatch_otlp_request`'s raw TCP/TLS client rather
// than duplicating it.

use std::time::Duration;

use anyhow::Result as AnyResult;
use ferrogate_observability::OtlpHttpRequest;
use ferrogate_storage::QuotaScopeKind;
use serde::Serialize;

/// Wire payload for a budget-threshold-crossing webhook (issue #170). Flat
/// and self-describing so a receiver needs no FerroGate-internal knowledge
/// to route it (e.g. to a per-tenant Slack channel) -- this is the
/// documented extension point the issue calls for pluggable email/Slack
/// targets to eventually sit behind.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BudgetAlertWebhookPayload<'a> {
    pub(crate) event: &'static str,
    pub(crate) scope_type: &'static str,
    pub(crate) scope_id: &'a str,
    pub(crate) period_month: &'a str,
    pub(crate) threshold_pct: u8,
    pub(crate) spent_usd: f64,
    pub(crate) budget_usd: f64,
    pub(crate) fired_at_unix: i64,
}

impl<'a> BudgetAlertWebhookPayload<'a> {
    pub(crate) fn new(
        scope_type: QuotaScopeKind,
        scope_id: &'a str,
        period_month: &'a str,
        threshold_pct: u8,
        spent_usd: f64,
        budget_usd: f64,
        fired_at_unix: i64,
    ) -> Self {
        Self {
            event: "budget_threshold_crossed",
            scope_type: scope_type.as_str(),
            scope_id,
            period_month,
            threshold_pct,
            spent_usd,
            budget_usd,
            fired_at_unix,
        }
    }
}

/// Best-effort delivery -- callers must not let a webhook failure block or
/// retry the request that triggered it. See [`crate::state::AppState`]'s
/// budget-threshold-alert dispatch for the idempotency handling that makes
/// a delivery failure here merely "this tier's alert didn't go out" rather
/// than a correctness problem for the gateway itself.
pub(crate) fn dispatch_budget_alert_webhook(
    webhook_url: &str,
    timeout: Duration,
    payload: &BudgetAlertWebhookPayload<'_>,
) -> AnyResult<()> {
    let body = serde_json::to_vec(payload)?;
    let request = OtlpHttpRequest {
        method: "POST",
        url: webhook_url.to_string(),
        content_type: "application/json",
        body,
    };
    crate::telemetry::dispatch_otlp_request(&request, timeout)
}
