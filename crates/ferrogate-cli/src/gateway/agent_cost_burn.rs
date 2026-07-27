// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Admin agent-cost-burn surface (#428, slice B-surface):
// `GET /admin/v1/agent-cost-burn`. Surfaces the durable, per-agent runtime
// cost-burn accumulated by slice B-storage (the `agent_cost_burn` table:
// one row per (tenant_id, agent_key, period) whose `accumulated_usd` folds every
// run of the agent inside the billing period) in the existing
// observability/billing admin surface, so CF-hosted-agent runtime cost is
// visible per tenant/agent (acceptance box 1 of #428). READ-ONLY: enforcement
// (bounding a run against the per-agent ceiling) is a separate slice; this adds
// no hot-path write. The read is tenant-isolated BEFORE pagination -- a
// tenant-scoped admin only ever sees its own tenant's burn; the platform
// operator (organization_id == None) sees the cross-tenant view. A durable-store
// failure degrades to an explicit `service_unavailable`, never a fabricated
// empty list (which would read as "no burn"), per AGENTS.md "never fake a zero".

use std::time::{SystemTime, UNIX_EPOCH};

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Serialize;

use ferrogate_storage::StoredAgentCostBurn;

use super::{FerroGateway, ProxyContext};
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, AdminList},
};

/// One durable per-agent cost-burn row, as presented on the admin surface. A
/// projection of [`StoredAgentCostBurn`] onto exactly the observability fields
/// (`first_seen_unix` is internal bookkeeping, so it is not surfaced).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct AgentCostBurnRow {
    pub(crate) tenant_id: String,
    /// STABLE per-agent identity (the agent/deployment key), not a per-run id:
    /// every run of the same agent inside `period` folds into this row's total.
    pub(crate) agent_key: String,
    /// `YYYY-MM` billing window the accumulated total covers.
    pub(crate) period: String,
    pub(crate) accumulated_usd: f64,
    pub(crate) updated_at_unix: i64,
}

impl AgentCostBurnRow {
    fn from_stored(stored: StoredAgentCostBurn) -> Self {
        Self {
            tenant_id: stored.tenant_id,
            agent_key: stored.agent_key,
            period: stored.period,
            accumulated_usd: stored.accumulated_usd,
            updated_at_unix: stored.updated_at_unix,
        }
    }
}

/// The outcome of the durable list read, kept as an explicit sum type so the
/// unavailable case can never be silently collapsed into an empty `Available`
/// list. Tenant isolation is applied at the storage layer (the list is scoped to
/// the caller's tenant), so this projection only shapes the response.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AgentCostBurnOutcome {
    Available(Vec<AgentCostBurnRow>),
    Unavailable(String),
}

/// Project the durable list read into the presentation outcome. Pure and
/// testable without a live gateway/store: an `Ok` becomes `Available` rows in
/// the storage-provided order (biggest accumulated total first); an `Err`
/// becomes `Unavailable`, which the handler renders as a 503 -- never a
/// fabricated empty list.
pub(crate) fn build_agent_cost_burn_outcome(
    result: Result<Vec<StoredAgentCostBurn>, String>,
) -> AgentCostBurnOutcome {
    match result {
        Ok(rows) => AgentCostBurnOutcome::Available(
            rows.into_iter()
                .map(AgentCostBurnRow::from_stored)
                .collect(),
        ),
        Err(error) => AgentCostBurnOutcome::Unavailable(error),
    }
}

/// Resolve the billing period the read covers: an explicit, well-formed
/// `?period=YYYY-MM` query value wins; otherwise default to the current UTC
/// billing month derived the same way usage rollups derive it
/// ([`ferrogate_storage::period_month_from_unix`]). A blank/garbage `period` is
/// ignored in favor of the current month rather than returning an error, so the
/// surface stays usable without a param.
pub(crate) fn resolve_agent_cost_burn_period(query_period: Option<&str>, now_unix: i64) -> String {
    match query_period.map(str::trim) {
        Some(raw) if is_period_month(raw) => raw.to_string(),
        _ => ferrogate_storage::period_month_from_unix(now_unix),
    }
}

/// Extract the raw value of the `key` query parameter (e.g. `period`) from a
/// `a=b&c=d` query string, if present. A `YYYY-MM` period carries no characters
/// that require percent-decoding, so this scans the raw pairs directly.
pub(crate) fn query_param<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

/// A `YYYY-MM` calendar month: four digits, a dash, two digits in `01..=12`.
fn is_period_month(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 7 || bytes[4] != b'-' {
        return false;
    }
    if !bytes[..4].iter().all(u8::is_ascii_digit) || !bytes[5..].iter().all(u8::is_ascii_digit) {
        return false;
    }
    matches!(
        &value[5..],
        "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
    )
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

impl FerroGateway {
    /// `GET /admin/v1/agent-cost-burn`: tenant-scoped, per-period list of the
    /// durable accumulated cost-burn for each agent. Authorizes `admin.read`,
    /// isolates by tenant BEFORE pagination, and honors an optional
    /// `?period=YYYY-MM` (default: the current billing month). Read-only.
    pub(super) async fn handle_admin_agent_cost_burn(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        if method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "agent cost-burn visibility supports GET only",
                &ctx.request_id,
            )
            .await;
        }
        match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => {
                let pagination = state.admin_pagination(query);
                let period = resolve_agent_cost_burn_period(
                    query_param(query, "period"),
                    now_unix_seconds(),
                );
                // Tenant isolation BEFORE pagination: the durable list is scoped
                // to the caller's tenant (Some) or the platform operator's
                // cross-tenant view (None) at the storage layer, so a
                // tenant-scoped caller can never page into another tenant's burn.
                // #515: which of the two it is comes from `tenant_filter()`, the
                // declared classification -- not from a null `organization_id`,
                // which also caught credentials that declared nothing.
                let result = state
                    .list_agent_cost_burn(auth.tenant_filter(), &period)
                    .await
                    .map_err(|error| {
                        tracing::warn!(error = %error, "agent cost-burn list unavailable");
                        format!("agent cost-burn surface unavailable: {error}")
                    });
                match build_agent_cost_burn_outcome(result) {
                    AgentCostBurnOutcome::Available(rows) => {
                        let total = rows.len();
                        let data = rows
                            .into_iter()
                            .skip(pagination.offset)
                            .take(pagination.limit)
                            .collect();
                        let body =
                            AdminList::paginated(data, total, pagination.offset, pagination.limit);
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    AgentCostBurnOutcome::Unavailable(message) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "service_unavailable",
                            &message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            Err(error) => {
                write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
#[path = "agent_cost_burn_test.rs"]
mod agent_cost_burn_test;
