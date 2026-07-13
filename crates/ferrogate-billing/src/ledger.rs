// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Billing ledger: converting a token-usage [`BillingEvent`] into a priced
//! [`LedgerEntry`] and persisting the resulting flow of charges.
//!
//! This is the core of the standalone billing microservice (issue #129): the
//! gateway forwards nothing but a usage event, and the ledger turns it into an
//! actual charge — settled USD plus abstract credits — using the [`PriceBook`]
//! rate card. The [`LedgerSink`] trait is the persistence seam; the durable
//! Supabase-backed implementation lives in `ferrogate-storage` (which already
//! depends on this crate), while [`InMemoryLedgerSink`] serves tests and
//! ephemeral deployments.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    pricing::PriceBook, BillingError, BillingEvent, BillingUsageSource, CostEstimate, ModelPrice,
    ProviderAttempt, TokenUsage,
};
use ferrogate_core::TenantContext;

/// Where the settled `cost` on a [`LedgerEntry`] came from.
///
/// `GatewaySettled` means the gateway already priced the request from its
/// configured route rates and enforced the monthly budget against that number,
/// so the ledger honors it verbatim (single source of truth, issue #135).
/// `BillingPriceBook` means the event carried no settled cost and the billing
/// service priced it from its own rate card.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    GatewaySettled,
    #[default]
    BillingPriceBook,
}

impl CostSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CostSource::GatewaySettled => "gateway_settled",
            CostSource::BillingPriceBook => "billing_price_book",
        }
    }
}

/// A settled charge derived from a single usage event. This is the output of
/// the `POST /v1/billing/charge` endpoint and the row shape of the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Idempotency key for the charge, derived from the request/trace and
    /// provider-attempt identity.
    pub id: String,
    pub request_id: String,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default, flatten)]
    pub provider_attempt: ProviderAttempt,
    pub tenant: TenantContext,
    pub logical_model: String,
    pub provider: String,
    pub provider_model: String,
    pub usage: TokenUsage,
    #[serde(default)]
    pub usage_source: BillingUsageSource,
    pub status_code: u16,
    /// Settled cost broken down into input/output/total USD.
    pub cost: CostEstimate,
    /// Abstract credit/quota consumption (`total_cost_usd * credits_per_usd`).
    pub credits: f64,
    /// The rate-card price that was applied (informational when
    /// `cost_source == GatewaySettled`).
    pub unit_price: ModelPrice,
    /// Whether `cost` is the gateway-settled figure or a billing re-price.
    #[serde(default)]
    pub cost_source: CostSource,
    #[serde(default)]
    pub occurred_at_unix: Option<u64>,
    /// This entry's debit against the tenant's prepaid-credit wallet
    /// (issue #169), copied through verbatim from the originating
    /// [`BillingEvent`] -- see that field's doc comment for why this
    /// crate only mirrors the outcome rather than computing or applying
    /// it.
    #[serde(default)]
    pub wallet_delta_credits: Option<i64>,
    #[serde(default)]
    pub wallet_balance_after_credits: Option<i64>,
}

/// Returns whether two entries are an exact replay of one immutable
/// provider-attempt settlement. The attempt id is an idempotency key, not
/// permission to rewrite correlation or timing evidence after the first write.
pub fn same_provider_attempt_settlement(left: &LedgerEntry, right: &LedgerEntry) -> bool {
    left == right
}

/// Deterministic idempotency key for a usage event. New provider-dispatch
/// events include the stable attempt identity; legacy serialized events that
/// predate issue #213 preserve the old request/trace-only key.
pub fn ledger_entry_id(event: &BillingEvent) -> String {
    if !event.provider_attempt.is_legacy() {
        return format!(
            "ferrogate:provider-attempt:{}",
            event.provider_attempt.provider_attempt_id
        );
    }

    event
        .trace_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|trace_id| format!("ferrogate:{trace_id}:{}", event.request_id))
        .unwrap_or_else(|| format!("ferrogate:{}", event.request_id))
}

/// Price a usage event into a [`LedgerEntry`].
///
/// Source-of-truth rule (issue #135): if the event carries a gateway-settled
/// `cost_usd`, that figure is authoritative — the gateway already priced the
/// request from its configured route rates and enforced the monthly budget
/// against it, so the ledger must record the same number rather than re-pricing
/// and silently diverging. The `PriceBook` is consulted only for the
/// input/output breakdown in that case.
///
/// When the event carries no settled cost, the billing service prices it from
/// the rate card and fails closed with `price_not_found` when no rule matches
/// (`(provider, provider_model)`), so it never bills zero.
pub fn charge(book: &PriceBook, event: &BillingEvent) -> Result<LedgerEntry, BillingError> {
    let usage = event.usage.clone().reconcile_split();
    let price_opt = book
        .price_for(&event.provider, &event.provider_model)
        .cloned();

    let (cost, unit_price, cost_source) = match authoritative_cost(event) {
        Some(total) => {
            // Restore visibility into gateway/PriceBook rate-card drift (issue
            // #152): #135 made the gateway-settled cost authoritative (so the
            // two systems stop silently diverging in the ledger), but that also
            // meant the billing service could no longer catch a misconfigured
            // gateway price. Log — never reject or override — when the two
            // disagree beyond tolerance, so the drift stays visible without
            // reopening #135's single-source-of-truth guarantee.
            if let Some(price) = price_opt.as_ref() {
                let expected = price.estimate(&usage).total_cost;
                if cost_diverges(total, expected) {
                    tracing::warn!(
                        request_id = %event.request_id,
                        provider = %event.provider,
                        provider_model = %event.provider_model,
                        gateway_settled_cost_usd = total,
                        price_book_estimate_usd = expected,
                        "gateway-settled cost diverges from the billing service's rate card; \
                         honoring the gateway-settled figure (issue #135), but the rate cards \
                         may be out of sync"
                    );
                }
            }
            let cost = settled_breakdown(total, &usage, price_opt.as_ref());
            let unit_price = price_opt.unwrap_or_else(|| ModelPrice::usd(0.0, 0.0));
            (cost, unit_price, CostSource::GatewaySettled)
        }
        None => {
            let price = price_opt.ok_or_else(|| {
                BillingError::new(
                    "price_not_found",
                    format!(
                        "no rate-card price for provider '{}' model '{}' and the event carried no settled cost",
                        event.provider, event.provider_model
                    ),
                )
            })?;
            let cost = price.estimate(&usage);
            (cost, price, CostSource::BillingPriceBook)
        }
    };

    let credits = book.credits_for_usd(cost.total_cost);

    Ok(LedgerEntry {
        id: ledger_entry_id(event),
        request_id: event.request_id.clone(),
        trace_id: event.trace_id.clone(),
        provider_attempt: event.provider_attempt.clone(),
        tenant: event.tenant.clone(),
        logical_model: event.logical_model.clone(),
        provider: event.provider.clone(),
        provider_model: event.provider_model.clone(),
        usage,
        usage_source: event.usage_source,
        status_code: event.status_code,
        cost,
        credits,
        unit_price,
        cost_source,
        occurred_at_unix: event.occurred_at_unix,
        wallet_delta_credits: event.wallet_delta_credits,
        wallet_balance_after_credits: event.wallet_balance_after_credits,
    })
}

/// Relative tolerance (issue #152): flag divergence beyond 5% of the expected
/// PriceBook cost.
const COST_DIVERGENCE_RELATIVE_TOLERANCE: f64 = 0.05;
/// Absolute floor (issue #152): below this, relative-percentage noise on
/// near-zero costs is not worth a warning.
const COST_DIVERGENCE_ABSOLUTE_FLOOR_USD: f64 = 0.0001;

/// Whether a gateway-settled cost materially diverges from what the rate card
/// would have computed for the same usage. Pure and independently testable so
/// the tolerance logic can be pinned without a tracing subscriber.
fn cost_diverges(settled: f64, expected: f64) -> bool {
    let diff = (settled - expected).abs();
    if diff < COST_DIVERGENCE_ABSOLUTE_FLOOR_USD {
        return false;
    }
    let relative_base = expected.abs().max(COST_DIVERGENCE_ABSOLUTE_FLOOR_USD);
    diff / relative_base > COST_DIVERGENCE_RELATIVE_TOLERANCE
}

/// The gateway-settled cost, if the event carries a usable one.
fn authoritative_cost(event: &BillingEvent) -> Option<f64> {
    event
        .cost_usd
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

/// Break a gateway-settled total into input/output components for reporting.
/// Uses the rate card's input/output ratio when a price is known, otherwise
/// splits by token counts; either way `total_cost` equals the settled figure.
fn settled_breakdown(total: f64, usage: &TokenUsage, price: Option<&ModelPrice>) -> CostEstimate {
    if let Some(price) = price {
        let est = price.estimate(usage);
        if est.total_cost > 0.0 {
            let scale = total / est.total_cost;
            return CostEstimate {
                input_cost: est.input_cost * scale,
                output_cost: est.output_cost * scale,
                total_cost: total,
                currency: price.currency.clone(),
            };
        }
    }
    let denominator = usage.prompt_tokens.saturating_add(usage.completion_tokens) as f64;
    let input_cost = if denominator > 0.0 {
        total * usage.prompt_tokens as f64 / denominator
    } else {
        0.0
    };
    CostEstimate {
        input_cost,
        output_cost: total - input_cost,
        total_cost: total,
        currency: "USD".to_string(),
    }
}

/// Optional tenant scoping for [`LedgerSink::list`] (issue #149). When any
/// field is set, only entries matching it are returned. Implementations
/// should push this into the storage query itself (not filter a fetched page
/// after the fact) so pagination operates on the already-scoped result set —
/// otherwise a scoped page can silently come back empty or incomplete in a
/// busy, multi-tenant ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerListFilter {
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub api_key_id: Option<String>,
}

impl LedgerListFilter {
    pub fn is_empty(&self) -> bool {
        self.organization_id.is_none() && self.project_id.is_none() && self.api_key_id.is_none()
    }

    /// Whether a tenant matches this filter (used by the in-memory sink,
    /// which has no separate query layer to push the filter into).
    pub fn matches(&self, tenant: &TenantContext) -> bool {
        Self::field_matches(
            self.organization_id.as_deref(),
            tenant.organization_id.as_deref(),
        ) && Self::field_matches(self.project_id.as_deref(), tenant.project_id.as_deref())
            && Self::field_matches(self.api_key_id.as_deref(), tenant.api_key_id.as_deref())
    }

    fn field_matches(filter: Option<&str>, actual: Option<&str>) -> bool {
        match filter {
            Some(expected) => actual == Some(expected),
            None => true,
        }
    }
}

/// Persistence seam for settled ledger entries. Implementations must be
/// idempotent on [`LedgerEntry::id`] so a retried charge does not double-bill.
pub trait LedgerSink: Send + Sync {
    /// Persist a settled entry. Returns `true` if newly recorded, `false` if a
    /// prior entry with the same id already existed (idempotent no-op).
    fn record(&self, entry: &LedgerEntry) -> Result<bool, BillingError>;
    /// List recorded entries matching `filter`, newest last, paginated.
    fn list(
        &self,
        filter: &LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>, BillingError>;
    /// Fetch a single entry by its idempotency id.
    fn get(&self, id: &str) -> Result<Option<LedgerEntry>, BillingError>;
}

/// Aggregate settlement totals across the in-memory ledger, useful for
/// smoke assertions and lightweight reporting.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LedgerTotals {
    pub entries: usize,
    pub total_cost_usd: f64,
    pub total_credits: f64,
    pub total_tokens: u64,
}

/// In-memory, idempotent [`LedgerSink`] with an optional retention bound.
#[derive(Debug, Default, Clone)]
pub struct InMemoryLedgerSink {
    inner: Arc<Mutex<InMemoryLedgerState>>,
}

#[derive(Debug, Default)]
struct InMemoryLedgerState {
    entries: VecDeque<LedgerEntry>,
    retention_limit: Option<usize>,
    recorded_total: u64,
}

impl InMemoryLedgerSink {
    pub fn with_retention_limit(retention_limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryLedgerState {
                entries: VecDeque::new(),
                retention_limit: Some(retention_limit),
                recorded_total: 0,
            })),
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.entries.is_empty())
            .unwrap_or(true)
    }

    pub fn recorded_total(&self) -> u64 {
        self.inner
            .lock()
            .map(|state| state.recorded_total)
            .unwrap_or_default()
    }

    pub fn totals(&self) -> LedgerTotals {
        self.inner
            .lock()
            .map(|state| {
                let mut totals = LedgerTotals {
                    entries: state.entries.len(),
                    ..LedgerTotals::default()
                };
                for entry in &state.entries {
                    totals.total_cost_usd += entry.cost.total_cost;
                    totals.total_credits += entry.credits;
                    totals.total_tokens += entry.usage.total_tokens;
                }
                totals
            })
            .unwrap_or_default()
    }
}

fn poisoned() -> BillingError {
    BillingError::new("billing_ledger_poisoned", "billing ledger lock poisoned")
}

impl LedgerSink for InMemoryLedgerSink {
    fn record(&self, entry: &LedgerEntry) -> Result<bool, BillingError> {
        let mut state = self.inner.lock().map_err(|_| poisoned())?;
        if let Some(existing) = state
            .entries
            .iter()
            .find(|existing| existing.id == entry.id)
        {
            if same_provider_attempt_settlement(existing, entry) {
                return Ok(false);
            }
            return Err(BillingError::new(
                "billing_idempotency_conflict",
                format!(
                    "ledger id {} was replayed with different provider-attempt settlement data",
                    entry.id
                ),
            ));
        }
        state.entries.push_back(entry.clone());
        state.recorded_total = state.recorded_total.saturating_add(1);
        if let Some(limit) = state.retention_limit {
            while state.entries.len() > limit {
                state.entries.pop_front();
            }
        }
        Ok(true)
    }

    fn list(
        &self,
        filter: &LedgerListFilter,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>, BillingError> {
        let state = self.inner.lock().map_err(|_| poisoned())?;
        Ok(state
            .entries
            .iter()
            .filter(|entry| filter.matches(&entry.tenant))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect())
    }

    fn get(&self, id: &str) -> Result<Option<LedgerEntry>, BillingError> {
        let state = self.inner.lock().map_err(|_| poisoned())?;
        Ok(state.entries.iter().find(|entry| entry.id == id).cloned())
    }
}

#[cfg(test)]
#[path = "ledger_test.rs"]
mod tests;
