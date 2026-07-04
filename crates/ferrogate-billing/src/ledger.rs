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
    TokenUsage,
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
    /// Idempotency key for the charge, derived from the request/trace id.
    pub id: String,
    pub request_id: String,
    #[serde(default)]
    pub trace_id: Option<String>,
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
}

/// Deterministic idempotency key for a usage event, matching the metering
/// exporter's convention (`ferrogate:{trace}:{request}` or `ferrogate:{request}`).
pub fn ledger_entry_id(event: &BillingEvent) -> String {
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
    let price_opt = book.price_for(&event.provider, &event.provider_model).cloned();

    let (cost, unit_price, cost_source) = match authoritative_cost(event) {
        Some(total) => {
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
    })
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

/// Persistence seam for settled ledger entries. Implementations must be
/// idempotent on [`LedgerEntry::id`] so a retried charge does not double-bill.
pub trait LedgerSink: Send + Sync {
    /// Persist a settled entry. Returns `true` if newly recorded, `false` if a
    /// prior entry with the same id already existed (idempotent no-op).
    fn record(&self, entry: &LedgerEntry) -> Result<bool, BillingError>;
    /// List recorded entries, newest last, paginated.
    fn list(&self, offset: usize, limit: usize) -> Result<Vec<LedgerEntry>, BillingError>;
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
        if state.entries.iter().any(|existing| existing.id == entry.id) {
            return Ok(false);
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

    fn list(&self, offset: usize, limit: usize) -> Result<Vec<LedgerEntry>, BillingError> {
        let state = self.inner.lock().map_err(|_| poisoned())?;
        Ok(state
            .entries
            .iter()
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
mod tests {
    use super::*;
    use crate::pricing::{PriceBook, PriceEntry};

    fn event(request_id: &str, provider: &str, model: &str) -> BillingEvent {
        BillingEvent {
            request_id: request_id.into(),
            trace_id: Some(format!("trace-{request_id}")),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext {
                organization_id: Some("org".into()),
                api_key_id: Some("key".into()),
                ..TenantContext::default()
            },
            logical_model: "fast-chat".into(),
            provider: provider.into(),
            provider_model: model.into(),
            usage: TokenUsage::new(1_000, 2_000, 0),
            usage_source: BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1_800_000_000),
            cost_usd: None,
            latency_ms: None,
        }
    }

    fn book() -> PriceBook {
        PriceBook::new(vec![PriceEntry::new(
            "openai",
            "gpt-5.5",
            ModelPrice::usd(5.0, 15.0),
        )])
    }

    #[test]
    fn charge_prices_usage_and_credits() {
        let entry = charge(&book(), &event("req-1", "openai", "gpt-5.5")).unwrap();
        // input: 1000 * 5 / 1e6 = 0.005 ; output: 2000 * 15 / 1e6 = 0.030
        assert!((entry.cost.input_cost - 0.005).abs() < 1e-9);
        assert!((entry.cost.output_cost - 0.030).abs() < 1e-9);
        assert!((entry.cost.total_cost - 0.035).abs() < 1e-9);
        // default 1e6 credits per usd
        assert!((entry.credits - 35_000.0).abs() < 1e-3);
        // total was 0 -> derived to 3000
        assert_eq!(entry.usage.total_tokens, 3_000);
        assert_eq!(entry.id, "ferrogate:trace-req-1:req-1");
    }

    #[test]
    fn charge_fails_closed_on_missing_price() {
        let error = charge(&book(), &event("req-2", "anthropic", "claude")).unwrap_err();
        assert_eq!(error.code, "price_not_found");
    }

    #[test]
    fn sink_is_idempotent_on_id() {
        let sink = InMemoryLedgerSink::default();
        let entry = charge(&book(), &event("req-3", "openai", "gpt-5.5")).unwrap();
        assert!(sink.record(&entry).unwrap());
        assert!(!sink.record(&entry).unwrap());
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.recorded_total(), 1);
        let totals = sink.totals();
        assert_eq!(totals.entries, 1);
        assert!((totals.total_cost_usd - 0.035).abs() < 1e-9);
    }

    #[test]
    fn sink_lists_and_gets() {
        let sink = InMemoryLedgerSink::default();
        let entry = charge(&book(), &event("req-4", "openai", "gpt-5.5")).unwrap();
        sink.record(&entry).unwrap();
        assert_eq!(sink.list(0, 10).unwrap().len(), 1);
        assert_eq!(sink.get(&entry.id).unwrap().unwrap().request_id, "req-4");
        assert!(sink.get("missing").unwrap().is_none());
    }

    #[test]
    fn charge_honors_gateway_settled_cost_over_pricebook() {
        // Gateway already settled $0.01; the PriceBook would compute $0.035.
        let mut e = event("req-5", "openai", "gpt-5.5");
        e.cost_usd = Some(0.01);
        let entry = charge(&book(), &e).unwrap();
        assert_eq!(entry.cost_source, CostSource::GatewaySettled);
        assert!((entry.cost.total_cost - 0.01).abs() < 1e-9);
        // breakdown scales to the settled total
        assert!((entry.cost.input_cost + entry.cost.output_cost - 0.01).abs() < 1e-9);
        // credits follow the settled total, not the re-price
        assert!((entry.credits - 10_000.0).abs() < 1e-3);
    }

    #[test]
    fn charge_honors_settled_cost_even_without_a_pricebook_entry() {
        // Unknown provider/model: no PriceBook rule, but the gateway settled a
        // cost, so the ledger records it instead of failing closed.
        let mut e = event("req-6", "custom-vendor", "mystery-model");
        e.cost_usd = Some(0.5);
        let entry = charge(&book(), &e).unwrap();
        assert_eq!(entry.cost_source, CostSource::GatewaySettled);
        assert!((entry.cost.total_cost - 0.5).abs() < 1e-9);
    }

    #[test]
    fn charge_reconciles_missing_completion_split_before_pricing() {
        // Provider reported prompt + total but omitted the completion split.
        let mut e = event("req-7", "openai", "gpt-5.5");
        e.usage = TokenUsage::new(1_000, 0, 3_000);
        let entry = charge(&book(), &e).unwrap();
        // completion derived as 3000 - 1000 = 2000, so output is billed
        assert_eq!(entry.usage.completion_tokens, 2_000);
        assert!((entry.cost.output_cost - 0.030).abs() < 1e-9);
        assert!((entry.cost.total_cost - 0.035).abs() < 1e-9);
    }
}
