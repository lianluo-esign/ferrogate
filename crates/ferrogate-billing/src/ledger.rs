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
    /// The rate-card price that was applied.
    pub unit_price: ModelPrice,
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

/// Price a usage event against the rate card, producing a [`LedgerEntry`].
///
/// Fails closed with `price_not_found` when the `(provider, provider_model)`
/// pair matches no rule in the book — the caller must reject the charge rather
/// than bill zero.
pub fn charge(book: &PriceBook, event: &BillingEvent) -> Result<LedgerEntry, BillingError> {
    let price = book
        .price_for(&event.provider, &event.provider_model)
        .cloned()
        .ok_or_else(|| {
            BillingError::new(
                "price_not_found",
                format!(
                    "no rate-card price configured for provider '{}' model '{}'",
                    event.provider, event.provider_model
                ),
            )
        })?;

    let usage = event.usage.clone().estimate_missing_total();
    let cost = price.estimate(&usage);
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
        unit_price: price,
        occurred_at_unix: event.occurred_at_unix,
    })
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
}
