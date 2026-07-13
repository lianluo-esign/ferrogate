// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Token usage metering and local event retention boundaries.
//!
//! Beyond raw metering, this crate hosts the standalone billing microservice
//! (issue #129): a [`pricing::PriceBook`] rate card, a [`ledger::charge`]
//! function that turns a [`BillingEvent`] into a priced [`ledger::LedgerEntry`],
//! a [`ledger::LedgerSink`] persistence seam, and an HTTP [`service::serve`]
//! entrypoint. The crate stays free of any storage dependency (the durable
//! `LedgerSink` lives in `ferrogate-storage`, which already depends on this
//! crate) so the dependency graph stays acyclic.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};

pub mod ledger;
pub mod pricing;
pub mod service;

pub use ledger::{
    charge, same_provider_attempt_settlement, CostSource, InMemoryLedgerSink, LedgerEntry,
    LedgerListFilter, LedgerSink, LedgerTotals,
};
pub use pricing::{PriceBook, PriceEntry, DEFAULT_CREDITS_PER_USD};
pub use service::{billing_error_http_status, serve, BillingServiceConfig};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

impl TokenUsage {
    pub fn new(prompt_tokens: u64, completion_tokens: u64, total_tokens: u64) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        }
    }

    pub fn estimate_missing_total(mut self) -> Self {
        if self.total_tokens == 0 {
            self.total_tokens = self.prompt_tokens + self.completion_tokens;
        }
        self
    }

    /// Reconcile the prompt/completion split with `total_tokens` before pricing.
    ///
    /// Some providers report only a total, or omit one side of the split (e.g.
    /// Gemini can return `promptTokenCount` + `totalTokenCount` without
    /// `candidatesTokenCount`). Pricing by `prompt + completion` alone would
    /// then bill the missing side at $0 (issue #140). This fills a missing
    /// total from the split, and a missing split side from the total, so cost
    /// estimation always sees a consistent breakdown.
    pub fn reconcile_split(mut self) -> Self {
        if self.total_tokens == 0 {
            self.total_tokens = self.prompt_tokens.saturating_add(self.completion_tokens);
        } else {
            if self.completion_tokens == 0 && self.total_tokens > self.prompt_tokens {
                self.completion_tokens = self.total_tokens - self.prompt_tokens;
            }
            if self.prompt_tokens == 0 && self.total_tokens > self.completion_tokens {
                self.prompt_tokens = self.total_tokens - self.completion_tokens;
            }
        }
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelPrice {
    pub input_price_per_1m: f64,
    pub output_price_per_1m: f64,
    pub currency: String,
}

impl ModelPrice {
    pub fn usd(input_price_per_1m: f64, output_price_per_1m: f64) -> Self {
        Self {
            input_price_per_1m,
            output_price_per_1m,
            currency: "USD".into(),
        }
    }

    pub fn estimate(&self, usage: &TokenUsage) -> CostEstimate {
        let input_cost = usage.prompt_tokens as f64 * self.input_price_per_1m / 1_000_000.0;
        let output_cost = usage.completion_tokens as f64 * self.output_price_per_1m / 1_000_000.0;
        CostEstimate {
            input_cost,
            output_cost,
            total_cost: input_cost + output_cost,
            currency: self.currency.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CostEstimate {
    pub input_cost: f64,
    pub output_cost: f64,
    pub total_cost: f64,
    pub currency: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingUsageSource {
    #[default]
    ProviderUsage,
    GatewayEstimate,
}

impl BillingUsageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            BillingUsageSource::ProviderUsage => "provider_usage",
            BillingUsageSource::GatewayEstimate => "gateway_estimate",
        }
    }
}

/// Stable identity for one concrete provider dispatch within a logical AI
/// request. The logical [`BillingEvent::request_id`] remains the correlation
/// key across the gateway; this identity distinguishes retries and fallback
/// dispatches that can each report billable usage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAttempt {
    #[serde(default)]
    pub provider_attempt_id: String,
    #[serde(default)]
    pub provider_attempt_index: u32,
}

impl ProviderAttempt {
    pub fn for_request(request_id: &str, provider_attempt_index: u32) -> Self {
        Self {
            provider_attempt_id: format!("{request_id}:provider-attempt:{provider_attempt_index}"),
            provider_attempt_index,
        }
    }

    pub fn is_legacy(&self) -> bool {
        self.provider_attempt_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingEvent {
    pub request_id: String,
    pub trace_id: Option<String>,
    #[serde(default, flatten)]
    pub provider_attempt: ProviderAttempt,
    #[serde(default)]
    pub agent_run_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub workflow_version: Option<u32>,
    #[serde(default)]
    pub workflow_node_id: Option<String>,
    pub cluster_id: Option<String>,
    pub node_id: Option<String>,
    pub tenant: TenantContext,
    pub logical_model: String,
    pub provider: String,
    pub provider_model: String,
    pub usage: TokenUsage,
    #[serde(default)]
    pub usage_source: BillingUsageSource,
    pub status_code: u16,
    pub occurred_at_unix: Option<u64>,
    /// Settled cost in USD, computed from the route's `ModelPrice` at
    /// request-completion time. `None` when no pricing is configured for
    /// the model/provider (P1-4).
    #[serde(default)]
    pub cost_usd: Option<f64>,
    /// Wall-clock duration of the request as observed by the gateway,
    /// dispatch-start to response-settlement (P1-4).
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Arbitrary caller-supplied request tags (issue #171), e.g. an
    /// end-customer id, a feature flag, an experiment arm -- attribution
    /// dimensions beyond the built-in tenant/project/workspace/key scope
    /// chain. Bounded by [`MAX_METADATA_ENTRIES`]/[`MAX_METADATA_KEY_LEN`]/
    /// [`MAX_METADATA_VALUE_LEN`] at the point a request is accepted, so
    /// this map is never unbounded once it reaches the ledger.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// This request's debit against the tenant's prepaid-credit wallet
    /// (issue #169), if one exists -- always negative (credits drawn
    /// down), `None` for a tenant with no wallet row or when `cost_usd`
    /// is `None`/zero. Reported here purely for visibility: the debit
    /// itself already happened in the gateway's own wallet storage
    /// (`AppState::debit_wallet_for_settled_cost`) before this event was
    /// built, so `ferrogate-billing` (which cannot depend on
    /// `ferrogate-storage` -- see the module doc comment) never mutates
    /// a wallet balance itself, only mirrors the outcome.
    #[serde(default)]
    pub wallet_delta_credits: Option<i64>,
    /// The wallet's balance immediately after `wallet_delta_credits` was
    /// applied. `None` under the same conditions as
    /// `wallet_delta_credits`.
    #[serde(default)]
    pub wallet_balance_after_credits: Option<i64>,
}

/// Maximum number of metadata key/value pairs a single request may attach
/// (issue #171) -- comparable to Cloudflare AI Gateway's 5 Custom Metadata
/// pairs. Enforced where a request is first accepted (the gateway's
/// `ChatCompletionRequest` parsing), not here, but the ledger/rollup
/// storage code documents/relies on this bound too.
pub const MAX_METADATA_ENTRIES: usize = 8;
/// Maximum byte length of a single metadata key (issue #171).
pub const MAX_METADATA_KEY_LEN: usize = 64;
/// Maximum byte length of a single metadata value (issue #171).
pub const MAX_METADATA_VALUE_LEN: usize = 256;

/// Validates a caller-supplied request metadata map against the
/// [`MAX_METADATA_ENTRIES`]/[`MAX_METADATA_KEY_LEN`]/[`MAX_METADATA_VALUE_LEN`]
/// bounds (issue #171), returning a human-readable reason on the first
/// violation found. Shared by every ingress path that accepts a `metadata`
/// object so the limits can't drift between chat completions and Responses
/// API (issue #171's suggested scope explicitly covers both).
pub fn validate_request_metadata(metadata: &BTreeMap<String, String>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(format!(
            "metadata supports at most {MAX_METADATA_ENTRIES} entries, got {}",
            metadata.len()
        ));
    }
    for (key, value) in metadata {
        if key.is_empty() {
            return Err("metadata keys must not be empty".to_string());
        }
        if key.len() > MAX_METADATA_KEY_LEN {
            return Err(format!(
                "metadata key {key:?} exceeds the {MAX_METADATA_KEY_LEN}-byte limit"
            ));
        }
        if value.len() > MAX_METADATA_VALUE_LEN {
            return Err(format!(
                "metadata value for key {key:?} exceeds the {MAX_METADATA_VALUE_LEN}-byte limit"
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingError {
    pub code: String,
    pub message: String,
}

impl BillingError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub trait BillingEventSink: Send + Sync {
    fn record(&self, event: BillingEvent) -> Result<(), BillingError>;
    fn list(&self) -> Vec<BillingEvent>;
}

#[derive(Debug, Default, Clone)]
pub struct InMemoryBillingEventSink {
    inner: Arc<Mutex<InMemoryBillingEventState>>,
}

#[derive(Debug, Default)]
struct InMemoryBillingEventState {
    events: VecDeque<BillingEvent>,
    retention_limit: Option<usize>,
    recorded_total: u64,
}

impl InMemoryBillingEventSink {
    pub fn with_retention_limit(retention_limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryBillingEventState {
                events: VecDeque::new(),
                retention_limit: Some(retention_limit),
                recorded_total: 0,
            })),
        }
    }

    pub fn set_retention_limit(&self, retention_limit: usize) -> Result<(), BillingError> {
        let mut inner = self.inner.lock().map_err(|_| {
            BillingError::new("billing_sink_poisoned", "billing event sink lock poisoned")
        })?;
        inner.retention_limit = Some(retention_limit);
        enforce_retention_limit(&mut inner);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.events.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .map(|inner| inner.events.is_empty())
            .unwrap_or(true)
    }

    pub fn recorded_total(&self) -> u64 {
        self.inner
            .lock()
            .map(|inner| inner.recorded_total)
            .unwrap_or_default()
    }

    pub fn list_paginated(&self, offset: usize, limit: usize) -> Vec<BillingEvent> {
        self.inner
            .lock()
            .map(|inner| {
                inner
                    .events
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl BillingEventSink for InMemoryBillingEventSink {
    fn record(&self, event: BillingEvent) -> Result<(), BillingError> {
        let mut inner = self.inner.lock().map_err(|_| {
            BillingError::new("billing_sink_poisoned", "billing event sink lock poisoned")
        })?;
        inner.events.push_back(event);
        inner.recorded_total = inner.recorded_total.saturating_add(1);
        enforce_retention_limit(&mut inner);
        Ok(())
    }

    fn list(&self) -> Vec<BillingEvent> {
        self.inner
            .lock()
            .map(|inner| inner.events.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn enforce_retention_limit(inner: &mut InMemoryBillingEventState) {
    if let Some(limit) = inner.retention_limit {
        while inner.events.len() > limit {
            inner.events.pop_front();
        }
    }
}

#[cfg(test)]
#[path = "lib_test.rs"]
mod tests;
