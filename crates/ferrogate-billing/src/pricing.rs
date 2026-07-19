// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Model pricing registry (rate card) for the billing service.
//!
//! A [`PriceBook`] maps a `(provider, model)` pair to a [`ModelPrice`] so the
//! billing service can convert token usage into a settled cost. Lookup is
//! wildcard-aware and fail-closed: a request whose `(provider, model)` matches
//! no rule (including the `("*", "*")` catch-all, if configured) yields
//! [`None`], and the charge endpoint rejects it rather than billing zero.
//!
//! The design mirrors sub2api-style per-model rate cards: input and output
//! tokens are priced separately (`ModelPrice`), and a `credits_per_usd`
//! conversion turns settled USD into an abstract credit/quota consumption so a
//! deployment can bill either in money or in credits from the same usage.

use serde::{Deserialize, Serialize};

use crate::ModelPrice;

/// Default credit granularity: 1 USD == 1_000_000 credits (1 credit == 1 micro-USD).
pub const DEFAULT_CREDITS_PER_USD: f64 = 1_000_000.0;

/// Bytes in one billed gigabyte for egress metering (#262). Uses the decimal
/// GB (10^9) that bandwidth/CDN rate cards are quoted in, not the binary GiB,
/// so a `$/GB` egress rate matches how object-storage and CDN egress is sold.
pub const BYTES_PER_BILLED_GB: f64 = 1_000_000_000.0;

/// A conservative default asset-egress rate ($/GB) seeded into
/// [`PriceBook::with_default_rate_card`] (#262), in the ballpark of commodity
/// object-storage/CDN egress. A deployment overrides it via configuration.
pub const DEFAULT_EGRESS_PRICE_PER_GB: f64 = 0.09;

const WILDCARD: &str = "*";

fn default_credits_per_usd() -> f64 {
    DEFAULT_CREDITS_PER_USD
}

/// Settled USD cost of transferring `bytes` of asset egress at `price_per_gb`
/// (#262). Shared by [`PriceBook::egress_cost_usd`] and the gateway's
/// per-download metering so the two can never drift on the GB divisor.
pub fn egress_cost_usd(price_per_gb: f64, bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_BILLED_GB * price_per_gb
}

/// A single rate-card rule. `provider` and `model` may be the literal `"*"`
/// wildcard to match any provider or model respectively.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceEntry {
    pub provider: String,
    pub model: String,
    pub price: ModelPrice,
}

impl PriceEntry {
    pub fn new(provider: impl Into<String>, model: impl Into<String>, price: ModelPrice) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            price,
        }
    }
}

/// The rate card consulted by the billing service. Rules are matched with a
/// deterministic specificity order (most specific first) so a catch-all never
/// shadows an exact match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceBook {
    #[serde(default)]
    pub entries: Vec<PriceEntry>,
    /// Credits charged per settled USD. `credits = total_cost_usd * credits_per_usd`.
    #[serde(default = "default_credits_per_usd")]
    pub credits_per_usd: f64,
    /// Asset-egress (download bandwidth) rate in USD per GB (#262), the
    /// non-token billing dimension the asset-hosting surface settles against.
    /// `None` means egress is unpriced, so an egress metering event carries no
    /// cost and the ledger/wallet are untouched -- exactly like an unpriced
    /// model, fail-open on charge rather than fabricating a cost.
    #[serde(default)]
    pub egress_price_per_gb: Option<f64>,
}

impl Default for PriceBook {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            credits_per_usd: DEFAULT_CREDITS_PER_USD,
            egress_price_per_gb: None,
        }
    }
}

impl PriceBook {
    pub fn new(entries: Vec<PriceEntry>) -> Self {
        Self {
            entries,
            credits_per_usd: DEFAULT_CREDITS_PER_USD,
            egress_price_per_gb: None,
        }
    }

    /// Set the asset-egress rate (USD per GB) for this rate card (#262).
    pub fn with_egress_price_per_gb(mut self, egress_price_per_gb: f64) -> Self {
        self.egress_price_per_gb = Some(egress_price_per_gb);
        self
    }

    /// Settled USD cost of `bytes` of asset egress under this rate card (#262),
    /// or `None` when egress is unpriced so the caller can fail closed on the
    /// charge (no fabricated zero cost), mirroring [`Self::price_for`].
    pub fn egress_cost_usd(&self, bytes: u64) -> Option<f64> {
        self.egress_price_per_gb
            .map(|price_per_gb| egress_cost_usd(price_per_gb, bytes))
    }

    pub fn with_credits_per_usd(mut self, credits_per_usd: f64) -> Self {
        self.credits_per_usd = credits_per_usd;
        self
    }

    /// Parse a rate card from JSON. Accepts either a bare array of
    /// [`PriceEntry`] or a full `{ "entries": [...], "credits_per_usd": N }`
    /// object.
    pub fn from_json_slice(bytes: &[u8]) -> anyhow::Result<Self> {
        // Try the full object form first, then fall back to a bare array.
        match serde_json::from_slice::<PriceBook>(bytes) {
            Ok(book) => Ok(book),
            Err(object_error) => match serde_json::from_slice::<Vec<PriceEntry>>(bytes) {
                Ok(entries) => Ok(PriceBook::new(entries)),
                Err(_) => Err(anyhow::anyhow!(
                    "failed to parse price book: {object_error}"
                )),
            },
        }
    }

    /// The number of rules in the book.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Resolve the price for a `(provider, model)` pair. Precedence, most
    /// specific first:
    /// 1. exact `(provider, model)`
    /// 2. `(provider, "*")`
    /// 3. `("*", model)`
    /// 4. `("*", "*")`
    ///
    /// Returns `None` when nothing matches so the caller can fail closed.
    pub fn price_for(&self, provider: &str, model: &str) -> Option<&ModelPrice> {
        self.find(provider, model)
            .or_else(|| self.find(provider, WILDCARD))
            .or_else(|| self.find(WILDCARD, model))
            .or_else(|| self.find(WILDCARD, WILDCARD))
    }

    fn find(&self, provider: &str, model: &str) -> Option<&ModelPrice> {
        self.entries
            .iter()
            .find(|entry| entry.provider == provider && entry.model == model)
            .map(|entry| &entry.price)
    }

    /// Convert a settled USD cost into abstract credits.
    pub fn credits_for_usd(&self, total_cost_usd: f64) -> f64 {
        total_cost_usd * self.credits_per_usd
    }

    /// A conservative default rate card covering the major vendors FerroGate
    /// proxies. Prices are per 1M tokens (input, output) in USD and are meant
    /// as sane starting values a deployment overrides via configuration.
    ///
    /// Entries are keyed on the wildcard provider `"*"` and the concrete model
    /// id, because a model name like `gpt-5.5` is unambiguous regardless of
    /// which upstream (e.g. a provider named `openai` or `token4ai`) serves it.
    /// A deployment that needs per-provider prices for the same model overrides
    /// with a provider-specific `PriceEntry`, which takes precedence.
    pub fn with_default_rate_card() -> Self {
        let entries = vec![
            // OpenAI family (incl. the token4ai gpt-5.x upstream).
            PriceEntry::new("*", "gpt-5.5", ModelPrice::usd(5.0, 15.0)),
            PriceEntry::new("*", "gpt-5", ModelPrice::usd(5.0, 15.0)),
            PriceEntry::new("*", "gpt-4o", ModelPrice::usd(2.5, 10.0)),
            PriceEntry::new("*", "gpt-4o-mini", ModelPrice::usd(0.15, 0.60)),
            // Anthropic Claude.
            PriceEntry::new("*", "claude-sonnet-4", ModelPrice::usd(3.0, 15.0)),
            PriceEntry::new("*", "claude-opus-4", ModelPrice::usd(15.0, 75.0)),
            // Google Gemini.
            PriceEntry::new("*", "gemini-2.5-pro", ModelPrice::usd(1.25, 10.0)),
            PriceEntry::new("*", "gemini-2.5-flash", ModelPrice::usd(0.30, 2.50)),
            // xAI Grok.
            PriceEntry::new("*", "grok-4", ModelPrice::usd(3.0, 15.0)),
            // DeepSeek (OpenAI-compatible upstream).
            PriceEntry::new("*", "deepseek-chat", ModelPrice::usd(0.27, 1.10)),
            PriceEntry::new("*", "deepseek-reasoner", ModelPrice::usd(0.55, 2.19)),
        ];
        Self::new(entries).with_egress_price_per_gb(DEFAULT_EGRESS_PRICE_PER_GB)
    }
}

#[cfg(test)]
#[path = "pricing_test.rs"]
mod tests;
