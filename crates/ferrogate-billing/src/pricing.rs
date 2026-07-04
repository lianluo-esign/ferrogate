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

const WILDCARD: &str = "*";

fn default_credits_per_usd() -> f64 {
    DEFAULT_CREDITS_PER_USD
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
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        price: ModelPrice,
    ) -> Self {
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
}

impl Default for PriceBook {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            credits_per_usd: DEFAULT_CREDITS_PER_USD,
        }
    }
}

impl PriceBook {
    pub fn new(entries: Vec<PriceEntry>) -> Self {
        Self {
            entries,
            credits_per_usd: DEFAULT_CREDITS_PER_USD,
        }
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
        Self::new(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book() -> PriceBook {
        PriceBook::new(vec![
            PriceEntry::new("openai", "gpt-5.5", ModelPrice::usd(5.0, 15.0)),
            PriceEntry::new("openai", "*", ModelPrice::usd(1.0, 2.0)),
            PriceEntry::new("*", "*", ModelPrice::usd(10.0, 10.0)),
        ])
    }

    #[test]
    fn exact_match_wins_over_wildcards() {
        let price = book().price_for("openai", "gpt-5.5").cloned().unwrap();
        assert_eq!(price, ModelPrice::usd(5.0, 15.0));
    }

    #[test]
    fn provider_wildcard_matches_unknown_model() {
        let price = book().price_for("openai", "gpt-4o").cloned().unwrap();
        assert_eq!(price, ModelPrice::usd(1.0, 2.0));
    }

    #[test]
    fn global_wildcard_is_last_resort() {
        let price = book().price_for("mystery", "model-x").cloned().unwrap();
        assert_eq!(price, ModelPrice::usd(10.0, 10.0));
    }

    #[test]
    fn missing_price_is_none_when_no_wildcard() {
        let book = PriceBook::new(vec![PriceEntry::new(
            "openai",
            "gpt-5.5",
            ModelPrice::usd(5.0, 15.0),
        )]);
        assert!(book.price_for("anthropic", "claude").is_none());
    }

    #[test]
    fn credits_scale_with_configured_rate() {
        let book = PriceBook::default().with_credits_per_usd(1_000.0);
        assert!((book.credits_for_usd(0.5) - 500.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parses_bare_array_and_full_object() {
        let array = br#"[{"provider":"openai","model":"gpt-5.5","price":{"input_price_per_1m":5.0,"output_price_per_1m":15.0,"currency":"USD"}}]"#;
        let from_array = PriceBook::from_json_slice(array).unwrap();
        assert_eq!(from_array.len(), 1);
        assert_eq!(from_array.credits_per_usd, DEFAULT_CREDITS_PER_USD);

        let object = br#"{"credits_per_usd":1000.0,"entries":[{"provider":"*","model":"*","price":{"input_price_per_1m":1.0,"output_price_per_1m":1.0,"currency":"USD"}}]}"#;
        let from_object = PriceBook::from_json_slice(object).unwrap();
        assert_eq!(from_object.credits_per_usd, 1000.0);
        assert_eq!(from_object.len(), 1);
    }
}
