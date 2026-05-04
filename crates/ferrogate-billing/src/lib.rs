//! Token usage, cost estimation, and billing event boundaries.

use std::sync::{Arc, Mutex};

use ferrogate_core::TenantContext;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillingEvent {
    pub request_id: String,
    pub trace_id: Option<String>,
    pub tenant: TenantContext,
    pub logical_model: String,
    pub provider: String,
    pub provider_model: String,
    pub usage: TokenUsage,
    #[serde(default)]
    pub usage_source: BillingUsageSource,
    pub cost: Option<CostEstimate>,
    pub status_code: u16,
    pub occurred_at_unix: Option<u64>,
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
    events: Arc<Mutex<Vec<BillingEvent>>>,
}

impl BillingEventSink for InMemoryBillingEventSink {
    fn record(&self, event: BillingEvent) -> Result<(), BillingError> {
        let mut events = self.events.lock().map_err(|_| {
            BillingError::new("billing_sink_poisoned", "billing event sink lock poisoned")
        })?;
        events.push(event);
        Ok(())
    }

    fn list(&self) -> Vec<BillingEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_model_cost_from_token_usage() {
        let price = ModelPrice::usd(0.15, 0.60);
        let usage = TokenUsage::new(1_000, 2_000, 3_000);

        let cost = price.estimate(&usage);

        assert_eq!(cost.currency, "USD");
        assert!((cost.input_cost - 0.00015).abs() < f64::EPSILON);
        assert!((cost.output_cost - 0.0012).abs() < f64::EPSILON);
        assert!((cost.total_cost - 0.00135).abs() < f64::EPSILON);
    }

    #[test]
    fn in_memory_sink_records_billing_events() {
        let sink = InMemoryBillingEventSink::default();
        sink.record(BillingEvent {
            request_id: "fg-test".into(),
            trace_id: Some("trace-test".into()),
            tenant: TenantContext {
                organization_id: Some("org".into()),
                team_id: None,
                project_id: Some("project".into()),
                user_id: None,
                api_key_id: Some("key_dev".into()),
            },
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(3, 5, 8),
            usage_source: BillingUsageSource::ProviderUsage,
            cost: Some(ModelPrice::usd(1.0, 2.0).estimate(&TokenUsage::new(3, 5, 8))),
            status_code: 200,
            occurred_at_unix: Some(1),
        })
        .unwrap();

        let events = sink.list();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant.organization_id.as_deref(), Some("org"));
        assert_eq!(events[0].usage.total_tokens, 8);
    }
}
