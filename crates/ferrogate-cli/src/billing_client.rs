// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-side client for the standalone billing service (issues #131/#137).
//!
//! Delivery is durable, not fire-and-forget: the gateway enqueues each settled
//! usage event to a persistent outbox (see `state.rs`), and a background sweeper
//! drains it by calling [`BillingReporter::deliver_once`] and deleting the row
//! on success. A charge therefore survives a billing outage or a gateway
//! restart rather than being dropped by a best-effort POST.

use std::time::Duration;

use ferrogate_billing::BillingEvent;

use crate::{config::BillingServiceConfig, metering};

const CHARGE_PATH: &str = "/v1/billing/charge";

/// A resolved, cheaply-cloneable client that POSTs one usage event to the
/// billing service's charge endpoint.
#[derive(Debug, Clone)]
pub(crate) struct BillingReporter {
    endpoint: String,
    bearer_token: String,
    timeout: Duration,
}

impl BillingReporter {
    /// Build a reporter from config, resolving the optional bearer token from an
    /// inline value or an environment variable. Returns `Ok(None)` when the
    /// billing-service client is disabled.
    pub(crate) fn from_config(config: &BillingServiceConfig) -> anyhow::Result<Option<Self>> {
        if !config.enabled {
            return Ok(None);
        }
        let endpoint = format!("{}{}", config.endpoint.trim_end_matches('/'), CHARGE_PATH);
        let bearer_token = resolve_token(config)?;
        Ok(Some(Self {
            endpoint,
            bearer_token,
            timeout: Duration::from_millis(config.timeout_millis.max(1)),
        }))
    }

    /// Deliver a single usage event to the billing service, synchronously.
    /// Returns `Err` on any transport or non-2xx failure so the caller (the
    /// outbox sweeper) can retry with backoff. Idempotent on the billing side
    /// (keyed by the ledger entry id), so replay never double-bills.
    pub(crate) fn deliver_once(&self, event: &BillingEvent) -> anyhow::Result<()> {
        let body = serde_json::to_vec(event)?;
        metering::post_json(&self.endpoint, &self.bearer_token, &body, self.timeout)
    }
}

fn resolve_token(config: &BillingServiceConfig) -> anyhow::Result<String> {
    if let Some(token) = config.token.as_deref() {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }
    if let Some(env_name) = config.token_env.as_deref() {
        let env_name = env_name.trim();
        if !env_name.is_empty() {
            return std::env::var(env_name).map_err(|_| {
                anyhow::anyhow!("failed to read billing service token env {env_name}")
            });
        }
    }
    Ok(String::new())
}
