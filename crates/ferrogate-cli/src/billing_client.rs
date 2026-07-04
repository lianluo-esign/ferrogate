// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-side client for the standalone billing service (issue #131).
//!
//! When `config.billing_service.enabled` is set, the gateway reports each
//! settled [`BillingEvent`] to the billing service's `POST /v1/billing/charge`
//! endpoint over REST. The report is fire-and-forget on a background task so
//! the request hot path is never blocked on the billing round-trip; billing is
//! an accounting side effect, not a gate on serving the response.

use std::time::Duration;

use ferrogate_billing::BillingEvent;

use crate::{config::BillingServiceConfig, metering};

const CHARGE_PATH: &str = "/v1/billing/charge";

/// A resolved, cheaply-cloneable reporter that POSTs usage events to the
/// billing service.
#[derive(Debug, Clone)]
pub(crate) struct BillingReporter {
    endpoint: String,
    bearer_token: String,
    timeout: Duration,
}

impl BillingReporter {
    /// Build a reporter from config, resolving the optional bearer token from
    /// an inline value or an environment variable. Returns `Ok(None)` when the
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

    /// Report a settled usage event to the billing service. Fire-and-forget:
    /// failures are logged and never propagated to the request path.
    pub(crate) fn report(&self, event: BillingEvent) {
        let reporter = self.clone();
        tokio::task::spawn_blocking(move || {
            let body = match serde_json::to_vec(&event) {
                Ok(body) => body,
                Err(error) => {
                    tracing::warn!(
                        request_id = %event.request_id,
                        error = %error,
                        "failed to serialize billing charge event"
                    );
                    return;
                }
            };
            if let Err(error) = metering::post_json(
                &reporter.endpoint,
                &reporter.bearer_token,
                &body,
                reporter.timeout,
            ) {
                tracing::warn!(
                    request_id = %event.request_id,
                    endpoint = %reporter.endpoint,
                    error = %error,
                    "billing service charge report failed"
                );
            }
        });
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
