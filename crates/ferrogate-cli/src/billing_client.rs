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

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use ferrogate_billing::BillingEvent;

use crate::{config::BillingServiceConfig, metering};

const CHARGE_PATH: &str = "/v1/billing/charge";
/// Attempts (initial + retries) per report before giving up, to ride out a
/// transient billing outage without an unbounded queue (issue #137).
const MAX_REPORT_ATTEMPTS: u32 = 3;
const REPORT_BACKOFF: Duration = Duration::from_millis(50);
/// Cap on concurrently in-flight report tasks so a slow billing dependency
/// cannot starve the shared Tokio blocking pool (issue #137).
const MAX_INFLIGHT_REPORTS: usize = 256;

/// A resolved, cheaply-cloneable reporter that POSTs usage events to the
/// billing service.
#[derive(Debug, Clone)]
pub(crate) struct BillingReporter {
    endpoint: String,
    bearer_token: String,
    timeout: Duration,
    inflight: Arc<AtomicUsize>,
}

/// RAII guard decrementing the in-flight report counter on completion.
struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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
            inflight: Arc::new(AtomicUsize::new(0)),
        }))
    }

    /// Report a settled usage event to the billing service. Fire-and-forget so
    /// the request hot path is never blocked; failures are retried a bounded
    /// number of times and then logged. In-flight reports are capped so a slow
    /// billing dependency cannot starve the shared blocking pool (issue #137).
    ///
    /// NOTE: this is best-effort delivery, not durable. Charges can still be
    /// lost if the billing service is down for longer than the retry window; a
    /// durable outbox / reconciliation sweep replaying persisted metering
    /// events is tracked as follow-up on issue #137.
    pub(crate) fn report(&self, event: BillingEvent) {
        if self.inflight.load(Ordering::SeqCst) >= MAX_INFLIGHT_REPORTS {
            tracing::warn!(
                request_id = %event.request_id,
                "billing report shed: too many in-flight billing reports"
            );
            return;
        }
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let reporter = self.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = InflightGuard(reporter.inflight.clone());
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
            let mut attempt = 0;
            loop {
                attempt += 1;
                match metering::post_json(
                    &reporter.endpoint,
                    &reporter.bearer_token,
                    &body,
                    reporter.timeout,
                ) {
                    Ok(()) => return,
                    Err(error) => {
                        if attempt >= MAX_REPORT_ATTEMPTS {
                            tracing::warn!(
                                request_id = %event.request_id,
                                endpoint = %reporter.endpoint,
                                attempts = attempt,
                                error = %error,
                                "billing service charge report failed after retries"
                            );
                            return;
                        }
                        std::thread::sleep(REPORT_BACKOFF * attempt);
                    }
                }
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
