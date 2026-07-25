// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Tether-bypass DETECTION for the Cloudflare container agent tier (issue #471):
//   reconcile provider-reported usage against gateway-metered usage per run and emit a typed,
//   fail-loud verdict, so a bypass that prevention did not catch is never silent.

//! Tether-bypass **detection** for the Cloudflare container agent tier
//! (issue #471).
//!
//! Prevention (see [`crate::cloudflare_container_egress`]) is the primary
//! control and it is a real network control: `enableInternet = false` plus a
//! one-host allowlist is enforced by Cloudflare outside the container. But
//! prevention is only as good as its configuration and its blast radius:
//!
//! * an operator can bind `CONTAINER_SANDBOX` to a class that does **not**
//!   subclass `AgentSandbox` (so `enableInternet` reverts to the SDK default of
//!   `true`);
//! * a run can be started through a Worker deployment that predates this slice;
//! * DNS remains reachable (to Cloudflare's resolvers) even when sealed, which
//!   is a low-bandwidth covert channel the platform does not close;
//! * an agent can exfiltrate a prompt through an *allowed* host that happens to
//!   proxy to a provider.
//!
//! None of those are hypothetical enough to assert "cannot happen". So the tier
//! also has to make a bypass **loud**. The reconciliation here is the detector:
//! for one run window, compare what the provider says it served against what the
//! gateway says it metered. Tokens the provider billed that the gateway never
//! saw are, by definition, tokens that did not traverse the governed path.
//!
//! ```text
//!   provider_tokens - gateway_tokens > tolerance   =>   TetherVerdict::Breached
//! ```
//!
//! ## What this slice lands
//!
//! The typed representation and the **seam** — [`RunUsageSource`] (implemented
//! twice: once over the gateway meter, once over a provider's usage/billing
//! API), [`TetherAuditor`] that joins them, and [`TetherReconciliation`] /
//! [`TetherVerdict`], the record an alarm, an audit row or a budget guard reads.
//! Wiring live provider-usage pulls (each provider's admin/usage API, with its
//! own attribution key and reporting lag) is deliberately NOT in this slice; the
//! honest posture is encoded in [`TetherVerdict::Unattested`], which is the
//! verdict every run gets until a provider source is actually connected. An
//! `Unattested` run is **not** evidence of a tethered run and must never be
//! reported as one.
//!
//! ## Fail-loud, not fail-open
//!
//! [`TetherVerdict::Unattested`] is a distinct verdict precisely so "we could not
//! check" can never be rendered as "we checked and it was fine". Callers that
//! must be conservative use [`TetherVerdict::is_proven_tethered`], which is
//! `true` only for [`TetherVerdict::Tethered`].

use std::{error::Error, fmt};

use crate::cloudflare_agent_memory::AgentInstanceIdentity;

/// Which side of the reconciliation a usage figure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageSource {
    /// FerroGate's own metering of traffic that traversed the governed path.
    GatewayMeter,
    /// The upstream provider's account-side usage/billing report.
    ProviderAccount,
}

impl UsageSource {
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::GatewayMeter => "gateway-meter",
            Self::ProviderAccount => "provider-account",
        }
    }
}

/// Token/request usage attributed to one run over one window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunTokenUsage {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl RunTokenUsage {
    pub fn new(requests: u64, input_tokens: u64, output_tokens: u64) -> Self {
        Self {
            requests,
            input_tokens,
            output_tokens,
        }
    }

    /// Total tokens (input + output), saturating.
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// The window a reconciliation covers. Half-open `[start, end)` in unix millis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TetherWindow {
    pub start_unix_millis: u64,
    pub end_unix_millis: u64,
}

impl TetherWindow {
    pub fn new(start_unix_millis: u64, end_unix_millis: u64) -> Self {
        Self {
            start_unix_millis,
            end_unix_millis,
        }
    }
}

/// Slack absorbed before a divergence is called a breach.
///
/// Real reconciliation is noisy for reasons that are NOT bypass: provider usage
/// APIs report on their own lag and rounding, a retried request can be billed
/// once and metered twice (or vice versa), and provider-side token counts differ
/// from gateway-side counts by the provider's own accounting of cached or
/// system-injected tokens. The tolerance must be small enough that a real bypass
/// (an entire conversation's worth of tokens) always clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TetherTolerance {
    pub request_slack: u64,
    pub token_slack: u64,
}

impl Default for TetherTolerance {
    fn default() -> Self {
        // Deliberately tight: one request / a few hundred tokens of accounting
        // noise, far below the size of any useful bypassed exchange.
        Self {
            request_slack: 1,
            token_slack: 512,
        }
    }
}

/// The outcome of one reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TetherVerdict {
    /// Provider-reported usage is within tolerance of gateway-metered usage:
    /// the run's traffic is accounted for on the governed path.
    Tethered,
    /// Provider usage could not be obtained (no source wired, provider reporting
    /// lag, source error). **Not** a pass — the run is simply unproven.
    Unattested { reason: String },
    /// The provider served materially more than the gateway metered. Those
    /// tokens did not traverse the governed path: metering, guardrails, the
    /// audit trail and the #428 spend cap all missed them.
    Breached {
        unmetered_requests: u64,
        unmetered_input_tokens: u64,
        unmetered_output_tokens: u64,
    },
}

impl TetherVerdict {
    /// `true` only for [`Self::Tethered`]. `Unattested` is never a pass.
    pub fn is_proven_tethered(&self) -> bool {
        matches!(self, Self::Tethered)
    }

    /// `true` when the tether is provably broken — the alarm condition.
    pub fn is_breach(&self) -> bool {
        matches!(self, Self::Breached { .. })
    }

    /// Stable label for logs, audit rows and alarm routing.
    pub fn class_label(&self) -> &'static str {
        match self {
            Self::Tethered => "tethered",
            Self::Unattested { .. } => "unattested",
            Self::Breached { .. } => "tether_breached",
        }
    }

    /// Severity for alarm routing: a breach is a security incident, an
    /// unattested run is an observability gap, a tethered run is informational.
    pub fn severity(&self) -> &'static str {
        match self {
            Self::Tethered => "info",
            Self::Unattested { .. } => "warn",
            Self::Breached { .. } => "critical",
        }
    }

    /// Total tokens the provider served that the gateway never metered.
    pub fn unmetered_tokens(&self) -> u64 {
        match self {
            Self::Breached {
                unmetered_input_tokens,
                unmetered_output_tokens,
                ..
            } => unmetered_input_tokens.saturating_add(*unmetered_output_tokens),
            _ => 0,
        }
    }
}

/// A durable, inspectable reconciliation record for one run window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TetherReconciliation {
    pub tenant_id: String,
    pub session_id: String,
    pub run_id: String,
    pub window: TetherWindow,
    pub gateway: RunTokenUsage,
    pub provider: Option<RunTokenUsage>,
    pub tolerance: TetherTolerance,
    pub verdict: TetherVerdict,
}

impl TetherReconciliation {
    /// One-line rendering for an alarm payload / log line.
    pub fn alarm_line(&self) -> String {
        format!(
            "container-tether {verdict} tenant={tenant} session={session} run={run} \
             gateway_tokens={gw} provider_tokens={pv} unmetered_tokens={un}",
            verdict = self.verdict.class_label(),
            tenant = self.tenant_id,
            session = self.session_id,
            run = self.run_id,
            gw = self.gateway.total_tokens(),
            pv = self
                .provider
                .map(|p| p.total_tokens().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            un = self.verdict.unmetered_tokens(),
        )
    }
}

/// Failure obtaining usage from one side of the reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TetherAuditError {
    /// The usage source failed (network, auth, quota, parse).
    Source {
        source: UsageSource,
        message: String,
    },
}

impl fmt::Display for TetherAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source { source, message } => write!(
                f,
                "tether audit usage source {} failed: {message}",
                source.as_wire()
            ),
        }
    }
}

impl Error for TetherAuditError {}

/// A source of per-run usage. Implemented once over FerroGate's own meter and
/// once per provider usage API — the seam that lets the two be compared without
/// this module knowing either shape.
///
/// `Ok(None)` means "this source has no figure for that run in that window" —
/// which for the provider side yields [`TetherVerdict::Unattested`], never a
/// pass.
pub trait RunUsageSource {
    fn usage_for_run(
        &self,
        identity: &AgentInstanceIdentity,
        window: &TetherWindow,
    ) -> Result<Option<RunTokenUsage>, TetherAuditError>;
}

/// Joins the gateway meter and a provider usage source into a verdict per run.
pub struct TetherAuditor<G: RunUsageSource, P: RunUsageSource> {
    gateway: G,
    provider: Option<P>,
    tolerance: TetherTolerance,
}

impl<G: RunUsageSource, P: RunUsageSource> TetherAuditor<G, P> {
    /// Build an auditor with both sides wired.
    pub fn new(gateway: G, provider: P) -> Self {
        Self {
            gateway,
            provider: Some(provider),
            tolerance: TetherTolerance::default(),
        }
    }

    /// Build an auditor with **no** provider source. Every run reconciles to
    /// [`TetherVerdict::Unattested`] — the honest state of the tier until a
    /// provider usage API is connected.
    pub fn gateway_only(gateway: G) -> Self {
        Self {
            gateway,
            provider: None,
            tolerance: TetherTolerance::default(),
        }
    }

    pub fn with_tolerance(mut self, tolerance: TetherTolerance) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Reconcile one run window.
    ///
    /// A gateway-side source error is propagated (never read as zero: zero
    /// gateway usage against real provider usage would be reported as a total
    /// bypass). A provider-side error degrades to `Unattested` carrying the
    /// reason — a provider outage must not manufacture a false breach, but it
    /// must not manufacture a pass either.
    pub fn audit(
        &self,
        identity: &AgentInstanceIdentity,
        window: &TetherWindow,
    ) -> Result<TetherReconciliation, TetherAuditError> {
        let gateway = self
            .gateway
            .usage_for_run(identity, window)?
            .unwrap_or_default();
        let (provider, unattested_reason) = match &self.provider {
            None => (
                None,
                Some("no provider usage source is wired for this tier".to_string()),
            ),
            Some(source) => match source.usage_for_run(identity, window) {
                Ok(Some(usage)) => (Some(usage), None),
                Ok(None) => (
                    None,
                    Some("provider reported no usage figure for this run window".to_string()),
                ),
                Err(err) => (None, Some(err.to_string())),
            },
        };
        let verdict = match (provider, unattested_reason) {
            (Some(provider), _) => verdict_for(&gateway, &provider, &self.tolerance),
            (None, Some(reason)) => TetherVerdict::Unattested { reason },
            (None, None) => TetherVerdict::Unattested {
                reason: "provider usage unavailable".to_string(),
            },
        };
        Ok(TetherReconciliation {
            tenant_id: identity.tenant_id.clone(),
            session_id: identity.session_id.clone(),
            run_id: identity.run_id.clone(),
            window: *window,
            gateway,
            provider,
            tolerance: self.tolerance,
            verdict,
        })
    }
}

/// Pure comparison: provider usage beyond gateway usage + tolerance is a breach.
///
/// Only an EXCESS on the provider side is a bypass. The reverse (gateway metered
/// more than the provider billed) is normal — guardrail-blocked requests, cached
/// responses and gateway-side retries are metered without ever reaching the
/// provider — so it is never reported as a tether failure.
pub fn verdict_for(
    gateway: &RunTokenUsage,
    provider: &RunTokenUsage,
    tolerance: &TetherTolerance,
) -> TetherVerdict {
    let excess = |provider: u64, gateway: u64, slack: u64| -> u64 {
        provider.saturating_sub(gateway).saturating_sub(slack)
    };
    let unmetered_requests = excess(provider.requests, gateway.requests, tolerance.request_slack);
    let unmetered_input = excess(
        provider.input_tokens,
        gateway.input_tokens,
        tolerance.token_slack,
    );
    let unmetered_output = excess(
        provider.output_tokens,
        gateway.output_tokens,
        tolerance.token_slack,
    );
    if unmetered_requests == 0 && unmetered_input == 0 && unmetered_output == 0 {
        TetherVerdict::Tethered
    } else {
        TetherVerdict::Breached {
            unmetered_requests,
            unmetered_input_tokens: unmetered_input,
            unmetered_output_tokens: unmetered_output,
        }
    }
}

/// A scripted [`RunUsageSource`] for tests and offline wiring.
#[derive(Debug, Default, Clone)]
pub struct ScriptedRunUsageSource {
    entries: Vec<(String, RunTokenUsage)>,
    failure: Option<(UsageSource, String)>,
}

impl ScriptedRunUsageSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record usage for a run id.
    pub fn with_run(mut self, run_id: impl Into<String>, usage: RunTokenUsage) -> Self {
        self.entries.push((run_id.into(), usage));
        self
    }

    /// Make every lookup fail, to exercise the degrade path.
    pub fn failing(mut self, source: UsageSource, message: impl Into<String>) -> Self {
        self.failure = Some((source, message.into()));
        self
    }
}

impl RunUsageSource for ScriptedRunUsageSource {
    fn usage_for_run(
        &self,
        identity: &AgentInstanceIdentity,
        _window: &TetherWindow,
    ) -> Result<Option<RunTokenUsage>, TetherAuditError> {
        if let Some((source, message)) = &self.failure {
            return Err(TetherAuditError::Source {
                source: *source,
                message: message.clone(),
            });
        }
        Ok(self
            .entries
            .iter()
            .find(|(run_id, _)| run_id == &identity.run_id)
            .map(|(_, usage)| *usage))
    }
}

#[cfg(test)]
#[path = "cloudflare_container_tether_audit_test.rs"]
mod tests;
