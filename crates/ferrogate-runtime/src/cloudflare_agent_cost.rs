// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: FerroGate-side per-agent/tenant cost-governance enforcement core for
//   Cloudflare-hosted agents (issue #428, slice A). CF exposes no per-agent spend cap, so
//   FerroGate owns usage->cost computation, budget evaluation, kill/throttle enforcement
//   through the #414 control surface, and a dispatch guard for the managed scheduler.

//! Cost-governance **enforcement core** for Cloudflare-hosted agents (issue
//! #428, slice A).
//!
//! Cloudflare provides **no per-agent spend cap**: a runaway agent (tight loop,
//! pathological SQLite scan, WebSocket flood) bills the account without limit.
//! FerroGate therefore owns usage/cost tracking and enforcement for the agents
//! it hosts on Cloudflare. This module is the self-contained, pure-where-possible
//! **enforcement engine**:
//!
//! 1. [`AgentRuntimeUsageSample`] — the CF cost drivers for one agent/run over a
//!    window (DO requests, GB-seconds duration, SQLite rows read/written, stored
//!    bytes, WebSocket inbound messages, plus the already-metered egress USD).
//! 2. [`CfRuntimeCostModel`] — pure USD cost from a sample using configurable CF
//!    pricing constants ([`CfRuntimePricing`]), broken out per resource class
//!    ([`CostBreakdown`]).
//! 3. [`AgentBudgetPolicy`] + [`evaluate`] — a per-agent/tenant cost ceiling with
//!    warn/degrade/kill thresholds, yielding a pure [`BudgetDecision`].
//! 4. [`AgentCostReceipt`] — the durable, inspectable "cost as an action receipt"
//!    per evaluation (attribution + breakdown + decision + audit reference).
//! 5. [`AgentCostGovernor`] — wires it together: compute cost, accumulate burn in
//!    an injected [`AgentBurnLedger`], evaluate, and on `Kill` destroy/cancel the
//!    over-budget run through the #414 [`CloudflareControlSurface`]; plus
//!    [`should_dispatch`], the guard the managed scheduler consults.
//!
//! ## Scope of this slice
//!
//! This is the **engine only**. The live-metrics pull (enabling Worker
//! `observability` and pulling DO/Workers metrics via CF GraphQL Analytics — see
//! [`AgentRuntimeUsageSource`]) and the admin-API / billing-surface **visibility**
//! are explicitly the follow-up slice / test gate's job. Usage numbers and the
//! budget ceiling are **inputs** to this engine (structs/traits defined here),
//! never reached out of the policy/storage crates.
//!
//! ## Attribution
//!
//! Cost is attributed on the FerroGate identity triple
//! [`AgentInstanceIdentity`] (`fg.{tenant_id}.{session_id}.{run_id}`), the same
//! key the per-instance memory module (#427) uses to address a Durable Object.
//! The kill-switch targets a run by that minted **instance name**, so destroying
//! an over-budget agent hits exactly the DO the identity names.

use std::collections::HashMap;
use std::sync::Arc;
use std::{error::Error, fmt};

use async_trait::async_trait;
use ferrogate_storage::RuntimeStorageRepositories;
use serde::{Deserialize, Serialize};

use crate::cloudflare_agent_memory::{AgentInstanceIdentity, AgentMemoryError};
use crate::cloudflare_worker::{CloudflareControlSurface, CloudflareControlSurfaceError};

// ---------------------------------------------------------------------------
// Pricing constants
// ---------------------------------------------------------------------------
//
// Defaults are the Cloudflare **Durable Objects (SQLite storage backend)**
// Workers-Paid list prices, the primitive a Cloudflare Agent runs on (one DO per
// named instance). Source: Cloudflare Durable Objects pricing,
// <https://developers.cloudflare.com/durable-objects/platform/pricing/> (as read
// 2026-07; free-tier inclusions are deliberately NOT modeled here — this engine
// prices marginal usage so a per-agent cap is conservative). All coefficients are
// overridable via [`CfRuntimePricing`] so a price change is config, not code.

/// Durable Object **requests**: $0.15 per million requests.
/// Source: CF Durable Objects pricing — Requests row.
pub const DEFAULT_DO_REQUEST_USD_PER_MILLION: f64 = 0.15;

/// Durable Object **active duration**: $12.50 per million GB-seconds of
/// wall-clock compute. Source: CF Durable Objects pricing — Duration row.
pub const DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS: f64 = 12.50;

/// SQLite **rows read**: $0.001 per million rows read.
/// Source: CF Durable Objects pricing (SQLite backend) — Rows read row.
pub const DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION: f64 = 0.001;

/// SQLite **rows written**: $1.00 per million rows written.
/// Source: CF Durable Objects pricing (SQLite backend) — Rows written row.
pub const DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION: f64 = 1.00;

/// SQLite **stored data**: $0.20 per GB-month at rest.
/// Source: CF Durable Objects pricing (SQLite backend) — Stored data row.
pub const DEFAULT_STORAGE_USD_PER_GB_MONTH: f64 = 0.20;

/// WebSocket billing ratio: **20 incoming WebSocket messages are billed as one
/// Durable Object request**. Source: CF Durable Objects pricing — "Incoming
/// WebSocket messages are counted as one request per 20 messages." Encoded so WS
/// pressure is priced at the DO-request rate divided by this ratio.
pub const WEBSOCKET_MESSAGES_PER_BILLED_REQUEST: f64 = 20.0;

/// Unit scale for the "per million" list prices.
pub const UNITS_PER_MILLION: f64 = 1_000_000.0;
/// Bytes per gigabyte (decimal GB, as Cloudflare meters stored data).
pub const BYTES_PER_GIGABYTE: f64 = 1_000_000_000.0;
/// Seconds in the 30-day billing month used to pro-rate the per-GB-month storage
/// price across a sample window.
pub const SECONDS_PER_BILLING_MONTH: f64 = 30.0 * 24.0 * 60.0 * 60.0;

/// Default fraction of the ceiling at which a budget starts to **throttle**
/// (warn). 80% of the hard cap.
pub const DEFAULT_WARN_FRACTION: f64 = 0.8;

// ---------------------------------------------------------------------------
// Usage sample
// ---------------------------------------------------------------------------

/// The Cloudflare cost drivers observed for one agent/run over a metering
/// window. Every field documents its unit. This is the **input** to
/// [`CfRuntimeCostModel`]; how it is obtained is behind
/// [`AgentRuntimeUsageSource`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeUsageSample {
    /// Durable Object requests in the window. Unit: **count of requests**.
    pub do_requests: u64,
    /// Wall-clock active compute. Unit: **GB-seconds** (allocated memory in GB
    /// multiplied by active seconds), matching the CF "duration" meter.
    pub duration_gb_seconds: f64,
    /// SQLite rows read by the instance in the window. Unit: **count of rows**.
    pub sqlite_rows_read: u64,
    /// SQLite rows written by the instance in the window. Unit: **count of
    /// rows**.
    pub sqlite_rows_written: u64,
    /// Bytes at rest in the instance's SQLite over the window. Unit: **bytes**.
    /// Priced against the per-GB-month rate, pro-rated by
    /// [`Self::stored_window_seconds`].
    pub stored_bytes: u64,
    /// Length of time the [`Self::stored_bytes`] were stored, i.e. the storage
    /// integration window. Unit: **seconds**. Lets the pure cost model turn a
    /// point-in-time byte count into a GB-month charge.
    pub stored_window_seconds: f64,
    /// Incoming WebSocket messages in the window. Unit: **count of messages**.
    /// Billed 20:1 as DO requests (see [`WEBSOCKET_MESSAGES_PER_BILLED_REQUEST`]).
    pub ws_inbound_messages: u64,
    /// Already-metered model/tool/MCP egress cost for the window, in **USD**,
    /// taken as a pre-computed input from the existing tethered-egress metering.
    /// This engine **passes it through** and does NOT recompute it.
    pub metered_egress_usd: f64,
}

impl AgentRuntimeUsageSample {
    /// An all-zero sample (no billable activity in the window).
    pub fn zero() -> Self {
        Self {
            do_requests: 0,
            duration_gb_seconds: 0.0,
            sqlite_rows_read: 0,
            sqlite_rows_written: 0,
            stored_bytes: 0,
            stored_window_seconds: 0.0,
            ws_inbound_messages: 0,
            metered_egress_usd: 0.0,
        }
    }
}

// ---------------------------------------------------------------------------
// Cost model
// ---------------------------------------------------------------------------

/// The overridable CF pricing coefficients. Defaults are the `DEFAULT_*`
/// constants above; a pricing change is a config edit, not a code edit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CfRuntimePricing {
    pub do_request_usd_per_million: f64,
    pub duration_usd_per_million_gb_seconds: f64,
    pub sqlite_rows_read_usd_per_million: f64,
    pub sqlite_rows_written_usd_per_million: f64,
    pub storage_usd_per_gb_month: f64,
    /// Incoming WebSocket messages counted as one DO request per this many
    /// messages (default [`WEBSOCKET_MESSAGES_PER_BILLED_REQUEST`]).
    pub websocket_messages_per_billed_request: f64,
}

impl Default for CfRuntimePricing {
    fn default() -> Self {
        Self {
            do_request_usd_per_million: DEFAULT_DO_REQUEST_USD_PER_MILLION,
            duration_usd_per_million_gb_seconds: DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS,
            sqlite_rows_read_usd_per_million: DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION,
            sqlite_rows_written_usd_per_million: DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION,
            storage_usd_per_gb_month: DEFAULT_STORAGE_USD_PER_GB_MONTH,
            websocket_messages_per_billed_request: WEBSOCKET_MESSAGES_PER_BILLED_REQUEST,
        }
    }
}

/// USD cost of one window, split by resource class. `total_usd` is the sum of
/// the per-class fields and is what a budget evaluates against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostBreakdown {
    pub do_requests_usd: f64,
    pub duration_usd: f64,
    pub sqlite_rows_read_usd: f64,
    pub sqlite_rows_written_usd: f64,
    pub storage_usd: f64,
    pub websocket_usd: f64,
    pub metered_egress_usd: f64,
    pub total_usd: f64,
}

/// Pure cost computation from an [`AgentRuntimeUsageSample`]. No I/O, no clock,
/// fully deterministic — the arithmetic is unit-tested on known inputs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CfRuntimeCostModel {
    pricing: CfRuntimePricing,
}

impl CfRuntimeCostModel {
    /// A model with the default CF list prices.
    pub fn new() -> Self {
        Self::default()
    }

    /// A model with custom pricing coefficients.
    pub fn with_pricing(pricing: CfRuntimePricing) -> Self {
        Self { pricing }
    }

    /// The pricing coefficients in effect.
    pub fn pricing(&self) -> &CfRuntimePricing {
        &self.pricing
    }

    /// The per-resource-class USD breakdown for a sample.
    pub fn breakdown(&self, sample: &AgentRuntimeUsageSample) -> CostBreakdown {
        let p = &self.pricing;

        let do_requests_usd =
            (sample.do_requests as f64 / UNITS_PER_MILLION) * p.do_request_usd_per_million;

        let duration_usd = (sample.duration_gb_seconds / UNITS_PER_MILLION)
            * p.duration_usd_per_million_gb_seconds;

        let sqlite_rows_read_usd = (sample.sqlite_rows_read as f64 / UNITS_PER_MILLION)
            * p.sqlite_rows_read_usd_per_million;

        let sqlite_rows_written_usd = (sample.sqlite_rows_written as f64 / UNITS_PER_MILLION)
            * p.sqlite_rows_written_usd_per_million;

        let storage_gb = sample.stored_bytes as f64 / BYTES_PER_GIGABYTE;
        let storage_month_fraction = sample.stored_window_seconds / SECONDS_PER_BILLING_MONTH;
        let storage_usd = storage_gb * storage_month_fraction * p.storage_usd_per_gb_month;

        // WebSocket 20:1 — inbound messages are priced at the DO-request rate
        // divided by the billing ratio.
        let ws_billed_requests =
            sample.ws_inbound_messages as f64 / p.websocket_messages_per_billed_request;
        let websocket_usd = (ws_billed_requests / UNITS_PER_MILLION) * p.do_request_usd_per_million;

        // Egress is a pass-through of the pre-metered USD; never recomputed.
        let metered_egress_usd = sample.metered_egress_usd;

        let total_usd = do_requests_usd
            + duration_usd
            + sqlite_rows_read_usd
            + sqlite_rows_written_usd
            + storage_usd
            + websocket_usd
            + metered_egress_usd;

        CostBreakdown {
            do_requests_usd,
            duration_usd,
            sqlite_rows_read_usd,
            sqlite_rows_written_usd,
            storage_usd,
            websocket_usd,
            metered_egress_usd,
            total_usd,
        }
    }

    /// Total USD cost of a sample (sum of the [`CostBreakdown`]).
    pub fn cost_usd(&self, sample: &AgentRuntimeUsageSample) -> f64 {
        self.breakdown(sample).total_usd
    }
}

// ---------------------------------------------------------------------------
// Budget policy + decision
// ---------------------------------------------------------------------------

/// A per-agent/tenant cost budget: a hard ceiling plus threshold fractions.
///
/// The `ceiling_usd` is an **input** to the engine. It is deliberately NOT
/// sourced from `ferrogate-policy` here: this crate does not depend on
/// `ferrogate-policy`, which keeps the pure burn/decision engine testable and
/// free of the control-plane resolution stack.
///
/// The control plane owns the ceiling as of #428 slice B-policy
/// (`ferrogate_policy::EffectiveQuota::agent_cost_budget_usd`, resolved
/// `min`-across-the-tenant-chain with a plan default), and the connector that
/// turns that quota into an `AgentBudgetPolicy` lives in the crate that depends
/// on both sides: `AppState::resolve_agent_budget_policy` in
/// `ferrogate-cli/src/state_quota_and_policy.rs`. It returns `None` when no
/// budget is configured, so an unbudgeted tenant constructs no governor at all
/// rather than a zero ceiling. Callers hand the resulting policy to this engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBudgetPolicy {
    /// Hard spend cap for the budget window, in USD. Burn at or above this is a
    /// [`BudgetDecision::Kill`].
    pub ceiling_usd: f64,
    /// Fraction of `ceiling_usd` at which the budget begins to **throttle**
    /// (warn). Burn in `[warn, degrade)` (or `[warn, ceiling)` when no degrade
    /// tier) is a [`BudgetDecision::Throttle`].
    pub warn_fraction: f64,
    /// Optional intermediate tier: fraction of `ceiling_usd` at which the budget
    /// escalates from throttle to **degrade** (reduce effect rather than merely
    /// slow dispatch). When `Some(f)`, expected `warn_fraction <= f <= 1.0`, and
    /// burn in `[f*ceiling, ceiling)` is a [`BudgetDecision::Degrade`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degrade_fraction: Option<f64>,
    /// Opaque version tag of the policy that produced a decision, carried onto
    /// every [`AgentCostReceipt`] for audit.
    pub policy_version: String,
}

impl AgentBudgetPolicy {
    /// A policy with a hard ceiling, the [`DEFAULT_WARN_FRACTION`] throttle
    /// threshold, and no degrade tier.
    pub fn new(ceiling_usd: f64, policy_version: impl Into<String>) -> Self {
        Self {
            ceiling_usd,
            warn_fraction: DEFAULT_WARN_FRACTION,
            degrade_fraction: None,
            policy_version: policy_version.into(),
        }
    }

    /// Override the throttle (warn) fraction.
    pub fn with_warn_fraction(mut self, warn_fraction: f64) -> Self {
        self.warn_fraction = warn_fraction;
        self
    }

    /// Add an intermediate degrade tier at `degrade_fraction` of the ceiling.
    pub fn with_degrade_fraction(mut self, degrade_fraction: f64) -> Self {
        self.degrade_fraction = Some(degrade_fraction);
        self
    }

    /// The absolute USD burn at which throttling begins.
    pub fn warn_threshold_usd(&self) -> f64 {
        self.ceiling_usd * self.warn_fraction
    }

    /// The absolute USD burn at which degrade begins, if a degrade tier is set.
    pub fn degrade_threshold_usd(&self) -> Option<f64> {
        self.degrade_fraction.map(|f| self.ceiling_usd * f)
    }

    /// Validate the policy shape: positive ceiling, `0 < warn_fraction <= 1`, and
    /// (when set) `warn_fraction <= degrade_fraction <= 1`.
    pub fn validate(&self) -> Result<(), CostGovernorError> {
        if self.ceiling_usd <= 0.0 {
            return Err(CostGovernorError::InvalidPolicy(
                "ceiling_usd must be positive".to_string(),
            ));
        }
        if self.warn_fraction <= 0.0 || self.warn_fraction > 1.0 {
            return Err(CostGovernorError::InvalidPolicy(
                "warn_fraction must be in (0, 1]".to_string(),
            ));
        }
        if let Some(f) = self.degrade_fraction {
            if f < self.warn_fraction || f > 1.0 {
                return Err(CostGovernorError::InvalidPolicy(
                    "degrade_fraction must be in [warn_fraction, 1]".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// The pure enforcement decision for a budget evaluation. Mirrors the severity
/// ladder Allow < Throttle < Degrade < Kill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum BudgetDecision {
    /// Under the warn threshold — the run may proceed and new dispatch is
    /// allowed.
    Allow,
    /// At/above warn but under the next tier — slow / halt new dispatch, but do
    /// not tear the run down.
    Throttle { reason: String },
    /// At/above the degrade tier but under the ceiling — the run proceeds with
    /// reduced effect (e.g. cheaper model / fewer tools). Consistent with
    /// [`crate::ActionDecision::Degrade`].
    Degrade { reason: String },
    /// At/above the hard ceiling — tear the run down (destroy or cancel).
    Kill { reason: String },
}

impl BudgetDecision {
    /// The compact snake_case class label, identical to the serde `decision`
    /// tag.
    pub fn class_label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Throttle { .. } => "throttle",
            Self::Degrade { .. } => "degrade",
            Self::Kill { .. } => "kill",
        }
    }

    /// Whether this decision permits **new** dispatch. Only [`Self::Allow`] does:
    /// any budget pressure (throttle/degrade/kill) refuses a new run — this is
    /// the halt-dispatch flag [`should_dispatch`] reads.
    pub fn permits_dispatch(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Whether this decision tears the run down (kill).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Kill { .. })
    }

    /// The human-readable reason, if any (`Allow` carries none).
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Throttle { reason } | Self::Degrade { reason } | Self::Kill { reason } => {
                Some(reason)
            }
        }
    }
}

/// Pure budget evaluation: project the burn (`accumulated_burn_usd +
/// this_window_cost_usd`) and classify it against the policy thresholds.
///
/// Boundaries are **inclusive at the more severe tier**: burn exactly at the
/// ceiling is a `Kill`, exactly at the degrade threshold is a `Degrade`, exactly
/// at the warn threshold is a `Throttle`.
pub fn evaluate(
    policy: &AgentBudgetPolicy,
    accumulated_burn_usd: f64,
    this_window_cost_usd: f64,
) -> BudgetDecision {
    let projected = accumulated_burn_usd + this_window_cost_usd;
    let ceiling = policy.ceiling_usd;

    if projected >= ceiling {
        return BudgetDecision::Kill {
            reason: format!(
                "projected burn ${projected:.4} reached hard ceiling ${ceiling:.4} \
                 (policy {})",
                policy.policy_version
            ),
        };
    }
    if let Some(degrade_threshold) = policy.degrade_threshold_usd() {
        if projected >= degrade_threshold {
            return BudgetDecision::Degrade {
                reason: format!(
                    "projected burn ${projected:.4} reached degrade threshold \
                     ${degrade_threshold:.4} of ceiling ${ceiling:.4} (policy {})",
                    policy.policy_version
                ),
            };
        }
    }
    let warn_threshold = policy.warn_threshold_usd();
    if projected >= warn_threshold {
        return BudgetDecision::Throttle {
            reason: format!(
                "projected burn ${projected:.4} reached warn threshold \
                 ${warn_threshold:.4} of ceiling ${ceiling:.4} (policy {})",
                policy.policy_version
            ),
        };
    }
    BudgetDecision::Allow
}

// ---------------------------------------------------------------------------
// Cost receipt
// ---------------------------------------------------------------------------

/// A serializable projection of the [`AgentInstanceIdentity`] attribution key,
/// carried on a receipt so the durable artifact is self-describing. Derived from
/// the identity triple plus its minted `fg.{tenant}.{session}.{run}` instance
/// name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCostAttribution {
    pub tenant_id: String,
    pub session_id: String,
    pub run_id: String,
    /// The minted Durable Object instance name the kill-switch addresses.
    pub instance_name: String,
}

impl AgentCostAttribution {
    /// Project an [`AgentInstanceIdentity`], validating + minting its instance
    /// name (so an invalid triple is rejected before a receipt is built).
    pub fn from_identity(identity: &AgentInstanceIdentity) -> Result<Self, CostGovernorError> {
        let instance_name = identity.instance_name()?;
        Ok(Self {
            tenant_id: identity.tenant_id.clone(),
            session_id: identity.session_id.clone(),
            run_id: identity.run_id.clone(),
            instance_name,
        })
    }
}

/// "Cost as an action receipt": the durable, inspectable record of one budget
/// evaluation. Assembled by [`AgentCostGovernor::enforce`] (or directly via
/// [`AgentCostReceipt::assemble`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentCostReceipt {
    /// Who/what the cost is attributed to (identity triple + instance name).
    pub attribution: AgentCostAttribution,
    /// The raw cost drivers this receipt priced.
    pub sample: AgentRuntimeUsageSample,
    /// The per-resource-class USD breakdown.
    pub breakdown: CostBreakdown,
    /// Cost of this window (equals `breakdown.total_usd`).
    pub this_window_cost_usd: f64,
    /// Accumulated burn AFTER folding in this window.
    pub accumulated_burn_usd: f64,
    /// Version of the budget policy that produced [`Self::decision`].
    pub policy_version: String,
    /// Whether a budget threshold was crossed (i.e. the decision is not
    /// `Allow`).
    pub threshold_crossed: bool,
    /// The enforcement decision.
    pub decision: BudgetDecision,
    /// Reference to the emitted cost/enforcement audit event.
    pub audit_event_ref: String,
}

impl AgentCostReceipt {
    /// Assemble a receipt from the pieces of one evaluation. `accumulated_burn_usd`
    /// is the burn total *after* this window has been folded in. Fails only if the
    /// identity triple cannot be minted into an instance name.
    pub fn assemble(
        identity: &AgentInstanceIdentity,
        sample: &AgentRuntimeUsageSample,
        breakdown: &CostBreakdown,
        accumulated_burn_usd: f64,
        policy: &AgentBudgetPolicy,
        decision: BudgetDecision,
    ) -> Result<Self, CostGovernorError> {
        let attribution = AgentCostAttribution::from_identity(identity)?;
        let audit_event_ref = format!(
            "cost.enforcement.{}.{}",
            attribution.instance_name,
            decision.class_label()
        );
        Ok(Self {
            threshold_crossed: !decision.permits_dispatch() || decision.is_terminal(),
            attribution,
            sample: sample.clone(),
            this_window_cost_usd: breakdown.total_usd,
            breakdown: breakdown.clone(),
            accumulated_burn_usd,
            policy_version: policy.policy_version.clone(),
            decision,
            audit_event_ref,
        })
    }
}

// ---------------------------------------------------------------------------
// Burn ledger
// ---------------------------------------------------------------------------

/// A failure from a [`AgentBurnLedger`] backend.
///
/// Carried so the enforce path can **fail closed**: a durable-store read/write
/// failure is propagated (folded into [`CostGovernorError::Ledger`]) rather than
/// being silently treated as zero burn — an over-budget agent whose ledger
/// errors must NOT be allowed to keep spending.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentBurnLedgerError {
    /// The durable burn store failed to read or write. Carries the underlying
    /// storage failure rendered as a message (kept as a `String` so this crate's
    /// error type does not leak the storage error's concrete type).
    Storage(String),
}

impl fmt::Display for AgentBurnLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(m) => write!(f, "agent burn ledger storage failure: {m}"),
        }
    }
}

impl Error for AgentBurnLedgerError {}

/// The store of accumulated per-agent burn the governor consults and updates.
///
/// The in-memory [`InMemoryAgentBurnLedger`] backs unit tests / single-process
/// use; [`StorageAgentBurnLedger`] is the **durable**, atomically-accumulating
/// backend over the landed `ferrogate-storage` per-agent burn facade (#428 slice
/// B). Both fit this one abstraction.
///
/// `async` + `Result` so a durable (DB-backed) backend that does fallible I/O
/// shares the same trait as the pure in-memory map; the in-memory impl simply
/// wraps its infallible logic in `Ok(..)`.
#[async_trait]
pub trait AgentBurnLedger {
    /// Current accumulated burn (USD) for the identity; `Ok(0.0)` if unseen. An
    /// `Err` is a store failure — the caller must fail closed, never read it as
    /// zero burn.
    async fn get(&self, identity: &AgentInstanceIdentity) -> Result<f64, AgentBurnLedgerError>;
    /// Fold `cost_usd` into the identity's burn and return the new total (or a
    /// store failure).
    async fn add(
        &mut self,
        identity: &AgentInstanceIdentity,
        cost_usd: f64,
    ) -> Result<f64, AgentBurnLedgerError>;
}

/// Ledger key: the identity triple. Injective by construction (the same property
/// the instance-name minting relies on) and always available, even for a triple
/// that would fail instance-name validation.
fn ledger_key(identity: &AgentInstanceIdentity) -> (String, String, String) {
    (
        identity.tenant_id.clone(),
        identity.session_id.clone(),
        identity.run_id.clone(),
    )
}

/// An in-memory [`AgentBurnLedger`] for tests and single-process use.
#[derive(Debug, Default, Clone)]
pub struct InMemoryAgentBurnLedger {
    burn: HashMap<(String, String, String), f64>,
}

impl InMemoryAgentBurnLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AgentBurnLedger for InMemoryAgentBurnLedger {
    async fn get(&self, identity: &AgentInstanceIdentity) -> Result<f64, AgentBurnLedgerError> {
        Ok(self.burn.get(&ledger_key(identity)).copied().unwrap_or(0.0))
    }

    async fn add(
        &mut self,
        identity: &AgentInstanceIdentity,
        cost_usd: f64,
    ) -> Result<f64, AgentBurnLedgerError> {
        let entry = self.burn.entry(ledger_key(identity)).or_insert(0.0);
        *entry += cost_usd;
        Ok(*entry)
    }
}

/// A **durable** [`AgentBurnLedger`] over the landed `ferrogate-storage` atomic
/// per-agent burn facade
/// ([`RuntimeStorageRepositories::add_agent_burn`]/`get_agent_burn`, #428 slice
/// B-storage). A per-agent budget survives a restart, and concurrent adds for
/// one key can never lose an increment (the storage upsert accumulates and
/// returns the new total in one atomic statement).
///
/// ## Identity → `(tenant_id, agent_key, period)` attribution
///
/// - `tenant_id` = the identity's [`AgentInstanceIdentity::tenant_id`].
/// - `agent_key` = the identity's **[`AgentInstanceIdentity::session_id`]** — the
///   STABLE per-agent identity, deliberately **NOT** the ephemeral `run_id`. A
///   per-agent budget must fold **every run** of the same agent within a `period`
///   into one accumulating total; keying on the session/agent component does
///   exactly that, whereas keying on the per-run id would give each run its own
///   untethered budget and defeat the cap. (The durable store documents the same
///   choice for its `agent_key` column.)
/// - `period` = an **injected** billing-window string (the storage layer reuses
///   the `YYYY-MM` convention). It is supplied at construction so the ledger is
///   deterministic and never reaches for a wall clock behind the caller's back —
///   the injection seam the scheduler slice fills with the live period.
pub struct StorageAgentBurnLedger {
    repos: Arc<RuntimeStorageRepositories>,
    period: String,
}

impl StorageAgentBurnLedger {
    /// Build a durable ledger over `repos`, attributing all burn to `period` (a
    /// `YYYY-MM` billing window). `period` is injected — not read from a clock —
    /// so enforcement is deterministic and unit-testable.
    pub fn new(repos: Arc<RuntimeStorageRepositories>, period: impl Into<String>) -> Self {
        Self {
            repos,
            period: period.into(),
        }
    }

    /// The billing period this ledger attributes burn to.
    pub fn period(&self) -> &str {
        &self.period
    }

    /// The `(tenant_id, agent_key)` the identity attributes burn to: tenant is
    /// the identity's tenant; `agent_key` is the stable `session_id` (see the
    /// type docs for why it is the agent component, not the per-run id).
    fn attribution(identity: &AgentInstanceIdentity) -> (&str, &str) {
        (identity.tenant_id.as_str(), identity.session_id.as_str())
    }
}

#[async_trait]
impl AgentBurnLedger for StorageAgentBurnLedger {
    async fn get(&self, identity: &AgentInstanceIdentity) -> Result<f64, AgentBurnLedgerError> {
        let (tenant_id, agent_key) = Self::attribution(identity);
        match self
            .repos
            .get_agent_burn(tenant_id, agent_key, &self.period)
            .await
        {
            // Unseen (no durable row yet) == zero burn.
            Ok(None) => Ok(0.0),
            Ok(Some(total)) => Ok(total),
            // Fail closed: a store read failure is an error, NOT zero burn.
            Err(e) => Err(AgentBurnLedgerError::Storage(e.to_string())),
        }
    }

    async fn add(
        &mut self,
        identity: &AgentInstanceIdentity,
        cost_usd: f64,
    ) -> Result<f64, AgentBurnLedgerError> {
        let (tenant_id, agent_key) = Self::attribution(identity);
        self.repos
            .add_agent_burn(tenant_id, agent_key, &self.period, cost_usd)
            .await
            .map_err(|e| AgentBurnLedgerError::Storage(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Usage source
// ---------------------------------------------------------------------------

/// A closed-open metering window `[start, end)` in Unix milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostWindow {
    pub start_unix_millis: u64,
    pub end_unix_millis: u64,
}

impl CostWindow {
    pub fn new(start_unix_millis: u64, end_unix_millis: u64) -> Self {
        Self {
            start_unix_millis,
            end_unix_millis,
        }
    }

    /// Window length in seconds (saturating; never negative).
    pub fn duration_seconds(&self) -> f64 {
        self.end_unix_millis.saturating_sub(self.start_unix_millis) as f64 / 1000.0
    }
}

/// Obtains an [`AgentRuntimeUsageSample`] for an agent/window.
///
/// The **live** implementation — enabling the gateway Worker's `observability`
/// and pulling Durable Object / Workers metrics via Cloudflare's GraphQL
/// Analytics API — is deliberately **out of scope for this slice**: it is
/// gate-owned / slice B. This trait is the seam that live client plugs into; the
/// scripted [`ScriptedUsageSource`] backs unit tests with no network.
#[async_trait]
pub trait AgentRuntimeUsageSource {
    async fn usage_for(
        &self,
        identity: &AgentInstanceIdentity,
        window: CostWindow,
    ) -> Result<AgentRuntimeUsageSample, CostGovernorError>;
}

/// A scripted [`AgentRuntimeUsageSource`] for tests: returns a per-identity
/// sample (or a default), recording the windows it was queried for. No network.
#[derive(Debug, Default, Clone)]
pub struct ScriptedUsageSource {
    default_sample: Option<AgentRuntimeUsageSample>,
    by_run: HashMap<String, AgentRuntimeUsageSample>,
}

impl ScriptedUsageSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `sample` for any identity that has no more specific scripting.
    pub fn with_default(mut self, sample: AgentRuntimeUsageSample) -> Self {
        self.default_sample = Some(sample);
        self
    }

    /// Return `sample` for the given `run_id`.
    pub fn with_run_sample(
        mut self,
        run_id: impl Into<String>,
        sample: AgentRuntimeUsageSample,
    ) -> Self {
        self.by_run.insert(run_id.into(), sample);
        self
    }
}

#[async_trait]
impl AgentRuntimeUsageSource for ScriptedUsageSource {
    async fn usage_for(
        &self,
        identity: &AgentInstanceIdentity,
        _window: CostWindow,
    ) -> Result<AgentRuntimeUsageSample, CostGovernorError> {
        if let Some(sample) = self.by_run.get(&identity.run_id) {
            return Ok(sample.clone());
        }
        self.default_sample.clone().ok_or_else(|| {
            CostGovernorError::Usage(format!(
                "no scripted usage sample for run {:?}",
                identity.run_id
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// How the governor tears down an over-budget run on a [`BudgetDecision::Kill`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KillMode {
    /// `this.destroy()` — the hard kill ([`CloudflareControlSurface::cleanup_run`]).
    #[default]
    Destroy,
    /// Fiber-cancel — a softer stop that aborts in-flight work
    /// ([`CloudflareControlSurface::cancel_run`]) but leaves the instance.
    Cancel,
}

/// Failure surfaced by the cost-governance engine.
#[derive(Debug, Clone, PartialEq)]
pub enum CostGovernorError {
    /// The identity triple cannot be minted into a safe instance name.
    InvalidIdentity(AgentMemoryError),
    /// The budget policy is malformed.
    InvalidPolicy(String),
    /// A control-surface call (kill/cancel) failed.
    Control(CloudflareControlSurfaceError),
    /// Obtaining a usage sample failed.
    Usage(String),
    /// The burn ledger (durable store) failed. **Fail closed**: enforcement
    /// propagates this rather than treating the failure as zero burn, so an
    /// over-budget agent whose ledger read/write fails is NOT allowed to keep
    /// spending.
    Ledger(AgentBurnLedgerError),
}

impl fmt::Display for CostGovernorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(e) => {
                write!(f, "invalid agent identity for cost governance: {e}")
            }
            Self::InvalidPolicy(m) => write!(f, "invalid budget policy: {m}"),
            Self::Control(e) => write!(f, "cost-governance enforcement control call failed: {e}"),
            Self::Usage(m) => write!(f, "agent runtime usage source failed: {m}"),
            Self::Ledger(e) => write!(f, "cost-governance burn ledger failed: {e}"),
        }
    }
}

impl Error for CostGovernorError {}

impl From<AgentBurnLedgerError> for CostGovernorError {
    fn from(error: AgentBurnLedgerError) -> Self {
        Self::Ledger(error)
    }
}

impl From<AgentMemoryError> for CostGovernorError {
    fn from(error: AgentMemoryError) -> Self {
        Self::InvalidIdentity(error)
    }
}

impl From<CloudflareControlSurfaceError> for CostGovernorError {
    fn from(error: CloudflareControlSurfaceError) -> Self {
        Self::Control(error)
    }
}

/// The enforcement engine: prices a window, accumulates burn, evaluates the
/// budget, and — on `Kill` — tears the run down through the #414
/// [`CloudflareControlSurface`]. Generic over the control surface `C` and the
/// burn ledger `L` so it is fully unit-testable against the in-memory ledger and
/// the [`crate::MockCloudflareControlSurface`].
pub struct AgentCostGovernor<C: CloudflareControlSurface, L: AgentBurnLedger> {
    cost_model: CfRuntimeCostModel,
    policy: AgentBudgetPolicy,
    ledger: L,
    control: C,
    kill_mode: KillMode,
}

impl<C: CloudflareControlSurface, L: AgentBurnLedger> AgentCostGovernor<C, L> {
    /// Build a governor with the default [`KillMode::Destroy`] kill behavior.
    pub fn new(
        cost_model: CfRuntimeCostModel,
        policy: AgentBudgetPolicy,
        ledger: L,
        control: C,
    ) -> Self {
        Self {
            cost_model,
            policy,
            ledger,
            control,
            kill_mode: KillMode::Destroy,
        }
    }

    /// Choose whether a kill destroys (`this.destroy()`) or cancels (fiber
    /// cancel) the over-budget run.
    pub fn with_kill_mode(mut self, kill_mode: KillMode) -> Self {
        self.kill_mode = kill_mode;
        self
    }

    /// The budget policy in effect.
    pub fn policy(&self) -> &AgentBudgetPolicy {
        &self.policy
    }

    /// The cost model in effect.
    pub fn cost_model(&self) -> &CfRuntimeCostModel {
        &self.cost_model
    }

    /// Borrow the burn ledger (tests inspect accumulated burn through this).
    pub fn ledger(&self) -> &L {
        &self.ledger
    }

    /// Borrow the control surface (tests inspect recorded calls through this).
    pub fn control(&self) -> &C {
        &self.control
    }

    /// Whether a NEW run for `identity` may be dispatched under the current
    /// accumulated burn. Delegates to the free [`should_dispatch`] guard.
    ///
    /// `async` + `Result` because the burn read is now fallible (durable
    /// ledgers). A ledger error is **propagated** (fail closed) — the caller
    /// treats both `Ok(false)` and `Err(_)` as "do not dispatch".
    pub async fn should_dispatch(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<bool, CostGovernorError> {
        should_dispatch(&self.ledger, &self.policy, identity).await
    }

    /// Enforce the budget for one usage window of `identity`.
    ///
    /// Computes the window cost, evaluates the budget against the burn *before*
    /// this window, folds the window into the ledger, and — when the decision is
    /// [`BudgetDecision::Kill`] — tears the run down through the control surface
    /// (destroy or cancel per [`KillMode`]) addressing the run by its minted
    /// instance name. A `Throttle`/`Degrade` performs no control call: the
    /// accumulated burn now recorded in the ledger IS the halt-dispatch flag that
    /// [`Self::should_dispatch`] reads. Returns the durable [`AgentCostReceipt`].
    ///
    /// `async` so slice B can swap in a durable (DB-backed) ledger or an async
    /// control surface without changing callers.
    pub async fn enforce(
        &mut self,
        identity: &AgentInstanceIdentity,
        sample: AgentRuntimeUsageSample,
    ) -> Result<AgentCostReceipt, CostGovernorError> {
        // Validate + mint the instance name up front so the kill-switch (and the
        // receipt) address exactly the DO the identity names.
        let instance_name = identity.instance_name()?;

        let breakdown = self.cost_model.breakdown(&sample);
        let window_cost = breakdown.total_usd;

        // Fail closed: a ledger read/write failure propagates as
        // `CostGovernorError::Ledger` (via `?`) BEFORE any budget decision, kill
        // control call, or receipt — a storage error is never silently treated
        // as zero burn, so an over-budget agent whose ledger errors cannot slip
        // through as `Allow`.
        let prior_burn = self.ledger.get(identity).await?;
        let decision = evaluate(&self.policy, prior_burn, window_cost);

        // Record the burn regardless of decision — it happened.
        let accumulated_burn = self.ledger.add(identity, window_cost).await?;

        if let BudgetDecision::Kill { reason } = &decision {
            match self.kill_mode {
                KillMode::Destroy => {
                    self.control.cleanup_run(&instance_name)?;
                }
                KillMode::Cancel => {
                    self.control.cancel_run(&instance_name, reason)?;
                }
            }
        }

        AgentCostReceipt::assemble(
            identity,
            &sample,
            &breakdown,
            accumulated_burn,
            &self.policy,
            decision,
        )
    }

    /// Pull a usage sample from `source` for `window`, then [`Self::enforce`] it.
    /// Ties the [`AgentRuntimeUsageSource`] seam to enforcement; the live source
    /// is slice B.
    pub async fn enforce_from_source<S>(
        &mut self,
        identity: &AgentInstanceIdentity,
        window: CostWindow,
        source: &S,
    ) -> Result<AgentCostReceipt, CostGovernorError>
    where
        S: AgentRuntimeUsageSource + Sync + ?Sized,
    {
        let sample = source.usage_for(identity, window).await?;
        self.enforce(identity, sample).await
    }
}

/// The dispatch guard the [`crate::ManagedWorkerScheduler`] consults before
/// dispatching a new run: returns `Ok(true)` only when the identity's
/// accumulated burn still evaluates to [`BudgetDecision::Allow`]. Any
/// throttle/degrade/kill pressure refuses the new dispatch. Reads the ledger and
/// evaluates the policy with a zero incremental cost.
///
/// A ledger error is **propagated** (fail closed) rather than swallowed into a
/// zero burn: the scheduler treats both `Ok(false)` and `Err(_)` as "do not
/// dispatch", so a store outage can never let an over-budget run through.
pub async fn should_dispatch<L: AgentBurnLedger>(
    ledger: &L,
    policy: &AgentBudgetPolicy,
    identity: &AgentInstanceIdentity,
) -> Result<bool, CostGovernorError> {
    let burn = ledger.get(identity).await?;
    Ok(evaluate(policy, burn, 0.0).permits_dispatch())
}

/// Object-safe dispatch guard the [`crate::ManagedWorkerScheduler`] consults
/// before provisioning a new run.
///
/// Decouples the scheduler from the [`AgentCostGovernor`]'s `<C, L>` generics: a
/// live governor is handed to the scheduler as an `Arc<dyn AgentDispatchGuard>`,
/// so the scheduler enforces cost governance without naming the control surface
/// or ledger types.
///
/// The contract is **fail closed** by convention — the scheduler treats both
/// `Ok(false)` (over budget) and `Err(_)` (ledger/store failure) as "do not
/// dispatch"; only `Ok(true)` permits a new run.
#[async_trait]
pub trait AgentDispatchGuard: Send + Sync {
    /// `Ok(true)` = allow dispatch; `Ok(false)` = over budget, refuse; `Err` =
    /// fail closed (refuse).
    async fn allow_dispatch(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<bool, CostGovernorError>;
}

/// The live governor is a dispatch guard: `allow_dispatch` delegates to
/// [`AgentCostGovernor::should_dispatch`], which reads the burn ledger and
/// evaluates the budget with a zero incremental cost (any throttle/degrade/kill
/// pressure — or a ledger error — refuses the dispatch).
#[async_trait]
impl<C, L> AgentDispatchGuard for AgentCostGovernor<C, L>
where
    C: CloudflareControlSurface + Send + Sync,
    L: AgentBurnLedger + Send + Sync,
{
    async fn allow_dispatch(
        &self,
        identity: &AgentInstanceIdentity,
    ) -> Result<bool, CostGovernorError> {
        self.should_dispatch(identity).await
    }
}

#[cfg(test)]
#[path = "cloudflare_agent_cost_test.rs"]
mod tests;
