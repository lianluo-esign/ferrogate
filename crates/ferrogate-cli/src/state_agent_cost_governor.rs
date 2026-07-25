// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Product wiring for the #428 agent cost governor -- construct the
// AgentCostGovernor from the control-plane-resolved per-tenant ceiling plus the
// durable per-agent burn ledger, and consult it at agent-run admission so a
// budget breach actually halts dispatch.

//! Agent-run cost governance, wired into product flow (issue #428).
//!
//! Every piece of the cost-governance machinery already existed and was tested
//! -- the cost model + decision engine + kill switch (slice A), the durable
//! atomically-accumulating burn ledger
//! ([`ferrogate_storage::RuntimeStorageRepositories::add_agent_burn`] /
//! `get_agent_burn`, slice B-storage), the fail-closed
//! [`StorageAgentBurnLedger`] over it (slice B-runtime), and the per-tenant
//! ceiling resolved by [`AppState::resolve_agent_budget_policy`] (slice
//! B-policy) -- but **nothing constructed or invoked the governor**, so a budget
//! breach halted nothing. This module is the missing connector: it builds the
//! governor for a tenant that has a configured budget and consults it at agent
//! run admission.
//!
//! ## Default-off is load bearing
//!
//! [`AppState::resolve_agent_budget_policy`] returns `Ok(None)` when NO agent
//! budget is configured anywhere in the tenant/project/workspace/key chain (or
//! its plan default). In that case this module constructs **no governor at all**
//! and performs **no ledger read**, and [`AgentRunAdmission::Unbudgeted`] leaves
//! the caller on exactly the pre-#428 code path. An absent budget must never be
//! turned into a `0.0` ceiling -- that is an instant `BudgetDecision::Kill` for
//! every run on every unbudgeted tenant.
//!
//! ## Fail closed
//!
//! Once a budget IS configured, every way of *not knowing* the answer refuses
//! dispatch rather than admitting it:
//!
//! - a burn-ledger/durable-store failure surfaces as
//!   [`CostGovernorError::Ledger`] and refuses (never read as zero burn);
//! - a configured-but-unusable ceiling (non-finite/negative/zero) is an `Err`
//!   from the resolver and refuses (never silently collapsed to "unbudgeted",
//!   which would be an unbounded-spend hole);
//! - any budget pressure at all -- throttle, degrade or kill -- refuses a NEW
//!   run ([`ferrogate_runtime::BudgetDecision::permits_dispatch`] is true only
//!   for `Allow`).

use super::*;

use ferrogate_runtime::{
    AgentCostGovernor, AgentDispatchGuard, AgentInstanceIdentity, CfRuntimeCostModel,
    CloudflareControlSurface, CloudflareControlSurfaceError, CloudflareRunExecOutcome,
    CloudflareRunExecRequest, CloudflareRunHandle, CloudflareRunStartRequest, CloudflareRunStatus,
    CostGovernorError, StorageAgentBurnLedger,
};

/// The `agent_key` (the STABLE per-agent component of the identity triple, the
/// one the durable burn ledger accumulates against) recorded for a run whose
/// request carries no api-key identity. A literal rather than an empty string so
/// unattributed runs of one tenant still share ONE burn row instead of silently
/// keying on `""`, and so the value is legible on
/// `GET /admin/v1/agent-cost-burn`.
pub(crate) const UNATTRIBUTED_AGENT_KEY: &str = "unattributed";

/// The `tenant_id` component used when a request carries no organization.
/// Matches the `"quota:unscoped:unknown"` fallback
/// [`AppState::resolve_agent_budget_policy`] stamps into `policy_version`, so
/// the burn row and the policy version agree about what they are attributing.
pub(crate) const UNKNOWN_TENANT_ID: &str = "unknown";

/// The [`CloudflareControlSurface`] the gateway's own agent-run admission path
/// hands the governor.
///
/// `POST /v1/agent-runs` runs the agent through the in-process
/// [`ferrogate_runtime::AgentHarness`] (or an operator-configured external
/// provider process). There is **no Cloudflare-hosted Durable Object behind it**
/// and the operator config carries no deployed agent-gateway Worker address, so
/// at admission there is literally nothing to `this.destroy()`: the halt
/// FerroGate can perform here is refusing to start the run, which
/// [`AppState::admit_agent_run`] does.
///
/// Every verb therefore returns [`CloudflareControlSurfaceError::NotReady`]
/// instead of a fabricated success. If an `enforce` loop ever reached the kill
/// switch through this surface it fails loudly as
/// [`CostGovernorError::Control`] rather than reporting a `destroy()` that never
/// happened -- the "never fake a zero" rule applied to the kill switch.
/// [`AgentDispatchGuard::allow_dispatch`] (the admission call) reads only the
/// burn ledger and never touches the control surface, so admission is
/// unaffected. A deployment that hosts its agents on Cloudflare passes
/// [`ferrogate_runtime::WorkerGatewayControlSurface`] to
/// [`AppState::agent_cost_governor`] instead; the constructor is generic over
/// the surface precisely so that swap needs no change here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UnhostedAgentControlSurface;

impl UnhostedAgentControlSurface {
    fn not_ready(verb: &str) -> CloudflareControlSurfaceError {
        CloudflareControlSurfaceError::NotReady(format!(
            "no Cloudflare agent control surface is configured; cannot {verb} a \
             gateway-hosted agent run"
        ))
    }
}

impl CloudflareControlSurface for UnhostedAgentControlSurface {
    fn start_run(
        &mut self,
        _request: CloudflareRunStartRequest,
    ) -> Result<CloudflareRunHandle, CloudflareControlSurfaceError> {
        Err(Self::not_ready("start"))
    }

    fn exec_run(
        &mut self,
        _request: CloudflareRunExecRequest,
    ) -> Result<CloudflareRunExecOutcome, CloudflareControlSurfaceError> {
        Err(Self::not_ready("exec"))
    }

    fn stop_run(
        &mut self,
        _run_ref: &str,
        _reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        Err(Self::not_ready("stop"))
    }

    fn cancel_run(
        &mut self,
        _run_ref: &str,
        _reason: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        Err(Self::not_ready("cancel"))
    }

    fn cleanup_run(
        &mut self,
        _run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        Err(Self::not_ready("destroy"))
    }

    fn run_status(
        &mut self,
        _run_ref: &str,
    ) -> Result<CloudflareRunStatus, CloudflareControlSurfaceError> {
        Err(Self::not_ready("read the status of"))
    }
}

/// The verdict of consulting the cost governor before admitting an agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentRunAdmission {
    /// No agent budget is configured for this tenant chain: **no governor was
    /// constructed and no ledger read happened**, and the caller must behave
    /// exactly as it did before #428. This is the documented default-off.
    Unbudgeted,
    /// A budget is configured and the agent's accumulated burn still evaluates
    /// to `BudgetDecision::Allow`. Carries the `policy_version` of the
    /// control-plane scope that won the chain's `min`, so the audit trail can
    /// name the row that governed the run.
    Admitted { policy_version: String },
    /// Dispatch is refused. Either the agent is over budget
    /// (`agent_budget_exceeded`, 402 -- the same status/shape the #279 workflow
    /// budget denial uses) or the budget could not be evaluated
    /// (`agent_budget_unavailable`, 503 -- the fail-closed arm).
    Refused {
        status: http::StatusCode,
        code: &'static str,
        message: String,
    },
}

/// Error code for a refusal caused by real budget pressure.
pub(crate) const AGENT_BUDGET_EXCEEDED_CODE: &str = "agent_budget_exceeded";
/// Error code for a fail-closed refusal: the budget could not be evaluated.
pub(crate) const AGENT_BUDGET_UNAVAILABLE_CODE: &str = "agent_budget_unavailable";

impl AgentRunAdmission {
    /// A fail-closed refusal: the budget IS configured but could not be
    /// evaluated, so the run is not admitted.
    fn unavailable(message: String) -> Self {
        Self::Refused {
            status: http::StatusCode::SERVICE_UNAVAILABLE,
            code: AGENT_BUDGET_UNAVAILABLE_CODE,
            message,
        }
    }
}

/// Map a dispatch guard's verdict onto the admission outcome.
///
/// Split out as a pure function so the **fail-closed** contract is provable
/// without needing a durable store that can be made to fail: `Ok(false)` (over
/// budget) and `Err(_)` (ledger/store failure) must BOTH refuse, and only
/// `Ok(true)` may admit.
pub(crate) fn agent_run_admission(
    policy_version: &str,
    verdict: Result<bool, CostGovernorError>,
) -> AgentRunAdmission {
    match verdict {
        Ok(true) => AgentRunAdmission::Admitted {
            policy_version: policy_version.to_string(),
        },
        Ok(false) => AgentRunAdmission::Refused {
            status: http::StatusCode::PAYMENT_REQUIRED,
            code: AGENT_BUDGET_EXCEEDED_CODE,
            message: format!(
                "agent cost budget {policy_version} halts new dispatch for this agent: \
                 its accumulated runtime burn has reached a budget threshold"
            ),
        },
        Err(error) => AgentRunAdmission::unavailable(format!(
            "agent cost budget {policy_version} could not be evaluated, so the run is \
             refused (failing closed): {error}"
        )),
    }
}

impl AppState {
    /// Construct the #428 [`AgentCostGovernor`] for `tenant`, or `None` when the
    /// tenant has **no configured agent budget**.
    ///
    /// The governor is assembled entirely from the landed pieces: the resolved
    /// per-tenant ceiling ([`Self::resolve_agent_budget_policy`]), the default
    /// Cloudflare runtime cost model, and the **durable**
    /// [`StorageAgentBurnLedger`] over this state's repositories facade, keyed to
    /// the current `YYYY-MM` billing period (the same window
    /// `GET /admin/v1/agent-cost-burn` reports and `usage_monthly_rollups` uses).
    ///
    /// Generic over the control surface so the same product constructor serves
    /// the gateway's own unhosted runs ([`UnhostedAgentControlSurface`]), a real
    /// [`ferrogate_runtime::WorkerGatewayControlSurface`] once a CF agent
    /// deployment is configured, and the mock surface tests assert the kill
    /// switch through.
    ///
    /// `Ok(None)` is the default-off contract and must stay: it means no
    /// governor, no ledger read, and no behavior change for unbudgeted tenants.
    /// `Err` means a budget IS configured but is unusable, which callers must
    /// treat as fail-closed.
    pub(crate) async fn agent_cost_governor<C: CloudflareControlSurface>(
        &self,
        tenant: &ferrogate_core::TenantContext,
        control: C,
    ) -> anyhow::Result<Option<AgentCostGovernor<C, StorageAgentBurnLedger>>> {
        let Some(policy) = self.resolve_agent_budget_policy(tenant).await? else {
            return Ok(None);
        };
        let ledger =
            StorageAgentBurnLedger::new(self.repositories.clone(), self.current_period_month());
        Ok(Some(AgentCostGovernor::new(
            CfRuntimeCostModel::new(),
            policy,
            ledger,
            control,
        )))
    }

    /// Consult the cost governor before admitting a new agent run.
    ///
    /// `agent_key` is the STABLE per-agent identity the durable burn ledger
    /// accumulates against (the api key / virtual key the agent runs under --
    /// the same identity `#357`/`#464` treat as "the agent" when surfacing
    /// unattributed activity), deliberately NOT the ephemeral `run_id`: a
    /// per-agent budget must fold every run of the agent inside the billing
    /// period into one total, and keying on the run id would hand each run its
    /// own untethered budget.
    ///
    /// Returns [`AgentRunAdmission::Unbudgeted`] without touching the ledger when
    /// the tenant has no configured budget.
    pub(crate) async fn admit_agent_run(
        &self,
        tenant: &ferrogate_core::TenantContext,
        agent_key: &str,
        run_id: &str,
    ) -> AgentRunAdmission {
        let governor = match self
            .agent_cost_governor(tenant, UnhostedAgentControlSurface)
            .await
        {
            // Default-off: nothing configured, nothing constructed, nothing changed.
            Ok(None) => return AgentRunAdmission::Unbudgeted,
            Ok(Some(governor)) => governor,
            Err(error) => {
                warn!(
                    %error,
                    "agent cost budget is configured but unusable; refusing agent run dispatch"
                );
                return AgentRunAdmission::unavailable(format!(
                    "agent cost budget is configured but unusable, so the run is refused \
                     (failing closed): {error}"
                ));
            }
        };
        let policy_version = governor.policy().policy_version.clone();
        let identity = AgentInstanceIdentity::new(
            tenant
                .organization_id
                .as_deref()
                .unwrap_or(UNKNOWN_TENANT_ID),
            agent_key,
            run_id,
        );
        // `allow_dispatch` is the object-safe #428 dispatch-guard seam (the same
        // one `ManagedWorkerScheduler::with_dispatch_guard` consults): it reads
        // the durable burn ledger and evaluates the ceiling with a zero
        // incremental cost, so any throttle/degrade/kill pressure -- or a store
        // failure -- refuses the new run.
        let admission =
            agent_run_admission(&policy_version, governor.allow_dispatch(&identity).await);
        if let AgentRunAdmission::Refused { code, message, .. } = &admission {
            warn!(
                policy_version = %policy_version,
                agent_key,
                run_id,
                code,
                message,
                "agent cost governor refused an agent run dispatch"
            );
        }
        admission
    }
}

#[cfg(test)]
#[path = "state_agent_cost_governor_test.rs"]
mod state_agent_cost_governor_test;
