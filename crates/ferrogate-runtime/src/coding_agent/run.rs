// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472),
//   phase 3 + close-out: run identity, run outcome, and the terminal receipt that cannot exist
//   without a credential-revocation record.

//! **Phase 3 — run**, and the close-out that discharges phase 1's obligation.
//!
//! A coding run is long-running, filesystem-mutating and VCS-writing; it is
//! not request/response, which is why it does not fit
//! [`crate::FrameworkAdapter`]'s session/submit/stream shape. What the contract
//! fixes here is only what the control plane must know: the identity the run is
//! attributed to, when it stopped and why, and — mandatorily — that its
//! credential was closed.
//!
//! [`CodingRunReceipt`] holds a non-optional
//! [`CredentialRevocation`]. There is no constructor that omits it, and
//! [`RunFinalization`] takes the [`RepoCredentialGrant`] **by value**, so the
//! grant is consumed exactly where it is revoked. "Revoked on success and on
//! failure" therefore is not a rule someone has to remember; it is the only way
//! to produce a terminal record at all.

use serde::{Deserialize, Serialize};

use crate::coding_agent::bootstrap::{BootstrappedAgent, EgressEnforcement, EgressPosture};
use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::extract::WorkProduct;
use crate::coding_agent::materialize::{
    CredentialRevocation, RepoCredentialGrant, RevocationOutcome,
};
use crate::coding_agent::write_back::WriteBackReceipt;
use crate::{AgentCostAttribution, AgentInstanceIdentity, AuditOutcome};

/// The correlation triple every phase, artifact and audit row is keyed on.
/// Projects onto the #427 instance-naming scheme so the coding runtime shares
/// one identity with container isolation (#415), memory (#427) and cost
/// governance (#428) instead of inventing a fourth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingRunIdentity {
    pub tenant_id: String,
    pub session_id: String,
    pub run_id: String,
}

impl CodingRunIdentity {
    pub fn new(
        tenant_id: impl Into<String>,
        session_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            session_id: session_id.into(),
            run_id: run_id.into(),
        }
    }

    pub fn instance_identity(&self) -> AgentInstanceIdentity {
        AgentInstanceIdentity::new(&self.tenant_id, &self.session_id, &self.run_id)
    }

    /// Mint the `fg.{tenant}.{session}.{run}` instance name, rejecting (never
    /// sanitizing) invalid components.
    pub fn instance_name(&self) -> Result<String, CodingAgentError> {
        self.instance_identity().instance_name().map_err(|error| {
            CodingAgentError::invalid(CodingAgentPhase::Run, "run_identity", error.to_string())
        })
    }

    /// Project onto the #428 cost-attribution tuple so a coding run's burn
    /// lands on the same ledger key as any other agent run.
    pub fn cost_attribution(&self) -> Result<AgentCostAttribution, CodingAgentError> {
        AgentCostAttribution::from_identity(&self.instance_identity()).map_err(|error| {
            CodingAgentError::invalid(CodingAgentPhase::Run, "run_identity", error.to_string())
        })
    }
}

/// Binding to the #428 budget policy that governs this run's spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBudgetBinding {
    pub policy_revision: String,
    pub attribution: AgentCostAttribution,
}

/// Phase-3 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodingRunRequest {
    pub run: CodingRunIdentity,
    pub agent: BootstrappedAgent,
    /// Wall-clock deadline. A coding agent with no deadline is a container
    /// that never stops billing.
    pub deadline_unix: u64,
    pub budget: Option<RunBudgetBinding>,
}

impl CodingRunRequest {
    pub fn validate(&self, now_unix: u64) -> Result<(), CodingAgentError> {
        if self.agent.run.run_id != self.run.run_id {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Run,
                "agent",
                "bootstrapped agent belongs to a different run",
            ));
        }
        if self.deadline_unix <= now_unix {
            return Err(CodingAgentError::invalid(
                CodingAgentPhase::Run,
                "deadline_unix",
                "deadline must be in the future",
            ));
        }
        Ok(())
    }
}

/// Why the run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingRunStatus {
    /// The agent finished on its own terms.
    Completed,
    /// The agent stopped with an error.
    Failed,
    /// The wall-clock deadline elapsed.
    TimedOut,
    /// A human or the control plane stopped it.
    Cancelled,
    /// The #428 budget governor killed it.
    BudgetExhausted,
    /// A policy/guardrail decision stopped it.
    PolicyBlocked,
}

impl CodingRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::BudgetExhausted => "budget_exhausted",
            Self::PolicyBlocked => "policy_blocked",
        }
    }

    /// Whether extraction is still worth attempting. A timed-out or
    /// budget-killed run has usually written real, partially useful changes to
    /// the workspace — discarding them because the status is not `Completed`
    /// throws away work the customer already paid for.
    pub fn may_have_work_product(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }

    pub fn audit_outcome(self) -> AuditOutcome {
        match self {
            Self::Completed => AuditOutcome::Success,
            Self::Failed | Self::TimedOut => AuditOutcome::ErrorOutcome,
            Self::Cancelled | Self::BudgetExhausted | Self::PolicyBlocked => AuditOutcome::Rejected,
        }
    }
}

/// Phase-3 result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingRunOutcome {
    pub run: CodingRunIdentity,
    pub status: CodingRunStatus,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    /// Agent-reported step count, for cost/behaviour triage. Advisory.
    pub steps: u32,
    /// Terminal failure detail when `status` is not `Completed`.
    pub failure_detail: Option<String>,
}

impl CodingRunOutcome {
    pub fn duration_secs(&self) -> u64 {
        self.finished_at_unix.saturating_sub(self.started_at_unix)
    }
}

/// Close-out input. Owns the credential grant by value: the grant ends here,
/// in the same call that revokes it. Not `Clone`, because the grant is not.
#[derive(Debug, PartialEq, Eq)]
pub struct RunFinalization {
    pub run: CodingRunIdentity,
    pub outcome: CodingRunOutcome,
    pub credential: RepoCredentialGrant,
    pub work_product: Option<WorkProduct>,
    pub write_back: Option<WriteBackReceipt>,
    pub egress_posture: EgressPosture,
    pub finalized_at_unix: u64,
}

/// The terminal, control-plane-visible record of one coding run.
///
/// `credential_revocation` is **not** optional. That single decision is what
/// makes "the credential is revoked on both the success and the failure path"
/// a property of the type rather than of the implementation's care.
#[must_use = "the run receipt is the control-plane evidence for the run"]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingRunReceipt {
    pub run: CodingRunIdentity,
    pub status: CodingRunStatus,
    /// `None` when the run changed nothing — an honest outcome, distinct from
    /// failure.
    pub work_product_id: Option<String>,
    /// `None` when nothing was written back, which is the default: write-back
    /// requires a grant (phase 5).
    pub write_back: Option<WriteBackReceipt>,
    pub credential_revocation: CredentialRevocation,
    /// Posture the run actually executed under, and whether the gateway was a
    /// wall. Recorded so a cooperative-egress run is auditable after the fact.
    pub egress_posture: String,
    pub egress_enforcement: EgressEnforcement,
    /// Whether the repo credential was readable by a process inside the
    /// instance (`ephemeral_file` delivery). Visible weakening, not a footnote.
    pub credential_readable_in_instance: bool,
    pub started_at_unix: u64,
    pub finalized_at_unix: u64,
}

impl CodingRunReceipt {
    /// Assemble the terminal record, **consuming** the finalization — and with
    /// it the credential grant, which is turned into the mandatory
    /// [`CredentialRevocation`] here rather than accepted alongside it. The
    /// old shape took the revocation as a separate argument and compared grant
    /// ids; minting it from the surrendered grant makes the mismatch it was
    /// guarding against unrepresentable.
    ///
    /// Cross-checks that everything attributed to this run actually belongs to
    /// it — including that the commit the write-back says it published is the
    /// commit the work product actually produced.
    pub fn assemble(
        finalization: RunFinalization,
        revocation_outcome: RevocationOutcome,
    ) -> Result<Self, CodingAgentError> {
        let RunFinalization {
            run,
            outcome,
            credential,
            work_product,
            write_back,
            egress_posture,
            finalized_at_unix,
        } = finalization;
        let run_id = run.run_id.as_str();
        if credential.run_id() != run_id {
            return Err(CodingAgentError::credential(
                "finalization presented a credential grant from another run",
            ));
        }
        if let Some(product) = &work_product {
            if !product.attributed_to(run_id) {
                return Err(CodingAgentError::invalid(
                    CodingAgentPhase::Finalize,
                    "work_product",
                    "work product is not attributable to this run",
                ));
            }
        }
        if let Some(receipt) = &write_back {
            check_write_back_publishes(&run, work_product.as_ref(), receipt)?;
        }
        let credential_readable_in_instance = credential.delivery().readable_in_instance();
        let credential_revocation =
            CredentialRevocation::for_grant(credential, finalized_at_unix, revocation_outcome);
        Ok(Self {
            work_product_id: work_product
                .as_ref()
                .map(|product| product.product_id().to_string()),
            status: outcome.status,
            started_at_unix: outcome.started_at_unix,
            run,
            write_back,
            credential_revocation,
            egress_posture: egress_posture.as_str().to_string(),
            egress_enforcement: egress_posture.enforcement(),
            credential_readable_in_instance,
            finalized_at_unix,
        })
    }

    /// True when the credential can no longer be used. False is an incident:
    /// a live credential outlived its run.
    pub fn credential_is_closed(&self) -> bool {
        self.credential_revocation
            .outcome
            .is_credential_neutralized()
    }
}

/// Check that a write-back receipt describes publishing *this* run's work
/// product — not merely one whose id it quotes.
///
/// Matching `work_product_id` alone is not enough. A receipt could carry the
/// right product id and an unrelated `head_commit`, and the terminal record
/// would honestly state "work product X was published" while the commit that
/// actually reached the remote has nothing to do with X. So the branch, the
/// head commit, the repo and the tenant are all checked against the product.
fn check_write_back_publishes(
    run: &CodingRunIdentity,
    work_product: Option<&WorkProduct>,
    receipt: &WriteBackReceipt,
) -> Result<(), CodingAgentError> {
    let mismatch = |detail: &str| {
        CodingAgentError::invalid(CodingAgentPhase::Finalize, "write_back", detail.to_string())
    };
    if receipt.run_id != run.run_id {
        return Err(mismatch("write-back receipt belongs to another run"));
    }
    if receipt.tenant_id != run.tenant_id {
        return Err(mismatch("write-back receipt belongs to another tenant"));
    }
    let Some(product) = work_product else {
        return Err(mismatch(
            "write-back published a work product this run did not extract",
        ));
    };
    if product.product_id() != receipt.work_product_id {
        return Err(mismatch(
            "write-back published a work product this run did not extract",
        ));
    }
    if receipt.repo_id != product.repo.canonical_id() {
        return Err(mismatch(
            "write-back names a different repository than the work product came from",
        ));
    }
    // A work product with no produced branch is a bare diff: there is no
    // commit in it for a push to have published. Accepting a receipt here
    // would be accepting an unverifiable head commit.
    let Some(branch) = &product.branch else {
        return Err(mismatch(
            "write-back published a commit for a work product that produced no branch; \
             there is nothing to check the pushed head against",
        ));
    };
    if receipt.head_commit != branch.head_commit {
        return Err(mismatch(
            "write-back published a head commit that is not the work product's head commit",
        ));
    }
    if receipt.branch != branch.name {
        return Err(mismatch(
            "write-back published a branch that is not the work product's branch",
        ));
    }
    Ok(())
}
