// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472):
//   the CodingAgentAdapter trait, its descriptor/capability advertisement, and the fail-closed
//   preflight that keeps an adapter from being asked for a phase it does not implement.

//! The adapter trait itself.
//!
//! Six methods, one per contract phase plus the close-out. Synchronous, like
//! [`crate::FrameworkAdapter`], [`crate::IsolationBackendLifecycle`] and the
//! #415 container client — the control-plane seams in this crate are sync over
//! an injectable transport so every one of them is testable with no network and
//! no runtime.
//!
//! The descriptor is the fail-closed part: an adapter advertises what it can
//! do, [`CodingAgentCapabilities::preflight`] refuses a request the adapter
//! cannot honour, and the caller finds out before a container is started rather
//! than after a credential has been issued.

use serde::{Deserialize, Serialize};

use crate::coding_agent::bootstrap::{AgentBootstrapRequest, BootstrappedAgent};
use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::extract::{WorkProduct, WorkProductRequest};
use crate::coding_agent::materialize::{
    CredentialDelivery, MaterializedWorkspace, RepoMaterializationRequest,
};
use crate::coding_agent::run::{
    CodingRunOutcome, CodingRunReceipt, CodingRunRequest, RunFinalization,
};
use crate::coding_agent::write_back::{AuthorizedWriteBack, WriteBackOperation, WriteBackReceipt};

/// What an adapter implementation can actually do.
///
/// Advertised, checked, and a strict statement — an adapter that sets a flag it
/// does not implement is lying to the selector, exactly the #188 failure mode
/// (the API accepted a value the runtime ignored).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingAgentCapabilities {
    /// Clone/checkout at a pinned ref.
    pub materialize_repo: bool,
    pub shallow_clone: bool,
    pub submodules: bool,
    /// Can consume a brokered per-operation credential (no secret at rest in
    /// the instance). The delivery that survives an untrusted-process threat
    /// model; an adapter without it forces the weaker file delivery.
    pub brokered_credentials: bool,
    /// Produces a unified diff.
    pub diff_extraction: bool,
    /// Produces a local branch/commit, not just a working-tree diff.
    pub branch_extraction: bool,
    /// Can push a branch when authorized.
    pub push_branch: bool,
    /// Can open/update a review request when authorized.
    pub pull_request: bool,
    /// Can resume an interrupted run instead of restarting it.
    pub resume: bool,
}

impl CodingAgentCapabilities {
    /// The minimum viable coding agent: clone a pin, run, emit a diff. No
    /// write-back — that is the point of the default.
    pub fn diff_only() -> Self {
        Self {
            materialize_repo: true,
            diff_extraction: true,
            ..Self::default()
        }
    }

    pub fn supports_write_back(&self, operation: WriteBackOperation) -> bool {
        match operation {
            WriteBackOperation::PushBranch | WriteBackOperation::PushTag => self.push_branch,
            WriteBackOperation::OpenPullRequest | WriteBackOperation::UpdatePullRequest => {
                self.pull_request
            }
        }
    }

    pub fn supports_delivery(&self, delivery: &CredentialDelivery) -> bool {
        match delivery {
            CredentialDelivery::BrokeredPerOperation { .. } => self.brokered_credentials,
            CredentialDelivery::EphemeralFile { .. } => true,
        }
    }

    /// Fail-closed preflight for a materialization request.
    pub fn preflight(&self, request: &RepoMaterializationRequest) -> Result<(), CodingAgentError> {
        if !self.materialize_repo {
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::Materialize,
                capability: "materialize_repo",
            });
        }
        if request.fetch_depth.is_some() && !self.shallow_clone {
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::Materialize,
                capability: "shallow_clone",
            });
        }
        if request.include_submodules && !self.submodules {
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::Materialize,
                capability: "submodules",
            });
        }
        if !self.supports_delivery(request.credential.delivery()) {
            return Err(CodingAgentError::Unsupported {
                phase: CodingAgentPhase::Materialize,
                capability: "brokered_credentials",
            });
        }
        Ok(())
    }
}

/// Identity of one adapter implementation.
///
/// `agent_name` is a **free string**, and there is deliberately no
/// `SupportedCodingAgent` enum mirroring [`crate::SupportedFramework`]. A
/// closed vendor list would have to be edited — and every match arm on it
/// revisited — to add the second coding agent, which is exactly the "freeze the
/// contract around one implementation" failure the issue calls out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodingAgentDescriptor {
    pub adapter_name: String,
    pub adapter_version: String,
    /// The coding agent this adapter drives, e.g. `"claude-code"`, `"aider"`,
    /// an in-house harness. Recorded for attribution; never branched on by the
    /// contract.
    pub agent_name: String,
    /// Isolation backend the adapter runs the agent in, e.g.
    /// [`crate::CLOUDFLARE_CONTAINER_BACKEND_NAME`].
    pub isolation_backend: String,
    pub capabilities: CodingAgentCapabilities,
}

/// The coding-agent adapter contract.
///
/// Five phases plus a mandatory close-out. Each method is a seam, not a
/// workflow: sequencing, retry, persistence and admin exposure belong to the
/// control plane, which is why nothing here returns a future, opens a socket,
/// or knows what a Worker is.
pub trait CodingAgentAdapter {
    fn descriptor(&self) -> &CodingAgentDescriptor;

    /// **Phase 1.** Clone the repo at the pinned ref using the short-lived,
    /// repo-scoped credential grant. Implementations must verify the checkout
    /// landed on the pin ([`MaterializedWorkspace::verify`]) and must not
    /// persist the credential anywhere the agent can read.
    fn materialize_repo(
        &mut self,
        request: RepoMaterializationRequest,
    ) -> Result<MaterializedWorkspace, CodingAgentError>;

    /// **Phase 2.** Launch the coding agent against the workspace with the task
    /// brief, under the declared egress posture, with model traffic pointed at
    /// the governed gateway.
    fn bootstrap(
        &mut self,
        request: AgentBootstrapRequest,
    ) -> Result<BootstrappedAgent, CodingAgentError>;

    /// **Phase 3.** Run to a terminal state. Long-running and
    /// filesystem-mutating; the deadline is the caller's, not the agent's.
    fn run(&mut self, request: CodingRunRequest) -> Result<CodingRunOutcome, CodingAgentError>;

    /// **Phase 4.** Turn the mutated workspace into a run-attributed work
    /// product. `Ok(None)` means the run changed nothing — a real outcome, not
    /// an error, and not an empty patch.
    fn extract(
        &mut self,
        request: WorkProductRequest,
    ) -> Result<Option<WorkProduct>, CodingAgentError>;

    /// **Phase 5.** Perform the authorized outward mutation.
    ///
    /// The parameter type is the enforcement: an [`AuthorizedWriteBack`] can
    /// only come from
    /// [`authorize_write_back`](crate::coding_agent::authorize_write_back), so
    /// an implementation cannot be handed "just push this" and cannot mint its
    /// own permission.
    fn write_back(
        &mut self,
        authorized: AuthorizedWriteBack,
    ) -> Result<WriteBackReceipt, CodingAgentError>;

    /// Close the run: revoke the credential, tear down the instance, and emit
    /// the terminal receipt. Must be called on **every** path — success,
    /// failure, timeout, cancellation — which is why
    /// [`CodingRunReceipt`] cannot be built without the revocation record.
    fn finalize(
        &mut self,
        finalization: RunFinalization,
    ) -> Result<CodingRunReceipt, CodingAgentError>;
}

#[cfg(test)]
#[path = "adapter_test.rs"]
mod tests;
