// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472),
//   phase 5: VCS write-back as an explicitly granted per-run capability with an ActionReceipt
//   audit event, never an implicit consequence of running an agent.

//! **Phase 5 — write-back authorization.**
//!
//! Pushing a branch or opening a pull request is an outward side effect on a
//! system FerroGate does not own. It is modelled as a capability that must be
//! *handed to* a run, not one a run can conclude it has.
//!
//! The enforcement is structural:
//!
//! * [`CodingAgentAdapter::write_back`](crate::coding_agent::CodingAgentAdapter::write_back)
//!   accepts only an [`AuthorizedWriteBack`].
//! * [`AuthorizedWriteBack`] has private fields, no public constructor, no
//!   `Default`, and — deliberately — **no `Deserialize`**, so it cannot be
//!   forged from JSON crossing a control-plane boundary.
//! * The only way to obtain one is [`authorize_write_back`], which takes the
//!   grant as `Option<&WriteBackGrant>`. Passing `None` (the "we never granted
//!   anything" case) is a `deny`, not a fallthrough.
//! * Every call — allow *and* deny — returns an [`ActionReceipt`] carrying the
//!   canonical [`ActionIdentity`], the [`ActionDecision`], and an
//!   [`AuditOutcome`]. There is no authorization path that produces no evidence.
//!
//! **Two-level fingerprints**, per the `action_identity` module contract:
//! the [`ActionIdentity::action_fingerprint`] is the target-level fingerprint
//! over the repo's git remote as a [`CanonicalCapabilityTarget::Network`]
//! target — it answers "which repo is being mutated". The exact operation,
//! branch, work product and head commit live in
//! [`WriteBackRequest::invocation_fingerprint`], the invocation-level binding
//! an approval would be issued against. Neither substitutes for the other.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::coding_agent::error::{CodingAgentError, CodingAgentPhase};
use crate::coding_agent::materialize::RepoCoordinates;
use crate::coding_agent::run::CodingRunIdentity;
use crate::{
    canonical_network_url, opaque_reference_fingerprint, ActingPrincipal, ActionContext,
    ActionDecision, ActionIdentity, ActionReceipt, AuditOutcome, CanonicalCapabilityTarget,
    DecisionReason, OutputDisposition,
};

/// Action class recorded in [`ActionIdentity::action`] for a VCS write-back.
/// A new class rather than a reuse of `rest`/`network.egress`: an outward
/// mutation of someone's repository is not the same governance question as an
/// HTTP call.
pub const VCS_WRITE_BACK_ACTION: &str = "vcs.write_back";

/// Upper bound on a write-back grant's lifetime. A grant outliving the run it
/// was issued for is a standing permission.
pub const MAX_WRITE_BACK_GRANT_TTL_SECS: u64 = 86_400;

/// Stable decision codes carried by [`DecisionReason::code`] and by
/// [`CodingAgentError::WriteBackNotAuthorized`].
pub mod write_back_codes {
    /// No grant was presented at all — the default for every run.
    pub const NOT_GRANTED: &str = "write_back_not_granted";
    /// The grant belongs to a different run.
    pub const RUN_MISMATCH: &str = "write_back_run_mismatch";
    /// The grant is for a different repository.
    pub const REPO_MISMATCH: &str = "write_back_repo_mismatch";
    /// The grant does not include the requested operation.
    pub const OPERATION_NOT_GRANTED: &str = "write_back_operation_not_granted";
    /// The grant's window has elapsed.
    pub const EXPIRED: &str = "write_back_grant_expired";
    /// The target branch is outside the namespace the grant confines the run to.
    pub const BRANCH_OUTSIDE_NAMESPACE: &str = "write_back_branch_outside_namespace";
    /// The request does not reference an extracted work product.
    pub const NO_WORK_PRODUCT: &str = "write_back_no_work_product";
    /// Authorized.
    pub const GRANTED: &str = "write_back_granted";
}

/// The outward operations a grant can confer. Enumerated, not a free string:
/// "what may this run do to the repo" is a closed question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteBackOperation {
    PushBranch,
    OpenPullRequest,
    UpdatePullRequest,
    PushTag,
}

impl WriteBackOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PushBranch => "push_branch",
            Self::OpenPullRequest => "open_pull_request",
            Self::UpdatePullRequest => "update_pull_request",
            Self::PushTag => "push_tag",
        }
    }

    pub fn is_pull_request(self) -> bool {
        matches!(self, Self::OpenPullRequest | Self::UpdatePullRequest)
    }
}

/// An explicit, per-run, time-boxed authorization to mutate one repository.
///
/// There is no `Default`, no builder that fills in operations, and no
/// constructor that derives a grant from a run request. Granting is an act by
/// a principal, recorded as [`Self::granted_by`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBackGrant {
    grant_id: String,
    run_id: String,
    repo_id: String,
    operations: BTreeSet<WriteBackOperation>,
    /// Branch namespace the run is confined to, e.g. `ferrogate/run-`. A grant
    /// that could push any branch is a grant to overwrite `main`.
    branch_prefix: String,
    granted_by: ActingPrincipal,
    granted_at_unix: u64,
    expires_at_unix: u64,
    /// Approval-workflow reference when the grant came from a human gate.
    approval_reference: Option<String>,
}

impl WriteBackGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        grant_id: impl Into<String>,
        run_id: impl Into<String>,
        repo: &RepoCoordinates,
        operations: BTreeSet<WriteBackOperation>,
        branch_prefix: impl Into<String>,
        granted_by: ActingPrincipal,
        granted_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<Self, CodingAgentError> {
        let grant_id = grant_id.into();
        let run_id = run_id.into();
        let branch_prefix = branch_prefix.into();
        let field = |field: &'static str, detail: &str| {
            CodingAgentError::invalid(CodingAgentPhase::WriteBack, field, detail.to_string())
        };
        if grant_id.trim().is_empty() {
            return Err(field("grant_id", "must not be empty"));
        }
        if run_id.trim().is_empty() {
            return Err(field("run_id", "must not be empty"));
        }
        if operations.is_empty() {
            return Err(field(
                "operations",
                "a grant with no operations is not a grant",
            ));
        }
        if branch_prefix.trim().is_empty() {
            return Err(field(
                "branch_prefix",
                "a grant must confine the run to a branch namespace",
            ));
        }
        if granted_by.subject.trim().is_empty() {
            return Err(field("granted_by.subject", "granting is an act by someone"));
        }
        if expires_at_unix <= granted_at_unix {
            return Err(field(
                "expires_at_unix",
                "a grant must expire strictly after it is issued",
            ));
        }
        if expires_at_unix - granted_at_unix > MAX_WRITE_BACK_GRANT_TTL_SECS {
            return Err(field(
                "expires_at_unix",
                "grant TTL exceeds the per-run cap; this is a standing permission",
            ));
        }
        Ok(Self {
            grant_id,
            run_id,
            repo_id: repo.canonical_id(),
            operations,
            branch_prefix,
            granted_by,
            granted_at_unix,
            expires_at_unix,
            approval_reference: None,
        })
    }

    pub fn with_approval_reference(mut self, reference: impl Into<String>) -> Self {
        self.approval_reference = Some(reference.into());
        self
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn operations(&self) -> &BTreeSet<WriteBackOperation> {
        &self.operations
    }

    pub fn branch_prefix(&self) -> &str {
        &self.branch_prefix
    }

    pub fn granted_by(&self) -> &ActingPrincipal {
        &self.granted_by
    }

    pub fn granted_at_unix(&self) -> u64 {
        self.granted_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn approval_reference(&self) -> Option<&str> {
        self.approval_reference.as_deref()
    }

    pub fn grants_pull_requests(&self) -> bool {
        self.operations.iter().any(|op| op.is_pull_request())
    }
}

/// A requested outward mutation. Always references the work product it
/// publishes: pushing something that was never extracted and attributed is how
/// an unreviewable change reaches a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBackRequest {
    pub run: CodingRunIdentity,
    pub repo: RepoCoordinates,
    pub operation: WriteBackOperation,
    pub branch: String,
    /// [`crate::coding_agent::WorkProduct::product_id`] this publishes.
    pub work_product_id: String,
    pub head_commit: String,
    pub title: Option<String>,
    pub body: Option<String>,
}

impl WriteBackRequest {
    /// Invocation-level fingerprint: binds one approval to one concrete
    /// mutation (run, operation, branch, work product, head commit). Distinct
    /// from the target-level [`ActionIdentity::action_fingerprint`].
    pub fn invocation_fingerprint(&self) -> String {
        opaque_reference_fingerprint(&format!(
            "{}|{}|{}|{}|{}|{}",
            self.run.tenant_id,
            self.run.run_id,
            self.repo.canonical_id(),
            self.operation.as_str(),
            self.branch,
            format_args!("{}:{}", self.work_product_id, self.head_commit),
        ))
    }
}

/// Canonical target for a write-back: the repo's git HTTPS remote as a
/// [`CanonicalCapabilityTarget::Network`] target.
///
/// The operation and branch are intentionally **not** in the target. Encoding
/// them would require inventing provider-specific API URLs (`/repos/{o}/{r}/
/// pulls` is GitHub's shape, not GitLab's), which is precisely the
/// vendor-shaped abstraction the issue warns against. The exact action lives in
/// [`WriteBackRequest::invocation_fingerprint`] instead.
pub fn canonical_write_back_target(
    repo: &RepoCoordinates,
) -> Result<CanonicalCapabilityTarget, CodingAgentError> {
    canonical_network_url(&repo.https_remote(), Some("POST"), &[], &[])
        .map_err(|detail| CodingAgentError::invalid(CodingAgentPhase::WriteBack, "repo", detail))
}

/// Proof that a specific write-back was authorized.
///
/// Private fields, no public constructor, no `Default`, and **no `Deserialize`
/// on purpose** — a capability token that can be parsed from untrusted input is
/// not a capability token. The only mint is [`authorize_write_back`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizedWriteBack {
    request: WriteBackRequest,
    grant_id: String,
    identity: ActionIdentity,
    invocation_fingerprint: String,
    authorized_at_unix: u64,
}

impl AuthorizedWriteBack {
    pub fn request(&self) -> &WriteBackRequest {
        &self.request
    }

    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn action_identity(&self) -> &ActionIdentity {
        &self.identity
    }

    pub fn invocation_fingerprint(&self) -> &str {
        &self.invocation_fingerprint
    }

    pub fn authorized_at_unix(&self) -> u64 {
        self.authorized_at_unix
    }
}

/// The outcome of one authorization attempt: a canonical decision, the audit
/// receipt to persist, and — only on allow — the capability token.
#[derive(Debug, Clone)]
pub struct WriteBackAuthorization {
    decision: ActionDecision,
    receipt: ActionReceipt,
    authorized: Option<AuthorizedWriteBack>,
}

impl WriteBackAuthorization {
    pub fn decision(&self) -> &ActionDecision {
        &self.decision
    }

    /// The audit event to persist. Present on every path, allow or deny.
    pub fn receipt(&self) -> &ActionReceipt {
        &self.receipt
    }

    pub fn is_allowed(&self) -> bool {
        self.authorized.is_some()
    }

    /// Audit `outcome` for the evidence row: `allowed` or `rejected`.
    pub fn audit_outcome(&self) -> AuditOutcome {
        if self.is_allowed() {
            AuditOutcome::Allowed
        } else {
            AuditOutcome::Rejected
        }
    }

    /// Take the capability token. `None` on every denial.
    pub fn into_authorized(self) -> Option<AuthorizedWriteBack> {
        self.authorized
    }

    /// Convenience for callers that want the denial as an error.
    pub fn require_authorized(self) -> Result<AuthorizedWriteBack, CodingAgentError> {
        let code = self.decision.code().to_string();
        let detail = self
            .decision
            .reason()
            .detail
            .clone()
            .unwrap_or_else(|| code.clone());
        self.authorized
            .ok_or(CodingAgentError::WriteBackNotAuthorized { code, detail })
    }
}

/// Authorize (or refuse) one write-back.
///
/// `grant` is an `Option` on purpose: the absence of a grant is the normal
/// state of a run, and it must produce a recorded denial rather than an
/// unchecked path. Every return value carries an [`ActionReceipt`].
pub fn authorize_write_back(
    grant: Option<&WriteBackGrant>,
    request: &WriteBackRequest,
    principal: &ActingPrincipal,
    context: &ActionContext,
    now_unix: u64,
) -> Result<WriteBackAuthorization, CodingAgentError> {
    let target = canonical_write_back_target(&request.repo)?;
    let identity = ActionIdentity::from_canonical_target(
        VCS_WRITE_BACK_ACTION,
        &target,
        principal.clone(),
        context.clone(),
    );

    let refusal = |code: &str, detail: String| -> Option<DecisionReason> {
        Some(DecisionReason::new(code).with_detail(detail))
    };

    let denial = match grant {
        None => refusal(
            write_back_codes::NOT_GRANTED,
            "no write-back grant was issued for this run".to_string(),
        ),
        Some(grant) if grant.run_id() != request.run.run_id => refusal(
            write_back_codes::RUN_MISMATCH,
            format!(
                "grant {} authorizes run {}, not {}",
                grant.grant_id(),
                grant.run_id(),
                request.run.run_id
            ),
        ),
        Some(grant) if grant.repo_id() != request.repo.canonical_id() => refusal(
            write_back_codes::REPO_MISMATCH,
            format!(
                "grant {} authorizes {}, not {}",
                grant.grant_id(),
                grant.repo_id(),
                request.repo.canonical_id()
            ),
        ),
        Some(grant) if now_unix >= grant.expires_at_unix() => refusal(
            write_back_codes::EXPIRED,
            format!(
                "grant {} expired at {}",
                grant.grant_id(),
                grant.expires_at_unix()
            ),
        ),
        Some(grant) if !grant.operations().contains(&request.operation) => refusal(
            write_back_codes::OPERATION_NOT_GRANTED,
            format!(
                "grant {} does not include {}",
                grant.grant_id(),
                request.operation.as_str()
            ),
        ),
        Some(grant) if !request.branch.starts_with(grant.branch_prefix()) => refusal(
            write_back_codes::BRANCH_OUTSIDE_NAMESPACE,
            format!(
                "branch {} is outside the granted namespace {}",
                request.branch,
                grant.branch_prefix()
            ),
        ),
        Some(_) if request.work_product_id.trim().is_empty() => refusal(
            write_back_codes::NO_WORK_PRODUCT,
            "write-back must publish an extracted, run-attributed work product".to_string(),
        ),
        Some(_) => None,
    };

    if let Some(reason) = denial {
        let decision = ActionDecision::Deny { reason };
        let receipt = ActionReceipt {
            identity,
            decision: decision.clone(),
            output_disposition: OutputDisposition::Withheld,
            latency_ms: None,
            attempt: 1,
        };
        return Ok(WriteBackAuthorization {
            decision,
            receipt,
            authorized: None,
        });
    }

    let grant = grant.expect("denial arm covers the None case");
    let detail = match grant.approval_reference() {
        Some(reference) => format!(
            "grant {} (approval {}) authorizes {} on {}",
            grant.grant_id(),
            reference,
            request.operation.as_str(),
            grant.repo_id()
        ),
        None => format!(
            "grant {} authorizes {} on {}",
            grant.grant_id(),
            request.operation.as_str(),
            grant.repo_id()
        ),
    };
    let decision = ActionDecision::Allow {
        reason: DecisionReason::new(write_back_codes::GRANTED).with_detail(detail),
    };
    let receipt = ActionReceipt {
        identity: identity.clone(),
        decision: decision.clone(),
        output_disposition: OutputDisposition::Returned,
        latency_ms: None,
        attempt: 1,
    };
    Ok(WriteBackAuthorization {
        decision,
        receipt,
        authorized: Some(AuthorizedWriteBack {
            request: request.clone(),
            grant_id: grant.grant_id().to_string(),
            invocation_fingerprint: request.invocation_fingerprint(),
            identity,
            authorized_at_unix: now_unix,
        }),
    })
}

/// What actually happened at the remote, attributable to the run and to the
/// grant that permitted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteBackReceipt {
    pub run_id: String,
    pub grant_id: String,
    pub operation: WriteBackOperation,
    pub repo_id: String,
    pub branch: String,
    pub work_product_id: String,
    pub head_commit: String,
    /// Provider-side reference for the created change (PR/MR URL or number).
    /// A free string: the shape is the provider's, not the contract's.
    pub review_reference: Option<String>,
    /// Target-level fingerprint from the authorizing [`ActionIdentity`].
    pub action_fingerprint: String,
    /// Invocation-level fingerprint from [`AuthorizedWriteBack`].
    pub invocation_fingerprint: String,
    pub completed_at_unix: u64,
    pub outcome: WriteBackOutcome,
}

/// Terminal state of the outward call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WriteBackOutcome {
    Completed,
    /// The remote refused (protected branch, conflict, permission). The run is
    /// not a failure; the mutation is.
    Refused {
        code: String,
    },
    Failed {
        code: String,
    },
}

impl WriteBackOutcome {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Completed => "completed",
            Self::Refused { .. } => "refused",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn audit_outcome(&self) -> AuditOutcome {
        match self {
            Self::Completed => AuditOutcome::Success,
            Self::Refused { .. } => AuditOutcome::Rejected,
            Self::Failed { .. } => AuditOutcome::ErrorOutcome,
        }
    }
}

impl WriteBackReceipt {
    /// Build the receipt from the capability token, so a receipt can never
    /// describe a mutation that was not authorized.
    pub fn from_authorized(
        authorized: &AuthorizedWriteBack,
        review_reference: Option<String>,
        completed_at_unix: u64,
        outcome: WriteBackOutcome,
    ) -> Self {
        let request = authorized.request();
        Self {
            run_id: request.run.run_id.clone(),
            grant_id: authorized.grant_id().to_string(),
            operation: request.operation,
            repo_id: request.repo.canonical_id(),
            branch: request.branch.clone(),
            work_product_id: request.work_product_id.clone(),
            head_commit: request.head_commit.clone(),
            review_reference,
            action_fingerprint: authorized.action_identity().action_fingerprint.clone(),
            invocation_fingerprint: authorized.invocation_fingerprint().to_string(),
            completed_at_unix,
            outcome,
        }
    }
}

#[cfg(test)]
#[path = "write_back_test.rs"]
mod tests;
