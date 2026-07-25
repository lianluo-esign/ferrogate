// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, coding-agent adapter contract (issue #472):
//   phase enum and error taxonomy shared by materialize/bootstrap/run/extract/write-back.

//! Phase labels and the error taxonomy for the coding-agent adapter contract.
//!
//! Every failure names the phase it happened in, because the recovery action
//! differs per phase: a materialization failure leaves nothing to revoke but a
//! credential grant, a run failure still owes a work-product extraction
//! attempt, and a write-back failure must never be retried without a fresh
//! authorization.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

/// The ordered phases of one coding-agent run.
///
/// The first five are the contract the issue asks for. [`Self::Finalize`] is
/// not a sixth feature — it is the mandatory close-out that discharges the
/// obligations opened by [`Self::Materialize`] (credential revocation) and
/// [`Self::WriteBack`] (receipt attribution). A run that never reaches
/// `Finalize` has leaked a credential, so the contract makes the terminal
/// record unconstructible without a revocation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodingAgentPhase {
    Materialize,
    Bootstrap,
    Run,
    Extract,
    WriteBack,
    Finalize,
}

impl CodingAgentPhase {
    /// The contract's phase order. Implementations may skip a phase (an
    /// adapter that cannot push has no `WriteBack`), but must not reorder it.
    pub const ORDER: [Self; 6] = [
        Self::Materialize,
        Self::Bootstrap,
        Self::Run,
        Self::Extract,
        Self::WriteBack,
        Self::Finalize,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Materialize => "materialize",
            Self::Bootstrap => "bootstrap",
            Self::Run => "run",
            Self::Extract => "extract",
            Self::WriteBack => "write_back",
            Self::Finalize => "finalize",
        }
    }
}

impl fmt::Display for CodingAgentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure modes of the coding-agent contract.
///
/// The taxonomy is deliberately narrow: the variants that exist are the ones a
/// caller must branch on. Anything an implementation-specific backend reports
/// lands in [`Self::Backend`] with its phase, rather than growing a variant
/// shaped by one vendor's error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodingAgentError {
    /// A request field is missing, empty, or structurally invalid. Rejected
    /// before any side effect.
    InvalidRequest {
        phase: CodingAgentPhase,
        field: &'static str,
        detail: String,
    },
    /// A repo credential was described in a way the contract refuses to carry
    /// — most importantly, as key material or as a process-environment
    /// reference rather than a secret-store reference.
    CredentialRejected { detail: String },
    /// The requested ref is not an immutable pin (a branch or tag name is not
    /// a pin; only a full commit id is).
    UnpinnedRef { detail: String },
    /// The workspace materialized at a different commit than the one pinned.
    /// This is a hard failure, never a warning: everything downstream —
    /// the diff base, the work-product id, the review — is attributed to the
    /// pin.
    RefMismatch {
        requested: String,
        materialized: String,
    },
    /// The declared egress posture would let the agent reach model providers
    /// without traversing the governed gateway, or omits the gateway entirely.
    EgressNotGoverned { detail: String },
    /// A write-back was attempted without a valid, matching, unexpired grant.
    /// `code` is the stable [`crate::coding_agent::write_back_codes`]
    /// discriminator that the audit receipt also carries.
    WriteBackNotAuthorized { code: String, detail: String },
    /// Extraction found no change. Not an error condition of the run — it is
    /// an error of *assembling a work product*, because "no diff" must be
    /// reported as "the run produced nothing", never as an empty patch that
    /// looks like a reviewable change.
    EmptyWorkProduct,
    /// The adapter does not implement the capability the phase requires. The
    /// descriptor advertises this up front so callers fail closed instead of
    /// discovering it mid-run.
    Unsupported {
        phase: CodingAgentPhase,
        capability: &'static str,
    },
    /// An implementation-side failure (container exec, VCS transport, agent
    /// process). Carries the phase so the caller knows which obligations are
    /// still outstanding.
    Backend {
        phase: CodingAgentPhase,
        detail: String,
    },
}

impl CodingAgentError {
    pub fn invalid(
        phase: CodingAgentPhase,
        field: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::InvalidRequest {
            phase,
            field,
            detail: detail.into(),
        }
    }

    pub fn credential(detail: impl Into<String>) -> Self {
        Self::CredentialRejected {
            detail: detail.into(),
        }
    }

    pub fn backend(phase: CodingAgentPhase, detail: impl Into<String>) -> Self {
        Self::Backend {
            phase,
            detail: detail.into(),
        }
    }

    /// The phase the failure is attributed to, when it has one.
    pub fn phase(&self) -> Option<CodingAgentPhase> {
        match self {
            Self::InvalidRequest { phase, .. }
            | Self::Unsupported { phase, .. }
            | Self::Backend { phase, .. } => Some(*phase),
            Self::CredentialRejected { .. } => Some(CodingAgentPhase::Materialize),
            Self::UnpinnedRef { .. } | Self::RefMismatch { .. } => {
                Some(CodingAgentPhase::Materialize)
            }
            Self::EgressNotGoverned { .. } => Some(CodingAgentPhase::Bootstrap),
            Self::WriteBackNotAuthorized { .. } => Some(CodingAgentPhase::WriteBack),
            Self::EmptyWorkProduct => Some(CodingAgentPhase::Extract),
        }
    }
}

impl fmt::Display for CodingAgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest {
                phase,
                field,
                detail,
            } => write!(f, "{phase} request field {field} is invalid: {detail}"),
            Self::CredentialRejected { detail } => {
                write!(f, "repo credential rejected: {detail}")
            }
            Self::UnpinnedRef { detail } => write!(f, "ref is not pinned: {detail}"),
            Self::RefMismatch {
                requested,
                materialized,
            } => write!(
                f,
                "workspace materialized at {materialized} but {requested} was pinned"
            ),
            Self::EgressNotGoverned { detail } => {
                write!(f, "egress posture is not governed: {detail}")
            }
            Self::WriteBackNotAuthorized { code, detail } => {
                write!(f, "write-back not authorized ({code}): {detail}")
            }
            Self::EmptyWorkProduct => {
                f.write_str("run produced no change; there is no work product to extract")
            }
            Self::Unsupported { phase, capability } => {
                write!(f, "adapter does not support {capability} in phase {phase}")
            }
            Self::Backend { phase, detail } => write!(f, "{phase} failed: {detail}"),
        }
    }
}

impl Error for CodingAgentError {}
