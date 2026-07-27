// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: The two enforcement seams for the control-plane lifecycle
// `status` column (issue #514): request-time ("does an existing key stop
// working?") and attach-time ("can a suspended row still be referenced by a new
// child?"). Before this, `status` was decorative -- a test-gate audit plus a
// live probe confirmed that after suspending a tenant, its project and its
// workspace, every pre-existing virtual key still served `/v1/models` and
// `/v1/chat/completions`, and a brand-new virtual key could still be minted
// under the suspended chain. Suspension is a billing and abuse control; a
// control only the console honours is not a control.
//
// Both seams share ONE pure decision (`check_lifecycle_chain`) over ONE shared
// vocabulary (`ferrogate_storage::LifecycleStatus`), so every caller and every
// storage backend reaches the same verdict instead of each handler growing its
// own `status == "suspended"` test.

use http::StatusCode;

use ferrogate_storage::LifecycleStatus;

/// Which seam is asking. The two are separate because they answer different
/// questions and are reached by different code paths -- but they share the
/// vocabulary and the rejection shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LifecycleSeam {
    /// A credential is being used to serve a request. This is the seam that
    /// matters for billing: a suspended tenant must stop generating spend.
    Request,
    /// A new row is being created under, or pointed at, an existing hierarchy
    /// row. Without this, "suspend the tenant" is undone by minting a fresh
    /// key under it.
    Attach,
}

impl LifecycleSeam {
    fn allows(self, status: LifecycleStatus) -> bool {
        match self {
            Self::Request => status.allows_requests(),
            Self::Attach => status.allows_attach(),
        }
    }
}

/// One resolved ancestor in the `tenant -> project -> workspace` chain.
///
/// A reference whose row does NOT exist is simply absent from the chain: the
/// api-key tenancy rules already treat a dangling reference as "resolves to
/// nothing" rather than a rejection (see `ApiKeyTenancyOutcome::unresolved`),
/// and inventing a denial here would make a typo indistinguishable from a
/// suspension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LifecycleRef {
    /// `"tenant"`, `"project"` or `"workspace"` -- used verbatim in the
    /// rejection message.
    pub(crate) kind: &'static str,
    pub(crate) id: String,
    pub(crate) status: LifecycleStatus,
}

impl LifecycleRef {
    pub(crate) fn new(kind: &'static str, id: impl Into<String>, raw_status: &str) -> Self {
        Self {
            kind,
            id: id.into(),
            status: LifecycleStatus::parse(raw_status),
        }
    }
}

/// A typed refusal. Rendered as a 403 with a distinguishable, machine-readable
/// code -- never a panic, never a generic 500, and deliberately not a 404 (the
/// resource exists; the caller is simply not allowed to use it right now, and
/// hiding that would make "suspended" indistinguishable from "typo").
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LifecycleRejection {
    pub(crate) seam: LifecycleSeam,
    pub(crate) reference: LifecycleRef,
}

impl LifecycleRejection {
    pub(crate) fn status(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }

    /// Distinguishable per seam AND per state, so a client can tell "your
    /// account is suspended, pay the bill" from "you pointed a new key at a
    /// deleted workspace".
    pub(crate) fn code(&self) -> &'static str {
        match (self.seam, self.reference.status) {
            (LifecycleSeam::Request, LifecycleStatus::Suspended) => "tenancy_suspended",
            (LifecycleSeam::Request, LifecycleStatus::Disabled) => "tenancy_disabled",
            (LifecycleSeam::Request, LifecycleStatus::Deleted) => "tenancy_deleted",
            (LifecycleSeam::Attach, _) => "inactive_tenancy_reference",
            // Unreachable: an Active status never produces a rejection. Kept
            // total rather than `unreachable!()` so a future variant can never
            // turn this seam into a panic.
            (LifecycleSeam::Request, LifecycleStatus::Active) => "tenancy_inactive",
        }
    }

    pub(crate) fn message(&self) -> String {
        let LifecycleRef { kind, id, status } = &self.reference;
        match self.seam {
            LifecycleSeam::Request => format!(
                "{kind} {id} is {}; requests authenticated against this tenancy chain are refused",
                status.as_str()
            ),
            LifecycleSeam::Attach => format!(
                "{kind} {id} is {}; it cannot be referenced by a new resource",
                status.as_str()
            ),
        }
    }
}

/// THE decision, for both seams.
///
/// `chain` must be ordered shallowest-first (tenant, then project, then
/// workspace) so the rejection names the ROOT cause: when an operator suspends
/// a tenant and the cascade marks its project and workspace too, the caller is
/// told the tenant is suspended rather than being sent chasing the workspace.
pub(crate) fn check_lifecycle_chain(
    seam: LifecycleSeam,
    chain: &[LifecycleRef],
) -> Result<(), LifecycleRejection> {
    for reference in chain {
        if !seam.allows(reference.status) {
            return Err(LifecycleRejection {
                seam,
                reference: reference.clone(),
            });
        }
    }
    Ok(())
}

/// What a seam check can go wrong with. Storage being unreachable is NOT
/// silently treated as "active": it is a retryable 503, matching how
/// `finalize_auth` already surfaces a failed quota-policy lookup. Fail-open
/// here would hand every suspended tenant a trivial bypass (make the control
/// plane flap and keep serving).
#[derive(Debug)]
pub(crate) enum LifecycleGateError {
    Unavailable(String),
    Inactive(LifecycleRejection),
}

impl LifecycleGateError {
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Inactive(rejection) => rejection.status(),
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unavailable(_) => "lifecycle_status_unavailable",
            Self::Inactive(rejection) => rejection.code(),
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Unavailable(error) => format!("tenancy lifecycle lookup failed: {error}"),
            Self::Inactive(rejection) => rejection.message(),
        }
    }
}

impl From<LifecycleGateError> for crate::auth::AuthError {
    fn from(error: LifecycleGateError) -> Self {
        crate::auth::AuthError {
            status: error.status(),
            code: error.code(),
            message: error.message(),
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_gate_test.rs"]
mod lifecycle_gate_test;
