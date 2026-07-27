// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: The one place that interprets the `status` column shared by
// `tenant_accounts`, `projects` and `workspaces` (issue #514). Before this,
// `status` was a decorative string: the admin API wrote `"suspended"`, the
// console rendered it, and NOTHING in the request or attach path ever compared
// it -- so a suspended tenant's keys kept authenticating and fresh credentials
// could still be minted under the suspended chain. Parsing lives here, in the
// crate that owns the rows, so every storage backend and every caller reaches
// the same verdict instead of scattering `status == "active"` string tests.

/// The lifecycle state of a control-plane hierarchy row (tenant account,
/// project, workspace).
///
/// The vocabulary is deliberately closed: the admin API and the console only
/// ever write these four tokens. Anything else -- including an empty string, a
/// NULL that deserialized into `""`, or a token from a newer/older schema -- is
/// [`LifecycleStatus::Active`]. That default is load-bearing and is NOT an
/// oversight: these columns were purely decorative until #514, so rows written
/// before this landed (and rows written by any path that omits `status`) carry
/// arbitrary or empty values. Failing closed on them would revoke every
/// pre-existing tenant's traffic the moment this code shipped, which is a
/// far larger outage than the abuse window it would close. Denial is opt-in:
/// an operator must have explicitly written `suspended`/`disabled`/`deleted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleStatus {
    /// Normal, fully usable. Also the verdict for absent/unrecognized values.
    Active,
    /// Reversible, operator- or billing-driven stop. The row and its children
    /// keep existing and can be reactivated; they just may not be used.
    Suspended,
    /// Reversible, operator-driven off switch (the tenant's own "turn this
    /// project off" rather than the platform's billing action).
    Disabled,
    /// Soft delete. The row is retained for audit/restore but must behave as
    /// though it is gone.
    Deleted,
}

impl LifecycleStatus {
    /// Interprets a raw `status` column value. Case- and whitespace-insensitive
    /// because the column is free-form `TEXT` on every backend.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "suspended" => Self::Suspended,
            "disabled" => Self::Disabled,
            "deleted" => Self::Deleted,
            // "active", "", and every unrecognized token. See the type docs:
            // legacy/absent rows must keep working.
            _ => Self::Active,
        }
    }

    /// The canonical token, for error messages and audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Request-time seam: may a credential whose tenancy chain contains a row
    /// in this state still serve traffic?
    ///
    /// This is the seam that matters for billing and abuse: suspension exists
    /// precisely so that an unpaid or compromised tenant STOPS generating
    /// upstream spend. All three non-active states deny. They are kept as
    /// distinct variants (rather than collapsed into a bool) so the rejection
    /// can name the actual state and so a future policy can diverge without
    /// re-deriving the vocabulary.
    pub fn allows_requests(self) -> bool {
        self.is_active()
    }

    /// Attach-time seam: may a NEW child row (project, workspace, api key,
    /// virtual key) be created under, or pointed at, a row in this state?
    ///
    /// Denies for the same three states. Minting a fresh credential under a
    /// suspended chain is the exact escalation the live probe demonstrated:
    /// without this, "suspend the tenant" is trivially undone by anyone who can
    /// call the admin API.
    pub fn allows_attach(self) -> bool {
        self.is_active()
    }
}

#[cfg(test)]
#[path = "lifecycle_status_test.rs"]
mod lifecycle_status_test;
