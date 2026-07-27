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

    /// The WRITE-side counterpart to [`LifecycleStatus::parse`]: `None` for
    /// anything outside the closed vocabulary.
    ///
    /// The read-side fail-open above is right for rows that already exist, but
    /// paired with an unvalidated write it re-created the exact failure this
    /// issue exists to kill: `PUT .../tenant-accounts/{id} {"status":"suspend"}`
    /// (note the missing `-ed`) answered `200 OK`, the console rendered
    /// `suspend`, and the tenant kept serving -- a green confirmation for a
    /// control that was never applied. Admin write handlers reject the token
    /// here, at the boundary, so an operator learns immediately; nothing that
    /// is already in the database is affected.
    pub fn parse_strict(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "disabled" => Some(Self::Disabled),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }

    /// Every token a write handler will accept, for the rejection message and
    /// the OpenAPI enum.
    pub const ALL: [Self; 4] = [Self::Active, Self::Suspended, Self::Disabled, Self::Deleted];

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

    /// Recovery seam: may a credential whose tenancy chain contains a row in
    /// this state still reach the handful of requests that exist to turn the
    /// hierarchy back ON (the lifecycle `status` PUT/PATCH routes, and the
    /// admin-console session key those routes are called with)?
    ///
    /// [`LifecycleStatus::Disabled`] is documented right above as the TENANT's
    /// own "turn this project off" switch, as distinct from the platform's
    /// billing action. If the request-time seam denied it everywhere, it would
    /// be a one-way door: the console key a tenant holds is scoped to its
    /// project, so disabling that project would revoke the very credential
    /// needed to re-enable it, and a self-service toggle would require a
    /// support ticket to undo. So `disabled` is admitted here and ONLY here.
    ///
    /// `suspended` and `deleted` still deny. Both are platform-operator
    /// actions; reversing them is meant to require an operator key, which
    /// carries no tenancy chain and is therefore never gated at all. Letting a
    /// suspended tenant reach its own status PUT would make suspension
    /// self-serviceable, i.e. not a control.
    pub fn allows_recovery(self) -> bool {
        matches!(self, Self::Active | Self::Disabled)
    }
}

#[cfg(test)]
#[path = "lifecycle_status_test.rs"]
mod lifecycle_status_test;
