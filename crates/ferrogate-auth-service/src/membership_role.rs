// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The four tenant-membership tiers (issue #517).
//!
//! `sql/001_init_postgres.sql` has advertised
//! `CHECK (role IN ('owner','admin','member','viewer'))` since the console
//! shipped, but the code implemented exactly two behaviours: `"owner"` and
//! *not* `"owner"`. Worse, the gateway virtual key minted for a console
//! session (`provision_gateway_api_key`) was a fixed
//! `admin.read + admin.write + assets.read + assets.write` grant for EVERY
//! session, so a user invited as `viewer` walked away with a key that could
//! mutate the control plane. This module makes the tier a real type, gives it
//! a scope ladder, and gives every write path a validator that does not depend
//! on a Postgres `CHECK` the D1 twin never had.

use std::fmt;
use std::str::FromStr;

/// A tenant membership tier. The string forms are exactly the four values the
/// Postgres `CHECK` constraint accepts, and parsing is **case-sensitive** on
/// purpose: the pre-#517 gates were literal `role != "owner"` comparisons, so
/// accepting `"Owner"` here would *grant* owner authority to a stored value
/// that is denied today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MembershipRole {
    /// Full tenant authority, including the team/RBAC/SSO/SCIM management
    /// endpoints. The only tier that passes the owner-only gates.
    Owner,
    /// Control-plane read+write, but not tenant administration.
    Admin,
    /// A working non-admin: reads the control plane, and may manage assets.
    Member,
    /// Read-only. Holds no `.write` scope of any kind.
    Viewer,
}

/// The error returned by [`MembershipRole::parse`] for a value outside the
/// accepted set. Carries the offending value so the caller can render a 4xx
/// that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidMembershipRole {
    value: String,
}

impl InvalidMembershipRole {
    /// The rejected value, verbatim.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for InvalidMembershipRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown role {:?}; must be one of {}",
            self.value,
            MembershipRole::accepted_values()
        )
    }
}

impl std::error::Error for InvalidMembershipRole {}

impl MembershipRole {
    /// Every tier, most privileged first.
    pub const ALL: [MembershipRole; 4] = [
        MembershipRole::Owner,
        MembershipRole::Admin,
        MembershipRole::Member,
        MembershipRole::Viewer,
    ];

    /// The canonical wire/storage string. Matches the Postgres `CHECK` set.
    pub fn as_str(self) -> &'static str {
        match self {
            MembershipRole::Owner => "owner",
            MembershipRole::Admin => "admin",
            MembershipRole::Member => "member",
            MembershipRole::Viewer => "viewer",
        }
    }

    /// Strict parse for **write paths** (invite, change-role, SCIM
    /// provisioning, SSO config). An unknown value is an error, never a
    /// silently-stored string and never a tier.
    pub fn parse(value: &str) -> Result<Self, InvalidMembershipRole> {
        match value {
            "owner" => Ok(MembershipRole::Owner),
            "admin" => Ok(MembershipRole::Admin),
            "member" => Ok(MembershipRole::Member),
            "viewer" => Ok(MembershipRole::Viewer),
            other => Err(InvalidMembershipRole {
                value: other.to_string(),
            }),
        }
    }

    /// Resolution for values ALREADY in storage (legacy rows, rows written
    /// before this validator existed, or rows written straight into a D1
    /// database that never carried the `CHECK`).
    ///
    /// **Fails closed by design**: an unrecognised value resolves to
    /// [`MembershipRole::Viewer`], the least-privileged tier, never to
    /// `Owner`. This is the dangerous-default guard called out in issue #517 —
    /// a typo'd or hostile role string must not be able to mint an
    /// `admin.write` key, and it must not pass [`Self::is_owner`]. The
    /// behaviour is identical to the pre-#517 gates for authorization
    /// purposes (anything that is not literally `"owner"` was already denied),
    /// but now it also caps what the session's gateway key can do.
    pub fn from_stored(value: &str) -> Self {
        Self::parse(value).unwrap_or(MembershipRole::Viewer)
    }

    /// The owner-only gate, replacing the literal `role != "owner"` compares.
    pub fn is_owner(self) -> bool {
        matches!(self, MembershipRole::Owner)
    }

    /// The scopes minted on this tier's console gateway virtual key
    /// (issue #517). The vocabulary is the gateway's own
    /// (`crates/ferrogate-cli/src/admin_api.rs`): `admin.read` / `admin.write`
    /// for the control plane, `assets.read` / `assets.write` for the asset
    /// APIs.
    ///
    /// The ladder is anchored on one fact: **`admin.write` is the
    /// self-escalation scope.** Any `admin.write` holder can call
    /// `POST /admin/v1/virtual-keys` and mint an arbitrarily-scoped key, so
    /// handing it to a non-administrative tier makes that tier meaningless.
    /// Hence:
    ///
    /// | tier   | scopes                                              |
    /// |--------|-----------------------------------------------------|
    /// | Owner  | `admin.read`, `admin.write`, `assets.read`, `assets.write` |
    /// | Admin  | `admin.read`, `admin.write`, `assets.read`, `assets.write` |
    /// | Member | `admin.read`, `assets.read`, `assets.write`          |
    /// | Viewer | `admin.read`, `assets.read`                          |
    ///
    /// `Owner` and `Admin` share a scope set: the difference between them is
    /// tenant administration (team/RBAC/SSO/SCIM management), which is gated
    /// in this service by [`Self::is_owner`] and is not expressible as a
    /// gateway scope. `Member` keeps `assets.write` — uploading assets is the
    /// working-but-not-administrative capability (#178's console feature) and
    /// does not confer control-plane mutation. `Viewer` holds **no `.write`
    /// scope at all**.
    pub fn gateway_api_key_scopes(self) -> Vec<String> {
        let scopes: &[&str] = match self {
            MembershipRole::Owner | MembershipRole::Admin => {
                &["admin.read", "admin.write", "assets.read", "assets.write"]
            }
            MembershipRole::Member => &["admin.read", "assets.read", "assets.write"],
            MembershipRole::Viewer => &["admin.read", "assets.read"],
        };
        scopes.iter().map(|scope| (*scope).to_string()).collect()
    }

    /// `owner, admin, member, viewer` — for error messages.
    pub fn accepted_values() -> String {
        Self::ALL
            .iter()
            .map(|role| role.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for MembershipRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MembershipRole {
    type Err = InvalidMembershipRole;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}
