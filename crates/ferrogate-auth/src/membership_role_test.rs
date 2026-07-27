// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the four membership tiers and the role -> gateway-scope
//! ladder (issue #517).

use super::MembershipRole;
use std::str::FromStr;

/// THE per-tier assertion the issue asks for: each tier's minted scope set,
/// spelled out. Flattening the ladder (e.g. giving every tier the owner set)
/// makes three of these four assertions fail.
#[test]
fn each_tier_mints_its_own_gateway_scope_set() {
    assert_eq!(
        MembershipRole::Owner.gateway_api_key_scopes(),
        ["admin.read", "admin.write", "assets.read", "assets.write"]
    );
    assert_eq!(
        MembershipRole::Admin.gateway_api_key_scopes(),
        ["admin.read", "admin.write", "assets.read", "assets.write"]
    );
    assert_eq!(
        MembershipRole::Member.gateway_api_key_scopes(),
        ["admin.read", "assets.read", "assets.write"]
    );
    assert_eq!(
        MembershipRole::Viewer.gateway_api_key_scopes(),
        ["admin.read", "assets.read"]
    );
}

/// The invariant behind the ladder, stated independently of the exact lists
/// above so it survives a future scope being added: `admin.write` is the
/// self-escalation scope (any holder can mint an arbitrarily-scoped key via
/// `POST /admin/v1/virtual-keys`), so ONLY the two administrative tiers may
/// hold it, and a viewer holds no `.write` scope whatsoever.
#[test]
fn admin_write_is_reserved_for_the_administrative_tiers() {
    for role in MembershipRole::ALL {
        let scopes = role.gateway_api_key_scopes();
        let has_admin_write = scopes.iter().any(|scope| scope == "admin.write");
        assert_eq!(
            has_admin_write,
            matches!(role, MembershipRole::Owner | MembershipRole::Admin),
            "{role} must {} admin.write",
            if matches!(role, MembershipRole::Owner | MembershipRole::Admin) {
                "hold"
            } else {
                "not hold"
            }
        );
    }
    assert!(
        !MembershipRole::Viewer
            .gateway_api_key_scopes()
            .iter()
            .any(|scope| scope.ends_with(".write")),
        "a viewer must hold no .write scope of any kind"
    );
    // Every minted scope is drawn from the gateway's own vocabulary
    // (crates/ferrogate-cli/src/admin_api.rs) -- a typo'd scope would be a
    // silently-inert grant.
    for role in MembershipRole::ALL {
        for scope in role.gateway_api_key_scopes() {
            assert!(
                ["admin.read", "admin.write", "assets.read", "assets.write"]
                    .contains(&scope.as_str()),
                "{role} mints unknown scope {scope}"
            );
        }
    }
}

/// Every tier is a distinct grant except the two administrative ones, which
/// share a scope set by design (their difference is the owner-only management
/// gate, which is not expressible as a gateway scope). A flattened map
/// collapses these distinctions.
#[test]
fn the_ladder_is_strictly_decreasing() {
    let owner = MembershipRole::Owner.gateway_api_key_scopes();
    let admin = MembershipRole::Admin.gateway_api_key_scopes();
    let member = MembershipRole::Member.gateway_api_key_scopes();
    let viewer = MembershipRole::Viewer.gateway_api_key_scopes();

    assert_eq!(owner, admin, "owner and admin share a scope set by design");
    assert!(
        member.len() < admin.len() && member.iter().all(|scope| admin.contains(scope)),
        "member must be a strict subset of admin: {member:?} vs {admin:?}"
    );
    assert!(
        viewer.len() < member.len() && viewer.iter().all(|scope| member.contains(scope)),
        "viewer must be a strict subset of member: {viewer:?} vs {member:?}"
    );
}

#[test]
fn parse_accepts_exactly_the_four_declared_tiers() {
    assert_eq!(MembershipRole::parse("owner"), Ok(MembershipRole::Owner));
    assert_eq!(MembershipRole::parse("admin"), Ok(MembershipRole::Admin));
    assert_eq!(MembershipRole::parse("member"), Ok(MembershipRole::Member));
    assert_eq!(MembershipRole::parse("viewer"), Ok(MembershipRole::Viewer));
    // The set matches the Postgres CHECK constraint exactly.
    for role in MembershipRole::ALL {
        assert_eq!(MembershipRole::parse(role.as_str()), Ok(role));
        assert_eq!(MembershipRole::from_str(role.as_str()), Ok(role));
        assert_eq!(role.to_string(), role.as_str());
    }
}

#[test]
fn parse_rejects_anything_outside_the_set() {
    for value in [
        "",
        " ",
        "superuser",
        "root",
        "owners",
        "Owner",
        "OWNER",
        "owner ",
        "owner,admin",
        "admin.write",
    ] {
        let error = MembershipRole::parse(value)
            .expect_err(&format!("{value:?} must not parse as a membership role"));
        assert_eq!(error.value(), value);
        assert!(
            error.to_string().contains("owner, admin, member, viewer"),
            "the error must name the accepted set: {error}"
        );
    }
}

/// The dangerous default, pinned: an unparseable / legacy / hostile stored
/// role resolves DOWN to the least privilege, never up to owner. If
/// `from_stored` ever defaults to `Owner` (or to any tier holding
/// `admin.write`), this fails.
#[test]
fn an_unknown_stored_role_fails_closed_to_the_least_privilege() {
    for value in ["", "superuser", "root", "Owner", "OWNER", "owner "] {
        let resolved = MembershipRole::from_stored(value);
        assert_eq!(
            resolved,
            MembershipRole::Viewer,
            "{value:?} must resolve to the least privilege, got {resolved}"
        );
        assert!(
            !resolved.is_owner(),
            "{value:?} must not pass the owner gate"
        );
        assert!(
            !resolved
                .gateway_api_key_scopes()
                .iter()
                .any(|scope| scope.ends_with(".write")),
            "{value:?} must not be able to mint a .write scope"
        );
    }
    // ... and a legitimate stored value still round-trips.
    for role in MembershipRole::ALL {
        assert_eq!(MembershipRole::from_stored(role.as_str()), role);
    }
}

/// `is_owner` must be exactly as tight as the literal `role != "owner"`
/// compares it replaced -- no case folding, no trimming, no aliases.
#[test]
fn is_owner_matches_the_literal_owner_string_only() {
    assert!(MembershipRole::from_stored("owner").is_owner());
    for role in [
        MembershipRole::Admin,
        MembershipRole::Member,
        MembershipRole::Viewer,
    ] {
        assert!(!role.is_owner(), "{role} must not pass the owner gate");
    }
    for value in ["Owner", "OWNER", " owner", "owner ", "0wner", "admin"] {
        assert!(
            !MembershipRole::from_stored(value).is_owner(),
            "{value:?} must not pass the owner gate"
        );
    }
}
