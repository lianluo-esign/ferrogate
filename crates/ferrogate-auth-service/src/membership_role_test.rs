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
    // Pinned separately by `the_tier_set_matches_the_sql_check_constraint`;
    // the loop below iterates ALL, so on its own it self-adjusts to any
    // number of variants and proves nothing about the SET.
    for role in MembershipRole::ALL {
        assert_eq!(MembershipRole::parse(role.as_str()), Ok(role));
        assert_eq!(MembershipRole::from_str(role.as_str()), Ok(role));
        assert_eq!(role.to_string(), role.as_str());
    }
}

/// The migration files this crate's enum has to agree with. Read from disk
/// at compile time so the coupling below cannot drift into a hand-copied
/// literal that stops tracking the schema.
const POSTGRES_MIGRATION_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");
const D1_MIGRATION_SQL: &str = include_str!("../../../sql/d1/001_init_d1.sql");

/// Extracts the value list from
/// `role TEXT NOT NULL CHECK (role IN ('owner', 'admin', ...))` on
/// `admin_user_tenant_memberships`, in declaration order.
fn membership_role_check_domain(sql: &str, dialect: &str) -> Vec<String> {
    let table = sql
        .split("CREATE TABLE IF NOT EXISTS admin_user_tenant_memberships")
        .nth(1)
        .unwrap_or_else(|| panic!("{dialect} migration must define admin_user_tenant_memberships"))
        .split(");")
        .next()
        .unwrap();
    let list = table
        .split("CHECK (role IN (")
        .nth(1)
        .unwrap_or_else(|| {
            panic!("{dialect} admin_user_tenant_memberships.role must carry a CHECK (role IN ...)")
        })
        .split(')')
        .next()
        .unwrap();
    list.split(',')
        .map(|value| value.trim().trim_matches('\'').to_string())
        .collect()
}

/// Issue #517, review finding 5. `parse_accepts_exactly_the_four_declared_
/// tiers` used to carry the comment "the set matches the Postgres CHECK
/// constraint exactly" while asserting nothing of the kind: it iterates
/// `MembershipRole::ALL`, so adding a fifth variant left it green, and
/// `parse_rejects_anything_outside_the_set` only checks a FIXED reject list
/// (its `error.to_string().contains("owner, admin, member, viewer")` also
/// still matches a longer joined string). A fifth variant would therefore
/// ship silently, `parse("support")` would return `Ok`, D1 would store it,
/// and Postgres would 500 on the INSERT.
///
/// This is the coupling: the enum IS the CHECK domain, in both dialects,
/// in order, with nothing extra on either side. Adding, removing, renaming
/// or reordering a variant now fails here until the migrations agree.
#[test]
fn the_tier_set_matches_the_sql_check_constraint() {
    let declared: Vec<String> = MembershipRole::ALL
        .iter()
        .map(|role| role.as_str().to_string())
        .collect();
    // Belt and braces: the arity is asserted outright, so a fifth variant
    // cannot hide behind a parser change either.
    assert_eq!(
        MembershipRole::ALL.len(),
        4,
        "the tier set is fixed at four; a new tier needs a migration that \
         widens the CHECK constraint on admin_user_tenant_memberships.role \
         in EVERY dialect first"
    );
    assert_eq!(declared, ["owner", "admin", "member", "viewer"]);

    for (dialect, sql) in [
        ("postgres", POSTGRES_MIGRATION_SQL),
        ("d1", D1_MIGRATION_SQL),
    ] {
        let domain = membership_role_check_domain(sql, dialect);
        assert_eq!(
            domain, declared,
            "MembershipRole::ALL and the {dialect} CHECK domain must be the \
             same set in the same order; enum={declared:?} sql={domain:?}"
        );
        // ... and every value the schema accepts must round-trip through
        // the strict parser, so the two can never agree as strings while
        // disagreeing on behaviour.
        for value in &domain {
            let parsed = MembershipRole::parse(value)
                .unwrap_or_else(|_| panic!("{dialect} accepts {value:?} but parse() rejects it"));
            assert_eq!(parsed.as_str(), value);
        }
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
