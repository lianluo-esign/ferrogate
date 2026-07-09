// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-09
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Red-team regression: CVE-2025-53967-class egress-target escalation (#190).
//!
//! Companion to `managed_external_action_red_team_test.rs`. Where that file
//! proves the `CapabilityAction`-class boundary holds, this file proves the
//! second, independent fail-closed layer: a tenant legitimately authorized
//! to invoke ONE edge function at ONE base URL cannot pivot a brokered call
//! to a different function slug or a different project it was never
//! allowlisted for.
//!
//! `crates/ferrogate-cli/src/gateway/local.rs`'s `/v1/functions/execute`
//! handler calls `prepare_brokered_invocation`, which calls
//! `FunctionEgressAllowlist::authorize` first and, on
//! `Err(FunctionBrokerError::Denied(_))`, records an admin audit event with
//! outcome `"denied"` (via `record_admin_audit_event`) before any network
//! call is made. This test exercises `FunctionEgressAllowlist::authorize`
//! directly -- the fail-closed decision point -- and asserts the returned
//! evidence identifies exactly what was attempted.

use super::*;

fn target(base: &str, slug: &str) -> SupabaseEdgeFunctionTarget {
    SupabaseEdgeFunctionTarget {
        base_url: base.to_string(),
        function_slug: slug.to_string(),
        auth_key_ref: "secret:svc".to_string(),
    }
}

/// A tenant legitimately authorized for exactly one function, at one
/// project, matching a real narrow-scope deployment (e.g. a tool that is
/// only supposed to call `charge-credits`).
fn narrowly_scoped_allowlist() -> FunctionEgressAllowlist {
    FunctionEgressAllowlist::new(vec![FunctionEgressRule {
        tenant: "tenant-victim".to_string(),
        base_url: "https://legit-project.supabase.co".to_string(),
        function_slugs: vec!["charge-credits".to_string()],
    }])
}

#[test]
fn authorized_tenant_cannot_pivot_to_a_different_function_at_the_same_project() {
    // The attack: a compromised tool that legitimately obtained a scoped
    // token for `charge-credits` tries to reuse the same tenant identity to
    // invoke an unrelated, more dangerous function at the same project.
    let list = narrowly_scoped_allowlist();

    let error = list
        .authorize(
            "tenant-victim",
            &target("https://legit-project.supabase.co", "admin-delete-all-data"),
        )
        .expect_err("a non-allowlisted slug must be denied fail-closed");

    assert_eq!(
        error,
        FunctionEgressDenied::TargetNotAllowed {
            tenant: "tenant-victim".to_string(),
            base_url: "https://legit-project.supabase.co".to_string(),
            function_slug: "admin-delete-all-data".to_string(),
        }
    );
    // The evidence names exactly what was attempted, which is what
    // `local.rs` turns into the persisted audit message via `Display`.
    assert!(error.to_string().contains("admin-delete-all-data"));
}

#[test]
fn authorized_tenant_cannot_pivot_to_an_attacker_controlled_project() {
    // The attack: the same compromised tool tries to redirect the brokered
    // call to an entirely different (attacker-controlled) Supabase project,
    // hoping the gateway only checks the tenant identity and not the target.
    let list = narrowly_scoped_allowlist();

    let error = list
        .authorize(
            "tenant-victim",
            &target("https://attacker-project.supabase.co", "charge-credits"),
        )
        .expect_err("a non-allowlisted base URL must be denied fail-closed");

    assert_eq!(
        error,
        FunctionEgressDenied::TargetNotAllowed {
            tenant: "tenant-victim".to_string(),
            base_url: "https://attacker-project.supabase.co".to_string(),
            function_slug: "charge-credits".to_string(),
        }
    );
    assert!(error.to_string().contains("attacker-project.supabase.co"));
}

#[test]
fn unknown_tenant_is_denied_fail_closed_by_default_not_allowed() {
    // Baseline fail-closed proof: an unrecognized tenant (e.g. a forged or
    // stale identity) gets NoRuleForTenant, never a silent allow.
    let list = narrowly_scoped_allowlist();

    let error = list
        .authorize(
            "tenant-attacker",
            &target("https://legit-project.supabase.co", "charge-credits"),
        )
        .expect_err("an unlisted tenant must be denied fail-closed");

    assert_eq!(
        error,
        FunctionEgressDenied::NoRuleForTenant("tenant-attacker".to_string())
    );
}

#[test]
fn empty_allowlist_denies_every_target_fail_closed() {
    // Deny-by-default at the extreme: an empty policy (e.g. misconfiguration
    // or a not-yet-provisioned tenant) must reject everything, not fall back
    // to an implicit allow.
    let list = FunctionEgressAllowlist::new(vec![]);
    assert!(list.is_empty());

    let error = list
        .authorize(
            "tenant-victim",
            &target("https://legit-project.supabase.co", "charge-credits"),
        )
        .expect_err("an empty allowlist must deny fail-closed");

    assert_eq!(
        error,
        FunctionEgressDenied::NoRuleForTenant("tenant-victim".to_string())
    );
}
