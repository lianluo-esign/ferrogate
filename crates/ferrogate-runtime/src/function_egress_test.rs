// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the fail-closed function egress allowlist (#117).

use super::*;

fn target(base: &str, slug: &str) -> SupabaseEdgeFunctionTarget {
    SupabaseEdgeFunctionTarget {
        base_url: base.to_string(),
        function_slug: slug.to_string(),
        auth_key_ref: "secret:svc".to_string(),
    }
}

fn allowlist() -> FunctionEgressAllowlist {
    FunctionEgressAllowlist::new(vec![
        FunctionEgressRule {
            tenant: "org_a".to_string(),
            base_url: "https://aaaa.supabase.co".to_string(),
            function_slugs: vec!["charge-credits".to_string(), "send-email".to_string()],
        },
        FunctionEgressRule {
            tenant: "org_b".to_string(),
            base_url: "https://bbbb.supabase.co".to_string(),
            function_slugs: vec![ANY_FUNCTION_SLUG.to_string()],
        },
    ])
}

#[test]
fn allows_exact_tenant_base_and_slug() {
    let list = allowlist();
    assert_eq!(
        list.authorize(
            "org_a",
            &target("https://aaaa.supabase.co", "charge-credits")
        ),
        Ok(())
    );
    // Trailing slash on the requested base is normalized to match.
    assert_eq!(
        list.authorize("org_a", &target("https://aaaa.supabase.co/", "send-email")),
        Ok(())
    );
}

#[test]
fn wildcard_slug_allows_any_function_under_base() {
    let list = allowlist();
    assert_eq!(
        list.authorize(
            "org_b",
            &target("https://bbbb.supabase.co", "anything-goes")
        ),
        Ok(())
    );
}

#[test]
fn denies_unknown_tenant_fail_closed() {
    let list = allowlist();
    assert_eq!(
        list.authorize(
            "org_ghost",
            &target("https://aaaa.supabase.co", "charge-credits")
        ),
        Err(FunctionEgressDenied::NoRuleForTenant(
            "org_ghost".to_string()
        ))
    );
    // An empty allowlist denies everyone.
    let empty = FunctionEgressAllowlist::default();
    assert!(empty.is_empty());
    assert!(matches!(
        empty.authorize(
            "org_a",
            &target("https://aaaa.supabase.co", "charge-credits")
        ),
        Err(FunctionEgressDenied::NoRuleForTenant(_))
    ));
}

#[test]
fn denies_non_listed_slug_and_base_for_known_tenant() {
    let list = allowlist();
    // Known tenant, allowed base, but slug not in the list.
    assert!(matches!(
        list.authorize(
            "org_a",
            &target("https://aaaa.supabase.co", "delete-everything")
        ),
        Err(FunctionEgressDenied::TargetNotAllowed { .. })
    ));
    // Known tenant, but a different project base than allowed.
    assert!(matches!(
        list.authorize(
            "org_a",
            &target("https://evil.supabase.co", "charge-credits")
        ),
        Err(FunctionEgressDenied::TargetNotAllowed { .. })
    ));
}

#[test]
fn cross_tenant_rule_does_not_leak() {
    let list = allowlist();
    // org_a must not be able to use org_b's allowlisted base.
    assert!(matches!(
        list.authorize("org_a", &target("https://bbbb.supabase.co", "anything")),
        Err(FunctionEgressDenied::TargetNotAllowed { .. })
    ));
}

#[test]
fn invalid_target_is_rejected_before_allowlist_match() {
    let list = allowlist();
    // http (insecure) base fails target validation even though the tenant exists.
    let denied = list
        .authorize(
            "org_a",
            &target("http://aaaa.supabase.co", "charge-credits"),
        )
        .unwrap_err();
    assert!(matches!(denied, FunctionEgressDenied::InvalidTarget(_)));
}

#[test]
fn invocation_request_defaults_method_to_post() {
    let json = r#"{"tenant":"org_a","target":{"base_url":"https://aaaa.supabase.co","function_slug":"charge-credits","auth_key_ref":"secret:svc"}}"#;
    let request: FunctionInvocationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.body_json, "");
    assert_eq!(request.target.function_slug, "charge-credits");
}
