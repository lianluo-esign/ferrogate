// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the Supabase edge-function invocation entry (#115).

use super::*;

fn target() -> SupabaseEdgeFunctionTarget {
    SupabaseEdgeFunctionTarget {
        base_url: "https://abcdefgh.supabase.co".to_string(),
        function_slug: "charge-credits".to_string(),
        auth_key_ref: "secret:service-role".to_string(),
    }
}

#[test]
fn invocation_url_uses_functions_v1_path() {
    assert_eq!(
        target().invocation_url(),
        "https://abcdefgh.supabase.co/functions/v1/charge-credits"
    );
    // Trailing slash on base_url is normalized.
    let mut t = target();
    t.base_url = "https://abcdefgh.supabase.co/".to_string();
    assert_eq!(
        t.invocation_url(),
        "https://abcdefgh.supabase.co/functions/v1/charge-credits"
    );
}

#[test]
fn validation_fails_closed() {
    assert_eq!(target().validate(), Ok(()));

    let mut insecure = target();
    insecure.base_url = "http://abcdefgh.supabase.co".to_string();
    assert!(matches!(
        insecure.validate(),
        Err(SupabaseEdgeFunctionError::InsecureBaseUrl(_))
    ));

    let mut empty = target();
    empty.base_url = "   ".to_string();
    assert_eq!(
        empty.validate(),
        Err(SupabaseEdgeFunctionError::EmptyBaseUrl)
    );

    for bad in [
        "../secrets",
        "a/b",
        "with space",
        "slug?x=1",
        "slug#frag",
        "",
    ] {
        let mut t = target();
        t.function_slug = bad.to_string();
        assert!(
            matches!(t.validate(), Err(SupabaseEdgeFunctionError::InvalidSlug(_))),
            "slug {bad:?} must be rejected"
        );
    }

    let mut no_ref = target();
    no_ref.auth_key_ref = "".to_string();
    assert_eq!(
        no_ref.validate(),
        Err(SupabaseEdgeFunctionError::EmptyAuthKeyRef)
    );
}

#[test]
fn build_http_request_injects_auth_and_apikey_headers() {
    let invocation = SupabaseEdgeFunctionInvocation::post(target(), r#"{"amount":10}"#);
    let request = invocation
        .build_http_request(&FunctionCredential::static_key("sk-resolved-key"))
        .unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(
        request.url,
        "https://abcdefgh.supabase.co/functions/v1/charge-credits"
    );
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer sk-resolved-key")
    );
    assert_eq!(
        request.headers.get("apikey").map(String::as_str),
        Some("sk-resolved-key")
    );
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(request.body, r#"{"amount":10}"#);
}

#[test]
fn build_http_request_rejects_empty_resolved_key_and_bad_method() {
    let invocation = SupabaseEdgeFunctionInvocation::post(target(), "{}");
    assert_eq!(
        invocation.build_http_request(&FunctionCredential::static_key("   ")),
        Err(SupabaseEdgeFunctionError::EmptyResolvedKey)
    );
    // A scoped token with an empty apikey is also unusable.
    assert_eq!(
        invocation.build_http_request(&FunctionCredential::scoped_token("jwt", "  ")),
        Err(SupabaseEdgeFunctionError::EmptyResolvedKey)
    );

    let mut bad_method = SupabaseEdgeFunctionInvocation::post(target(), "{}");
    bad_method.method = "DELETE".to_string();
    assert!(matches!(
        bad_method.build_http_request(&FunctionCredential::static_key("k")),
        Err(SupabaseEdgeFunctionError::UnsupportedMethod(_))
    ));
}
