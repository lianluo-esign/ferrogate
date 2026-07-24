// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the Cloudflare Worker hosted-function invocation entry (#416).
//! Test parity with `supabase_edge_function_test.rs`, plus governed-egress and
//! scoped-token pipeline coverage proving the Worker path clears the exact
//! same fail-closed gates as the Supabase path.

use super::*;
use crate::function_egress::{FunctionEgressRule, ANY_FUNCTION_SLUG};
use crate::function_token::DEFAULT_FUNCTION_TOKEN_TTL_SECS;

fn target() -> CloudflareWorkerTarget {
    CloudflareWorkerTarget {
        base_url: "https://tool-runner.acme.workers.dev".to_string(),
        invoke_path: "charge-credits".to_string(),
        auth_key_ref: "secret:worker-bearer".to_string(),
    }
}

#[test]
fn invocation_url_joins_base_and_invoke_path() {
    assert_eq!(
        target().invocation_url(),
        "https://tool-runner.acme.workers.dev/charge-credits"
    );
    // Trailing slash on base_url is normalized.
    let mut t = target();
    t.base_url = "https://tool-runner.acme.workers.dev/".to_string();
    assert_eq!(
        t.invocation_url(),
        "https://tool-runner.acme.workers.dev/charge-credits"
    );
    // A custom-domain route base works the same way.
    let mut custom = target();
    custom.base_url = "https://functions.example.com".to_string();
    assert_eq!(
        custom.invocation_url(),
        "https://functions.example.com/charge-credits"
    );
}

#[test]
fn validation_fails_closed() {
    assert_eq!(target().validate(), Ok(()));

    let mut insecure = target();
    insecure.base_url = "http://tool-runner.acme.workers.dev".to_string();
    assert!(matches!(
        insecure.validate(),
        Err(CloudflareWorkerTargetError::InsecureBaseUrl(_))
    ));

    let mut empty = target();
    empty.base_url = "   ".to_string();
    assert_eq!(
        empty.validate(),
        Err(CloudflareWorkerTargetError::EmptyBaseUrl)
    );

    for bad in [
        "../secrets",
        "a/b",
        "with space",
        "path?x=1",
        "path#frag",
        "",
    ] {
        let mut t = target();
        t.invoke_path = bad.to_string();
        assert!(
            matches!(
                t.validate(),
                Err(CloudflareWorkerTargetError::InvalidInvokePath(_))
            ),
            "invoke_path {bad:?} must be rejected"
        );
    }

    let mut no_ref = target();
    no_ref.auth_key_ref = "".to_string();
    assert_eq!(
        no_ref.validate(),
        Err(CloudflareWorkerTargetError::EmptyAuthKeyRef)
    );
}

#[test]
fn build_http_request_injects_bearer_for_static_key_credential() {
    let invocation = CloudflareWorkerInvocation::post(target(), r#"{"amount":10}"#);
    let request = invocation
        .build_http_request(&FunctionCredential::static_key("sk-resolved-key"))
        .unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(
        request.url,
        "https://tool-runner.acme.workers.dev/charge-credits"
    );
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer sk-resolved-key")
    );
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    // Workers have no Supabase apikey concept; the header must not be emitted.
    assert!(!request.headers.contains_key("apikey"));
    assert_eq!(request.body, r#"{"amount":10}"#);
}

#[test]
fn build_http_request_injects_bearer_for_scoped_token_credential() {
    let invocation = CloudflareWorkerInvocation::post(target(), "{}");
    let request = invocation
        .build_http_request(&FunctionCredential::scoped_token("scoped.jwt.token", ""))
        .unwrap();
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer scoped.jwt.token")
    );
    assert!(!request.headers.contains_key("apikey"));
}

#[test]
fn build_http_request_rejects_empty_bearer_and_bad_method() {
    let invocation = CloudflareWorkerInvocation::post(target(), "{}");
    assert_eq!(
        invocation.build_http_request(&FunctionCredential::static_key("   ")),
        Err(CloudflareWorkerTargetError::EmptyResolvedBearer)
    );
    assert_eq!(
        invocation.build_http_request(&FunctionCredential::scoped_token("  ", "apikey")),
        Err(CloudflareWorkerTargetError::EmptyResolvedBearer)
    );

    let mut bad_method = CloudflareWorkerInvocation::post(target(), "{}");
    bad_method.method = "DELETE".to_string();
    assert!(matches!(
        bad_method.build_http_request(&FunctionCredential::static_key("k")),
        Err(CloudflareWorkerTargetError::UnsupportedMethod(_))
    ));
}

#[test]
fn invocation_request_defaults_method_to_post() {
    let json = r#"{"tenant":"org_a","target":{"base_url":"https://tool-runner.acme.workers.dev","invoke_path":"charge-credits","auth_key_ref":"secret:worker-bearer"}}"#;
    let request: WorkerInvocationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.method, "POST");
    assert_eq!(request.body_json, "");
    assert_eq!(request.target.invoke_path, "charge-credits");
}

// --- Egress allowlist parity: one allowlist governs Worker targets too. ---

fn allowlist() -> FunctionEgressAllowlist {
    FunctionEgressAllowlist::new(vec![
        FunctionEgressRule {
            tenant: "org_a".to_string(),
            base_url: "https://tool-runner.acme.workers.dev".to_string(),
            function_slugs: vec!["charge-credits".to_string(), "send-email".to_string()],
        },
        FunctionEgressRule {
            tenant: "org_b".to_string(),
            base_url: "https://anything.acme.workers.dev".to_string(),
            function_slugs: vec![ANY_FUNCTION_SLUG.to_string()],
        },
    ])
}

fn worker(base: &str, path: &str) -> CloudflareWorkerTarget {
    CloudflareWorkerTarget {
        base_url: base.to_string(),
        invoke_path: path.to_string(),
        auth_key_ref: "secret:worker-bearer".to_string(),
    }
}

#[test]
fn allowlist_allows_exact_tenant_base_and_path() {
    let list = allowlist();
    assert_eq!(
        list.authorize_cloudflare_worker(
            "org_a",
            &worker("https://tool-runner.acme.workers.dev", "charge-credits")
        ),
        Ok(())
    );
    // Trailing slash on the requested base is normalized to match.
    assert_eq!(
        list.authorize_cloudflare_worker(
            "org_a",
            &worker("https://tool-runner.acme.workers.dev/", "send-email")
        ),
        Ok(())
    );
}

#[test]
fn allowlist_wildcard_allows_any_path_under_base() {
    let list = allowlist();
    assert_eq!(
        list.authorize_cloudflare_worker(
            "org_b",
            &worker("https://anything.acme.workers.dev", "anything-goes")
        ),
        Ok(())
    );
}

#[test]
fn allowlist_denies_unknown_tenant_and_empty_list_fail_closed() {
    let list = allowlist();
    assert_eq!(
        list.authorize_cloudflare_worker(
            "org_ghost",
            &worker("https://tool-runner.acme.workers.dev", "charge-credits")
        ),
        Err(FunctionEgressDenied::NoRuleForTenant(
            "org_ghost".to_string()
        ))
    );
    let empty = FunctionEgressAllowlist::default();
    assert!(matches!(
        empty.authorize_cloudflare_worker(
            "org_a",
            &worker("https://tool-runner.acme.workers.dev", "charge-credits")
        ),
        Err(FunctionEgressDenied::NoRuleForTenant(_))
    ));
}

#[test]
fn allowlist_denies_non_listed_path_base_and_cross_tenant_pivot() {
    let list = allowlist();
    // Known tenant, allowed base, but path not in the list.
    assert_eq!(
        list.authorize_cloudflare_worker(
            "org_a",
            &worker("https://tool-runner.acme.workers.dev", "delete-everything")
        ),
        Err(FunctionEgressDenied::TargetNotAllowed {
            tenant: "org_a".to_string(),
            base_url: "https://tool-runner.acme.workers.dev".to_string(),
            function_slug: "delete-everything".to_string(),
        })
    );
    // Known tenant, but an attacker-controlled Worker host.
    assert!(matches!(
        list.authorize_cloudflare_worker(
            "org_a",
            &worker("https://evil.attacker.workers.dev", "charge-credits")
        ),
        Err(FunctionEgressDenied::TargetNotAllowed { .. })
    ));
    // org_a must not be able to use org_b's allowlisted base.
    assert!(matches!(
        list.authorize_cloudflare_worker(
            "org_a",
            &worker("https://anything.acme.workers.dev", "anything")
        ),
        Err(FunctionEgressDenied::TargetNotAllowed { .. })
    ));
}

#[test]
fn allowlist_rejects_invalid_worker_target_before_rule_match() {
    let list = allowlist();
    let denied = list
        .authorize_cloudflare_worker(
            "org_a",
            &worker("http://tool-runner.acme.workers.dev", "charge-credits"),
        )
        .unwrap_err();
    assert!(matches!(
        denied,
        FunctionEgressDenied::InvalidWorkerTarget(CloudflareWorkerTargetError::InsecureBaseUrl(_))
    ));
}

// --- Governed broker pipeline: allowlist + scoped-token minting composed. ---

fn minter() -> FunctionTokenMinter {
    FunctionTokenMinter::new("ferrogate", "worker-signing-secret").unwrap()
}

fn invocation_request(base: &str, path: &str) -> WorkerInvocationRequest {
    WorkerInvocationRequest {
        tenant: "org_a".to_string(),
        target: worker(base, path),
        method: "POST".to_string(),
        body_json: r#"{"amount":10}"#.to_string(),
    }
}

#[test]
fn governed_pipeline_mints_scoped_token_and_builds_request() {
    let request = invocation_request("https://tool-runner.acme.workers.dev", "charge-credits");
    let prepared = prepare_governed_worker_invocation(
        &allowlist(),
        &minter(),
        "org_a",
        &request,
        1_700_000_000,
        DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    )
    .unwrap();

    assert_eq!(prepared.invoke_path, "charge-credits");
    assert_eq!(
        prepared.timeout_millis,
        DEFAULT_WORKER_INVOCATION_TIMEOUT_MILLIS
    );
    assert_eq!(prepared.http_request.method, "POST");
    assert_eq!(
        prepared.http_request.url,
        "https://tool-runner.acme.workers.dev/charge-credits"
    );
    assert!(!prepared.http_request.headers.contains_key("apikey"));

    // The Authorization header carries a verifiable scoped token bound to the
    // tenant + invoke path + shared function capability.
    let bearer = prepared
        .http_request
        .headers
        .get("authorization")
        .unwrap()
        .strip_prefix("Bearer ")
        .unwrap();
    let claims = minter().verify(bearer, 1_700_000_000).unwrap();
    assert_eq!(claims.iss, "ferrogate");
    assert_eq!(claims.aud, "charge-credits");
    assert_eq!(claims.tenant, "org_a");
    assert_eq!(claims.capability, WORKER_FUNCTION_CAPABILITY);
    assert_eq!(claims.exp, 1_700_000_000 + DEFAULT_FUNCTION_TOKEN_TTL_SECS);
}

#[test]
fn governed_pipeline_denies_before_minting_fail_closed() {
    // Non-allowlisted path: denied by the same egress gate as Supabase calls.
    let request = invocation_request("https://tool-runner.acme.workers.dev", "delete-everything");
    let error = prepare_governed_worker_invocation(
        &allowlist(),
        &minter(),
        "org_a",
        &request,
        1_700_000_000,
        DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        WorkerBrokerError::Denied(FunctionEgressDenied::TargetNotAllowed { .. })
    ));

    // Unknown tenant: deny-by-default.
    let request = invocation_request("https://tool-runner.acme.workers.dev", "charge-credits");
    let error = prepare_governed_worker_invocation(
        &allowlist(),
        &minter(),
        "org_ghost",
        &request,
        1_700_000_000,
        DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        WorkerBrokerError::Denied(FunctionEgressDenied::NoRuleForTenant(_))
    ));

    // Invalid (http) target: rejected before any rule match or token mint.
    let request = invocation_request("http://tool-runner.acme.workers.dev", "charge-credits");
    let error = prepare_governed_worker_invocation(
        &allowlist(),
        &minter(),
        "org_a",
        &request,
        1_700_000_000,
        DEFAULT_FUNCTION_TOKEN_TTL_SECS,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        WorkerBrokerError::Denied(FunctionEgressDenied::InvalidWorkerTarget(_))
    ));
}

#[test]
fn governed_pipeline_propagates_token_ttl_errors() {
    let request = invocation_request("https://tool-runner.acme.workers.dev", "charge-credits");
    let error = prepare_governed_worker_invocation(
        &allowlist(),
        &minter(),
        "org_a",
        &request,
        1_700_000_000,
        0,
    )
    .unwrap_err();
    assert!(matches!(error, WorkerBrokerError::Token(_)));
}
