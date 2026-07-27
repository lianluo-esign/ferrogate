// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit tests for the token-resolver seam; kept out of the business-logic file.

use crate::error::CloudflareError;
use crate::resolver::{EnvTokenResolver, TokenResolver};

fn resolver_with(entries: &'static [(&'static str, &'static str)]) -> EnvTokenResolver {
    EnvTokenResolver::with_env_lookup(move |name| {
        entries
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_string())
    })
}

#[test]
fn resolves_env_reference_from_injected_environment() {
    let resolver = resolver_with(&[("CF_API_TOKEN", "secret-abc")]);
    let token = resolver.resolve("env://CF_API_TOKEN").unwrap();
    assert_eq!(token.expose(), "secret-abc");
}

#[test]
fn missing_env_variable_is_a_typed_error() {
    let resolver = resolver_with(&[]);
    let err = resolver.resolve("env://CF_API_TOKEN").unwrap_err();
    match err {
        CloudflareError::TokenResolution(msg) => assert!(msg.contains("CF_API_TOKEN")),
        other => panic!("expected TokenResolution, got {other:?}"),
    }
}

#[test]
fn empty_env_variable_is_rejected() {
    let resolver = resolver_with(&[("CF_API_TOKEN", "   ")]);
    let err = resolver.resolve("env://CF_API_TOKEN").unwrap_err();
    assert!(
        matches!(err, CloudflareError::TokenResolution(_)),
        "got {err:?}"
    );
}

#[test]
fn env_reference_without_name_is_rejected() {
    let resolver = EnvTokenResolver::with_env_lookup(|_| None);
    let err = resolver.resolve("env://").unwrap_err();
    assert!(
        matches!(err, CloudflareError::TokenResolution(_)),
        "got {err:?}"
    );
}

#[test]
fn plaintext_reference_passes_through() {
    let resolver = EnvTokenResolver::with_env_lookup(|_| None);
    let token = resolver.resolve("inline-plaintext-token").unwrap();
    assert_eq!(token.expose(), "inline-plaintext-token");
}

/// `cf://` is a **permanent crate boundary**, not a deferral (issue #417 is
/// implemented — in `ferrogate-secrets`, which depends on this crate, so the
/// reverse edge would be a cycle). This test replaces the former
/// `cf_scheme_is_deferred_to_417` marker: it pins that the rejection is
/// *actionable and timeless* rather than a pointer at a finished issue, which
/// is exactly what a stale "deferred to #<n>" message stops being.
#[test]
fn cf_scheme_is_a_permanent_crate_boundary_not_a_deferral() {
    let resolver = EnvTokenResolver::with_env_lookup(|_| None);
    let err = resolver.resolve("cf://secrets/cf-token").unwrap_err();
    match err {
        CloudflareError::TokenResolution(msg) => {
            // Names the crate that does own cf://, and the reason it cannot
            // move here.
            assert!(
                msg.contains("ferrogate-secrets"),
                "message should name the owning crate: {msg}"
            );
            assert!(
                msg.contains("dependency cycle"),
                "message should state why this crate cannot resolve cf://: {msg}"
            );
            // Tells the operator exactly what to write instead.
            assert!(
                msg.contains("env://FERROGATE_CF_SECRET_"),
                "message should give the Worker-binding spelling: {msg}"
            );
            // And must NOT promise a future implementation or point at an
            // issue number that is already closed.
            assert!(
                !msg.contains("not yet supported") && !msg.contains("deferred"),
                "the rejection must not read as a deferral: {msg}"
            );
            assert!(
                !msg.contains("#417"),
                "the rejection must not point at a completed issue: {msg}"
            );
        }
        other => panic!("expected TokenResolution, got {other:?}"),
    }
}

#[test]
fn empty_reference_is_rejected() {
    let resolver = EnvTokenResolver::with_env_lookup(|_| None);
    let err = resolver.resolve("   ").unwrap_err();
    assert!(
        matches!(err, CloudflareError::TokenResolution(_)),
        "got {err:?}"
    );
}

#[test]
fn resolved_token_debug_is_redacted() {
    let resolver = EnvTokenResolver::with_env_lookup(|_| None);
    let token = resolver.resolve("super-secret").unwrap();
    let debug = format!("{token:?}");
    assert!(
        !debug.contains("super-secret"),
        "token leaked in Debug: {debug}"
    );
    assert!(debug.contains("redacted"));
}
