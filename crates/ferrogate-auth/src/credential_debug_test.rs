// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Regression guards that admin passwords and minted SCIM tokens never reach a rendered Debug string.

//! Issue #492: the credential-bearing payload types in this crate must not be
//! renderable. `AdminRegisterRequest` / `AdminLoginRequest` carry a user's
//! plaintext password and are produced by `serde_json::from_slice` on the
//! register/login routes; `AdminScimTokenResponse` carries the one-time SCIM
//! provisioning secret at the only moment it exists in plaintext. A derived
//! `Debug` puts each of them one `{:?}` — a `tracing::debug!`, an `anyhow`
//! chain, an `unwrap()` panic, a failing `assert_eq!` — away from a log line.
//!
//! Every test below was verified to FAIL against the previous
//! `#[derive(Debug)]` before the hand-written impls landed. #489 showed why
//! that step is mandatory: a "does not contain the secret" assertion can be
//! vacuous (for a `Vec<u8>` the derive prints decimal bytes, not text). These
//! fields are `String`, so plaintext matching does bite — but each guard was
//! still watched failing rather than assumed.

use crate::{AdminLoginRequest, AdminRegisterRequest, AdminScimTokenResponse};

const PASSWORD: &str = "correct-horse-battery-staple-92";
const SCIM_TOKEN: &str = "fg_live_scim_provisioning_secret_value";

#[test]
fn admin_register_request_debug_redacts_the_password() {
    let rendered = format!(
        "{:?}",
        AdminRegisterRequest {
            organization_name: "Acme".into(),
            email: "owner@acme.test".into(),
            password: PASSWORD.into(),
            display_name: Some("Acme Owner".into()),
        }
    );

    assert!(
        !rendered.contains(PASSWORD),
        "password leaked into AdminRegisterRequest Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The non-secret fields must survive: this payload is what a 4xx on the
    // register route gets diagnosed from.
    assert!(rendered.contains("AdminRegisterRequest"), "{rendered}");
    assert!(rendered.contains("Acme"), "{rendered}");
    assert!(rendered.contains("owner@acme.test"), "{rendered}");
}

/// A password is user-chosen, so a substring of it can be the whole secret in
/// practice. Pin that the impl redacts the field rather than, say, printing a
/// prefix.
#[test]
fn admin_register_request_debug_prints_no_prefix_of_the_password() {
    let rendered = format!(
        "{:?}",
        AdminRegisterRequest {
            organization_name: "Acme".into(),
            email: "owner@acme.test".into(),
            password: PASSWORD.into(),
            display_name: None,
        }
    );

    for prefix_len in [4usize, 8, 16] {
        let prefix = &PASSWORD[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "a {prefix_len}-char password prefix leaked into AdminRegisterRequest Debug: {rendered}"
        );
    }
}

#[test]
fn admin_login_request_debug_redacts_the_password() {
    let rendered = format!(
        "{:?}",
        AdminLoginRequest {
            email: "owner@acme.test".into(),
            password: PASSWORD.into(),
        }
    );

    assert!(
        !rendered.contains(PASSWORD),
        "password leaked into AdminLoginRequest Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains("AdminLoginRequest"), "{rendered}");
    assert!(rendered.contains("owner@acme.test"), "{rendered}");
}

/// `assert_eq!` on these types formats BOTH sides with `Debug` on failure, so
/// a mismatched-password assertion in any future test would have dumped two
/// live passwords into the test log. Exercise that exact rendering.
#[test]
fn a_failed_equality_comparison_renders_no_password() {
    let left = AdminLoginRequest {
        email: "owner@acme.test".into(),
        password: PASSWORD.into(),
    };
    let right = AdminLoginRequest {
        email: "owner@acme.test".into(),
        password: "a-different-password".into(),
    };
    assert_ne!(left, right, "fixture error: the two payloads must differ");

    // What `assert_eq!(left, right)` would have printed.
    let rendered = format!("{left:?} {right:?}");
    assert!(!rendered.contains(PASSWORD), "{rendered}");
    assert!(!rendered.contains("a-different-password"), "{rendered}");
}

#[test]
fn admin_scim_token_response_debug_redacts_the_minted_token() {
    let rendered = format!(
        "{:?}",
        AdminScimTokenResponse {
            token: SCIM_TOKEN.into(),
        }
    );

    assert!(
        !rendered.contains(SCIM_TOKEN),
        "minted SCIM token leaked into AdminScimTokenResponse Debug: {rendered}"
    );
    // The `fg_` prefix alone is not secret, but no part of the secret body may
    // appear.
    assert!(
        !rendered.contains("scim_provisioning_secret_value"),
        "minted SCIM token body leaked into AdminScimTokenResponse Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // Length survives so a truncated/short mint is still diagnosable.
    assert!(
        rendered.contains(&format!("token_len: {}", SCIM_TOKEN.len())),
        "{rendered}"
    );
}
