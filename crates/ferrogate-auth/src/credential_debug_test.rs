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
//! `HttpRequest`/`HttpResponse` are the same class one frame lower down, and
//! are where those secrets *actually* live on the wire: the password is in
//! `HttpRequest.body` before `AdminLoginRequest` exists, and the minted SCIM
//! token is in `HttpResponse.body` after `AdminScimTokenResponse` has been
//! serialized away — so redacting the payload types alone leaves the only real
//! mint path uncovered.
//!
//! Every test below was verified to FAIL against the previous
//! `#[derive(Debug)]` before the hand-written impls landed. #489 showed why
//! that step is mandatory: a "does not contain the secret" assertion can be
//! vacuous (for a `Vec<u8>` the derive prints decimal bytes, not text). The
//! `String` fields do bite on plaintext matching; the two `Vec<u8>` bodies do
//! not, so every guard on them also asserts [`decimal_byte_run`].

use std::collections::HashMap;

use crate::{
    AdminLoginRequest, AdminRegisterRequest, AdminScimTokenResponse, HttpRequest, HttpResponse,
};

const PASSWORD: &str = "correct-horse-battery-staple-92";
const SCIM_TOKEN: &str = "fg_live_scim_provisioning_secret_value";
const ACCESS_TOKEN: &str = "fg_live_admin_access_token_value_44";

/// The contiguous run a `#[derive(Debug)]` over `Vec<u8>` would emit for
/// `secret` *inside* an enclosing byte slice: `[102, 103, …]` -> `102, 103, …`.
///
/// This is the whole point of #489. A `Vec<u8>` `Debug` prints decimal bytes,
/// never text, so `!rendered.contains(SECRET)` is **vacuous** against the
/// derive — it passes with the full leak present. Every guard below that covers
/// a byte-carrying field asserts this form as well as the plaintext one.
fn decimal_byte_run(secret: &str) -> String {
    format!("{:?}", secret.as_bytes())
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

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

/// The register guard's prefix check applied to the login payload too: without
/// it a "helpful triage" edit adding `.field("password_prefix",
/// &&self.password[..8])` to `AdminLoginRequest::fmt` renders `correct-` while
/// leaving `<redacted>` in place and the full-secret assertion green.
#[test]
fn admin_login_request_debug_prints_no_prefix_of_the_password() {
    let rendered = format!(
        "{:?}",
        AdminLoginRequest {
            email: "owner@acme.test".into(),
            password: PASSWORD.into(),
        }
    );

    for prefix_len in [4usize, 8, 16] {
        let prefix = &PASSWORD[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "a {prefix_len}-char password prefix leaked into AdminLoginRequest Debug: {rendered}"
        );
    }
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

/// A minted SCIM token is machine-generated, so any leading run of it narrows
/// the search space directly. Without this, `.field("token_prefix",
/// &&self.token[..20])` renders `fg_live_scim_provisi` and passes both
/// assertions above (it contains neither the full token nor the
/// `scim_provisioning_secret_value` body substring).
#[test]
fn admin_scim_token_response_debug_prints_no_prefix_of_the_token() {
    let rendered = format!(
        "{:?}",
        AdminScimTokenResponse {
            token: SCIM_TOKEN.into(),
        }
    );

    for prefix_len in [4usize, 8, 16] {
        let prefix = &SCIM_TOKEN[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "a {prefix_len}-char token prefix leaked into AdminScimTokenResponse Debug: {rendered}"
        );
    }
}

// -- the transport types the secrets actually travel in (#492 bounce) --------

fn admin_login_request_bytes() -> Vec<u8> {
    serde_json::to_vec(&AdminLoginRequest {
        email: "owner@acme.test".into(),
        password: PASSWORD.into(),
    })
    .expect("login payload serializes")
}

fn authenticated_request() -> HttpRequest {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "authorization".to_string(),
        format!("Bearer {ACCESS_TOKEN}"),
    );
    HttpRequest {
        method: "POST".to_string(),
        path: "/v1/admin/login".to_string(),
        query: String::new(),
        headers,
        body: admin_login_request_bytes(),
    }
}

/// `AdminLoginRequest`'s redaction is applied only *after* the bytes have been
/// read into `HttpRequest.body` and parsed in `server.rs`, so the request type
/// is where the plaintext password really lives. `{:?}` on it — a
/// `tracing::debug!(?request)` in the router, an `unwrap()` on
/// `read_http_request_bounded`, a failing assertion in a route test — must
/// render neither form of it.
#[test]
fn http_request_debug_never_prints_the_body_bytes() {
    let rendered = format!("{:?}", authenticated_request());

    assert!(
        !rendered.contains(PASSWORD),
        "admin password leaked into HttpRequest Debug as plaintext: {rendered}"
    );
    // The assertion that actually bites against `#[derive(Debug)]`: the derive
    // prints `body: [123, 34, ...]`, so the plaintext check above alone is
    // vacuous here (#489).
    assert!(
        !rendered.contains(&decimal_byte_run(PASSWORD)),
        "admin password leaked into HttpRequest Debug as raw bytes: {rendered}"
    );
    assert!(
        !rendered.contains("body:"),
        "HttpRequest Debug must expose only body_len, never the body: {rendered}"
    );
    // Still diagnosable: route and payload size survive.
    assert!(rendered.contains("HttpRequest"), "{rendered}");
    assert!(rendered.contains("/v1/admin/login"), "{rendered}");
    assert!(
        rendered.contains(&format!("body_len: {}", admin_login_request_bytes().len())),
        "{rendered}"
    );
}

/// Every authenticated admin/SCIM route carries `authorization: Bearer
/// <access_token>` in the header map. A derived `Debug` over
/// `HashMap<String, String>` renders header values as readable text, so this
/// one leaks in plaintext rather than as bytes.
#[test]
fn http_request_debug_never_prints_header_values() {
    let rendered = format!("{:?}", authenticated_request());

    assert!(
        !rendered.contains(ACCESS_TOKEN),
        "bearer token leaked into HttpRequest Debug: {rendered}"
    );
    assert!(
        !rendered.contains("Bearer "),
        "an authorization header value leaked into HttpRequest Debug: {rendered}"
    );
    assert!(
        !rendered.contains("application/json"),
        "a header value leaked into HttpRequest Debug: {rendered}"
    );
    // Header *names* are not secret and are the triage signal worth keeping.
    assert!(rendered.contains("authorization"), "{rendered}");
    assert!(rendered.contains("content-type"), "{rendered}");
}

/// The OIDC SSO callback (issue #160) arrives as
/// `GET /v1/auth/sso/callback?code=..&state=..`, and that `code` is a
/// single-use credential exchangeable at the IdP for tokens — the only
/// credential this service accepts outside a body or a header.
#[test]
fn http_request_debug_never_prints_the_query_string() {
    const CALLBACK_QUERY: &str = "code=oauth-authorization-code-value&state=st_1";
    let rendered = format!(
        "{:?}",
        HttpRequest {
            method: "GET".to_string(),
            path: "/v1/auth/sso/callback".to_string(),
            query: CALLBACK_QUERY.to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    );

    assert!(
        !rendered.contains("oauth-authorization-code-value"),
        "OAuth authorization code leaked into HttpRequest Debug: {rendered}"
    );
    assert!(
        rendered.contains(&format!("query_len: {}", CALLBACK_QUERY.len())),
        "{rendered}"
    );
}

/// The bounce's central finding: the minted SCIM token is serialized into
/// `HttpResponse.body` in `scim.rs` **before** `AdminScimTokenResponse::fmt`
/// can ever run, so the redacted `Debug` on that type is bypassed on the only
/// real mint path. Build the response exactly the way the handler does.
#[test]
fn http_response_debug_never_prints_a_minted_scim_token() {
    let response = HttpResponse::json(
        201,
        AdminScimTokenResponse {
            token: SCIM_TOKEN.into(),
        },
    );
    let rendered = format!("{response:?}");

    assert!(
        !rendered.contains(SCIM_TOKEN),
        "minted SCIM token leaked into HttpResponse Debug as plaintext: {rendered}"
    );
    // The only assertion that fails against `#[derive(Debug)]` here: what the
    // derive prints is `body: [123, 34, 116, 111, 107, 101, 110, ...]`.
    assert!(
        !rendered.contains(&decimal_byte_run(SCIM_TOKEN)),
        "minted SCIM token leaked into HttpResponse Debug as raw bytes: {rendered}"
    );
    assert!(
        !rendered.contains("body:"),
        "HttpResponse Debug must expose only body_len, never the body: {rendered}"
    );
    assert!(rendered.contains("HttpResponse"), "{rendered}");
    assert!(rendered.contains("201"), "{rendered}");
}

/// Length survives so a truncated or empty payload is still diagnosable.
#[test]
fn http_response_debug_keeps_status_and_body_len() {
    let rendered = format!("{:?}", HttpResponse::no_content(204));

    assert!(rendered.contains("204"), "{rendered}");
    assert!(rendered.contains("body_len: 0"), "{rendered}");
}
