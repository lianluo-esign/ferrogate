// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Regression guards that admin passwords, session/refresh tokens, minted SCIM and gateway keys, and configured API-key secrets never reach a rendered Debug string.

//! Issue #492: the credential-bearing payload types in this crate must not be
//! renderable. `AdminRegisterRequest` / `AdminLoginRequest` carry a user's
//! plaintext password and are produced by `serde_json::from_slice` on the
//! register/login routes; `AdminScimTokenResponse` carries the one-time SCIM
//! provisioning secret at the only moment it exists in plaintext. A derived
//! `Debug` puts each of them one `{:?}` — a `tracing::debug!`, an `anyhow`
//! chain, an `unwrap()` panic, a failing `assert_eq!` — away from a log line.
//!
//! Issue #537 closed the four of the same class that #492 had left outside its
//! stated scope: `AdminRefreshRequest` and `AdminLogoutRequest` (a live refresh
//! token, parsed from a request body exactly like the login payload),
//! `AdminSessionResponse` (three secrets at once — access token, refresh token,
//! and the once-shown minted gateway API key from #517), and `AuthApiKey`
//! (a configured API-key secret, reachable from `{:?}` on the whole
//! `RbacAuthService`).
//!
//! `HttpRequest`/`HttpResponse` are the same class one frame lower down, and
//! are where those secrets *actually* live on the wire: the password is in
//! `HttpRequest.body` before `AdminLoginRequest` exists, and the minted SCIM
//! token is in `HttpResponse.body` after `AdminScimTokenResponse` has been
//! serialized away — so redacting the payload types alone leaves the only real
//! mint path uncovered.
//!
//! Every #492 test below was verified to FAIL against the previous
//! `#[derive(Debug)]` before the hand-written impls landed. #489 showed why
//! that step is mandatory: a "does not contain the secret" assertion can be
//! vacuous (for a `Vec<u8>` the derive prints decimal bytes, not text). The
//! `String` fields do bite on plaintext matching; the two `Vec<u8>` bodies do
//! not, so every guard on them also asserts [`decimal_byte_run`].
//!
//! The #537 tests at the bottom of this file were **not** observed failing
//! against the reverted derive — the slice that added them ran under a
//! no-test-execution directive. Each states in its doc comment which impl it
//! pins and which two mutations it is built to catch (revert-to-derive, and
//! drop-the-field-instead-of-redacting); those claims are reasoned, not
//! observed. All four fields they cover are `String`/`Option<String>`, so the
//! #489 `Vec<u8>` vacuity does not apply to them.

use std::collections::HashMap;

use ferrogate_core::TenantContext;

use crate::{
    AdminLoginRequest, AdminLogoutRequest, AdminRefreshRequest, AdminRegisterRequest,
    AdminScimTokenResponse, AdminSessionResponse, AdminTenantView, AdminUserView, AuthApiKey,
    AuthServiceData, HttpRequest, HttpResponse, RbacAuthService,
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

// -- issue #537: session/refresh tokens, the minted gateway key, and the -----
// -- configured API-key secret ----------------------------------------------

const REFRESH_TOKEN: &str = "fg_live_admin_refresh_token_value_71";
const GATEWAY_API_KEY: &str = "fg_live_gateway_admin_api_key_value_08";
const CONFIGURED_KEY_SECRET: &str = "fg_static_configured_api_key_secret_09";

/// Machine-minted credentials, so any leading run of one narrows the search
/// space directly. Asserting the absence of the whole value alone would pass
/// against an impl that "helpfully" printed a prefix for triage.
fn assert_no_prefix_of(rendered: &str, secret: &str, what: &str) {
    for prefix_len in [4usize, 8, 16] {
        let prefix = &secret[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "a {prefix_len}-char prefix of the {what} leaked into Debug: {rendered}"
        );
    }
}

/// Pins `impl Debug for AdminRefreshRequest` in `admin_console.rs`.
///
/// Reds against `#[derive(Debug)]` (the whole token is printed) **and** against
/// an impl that drops the field instead of redacting it (the
/// `refresh_token: "<redacted>"` pair disappears).
#[test]
fn admin_refresh_request_debug_redacts_the_token() {
    let rendered = format!(
        "{:?}",
        AdminRefreshRequest {
            refresh_token: REFRESH_TOKEN.into(),
        }
    );

    assert!(
        !rendered.contains(REFRESH_TOKEN),
        "refresh token leaked into AdminRefreshRequest Debug: {rendered}"
    );
    assert_no_prefix_of(&rendered, REFRESH_TOKEN, "refresh token");
    // Positive shape: the field must still be *named and redacted*, not simply
    // omitted -- an omission is indistinguishable from "this payload had no
    // token" when reading a log.
    assert!(
        rendered.contains(r#"refresh_token: "<redacted>""#),
        "{rendered}"
    );
    assert!(rendered.contains("AdminRefreshRequest"), "{rendered}");
    // Length survives: an empty or truncated token is the realistic client bug
    // on this route, and the length is the only signal left to triage it.
    assert!(
        rendered.contains(&format!("refresh_token_len: {}", REFRESH_TOKEN.len())),
        "{rendered}"
    );
}

/// Pins `impl Debug for AdminLogoutRequest` in `admin_console.rs`. Same two
/// mutations as the refresh guard above: revert-to-derive, and drop-the-field.
#[test]
fn admin_logout_request_debug_redacts_the_token() {
    let rendered = format!(
        "{:?}",
        AdminLogoutRequest {
            refresh_token: REFRESH_TOKEN.into(),
        }
    );

    assert!(
        !rendered.contains(REFRESH_TOKEN),
        "refresh token leaked into AdminLogoutRequest Debug: {rendered}"
    );
    assert_no_prefix_of(&rendered, REFRESH_TOKEN, "refresh token");
    assert!(
        rendered.contains(r#"refresh_token: "<redacted>""#),
        "{rendered}"
    );
    assert!(rendered.contains("AdminLogoutRequest"), "{rendered}");
    assert!(
        rendered.contains(&format!("refresh_token_len: {}", REFRESH_TOKEN.len())),
        "{rendered}"
    );
}

fn session_response() -> AdminSessionResponse {
    AdminSessionResponse {
        access_token: ACCESS_TOKEN.into(),
        refresh_token: REFRESH_TOKEN.into(),
        expires_in: 3600,
        user: AdminUserView {
            id: "usr_1".into(),
            email: "owner@acme.test".into(),
            display_name: "Acme Owner".into(),
        },
        tenant: AdminTenantView {
            id: "ten_1".into(),
            name: "Acme".into(),
            role: "owner".into(),
        },
        gateway_api_key: GATEWAY_API_KEY.into(),
    }
}

/// Pins `impl Debug for AdminSessionResponse` in `admin_console.rs` — the
/// densest of the four, with three live secrets in one struct.
///
/// Reds against `#[derive(Debug)]` (all three print verbatim). Each of the
/// three positive assertions also reds independently against an impl that
/// drops *that one* field: a bare `contains("<redacted>")` would not, because
/// the other two redactions would still satisfy it.
#[test]
fn admin_session_response_debug_redacts_all_three_credentials() {
    let rendered = format!("{:?}", session_response());

    for (secret, what) in [
        (ACCESS_TOKEN, "access token"),
        (REFRESH_TOKEN, "refresh token"),
        (GATEWAY_API_KEY, "minted gateway API key"),
    ] {
        assert!(
            !rendered.contains(secret),
            "{what} leaked into AdminSessionResponse Debug: {rendered}"
        );
        assert_no_prefix_of(&rendered, secret, what);
    }

    for field in ["access_token", "refresh_token", "gateway_api_key"] {
        assert!(
            rendered.contains(&format!(r#"{field}: "<redacted>""#)),
            "AdminSessionResponse Debug must name and redact `{field}`, not drop it: {rendered}"
        );
    }

    // The non-secret fields must survive, or the impl has traded a leak for an
    // undiagnosable login reply.
    assert!(rendered.contains("AdminSessionResponse"), "{rendered}");
    assert!(rendered.contains("expires_in: 3600"), "{rendered}");
    assert!(rendered.contains("owner@acme.test"), "{rendered}");
    assert!(rendered.contains("ten_1"), "{rendered}");
    // The gateway key is never recoverable after this response, so its length
    // is the only way a truncated mint could ever be diagnosed (#517).
    assert!(
        rendered.contains(&format!("gateway_api_key_len: {}", GATEWAY_API_KEY.len())),
        "{rendered}"
    );
}

/// `assert_eq!` formats BOTH sides with `Debug` on failure, so a mismatched
/// session assertion in any future route test would have dumped six live
/// credentials into the test log. Exercise that exact rendering.
#[test]
fn a_failed_session_comparison_renders_no_credentials() {
    let left = session_response();
    let mut right = session_response();
    right.access_token = "fg_live_a_different_access_token_22".into();
    assert_ne!(left, right, "fixture error: the two sessions must differ");

    // What `assert_eq!(left, right)` would have printed.
    let rendered = format!("{left:?} {right:?}");
    assert!(!rendered.contains(ACCESS_TOKEN), "{rendered}");
    assert!(!rendered.contains("a_different_access_token"), "{rendered}");
    assert!(!rendered.contains(REFRESH_TOKEN), "{rendered}");
    assert!(!rendered.contains(GATEWAY_API_KEY), "{rendered}");
}

fn configured_api_key(secret: Option<&str>) -> AuthApiKey {
    AuthApiKey {
        id: "key_1".into(),
        name: Some("ci-runner".into()),
        secret: secret.map(str::to_string),
        enabled: true,
        tenant: TenantContext {
            organization_id: Some("ten_1".into()),
            ..TenantContext::default()
        },
        scopes: vec!["chat.completions".into()],
    }
}

/// Pins `impl Debug for AuthApiKey` in `rbac.rs`.
///
/// Reds against `#[derive(Debug)]` (`secret: Some("fg_static_…")`) and against
/// an impl that drops the field (the `secret: Some("<redacted>")` pair goes
/// missing).
#[test]
fn auth_api_key_debug_redacts_the_configured_secret() {
    let rendered = format!("{:?}", configured_api_key(Some(CONFIGURED_KEY_SECRET)));

    assert!(
        !rendered.contains(CONFIGURED_KEY_SECRET),
        "configured API-key secret leaked into AuthApiKey Debug: {rendered}"
    );
    assert_no_prefix_of(&rendered, CONFIGURED_KEY_SECRET, "API-key secret");
    assert!(
        rendered.contains(r#"secret: Some("<redacted>")"#),
        "{rendered}"
    );
    // Configuration, not credential: all of it survives.
    assert!(rendered.contains("AuthApiKey"), "{rendered}");
    assert!(rendered.contains("key_1"), "{rendered}");
    assert!(rendered.contains("ci-runner"), "{rendered}");
    assert!(rendered.contains("enabled: true"), "{rendered}");
    assert!(rendered.contains("chat.completions"), "{rendered}");
    assert!(rendered.contains("ten_1"), "{rendered}");
}

/// The `Option` trap from #537: a key with **no** configured secret can never
/// authenticate, which is a real misconfiguration worth seeing in a log. An
/// impl that renders a flat `<redacted>` for both arms erases that signal
/// while looking correctly redacted.
///
/// Reds against an impl that collapses `Some`/`None`, and against
/// `#[derive(Debug)]` only indirectly — so it is paired with the guard above,
/// which is the one that catches the leak.
#[test]
fn auth_api_key_debug_keeps_none_distinguishable_from_some() {
    let with_secret = format!("{:?}", configured_api_key(Some(CONFIGURED_KEY_SECRET)));
    let without_secret = format!("{:?}", configured_api_key(None));

    assert!(
        without_secret.contains("secret: None"),
        "a key with no configured secret must still render as None: {without_secret}"
    );
    assert!(
        !without_secret.contains("<redacted>"),
        "redacting a None secret invents a credential that does not exist: {without_secret}"
    );
    assert_ne!(
        with_secret, without_secret,
        "Some(secret) and None must not render identically"
    );
}

/// The path that actually reaches a log: `AuthServiceData` derives `Debug` over
/// `Vec<AuthApiKey>` and `RbacAuthService` derives it over an
/// `Arc<RwLock<AuthServiceData>>`, so a single `{:?}` two levels up used to
/// print every configured secret in the deployment at once.
#[test]
fn rbac_service_debug_redacts_every_configured_secret() {
    let rendered = format!(
        "{:?}",
        RbacAuthService::new(AuthServiceData {
            api_keys: vec![
                configured_api_key(Some(CONFIGURED_KEY_SECRET)),
                configured_api_key(None),
            ],
            ..AuthServiceData::default()
        })
    );

    assert!(
        !rendered.contains(CONFIGURED_KEY_SECRET),
        "configured API-key secret leaked through RbacAuthService Debug: {rendered}"
    );
    assert_no_prefix_of(&rendered, CONFIGURED_KEY_SECRET, "API-key secret");
    assert!(
        rendered.contains(r#"secret: Some("<redacted>")"#),
        "{rendered}"
    );
    assert!(rendered.contains("secret: None"), "{rendered}");
}
