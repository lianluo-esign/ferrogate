// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Unit coverage for the standalone admin-console API service
// (issue #315): route classification (the data plane must never be
// reachable), scope mapping, #312 body-cap resolution, and the fail-closed
// behavior of the shared admin auth gate.

use super::*;
use crate::auth::authenticate_admin_gate;
use crate::config::AuthServiceConfig;
use ferrogate_auth::AuthDecision;
use ferrogate_core::TenantContext;
use http::StatusCode;

fn disabled_auth_service() -> AuthServiceConfig {
    // Serde defaults: enabled = false, so the gate never consults the
    // external service in these tests.
    serde_json::from_value(serde_json::json!({})).expect("default auth_service config")
}

fn config_key(value: serde_json::Value) -> crate::config::ApiKey {
    serde_json::from_value(value).expect("test api key")
}

fn admin_key() -> crate::config::ApiKey {
    config_key(serde_json::json!({
        "id": "admin",
        "name": "Platform operator",
        "key": "admin-secret",
        "scopes": ["admin.read", "admin.write"],
    }))
}

fn chat_only_key() -> crate::config::ApiKey {
    config_key(serde_json::json!({
        "id": "chat",
        "name": "Data-plane only",
        "key": "chat-secret",
        "scopes": ["chat.completions"],
    }))
}

/// A durable-storage stand-in so the durable branch of the gate is
/// testable without Postgres: one known key with the given scopes.
struct StubAuthenticator {
    key: &'static str,
    scopes: Vec<String>,
}

impl ferrogate_auth::ApiKeyAuthenticator for StubAuthenticator {
    fn authenticate(&self, presented_key: &str) -> Option<AuthDecision> {
        (presented_key == self.key).then(|| AuthDecision {
            tenant: TenantContext::default(),
            subject: ferrogate_auth::PolicySubject::User {
                user_id: "user-1".into(),
            },
            scopes: self.scopes.clone(),
            allowed_models: Vec::new(),
            allowed_providers: Vec::new(),
            monthly_token_budget: None,
            request_limit_per_minute: None,
        })
    }
}

#[test]
fn classify_route_admits_only_the_admin_and_asset_surfaces() {
    assert_eq!(
        classify_route("/admin/v1/tenant-accounts"),
        Some(RouteClass::Admin)
    );
    assert_eq!(classify_route("/admin/status"), Some(RouteClass::Admin));
    assert_eq!(
        classify_route("/admin/v1/wallets/t1"),
        Some(RouteClass::Admin)
    );
    assert_eq!(classify_route("/v1/assets"), Some(RouteClass::Assets));
    assert_eq!(
        classify_route("/v1/assets/cli_tool/tool/1.0.0"),
        Some(RouteClass::Assets)
    );

    // The AI data plane and everything else is refused outright.
    assert_eq!(classify_route("/v1/chat/completions"), None);
    assert_eq!(classify_route("/v1/models"), None);
    assert_eq!(classify_route("/v1/messages"), None);
    assert_eq!(classify_route("/"), None);
    assert_eq!(classify_route("/administrator"), None);
    assert_eq!(classify_route("/v1/assets-other"), None);
}

#[test]
fn required_scope_mirrors_the_gateway_read_write_convention() {
    assert_eq!(required_scope(RouteClass::Admin, "GET"), "admin.read");
    assert_eq!(required_scope(RouteClass::Admin, "HEAD"), "admin.read");
    assert_eq!(required_scope(RouteClass::Admin, "POST"), "admin.write");
    assert_eq!(required_scope(RouteClass::Admin, "PUT"), "admin.write");
    assert_eq!(required_scope(RouteClass::Admin, "DELETE"), "admin.write");
    assert_eq!(required_scope(RouteClass::Assets, "GET"), "assets.read");
    assert_eq!(required_scope(RouteClass::Assets, "POST"), "assets.write");
    assert_eq!(required_scope(RouteClass::Assets, "DELETE"), "assets.write");
}

/// #312: the proxy's outer body caps resolve from the `[limits]` section
/// and are always the loosest cap the gateway applies for that family, so
/// the proxy can never reject a request the gateway would accept.
#[test]
fn body_cap_resolves_per_path_from_the_limits_section() {
    let config = Config::default();
    assert_eq!(
        body_cap_bytes(&config, RouteClass::Admin, "/admin/v1/tenant-accounts"),
        64 * 1024
    );
    assert_eq!(
        body_cap_bytes(&config, RouteClass::Admin, "/admin/v1/config/reload"),
        256 * 1024
    );
    assert_eq!(
        body_cap_bytes(&config, RouteClass::Admin, "/admin/v1/guardrail-policies"),
        1024 * 1024
    );
    assert_eq!(
        body_cap_bytes(&config, RouteClass::Assets, "/v1/assets/static_site/site/1"),
        10 * 1024 * 1024
    );
    // MAX_PROXY_REQUEST_BYTES must be able to carry the largest per-path
    // cap plus headers, or the parse-time bound would starve the per-path
    // bound of ever firing cleanly.
    let largest_cap = body_cap_bytes(&config, RouteClass::Assets, "/v1/assets/any");
    assert!(MAX_PROXY_REQUEST_BYTES > largest_cap);
}

/// The gate refuses an absent credential outright: never an open proxy.
#[test]
fn admin_gate_rejects_missing_and_unknown_keys_with_401() {
    let keys = vec![admin_key()];
    for presented in [None, Some(""), Some("   ")] {
        let error = authenticate_admin_gate(
            &disabled_auth_service(),
            &keys,
            None,
            presented,
            "admin.read",
            "req-1",
        )
        .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(error.code, "missing_api_key");
    }

    let error = authenticate_admin_gate(
        &disabled_auth_service(),
        &keys,
        None,
        Some("not-a-real-key"),
        "admin.read",
        "req-2",
    )
    .unwrap_err();
    assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    assert_eq!(error.code, "invalid_api_key");
}

/// A recognized key without the admin scope is refused with 403 BEFORE any
/// forwarding, with the gateway's own error code.
#[test]
fn admin_gate_rejects_wrong_scope_with_403() {
    let keys = vec![admin_key(), chat_only_key()];
    let error = authenticate_admin_gate(
        &disabled_auth_service(),
        &keys,
        None,
        Some("chat-secret"),
        "admin.read",
        "req-3",
    )
    .unwrap_err();
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "scope_denied");

    // The admin key passes both admin scopes.
    for scope in ["admin.read", "admin.write"] {
        authenticate_admin_gate(
            &disabled_auth_service(),
            &keys,
            None,
            Some("admin-secret"),
            scope,
            "req-4",
        )
        .expect("admin-scoped key must pass");
    }
}

/// Disabled and expired static keys fail closed with the same codes the
/// gateway's `authenticate` uses.
#[test]
fn admin_gate_rejects_disabled_and_expired_keys() {
    let disabled = config_key(serde_json::json!({
        "id": "off",
        "name": "Disabled",
        "key": "off-secret",
        "enabled": false,
        "scopes": ["admin.read"],
    }));
    let expired = config_key(serde_json::json!({
        "id": "old",
        "name": "Expired",
        "key": "old-secret",
        "expires_at_unix": 1,
        "scopes": ["admin.read"],
    }));
    let keys = vec![disabled, expired];

    let error = authenticate_admin_gate(
        &disabled_auth_service(),
        &keys,
        None,
        Some("off-secret"),
        "admin.read",
        "req-5",
    )
    .unwrap_err();
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "api_key_disabled");

    let error = authenticate_admin_gate(
        &disabled_auth_service(),
        &keys,
        None,
        Some("old-secret"),
        "admin.read",
        "req-6",
    )
    .unwrap_err();
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "api_key_expired");
}

/// The durable branch shares `scope_set_allows`: a virtual key minted with
/// NO scopes gets data-plane scopes only, never `admin.*` (the round-7
/// finding), while explicit admin scopes pass.
#[test]
fn admin_gate_durable_keys_share_the_empty_scope_is_not_admin_rule() {
    let unscoped = StubAuthenticator {
        key: "vk-unscoped",
        scopes: Vec::new(),
    };
    let error = authenticate_admin_gate(
        &disabled_auth_service(),
        &[],
        Some(&unscoped),
        Some("vk-unscoped"),
        "admin.read",
        "req-7",
    )
    .unwrap_err();
    assert_eq!(error.status, StatusCode::FORBIDDEN);
    assert_eq!(error.code, "scope_denied");

    // ...but the same empty scope set still grants a data-plane scope
    // (the asset page's assets.read), identical to the gateway.
    authenticate_admin_gate(
        &disabled_auth_service(),
        &[],
        Some(&unscoped),
        Some("vk-unscoped"),
        "assets.read",
        "req-8",
    )
    .expect("empty durable scope set must still grant data-plane scopes");

    let scoped = StubAuthenticator {
        key: "vk-admin",
        scopes: vec!["admin.read".into(), "admin.write".into()],
    };
    authenticate_admin_gate(
        &disabled_auth_service(),
        &[],
        Some(&scoped),
        Some("vk-admin"),
        "admin.write",
        "req-9",
    )
    .expect("admin-scoped durable key must pass");
}

#[test]
fn hop_by_hop_headers_are_not_forwarded() {
    for header in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "host",
        "content-length",
    ] {
        assert!(is_hop_by_hop(header), "{header} must be hop-by-hop");
    }
    for header in ["authorization", "x-api-key", "content-type", "accept"] {
        assert!(!is_hop_by_hop(header), "{header} must be forwarded");
    }
}
