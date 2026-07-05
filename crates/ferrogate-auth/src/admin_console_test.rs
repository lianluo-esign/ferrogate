// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-05
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the admin-console register/login/refresh/logout/me endpoints
//! (issue #157), against an in-memory `RuntimeStorageRepositories` backend.

use super::*;
use ferrogate_storage::{RuntimeControlPlaneState, RuntimeStorageBackend, StorageProviderKind};
use serde_json::Value;

fn console() -> AdminConsoleState {
    let repositories = Arc::new(RuntimeStorageRepositories::new(
        RuntimeStorageBackend::in_memory(vec![StorageProviderKind::Memory]),
        RuntimeControlPlaneState::new(),
        0,
        0,
    ));
    AdminConsoleState::new(AdminConsoleConfig {
        repositories,
        jwt_secret: "test-jwt-secret-do-not-use-in-production".into(),
    })
}

fn body_json(response: &HttpResponse) -> Value {
    serde_json::from_slice(&response.body).expect("response body must be valid JSON")
}

fn register(console: &AdminConsoleState, email: &str, password: &str) -> HttpResponse {
    handle_admin_register(
        console,
        AdminRegisterRequest {
            organization_name: "Acme Corp".into(),
            email: email.into(),
            password: password.into(),
            display_name: Some("Ada".into()),
        },
    )
}

#[test]
fn register_creates_a_working_session_and_gateway_key() {
    let console = console();
    let response = register(&console, "admin@acme.test", "correct-horse-battery");

    assert_eq!(response.status, 201);
    let body = body_json(&response);
    assert_eq!(body["user"]["email"], "admin@acme.test");
    assert_eq!(body["tenant"]["name"], "Acme Corp");
    assert_eq!(body["tenant"]["role"], "owner");
    assert!(
        body["access_token"].as_str().unwrap().contains('.'),
        "JWT-shaped"
    );
    assert!(!body["refresh_token"].as_str().unwrap().is_empty());
    assert!(body["gateway_api_key"].as_str().unwrap().starts_with("fg_"));

    // The provisioned virtual key is a real, durable StoredApiKey scoped to
    // this tenant with admin.read+admin.write, exactly like one created
    // directly through the gateway's own /admin/v1/virtual-keys endpoint.
    let gateway_api_key = body["gateway_api_key"].as_str().unwrap();
    let material = virtual_api_key_material(gateway_api_key).unwrap();
    let candidates = console
        .repositories
        .find_api_key_records_by_prefix(&material.key_prefix)
        .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].scopes, ["admin.read", "admin.write"]);
    assert!(candidates[0].enabled);
}

#[test]
fn register_rejects_duplicate_email() {
    let console = console();
    assert_eq!(
        register(&console, "dup@acme.test", "correct-horse-battery").status,
        201
    );

    let second = register(&console, "dup@acme.test", "another-long-password");
    assert_eq!(second.status, 409);
}

#[test]
fn register_rejects_invalid_input() {
    let console = console();

    let bad_email = handle_admin_register(
        &console,
        AdminRegisterRequest {
            organization_name: "Acme".into(),
            email: "not-an-email".into(),
            password: "correct-horse-battery".into(),
            display_name: None,
        },
    );
    assert_eq!(bad_email.status, 422);

    let short_password = handle_admin_register(
        &console,
        AdminRegisterRequest {
            organization_name: "Acme".into(),
            email: "short@acme.test".into(),
            password: "short".into(),
            display_name: None,
        },
    );
    assert_eq!(short_password.status, 422);

    let empty_org = handle_admin_register(
        &console,
        AdminRegisterRequest {
            organization_name: "   ".into(),
            email: "org@acme.test".into(),
            password: "correct-horse-battery".into(),
            display_name: None,
        },
    );
    assert_eq!(empty_org.status, 422);
}

#[test]
fn login_verifies_password_and_mints_a_fresh_session() {
    let console = console();
    register(&console, "admin@acme.test", "correct-horse-battery");

    let wrong = handle_admin_login(
        &console,
        AdminLoginRequest {
            email: "admin@acme.test".into(),
            password: "wrong-password".into(),
        },
    );
    assert_eq!(wrong.status, 401);

    let ok = handle_admin_login(
        &console,
        AdminLoginRequest {
            email: "ADMIN@acme.test".into(), // case-insensitive email match
            password: "correct-horse-battery".into(),
        },
    );
    assert_eq!(ok.status, 200);
    let body = body_json(&ok);
    assert_eq!(body["tenant"]["role"], "owner");
    assert!(body["gateway_api_key"].as_str().unwrap().starts_with("fg_"));
}

#[test]
fn login_rejects_unknown_email_and_disabled_account() {
    let console = console();
    let unknown = handle_admin_login(
        &console,
        AdminLoginRequest {
            email: "nobody@acme.test".into(),
            password: "whatever-password".into(),
        },
    );
    assert_eq!(unknown.status, 401);

    register(&console, "disabled@acme.test", "correct-horse-battery");
    let mut user = console
        .repositories
        .get_admin_user_by_email("disabled@acme.test")
        .unwrap()
        .unwrap();
    user.disabled_at_unix = Some(now_unix_seconds() as i64);
    console.repositories.upsert_admin_user(user).unwrap();

    let disabled = handle_admin_login(
        &console,
        AdminLoginRequest {
            email: "disabled@acme.test".into(),
            password: "correct-horse-battery".into(),
        },
    );
    assert_eq!(disabled.status, 401);
}

#[test]
fn refresh_rotates_the_token_and_rejects_reuse() {
    let console = console();
    let register_body = body_json(&register(
        &console,
        "admin@acme.test",
        "correct-horse-battery",
    ));
    let refresh_token = register_body["refresh_token"].as_str().unwrap().to_string();

    let refreshed = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: refresh_token.clone(),
        },
    );
    assert_eq!(refreshed.status, 200);
    let refreshed_body = body_json(&refreshed);
    let new_refresh_token = refreshed_body["refresh_token"].as_str().unwrap();
    assert_ne!(
        new_refresh_token, refresh_token,
        "refresh token must rotate"
    );

    // Reusing the now-revoked original refresh token must fail.
    let reuse = handle_admin_refresh(&console, AdminRefreshRequest { refresh_token });
    assert_eq!(reuse.status, 401);

    // The freshly-issued refresh token must still work.
    let second_refresh = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: new_refresh_token.to_string(),
        },
    );
    assert_eq!(second_refresh.status, 200);
}

#[test]
fn logout_revokes_the_refresh_token() {
    let console = console();
    let register_body = body_json(&register(
        &console,
        "admin@acme.test",
        "correct-horse-battery",
    ));
    let refresh_token = register_body["refresh_token"].as_str().unwrap().to_string();

    let logout = handle_admin_logout(
        &console,
        AdminLogoutRequest {
            refresh_token: refresh_token.clone(),
        },
    );
    assert_eq!(logout.status, 200);
    assert_eq!(body_json(&logout)["revoked"], true);

    // The revoked token can no longer be used to refresh.
    let refresh_after_logout =
        handle_admin_refresh(&console, AdminRefreshRequest { refresh_token });
    assert_eq!(refresh_after_logout.status, 401);

    // Logging out an already-revoked (or unknown) token is not an error.
    let logout_unknown = handle_admin_logout(
        &console,
        AdminLogoutRequest {
            refresh_token: "not-a-real-token".into(),
        },
    );
    assert_eq!(logout_unknown.status, 200);
    assert_eq!(body_json(&logout_unknown)["revoked"], false);
}

#[test]
fn me_returns_the_current_user_and_memberships_for_a_valid_access_token() {
    let console = console();
    let register_body = body_json(&register(
        &console,
        "admin@acme.test",
        "correct-horse-battery",
    ));
    let access_token = register_body["access_token"].as_str().unwrap();

    let me = handle_admin_me(&console, access_token);
    assert_eq!(me.status, 200);
    let body = body_json(&me);
    assert_eq!(body["user"]["email"], "admin@acme.test");
    assert_eq!(body["memberships"][0]["name"], "Acme Corp");
    assert_eq!(body["memberships"][0]["role"], "owner");
}

#[test]
fn me_rejects_a_garbage_access_token() {
    let console = console();
    let me = handle_admin_me(&console, "not-a-real-jwt");
    assert_eq!(me.status, 401);
}

#[test]
fn with_admin_console_returns_503_when_not_configured() {
    let service = AuthService::from_data(AuthServiceData::default());
    let response = with_admin_console(&service, |_| unreachable!("must not be called"));
    assert_eq!(response.status, 503);
}

#[test]
fn options_preflight_gets_a_no_content_response_for_any_path() {
    let service = AuthService::from_data(AuthServiceData::default());
    let request = HttpRequest {
        method: "OPTIONS".into(),
        path: "/v1/admin/register".into(),
        headers: HashMap::new(),
        body: Vec::new(),
    };
    let response = route_request(&service, request);
    assert_eq!(response.status, 204);
    assert!(response.body.is_empty());
}

#[test]
fn slugify_with_suffix_differs_across_ids_sharing_a_pid_suffix() {
    // Regression for a bug where the suffix was the *last 8 characters* of
    // the tenant_id string ("tenant-{nanos}-{pid}"), which lands on the
    // constant `pid` segment rather than the per-call `nanos` segment --
    // every registration reusing an organization name within one process
    // lifetime collided on the identical slug.
    let seed_a = "tenant-1111111111111111111-42";
    let seed_b = "tenant-2222222222222222222-42";
    let slug_a = slugify_with_suffix("Acme Inc", seed_a);
    let slug_b = slugify_with_suffix("Acme Inc", seed_b);
    assert_ne!(slug_a, slug_b);
    assert!(slug_a.starts_with("acme-inc-"));
    assert!(slug_b.starts_with("acme-inc-"));
}

#[test]
fn register_allows_reusing_an_organization_name() {
    let console = console();
    let first = register(&console, "first@example.com", "supersecret1");
    assert_eq!(first.status, 201);
    // Same organization_name ("Acme Corp", per the register() helper) as the
    // first call -- must not collide on tenants.slug.
    let second = register(&console, "second@example.com", "supersecret2");
    assert_eq!(second.status, 201);
}
