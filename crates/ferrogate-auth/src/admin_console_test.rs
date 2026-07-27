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
use std::sync::Mutex;

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
    // this tenant with admin.read+admin.write+assets.read+assets.write,
    // exactly like one created directly through the gateway's own
    // /admin/v1/virtual-keys endpoint. The assets.* scopes (issue #178)
    // don't cross a real privilege boundary beyond what admin.write
    // already grants (see provision_gateway_api_key's doc comment).
    let gateway_api_key = body["gateway_api_key"].as_str().unwrap();
    let material = virtual_api_key_material(gateway_api_key).unwrap();
    let candidates = block_on_sync_bridge(
        console
            .repositories
            .find_api_key_records_by_prefix(&material.key_prefix),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].scopes,
        ["admin.read", "admin.write", "assets.read", "assets.write"]
    );
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
    let mut user = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_by_email("disabled@acme.test"),
    )
    .unwrap()
    .unwrap();
    user.disabled_at_unix = Some(now_unix_seconds() as i64);
    block_on_sync_bridge(console.repositories.upsert_admin_user(user)).unwrap();

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
        query: String::new(),
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

// -- issue #162: team invites, role changes, and revocation ----------------

#[test]
fn invite_adds_an_existing_user_to_the_tenant_with_a_non_owner_role() {
    let console = console();
    let owner = body_json(&register(&console, "owner@acme.test", "correct-horse-1"));
    let owner_token = owner["access_token"].as_str().unwrap();
    // The invitee must already have registered somewhere (creating their own
    // tenant as a side effect) before they can be invited elsewhere.
    let invitee = body_json(&register(&console, "member@acme.test", "correct-horse-2"));
    let invitee_user_id = invitee["user"]["id"].as_str().unwrap();

    let invite = handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "member@acme.test".into(),
            role: "member".into(),
        },
    );
    assert_eq!(invite.status, 201);
    let invite_body = body_json(&invite);
    assert_eq!(invite_body["role"], "member");
    assert_eq!(invite_body["user_id"], invitee_user_id);

    let list = handle_admin_team_list(&console, owner_token);
    assert_eq!(list.status, 200);
    let members = body_json(&list)["members"].clone();
    let roles: Vec<String> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["role"].as_str().unwrap().to_string())
        .collect();
    assert!(roles.contains(&"owner".to_string()));
    assert!(roles.contains(&"member".to_string()));

    // StoredAdminUserMembership.role is now set to something other than
    // "owner" via a real code path (acceptance criterion for #162).
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(owner_tenant_id),
    )
    .unwrap();
    assert!(memberships
        .iter()
        .any(|membership| membership.user_id == invitee_user_id && membership.role == "member"));

    // The invited user's own membership list now includes both tenants: the
    // one they registered (as owner) and the one they were invited into.
    let invitee_memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(invitee_user_id),
    )
    .unwrap();
    assert_eq!(invitee_memberships.len(), 2);
}

#[test]
fn invite_is_forbidden_for_a_non_owner() {
    let console = console();
    let owner = body_json(&register(&console, "owner2@acme.test", "correct-horse-3"));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let member = body_json(&register(&console, "member2@acme.test", "correct-horse-4"));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "member2@acme.test".into(),
            role: "member".into(),
        },
    );
    // A plain access_token from the invitee's OWN registration reflects
    // their (owner) role in *their own* tenant, not the tenant they were
    // just invited into as "member" -- mint a session directly scoped to
    // the inviter's tenant/role to test the authorization gate itself,
    // independent of which tenant `handle_admin_login` currently defaults
    // an account with multiple memberships into.
    let (member_token, _) = issue_session(
        &console,
        member_user_id,
        "member2@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();

    let invite = handle_admin_team_invite(
        &console,
        &member_token,
        AdminInviteRequest {
            email: "someone-else@acme.test".into(),
            role: "member".into(),
        },
    );

    assert_eq!(invite.status, 403);
}

#[test]
fn invite_rejects_an_email_with_no_registered_account() {
    let console = console();
    let owner_token = body_json(&register(&console, "owner3@acme.test", "correct-horse-5"))
        ["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let invite = handle_admin_team_invite(
        &console,
        &owner_token,
        AdminInviteRequest {
            email: "nobody@acme.test".into(),
            role: "member".into(),
        },
    );

    assert_eq!(invite.status, 404);
}

#[test]
fn change_role_updates_the_membership_and_enforces_the_owner_gate() {
    let console = console();
    let owner = body_json(&register(&console, "owner4@acme.test", "correct-horse-6"));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let member = body_json(&register(&console, "member4@acme.test", "correct-horse-7"));
    let member_user_id = member["user"]["id"].as_str().unwrap().to_string();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "member4@acme.test".into(),
            role: "member".into(),
        },
    );

    // A non-owner cannot change roles. Mint a session scoped to the owner's
    // tenant (see `invite_is_forbidden_for_a_non_owner` for why a plain
    // registration access_token won't do).
    let (member_token, _) = issue_session(
        &console,
        &member_user_id,
        "member4@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();
    let forbidden_change = handle_admin_team_change_role(
        &console,
        &member_token,
        &member_user_id,
        AdminChangeRoleRequest {
            role: "admin".into(),
        },
    );
    assert_eq!(forbidden_change.status, 403);

    // The owner can promote the member to admin.
    let change = handle_admin_team_change_role(
        &console,
        owner_token,
        &member_user_id,
        AdminChangeRoleRequest {
            role: "admin".into(),
        },
    );
    assert_eq!(change.status, 200);

    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(owner_tenant_id),
    )
    .unwrap();
    assert!(memberships
        .iter()
        .any(|membership| membership.user_id == member_user_id && membership.role == "admin"));
}

#[test]
fn change_role_refuses_to_demote_the_last_owner() {
    let console = console();
    let owner = body_json(&register(&console, "owner5@acme.test", "correct-horse-8"));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_user_id = owner["user"]["id"].as_str().unwrap();

    let change = handle_admin_team_change_role(
        &console,
        owner_token,
        owner_user_id,
        AdminChangeRoleRequest {
            role: "member".into(),
        },
    );

    assert_eq!(change.status, 409);
}

#[test]
fn revoke_removes_a_teammate_and_refuses_to_remove_the_last_owner() {
    let console = console();
    let owner = body_json(&register(&console, "owner6@acme.test", "correct-horse-9"));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_user_id = owner["user"]["id"].as_str().unwrap();
    let member = body_json(&register(&console, "member6@acme.test", "correct-horse-10"));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "member6@acme.test".into(),
            role: "member".into(),
        },
    );

    // The owner can remove the member.
    let revoke = handle_admin_team_revoke(&console, owner_token, member_user_id);
    assert_eq!(revoke.status, 200);
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(owner_tenant_id),
    )
    .unwrap();
    assert!(!memberships
        .iter()
        .any(|membership| membership.user_id == member_user_id));

    // The sole remaining owner cannot remove themselves (tenant lockout).
    let self_revoke = handle_admin_team_revoke(&console, owner_token, owner_user_id);
    assert_eq!(self_revoke.status, 409);
}

// -- issue #517: the four membership tiers are real, and the console
// session's gateway key is scoped from the caller's tier ------------------

/// Provisions a real, password-authenticating teammate whose ONLY membership
/// is `role` in `tenant_id`, so `handle_admin_login` resolves that tier. This
/// is the state an invited (non-self-registered) teammate is in.
fn seed_teammate(
    console: &AdminConsoleState,
    tenant_id: &str,
    email: &str,
    password: &str,
    role: &str,
) -> String {
    let now = now_unix_seconds() as i64;
    let user_id = next_id("user");
    block_on_sync_bridge(console.repositories.upsert_admin_user(StoredAdminUser {
        id: user_id.clone(),
        email: email.into(),
        password_hash: hash_password(password).unwrap(),
        display_name: "Teammate".into(),
        superadmin: false,
        created_at_unix: now,
        updated_at_unix: now,
        last_login_at_unix: None,
        disabled_at_unix: None,
    }))
    .unwrap();
    block_on_sync_bridge(console.repositories.upsert_admin_user_membership(
        StoredAdminUserMembership {
            id: next_id("membership"),
            user_id: user_id.clone(),
            tenant_id: tenant_id.into(),
            role: role.into(),
            created_at_unix: now,
        },
    ))
    .unwrap();
    user_id
}

fn login_gateway_key_scopes(
    console: &AdminConsoleState,
    email: &str,
    password: &str,
) -> Vec<String> {
    let login = handle_admin_login(
        console,
        AdminLoginRequest {
            email: email.into(),
            password: password.into(),
        },
    );
    assert_eq!(login.status, 200, "{:?}", body_json(&login));
    let secret = body_json(&login)["gateway_api_key"]
        .as_str()
        .unwrap()
        .to_string();
    let material = virtual_api_key_material(&secret).unwrap();
    let candidates = block_on_sync_bridge(
        console
            .repositories
            .find_api_key_records_by_prefix(&material.key_prefix),
    )
    .unwrap();
    assert_eq!(candidates.len(), 1);
    candidates[0].scopes.clone()
}

/// The bug in issue #517, end to end through the real login route: a console
/// session's gateway virtual key is minted with the scopes of the caller's
/// TIER, not a fixed admin.read+admin.write+assets.* grant. Each tier is
/// asserted separately, so flattening the ladder turns the non-owner cases
/// red.
#[test]
fn login_mints_a_gateway_key_scoped_to_the_membership_tier() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "tiers-owner@acme.test",
        "correct-horse-517",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    // owner: the registering user's own session key.
    let owner_key_scopes = {
        let material =
            virtual_api_key_material(owner["gateway_api_key"].as_str().unwrap()).unwrap();
        let candidates = block_on_sync_bridge(
            console
                .repositories
                .find_api_key_records_by_prefix(&material.key_prefix),
        )
        .unwrap();
        candidates[0].scopes.clone()
    };
    assert_eq!(
        owner_key_scopes,
        ["admin.read", "admin.write", "assets.read", "assets.write"],
        "owner"
    );

    for (role, expected) in [
        (
            "admin",
            vec!["admin.read", "admin.write", "assets.read", "assets.write"],
        ),
        ("member", vec!["admin.read", "assets.read", "assets.write"]),
        ("viewer", vec!["admin.read", "assets.read"]),
    ] {
        let email = format!("tiers-{role}@acme.test");
        seed_teammate(&console, &tenant_id, &email, "correct-horse-517", role);
        let scopes = login_gateway_key_scopes(&console, &email, "correct-horse-517");
        assert_eq!(scopes, expected, "tier {role}");
    }
}

/// The headline consequence, isolated: a `viewer` never receives a key that
/// can write anything.
#[test]
fn a_viewer_session_key_carries_no_write_scope() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "viewer-tenant-owner@acme.test",
        "correct-horse-517b",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    seed_teammate(
        &console,
        &tenant_id,
        "read-only@acme.test",
        "correct-horse-517b",
        "viewer",
    );

    let scopes = login_gateway_key_scopes(&console, "read-only@acme.test", "correct-horse-517b");
    assert!(
        !scopes.iter().any(|scope| scope.ends_with(".write")),
        "a viewer's gateway key must hold no .write scope, got {scopes:?}"
    );
    assert!(
        !scopes.iter().any(|scope| scope == "admin.write"),
        "a viewer must never hold admin.write (it self-escalates via \
         POST /admin/v1/virtual-keys), got {scopes:?}"
    );
}

/// A role value that predates the validator (or was written straight into a
/// D1 database, which carried no CHECK) must FAIL CLOSED: least privilege,
/// never the most privileged tier.
#[test]
fn a_legacy_unparseable_role_resolves_to_the_least_privilege() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "legacy-owner@acme.test",
        "correct-horse-517c",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    // Written directly to storage: no write path would accept this now.
    seed_teammate(
        &console,
        &tenant_id,
        "legacy@acme.test",
        "correct-horse-517c",
        "superuser",
    );

    let login = handle_admin_login(
        &console,
        AdminLoginRequest {
            email: "legacy@acme.test".into(),
            password: "correct-horse-517c".into(),
        },
    );
    assert_eq!(login.status, 200);
    let body = body_json(&login);
    assert_eq!(
        body["tenant"]["role"], "viewer",
        "an unknown stored role must be reported as the tier it actually got"
    );

    let material = virtual_api_key_material(body["gateway_api_key"].as_str().unwrap()).unwrap();
    let candidates = block_on_sync_bridge(
        console
            .repositories
            .find_api_key_records_by_prefix(&material.key_prefix),
    )
    .unwrap();
    assert_eq!(
        candidates[0].scopes,
        ["admin.read", "assets.read"],
        "an unknown stored role must not mint a write-capable key"
    );

    // ... and it must not pass the owner-only gate either.
    let token = body["access_token"].as_str().unwrap();
    let invite = handle_admin_team_invite(
        &console,
        token,
        AdminInviteRequest {
            email: "legacy-owner@acme.test".into(),
            role: "member".into(),
        },
    );
    assert_eq!(invite.status, 403);
}

/// Every path that WRITES a role validates it against the accepted set in
/// code -- not only in the Postgres CHECK the D1 twin lacks.
#[test]
fn invite_rejects_a_role_outside_the_accepted_set() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "role-validation-owner@acme.test",
        "correct-horse-517d",
    ));
    let owner_token = owner["access_token"].as_str().unwrap().to_string();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    register(&console, "invitee@acme.test", "correct-horse-517e");

    for role in ["superuser", "Owner", "", "   ", "owner,admin"] {
        let invite = handle_admin_team_invite(
            &console,
            &owner_token,
            AdminInviteRequest {
                email: "invitee@acme.test".into(),
                role: role.into(),
            },
        );
        assert_eq!(invite.status, 422, "role {role:?} must be rejected");
    }

    // Nothing was written: the tenant still has exactly its one owner.
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&tenant_id),
    )
    .unwrap();
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].role, "owner");

    // The accepted set still works.
    let ok = handle_admin_team_invite(
        &console,
        &owner_token,
        AdminInviteRequest {
            email: "invitee@acme.test".into(),
            role: "viewer".into(),
        },
    );
    assert_eq!(ok.status, 201);
    assert_eq!(body_json(&ok)["role"], "viewer");
}

#[test]
fn change_role_rejects_a_role_outside_the_accepted_set() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "change-validation-owner@acme.test",
        "correct-horse-517f",
    ));
    let owner_token = owner["access_token"].as_str().unwrap().to_string();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    let target_id = seed_teammate(
        &console,
        &tenant_id,
        "change-target@acme.test",
        "correct-horse-517f",
        "member",
    );

    for role in ["superuser", "ADMIN", "", "admin.write"] {
        let changed = handle_admin_team_change_role(
            &console,
            &owner_token,
            &target_id,
            AdminChangeRoleRequest { role: role.into() },
        );
        assert_eq!(changed.status, 422, "role {role:?} must be rejected");
    }

    // The stored role is untouched by every rejected attempt.
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&tenant_id),
    )
    .unwrap();
    let stored = memberships
        .iter()
        .find(|membership| membership.user_id == target_id)
        .unwrap();
    assert_eq!(stored.role, "member");

    let ok = handle_admin_team_change_role(
        &console,
        &owner_token,
        &target_id,
        AdminChangeRoleRequest {
            role: "viewer".into(),
        },
    );
    assert_eq!(ok.status, 200);
    assert_eq!(body_json(&ok)["role"], "viewer");
}

/// SCIM is an IdP-driven write path into the same column, and the D1 backend
/// has no CHECK to catch it.
#[test]
fn scim_user_create_rejects_a_role_outside_the_accepted_set() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-role-owner@acme.test",
        "correct-horse-517g",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-bad-role@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("superuser".into()),
        },
    );
    assert_eq!(create.status, 422);
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&tenant_id),
    )
    .unwrap();
    assert_eq!(memberships.len(), 1, "no membership may have been written");

    let ok = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-viewer@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("viewer".into()),
        },
    );
    assert_eq!(ok.status, 201);
    assert_eq!(body_json(&ok)["ferrogateRole"], "viewer");
}

#[test]
fn team_list_is_unauthorized_without_a_bearer_token() {
    let console = console();
    let response = handle_admin_team_list(&console, "not-a-real-jwt");
    assert_eq!(response.status, 401);
}

// -- issue #162: runtime Role/PolicyBinding CRUD ---------------------------

fn service() -> AuthService {
    AuthService::from_data(AuthServiceData::default())
}

#[test]
fn rbac_role_upsert_and_list_roundtrip() {
    let console = console();
    let service = service();
    let owner = body_json(&register(
        &console,
        "rbac-owner1@acme.test",
        "correct-horse-11",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();

    let create = handle_rbac_role_upsert(
        &service,
        &console,
        owner_token,
        RoleUpsertRequest {
            id: "role_reader".into(),
            name: "Reader".into(),
            permissions: vec![Permission {
                action: "chat.completions".into(),
                resource: "model:fast-chat".into(),
            }],
        },
    );
    assert_eq!(create.status, 200);

    let roles = service.rbac.list_roles();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, "role_reader");
    assert_eq!(roles[0].permissions.len(), 1);

    // Upserting the same id replaces it rather than duplicating.
    handle_rbac_role_upsert(
        &service,
        &console,
        owner_token,
        RoleUpsertRequest {
            id: "role_reader".into(),
            name: "Reader (renamed)".into(),
            permissions: vec![],
        },
    );
    let roles = service.rbac.list_roles();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].name, "Reader (renamed)");
}

#[test]
fn rbac_role_delete_refuses_while_a_binding_still_references_it() {
    let console = console();
    let service = service();
    let owner = body_json(&register(
        &console,
        "rbac-owner2@acme.test",
        "correct-horse-12",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    handle_rbac_role_upsert(
        &service,
        &console,
        owner_token,
        RoleUpsertRequest {
            id: "role_writer".into(),
            name: "Writer".into(),
            permissions: vec![],
        },
    );
    let bind = handle_rbac_binding_upsert(
        &service,
        &console,
        owner_token,
        BindingUpsertRequest {
            id: "binding_1".into(),
            role_id: "role_writer".into(),
            subject: PolicySubject::ApiKey {
                api_key_id: "key-1".into(),
            },
        },
    );
    assert_eq!(bind.status, 200);

    let delete_in_use = handle_rbac_role_delete(&service, &console, owner_token, "role_writer");
    assert_eq!(delete_in_use.status, 409);

    let unbind = handle_rbac_binding_delete(&service, &console, owner_token, "binding_1");
    assert_eq!(unbind.status, 200);

    let delete_now = handle_rbac_role_delete(&service, &console, owner_token, "role_writer");
    assert_eq!(delete_now.status, 200);
}

#[test]
fn rbac_binding_upsert_is_forbidden_for_a_non_owner() {
    let console = console();
    let service = service();
    let owner = body_json(&register(
        &console,
        "rbac-owner3@acme.test",
        "correct-horse-13",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    handle_rbac_role_upsert(
        &service,
        &console,
        owner_token,
        RoleUpsertRequest {
            id: "role_viewer".into(),
            name: "Viewer".into(),
            permissions: vec![],
        },
    );
    let member = body_json(&register(
        &console,
        "rbac-member3@acme.test",
        "correct-horse-14",
    ));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "rbac-member3@acme.test".into(),
            role: "member".into(),
        },
    );
    let (member_token, _) = issue_session(
        &console,
        member_user_id,
        "rbac-member3@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();

    let bind = handle_rbac_binding_upsert(
        &service,
        &console,
        &member_token,
        BindingUpsertRequest {
            id: "binding_2".into(),
            role_id: "role_viewer".into(),
            subject: PolicySubject::ApiKey {
                api_key_id: "key-2".into(),
            },
        },
    );

    assert_eq!(bind.status, 403);
}

#[test]
fn rbac_binding_upsert_rejects_unknown_role_id() {
    let console = console();
    let service = service();
    let owner = body_json(&register(
        &console,
        "rbac-owner4@acme.test",
        "correct-horse-15",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();

    let bind = handle_rbac_binding_upsert(
        &service,
        &console,
        owner_token,
        BindingUpsertRequest {
            id: "binding_3".into(),
            role_id: "role_does_not_exist".into(),
            subject: PolicySubject::ApiKey {
                api_key_id: "key-3".into(),
            },
        },
    );

    assert_eq!(bind.status, 422);
}

#[test]
fn rbac_binding_delete_refuses_to_touch_another_tenants_binding() {
    let console = console();
    let service = service();
    let tenant_a_owner = body_json(&register(&console, "rbac-a@acme.test", "correct-horse-16"));
    let tenant_a_token = tenant_a_owner["access_token"].as_str().unwrap();
    let tenant_b_owner = body_json(&register(&console, "rbac-b@acme.test", "correct-horse-17"));
    let tenant_b_token = tenant_b_owner["access_token"].as_str().unwrap();
    handle_rbac_role_upsert(
        &service,
        &console,
        tenant_a_token,
        RoleUpsertRequest {
            id: "role_shared".into(),
            name: "Shared".into(),
            permissions: vec![],
        },
    );
    handle_rbac_binding_upsert(
        &service,
        &console,
        tenant_a_token,
        BindingUpsertRequest {
            id: "binding_a".into(),
            role_id: "role_shared".into(),
            subject: PolicySubject::ApiKey {
                api_key_id: "key-a".into(),
            },
        },
    );

    // Tenant B's owner cannot delete tenant A's binding, even though they
    // are also a valid owner elsewhere.
    let cross_tenant_delete =
        handle_rbac_binding_delete(&service, &console, tenant_b_token, "binding_a");
    assert_eq!(cross_tenant_delete.status, 404);

    // The binding is untouched.
    let bindings = service.rbac.list_bindings_for_tenant(&tenant_context_for(
        tenant_a_owner["tenant"]["id"].as_str().unwrap(),
    ));
    assert_eq!(bindings.len(), 1);
}

#[test]
fn rbac_authorize_reflects_runtime_bindings_immediately() {
    let service = service();
    let request = AuthorizeRequest {
        tenant: TenantContext {
            organization_id: Some("tenant-runtime".into()),
            ..TenantContext::default()
        },
        subject: PolicySubject::ApiKey {
            api_key_id: "key-runtime".into(),
        },
        action: "chat.completions".into(),
        resource: "model:fast-chat".into(),
    };

    // No role/binding yet -- denied.
    assert!(!service.authorize(&request).allowed);

    service.rbac.upsert_role(Role {
        id: "role_runtime".into(),
        name: "Runtime".into(),
        tenant_id: None,
        permissions: vec![Permission {
            action: "chat.completions".into(),
            resource: "model:fast-chat".into(),
        }],
    });
    service
        .rbac
        .upsert_binding(PolicyBinding {
            id: "binding_runtime".into(),
            role_id: "role_runtime".into(),
            tenant: TenantContext {
                organization_id: Some("tenant-runtime".into()),
                ..TenantContext::default()
            },
            subject: PolicySubject::ApiKey {
                api_key_id: "key-runtime".into(),
            },
        })
        .unwrap();

    // The exact same service instance now allows it -- no restart, no YAML
    // reload, just the runtime REST-backed mutation (issue #162).
    let decision = service.authorize(&request);
    assert!(decision.allowed);
    assert_eq!(decision.reason, "matched_rbac_binding");
}

// -- issue #161: SCIM 2.0 user/group provisioning --------------------------

fn scim_request(method: &str, path: &str, token: &str, body: Vec<u8>) -> HttpRequest {
    let mut headers = HashMap::new();
    if !token.is_empty() {
        headers.insert("authorization".to_string(), format!("Bearer {token}"));
    }
    HttpRequest {
        method: method.into(),
        path: path.into(),
        query: String::new(),
        headers,
        body,
    }
}

#[test]
fn scim_token_create_requires_owner_and_mints_a_scim_scoped_key() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner1@acme.test",
        "correct-horse-18",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();

    let created = handle_admin_scim_token_create(&console, owner_token);
    assert_eq!(created.status, 201);
    let scim_token = body_json(&created)["token"].as_str().unwrap().to_string();
    assert!(scim_token.starts_with("fg_"));

    let request = scim_request("GET", "/scim/v2/Users", &scim_token, Vec::new());
    let tenant_id = resolve_scim_tenant(&console, &request).unwrap();
    assert_eq!(tenant_id, owner["tenant"]["id"].as_str().unwrap());
}

#[test]
fn scim_token_create_is_forbidden_for_a_non_owner() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner2@acme.test",
        "correct-horse-19",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let member = body_json(&register(
        &console,
        "scim-member2@acme.test",
        "correct-horse-20",
    ));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "scim-member2@acme.test".into(),
            role: "member".into(),
        },
    );
    let (member_token, _) = issue_session(
        &console,
        member_user_id,
        "scim-member2@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();

    let created = handle_admin_scim_token_create(&console, &member_token);
    assert_eq!(created.status, 403);
}

#[test]
fn resolve_scim_tenant_rejects_missing_and_wrong_scope_tokens() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner3@acme.test",
        "correct-horse-21",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();

    let no_token = scim_request("GET", "/scim/v2/Users", "", Vec::new());
    assert!(resolve_scim_tenant(&console, &no_token).is_err());

    // A regular admin-console JWT is not a virtual-key-shaped credential,
    // so it must not resolve as a SCIM token either.
    let jwt_as_scim = scim_request("GET", "/scim/v2/Users", owner_token, Vec::new());
    assert!(resolve_scim_tenant(&console, &jwt_as_scim).is_err());

    // A real gateway_api_key (admin.read/admin.write scoped, not
    // scim.provision) must also be rejected.
    let gateway_key = owner["gateway_api_key"].as_str().unwrap();
    let wrong_scope = scim_request("GET", "/scim/v2/Users", gateway_key, Vec::new());
    assert!(resolve_scim_tenant(&console, &wrong_scope).is_err());
}

#[test]
fn scim_user_create_provisions_a_new_account_with_the_given_role() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner4@acme.test",
        "correct-horse-22",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-provisioned@acme.test".into(),
            active: None,
            display_name: Some("SCIM User".into()),
            ferrogate_role: Some("admin".into()),
        },
    );
    assert_eq!(create.status, 201);
    let body = body_json(&create);
    assert_eq!(body["userName"], "scim-provisioned@acme.test");
    assert_eq!(body["ferrogateRole"], "admin");
    assert_eq!(body["active"], true);

    let user = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_by_email("scim-provisioned@acme.test"),
    )
    .unwrap()
    .unwrap();
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&tenant_id),
    )
    .unwrap();
    let membership = memberships
        .iter()
        .find(|membership| membership.user_id == user.id)
        .unwrap();
    // Not hardcoded to "owner" -- the actual bug #162/#161 close out.
    assert_eq!(membership.role, "admin");
}

#[test]
fn scim_user_create_adds_membership_for_an_already_registered_user_without_duplicating_the_account()
{
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner5@acme.test",
        "correct-horse-23",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    let existing = body_json(&register(
        &console,
        "scim-existing@acme.test",
        "correct-horse-24",
    ));
    let existing_user_id = existing["user"]["id"].as_str().unwrap().to_string();

    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-existing@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );
    assert_eq!(create.status, 201);
    assert_eq!(body_json(&create)["id"], existing_user_id);

    // Same account, now with a second membership -- not a duplicate user.
    let memberships = block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(&existing_user_id),
    )
    .unwrap();
    assert_eq!(memberships.len(), 2);
}

#[test]
fn scim_user_list_and_get_reflect_provisioned_users() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner6@acme.test",
        "correct-horse-25",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-listed@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );

    let list = handle_scim_users_list(&console, &tenant_id);
    assert_eq!(list.status, 200);
    let body = body_json(&list);
    assert_eq!(body["totalResults"], 2); // owner + provisioned member

    let listed_id = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|resource| resource["userName"] == "scim-listed@acme.test")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let get = handle_scim_user_get(&console, &tenant_id, &listed_id);
    assert_eq!(get.status, 200);
    assert_eq!(body_json(&get)["userName"], "scim-listed@acme.test");

    assert_eq!(
        handle_scim_user_get(&console, &tenant_id, "no-such-id").status,
        404
    );
}

#[test]
fn scim_patch_deactivate_revokes_refresh_tokens_and_supports_reactivation() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner7@acme.test",
        "correct-horse-26",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-deactivate@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );
    let user_id = body_json(&create)["id"].as_str().unwrap().to_string();

    // Issue the user a live session, matching what a real login would do.
    let (_, refresh_secret) = issue_session(
        &console,
        &user_id,
        "scim-deactivate@acme.test",
        &tenant_id,
        "member",
    )
    .unwrap();
    let refresh_hash = hash_virtual_api_key_secret(&refresh_secret);
    assert!(block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&refresh_hash)
    )
    .unwrap()
    .unwrap()
    .revoked_at_unix
    .is_none());

    let patch_body = serde_json::to_vec(&serde_json::json!({ "active": false })).unwrap();
    let patch = handle_scim_user_patch(&console, &tenant_id, &user_id, &patch_body);
    assert_eq!(patch.status, 200);
    assert_eq!(body_json(&patch)["active"], false);

    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&user_id))
        .unwrap()
        .unwrap();
    assert!(user.disabled_at_unix.is_some());
    let refreshed = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&refresh_hash),
    )
    .unwrap()
    .unwrap();
    assert!(
        refreshed.revoked_at_unix.is_some(),
        "deactivation must revoke existing sessions, not just block future logins"
    );

    // The standards-shaped SCIM PATCH Operations body also works.
    let standard_patch_body = serde_json::to_vec(&serde_json::json!({
        "Operations": [{"op": "replace", "path": "active", "value": true}]
    }))
    .unwrap();
    let reactivate = handle_scim_user_patch(&console, &tenant_id, &user_id, &standard_patch_body);
    assert_eq!(reactivate.status, 200);
    assert_eq!(body_json(&reactivate)["active"], true);
    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&user_id))
        .unwrap()
        .unwrap();
    assert!(user.disabled_at_unix.is_none());
}

#[test]
fn scim_patch_rejects_a_body_with_no_recognizable_active_value() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner7b@acme.test",
        "correct-horse-26b",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-badpatch@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );
    let user_id = body_json(&create)["id"].as_str().unwrap().to_string();

    let patch = handle_scim_user_patch(&console, &tenant_id, &user_id, b"{}");
    assert_eq!(patch.status, 422);
}

#[test]
fn scim_delete_deprovisions_a_user() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner8@acme.test",
        "correct-horse-27",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-delete@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );
    let user_id = body_json(&create)["id"].as_str().unwrap().to_string();

    let delete = handle_scim_user_delete(&console, &tenant_id, &user_id);
    assert_eq!(delete.status, 204);

    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&user_id))
        .unwrap()
        .unwrap();
    assert!(user.disabled_at_unix.is_some());

    assert_eq!(
        handle_scim_user_delete(&console, &tenant_id, "no-such-id").status,
        404
    );
}

#[test]
fn scim_groups_list_reflects_distinct_tenant_roles() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner9@acme.test",
        "correct-horse-28",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();
    handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "scim-group-member@acme.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("admin".into()),
        },
    );

    let groups = handle_scim_groups_list(&console, &tenant_id);
    assert_eq!(groups.status, 200);
    let names: Vec<String> = body_json(&groups)["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|resource| resource["displayName"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"owner".to_string()));
    assert!(names.contains(&"admin".to_string()));
}

#[test]
fn scim_user_create_rejects_invalid_username() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "scim-owner10@acme.test",
        "correct-horse-29",
    ));
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let create = handle_scim_user_create(
        &console,
        &tenant_id,
        ScimUserRequest {
            user_name: "not-an-email".into(),
            active: None,
            display_name: None,
            ferrogate_role: None,
        },
    );
    assert_eq!(create.status, 422);
}

// -- issue #160: OIDC SSO (Authorization Code + PKCE) ----------------------

#[derive(Clone)]
struct MockOidcRealm {
    jwks_json: String,
    id_token: String,
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    let chars: Vec<char> = hex.chars().collect();
    let mut bytes = Vec::with_capacity(chars.len() / 2);
    let mut index = 0;
    while index + 1 < chars.len() {
        let byte_str: String = chars[index..index + 2].iter().collect();
        bytes.push(u8::from_str_radix(&byte_str, 16).unwrap());
        index += 2;
    }
    bytes
}

/// Shells out to `openssl` (already relied on by the existing ACME tests)
/// to generate a real RSA keypair, returning the PEM-encoded private key
/// and the modulus (`n`) as a base64url string for building a matching JWK.
/// The public exponent is always `65537` ("AQAB") for openssl-generated
/// keys, so it's hardcoded rather than parsed.
fn generate_test_rsa_key() -> (Vec<u8>, String) {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.pem");
    let status = std::process::Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(&key_path)
        .arg("2048")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("openssl must be available to generate a test RSA key");
    assert!(status.success(), "openssl genrsa failed");
    let pem = std::fs::read(&key_path).unwrap();

    let modulus_output = std::process::Command::new("openssl")
        .arg("rsa")
        .arg("-in")
        .arg(&key_path)
        .arg("-noout")
        .arg("-modulus")
        .output()
        .expect("openssl rsa -modulus must succeed");
    assert!(modulus_output.status.success());
    let modulus_text = String::from_utf8(modulus_output.stdout).unwrap();
    let hex = modulus_text
        .trim()
        .strip_prefix("Modulus=")
        .expect("openssl -modulus output must start with Modulus=");
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decode_hex(hex));
    (pem, n)
}

fn jwks_json_for(n: &str, kid: &str) -> String {
    serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": kid,
            "alg": "RS256",
            "n": n,
            "e": "AQAB",
        }]
    })
    .to_string()
}

fn sign_test_id_token(
    key_pem: &[u8],
    kid: &str,
    issuer: &str,
    audience: &str,
    extra_claims: serde_json::Value,
) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let now = now_unix_seconds();
    let mut claims = serde_json::json!({
        "iss": issuer,
        "sub": "idp-user-1",
        "aud": audience,
        "iat": now,
        "exp": now + 300,
    });
    for (key, value) in extra_claims.as_object().unwrap() {
        claims[key] = value.clone();
    }
    encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(key_pem).unwrap(),
    )
    .unwrap()
}

/// Binds a mock OIDC IdP's listener up front so the real, OS-assigned port
/// is known before signing the ID token (whose `iss` claim must match).
fn bind_mock_oidc_server() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, format!("http://{addr}"))
}

/// Serves discovery/JWKS/token-exchange responses for up to 8 connections,
/// matching the small, fixed number of requests one authorize+callback
/// round trip makes (discovery is fetched twice since nothing is cached).
fn run_mock_oidc_server(listener: TcpListener, realm: MockOidcRealm, issuer: String) {
    std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(stream) = stream else { break };
            handle_mock_oidc_connection(stream, &realm, &issuer);
        }
    });
}

fn handle_mock_oidc_connection(
    mut stream: std::net::TcpStream,
    realm: &MockOidcRealm,
    issuer: &str,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(_) => return,
        };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos;
        }
        if buffer.len() > 65_536 {
            return;
        }
    };
    let header_text = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = header_text.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    let content_length: usize = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = match stream.read(&mut chunk) {
            Ok(read) => read,
            Err(_) => break,
        };
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body_end = (body_start + content_length).min(buffer.len());
    let body = String::from_utf8_lossy(&buffer[body_start..body_end]).to_string();

    if let Ok(mut requests) = realm.requests.lock() {
        requests.push((path.clone(), body));
    }

    let (status, content_body) = if path.starts_with("/.well-known/openid-configuration") {
        (
            200,
            serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
            })
            .to_string(),
        )
    } else if path.starts_with("/jwks") {
        (200, realm.jwks_json.clone())
    } else if path.starts_with("/token") {
        (
            200,
            serde_json::json!({ "id_token": realm.id_token, "access_token": "mock-access-token" })
                .to_string(),
        )
    } else {
        (404, "{}".to_string())
    };
    let response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        content_body.len(),
        content_body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Env var the tests point `client_secret_ref` at. Since the mock IdP's token
/// endpoint does not validate the client secret, any resolvable value works;
/// what matters is that the secret is stored/resolved via a `secret_ref` rather
/// than persisted in plaintext (#283).
const TEST_OIDC_SECRET_ENV: &str = "FERROGATE_TEST_OIDC_CLIENT_SECRET";

fn sso_config_request(issuer: &str) -> SsoConfigRequest {
    // SAFETY: single-threaded test setup; the value is stable across the suite.
    std::env::set_var(TEST_OIDC_SECRET_ENV, "test-client-secret");
    SsoConfigRequest {
        provider_kind: "oidc".into(),
        issuer: Some(issuer.to_string()),
        client_id: Some("test-client-id".into()),
        client_secret_ref: Some(format!("env://{TEST_OIDC_SECRET_ENV}")),
        redirect_uri: Some("http://localhost:3000/callback".into()),
        group_role_mapping: [("Engineering".to_string(), "admin".to_string())]
            .into_iter()
            .collect(),
        default_role: "member".into(),
        group_claim: "groups".into(),
        idp_entity_id: None,
        idp_sso_url: None,
        idp_certificate: None,
        sp_entity_id: None,
        acs_url: None,
        email_attribute: None,
        name_attribute: None,
        groups_attribute: None,
    }
}

/// Issue #517: an SSO config is a deferred role WRITE -- `default_role` and
/// every `group_role_mapping` value lands verbatim in
/// `admin_user_tenant_memberships.role` on a first SSO login. Validate the
/// tiers at config time, and persist nothing when one is unknown.
#[test]
fn sso_config_set_rejects_role_values_outside_the_accepted_set() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "sso-role-validation@acme.test",
        "correct-horse-517h",
    ));
    let owner_token = owner["access_token"].as_str().unwrap().to_string();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let mut bad_default = sso_config_request("https://idp.example.test");
    bad_default.default_role = "superuser".into();
    let response = handle_admin_sso_config_set(&console, &owner_token, bad_default);
    assert_eq!(response.status, 422);
    assert!(body_json(&response)["error"]["message"]
        .as_str()
        .unwrap()
        .contains("default_role"));

    let mut bad_mapping = sso_config_request("https://idp.example.test");
    bad_mapping.group_role_mapping = [("Engineering".to_string(), "root".to_string())]
        .into_iter()
        .collect();
    let response = handle_admin_sso_config_set(&console, &owner_token, bad_mapping);
    assert_eq!(response.status, 422);
    assert!(body_json(&response)["error"]["message"]
        .as_str()
        .unwrap()
        .contains("group_role_mapping"));

    // Nothing was persisted by either rejected attempt.
    assert!(
        block_on_sync_bridge(console.repositories.get_sso_provider_config(&tenant_id))
            .unwrap()
            .is_none(),
        "a rejected SSO config must not be stored"
    );

    // The accepted set still configures.
    let ok = handle_admin_sso_config_set(
        &console,
        &owner_token,
        sso_config_request("https://idp.example.test"),
    );
    assert_eq!(ok.status, 200);
}

#[test]
fn sso_config_set_requires_owner() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "sso-owner-gate@acme.test",
        "correct-horse-31",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let member = body_json(&register(
        &console,
        "sso-member-gate@acme.test",
        "correct-horse-32",
    ));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "sso-member-gate@acme.test".into(),
            role: "member".into(),
        },
    );
    let (member_token, _) = issue_session(
        &console,
        member_user_id,
        "sso-member-gate@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();

    let forbidden_set = handle_admin_sso_config_set(
        &console,
        &member_token,
        sso_config_request("http://127.0.0.1:1"),
    );
    assert_eq!(forbidden_set.status, 403);

    let ok_set = handle_admin_sso_config_set(
        &console,
        owner_token,
        sso_config_request("http://127.0.0.1:1"),
    );
    assert_eq!(ok_set.status, 200);
}

#[test]
fn sso_authorize_returns_404_when_not_configured() {
    let console = console();
    let response = handle_sso_authorize(&console, "no-such-tenant");
    assert_eq!(response.status, 404);
}

#[test]
fn sso_end_to_end_provisions_new_user_and_maps_group_to_role() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "sso-owner2@acme.test",
        "correct-horse-33",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let (listener, issuer) = bind_mock_oidc_server();
    let (key_pem, n) = generate_test_rsa_key();
    let kid = "test-key-1";
    let jwks_json = jwks_json_for(&n, kid);
    let id_token = sign_test_id_token(
        &key_pem,
        kid,
        &issuer,
        "test-client-id",
        serde_json::json!({
            "email": "sso-user@acme.test",
            "name": "SSO User",
            "groups": ["Engineering"],
        }),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let realm = MockOidcRealm {
        jwks_json,
        id_token,
        requests: requests.clone(),
    };
    run_mock_oidc_server(listener, realm, issuer.clone());

    let config_set =
        handle_admin_sso_config_set(&console, owner_token, sso_config_request(&issuer));
    assert_eq!(config_set.status, 200);

    let authorize = handle_sso_authorize(&console, &tenant_id);
    assert_eq!(authorize.status, 200);
    let authorize_body = body_json(&authorize);
    let state = authorize_body["state"].as_str().unwrap().to_string();
    assert!(authorize_body["authorize_url"]
        .as_str()
        .unwrap()
        .starts_with(&format!("{issuer}/authorize")));

    let callback = handle_sso_callback(&console, "fake-authorization-code", &state);
    assert_eq!(callback.status, 200);
    let session = body_json(&callback);
    assert_eq!(session["user"]["email"], "sso-user@acme.test");
    assert_eq!(session["tenant"]["id"], tenant_id);
    // Mapped via group_role_mapping (Engineering -> admin), not hardcoded
    // to "owner" or the configured default_role ("member").
    assert_eq!(session["tenant"]["role"], "admin");
    assert!(session["access_token"].as_str().unwrap().contains('.'));
    assert!(session["gateway_api_key"]
        .as_str()
        .unwrap()
        .starts_with("fg_"));

    // JIT-provisioned: a real StoredAdminUser + membership now exist.
    let user = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_by_email("sso-user@acme.test"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        membership_role_in_tenant(&console, &tenant_id, &user.id).as_deref(),
        Some("admin")
    );

    // PKCE was actually exercised end-to-end: the token-exchange request
    // included a code_verifier alongside the authorization code.
    let logged = requests.lock().unwrap();
    let token_request = logged
        .iter()
        .find(|(path, _)| path.starts_with("/token"))
        .expect("token endpoint must have been called");
    assert!(token_request.1.contains("code_verifier="));
    assert!(token_request.1.contains("grant_type=authorization_code"));
    assert!(token_request.1.contains("code=fake-authorization-code"));
    drop(logged);

    // The state is single-use: replaying the same callback must fail.
    let replay = handle_sso_callback(&console, "fake-authorization-code", &state);
    assert_eq!(replay.status, 401);
}

/// Round-13 audit: a tenant's own IdP must not be able to authenticate a
/// pre-existing GLOBAL account that belongs to a different tenant. Otherwise a
/// self-registered tenant owner, running their own IdP, could assert a victim's
/// email and mint a session/refresh-token bound to the victim's account
/// (cross-tenant account takeover).
#[test]
fn sso_callback_refuses_to_claim_a_foreign_pre_existing_account() {
    let console = console();
    // Victim owns tenant A -> a real global StoredAdminUser + tenant-A membership.
    let victim = body_json(&register(
        &console,
        "victim@tenant-a.test",
        "correct-horse-44",
    ));
    let victim_tenant = victim["tenant"]["id"].as_str().unwrap().to_string();

    // Attacker owns tenant B and controls its IdP.
    let attacker = body_json(&register(
        &console,
        "attacker@tenant-b.test",
        "correct-horse-55",
    ));
    let attacker_token = attacker["access_token"].as_str().unwrap();
    let attacker_tenant = attacker["tenant"]["id"].as_str().unwrap().to_string();

    // The attacker's IdP asserts the VICTIM's email.
    let (listener, issuer) = bind_mock_oidc_server();
    let (key_pem, n) = generate_test_rsa_key();
    let kid = "test-key-1";
    let jwks_json = jwks_json_for(&n, kid);
    let id_token = sign_test_id_token(
        &key_pem,
        kid,
        &issuer,
        "test-client-id",
        serde_json::json!({ "email": "victim@tenant-a.test", "name": "Victim" }),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let realm = MockOidcRealm {
        jwks_json,
        id_token,
        requests: requests.clone(),
    };
    run_mock_oidc_server(listener, realm, issuer.clone());

    let config_set =
        handle_admin_sso_config_set(&console, attacker_token, sso_config_request(&issuer));
    assert_eq!(config_set.status, 200);
    let authorize = handle_sso_authorize(&console, &attacker_tenant);
    assert_eq!(authorize.status, 200);
    let state = body_json(&authorize)["state"].as_str().unwrap().to_string();

    // The callback must REFUSE: the victim's account is not provisioned in
    // tenant B, so its IdP cannot authenticate it.
    let callback = handle_sso_callback(&console, "fake-authorization-code", &state);
    assert_eq!(
        callback.status,
        401,
        "SSO must not authenticate a foreign pre-existing account: {:?}",
        body_json(&callback)
    );

    // No cross-tenant membership was created, and the victim still only belongs
    // to tenant A -- no session/refresh-token was minted for the victim.
    let victim_user = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_by_email("victim@tenant-a.test"),
    )
    .unwrap()
    .unwrap();
    assert!(
        membership_role_in_tenant(&console, &attacker_tenant, &victim_user.id).is_none(),
        "SSO refusal must not create a cross-tenant membership for the victim",
    );
    assert!(membership_role_in_tenant(&console, &victim_tenant, &victim_user.id).is_some());
}

#[test]
fn sso_callback_rejects_an_unknown_state() {
    let console = console();
    let response = handle_sso_callback(&console, "some-code", "never-issued-state");
    assert_eq!(response.status, 401);
}

#[test]
fn sso_second_login_does_not_overwrite_a_role_set_afterward() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "sso-owner3@acme.test",
        "correct-horse-34",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let (listener, issuer) = bind_mock_oidc_server();
    let (key_pem, n) = generate_test_rsa_key();
    let kid = "test-key-2";
    let jwks_json = jwks_json_for(&n, kid);
    let id_token = sign_test_id_token(
        &key_pem,
        kid,
        &issuer,
        "test-client-id",
        serde_json::json!({
            "email": "sso-user2@acme.test",
            "name": "SSO User Two",
            "groups": ["Engineering"],
        }),
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let realm = MockOidcRealm {
        jwks_json,
        id_token,
        requests,
    };
    run_mock_oidc_server(listener, realm, issuer.clone());
    handle_admin_sso_config_set(&console, owner_token, sso_config_request(&issuer));

    // First login: JIT-provisioned as "admin" via the group mapping.
    let state_1 = body_json(&handle_sso_authorize(&console, &tenant_id))["state"]
        .as_str()
        .unwrap()
        .to_string();
    let first = handle_sso_callback(&console, "code-1", &state_1);
    assert_eq!(first.status, 200);
    assert_eq!(body_json(&first)["tenant"]["role"], "admin");

    // An owner then demotes them to "member" via the ordinary team API.
    let user_id = body_json(&first)["user"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let change = handle_admin_team_change_role(
        &console,
        owner_token,
        &user_id,
        AdminChangeRoleRequest {
            role: "member".into(),
        },
    );
    assert_eq!(change.status, 200);

    // A second SSO login (same IdP groups) must NOT silently re-promote them
    // back to "admin" -- the explicit change takes precedence.
    let state_2 = body_json(&handle_sso_authorize(&console, &tenant_id))["state"]
        .as_str()
        .unwrap()
        .to_string();
    let second = handle_sso_callback(&console, "code-2", &state_2);
    assert_eq!(second.status, 200);
    assert_eq!(body_json(&second)["tenant"]["role"], "member");
}

// -- issue #232: tenant-scoped accounts/roles/refresh tokens ---------------

/// Finding #1 (cross-tenant refresh confusion): a refresh token minted for a
/// session in tenant B must re-issue a session for tenant B -- not for
/// `memberships.first()`, the user's OLDEST membership (their own tenant A).
#[test]
fn refresh_reissues_for_the_tokens_tenant_not_the_first_membership() {
    let console = console();
    // The user's oldest membership: owner of their own tenant A.
    let user = body_json(&register(&console, "multi@acme.test", "correct-horse-60"));
    let user_id = user["user"]["id"].as_str().unwrap().to_string();
    let tenant_a = user["tenant"]["id"].as_str().unwrap().to_string();
    // Later invited into tenant B as a plain member.
    let owner_b = body_json(&register(&console, "owner-b@acme.test", "correct-horse-61"));
    let owner_b_token = owner_b["access_token"].as_str().unwrap();
    let tenant_b = owner_b["tenant"]["id"].as_str().unwrap().to_string();
    handle_admin_team_invite(
        &console,
        owner_b_token,
        AdminInviteRequest {
            email: "multi@acme.test".into(),
            role: "member".into(),
        },
    );

    // A session issued for tenant B (as "member")...
    let (_, refresh_secret) =
        issue_session(&console, &user_id, "multi@acme.test", &tenant_b, "member").unwrap();
    let stored = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&hash_virtual_api_key_secret(&refresh_secret)),
    )
    .unwrap()
    .unwrap();
    assert_eq!(stored.tenant_id.as_deref(), Some(tenant_b.as_str()));
    assert_eq!(stored.role.as_deref(), Some("member"));

    // ...must refresh back into tenant B as "member", not tenant A as owner.
    let refreshed = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: refresh_secret,
        },
    );
    assert_eq!(refreshed.status, 200);
    let body = body_json(&refreshed);
    let claims = decode_access_token(&console, body["access_token"].as_str().unwrap()).unwrap();
    assert_eq!(claims.tenant_id, tenant_b);
    assert_eq!(claims.role, "member");
    assert_ne!(claims.tenant_id, tenant_a);

    // The rotated refresh token is stamped for tenant B too.
    let rotated = block_on_sync_bridge(console.repositories.get_admin_user_refresh_token_by_hash(
        &hash_virtual_api_key_secret(body["refresh_token"].as_str().unwrap()),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(rotated.tenant_id.as_deref(), Some(tenant_b.as_str()));
}

/// Finding #1, legacy data: a pre-#232 refresh token row has no stamped
/// tenant. The secure option is to reject it (forcing one fresh login)
/// rather than guessing a tenant -- and the attempt still burns the token.
#[test]
fn refresh_rejects_a_legacy_token_with_no_stamped_tenant() {
    let console = console();
    let user = body_json(&register(&console, "legacy@acme.test", "correct-horse-62"));
    let user_id = user["user"]["id"].as_str().unwrap().to_string();

    let legacy_secret = "legacy-refresh-secret-000000000000000000000000000000000000000000";
    let now = now_unix_seconds() as i64;
    block_on_sync_bridge(console.repositories.upsert_admin_user_refresh_token(
        StoredAdminUserRefreshToken {
            id: "rt-legacy-1".into(),
            user_id: user_id.clone(),
            token_hash: hash_virtual_api_key_secret(legacy_secret),
            tenant_id: None,
            role: None,
            created_at_unix: now,
            expires_at_unix: now + 3600,
            revoked_at_unix: None,
        },
    ))
    .unwrap();

    let refreshed = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: legacy_secret.into(),
        },
    );
    assert_eq!(refreshed.status, 401);
    let burned = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&hash_virtual_api_key_secret(legacy_secret)),
    )
    .unwrap()
    .unwrap();
    assert!(burned.revoked_at_unix.is_some());
}

/// Finding #1 follow-through: if the membership the token was stamped for
/// has since been revoked, the refresh must fail rather than fall back to a
/// different tenant.
#[test]
fn refresh_rejects_when_the_stamped_tenant_membership_was_revoked() {
    let console = console();
    let user = body_json(&register(&console, "revoked@acme.test", "correct-horse-63"));
    let user_id = user["user"]["id"].as_str().unwrap().to_string();
    let owner_b = body_json(&register(
        &console,
        "owner-b2@acme.test",
        "correct-horse-64",
    ));
    let owner_b_token = owner_b["access_token"].as_str().unwrap();
    let tenant_b = owner_b["tenant"]["id"].as_str().unwrap().to_string();
    handle_admin_team_invite(
        &console,
        owner_b_token,
        AdminInviteRequest {
            email: "revoked@acme.test".into(),
            role: "member".into(),
        },
    );
    let (_, refresh_secret) =
        issue_session(&console, &user_id, "revoked@acme.test", &tenant_b, "member").unwrap();

    // Tenant B's owner removes them from the team.
    let revoke = handle_admin_team_revoke(&console, owner_b_token, &user_id);
    assert_eq!(revoke.status, 200);

    // The tenant-B session cannot be refreshed -- and must NOT silently
    // become a tenant-A (owner) session either.
    let refreshed = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: refresh_secret,
        },
    );
    assert_eq!(refreshed.status, 401);
}

/// Finding #2 (SCIM cross-tenant disable): deactivating a multi-tenant user
/// via one tenant's SCIM credential must only deprovision them from THAT
/// tenant -- never disable the shared global account or revoke the sessions
/// they hold in their other tenants.
#[test]
fn scim_deactivate_is_tenant_scoped_for_a_multi_tenant_account() {
    let console = console();
    // Victim: owner of their own tenant A, with a live tenant-A session.
    let victim = body_json(&register(
        &console,
        "victim2@tenant-a.test",
        "correct-horse-65",
    ));
    let victim_id = victim["user"]["id"].as_str().unwrap().to_string();
    let tenant_a = victim["tenant"]["id"].as_str().unwrap().to_string();
    let victim_a_refresh = victim["refresh_token"].as_str().unwrap().to_string();

    // Tenant B provisions the same email over SCIM (attaching a membership
    // to the pre-existing global account), and the victim gets a B session.
    let owner_b = body_json(&register(
        &console,
        "owner-b3@acme.test",
        "correct-horse-66",
    ));
    let tenant_b = owner_b["tenant"]["id"].as_str().unwrap().to_string();
    let create = handle_scim_user_create(
        &console,
        &tenant_b,
        ScimUserRequest {
            user_name: "victim2@tenant-a.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );
    assert_eq!(create.status, 201);
    let (_, victim_b_refresh) = issue_session(
        &console,
        &victim_id,
        "victim2@tenant-a.test",
        &tenant_b,
        "member",
    )
    .unwrap();

    // Tenant B deactivates the victim over SCIM.
    let patch_body = serde_json::to_vec(&serde_json::json!({ "active": false })).unwrap();
    let patch = handle_scim_user_patch(&console, &tenant_b, &victim_id, &patch_body);
    assert_eq!(patch.status, 200);
    assert_eq!(body_json(&patch)["active"], false);

    // The global account is NOT disabled (the pre-#232 cross-tenant DoS).
    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&victim_id))
        .unwrap()
        .unwrap();
    assert!(
        user.disabled_at_unix.is_none(),
        "tenant B's SCIM deactivation must not disable the account system-wide"
    );
    // Only tenant B's membership is gone; tenant A's survives.
    assert!(membership_role_in_tenant(&console, &tenant_b, &victim_id).is_none());
    assert!(membership_role_in_tenant(&console, &tenant_a, &victim_id).is_some());
    // Only tenant B's session was revoked; the tenant-A session still works.
    let b_token = block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&hash_virtual_api_key_secret(&victim_b_refresh)),
    )
    .unwrap()
    .unwrap();
    assert!(b_token.revoked_at_unix.is_some());
    let a_refresh = handle_admin_refresh(
        &console,
        AdminRefreshRequest {
            refresh_token: victim_a_refresh,
        },
    );
    assert_eq!(
        a_refresh.status, 200,
        "the victim's tenant-A session must survive tenant B's SCIM deactivation"
    );
    let a_claims = decode_access_token(
        &console,
        body_json(&a_refresh)["access_token"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(a_claims.tenant_id, tenant_a);
}

/// Finding #2, DELETE variant plus the last-membership rule: deprovisioning
/// from one tenant of a multi-tenant user leaves the account enabled, and
/// only the LAST tenant's deprovision globally disables it.
#[test]
fn scim_delete_only_disables_globally_when_the_last_membership_is_removed() {
    let console = console();
    let victim = body_json(&register(
        &console,
        "victim3@tenant-a.test",
        "correct-horse-67",
    ));
    let victim_id = victim["user"]["id"].as_str().unwrap().to_string();
    let tenant_a = victim["tenant"]["id"].as_str().unwrap().to_string();
    let owner_b = body_json(&register(
        &console,
        "owner-b4@acme.test",
        "correct-horse-68",
    ));
    let tenant_b = owner_b["tenant"]["id"].as_str().unwrap().to_string();
    handle_scim_user_create(
        &console,
        &tenant_b,
        ScimUserRequest {
            user_name: "victim3@tenant-a.test".into(),
            active: None,
            display_name: None,
            ferrogate_role: Some("member".into()),
        },
    );

    // Tenant B deletes them: tenant-scoped, account stays enabled.
    assert_eq!(
        handle_scim_user_delete(&console, &tenant_b, &victim_id).status,
        204
    );
    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&victim_id))
        .unwrap()
        .unwrap();
    assert!(user.disabled_at_unix.is_none());
    assert!(membership_role_in_tenant(&console, &tenant_a, &victim_id).is_some());

    // Tenant A (the last membership) deletes them: NOW the account is
    // globally disabled, and the membership is kept for reactivation.
    assert_eq!(
        handle_scim_user_delete(&console, &tenant_a, &victim_id).status,
        204
    );
    let user = block_on_sync_bridge(console.repositories.get_admin_user_by_id(&victim_id))
        .unwrap()
        .unwrap();
    assert!(user.disabled_at_unix.is_some());
    assert!(membership_role_in_tenant(&console, &tenant_a, &victim_id).is_some());
}

/// Finding #3 (cross-tenant role overwrite): tenant B upserting a role id
/// that tenant A's bindings resolve to must create B's OWN role, leaving
/// A's role -- and the permissions A's bindings grant -- untouched.
#[test]
fn rbac_role_upsert_cannot_overwrite_another_tenants_role() {
    let console = console();
    let service = service();
    let owner_a = body_json(&register(&console, "role-a@acme.test", "correct-horse-69"));
    let token_a = owner_a["access_token"].as_str().unwrap();
    let tenant_a = owner_a["tenant"]["id"].as_str().unwrap().to_string();
    let owner_b = body_json(&register(&console, "role-b@acme.test", "correct-horse-70"));
    let token_b = owner_b["access_token"].as_str().unwrap();

    // Tenant A: a narrow role, bound (owner-gated) to one of A's API keys.
    handle_rbac_role_upsert(
        &service,
        &console,
        token_a,
        RoleUpsertRequest {
            id: "role_contested".into(),
            name: "Narrow".into(),
            permissions: vec![Permission {
                action: "chat.completions".into(),
                resource: "model:fast-chat".into(),
            }],
        },
    );
    assert_eq!(
        handle_rbac_binding_upsert(
            &service,
            &console,
            token_a,
            BindingUpsertRequest {
                id: "binding_contested".into(),
                role_id: "role_contested".into(),
                subject: PolicySubject::ApiKey {
                    api_key_id: "key-a".into(),
                },
            },
        )
        .status,
        200
    );

    // Tenant B's owner "overwrites" the same role id with wildcard perms.
    assert_eq!(
        handle_rbac_role_upsert(
            &service,
            &console,
            token_b,
            RoleUpsertRequest {
                id: "role_contested".into(),
                name: "Wildcard".into(),
                permissions: vec![Permission {
                    action: "*".into(),
                    resource: "*".into(),
                }],
            },
        )
        .status,
        200
    );

    // A's binding still grants exactly A's own role: the original permission
    // works, B's wildcard did NOT leak into A's tenant.
    let mut request = AuthorizeRequest {
        tenant: TenantContext {
            organization_id: Some(tenant_a.clone()),
            ..TenantContext::default()
        },
        subject: PolicySubject::ApiKey {
            api_key_id: "key-a".into(),
        },
        action: "chat.completions".into(),
        resource: "model:fast-chat".into(),
    };
    assert!(service.authorize(&request).allowed);
    request.action = "admin.write".into();
    request.resource = "everything".into();
    assert!(
        !service.authorize(&request).allowed,
        "tenant B's wildcard role upsert must not escalate tenant A's binding"
    );

    // A's own catalog view still shows the narrow role, not B's wildcard.
    let a_roles = service.rbac.list_roles_visible_to_tenant(&tenant_a);
    let a_role = a_roles
        .iter()
        .find(|role| role.id == "role_contested")
        .unwrap();
    assert_eq!(a_role.name, "Narrow");
    assert_eq!(a_role.permissions.len(), 1);
}

/// Finding #3 gate: role writes now require a tenant owner.
#[test]
fn rbac_role_upsert_is_forbidden_for_a_non_owner() {
    let console = console();
    let service = service();
    let owner = body_json(&register(
        &console,
        "role-owner@acme.test",
        "correct-horse-71",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let owner_tenant_id = owner["tenant"]["id"].as_str().unwrap();
    let member = body_json(&register(
        &console,
        "role-member@acme.test",
        "correct-horse-72",
    ));
    let member_user_id = member["user"]["id"].as_str().unwrap();
    handle_admin_team_invite(
        &console,
        owner_token,
        AdminInviteRequest {
            email: "role-member@acme.test".into(),
            role: "member".into(),
        },
    );
    let (member_token, _) = issue_session(
        &console,
        member_user_id,
        "role-member@acme.test",
        owner_tenant_id,
        "member",
    )
    .unwrap();

    let upsert = handle_rbac_role_upsert(
        &service,
        &console,
        &member_token,
        RoleUpsertRequest {
            id: "role_member_made".into(),
            name: "Should not exist".into(),
            permissions: vec![],
        },
    );
    assert_eq!(upsert.status, 403);
    assert!(service.rbac.list_roles().is_empty());
}

/// Finding #3 listing: the role catalog returned to a tenant contains its
/// own roles plus read-only global built-ins -- never another tenant's.
#[test]
fn rbac_roles_list_is_tenant_scoped_but_includes_global_builtins() {
    let console = console();
    let service = service();
    // A global (YAML-style, tenant-less) built-in.
    service.rbac.upsert_role(Role {
        id: "role_global".into(),
        name: "Global".into(),
        tenant_id: None,
        permissions: vec![],
    });
    let owner_a = body_json(&register(&console, "list-a@acme.test", "correct-horse-73"));
    let token_a = owner_a["access_token"].as_str().unwrap();
    let owner_b = body_json(&register(&console, "list-b@acme.test", "correct-horse-74"));
    let token_b = owner_b["access_token"].as_str().unwrap();
    handle_rbac_role_upsert(
        &service,
        &console,
        token_a,
        RoleUpsertRequest {
            id: "role_of_a".into(),
            name: "A's".into(),
            permissions: vec![],
        },
    );
    handle_rbac_role_upsert(
        &service,
        &console,
        token_b,
        RoleUpsertRequest {
            id: "role_of_b".into(),
            name: "B's".into(),
            permissions: vec![],
        },
    );

    let listed = handle_rbac_roles_list(&service, &console, token_a);
    assert_eq!(listed.status, 200);
    let ids: Vec<String> = body_json(&listed)["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|role| role["id"].as_str().unwrap().to_string())
        .collect();
    assert!(ids.contains(&"role_of_a".to_string()));
    assert!(ids.contains(&"role_global".to_string()));
    assert!(
        !ids.contains(&"role_of_b".to_string()),
        "another tenant's roles must not be disclosed"
    );

    // And a tenant cannot delete a global built-in or another tenant's role.
    assert_eq!(
        handle_rbac_role_delete(&service, &console, token_a, "role_global").status,
        404
    );
    assert_eq!(
        handle_rbac_role_delete(&service, &console, token_a, "role_of_b").status,
        404
    );
}

// -- issue #283: SAML SP flow end-to-end (redirect binding) ----------------

const SAML_SIG_ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// Generates an RSA key (PEM) + self-signed X.509 certificate (PEM) via
/// openssl, mirroring the OIDC tests' reliance on the openssl CLI.
fn saml_key_and_cert() -> (std::path::PathBuf, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("key.pem");
    let cert_path = dir.path().join("cert.pem");
    assert!(std::process::Command::new("openssl")
        .args(["genrsa", "-out"])
        .arg(&key_path)
        .arg("2048")
        .output()
        .expect("openssl available")
        .status
        .success());
    assert!(std::process::Command::new("openssl")
        .args(["req", "-x509", "-new", "-key"])
        .arg(&key_path)
        .args(["-days", "1", "-subj", "/CN=saml-idp", "-out"])
        .arg(&cert_path)
        .output()
        .expect("openssl req")
        .status
        .success());
    let cert_pem = std::fs::read_to_string(&cert_path).unwrap();
    (key_path, cert_pem, dir)
}

fn saml_config_request(cert_pem: &str) -> SsoConfigRequest {
    SsoConfigRequest {
        provider_kind: "saml".into(),
        issuer: None,
        client_id: None,
        client_secret_ref: None,
        redirect_uri: None,
        group_role_mapping: [("Engineering".to_string(), "admin".to_string())]
            .into_iter()
            .collect(),
        default_role: "member".into(),
        group_claim: "groups".into(),
        idp_entity_id: Some("https://idp.example/entity".into()),
        idp_sso_url: Some("https://idp.example/sso".into()),
        idp_certificate: Some(cert_pem.to_string()),
        sp_entity_id: Some("sp-entity-id".into()),
        acs_url: Some("https://sp.example/acs".into()),
        email_attribute: Some("email".into()),
        name_attribute: Some("displayName".into()),
        groups_attribute: Some("groups".into()),
    }
}

fn saml_response_xml(request_id: &str, email: &str, group: &str) -> String {
    format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" InResponseTo=\"{request_id}\">\
         <saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\
         <saml:Assertion><saml:Issuer>https://idp.example/entity</saml:Issuer>\
         <saml:Subject><saml:NameID>{email}</saml:NameID></saml:Subject>\
         <saml:Conditions NotBefore=\"2020-01-01T00:00:00Z\" NotOnOrAfter=\"2999-01-01T00:00:00Z\">\
         <saml:AudienceRestriction><saml:Audience>sp-entity-id</saml:Audience></saml:AudienceRestriction>\
         </saml:Conditions><saml:AttributeStatement>\
         <saml:Attribute Name=\"email\"><saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute>\
         <saml:Attribute Name=\"groups\"><saml:AttributeValue>{group}</saml:AttributeValue></saml:Attribute>\
         </saml:AttributeStatement></saml:Assertion></samlp:Response>"
    )
}

fn saml_signed_query(key_path: &std::path::Path, response_xml: &str, state: &str) -> String {
    use base64::Engine as _;
    use std::io::Write as _;

    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(response_xml.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();
    let saml_response_b64 = base64::engine::general_purpose::STANDARD.encode(compressed);

    let saml_response_enc = urlencode(&saml_response_b64);
    let relay_state_enc = urlencode(state);
    let sig_alg_enc = urlencode(SAML_SIG_ALG_RSA_SHA256);
    let octet = format!(
        "SAMLResponse={saml_response_enc}&RelayState={relay_state_enc}&SigAlg={sig_alg_enc}"
    );

    let dir = tempfile::tempdir().unwrap();
    let data_path = dir.path().join("data.bin");
    let sig_path = dir.path().join("sig.bin");
    std::fs::write(&data_path, octet.as_bytes()).unwrap();
    assert!(std::process::Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(key_path)
        .arg("-out")
        .arg(&sig_path)
        .arg(&data_path)
        .output()
        .expect("openssl dgst -sign")
        .status
        .success());
    let signature = std::fs::read(&sig_path).unwrap();
    let signature_enc = urlencode(&base64::engine::general_purpose::STANDARD.encode(signature));
    format!("SAMLResponse={saml_response_enc}&RelayState={relay_state_enc}&SigAlg={sig_alg_enc}&Signature={signature_enc}")
}

#[test]
fn saml_authorize_requires_saml_configuration() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "saml-auth-gate@acme.test",
        "correct-horse-70",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    // Not configured at all -> 404.
    assert_eq!(handle_saml_authorize(&console, &tenant_id).status, 404);

    // Configured for OIDC -> the SAML authorize endpoint refuses (wrong kind).
    handle_admin_sso_config_set(
        &console,
        owner_token,
        sso_config_request("http://127.0.0.1:1"),
    );
    assert_eq!(handle_saml_authorize(&console, &tenant_id).status, 422);
}

#[test]
fn saml_end_to_end_provisions_user_and_maps_group_to_role() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "saml-owner@acme.test",
        "correct-horse-71",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    let (key_path, cert_pem, _dir) = saml_key_and_cert();
    let set = handle_admin_sso_config_set(&console, owner_token, saml_config_request(&cert_pem));
    assert_eq!(set.status, 200, "{:?}", body_json(&set));

    // The authorize endpoint issues a redirect + persists a restart-safe flow.
    let authorize = handle_saml_authorize(&console, &tenant_id);
    assert_eq!(authorize.status, 200);
    assert!(body_json(&authorize)["authorize_url"]
        .as_str()
        .unwrap()
        .starts_with("https://idp.example/sso?SAMLRequest="));

    // Seed a pending flow with a known state + request_id so the test can sign
    // a matching Response.
    let state = "saml-state-token";
    let request_id = "_saml-req-1";
    let now = now_unix_seconds() as i64;
    block_on_sync_bridge(
        console
            .repositories
            .insert_sso_pending_flow(StoredSsoPendingFlow {
                state: state.into(),
                tenant_id: tenant_id.clone(),
                provider_kind: "saml".into(),
                code_verifier: None,
                request_id: Some(request_id.into()),
                created_at_unix: now,
                expires_at_unix: now + 600,
            }),
    )
    .unwrap();

    let response_xml = saml_response_xml(request_id, "saml-user@acme.test", "Engineering");
    let query = saml_signed_query(&key_path, &response_xml, state);

    let acs = handle_saml_acs(&console, &query);
    assert_eq!(acs.status, 200, "{:?}", body_json(&acs));
    let body = body_json(&acs);
    assert_eq!(body["user"]["email"], "saml-user@acme.test");
    // Engineering -> admin via group_role_mapping.
    assert_eq!(body["tenant"]["role"], "admin");
    assert!(body["gateway_api_key"].as_str().unwrap().starts_with("fg_"));

    // The state is single-use: replaying it fails closed.
    assert_eq!(handle_saml_acs(&console, &query).status, 401);
}

#[test]
fn saml_acs_rejects_a_forged_signature() {
    let console = console();
    let owner = body_json(&register(
        &console,
        "saml-owner2@acme.test",
        "correct-horse-72",
    ));
    let owner_token = owner["access_token"].as_str().unwrap();
    let tenant_id = owner["tenant"]["id"].as_str().unwrap().to_string();

    // Configure the tenant with the REAL IdP certificate...
    let (_real_key, cert_pem, _dir) = saml_key_and_cert();
    handle_admin_sso_config_set(&console, owner_token, saml_config_request(&cert_pem));

    let state = "saml-state-token-2";
    let request_id = "_saml-req-2";
    let now = now_unix_seconds() as i64;
    block_on_sync_bridge(
        console
            .repositories
            .insert_sso_pending_flow(StoredSsoPendingFlow {
                state: state.into(),
                tenant_id: tenant_id.clone(),
                provider_kind: "saml".into(),
                code_verifier: None,
                request_id: Some(request_id.into()),
                created_at_unix: now,
                expires_at_unix: now + 600,
            }),
    )
    .unwrap();

    // ...but an attacker signs the (otherwise well-formed) Response with a
    // DIFFERENT key. The RelayState is intact so the flow is found; the
    // signature check must then fail closed. No user is provisioned.
    let (attacker_key, _attacker_cert, _dir2) = saml_key_and_cert();
    let response_xml = saml_response_xml(request_id, "victim@acme.test", "Engineering");
    let query = saml_signed_query(&attacker_key, &response_xml, state);
    let acs = handle_saml_acs(&console, &query);
    assert_eq!(acs.status, 401);

    assert!(
        block_on_sync_bridge(
            console
                .repositories
                .get_admin_user_by_email("victim@acme.test")
        )
        .unwrap()
        .is_none(),
        "a rejected assertion must not provision an account"
    );
}
