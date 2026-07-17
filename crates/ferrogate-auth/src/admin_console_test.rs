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

fn sso_config_request(issuer: &str) -> SsoConfigRequest {
    SsoConfigRequest {
        issuer: issuer.to_string(),
        client_id: "test-client-id".into(),
        client_secret: "test-client-secret".into(),
        redirect_uri: "http://localhost:3000/callback".into(),
        group_role_mapping: [("Engineering".to_string(), "admin".to_string())]
            .into_iter()
            .collect(),
        default_role: "member".into(),
        group_claim: "groups".into(),
    }
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
