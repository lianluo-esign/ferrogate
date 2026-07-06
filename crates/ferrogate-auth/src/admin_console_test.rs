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
    let memberships = console
        .repositories
        .list_admin_user_memberships_by_tenant(owner_tenant_id)
        .unwrap();
    assert!(memberships
        .iter()
        .any(|membership| membership.user_id == invitee_user_id && membership.role == "member"));

    // The invited user's own membership list now includes both tenants: the
    // one they registered (as owner) and the one they were invited into.
    let invitee_memberships = console
        .repositories
        .list_admin_user_memberships_by_user(invitee_user_id)
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

    let memberships = console
        .repositories
        .list_admin_user_memberships_by_tenant(owner_tenant_id)
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
    let memberships = console
        .repositories
        .list_admin_user_memberships_by_tenant(owner_tenant_id)
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
