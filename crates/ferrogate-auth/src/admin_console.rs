// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Admin console sessions, team management, and the owner-gated RBAC
//! management endpoints (issues #157/#162/#232).

use anyhow::anyhow;
use ferrogate_core::{TenantContext, WorkspaceScope};
use ferrogate_storage::{
    RuntimeStorageRepositories, StoredAdminUser, StoredAdminUserMembership,
    StoredAdminUserRefreshToken, StoredApiKey, StoredProject, StoredTenantAccount, StoredWorkspace,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::api_key::{
    generate_virtual_api_key_secret, hash_virtual_api_key_secret, virtual_api_key_material,
};
use crate::http::{
    conflict, forbidden, internal_error, not_found, storage_error, unauthorized, unprocessable,
    HttpResponse,
};
use crate::rbac::{Permission, PolicyBinding, PolicySubject, Role};
use crate::server::AuthService;
use crate::util::{
    block_on_sync_bridge, generate_refresh_token_secret, hash_password, is_valid_email, next_id,
    now_unix_seconds, slugify_with_suffix, verify_password,
};

/// Admin console session access-token lifetime (issue #157). Short-lived by
/// design: the refresh token (durable, revocable) is what actually gates a
/// browser session's lifetime.
pub(crate) const ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS: u64 = 60 * 60;
/// Admin console refresh-token lifetime.
const ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS: u64 = 60 * 60 * 24 * 30;

/// Durable-storage handle and JWT signing secret backing the admin-console
/// register/login/session endpoints.
///
/// `repositories` must point at the SAME Postgres/Supabase schema the
/// gateway's own control plane uses: registration provisions a
/// tenant/project/workspace and a gateway-facing virtual API key (issue
/// #157) that the gateway's Admin API must be able to read back. Pointing
/// this at a schema the gateway doesn't share (e.g. the auth service's own
/// dedicated `auth` schema default from issue #156) leaves the console fully
/// functional for its own register/login/session endpoints, but the minted
/// `gateway_api_key` will never authenticate against the gateway, since it
/// simply won't exist in the schema the gateway reads.
#[derive(Clone)]
pub struct AdminConsoleConfig {
    pub repositories: Arc<RuntimeStorageRepositories>,
    pub jwt_secret: String,
}

pub(crate) struct AdminConsoleState {
    pub(crate) repositories: Arc<RuntimeStorageRepositories>,
    pub(crate) encoding_key: EncodingKey,
    pub(crate) decoding_key: DecodingKey,
    /// Resolver for `secret_ref` URIs (issue #283) -- used to fetch an OIDC
    /// client secret at flow time so it never has to be persisted in plaintext.
    pub(crate) secret_resolver: Arc<ferrogate_secrets::SecretResolverRegistry>,
}

impl AdminConsoleState {
    pub(crate) fn new(config: AdminConsoleConfig) -> Self {
        Self {
            repositories: config.repositories,
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            secret_resolver: Arc::new(ferrogate_secrets::SecretResolverRegistry::from_env()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AdminSessionClaims {
    pub(crate) sub: String,
    pub(crate) email: String,
    pub(crate) tenant_id: String,
    pub(crate) role: String,
    pub(crate) iat: u64,
    pub(crate) exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRegisterRequest {
    pub organization_name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserView {
    pub id: String,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminTenantView {
    pub id: String,
    pub name: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user: AdminUserView,
    pub tenant: AdminTenantView,
    /// A freshly-minted, admin.read+admin.write-scoped virtual API key for
    /// the gateway's own Admin API, shown once (never recoverable after this
    /// response, matching the existing virtual-key create/rotate contract).
    pub gateway_api_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminMeResponse {
    pub user: AdminUserView,
    pub memberships: Vec<AdminTenantView>,
}

/// Invite an existing registered user (by email) into the caller's own
/// tenant with the given role (issue #162). Inviting an email with no
/// existing account is out of scope for this slice -- the invited person
/// must register (creating their own tenant as a side effect of today's
/// `/v1/admin/register` flow) before they can be invited elsewhere. Only a
/// tenant `owner` may invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminInviteRequest {
    pub email: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminChangeRoleRequest {
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminTeamMemberView {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub role: String,
}

/// Creates or replaces a `Role` by `id` within the caller's own tenant
/// (issue #162, tenant-scoped by #232). Only a tenant `owner` may define
/// roles, and an upsert can only ever create/replace the caller tenant's own
/// role -- never a global built-in or another tenant's role sharing the id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleUpsertRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

/// Creates or replaces a `PolicyBinding` by `id` (issue #162), always scoped
/// to the caller's own tenant regardless of any `tenant` the caller might
/// otherwise try to set -- only a tenant `owner` may call this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingUpsertRequest {
    pub id: String,
    pub role_id: String,
    pub subject: PolicySubject,
}

/// Handle a new organization signing itself up (issue #157): creates the
/// tenant/project/workspace hierarchy, the owning admin user, and a durable
/// gateway virtual API key, then issues a session -- all in one call so the
/// console has everything it needs to start managing its own tenant
/// immediately after registering.
pub(crate) fn handle_admin_register(
    console: &AdminConsoleState,
    payload: AdminRegisterRequest,
) -> HttpResponse {
    let email = payload.email.trim().to_ascii_lowercase();
    let organization_name = payload.organization_name.trim().to_string();
    let display_name = payload
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&email)
        .to_string();

    if !is_valid_email(&email) {
        return unprocessable("email must be a valid address");
    }
    if organization_name.is_empty() {
        return unprocessable("organization_name must not be empty");
    }
    if payload.password.len() < 8 {
        return unprocessable("password must be at least 8 characters");
    }
    match block_on_sync_bridge(console.repositories.get_admin_user_by_email(&email)) {
        Ok(Some(_)) => return conflict("an account with this email already exists"),
        Ok(None) => {}
        Err(error) => return storage_error(&error),
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(error) => return internal_error(&error.to_string()),
    };

    let now = now_unix_seconds() as i64;
    let tenant_id = next_id("tenant");
    let project_id = next_id("project");
    let workspace_id = next_id("workspace");
    let user_id = next_id("user");

    let tenant_account = StoredTenantAccount {
        id: tenant_id.clone(),
        name: organization_name.clone(),
        slug: slugify_with_suffix(&organization_name, &tenant_id),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) =
        block_on_sync_bridge(console.repositories.upsert_tenant_account(tenant_account))
    {
        return storage_error(&error);
    }
    let project = StoredProject {
        id: project_id.clone(),
        tenant_id: tenant_id.clone(),
        name: "Default".into(),
        slug: "default".into(),
        status: "active".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_project(project)) {
        return storage_error(&error);
    }
    let workspace = StoredWorkspace {
        id: workspace_id.clone(),
        project_id: project_id.clone(),
        tenant_id: tenant_id.clone(),
        name: "Default".into(),
        slug: "default".into(),
        environment: "production".into(),
        status: "active".into(),
        created_at_unix: now,
        updated_at_unix: now,
    };
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_workspace(workspace)) {
        return storage_error(&error);
    }
    let user = StoredAdminUser {
        id: user_id.clone(),
        email: email.clone(),
        password_hash,
        display_name: display_name.clone(),
        superadmin: false,
        created_at_unix: now,
        updated_at_unix: now,
        last_login_at_unix: Some(now),
        disabled_at_unix: None,
    };
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_admin_user(user)) {
        return storage_error(&error);
    }
    let membership = StoredAdminUserMembership {
        id: next_id("membership"),
        user_id: user_id.clone(),
        tenant_id: tenant_id.clone(),
        role: "owner".into(),
        created_at_unix: now,
    };
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_membership(membership),
    ) {
        return storage_error(&error);
    }

    let gateway_api_key =
        match provision_gateway_api_key(console, &workspace_id, &project_id, &tenant_id) {
            Ok(secret) => secret,
            Err(error) => return internal_error(&error.to_string()),
        };

    match issue_session(console, &user_id, &email, &tenant_id, "owner") {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            201,
            AdminSessionResponse {
                access_token,
                refresh_token,
                expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
                user: AdminUserView {
                    id: user_id,
                    email,
                    display_name,
                },
                tenant: AdminTenantView {
                    id: tenant_id,
                    name: organization_name,
                    role: "owner".into(),
                },
                gateway_api_key,
            },
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) fn handle_admin_login(
    console: &AdminConsoleState,
    payload: AdminLoginRequest,
) -> HttpResponse {
    let email = payload.email.trim().to_ascii_lowercase();
    let user = match block_on_sync_bridge(console.repositories.get_admin_user_by_email(&email)) {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("invalid email or password"),
        Err(error) => return storage_error(&error),
    };
    if user.disabled_at_unix.is_some() {
        return unauthorized("this account has been disabled");
    }
    if !verify_password(&payload.password, &user.password_hash) {
        return unauthorized("invalid email or password");
    }
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(&user.id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let Some(membership) = memberships.first() else {
        return unauthorized("this account has no tenant membership");
    };
    let tenant_account = match block_on_sync_bridge(
        console
            .repositories
            .get_tenant_account(&membership.tenant_id),
    ) {
        Ok(Some(account)) => account,
        Ok(None) => return internal_error("tenant account for this membership no longer exists"),
        Err(error) => return storage_error(&error),
    };
    let workspace = match resolve_default_workspace(console, &membership.tenant_id) {
        Ok(Some(workspace)) => workspace,
        Ok(None) => return internal_error("no workspace found for this tenant"),
        Err(error) => return storage_error(&error),
    };

    // Mint a fresh gateway virtual key on every login rather than trying to
    // recover a prior one (secrets are never plaintext-recoverable after
    // creation, matching the existing virtual-key create/rotate contract).
    // Known simplification: earlier session keys are not auto-revoked here,
    // so multiple concurrent browser sessions each keep their own working
    // key; an operator can still revoke any of them via the existing
    // /admin/v1/virtual-keys API.
    let gateway_api_key = match provision_gateway_api_key(
        console,
        &workspace.id,
        &workspace.project_id,
        &workspace.tenant_id,
    ) {
        Ok(secret) => secret,
        Err(error) => return internal_error(&error.to_string()),
    };

    let mut updated_user = user.clone();
    updated_user.last_login_at_unix = Some(now_unix_seconds() as i64);
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_admin_user(updated_user)) {
        return storage_error(&error);
    }

    match issue_session(
        console,
        &user.id,
        &email,
        &membership.tenant_id,
        &membership.role,
    ) {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            200,
            AdminSessionResponse {
                access_token,
                refresh_token,
                expires_in: ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
                user: AdminUserView {
                    id: user.id,
                    email,
                    display_name: user.display_name,
                },
                tenant: AdminTenantView {
                    id: tenant_account.id,
                    name: tenant_account.name,
                    role: membership.role.clone(),
                },
                gateway_api_key,
            },
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) fn handle_admin_refresh(
    console: &AdminConsoleState,
    payload: AdminRefreshRequest,
) -> HttpResponse {
    let token_hash = hash_virtual_api_key_secret(&payload.refresh_token);
    let stored = match block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&token_hash),
    ) {
        Ok(Some(token)) => token,
        Ok(None) => return unauthorized("invalid refresh token"),
        Err(error) => return storage_error(&error),
    };
    let now = now_unix_seconds() as i64;
    if stored.revoked_at_unix.is_some() || stored.expires_at_unix <= now {
        return unauthorized("refresh token has expired or been revoked");
    }
    let mut revoked = stored.clone();
    revoked.revoked_at_unix = Some(now);
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_refresh_token(revoked),
    ) {
        return storage_error(&error);
    }
    let user =
        match block_on_sync_bridge(console.repositories.get_admin_user_by_id(&stored.user_id)) {
            Ok(Some(user)) => user,
            Ok(None) => return unauthorized("account no longer exists"),
            Err(error) => return storage_error(&error),
        };
    if user.disabled_at_unix.is_some() {
        return unauthorized("this account has been disabled");
    }
    // Re-issue for the tenant this token's session was minted for (issue
    // #232) -- NOT `memberships.first()`, which is merely the user's oldest
    // membership and silently swapped a multi-tenant user into the wrong
    // tenant/role on refresh. Legacy rows without a stamped tenant are
    // rejected (fail closed): guessing a tenant would recreate the
    // confusion, so those sessions must re-authenticate once.
    let Some(token_tenant_id) = stored.tenant_id.as_deref() else {
        return unauthorized(
            "this refresh token predates tenant-scoped sessions; please sign in again",
        );
    };
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(&user.id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    // Resolve the CURRENT membership in the stamped tenant rather than
    // replaying the stamped role, so role changes (e.g. an owner demoting
    // the user) take effect on the next refresh; a revoked membership ends
    // the session entirely.
    let Some(membership) = memberships
        .iter()
        .find(|membership| membership.tenant_id == token_tenant_id)
    else {
        return unauthorized("this account is no longer a member of the session's tenant");
    };
    match issue_session(
        console,
        &user.id,
        &user.email,
        &membership.tenant_id,
        &membership.role,
    ) {
        Ok((access_token, refresh_token)) => HttpResponse::json(
            200,
            json!({
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_in": ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
            }),
        ),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) fn handle_admin_logout(
    console: &AdminConsoleState,
    payload: AdminLogoutRequest,
) -> HttpResponse {
    let token_hash = hash_virtual_api_key_secret(&payload.refresh_token);
    match block_on_sync_bridge(
        console
            .repositories
            .get_admin_user_refresh_token_by_hash(&token_hash),
    ) {
        Ok(Some(mut stored)) => {
            if stored.revoked_at_unix.is_none() {
                stored.revoked_at_unix = Some(now_unix_seconds() as i64);
                if let Err(error) = block_on_sync_bridge(
                    console.repositories.upsert_admin_user_refresh_token(stored),
                ) {
                    return storage_error(&error);
                }
            }
            HttpResponse::json(200, json!({ "object": "logout", "revoked": true }))
        }
        Ok(None) => HttpResponse::json(200, json!({ "object": "logout", "revoked": false })),
        Err(error) => storage_error(&error),
    }
}

pub(crate) fn handle_admin_me(console: &AdminConsoleState, token: &str) -> HttpResponse {
    let claims = match decode_access_token(console, token) {
        Ok(claims) => claims,
        Err(_) => return unauthorized("invalid or expired access token"),
    };
    let user = match block_on_sync_bridge(console.repositories.get_admin_user_by_id(&claims.sub)) {
        Ok(Some(user)) => user,
        Ok(None) => return unauthorized("account no longer exists"),
        Err(error) => return storage_error(&error),
    };
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(&user.id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let mut tenant_views = Vec::with_capacity(memberships.len());
    for membership in memberships {
        match block_on_sync_bridge(
            console
                .repositories
                .get_tenant_account(&membership.tenant_id),
        ) {
            Ok(Some(account)) => tenant_views.push(AdminTenantView {
                id: account.id,
                name: account.name,
                role: membership.role,
            }),
            Ok(None) => {}
            Err(error) => return storage_error(&error),
        }
    }
    HttpResponse::json(
        200,
        AdminMeResponse {
            user: AdminUserView {
                id: user.id,
                email: user.email,
                display_name: user.display_name,
            },
            memberships: tenant_views,
        },
    )
}

/// Resolves the caller's admin user and their membership in the tenant
/// their current session was issued for (issue #162). Every team-management
/// endpoint needs both: the user for audit/self-checks, the membership for
/// the role gate.
pub(crate) fn current_admin_session(
    console: &AdminConsoleState,
    token: &str,
) -> Result<(StoredAdminUser, StoredAdminUserMembership), HttpResponse> {
    let claims = decode_access_token(console, token)
        .map_err(|_| unauthorized("invalid or expired access token"))?;
    let user = match block_on_sync_bridge(console.repositories.get_admin_user_by_id(&claims.sub)) {
        Ok(Some(user)) => user,
        Ok(None) => return Err(unauthorized("account no longer exists")),
        Err(error) => return Err(storage_error(&error)),
    };
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(&user.id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return Err(storage_error(&error)),
    };
    match memberships
        .into_iter()
        .find(|membership| membership.tenant_id == claims.tenant_id)
    {
        Some(membership) => Ok((user, membership)),
        None => Err(unauthorized("session tenant membership no longer exists")),
    }
}

/// Lists every teammate in the caller's own tenant (issue #162). Any member
/// (not just owners) may view the roster.
pub(crate) fn handle_admin_team_list(console: &AdminConsoleState, token: &str) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&membership.tenant_id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let mut members = Vec::with_capacity(memberships.len());
    for member in memberships {
        match block_on_sync_bridge(console.repositories.get_admin_user_by_id(&member.user_id)) {
            Ok(Some(user)) => members.push(AdminTeamMemberView {
                user_id: user.id,
                email: user.email,
                display_name: user.display_name,
                role: member.role,
            }),
            Ok(None) => {}
            Err(error) => return storage_error(&error),
        }
    }
    HttpResponse::json(200, json!({ "members": members }))
}

/// Adds an existing registered user to the caller's tenant with a
/// caller-supplied role (issue #162) -- the fix for every membership being
/// hardcoded to `"owner"`. Only an existing `owner` may invite.
pub(crate) fn handle_admin_team_invite(
    console: &AdminConsoleState,
    token: &str,
    payload: AdminInviteRequest,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can invite teammates");
    }
    let email = payload.email.trim().to_ascii_lowercase();
    let role = payload.role.trim().to_string();
    if !is_valid_email(&email) {
        return unprocessable("email must be a valid address");
    }
    if role.is_empty() {
        return unprocessable("role must not be empty");
    }
    let invited_user = match block_on_sync_bridge(
        console.repositories.get_admin_user_by_email(&email),
    ) {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::json(
                404,
                json!({
                    "error": {
                        "code": "user_not_found",
                        "message": "no registered account with this email; ask them to register \
                                    first (this creates their own tenant), then invite them again"
                    }
                }),
            )
        }
        Err(error) => return storage_error(&error),
    };
    let new_membership = StoredAdminUserMembership {
        id: next_id("membership"),
        user_id: invited_user.id.clone(),
        tenant_id: membership.tenant_id,
        role: role.clone(),
        created_at_unix: now_unix_seconds() as i64,
    };
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_membership(new_membership),
    ) {
        return storage_error(&error);
    }
    HttpResponse::json(
        201,
        AdminTeamMemberView {
            user_id: invited_user.id,
            email: invited_user.email,
            display_name: invited_user.display_name,
            role,
        },
    )
}

/// Changes an existing teammate's role within the caller's tenant (issue
/// #162). Only an existing `owner` may change roles.
pub(crate) fn handle_admin_team_change_role(
    console: &AdminConsoleState,
    token: &str,
    target_user_id: &str,
    payload: AdminChangeRoleRequest,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can change teammate roles");
    }
    let role = payload.role.trim().to_string();
    if role.is_empty() {
        return unprocessable("role must not be empty");
    }
    let existing = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(&membership.tenant_id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let Some(mut target) = existing
        .into_iter()
        .find(|candidate| candidate.user_id == target_user_id)
    else {
        return not_found("no such teammate in this tenant");
    };
    if target.role == "owner" && role != "owner" {
        let owners = block_on_sync_bridge(
            console
                .repositories
                .list_admin_user_memberships_by_tenant(&membership.tenant_id),
        )
        .map(|memberships| {
            memberships
                .iter()
                .filter(|candidate| candidate.role == "owner")
                .count()
        })
        .unwrap_or(0);
        if owners <= 1 {
            return conflict("cannot demote the last owner of a tenant");
        }
    }
    target.role = role.clone();
    if let Err(error) =
        block_on_sync_bridge(console.repositories.upsert_admin_user_membership(target))
    {
        return storage_error(&error);
    }
    HttpResponse::json(
        200,
        json!({ "object": "membership", "user_id": target_user_id, "role": role }),
    )
}

/// Revokes a teammate's membership in the caller's tenant (issue #162).
/// Only an existing `owner` may remove teammates, and the last remaining
/// owner of a tenant cannot remove themselves (would lock the tenant out of
/// its own admin console).
pub(crate) fn handle_admin_team_revoke(
    console: &AdminConsoleState,
    token: &str,
    target_user_id: &str,
) -> HttpResponse {
    let (caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can remove teammates");
    }
    if caller.id == target_user_id {
        let owners = match block_on_sync_bridge(
            console
                .repositories
                .list_admin_user_memberships_by_tenant(&membership.tenant_id),
        ) {
            Ok(memberships) => memberships
                .iter()
                .filter(|candidate| candidate.role == "owner")
                .count(),
            Err(error) => return storage_error(&error),
        };
        if owners <= 1 {
            return conflict("cannot remove the last owner of a tenant");
        }
    }
    match block_on_sync_bridge(
        console
            .repositories
            .delete_admin_user_membership(target_user_id, &membership.tenant_id),
    ) {
        Ok(true) => HttpResponse::json(200, json!({ "object": "membership", "removed": true })),
        Ok(false) => not_found("no such teammate in this tenant"),
        Err(error) => storage_error(&error),
    }
}

pub(crate) fn tenant_context_for(tenant_id: &str) -> TenantContext {
    TenantContext {
        organization_id: Some(tenant_id.to_string()),
        ..TenantContext::default()
    }
}

/// Lists the roles visible to the caller's tenant (issue #162, tenant-scoped
/// by #232): the tenant's own roles plus the read-only global built-ins its
/// bindings may resolve to. Another tenant's roles are never disclosed.
pub(crate) fn handle_rbac_roles_list(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    HttpResponse::json(
        200,
        json!({ "roles": service.rbac.list_roles_visible_to_tenant(&membership.tenant_id) }),
    )
}

/// Creates or replaces a role owned by the caller's own tenant (issue #162,
/// tenant-scoped by #232). Only a tenant `owner` may write roles: even
/// though a role grants nothing until bound, an unscoped upsert could
/// overwrite the role a DIFFERENT tenant's owner-gated bindings resolve to
/// (cross-tenant privilege escalation / DoS, round-13 audit). Namespacing by
/// tenant means a colliding id creates this tenant's own independent role.
pub(crate) fn handle_rbac_role_upsert(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
    payload: RoleUpsertRequest,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can manage roles");
    }
    let id = payload.id.trim().to_string();
    let name = payload.name.trim().to_string();
    if id.is_empty() {
        return unprocessable("id must not be empty");
    }
    if name.is_empty() {
        return unprocessable("name must not be empty");
    }
    service.rbac.upsert_role(Role {
        id: id.clone(),
        name,
        tenant_id: Some(membership.tenant_id),
        permissions: payload.permissions,
    });
    HttpResponse::json(200, json!({ "object": "role", "id": id }))
}

/// Deletes one of the caller tenant's own roles by id (issue #162,
/// tenant-scoped and owner-gated by #232) -- global built-ins and other
/// tenants' roles are not deletable. Refuses if any of the tenant's bindings
/// still references it, so authorization decisions never silently lose their
/// backing role.
pub(crate) fn handle_rbac_role_delete(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
    role_id: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can manage roles");
    }
    match service
        .rbac
        .delete_tenant_role(&membership.tenant_id, role_id)
    {
        Ok(true) => HttpResponse::json(200, json!({ "object": "role", "removed": true })),
        Ok(false) => not_found("no such role in this tenant"),
        Err(message) => conflict(message),
    }
}

/// Lists policy bindings scoped to the caller's own tenant (issue #162).
pub(crate) fn handle_rbac_bindings_list(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    let tenant = tenant_context_for(&membership.tenant_id);
    HttpResponse::json(
        200,
        json!({ "bindings": service.rbac.list_bindings_for_tenant(&tenant) }),
    )
}

/// Creates or replaces a policy binding, always scoped to the caller's own
/// tenant (issue #162). Only a tenant `owner` may grant roles to subjects --
/// this is the actually-consequential half of the Role/Binding pair.
pub(crate) fn handle_rbac_binding_upsert(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
    payload: BindingUpsertRequest,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can manage policy bindings");
    }
    let id = payload.id.trim().to_string();
    let role_id = payload.role_id.trim().to_string();
    if id.is_empty() || role_id.is_empty() {
        return unprocessable("id and role_id must not be empty");
    }
    let binding = PolicyBinding {
        id: id.clone(),
        role_id,
        tenant: tenant_context_for(&membership.tenant_id),
        subject: payload.subject,
    };
    match service.rbac.upsert_binding(binding) {
        Ok(()) => HttpResponse::json(200, json!({ "object": "binding", "id": id })),
        Err(message) => unprocessable(message),
    }
}

/// Deletes a policy binding by id (issue #162), refusing to touch a binding
/// belonging to a different tenant.
pub(crate) fn handle_rbac_binding_delete(
    service: &AuthService,
    console: &AdminConsoleState,
    token: &str,
    binding_id: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if membership.role != "owner" {
        return forbidden("only a tenant owner can manage policy bindings");
    }
    let tenant = tenant_context_for(&membership.tenant_id);
    let owned = service
        .rbac
        .list_bindings_for_tenant(&tenant)
        .iter()
        .any(|binding| binding.id == binding_id);
    if !owned {
        return not_found("no such binding in this tenant");
    }
    if service.rbac.delete_binding(binding_id) {
        HttpResponse::json(200, json!({ "object": "binding", "removed": true }))
    } else {
        not_found("no such binding")
    }
}

pub(crate) fn resolve_default_workspace(
    console: &AdminConsoleState,
    tenant_id: &str,
) -> Result<Option<StoredWorkspace>, ferrogate_storage::StorageError> {
    let workspaces = block_on_sync_bridge(console.repositories.list_workspaces())?;
    Ok(workspaces
        .into_iter()
        .find(|workspace| workspace.tenant_id == tenant_id))
}

/// Create a durable, admin.read+admin.write+assets.read+assets.write
/// -scoped virtual API key for the gateway's own Admin API, reusing the
/// exact secret format/hashing the gateway's existing
/// `/admin/v1/virtual-keys` endpoint already produces and verifies
/// (issue #157) -- the console is just another virtual-key holder, not a
/// special case in the gateway's auth path.
///
/// The assets.* scopes (added for #178's admin-console asset management
/// UI) don't cross a real privilege boundary beyond what admin.write
/// already grants: any admin.write holder can already self-escalate to
/// any scope by calling `POST /admin/v1/virtual-keys` to mint a new,
/// arbitrarily-scoped key. Including them directly on the session key
/// just removes that indirection for the one console-native feature that
/// needs it, rather than expanding what a compromised session can
/// ultimately reach.
pub(crate) fn provision_gateway_api_key(
    console: &AdminConsoleState,
    workspace_id: &str,
    project_id: &str,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let secret = generate_virtual_api_key_secret()?;
    let material = virtual_api_key_material(&secret)
        .ok_or_else(|| anyhow!("failed to derive virtual key material"))?;
    let scope = WorkspaceScope::new(tenant_id, project_id, workspace_id);
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    let id = next_id("vk");
    tenant.api_key_id = Some(id.clone());
    let now = now_unix_seconds();
    let key = StoredApiKey {
        id,
        workspace_id: workspace_id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: project_id.to_string(),
        name: "Admin console session".into(),
        key_prefix: material.key_prefix,
        key_hash: material.key_hash,
        last4: material.last4,
        enabled: true,
        scopes: vec![
            "admin.read".into(),
            "admin.write".into(),
            "assets.read".into(),
            "assets.write".into(),
        ],
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
        tenant,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        created_at_unix: now,
        updated_at_unix: now,
        rotated_at_unix: None,
        expires_at_unix: None,
        revoked_at_unix: None,
    };
    block_on_sync_bridge(console.repositories.upsert_api_key_record(key))?;
    Ok(secret)
}

pub(crate) fn issue_session(
    console: &AdminConsoleState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    role: &str,
) -> anyhow::Result<(String, String)> {
    let access_token = issue_access_token(console, user_id, email, tenant_id, role)?;
    let refresh_secret = generate_refresh_token_secret()?;
    let now = now_unix_seconds() as i64;
    let refresh_token_row = StoredAdminUserRefreshToken {
        id: next_id("rt"),
        user_id: user_id.to_string(),
        token_hash: hash_virtual_api_key_secret(&refresh_secret),
        // Stamp the tenant/role this session was issued for (issue #232) so
        // a later refresh re-issues for the SAME tenant instead of whichever
        // membership happens to sort first.
        tenant_id: Some(tenant_id.to_string()),
        role: Some(role.to_string()),
        created_at_unix: now,
        expires_at_unix: now + ADMIN_SESSION_REFRESH_TOKEN_TTL_SECS as i64,
        revoked_at_unix: None,
    };
    block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_refresh_token(refresh_token_row),
    )?;
    Ok((access_token, refresh_secret))
}

pub(crate) fn issue_access_token(
    console: &AdminConsoleState,
    user_id: &str,
    email: &str,
    tenant_id: &str,
    role: &str,
) -> anyhow::Result<String> {
    let now = now_unix_seconds();
    let claims = AdminSessionClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        tenant_id: tenant_id.to_string(),
        role: role.to_string(),
        iat: now,
        exp: now + ADMIN_SESSION_ACCESS_TOKEN_TTL_SECS,
    };
    encode(&Header::default(), &claims, &console.encoding_key)
        .map_err(|error| anyhow!("failed to sign session token: {error}"))
}

pub(crate) fn decode_access_token(
    console: &AdminConsoleState,
    token: &str,
) -> anyhow::Result<AdminSessionClaims> {
    let data = decode::<AdminSessionClaims>(token, &console.decoding_key, &Validation::default())
        .map_err(|error| anyhow!("invalid session token: {error}"))?;
    Ok(data.claims)
}
