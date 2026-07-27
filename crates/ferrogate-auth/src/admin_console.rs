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
    LifecycleGateError, LifecycleSeam, RuntimeStorageRepositories, StoredAdminUser,
    StoredAdminUserMembership, StoredAdminUserRefreshToken, StoredApiKey, StoredProject,
    StoredTenantAccount, StoredWorkspace, TenancyRefs,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::api_key::{
    generate_virtual_api_key_secret, hash_virtual_api_key_secret, virtual_api_key_material,
};
use crate::http::{
    conflict, forbidden, internal_error, lifecycle_error, not_found, storage_error, unauthorized,
    unprocessable, HttpResponse,
};
use crate::membership_role::MembershipRole;
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
/// The `StoredApiKey::name` every console-session gateway key is minted
/// with. It is the only marker distinguishing a session key from a virtual
/// key an operator created deliberately through `/admin/v1/virtual-keys`,
/// so the revocation sweeps below key off it and must never widen.
pub(crate) const ADMIN_CONSOLE_SESSION_KEY_NAME: &str = "Admin console session";

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

/// `Debug` is hand-written — matching the redacting impls on `HttpRequest` /
/// `HttpResponse` in `ferrogate-cloudflare` — because `password` is a **user's
/// plaintext password**, the one secret in this crate we never even persist
/// (only [`hash_password`] output reaches storage). A derived `Debug` would
/// put it one `{:?}` away from a log line: this type is built by
/// `serde_json::from_slice` in the `POST /v1/admin/register` route, so any
/// future `tracing::debug!(?payload)`, validation-error context, `unwrap()`
/// panic or failing `assert_eq!` would render the password verbatim
/// (issue #492).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRegisterRequest {
    pub organization_name: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

impl std::fmt::Debug for AdminRegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminRegisterRequest")
            .field("organization_name", &self.organization_name)
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// `Debug` is hand-written for the same reason as [`AdminRegisterRequest`]
/// above: `password` is a user's plaintext password and must never reach a
/// rendered string (issue #492).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLoginRequest {
    pub email: String,
    pub password: String,
}

impl std::fmt::Debug for AdminLoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminLoginRequest")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .finish()
    }
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
    /// A freshly-minted virtual API key for the gateway's own Admin API,
    /// scoped to the session's membership tier
    /// ([`MembershipRole::gateway_api_key_scopes`], issue #517) and shown
    /// once (never recoverable after this response, matching the existing
    /// virtual-key create/rotate contract).
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
    // Registration always creates the tenant's first owner.
    let membership = StoredAdminUserMembership {
        id: next_id("membership"),
        user_id: user_id.clone(),
        tenant_id: tenant_id.clone(),
        role: MembershipRole::Owner.to_string(),
        created_at_unix: now,
    };
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_membership(membership),
    ) {
        return storage_error(&error);
    }

    let gateway_api_key = match provision_gateway_api_key(
        console,
        &workspace_id,
        &project_id,
        &tenant_id,
        &user_id,
        MembershipRole::Owner,
    ) {
        Ok(secret) => secret,
        // #514: a suspended/deleted tenancy is a 403 with the gateway's own
        // `tenancy_suspended` code, not a 500 -- and, crucially, not a live
        // `fg_...` secret, which is what this path returned before the gate
        // became reachable from `ferrogate-auth`.
        Err(error) => return error.into_response(),
    };

    match issue_session(
        console,
        &user_id,
        &email,
        &tenant_id,
        MembershipRole::Owner.as_str(),
    ) {
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
                    role: MembershipRole::Owner.to_string(),
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
    // creation, matching the existing virtual-key create/rotate contract),
    // and REVOKE the caller's prior session keys for this tenant while doing
    // so (issue #517, inside `provision_gateway_api_key`). Without that
    // sweep the tier ladder would only bind newly-minted keys, leaving every
    // pre-#517 `viewer` holding an `admin.write` key indefinitely.
    // Consequence: one browser session per user per tenant -- signing in
    // again invalidates the previous tab's gateway key. That is the
    // deliberate trade for a bounded credential lifetime; the refresh token
    // is unaffected, so only the gateway key (not the console session) is
    // displaced.
    // Derive the key's authority from the caller's tier in THIS tenant
    // (issue #517). `from_stored` resolves an unrecognised legacy value to
    // `viewer`, the least privilege, so a role string that predates the
    // validator can never mint `admin.write`.
    let session_role = MembershipRole::from_stored(&membership.role);
    let gateway_api_key = match provision_gateway_api_key(
        console,
        &workspace.id,
        &workspace.project_id,
        &workspace.tenant_id,
        &user.id,
        session_role,
    ) {
        Ok(secret) => secret,
        // #514: a suspended/deleted tenancy is a 403 with the gateway's own
        // `tenancy_suspended` code, not a 500 -- and, crucially, not a live
        // `fg_...` secret, which is what this path returned before the gate
        // became reachable from `ferrogate-auth`.
        Err(error) => return error.into_response(),
    };

    let mut updated_user = user.clone();
    updated_user.last_login_at_unix = Some(now_unix_seconds() as i64);
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_admin_user(updated_user)) {
        return storage_error(&error);
    }

    // Report the tier the session ACTUALLY got, i.e. the same resolved value
    // the gateway key above was scoped from -- never the raw stored string,
    // which would advertise an authority the key does not carry.
    match issue_session(
        console,
        &user.id,
        &email,
        &membership.tenant_id,
        session_role.as_str(),
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
                    role: session_role.to_string(),
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
    // #514: refresh is the endpoint that keeps a console session alive
    // indefinitely, so gating login without gating refresh would only bound the
    // bypass by the access token's TTL. Same Recovery seam as
    // `current_admin_session`, for the same reason.
    if let Err(error) = block_on_sync_bridge(console.repositories.require_usable_tenancy(
        LifecycleSeam::Recovery,
        TenancyRefs::tenant(&membership.tenant_id),
    )) {
        return lifecycle_error(&error);
    }
    match issue_session(
        console,
        &user.id,
        &user.email,
        &membership.tenant_id,
        MembershipRole::from_stored(&membership.role).as_str(),
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
            // Report the RESOLVED tier, exactly as login/refresh/SSO do
            // (issue #517). The console reads `/me` to rehydrate a stored
            // session, so returning the raw column here would re-advertise
            // an authority the session's key does not carry: for a legacy
            // `"superuser"` row login answers `viewer` while `/me` answered
            // `superuser` for the very same session.
            Ok(Some(account)) => tenant_views.push(AdminTenantView {
                id: account.id,
                name: account.name,
                role: MembershipRole::from_stored(&membership.role).to_string(),
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
    let Some(membership) = memberships
        .into_iter()
        .find(|membership| membership.tenant_id == claims.tenant_id)
    else {
        return Err(unauthorized("session tenant membership no longer exists"));
    };
    // #514: an admin-console session JWT is a live credential for every
    // team-management and RBAC endpoint below, and until now it checked user
    // existence + membership only -- so a suspended tenant's console session
    // kept working for its full TTL, and could keep re-issuing itself through
    // `POST /v1/admin/refresh`.
    //
    // `Recovery`, not `Request`: this seam is tenant-level only, and a tenant's
    // `disabled` state is one the console itself must be reachable to reverse
    // (see `LifecycleStatus::allows_recovery`). Suspension and soft-deletion
    // still end the session.
    if let Err(error) = block_on_sync_bridge(console.repositories.require_usable_tenancy(
        LifecycleSeam::Recovery,
        TenancyRefs::tenant(&membership.tenant_id),
    )) {
        return Err(lifecycle_error(&error));
    }
    Ok((user, membership))
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
            // Resolved tier, not the raw column (issue #517): the roster is
            // what an owner reads before deciding whether a teammate is
            // over-privileged, so it must show the authority that teammate's
            // session actually gets.
            Ok(Some(user)) => members.push(AdminTeamMemberView {
                user_id: user.id,
                email: user.email,
                display_name: user.display_name,
                role: MembershipRole::from_stored(&member.role).to_string(),
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can invite teammates");
    }
    let email = payload.email.trim().to_ascii_lowercase();
    if !is_valid_email(&email) {
        return unprocessable("email must be a valid address");
    }
    // Validate the tier IN CODE (issue #517), not only in the Postgres CHECK
    // the D1 twin does not carry: an unknown string must never be stored as a
    // role, because everything downstream (the owner gate, the minted gateway
    // scopes) then has to guess what it meant.
    let role = match MembershipRole::parse(payload.role.trim()) {
        Ok(role) => role,
        Err(error) => return unprocessable(&error.to_string()),
    };
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
        role: role.to_string(),
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
            role: role.to_string(),
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can change teammate roles");
    }
    // Pre-#517 this checked non-emptiness only, so ANY string was an
    // acceptable role. Validate against the accepted set in code.
    let role = match MembershipRole::parse(payload.role.trim()) {
        Ok(role) => role,
        Err(error) => return unprocessable(&error.to_string()),
    };
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
    if MembershipRole::from_stored(&target.role).is_owner() && !role.is_owner() {
        let owners = block_on_sync_bridge(
            console
                .repositories
                .list_admin_user_memberships_by_tenant(&membership.tenant_id),
        )
        .map(|memberships| {
            memberships
                .iter()
                .filter(|candidate| MembershipRole::from_stored(&candidate.role).is_owner())
                .count()
        })
        .unwrap_or(0);
        if owners <= 1 {
            return conflict("cannot demote the last owner of a tenant");
        }
    }
    // Store the CANONICAL string, so a padded/aliased input can never reach
    // storage as a role no reader recognises.
    target.role = role.to_string();
    let tenant_id = target.tenant_id.clone();
    if let Err(error) =
        block_on_sync_bridge(console.repositories.upsert_admin_user_membership(target))
    {
        return storage_error(&error);
    }
    // A tier is only real if DEMOTION takes effect (issue #517). The tier
    // is otherwise enforced at mint time alone: an `admin` who logged in
    // before this call keeps an `admin.write` gateway key indefinitely,
    // so writing `role` and returning 200 would report a demotion that
    // never happened. Revoking their session keys forces a re-login that
    // remints at the new tier -- the same reasoning by which
    // `scim::deactivate_admin_user_in_tenant` already invalidates refresh
    // tokens on a membership change; the gateway key simply was not in
    // that set. Refresh tokens are deliberately left alone: the refresh
    // path re-reads the CURRENT membership, and every owner-gated route
    // re-resolves the membership per request, so the JWT's `role` claim is
    // not a standing grant. The gateway key is.
    if let Err(error) = revoke_admin_console_session_keys(console, &tenant_id, target_user_id) {
        return storage_error(&error);
    }
    HttpResponse::json(
        200,
        json!({
            "object": "membership",
            "user_id": target_user_id,
            "role": role.as_str(),
        }),
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
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
                .filter(|candidate| MembershipRole::from_stored(&candidate.role).is_owner())
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
        Ok(true) => {
            // Removing the membership must remove the authority it granted
            // (issue #517). Deleting the row alone only closes the console
            // JWT paths (`current_admin_session` 401s once the membership
            // is gone); the gateway virtual key minted for their last
            // session is a SEPARATE credential the gateway authenticates on
            // its own, and it would have kept working -- an ex-teammate
            // holding `admin.write` on a tenant they were just removed
            // from.
            if let Err(error) =
                revoke_admin_console_session_keys(console, &membership.tenant_id, target_user_id)
            {
                return storage_error(&error);
            }
            HttpResponse::json(200, json!({ "object": "membership", "removed": true }))
        }
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
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
    if !MembershipRole::from_stored(&membership.role).is_owner() {
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

/// Revokes the console-session gateway keys a user holds in ONE tenant
/// (issue #517).
///
/// Deriving the minted scopes from the caller's tier only fixes the *next*
/// key. A key already in a browser's hands keeps whatever it was minted
/// with, forever: `provision_gateway_api_key` writes
/// `expires_at_unix: None, revoked_at_unix: None`, so on any deployment
/// that ran the pre-#517 code every `viewer` who ever logged in still holds
/// a full `admin.read + admin.write + assets.read + assets.write` key. That
/// is the issue title verbatim, and it is what this sweep closes. It is
/// also what makes a *demotion* mean something: without it, an `admin`
/// demoted to `viewer` keeps `admin.write` until the key is found by hand.
///
/// Two populations are swept, and the distinction matters:
///
/// * **Attributed** keys -- `tenant.user_id == Some(admin_user_id)`. Minted
///   by this code or later. Revoked whenever this user re-authenticates or
///   their membership changes. Precise: no other user is touched.
/// * **Unattributed** keys -- `tenant.user_id.is_none()`, i.e. every key
///   minted before this commit stamped the owner onto the record. They
///   cannot be attributed to a user at all, and they are exactly the
///   over-scoped population, so they are swept tenant-wide. The cost is one
///   forced re-login for other console users of that tenant; the sweep is
///   self-extinguishing, since every key minted from here on carries a
///   `user_id` and only ever matches its own owner.
///
/// Re-scoping in place was rejected: the secret is not plaintext-
/// recoverable, so an unattributed row cannot be re-scoped to the right
/// tier (we do not know whose it is), and a silently down-scoped key fails
/// mid-request rather than at sign-in. Revoke-and-remint gives the holder a
/// correctly-scoped key at the next login instead.
///
/// Deliberately does NOT touch keys with any other `name`: an operator's
/// own `/admin/v1/virtual-keys` creations are not session artifacts.
pub(crate) fn revoke_admin_console_session_keys(
    console: &AdminConsoleState,
    tenant_id: &str,
    admin_user_id: &str,
) -> Result<usize, ferrogate_storage::StorageError> {
    let records = block_on_sync_bridge(console.repositories.list_api_key_records())?;
    let now = now_unix_seconds();
    let mut revoked = 0usize;
    for mut key in records {
        if key.tenant_id != tenant_id || key.name != ADMIN_CONSOLE_SESSION_KEY_NAME {
            continue;
        }
        if key.revoked_at_unix.is_some() && !key.enabled {
            continue;
        }
        let belongs_to_caller = key.tenant.user_id.as_deref() == Some(admin_user_id);
        let unattributed_legacy = key.tenant.user_id.is_none();
        if !belongs_to_caller && !unattributed_legacy {
            continue;
        }
        key.enabled = false;
        key.revoked_at_unix = Some(now);
        key.updated_at_unix = now;
        block_on_sync_bridge(console.repositories.upsert_api_key_record(key))?;
        revoked += 1;
    }
    Ok(revoked)
}

/// Create a durable virtual API key for the gateway's own Admin API,
/// reusing the exact secret format/hashing the gateway's existing
/// `/admin/v1/virtual-keys` endpoint already produces and verifies
/// (issue #157) -- the console is just another virtual-key holder, not a
/// special case in the gateway's auth path.
///
/// **The scopes are derived from the caller's membership tier**
/// ([`MembershipRole::gateway_api_key_scopes`], issue #517). Before that,
/// every console session -- including one belonging to a user invited as
/// `viewer` -- was minted a fixed
/// `admin.read + admin.write + assets.read + assets.write` key, i.e. the
/// role column advertised four tiers while the key handed out one.
///
/// The `assets.*` scopes (added for #178's admin-console asset management
/// UI) don't cross a real privilege boundary *beyond what `admin.write`
/// already grants*: any `admin.write` holder can already self-escalate to
/// any scope by calling `POST /admin/v1/virtual-keys` to mint a new,
/// arbitrarily-scoped key. That is exactly why `admin.write` itself is now
/// restricted to `owner`/`admin`: on a tier that lacks it, the assets
/// scopes are the whole grant rather than a shortcut through one.
///
/// **Minting also revokes the caller's prior session keys for this tenant**
/// ([`revoke_admin_console_session_keys`], issue #517), which is what makes
/// the scope ladder retroactive rather than forward-only. The key is
/// stamped with `tenant.user_id` so that sweep -- and the membership-change
/// sweeps in `handle_admin_team_change_role` / `handle_admin_team_revoke` /
/// SCIM deactivation -- can find it again.
pub(crate) fn provision_gateway_api_key(
    console: &AdminConsoleState,
    workspace_id: &str,
    project_id: &str,
    tenant_id: &str,
    admin_user_id: &str,
    role: MembershipRole,
) -> Result<String, ProvisionSessionKeyError> {
    // #514, the attach-time seam -- reached from `ferrogate-auth`, which is why
    // the decision had to move down into `ferrogate-storage`. This function is
    // a credential MINT: it writes a live `StoredApiKey` with a freshly
    // generated `fg_...` secret. While the gate lived in `ferrogate-cli` it was
    // unreachable from here, so `POST /v1/admin/login` (and register, and SSO)
    // against a suspended tenant still returned a working gateway key -- the
    // exact probe row the issue enumerates, and the reason the "every caller"
    // claim was false.
    //
    // The seam is `Recovery`, not `Attach`: `disabled` is the tenant's OWN off
    // switch, and refusing to mint a console session under a disabled project
    // would lock the tenant out of the console it needs to re-enable it (see
    // `LifecycleStatus::allows_recovery`). `suspended`/`deleted` deny -- those
    // are platform actions, and an operator reverses them with an operator key
    // that carries no tenancy chain.
    block_on_sync_bridge(console.repositories.require_usable_tenancy(
        LifecycleSeam::Recovery,
        TenancyRefs::new(Some(tenant_id), Some(project_id), Some(workspace_id)),
    ))
    .map_err(ProvisionSessionKeyError::Inactive)?;
    revoke_admin_console_session_keys(console, tenant_id, admin_user_id)?;
    let secret = generate_virtual_api_key_secret()?;
    let material = virtual_api_key_material(&secret)
        .ok_or_else(|| anyhow!("failed to derive virtual key material"))?;
    let scope = WorkspaceScope::new(tenant_id, project_id, workspace_id);
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    let id = next_id("vk");
    tenant.api_key_id = Some(id.clone());
    // Attribution, so a later sweep can revoke THIS user's session keys
    // without collateral damage to their teammates'.
    tenant.user_id = Some(admin_user_id.to_string());
    let now = now_unix_seconds();
    let key = StoredApiKey {
        id,
        workspace_id: workspace_id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: project_id.to_string(),
        name: ADMIN_CONSOLE_SESSION_KEY_NAME.into(),
        key_prefix: material.key_prefix,
        key_hash: material.key_hash,
        last4: material.last4,
        enabled: true,
        scopes: role.gateway_api_key_scopes(),
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

/// Why a console session key was not minted (issue #514).
///
/// The two arms exist because they are DIFFERENT answers to the client: a
/// suspended tenancy is a 403 with the same machine-readable code the gateway
/// uses, not the 500 that every `provision_gateway_api_key` failure used to
/// collapse into. Rendering a policy refusal as an internal error would tell an
/// operator "FerroGate is broken" when the truth is "this tenant is suspended".
#[derive(Debug)]
pub(crate) enum ProvisionSessionKeyError {
    Inactive(LifecycleGateError),
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for ProvisionSessionKeyError {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

impl From<ferrogate_storage::StorageError> for ProvisionSessionKeyError {
    fn from(error: ferrogate_storage::StorageError) -> Self {
        Self::Failed(anyhow!(error.to_string()))
    }
}

impl ProvisionSessionKeyError {
    pub(crate) fn into_response(self) -> HttpResponse {
        match self {
            Self::Inactive(error) => lifecycle_error(&error),
            Self::Failed(error) => internal_error(&error.to_string()),
        }
    }
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
