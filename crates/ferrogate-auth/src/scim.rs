// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! SCIM 2.0 user/group provisioning endpoints and their tenant-scoped
//! deprovisioning semantics (issues #161/#232).

use ferrogate_core::{TenantContext, WorkspaceScope};
use ferrogate_storage::{StoredAdminUser, StoredAdminUserMembership, StoredApiKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::admin_console::{
    current_admin_session, resolve_default_workspace, revoke_admin_console_session_keys,
    AdminConsoleState,
};
use crate::api_key::{
    generate_virtual_api_key_secret, virtual_api_key_material, ApiKeyAuthenticator,
    StorageApiKeyAuthenticator,
};
use crate::http::{
    forbidden, internal_error, not_found, storage_error, unauthorized, unprocessable, HttpRequest,
    HttpResponse,
};
use crate::membership_role::MembershipRole;
use crate::util::{
    block_on_sync_bridge, is_valid_email, next_id, now_unix_seconds, unusable_password_hash,
};

// -- issue #161: SCIM 2.0 user/group provisioning --------------------------

/// Scope name marking a virtual API key as a SCIM provisioning credential,
/// distinct from the `admin.read`/`admin.write` scopes an interactive
/// admin-console session uses. Requests to `/scim/v2/*` must present a key
/// carrying exactly this scope.
const SCIM_PROVISION_SCOPE: &str = "scim.provision";

/// The one-time reply to `POST /admin/v1/scim/token`. `token` is the **only
/// time** the freshly minted SCIM provisioning secret exists in plaintext —
/// storage keeps a hash — so `Debug` is hand-written (the same treatment
/// `ferrogate-cloudflare` gives its minted R2 credential in `HttpResponse`).
/// A derived `Debug` would render the live token from any `{:?}`: a
/// `tracing::debug!(?response)` on the mint path, an `anyhow` chain, an
/// `unwrap()` panic, or a failing assertion in a test that happens to hold
/// one. Only the length survives, which is enough to triage a truncation
/// without disclosing the secret (issue #492).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminScimTokenResponse {
    pub token: String,
}

impl std::fmt::Debug for AdminScimTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminScimTokenResponse")
            .field("token", &"<redacted>")
            .field("token_len", &self.token.len())
            .finish()
    }
}

/// Mints a SCIM provisioning token for the caller's own tenant (issue #161).
/// Only a tenant `owner` may do this; the token is a normal virtual API key
/// carrying only [`SCIM_PROVISION_SCOPE`], so it is fully independent of --
/// and can be revoked/rotated the same way as -- any other virtual key via
/// the existing `/admin/v1/virtual-keys` endpoints.
pub(crate) fn handle_admin_scim_token_create(
    console: &AdminConsoleState,
    token: &str,
) -> HttpResponse {
    let (_caller, membership) = match current_admin_session(console, token) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if !MembershipRole::from_stored(&membership.role).is_owner() {
        return forbidden("only a tenant owner can create a SCIM provisioning token");
    }
    let workspace = match resolve_default_workspace(console, &membership.tenant_id) {
        Ok(Some(workspace)) => workspace,
        Ok(None) => return internal_error("no workspace found for this tenant"),
        Err(error) => return storage_error(&error),
    };
    let secret = match generate_virtual_api_key_secret() {
        Ok(secret) => secret,
        Err(error) => return internal_error(&error.to_string()),
    };
    let material = match virtual_api_key_material(&secret) {
        Some(material) => material,
        None => return internal_error("failed to derive SCIM token material"),
    };
    let scope = WorkspaceScope::new(&membership.tenant_id, &workspace.project_id, &workspace.id);
    let mut tenant = TenantContext::default();
    scope.apply_to(&mut tenant);
    let id = next_id("scim");
    tenant.api_key_id = Some(id.clone());
    let now = now_unix_seconds();
    let key = StoredApiKey {
        id,
        workspace_id: workspace.id,
        tenant_id: membership.tenant_id,
        project_id: workspace.project_id,
        name: "SCIM provisioning token".into(),
        key_prefix: material.key_prefix,
        key_hash: material.key_hash,
        last4: material.last4,
        enabled: true,
        scopes: vec![SCIM_PROVISION_SCOPE.into()],
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
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_api_key_record(key)) {
        return storage_error(&error);
    }
    HttpResponse::json(201, AdminScimTokenResponse { token: secret })
}

/// Resolves the tenant a SCIM request is authorized to operate on from its
/// bearer token, reusing `StorageApiKeyAuthenticator` (the same
/// prefix+hash+active-check resolution the gateway itself uses for virtual
/// keys) rather than a separate credential store.
pub(crate) fn resolve_scim_tenant(
    console: &AdminConsoleState,
    request: &HttpRequest,
) -> Result<String, HttpResponse> {
    let Some(token) = request.bearer_token() else {
        return Err(unauthorized("missing bearer token"));
    };
    let authenticator = StorageApiKeyAuthenticator::new(Arc::clone(&console.repositories));
    let Some(decision) = authenticator.authenticate(token) else {
        return Err(unauthorized("invalid SCIM provisioning token"));
    };
    if !decision
        .scopes
        .iter()
        .any(|scope| scope == SCIM_PROVISION_SCOPE)
    {
        return Err(forbidden("token is not scoped for SCIM provisioning"));
    }
    decision
        .tenant
        .organization_id
        .ok_or_else(|| internal_error("SCIM token has no tenant scope"))
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ScimUserRequest {
    #[serde(rename = "userName")]
    pub(crate) user_name: String,
    #[serde(default)]
    pub(crate) active: Option<bool>,
    #[serde(default, rename = "displayName")]
    pub(crate) display_name: Option<String>,
    /// FerroGate-specific extension (outside the standard SCIM core User
    /// schema): the tenant role to assign. Defaults to `"member"`. A real
    /// IdP group-push integration would derive this from the SCIM group
    /// memberships pushed alongside the user instead; that richer mapping
    /// is tracked as a follow-up.
    #[serde(default, rename = "ferrogateRole")]
    pub(crate) ferrogate_role: Option<String>,
}

fn scim_user_resource(user: &StoredAdminUser, role: &str) -> serde_json::Value {
    scim_user_resource_with_active(user, role, user.disabled_at_unix.is_none())
}

/// Variant with an explicit `active` value for tenant-scoped deprovisioning
/// responses (issue #232): a user removed from THIS tenant is inactive here
/// even when their global account stays enabled for their other tenants.
///
/// `ferrogateRole` is the RESOLVED tier, never the raw stored column (issue
/// #517) -- the single place every SCIM user representation is built, so
/// normalising here covers list/get/create/patch at once. A legacy or
/// D1-written value outside the four tiers resolves to `viewer`, which is
/// the authority that user's console session and gateway key actually get;
/// echoing the raw string would tell the IdP its user holds a tier this
/// service does not implement, and IdP-side reconciliation would then
/// believe a role assignment took effect that never did.
fn scim_user_resource_with_active(
    user: &StoredAdminUser,
    role: &str,
    active: bool,
) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user.id,
        "userName": user.email,
        "displayName": user.display_name,
        "active": active,
        "ferrogateRole": MembershipRole::from_stored(role).as_str(),
        "meta": { "resourceType": "User" }
    })
}

pub(crate) fn membership_role_in_tenant(
    console: &AdminConsoleState,
    tenant_id: &str,
    user_id: &str,
) -> Option<String> {
    block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(tenant_id),
    )
    .ok()?
    .into_iter()
    .find(|membership| membership.user_id == user_id)
    .map(|membership| membership.role)
}

pub(crate) fn handle_scim_users_list(console: &AdminConsoleState, tenant_id: &str) -> HttpResponse {
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(tenant_id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    let mut resources = Vec::with_capacity(memberships.len());
    for membership in &memberships {
        match block_on_sync_bridge(
            console
                .repositories
                .get_admin_user_by_id(&membership.user_id),
        ) {
            Ok(Some(user)) => resources.push(scim_user_resource(&user, &membership.role)),
            Ok(None) => {}
            Err(error) => return storage_error(&error),
        }
    }
    HttpResponse::json(
        200,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": resources.len(),
            "Resources": resources
        }),
    )
}

pub(crate) fn handle_scim_user_get(
    console: &AdminConsoleState,
    tenant_id: &str,
    user_id: &str,
) -> HttpResponse {
    let Some(role) = membership_role_in_tenant(console, tenant_id, user_id) else {
        return not_found("no such user in this tenant");
    };
    match block_on_sync_bridge(console.repositories.get_admin_user_by_id(user_id)) {
        Ok(Some(user)) => HttpResponse::json(200, scim_user_resource(&user, &role)),
        Ok(None) => not_found("no such user"),
        Err(error) => storage_error(&error),
    }
}

/// Creates a SCIM user under the token's tenant, or -- if an account with
/// this email already exists (e.g. self-registered, or provisioned into
/// another tenant earlier) -- adds a membership for it, matching
/// `handle_admin_team_invite`'s semantics but keyed by SCIM's own auth and
/// request shape. Never creates a new tenant/project/workspace.
pub(crate) fn handle_scim_user_create(
    console: &AdminConsoleState,
    tenant_id: &str,
    payload: ScimUserRequest,
) -> HttpResponse {
    let email = payload.user_name.trim().to_ascii_lowercase();
    if !is_valid_email(&email) {
        return unprocessable("userName must be a valid email address");
    }
    // Validate the IdP-supplied tier in code (issue #517): SCIM writes this
    // straight into `admin_user_tenant_memberships.role`, and the D1 backend
    // carries no CHECK to catch an unknown value.
    let role = match MembershipRole::parse(
        payload
            .ferrogate_role
            .as_deref()
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .unwrap_or(MembershipRole::Member.as_str()),
    ) {
        Ok(role) => role,
        Err(error) => return unprocessable(&format!("ferrogateRole: {error}")),
    };
    let display_name = payload
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&email)
        .to_string();

    let existing = match block_on_sync_bridge(console.repositories.get_admin_user_by_email(&email))
    {
        Ok(existing) => existing,
        Err(error) => return storage_error(&error),
    };
    let user = match existing {
        Some(user) => user,
        None => {
            let password_hash = match unusable_password_hash() {
                Ok(hash) => hash,
                Err(error) => return internal_error(&error.to_string()),
            };
            let now = now_unix_seconds() as i64;
            let user = StoredAdminUser {
                id: next_id("user"),
                email: email.clone(),
                password_hash,
                display_name: display_name.clone(),
                superadmin: false,
                created_at_unix: now,
                updated_at_unix: now,
                last_login_at_unix: None,
                disabled_at_unix: None,
            };
            if let Err(error) =
                block_on_sync_bridge(console.repositories.upsert_admin_user(user.clone()))
            {
                return storage_error(&error);
            }
            user
        }
    };

    let membership = StoredAdminUserMembership {
        id: next_id("membership"),
        user_id: user.id.clone(),
        tenant_id: tenant_id.to_string(),
        role: role.to_string(),
        created_at_unix: now_unix_seconds() as i64,
    };
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .upsert_admin_user_membership(membership),
    ) {
        return storage_error(&error);
    }

    if payload.active == Some(false) {
        if let Err(response) = deactivate_admin_user_in_tenant(console, tenant_id, &user.id) {
            return response;
        }
    }

    HttpResponse::json(
        201,
        scim_user_resource_with_active(&user, role.as_str(), payload.active != Some(false)),
    )
}

/// Tenant-scoped SCIM deprovisioning (issue #232). SCIM auth is per-tenant
/// (the provisioning token belongs to ONE tenant), so deactivation must be
/// too: revoke only this tenant's sessions, and either
/// - remove only this tenant's membership when the user still belongs to
///   other tenants (their global account and other sessions are untouched --
///   previously any tenant owner could disable a shared account system-wide
///   by knowing its email), or
/// - globally disable the account (and revoke every remaining token,
///   including legacy rows with no stamped tenant) when this was their last
///   membership -- the membership itself is kept in that case so a SCIM
///   PATCH `active: true` from the same tenant can reactivate them.
///
/// A session's artifacts are the refresh tokens AND the gateway virtual key
/// minted alongside them (issue #517). Only the tokens were revoked here
/// before, which left a deprovisioned user holding a working, still
/// `admin.write`-scoped Admin API credential for the tenant that just
/// deprovisioned them -- the gateway authenticates that key on its own, with
/// no reference to the membership row this function deletes.
fn deactivate_admin_user_in_tenant(
    console: &AdminConsoleState,
    tenant_id: &str,
    user_id: &str,
) -> Result<(), HttpResponse> {
    let mut user = match block_on_sync_bridge(console.repositories.get_admin_user_by_id(user_id)) {
        Ok(Some(user)) => user,
        Ok(None) => return Err(not_found("no such user")),
        Err(error) => return Err(storage_error(&error)),
    };
    let now = now_unix_seconds() as i64;
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .revoke_admin_user_refresh_tokens_for_tenant(user_id, tenant_id, now),
    ) {
        return Err(storage_error(&error));
    }
    if let Err(error) = revoke_admin_console_session_keys(console, tenant_id, user_id) {
        return Err(storage_error(&error));
    }
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_user(user_id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return Err(storage_error(&error)),
    };
    let has_other_memberships = memberships
        .iter()
        .any(|membership| membership.tenant_id != tenant_id);
    if has_other_memberships {
        if let Err(error) = block_on_sync_bridge(
            console
                .repositories
                .delete_admin_user_membership(user_id, tenant_id),
        ) {
            return Err(storage_error(&error));
        }
        return Ok(());
    }
    user.disabled_at_unix = Some(now);
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_admin_user(user)) {
        return Err(storage_error(&error));
    }
    if let Err(error) = block_on_sync_bridge(
        console
            .repositories
            .revoke_all_admin_user_refresh_tokens(user_id, now),
    ) {
        return Err(storage_error(&error));
    }
    Ok(())
}

fn reactivate_admin_user(console: &AdminConsoleState, user_id: &str) -> Result<(), HttpResponse> {
    let mut user = match block_on_sync_bridge(console.repositories.get_admin_user_by_id(user_id)) {
        Ok(Some(user)) => user,
        Ok(None) => return Err(not_found("no such user")),
        Err(error) => return Err(storage_error(&error)),
    };
    user.disabled_at_unix = None;
    if let Err(error) = block_on_sync_bridge(console.repositories.upsert_admin_user(user)) {
        return Err(storage_error(&error));
    }
    Ok(())
}

/// Parses the `active` value out of either a simplified `{"active": false}`
/// body or a standards-shaped SCIM PATCH
/// `{"Operations":[{"op":"replace","path":"active","value":false}]}` body.
fn parse_scim_active_patch(body: &[u8]) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if let Some(active) = value.get("active").and_then(serde_json::Value::as_bool) {
        return Some(active);
    }
    let operations = value.get("Operations")?.as_array()?;
    operations.iter().find_map(|operation| {
        let path = operation.get("path")?.as_str()?;
        if !path.eq_ignore_ascii_case("active") {
            return None;
        }
        operation.get("value")?.as_bool()
    })
}

/// Updates a SCIM user's `active` state (issue #161). Deactivation is
/// tenant-scoped (issue #232, see `deactivate_admin_user_in_tenant`): it
/// ends this tenant's sessions immediately and never disables the shared
/// global account while the user still belongs to other tenants.
pub(crate) fn handle_scim_user_patch(
    console: &AdminConsoleState,
    tenant_id: &str,
    user_id: &str,
    body: &[u8],
) -> HttpResponse {
    let Some(role) = membership_role_in_tenant(console, tenant_id, user_id) else {
        return not_found("no such user in this tenant");
    };
    let deactivated = match parse_scim_active_patch(body) {
        Some(true) => {
            if let Err(response) = reactivate_admin_user(console, user_id) {
                return response;
            }
            false
        }
        Some(false) => {
            if let Err(response) = deactivate_admin_user_in_tenant(console, tenant_id, user_id) {
                return response;
            }
            true
        }
        None => return unprocessable("could not determine an 'active' value from the PATCH body"),
    };
    match block_on_sync_bridge(console.repositories.get_admin_user_by_id(user_id)) {
        Ok(Some(user)) => HttpResponse::json(
            200,
            scim_user_resource_with_active(
                &user,
                &role,
                !deactivated && user.disabled_at_unix.is_none(),
            ),
        ),
        Ok(None) => not_found("no such user"),
        Err(error) => storage_error(&error),
    }
}

/// SCIM DELETE deprovisions a user from THIS tenant (issue #161, tenant
/// -scoped by #232): revoke this tenant's sessions and membership rather
/// than hard-deleting (or globally disabling) the shared account, preserving
/// audit history and any OTHER tenant's membership/sessions for the same
/// person. The account is only globally disabled when this was its last
/// remaining membership.
pub(crate) fn handle_scim_user_delete(
    console: &AdminConsoleState,
    tenant_id: &str,
    user_id: &str,
) -> HttpResponse {
    if membership_role_in_tenant(console, tenant_id, user_id).is_none() {
        return not_found("no such user in this tenant");
    }
    if let Err(response) = deactivate_admin_user_in_tenant(console, tenant_id, user_id) {
        return response;
    }
    HttpResponse::no_content(204)
}

/// Lists the tenant's in-use roles as SCIM groups (issue #161) -- a
/// read-only view for now; group-to-role assignment happens via the
/// `ferrogateRole` extension on `POST /scim/v2/Users` (see
/// `ScimUserRequest`), not by pushing SCIM group memberships.
pub(crate) fn handle_scim_groups_list(
    console: &AdminConsoleState,
    tenant_id: &str,
) -> HttpResponse {
    let memberships = match block_on_sync_bridge(
        console
            .repositories
            .list_admin_user_memberships_by_tenant(tenant_id),
    ) {
        Ok(memberships) => memberships,
        Err(error) => return storage_error(&error),
    };
    // Resolved tiers, not raw columns (issue #517): a group here is a role
    // an IdP may push users into, so advertising a legacy `"superuser"` row
    // as a group would offer an assignable tier that `MembershipRole::parse`
    // rejects on the way back in. Resolving first also collapses several
    // unparseable rows into the one `viewer` group they all really are.
    let mut roles: Vec<String> = memberships
        .into_iter()
        .map(|membership| MembershipRole::from_stored(&membership.role).to_string())
        .collect();
    roles.sort();
    roles.dedup();
    let resources: Vec<serde_json::Value> = roles
        .iter()
        .map(|role| {
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": role,
                "displayName": role,
            })
        })
        .collect();
    HttpResponse::json(
        200,
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": resources.len(),
            "Resources": resources
        }),
    )
}
