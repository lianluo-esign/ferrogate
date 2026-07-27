// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Admin management surface for tenant-level RBAC entitlements
// (issue #182): /admin/v1/permissions, /admin/v1/roles, and
// /admin/v1/tenant-roles/{tenant_id}[/{role_id}] -- a Permission -> Role ->
// TenantRoleBinding system generalizing the ad-hoc boolean feature flags on
// StoredPlan (#168/#176/#177).

use std::collections::HashSet;

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use ferrogate_storage::{StoredPermission, StoredRole, StoredTenantRoleBinding};

use super::admin_list_query::{list_response, matches_search, query_value};
use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::{authenticate, AuthContext},
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminDeleteResponse,
        AdminList, AdminPermission, AdminPermissionMutation, AdminPermissionMutationResponse,
        AdminRole, AdminRoleMutation, AdminRoleMutationResponse, AdminTenantRoleBinding,
        AdminTenantRoleBindingRequest,
    },
    state::AppState,
};

impl FerroGateway {
    pub(super) async fn handle_admin_permissions(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/permissions" {
            return match *method {
                Method::GET => {
                    self.handle_admin_permission_list(session, ctx, headers, query)
                        .await
                }
                Method::POST => {
                    self.handle_admin_permission_upsert(session, ctx, headers)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "permissions collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(id) = path.strip_prefix("/admin/v1/permissions/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "permission endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        if id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_permission",
                "permission id is required",
                &ctx.request_id,
            )
            .await;
        }

        match *method {
            Method::GET => {
                let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                // Issue #518: the by-id read is scoped by the same helper as
                // the collection read, so it cannot be walked to rebuild the
                // catalog the list no longer discloses.
                let scope = match rbac_catalog_scope(&state, &auth).await {
                    Ok(scope) => scope,
                    Err(error) => {
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                match state.get_permission(id).await {
                    Ok(found) => {
                        if !found
                            .as_ref()
                            .is_some_and(|permission| scope.allows_permission(permission))
                            && !scope.is_full()
                        {
                            return write_rbac_scope_denied(session, &ctx.request_id).await;
                        }
                        match found {
                            Some(permission) => {
                                let body = AdminPermissionMutationResponse {
                                    object: "permission",
                                    permission: admin_permission(&permission),
                                };
                                write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                    .await
                            }
                            None => {
                                write_json_error(
                                    session,
                                    StatusCode::NOT_FOUND,
                                    "permission_not_found",
                                    format!("no permission {id}"),
                                    &ctx.request_id,
                                )
                                .await
                            }
                        }
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            Method::DELETE => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if let Err(error) = crate::auth::require_platform_operator(&auth) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                match state.delete_permission(id).await {
                    Ok(true) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "permission.delete",
                            id,
                            "committed",
                            format!("permission {id} deleted"),
                        ));
                        let body = AdminDeleteResponse {
                            object: "permission",
                            id: id.to_string(),
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(false) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "permission_not_found",
                            format!("no permission {id}"),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "permission endpoint supports GET and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    /// `GET /admin/v1/permissions`. Extracted from the method match so the
    /// authenticated [`AuthContext`] can be *used* rather than discarded
    /// (issue #518): a tenant-scoped key only sees the permission keys its
    /// own tenant's bound roles actually compose.
    async fn handle_admin_permission_list(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let scope = match rbac_catalog_scope(&state, &auth).await {
            Ok(scope) => scope,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };
        match state.list_permissions().await {
            Ok(permissions) => {
                let search = query_value(query, "search");
                let permissions = permissions
                    .into_iter()
                    .filter(|permission| scope.allows_permission(permission))
                    .filter(|permission| {
                        matches_search(
                            search.as_deref(),
                            &[
                                &permission.id,
                                &permission.key,
                                &permission.name,
                                &permission.description,
                            ],
                        )
                    })
                    .map(|permission| admin_permission(&permission))
                    .collect();
                let body = list_response(permissions, query, state.admin_pagination(query));
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_permission_upsert(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        if let Err(error) = crate::auth::require_platform_operator(&auth) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload = match read_json_body::<AdminPermissionMutation>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(key) = payload.key.clone().filter(|key| !key.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_permission",
                "field key is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(name) = payload.name.clone().filter(|name| !name.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_permission",
                "field name is required",
                &ctx.request_id,
            )
            .await;
        };
        let now = now_unix_seconds();
        let id = payload
            .id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| next_rbac_id("permission"));
        let existing = state.get_permission(&id).await.ok().flatten();
        let created_at_unix = existing
            .as_ref()
            .map_or(now, |existing| existing.created_at_unix);
        let permission = StoredPermission {
            id: id.clone(),
            key,
            name,
            description: payload.description.unwrap_or_default(),
            created_at_unix,
            updated_at_unix: now,
        };
        match state.upsert_permission(permission.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "permission.upsert",
                    &id,
                    "committed",
                    format!("permission {id} upserted"),
                ));
                let body = AdminPermissionMutationResponse {
                    object: "permission",
                    permission: admin_permission(&permission),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_roles(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/roles" {
            return match *method {
                Method::GET => self.handle_admin_role_list(session, ctx, headers).await,
                Method::POST => self.handle_admin_role_upsert(session, ctx, headers).await,
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "roles collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(id) = path.strip_prefix("/admin/v1/roles/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "role endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        if id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_role",
                "role id is required",
                &ctx.request_id,
            )
            .await;
        }

        match *method {
            Method::GET => {
                let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                // Issue #518: same scoping as the collection read -- a role a
                // tenant cannot list is also a role it cannot fetch by id,
                // permission_keys and all.
                let scope = match rbac_catalog_scope(&state, &auth).await {
                    Ok(scope) => scope,
                    Err(error) => {
                        return write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                match state.get_role(id).await {
                    Ok(found) => {
                        if !found.as_ref().is_some_and(|role| scope.allows_role(role))
                            && !scope.is_full()
                        {
                            return write_rbac_scope_denied(session, &ctx.request_id).await;
                        }
                        match found {
                            Some(role) => {
                                let body = AdminRoleMutationResponse {
                                    object: "role",
                                    role: admin_role(&role),
                                };
                                write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                    .await
                            }
                            None => {
                                write_json_error(
                                    session,
                                    StatusCode::NOT_FOUND,
                                    "role_not_found",
                                    format!("no role {id}"),
                                    &ctx.request_id,
                                )
                                .await
                            }
                        }
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            Method::DELETE => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if let Err(error) = crate::auth::require_platform_operator(&auth) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                match state.delete_role(id).await {
                    Ok(true) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "role.delete",
                            id,
                            "committed",
                            format!("role {id} deleted"),
                        ));
                        let body = AdminDeleteResponse {
                            object: "role",
                            id: id.to_string(),
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(false) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "role_not_found",
                            format!("no role {id}"),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "role endpoint supports GET and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    /// `GET /admin/v1/roles`. Extracted from the method match so the
    /// authenticated [`AuthContext`] can be *used* rather than discarded
    /// (issue #518): a tenant-scoped key only sees the roles bound to its
    /// own tenant, not the platform's whole authority model.
    async fn handle_admin_role_list(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        let scope = match rbac_catalog_scope(&state, &auth).await {
            Ok(scope) => scope,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };
        match state.list_roles().await {
            Ok(roles) => {
                let body = AdminList::new(
                    roles
                        .iter()
                        .filter(|role| scope.allows_role(role))
                        .map(admin_role)
                        .collect(),
                );
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_role_upsert(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await {
            Ok(auth) => auth,
            Err(error) => {
                return write_json_error(
                    session,
                    error.status,
                    error.code,
                    error.message,
                    &ctx.request_id,
                )
                .await;
            }
        };
        if let Err(error) = crate::auth::require_platform_operator(&auth) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload = match read_json_body::<AdminRoleMutation>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(name) = payload.name.clone().filter(|name| !name.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_role",
                "field name is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(slug) = payload.slug.clone().filter(|slug| !slug.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_role",
                "field slug is required",
                &ctx.request_id,
            )
            .await;
        };
        let now = now_unix_seconds();
        let id = payload
            .id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| next_rbac_id("role"));
        let existing = state.get_role(&id).await.ok().flatten();
        let created_at_unix = existing
            .as_ref()
            .map_or(now, |existing| existing.created_at_unix);
        let role = StoredRole {
            id: id.clone(),
            name,
            slug,
            description: payload.description.unwrap_or_default(),
            permission_keys: payload.permission_keys.unwrap_or_default(),
            created_at_unix,
            updated_at_unix: now,
        };
        match state.upsert_role(role.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "role.upsert",
                    &id,
                    "committed",
                    format!("role {id} upserted"),
                ));
                let body = AdminRoleMutationResponse {
                    object: "role",
                    role: admin_role(&role),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Err(error) => {
                write_json_error(
                    session,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "storage_unavailable",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_tenant_roles(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let Some(rest) = path.strip_prefix("/admin/v1/tenant-roles/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "tenant-role endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        let mut segments = rest.splitn(2, '/');
        let Some(tenant_id) = segments.next().filter(|id| !id.is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_tenant_role",
                "tenant id is required",
                &ctx.request_id,
            )
            .await;
        };
        let role_id_segment = segments.next();

        match (method, role_id_segment) {
            (&Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
                    Ok(auth) => {
                        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                            return write_json_error(
                                session,
                                error.status,
                                error.code,
                                error.message,
                                &ctx.request_id,
                            )
                            .await;
                        }
                        match state.list_tenant_role_bindings(tenant_id).await {
                            Ok(bindings) => {
                                let body = AdminList::new(
                                    bindings.iter().map(admin_tenant_role_binding).collect(),
                                );
                                write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                    .await
                            }
                            Err(error) => {
                                write_json_error(
                                    session,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "storage_unavailable",
                                    error.to_string(),
                                    &ctx.request_id,
                                )
                                .await
                            }
                        }
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::POST, None) => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if let Err(error) = crate::auth::require_platform_operator(&auth) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                let payload = match read_json_body::<AdminTenantRoleBindingRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
                .await?
                {
                    Ok(payload) => payload,
                    Err(()) => return Ok(()),
                };
                if state
                    .get_role(&payload.role_id)
                    .await
                    .ok()
                    .flatten()
                    .is_none()
                {
                    return write_json_error(
                        session,
                        StatusCode::BAD_REQUEST,
                        "invalid_tenant_role",
                        format!("no role {}", payload.role_id),
                        &ctx.request_id,
                    )
                    .await;
                }
                let binding = StoredTenantRoleBinding {
                    id: ferrogate_storage::tenant_role_binding_id(tenant_id, &payload.role_id),
                    tenant_id: tenant_id.to_string(),
                    role_id: payload.role_id.clone(),
                    created_at_unix: now_unix_seconds(),
                };
                match state.bind_tenant_role(binding.clone()).await {
                    Ok(()) => {
                        let target = format!("{tenant_id}/{}", payload.role_id);
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "tenant_role.bind",
                            &target,
                            "committed",
                            format!("role {} bound to tenant {tenant_id}", payload.role_id),
                        ));
                        let body = admin_tenant_role_binding(&binding);
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            (&Method::DELETE, Some(role_id)) if !role_id.is_empty() => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id).await
                {
                    Ok(auth) => auth,
                    Err(error) => {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if let Err(error) = crate::auth::require_platform_operator(&auth) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                match state.unbind_tenant_role(tenant_id, role_id).await {
                    Ok(true) => {
                        let target = format!("{tenant_id}/{role_id}");
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "tenant_role.unbind",
                            &target,
                            "committed",
                            format!("role {role_id} unbound from tenant {tenant_id}"),
                        ));
                        let body = AdminDeleteResponse {
                            object: "tenant_role_binding",
                            id: target,
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(false) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "tenant_role_binding_not_found",
                            format!("tenant {tenant_id} does not have role {role_id}"),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Err(error) => {
                        write_json_error(
                            session,
                            StatusCode::SERVICE_UNAVAILABLE,
                            "storage_unavailable",
                            error.to_string(),
                            &ctx.request_id,
                        )
                        .await
                    }
                }
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "/admin/v1/tenant-roles/{tenant_id} supports GET, POST; \
                     /admin/v1/tenant-roles/{tenant_id}/{role_id} supports DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }
}

/// How much of the *global* RBAC catalog a caller is allowed to read
/// (issue #518).
///
/// The four `admin.read` GETs under `/admin/v1/permissions*` and
/// `/admin/v1/roles*` used to `authenticate(..)` and then throw the
/// resulting [`AuthContext`] away (`Ok(_) => match state.list_roles()`),
/// so any tenant-scoped `admin.read` key -- exactly the shape
/// `provision_gateway_api_key` mints on every admin-console login --
/// received the platform's entire entitlement model: every role name,
/// every permission key, and how the two compose. Mutation was already
/// closed (`require_platform_operator` on the POST/DELETE paths), so this
/// was pure disclosure, but it is the reconnaissance step that precedes an
/// escalation attempt.
///
/// The catalog is deliberately NOT public-to-tenants, and equally
/// deliberately not a blanket 403: `GET /admin/v1/roles` has legitimate
/// console/CLI use (a tenant showing which roles it actually holds), so a
/// tenant-scoped caller gets the *reachable* slice instead -- the roles
/// bound to its own tenant via `tenant_role_bindings`, and only the
/// permission keys those roles compose. A platform-operator key
/// (`organization_id: None`) still sees the whole catalog, matching
/// [`crate::auth::filter_by_tenant_scope`] and every other admin list.
enum RbacCatalogScope {
    /// Platform operator: the entire catalog, unfiltered.
    Full,
    /// Tenant-scoped caller: only what its own tenant's role bindings reach.
    Tenant {
        role_ids: HashSet<String>,
        permission_keys: HashSet<String>,
    },
}

impl RbacCatalogScope {
    fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }

    fn allows_role(&self, role: &StoredRole) -> bool {
        match self {
            Self::Full => true,
            Self::Tenant { role_ids, .. } => role_ids.contains(&role.id),
        }
    }

    fn allows_permission(&self, permission: &StoredPermission) -> bool {
        match self {
            Self::Full => true,
            Self::Tenant {
                permission_keys, ..
            } => permission_keys.contains(&permission.key),
        }
    }
}

/// Resolves the caller's [`RbacCatalogScope`] -- the ONE place the
/// tenant/platform-operator split is decided for the RBAC catalog, so the
/// four read sites cannot drift apart again (four copies of the check is
/// precisely how #518 survived four handlers).
///
/// Storage failures propagate rather than degrading to an empty (or, far
/// worse, unfiltered) scope: the callers turn them into the same
/// `503 storage_unavailable` they already return for a failed list.
async fn rbac_catalog_scope(
    state: &AppState,
    auth: &AuthContext,
) -> anyhow::Result<RbacCatalogScope> {
    let Some(tenant_id) = auth.organization_id.as_deref() else {
        return Ok(RbacCatalogScope::Full);
    };
    let role_ids: HashSet<String> = state
        .list_tenant_role_bindings(tenant_id)
        .await?
        .into_iter()
        .map(|binding| binding.role_id)
        .collect();
    let permission_keys = state
        .list_roles()
        .await?
        .into_iter()
        .filter(|role| role_ids.contains(&role.id))
        .flat_map(|role| role.permission_keys)
        .collect();
    Ok(RbacCatalogScope::Tenant {
        role_ids,
        permission_keys,
    })
}

/// The single-object counterpart to the list filters (issue #518). A
/// tenant-scoped caller asking for a catalog entry outside its reachable
/// slice is refused identically whether or not the entry exists, so the
/// by-id GETs cannot be used as an existence oracle to re-enumerate the
/// catalog one id at a time -- matching the fail-closed shape of
/// [`crate::auth::authorize_self_hosted_worker_scope`].
async fn write_rbac_scope_denied(session: &mut Session, request_id: &str) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::FORBIDDEN,
        "tenant_scope_denied",
        "API key is not authorized to read this RBAC catalog entry",
        request_id,
    )
    .await
}

async fn read_json_body<T: serde::de::DeserializeOwned>(
    session: &mut Session,
    max_bytes: usize,
    request_id: &str,
) -> PingoraResult<Result<T, ()>> {
    let body = match read_request_body(session, max_bytes).await? {
        Ok(body) => body,
        Err(limit) => {
            write_json_error_and_close(
                session,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                format!(
                    "request body exceeds maximum size of {} bytes",
                    limit.max_bytes
                ),
                request_id,
            )
            .await?;
            return Ok(Err(()));
        }
    };
    match serde_json::from_slice::<T>(&body) {
        Ok(payload) => Ok(Ok(payload)),
        Err(error) => {
            write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
                format!("request body is not valid JSON: {error}"),
                request_id,
            )
            .await?;
            Ok(Err(()))
        }
    }
}

fn admin_permission(permission: &StoredPermission) -> AdminPermission {
    AdminPermission {
        id: permission.id.clone(),
        key: permission.key.clone(),
        name: permission.name.clone(),
        description: permission.description.clone(),
        created_at_unix: permission.created_at_unix,
        updated_at_unix: permission.updated_at_unix,
    }
}

fn admin_role(role: &StoredRole) -> AdminRole {
    AdminRole {
        id: role.id.clone(),
        name: role.name.clone(),
        slug: role.slug.clone(),
        description: role.description.clone(),
        permission_keys: role.permission_keys.clone(),
        created_at_unix: role.created_at_unix,
        updated_at_unix: role.updated_at_unix,
    }
}

fn admin_tenant_role_binding(binding: &StoredTenantRoleBinding) -> AdminTenantRoleBinding {
    AdminTenantRoleBinding {
        id: binding.id.clone(),
        tenant_id: binding.tenant_id.clone(),
        role_id: binding.role_id.clone(),
        created_at_unix: binding.created_at_unix,
    }
}

fn next_rbac_id(kind: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{kind}-{nanos}-{}", std::process::id())
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
