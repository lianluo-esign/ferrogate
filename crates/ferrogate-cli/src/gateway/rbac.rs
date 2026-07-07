// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Admin management surface for tenant-level RBAC entitlements
// (issue #182): /admin/v1/permissions, /admin/v1/roles, and
// /admin/v1/tenant-roles/{tenant_id}[/{role_id}] -- a Permission -> Role ->
// TenantRoleBinding system generalizing the ad-hoc boolean feature flags on
// StoredPlan (#168/#176/#177).

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use ferrogate_storage::{StoredPermission, StoredRole, StoredTenantRoleBinding};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminDeleteResponse,
        AdminList, AdminPermission, AdminPermissionMutation, AdminPermissionMutationResponse,
        AdminRole, AdminRoleMutation, AdminRoleMutationResponse, AdminTenantRoleBinding,
        AdminTenantRoleBindingRequest,
    },
};

const MAX_BODY_BYTES: usize = 64 * 1024;

impl FerroGateway {
    pub(super) async fn handle_admin_permissions(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/permissions" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.list_permissions() {
                        Ok(permissions) => {
                            let body =
                                AdminList::new(permissions.iter().map(admin_permission).collect());
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
                    },
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
                },
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
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.get_permission(id) {
                    Ok(Some(permission)) => {
                        let body = AdminPermissionMutationResponse {
                            object: "permission",
                            permission: admin_permission(&permission),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(None) => {
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
                },
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
            },
            Method::DELETE => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
                match state.delete_permission(id) {
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

    async fn handle_admin_permission_upsert(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
        let payload =
            match read_json_body::<AdminPermissionMutation>(session, &ctx.request_id).await? {
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
        let existing = state.get_permission(&id).ok().flatten();
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
        match state.upsert_permission(permission.clone()) {
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
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.list_roles() {
                        Ok(roles) => {
                            let body = AdminList::new(roles.iter().map(admin_role).collect());
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
                    },
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
                },
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
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.get_role(id) {
                    Ok(Some(role)) => {
                        let body = AdminRoleMutationResponse {
                            object: "role",
                            role: admin_role(&role),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(None) => {
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
                },
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
            },
            Method::DELETE => {
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
                match state.delete_role(id) {
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

    async fn handle_admin_role_upsert(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
        let payload = match read_json_body::<AdminRoleMutation>(session, &ctx.request_id).await? {
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
        let existing = state.get_role(&id).ok().flatten();
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
        match state.upsert_role(role.clone()) {
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
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.list_tenant_role_bindings(tenant_id) {
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
                    },
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
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
                let payload =
                    match read_json_body::<AdminTenantRoleBindingRequest>(session, &ctx.request_id)
                        .await?
                    {
                        Ok(payload) => payload,
                        Err(()) => return Ok(()),
                    };
                if state.get_role(&payload.role_id).ok().flatten().is_none() {
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
                match state.bind_tenant_role(binding.clone()) {
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
                let auth = match authenticate(&state, headers, "admin.write", &ctx.request_id) {
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
                match state.unbind_tenant_role(tenant_id, role_id) {
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

async fn read_json_body<T: serde::de::DeserializeOwned>(
    session: &mut Session,
    request_id: &str,
) -> PingoraResult<Result<T, ()>> {
    let body = match read_request_body(session, MAX_BODY_BYTES).await? {
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
