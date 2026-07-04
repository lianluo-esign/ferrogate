// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: Admin management surface for the Supabase-backed multi-tenant
// hierarchy (tenant/project/workspace) and durable virtual API keys (TOK-11 /
// TOK-12). Tenant/project/workspace endpoints here are intentionally minimal
// (list + create) -- just enough to bootstrap the ownership chain that a
// virtual key binds to; full lifecycle management is out of scope for this
// slice.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_auth::virtual_api_key_material;
use ferrogate_core::TenantContext;
use ferrogate_storage::{StoredApiKey, StoredProject, StoredTenantAccount, StoredWorkspace};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminList, AdminProject,
        AdminProjectCreateRequest, AdminProjectMutationResponse, AdminTenantAccount,
        AdminTenantAccountCreateRequest, AdminTenantAccountMutationResponse, AdminVirtualApiKey,
        AdminVirtualApiKeyCreateRequest, AdminVirtualApiKeyMutationResponse, AdminWorkspace,
        AdminWorkspaceCreateRequest, AdminWorkspaceMutationResponse,
    },
};

const MAX_BODY_BYTES: usize = 64 * 1024;
/// 192 bits of entropy, matching the `fg_` prefix convention.
const VIRTUAL_KEY_SECRET_BYTES: usize = 24;

impl FerroGateway {
    pub(super) async fn handle_admin_tenant_accounts(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.list_tenant_accounts() {
                    Ok(tenants) => {
                        let body =
                            AdminList::new(tenants.iter().map(admin_tenant_account).collect());
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
                let payload = match read_json_body::<AdminTenantAccountCreateRequest>(
                    session,
                    &ctx.request_id,
                )
                .await?
                {
                    Ok(payload) => payload,
                    Err(()) => return Ok(()),
                };
                let now = now_unix_seconds();
                let id = payload
                    .id
                    .filter(|id| !id.trim().is_empty())
                    .unwrap_or_else(|| next_hierarchy_id("tenant"));
                let name = match payload.name.filter(|name| !name.trim().is_empty()) {
                    Some(name) => name,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            "field name is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let slug = match payload.slug.filter(|slug| !slug.trim().is_empty()) {
                    Some(slug) => slug,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            "field slug is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let account = StoredTenantAccount {
                    id: id.clone(),
                    name,
                    slug,
                    status: payload.status.unwrap_or_else(|| "active".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_tenant_account(account.clone()) {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "tenant_account.create",
                            &id,
                            "committed",
                            format!("tenant account {id} created"),
                        ));
                        let body = AdminTenantAccountMutationResponse {
                            object: "tenant_account",
                            tenant: admin_tenant_account(&account),
                        };
                        write_json_response(session, StatusCode::CREATED, &body, &ctx.request_id)
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
                    "tenant accounts endpoint supports GET and POST",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_projects(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.list_projects() {
                    Ok(projects) => {
                        let body = AdminList::new(projects.iter().map(admin_project).collect());
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
                    match read_json_body::<AdminProjectCreateRequest>(session, &ctx.request_id)
                        .await?
                    {
                        Ok(payload) => payload,
                        Err(()) => return Ok(()),
                    };
                let tenant_id = match payload
                    .tenant_id
                    .filter(|tenant_id| !tenant_id.trim().is_empty())
                {
                    Some(tenant_id) => tenant_id,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            "field tenant_id is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if state
                    .get_tenant_account(&tenant_id)
                    .ok()
                    .flatten()
                    .is_none()
                {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "tenant_not_found",
                        format!("tenant account {tenant_id} was not found"),
                        &ctx.request_id,
                    )
                    .await;
                }
                let name = match payload.name.filter(|name| !name.trim().is_empty()) {
                    Some(name) => name,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            "field name is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let slug = match payload.slug.filter(|slug| !slug.trim().is_empty()) {
                    Some(slug) => slug,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            "field slug is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let now = now_unix_seconds();
                let id = payload
                    .id
                    .filter(|id| !id.trim().is_empty())
                    .unwrap_or_else(|| next_hierarchy_id("project"));
                let project = StoredProject {
                    id: id.clone(),
                    tenant_id,
                    name,
                    slug,
                    status: payload.status.unwrap_or_else(|| "active".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_project(project.clone()) {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "project.create",
                            &id,
                            "committed",
                            format!("project {id} created"),
                        ));
                        let body = AdminProjectMutationResponse {
                            object: "project",
                            project: admin_project(&project),
                        };
                        write_json_response(session, StatusCode::CREATED, &body, &ctx.request_id)
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
                    "projects endpoint supports GET and POST",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_workspaces(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.list_workspaces() {
                    Ok(workspaces) => {
                        let body = AdminList::new(workspaces.iter().map(admin_workspace).collect());
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
                    match read_json_body::<AdminWorkspaceCreateRequest>(session, &ctx.request_id)
                        .await?
                    {
                        Ok(payload) => payload,
                        Err(()) => return Ok(()),
                    };
                let project_id = match payload
                    .project_id
                    .filter(|project_id| !project_id.trim().is_empty())
                {
                    Some(project_id) => project_id,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            "field project_id is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let Some(project) = state.get_project(&project_id).ok().flatten() else {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "project_not_found",
                        format!("project {project_id} was not found"),
                        &ctx.request_id,
                    )
                    .await;
                };
                let name = match payload.name.filter(|name| !name.trim().is_empty()) {
                    Some(name) => name,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            "field name is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let slug = match payload.slug.filter(|slug| !slug.trim().is_empty()) {
                    Some(slug) => slug,
                    None => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            "field slug is required",
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let now = now_unix_seconds();
                let id = payload
                    .id
                    .filter(|id| !id.trim().is_empty())
                    .unwrap_or_else(|| next_hierarchy_id("workspace"));
                let workspace = StoredWorkspace {
                    id: id.clone(),
                    project_id,
                    tenant_id: project.tenant_id,
                    name,
                    slug,
                    environment: payload.environment.unwrap_or_else(|| "default".into()),
                    status: payload.status.unwrap_or_else(|| "active".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_workspace(workspace.clone()) {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "workspace.create",
                            &id,
                            "committed",
                            format!("workspace {id} created"),
                        ));
                        let body = AdminWorkspaceMutationResponse {
                            object: "workspace",
                            workspace: admin_workspace(&workspace),
                        };
                        write_json_response(session, StatusCode::CREATED, &body, &ctx.request_id)
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
                    "workspaces endpoint supports GET and POST",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    pub(super) async fn handle_admin_virtual_keys(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/virtual-keys" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.list_virtual_api_keys() {
                        Ok(keys) => {
                            let body =
                                AdminList::new(keys.iter().map(admin_virtual_api_key).collect());
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
                    self.handle_admin_virtual_key_create(session, ctx, headers)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "virtual keys collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(rest) = path.strip_prefix("/admin/v1/virtual-keys/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "virtual key endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        let (id, action) = rest
            .split_once('/')
            .map_or((rest, None), |(id, action)| (id, Some(action)));
        if id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_virtual_key",
                "virtual key id is required",
                &ctx.request_id,
            )
            .await;
        }

        match (method.clone(), action) {
            (Method::GET, None) => {
                match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.get_virtual_api_key(id) {
                        Ok(Some(key)) => {
                            let body = AdminVirtualApiKeyMutationResponse {
                                object: "virtual_key",
                                key: admin_virtual_api_key(&key),
                                secret: None,
                            };
                            write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                .await
                        }
                        Ok(None) => {
                            write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "virtual_key_not_found",
                                format!("virtual key {id} was not found"),
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
                }
            }
            (Method::POST, Some("rotate")) => {
                self.handle_admin_virtual_key_rotate(session, ctx, headers, id)
                    .await
            }
            (Method::POST, Some("enable")) => {
                self.handle_admin_virtual_key_set_enabled(session, ctx, headers, id, true)
                    .await
            }
            (Method::POST, Some("disable")) => {
                self.handle_admin_virtual_key_set_enabled(session, ctx, headers, id, false)
                    .await
            }
            (Method::POST, Some("revoke")) | (Method::DELETE, None) => {
                self.handle_admin_virtual_key_revoke(session, ctx, headers, id)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "unsupported virtual key action",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_virtual_key_create(
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
            match read_json_body::<AdminVirtualApiKeyCreateRequest>(session, &ctx.request_id)
                .await?
            {
                Ok(payload) => payload,
                Err(()) => return Ok(()),
            };
        let workspace_id = match payload
            .workspace_id
            .filter(|workspace_id| !workspace_id.trim().is_empty())
        {
            Some(workspace_id) => workspace_id,
            None => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_virtual_key",
                    "field workspace_id is required",
                    &ctx.request_id,
                )
                .await;
            }
        };
        let name = match payload.name.filter(|name| !name.trim().is_empty()) {
            Some(name) => name,
            None => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_virtual_key",
                    "field name is required",
                    &ctx.request_id,
                )
                .await;
            }
        };
        let scope = match state.resolve_workspace_scope(&workspace_id) {
            Ok(Some(scope)) => scope,
            Ok(None) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "workspace_not_found",
                    format!("workspace {workspace_id} was not found"),
                    &ctx.request_id,
                )
                .await;
            }
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

        let id = payload
            .id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| next_hierarchy_id("vk"));
        let secret = match generate_virtual_api_key_secret() {
            Ok(secret) => secret,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "key_generation_failed",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(material) = virtual_api_key_material(&secret) else {
            return write_json_error(
                session,
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_generation_failed",
                "generated secret failed material derivation",
                &ctx.request_id,
            )
            .await;
        };
        let mut tenant = TenantContext::default();
        scope.apply_to(&mut tenant);
        tenant.api_key_id = Some(id.clone());
        let now = now_unix_seconds() as u64;
        let key = StoredApiKey {
            id: id.clone(),
            workspace_id: scope.workspace_id,
            tenant_id: scope.tenant_id,
            project_id: scope.project_id,
            name,
            key_prefix: material.key_prefix,
            key_hash: material.key_hash,
            last4: material.last4,
            enabled: true,
            scopes: payload.scopes.unwrap_or_default(),
            allowed_models: payload.allowed_models.unwrap_or_default(),
            allowed_providers: payload.allowed_providers.unwrap_or_default(),
            tenant,
            monthly_token_budget: payload.monthly_token_budget,
            request_limit_per_minute: payload.request_limit_per_minute,
            created_at_unix: now,
            updated_at_unix: now,
            rotated_at_unix: None,
            expires_at_unix: payload.expires_at_unix,
            revoked_at_unix: None,
        };

        match state.upsert_virtual_api_key(key.clone()) {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "virtual_key.create",
                    &id,
                    "committed",
                    format!(
                        "virtual key {id} created for workspace {}",
                        key.workspace_id
                    ),
                ));
                let body = AdminVirtualApiKeyMutationResponse {
                    object: "virtual_key",
                    key: admin_virtual_api_key(&key),
                    secret: Some(secret),
                };
                write_json_response(session, StatusCode::CREATED, &body, &ctx.request_id).await
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

    async fn handle_admin_virtual_key_rotate(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
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
        let Some(mut key) = (match state.get_virtual_api_key(id) {
            Ok(key) => key,
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
        }) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "virtual_key_not_found",
                format!("virtual key {id} was not found"),
                &ctx.request_id,
            )
            .await;
        };

        let secret = match generate_virtual_api_key_secret() {
            Ok(secret) => secret,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "key_generation_failed",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };
        let Some(material) = virtual_api_key_material(&secret) else {
            return write_json_error(
                session,
                StatusCode::INTERNAL_SERVER_ERROR,
                "key_generation_failed",
                "generated secret failed material derivation",
                &ctx.request_id,
            )
            .await;
        };
        let now = now_unix_seconds() as u64;
        key.key_prefix = material.key_prefix;
        key.key_hash = material.key_hash;
        key.last4 = material.last4;
        key.rotated_at_unix = Some(now);
        key.updated_at_unix = now;

        match state.upsert_virtual_api_key(key.clone()) {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "virtual_key.rotate",
                    id,
                    "committed",
                    format!("virtual key {id} rotated"),
                ));
                let body = AdminVirtualApiKeyMutationResponse {
                    object: "virtual_key",
                    key: admin_virtual_api_key(&key),
                    secret: Some(secret),
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

    async fn handle_admin_virtual_key_set_enabled(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
        enabled: bool,
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
        let Some(mut key) = (match state.get_virtual_api_key(id) {
            Ok(key) => key,
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
        }) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "virtual_key_not_found",
                format!("virtual key {id} was not found"),
                &ctx.request_id,
            )
            .await;
        };
        key.enabled = enabled;
        key.updated_at_unix = now_unix_seconds() as u64;

        let action = if enabled {
            "virtual_key.enable"
        } else {
            "virtual_key.disable"
        };
        match state.upsert_virtual_api_key(key.clone()) {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    action,
                    id,
                    "committed",
                    format!("virtual key {id} enabled={enabled}"),
                ));
                let body = AdminVirtualApiKeyMutationResponse {
                    object: "virtual_key",
                    key: admin_virtual_api_key(&key),
                    secret: None,
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

    async fn handle_admin_virtual_key_revoke(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
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
        let Some(mut key) = (match state.get_virtual_api_key(id) {
            Ok(key) => key,
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
        }) else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "virtual_key_not_found",
                format!("virtual key {id} was not found"),
                &ctx.request_id,
            )
            .await;
        };
        let now = now_unix_seconds() as u64;
        key.enabled = false;
        key.revoked_at_unix = Some(now);
        key.updated_at_unix = now;

        match state.upsert_virtual_api_key(key.clone()) {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "virtual_key.revoke",
                    id,
                    "committed",
                    format!("virtual key {id} revoked"),
                ));
                let body = AdminVirtualApiKeyMutationResponse {
                    object: "virtual_key",
                    key: admin_virtual_api_key(&key),
                    secret: None,
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
}

/// Reads and JSON-decodes the request body, writing a matching error response
/// (and returning `Err(())`) on size or parse failures so callers can early
/// return with `?` without duplicating the error-response boilerplate.
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

fn admin_tenant_account(tenant: &StoredTenantAccount) -> AdminTenantAccount {
    AdminTenantAccount {
        id: tenant.id.clone(),
        name: tenant.name.clone(),
        slug: tenant.slug.clone(),
        status: tenant.status.clone(),
        created_at_unix: tenant.created_at_unix,
        updated_at_unix: tenant.updated_at_unix,
    }
}

fn admin_project(project: &StoredProject) -> AdminProject {
    AdminProject {
        id: project.id.clone(),
        tenant_id: project.tenant_id.clone(),
        name: project.name.clone(),
        slug: project.slug.clone(),
        status: project.status.clone(),
        created_at_unix: project.created_at_unix,
        updated_at_unix: project.updated_at_unix,
    }
}

fn admin_workspace(workspace: &StoredWorkspace) -> AdminWorkspace {
    AdminWorkspace {
        id: workspace.id.clone(),
        project_id: workspace.project_id.clone(),
        tenant_id: workspace.tenant_id.clone(),
        name: workspace.name.clone(),
        slug: workspace.slug.clone(),
        environment: workspace.environment.clone(),
        status: workspace.status.clone(),
        created_at_unix: workspace.created_at_unix,
        updated_at_unix: workspace.updated_at_unix,
    }
}

fn admin_virtual_api_key(key: &StoredApiKey) -> AdminVirtualApiKey {
    AdminVirtualApiKey {
        id: key.id.clone(),
        workspace_id: key.workspace_id.clone(),
        tenant_id: key.tenant_id.clone(),
        project_id: key.project_id.clone(),
        name: key.name.clone(),
        key_prefix: key.key_prefix.clone(),
        last4: key.last4.clone(),
        enabled: key.enabled,
        scopes: key.scopes.clone(),
        allowed_models: key.allowed_models.clone(),
        allowed_providers: key.allowed_providers.clone(),
        monthly_token_budget: key.monthly_token_budget,
        request_limit_per_minute: key.request_limit_per_minute,
        created_at_unix: key.created_at_unix,
        updated_at_unix: key.updated_at_unix,
        rotated_at_unix: key.rotated_at_unix,
        expires_at_unix: key.expires_at_unix,
        revoked_at_unix: key.revoked_at_unix,
    }
}

/// Generates a fresh `fg_`-prefixed virtual API key secret using the
/// process's TLS-grade CSPRNG (`rustls`'s `ring` crypto provider, already a
/// direct dependency and already used for ACME/TLS in this crate). Returns
/// plaintext; callers must persist only the derived hash/prefix/last4 via
/// [`virtual_api_key_material`] and hand the plaintext to the operator once.
fn generate_virtual_api_key_secret() -> anyhow::Result<String> {
    let mut random_bytes = [0_u8; VIRTUAL_KEY_SECRET_BYTES];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut random_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate secure random bytes"))?;
    Ok(format!("fg_{}", encode_hex(&random_bytes)))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn next_hierarchy_id(kind: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("{kind}-{nanos}-{}", std::process::id())
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secrets_are_unique_fg_prefixed_and_verifiable() {
        let first = generate_virtual_api_key_secret().expect("first secret");
        let second = generate_virtual_api_key_secret().expect("second secret");

        assert!(first.starts_with("fg_"));
        assert_ne!(first, second, "secrets must not repeat across calls");
        assert_eq!(first.len(), "fg_".len() + VIRTUAL_KEY_SECRET_BYTES * 2);

        let material = virtual_api_key_material(&first).expect("material derivation");
        assert!(material.key_hash.starts_with("sha256:"));
        assert_eq!(material.last4, first[first.len() - 4..]);
    }

    #[test]
    fn admin_virtual_api_key_never_carries_the_hash_or_secret() {
        let key = StoredApiKey {
            id: "vk-1".into(),
            workspace_id: "ws-1".into(),
            tenant_id: "tenant-1".into(),
            project_id: "project-1".into(),
            name: "Live key".into(),
            key_prefix: "fg_live_deadbeef".into(),
            key_hash: "sha256:super-secret-hash".into(),
            last4: "beef".into(),
            enabled: true,
            scopes: vec!["chat.completions".into()],
            allowed_models: vec!["fast-chat".into()],
            allowed_providers: vec![],
            tenant: TenantContext::default(),
            monthly_token_budget: Some(1_000),
            request_limit_per_minute: Some(60),
            created_at_unix: 1,
            updated_at_unix: 1,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        };

        let redacted = admin_virtual_api_key(&key);
        let serialized = serde_json::to_string(&redacted).unwrap();

        assert_eq!(redacted.key_prefix, "fg_live_deadbeef");
        assert_eq!(redacted.last4, "beef");
        assert!(!serialized.contains("super-secret-hash"));
        assert!(!serialized.contains("key_hash"));
    }

    #[test]
    fn admin_workspace_maps_full_attribution_chain() {
        let workspace = StoredWorkspace {
            id: "ws-1".into(),
            project_id: "project-1".into(),
            tenant_id: "tenant-1".into(),
            name: "Workspace 1".into(),
            slug: "workspace-1".into(),
            environment: "prod".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 2,
        };

        let mapped = admin_workspace(&workspace);
        assert_eq!(mapped.id, "ws-1");
        assert_eq!(mapped.project_id, "project-1");
        assert_eq!(mapped.tenant_id, "tenant-1");
        assert_eq!(mapped.environment, "prod");
    }
}
