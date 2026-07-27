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
use ferrogate_storage::{
    DeleteProjectOutcome, DeleteWorkspaceOutcome, LifecycleStatus, StoredApiKey, StoredProject,
    StoredTenantAccount, StoredWorkspace,
};

/// Validate and canonicalize a `status` field on a tenant-account / project /
/// workspace write (issue #514, finding 3).
///
/// The read side deliberately fails OPEN: `LifecycleStatus::parse` resolves
/// anything it does not recognize to `Active`, because these columns were
/// decorative until #514 and refusing legacy rows would revoke every
/// pre-existing tenant. Paired with an unvalidated WRITE, though, that default
/// reproduced the exact failure the issue exists to kill:
/// `PUT /admin/v1/tenant-accounts/{id} {"status":"suspend"}` answered
/// `200 OK`, the console rendered `suspend`, and the tenant kept serving --
/// a green confirmation for a control that was never applied.
///
/// So: unrecognized tokens are refused at the boundary with a 400, and
/// accepted ones are stored in their canonical spelling (`"SUSPENDED"` is
/// persisted as `"suspended"`) so the column cannot drift from the vocabulary
/// the gate reads. Blank/absent is still "field not supplied" -- the callers
/// below already treat it that way and fall back to the existing value.
fn canonical_lifecycle_status(raw: Option<String>) -> Result<Option<String>, String> {
    let Some(raw) = raw.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    match LifecycleStatus::parse_strict(&raw) {
        Some(status) => Ok(Some(status.as_str().to_string())),
        None => Err(format!(
            "status {raw:?} is not a recognized lifecycle state; expected one of {}",
            LifecycleStatus::ALL
                .iter()
                .map(|status| status.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

use super::admin_list_query::{list_response, matches_search, query_value};
use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::{authenticate, authenticate_for_lifecycle_recovery},
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminList, AdminProject,
        AdminProjectCreateRequest, AdminProjectMutationResponse, AdminTenantAccount,
        AdminTenantAccountCreateRequest, AdminTenantAccountMutationResponse,
        AdminTenantPlanAssignmentRequest, AdminVirtualApiKey, AdminVirtualApiKeyCreateRequest,
        AdminVirtualApiKeyMutationResponse, AdminWorkspace, AdminWorkspaceCreateRequest,
        AdminWorkspaceMutationResponse,
    },
};

impl FerroGateway {
    pub(super) async fn handle_admin_tenant_accounts(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path != "/admin/v1/tenant-accounts" {
            let Some(id) = path
                .strip_prefix("/admin/v1/tenant-accounts/")
                .filter(|id| !id.is_empty())
            else {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "tenant account endpoint not found",
                    &ctx.request_id,
                )
                .await;
            };
            if let Some(tenant_id) = id.strip_suffix("/resolved-defaults") {
                if tenant_id.is_empty() {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "tenant account endpoint not found",
                        &ctx.request_id,
                    )
                    .await;
                }
                return self
                    .handle_admin_tenant_resolved_defaults(session, ctx, headers, method, tenant_id)
                    .await;
            }
            if let Some(tenant_id) = id.strip_suffix("/plan") {
                if tenant_id.is_empty() {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "not_found",
                        "tenant account endpoint not found",
                        &ctx.request_id,
                    )
                    .await;
                }
                return self
                    .handle_admin_assign_tenant_plan(session, ctx, headers, method, tenant_id)
                    .await;
            }
            return self
                .handle_admin_tenant_account_by_id(session, ctx, headers, method, id)
                .await;
        }
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => match state.list_tenant_accounts().await {
                    Ok(tenants) => {
                        let tenants = ferrogate_gateway::auth::filter_by_tenant_scope(
                            &auth,
                            tenants,
                            |tenant| tenant.id.as_str(),
                        );
                        let search = query_value(query, "search");
                        let tenants = tenants
                            .into_iter()
                            .filter(|tenant| {
                                matches_search(
                                    search.as_deref(),
                                    &[&tenant.id, &tenant.name, &tenant.slug],
                                )
                            })
                            .map(|tenant| admin_tenant_account(&tenant))
                            .collect();
                        let body = list_response(tenants, query, state.admin_pagination(query));
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
            // Creating a tenant account is a PLATFORM-operator action: it mints
            // a new tenant/org and its plan+status. Requiring an operator key
            // (organization_id: None) here closes the #84 follow-up where the
            // create branch, being an upsert (INSERT ... ON CONFLICT (id) DO
            // UPDATE), let a tenant-scoped admin key POST {id: <own tenant>,
            // plan_id: enterprise} to self-escalate its plan, or POST {id:
            // <victim>, status: suspended} to tamper with another tenant --
            // bypassing the PATCH-only guard added for #84. Updates go through
            // the tenant-scoped-and-guarded PATCH/PUT branch above.
            Method::POST => {
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
                if let Err(error) = ferrogate_gateway::auth::require_platform_operator(&auth) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                let payload = match read_json_body::<AdminTenantAccountCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
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
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let account = StoredTenantAccount {
                    id: id.clone(),
                    name,
                    slug,
                    status: status.unwrap_or_else(|| "active".into()),
                    plan_id: payload
                        .plan_id
                        .filter(|plan_id| !plan_id.trim().is_empty())
                        .unwrap_or_else(|| "free".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_tenant_account(account.clone()).await {
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

    /// `/admin/v1/tenant-accounts/{id}`: GET reads the account; PATCH merges
    /// (currently the only real use case is assigning `plan_id` -- issue
    /// #168 -- but every mutable field is accepted for symmetry with the
    /// create payload). No DELETE: out of scope, same as `plans.rs`.
    async fn handle_admin_tenant_account_by_id(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => {
                    if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, id) {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    match state.get_tenant_account(id).await {
                        Ok(Some(account)) => {
                            let body = AdminTenantAccountMutationResponse {
                                object: "tenant_account",
                                tenant: admin_tenant_account(&account),
                            };
                            write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                .await
                        }
                        Ok(None) => {
                            write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "tenant_account_not_found",
                                format!("no tenant account with id {id}"),
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
            // PUT and PATCH share identical merge semantics here (every
            // field optional, falls back to the existing value) -- PUT is
            // accepted alongside PATCH specifically so the admin-console's
            // generic resource-edit form (which always sends PUT) can
            // reassign a tenant's plan_id without a bespoke endpoint or
            // frontend special-case (issue #168).
            // #514 finding 5: this is a lifecycle-status REVERSAL route, so it
            // authenticates against the Recovery seam. The request-time gate
            // runs inside `authenticate()`, before any handler body, and the
            // admin console's own key is tenant-scoped -- so gating `disabled`
            // here would make the tenant's own self-service off switch a
            // one-way door, reversible only by a platform operator.
            // `suspended`/`deleted` still deny: those are platform actions.
            Method::PUT | Method::PATCH => {
                let auth = match authenticate_for_lifecycle_recovery(
                    &state,
                    headers,
                    "admin.write",
                    &ctx.request_id,
                )
                .await
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
                if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, id) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                let payload = match read_json_body::<AdminTenantAccountCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
                .await?
                {
                    Ok(payload) => payload,
                    Err(()) => return Ok(()),
                };
                let Some(existing) = state.get_tenant_account(id).await.ok().flatten() else {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "tenant_account_not_found",
                        format!("no tenant account with id {id}"),
                        &ctx.request_id,
                    )
                    .await;
                };
                if let Some(plan_id) = payload.plan_id.as_deref() {
                    if plan_id.trim().is_empty() {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            "field plan_id must not be empty when present",
                            &ctx.request_id,
                        )
                        .await;
                    }
                    if state.get_plan(plan_id).await.ok().flatten().is_none() {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            format!("plan {plan_id} does not exist"),
                            &ctx.request_id,
                        )
                        .await;
                    }
                }
                // A tenant-scoped admin key (organization_id == its own tenant --
                // the shape every admin-console login provisions) may edit its
                // own account's name/slug, but must NOT change its plan or
                // status. A plan change self-grants paid-tier entitlements +
                // multiplied rpm/tpm/budget/storage quotas, and a status change
                // could un-suspend the tenant -- both are platform-operator
                // actions (matching plans/rbac/wallet mutations, which all call
                // require_platform_operator). Without this a tenant reads a
                // higher plan id via GET /admin/v1/plans and PATCHes itself onto
                // it with no operator approval or billing.
                //
                // #515: asked as "is this NOT a declared platform operator?"
                // rather than "does it carry an organization_id?", so a
                // credential that merely omitted its tenant is held to the
                // tenant-scoped rule instead of being waved through as root.
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_tenant",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                if !auth.is_platform_operator() {
                    let changes_plan = payload
                        .plan_id
                        .as_deref()
                        .is_some_and(|plan_id| plan_id != existing.plan_id);
                    // Compared through the shared vocabulary rather than as raw
                    // strings, so re-sending the tenant's current state in a
                    // different spelling is not mistaken for an escalation
                    // attempt (and so an invalid token can never slip past this
                    // check by looking "unchanged").
                    let changes_status = status.as_deref().is_some_and(|status| {
                        status != LifecycleStatus::parse(&existing.status).as_str()
                    });
                    if changes_plan || changes_status {
                        return write_json_error(
                            session,
                            StatusCode::FORBIDDEN,
                            "platform_operator_required",
                            "changing a tenant's plan or status requires a platform-operator key",
                            &ctx.request_id,
                        )
                        .await;
                    }
                }
                let account = StoredTenantAccount {
                    id: id.to_string(),
                    name: payload.name.unwrap_or(existing.name),
                    slug: payload.slug.unwrap_or(existing.slug),
                    status: status.unwrap_or(existing.status),
                    plan_id: payload.plan_id.unwrap_or(existing.plan_id),
                    created_at_unix: existing.created_at_unix,
                    updated_at_unix: now_unix_seconds(),
                };
                match state.upsert_tenant_account(account.clone()).await {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "tenant_account.update",
                            id,
                            "committed",
                            format!("tenant account {id} updated"),
                        ));
                        let body = AdminTenantAccountMutationResponse {
                            object: "tenant_account",
                            tenant: admin_tenant_account(&account),
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
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "tenant account endpoint supports GET, PUT, and PATCH",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    /// `PUT /admin/v1/tenant-accounts/{tenant_id}/plan` (issue #388): the
    /// focused plan-assignment operation the #364 CLI drives. The general
    /// `handle_admin_tenant_account_by_id` PATCH/PUT already merges `plan_id`,
    /// but a dedicated, single-purpose endpoint gives the CLI a clean
    /// `assignTenantPlan` operation and a self-documenting audit action
    /// instead of overloading a whole-account edit. Assigning a plan
    /// self-grants paid-tier entitlements + multiplied quotas, so -- exactly
    /// like the plan-change guard in the merge path -- it is a
    /// platform-operator action: a tenant-scoped key is rejected.
    async fn handle_admin_assign_tenant_plan(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant_id: &str,
    ) -> PingoraResult<()> {
        if !matches!(*method, Method::PUT | Method::POST) {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "tenant plan-assignment endpoint supports PUT",
                &ctx.request_id,
            )
            .await;
        }
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
        if let Err(error) = ferrogate_gateway::auth::require_platform_operator(&auth) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload = match read_json_body::<AdminTenantPlanAssignmentRequest>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(plan_id) = payload.plan_id.filter(|plan_id| !plan_id.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_plan_assignment",
                "field plan_id is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(existing) = state.get_tenant_account(tenant_id).await.ok().flatten() else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "tenant_account_not_found",
                format!("no tenant account with id {tenant_id}"),
                &ctx.request_id,
            )
            .await;
        };
        if state.get_plan(&plan_id).await.ok().flatten().is_none() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_plan_assignment",
                format!("plan {plan_id} does not exist"),
                &ctx.request_id,
            )
            .await;
        }
        let account = StoredTenantAccount {
            id: existing.id,
            name: existing.name,
            slug: existing.slug,
            status: existing.status,
            plan_id: plan_id.clone(),
            created_at_unix: existing.created_at_unix,
            updated_at_unix: now_unix_seconds(),
        };
        match state.upsert_tenant_account(account.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "tenant_account.assign_plan",
                    tenant_id,
                    "committed",
                    format!("tenant account {tenant_id} assigned plan {plan_id}"),
                ));
                let body = AdminTenantAccountMutationResponse {
                    object: "tenant_account",
                    tenant: admin_tenant_account(&account),
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

    /// `GET /admin/v1/tenant-accounts/{id}/resolved-defaults` (issue
    /// #168): resolves the same `EffectiveQuota` merge chain the auth
    /// path uses at request time, scoped to the tenant alone (no
    /// project/workspace/key in the `TenantContext`), plus the plan's
    /// feature-entitlement flags -- so an operator can see what a plan
    /// actually grants without cross-referencing the Plans page and
    /// mentally re-deriving the merge.
    async fn handle_admin_tenant_resolved_defaults(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant_id: &str,
    ) -> PingoraResult<()> {
        if *method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "tenant resolved-defaults endpoint supports GET",
                &ctx.request_id,
            )
            .await;
        }
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
        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let Some(account) = state.get_tenant_account(tenant_id).await.ok().flatten() else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "tenant_account_not_found",
                format!("no tenant account with id {tenant_id}"),
                &ctx.request_id,
            )
            .await;
        };
        let effective_quota = match state
            .resolve_effective_quota(&TenantContext {
                organization_id: Some(tenant_id.to_string()),
                ..Default::default()
            })
            .await
        {
            Ok(quota) => quota,
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
        let plan = state.resolve_tenant_plan(tenant_id).await.ok().flatten();
        let body = crate::responses::AdminTenantResolvedDefaults {
            object: "tenant_resolved_defaults",
            tenant_id: tenant_id.to_string(),
            plan_id: account.plan_id,
            model_allowlist: effective_quota.model_allowlist,
            rpm_limit: effective_quota.rpm_limit,
            tpm_limit: effective_quota.tpm_limit,
            monthly_budget_usd: effective_quota.monthly_budget_usd,
            mcp_enabled: plan.as_ref().is_some_and(|plan| plan.mcp_enabled),
            extension_tools_enabled: plan
                .as_ref()
                .is_some_and(|plan| plan.extension_tools_enabled),
            self_hosted_workers_enabled: plan
                .as_ref()
                .is_some_and(|plan| plan.self_hosted_workers_enabled),
            asset_hosting_enabled: plan.as_ref().is_some_and(|plan| plan.asset_hosting_enabled),
            default_asset_storage_quota_bytes: plan
                .as_ref()
                .and_then(|plan| plan.default_asset_storage_quota_bytes),
            default_asset_max_object_bytes: plan
                .as_ref()
                .and_then(|plan| plan.default_asset_max_object_bytes),
            default_agent_cost_budget_usd: plan
                .as_ref()
                .and_then(|plan| plan.default_agent_cost_budget_usd),
        };
        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
    }

    pub(super) async fn handle_admin_projects(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path != "/admin/v1/projects" {
            let Some(id) = path
                .strip_prefix("/admin/v1/projects/")
                .filter(|id| !id.is_empty() && !id.contains('/'))
            else {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "project endpoint not found",
                    &ctx.request_id,
                )
                .await;
            };
            return self
                .handle_admin_project_by_id(session, ctx, headers, method, id)
                .await;
        }
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => match state.list_projects().await {
                    Ok(projects) => {
                        let projects = ferrogate_gateway::auth::filter_by_tenant_scope(
                            &auth,
                            projects,
                            |project| project.tenant_id.as_str(),
                        );
                        let search = query_value(query, "search");
                        let tenant_id = query_value(query, "tenant_id");
                        let projects = projects
                            .into_iter()
                            .filter(|project| {
                                tenant_id
                                    .as_deref()
                                    .is_none_or(|tenant_id| project.tenant_id == tenant_id)
                                    && matches_search(
                                        search.as_deref(),
                                        &[&project.id, &project.name, &project.slug],
                                    )
                            })
                            .map(|project| admin_project(&project))
                            .collect();
                        let body = list_response(projects, query, state.admin_pagination(query));
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
                let payload = match read_json_body::<AdminProjectCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
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
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                if state
                    .get_tenant_account(&tenant_id)
                    .await
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
                // #514 attach-time seam: a suspended tenant may not grow new
                // projects (and therefore, transitively, no new workspaces or
                // keys under them).
                if let Err(error) = state
                    .require_usable_tenancy(
                        ferrogate_storage::LifecycleSeam::Attach,
                        ferrogate_storage::TenancyRefs::tenant(&tenant_id),
                    )
                    .await
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
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
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let project = StoredProject {
                    id: id.clone(),
                    tenant_id,
                    name,
                    slug,
                    status: status.unwrap_or_else(|| "active".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_project(project.clone()).await {
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

    /// `/admin/v1/projects/{id}` (issue #326): GET reads a single project;
    /// PUT/PATCH merge its mutable fields (name/slug/status); DELETE removes
    /// it. Every verb is tenant-scoped -- a tenant-scoped caller may only
    /// touch a project it owns (the row's `tenant_id` must match the caller's
    /// organization, fail-closed per #185/#232); the platform operator is
    /// unrestricted. DELETE is reject-if-referenced: a project that still owns
    /// workspaces or virtual keys cannot be deleted, so a destructive DB-level
    /// `ON DELETE CASCADE` can never silently take out live credentials.
    async fn handle_admin_project_by_id(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => match state.get_project(id).await {
                    Ok(Some(project)) => {
                        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(
                            &auth,
                            &project.tenant_id,
                        ) {
                            return write_json_error(
                                session,
                                error.status,
                                error.code,
                                error.message,
                                &ctx.request_id,
                            )
                            .await;
                        }
                        let body = AdminProjectMutationResponse {
                            object: "project",
                            project: admin_project(&project),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(None) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "project_not_found",
                            format!("no project with id {id}"),
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
            // PUT and PATCH share the same merge semantics: every field is
            // optional and falls back to the existing value.
            // #514 finding 5: this is a lifecycle-status REVERSAL route, so it
            // authenticates against the Recovery seam. The request-time gate
            // runs inside `authenticate()`, before any handler body, and the
            // admin console's own key is tenant-scoped -- so gating `disabled`
            // here would make the tenant's own self-service off switch a
            // one-way door, reversible only by a platform operator.
            // `suspended`/`deleted` still deny: those are platform actions.
            Method::PUT | Method::PATCH => {
                let auth = match authenticate_for_lifecycle_recovery(
                    &state,
                    headers,
                    "admin.write",
                    &ctx.request_id,
                )
                .await
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
                let payload = match read_json_body::<AdminProjectCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
                .await?
                {
                    Ok(payload) => payload,
                    Err(()) => return Ok(()),
                };
                let existing = match state.get_project(id).await {
                    Ok(Some(existing)) => existing,
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "project_not_found",
                            format!("no project with id {id}"),
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
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &existing.tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                // Reassigning a project to a different tenant is not a mutation
                // this endpoint offers: there is no owning-tenant re-attribution
                // for the project's workspaces/keys, so a cross-tenant move
                // would strand them. Reject it outright (fail-closed) rather
                // than silently ignoring the field.
                if let Some(tenant_id) = payload.tenant_id.as_deref() {
                    if !tenant_id.trim().is_empty() && tenant_id != existing.tenant_id {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            "a project's tenant_id is immutable",
                            &ctx.request_id,
                        )
                        .await;
                    }
                }
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_project",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let project = StoredProject {
                    id: existing.id,
                    tenant_id: existing.tenant_id,
                    name: payload
                        .name
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or(existing.name),
                    slug: payload
                        .slug
                        .filter(|slug| !slug.trim().is_empty())
                        .unwrap_or(existing.slug),
                    status: status.unwrap_or(existing.status),
                    created_at_unix: existing.created_at_unix,
                    updated_at_unix: now_unix_seconds(),
                };
                match state.upsert_project(project.clone()).await {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "project.update",
                            id,
                            "committed",
                            format!("project {id} updated"),
                        ));
                        let body = AdminProjectMutationResponse {
                            object: "project",
                            project: admin_project(&project),
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
                let existing = match state.get_project(id).await {
                    Ok(Some(existing)) => existing,
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "project_not_found",
                            format!("no project with id {id}"),
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
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &existing.tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                // Reject-if-referenced: refuse to delete a project that still
                // owns workspaces or virtual keys. The Postgres schema declares
                // ON DELETE CASCADE on both, so a bare DELETE would silently
                // destroy live workspaces and API credentials; this guard keeps
                // the operation fail-closed and forces the caller to tear the
                // children down first. The child-count check and the delete run
                // atomically inside one transaction (issue #328, finding 4) so a
                // child created between the two can no longer slip through the
                // window and be cascade-deleted. Workspaces are surfaced before
                // virtual keys, preserving the prior two-step response order.
                match state.delete_project_if_unreferenced(id).await {
                    Ok(DeleteProjectOutcome::Referenced {
                        workspaces,
                        virtual_keys,
                    }) => {
                        if workspaces > 0 {
                            write_json_error(
                                session,
                                StatusCode::CONFLICT,
                                "project_has_workspaces",
                                format!(
                                    "project {id} still has {workspaces} workspace(s); delete them first"
                                ),
                                &ctx.request_id,
                            )
                            .await
                        } else {
                            write_json_error(
                                session,
                                StatusCode::CONFLICT,
                                "project_has_virtual_keys",
                                format!(
                                    "project {id} still has {virtual_keys} virtual key(s); delete them first"
                                ),
                                &ctx.request_id,
                            )
                            .await
                        }
                    }
                    Ok(DeleteProjectOutcome::Deleted) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "project.delete",
                            id,
                            "committed",
                            format!("project {id} deleted"),
                        ));
                        let body = crate::responses::AdminDeleteResponse {
                            object: "project",
                            id: id.to_string(),
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(DeleteProjectOutcome::NotFound) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "project_not_found",
                            format!("no project with id {id}"),
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
                    "project endpoint supports GET, PUT, PATCH, and DELETE",
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
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if path != "/admin/v1/workspaces" {
            let Some(id) = path
                .strip_prefix("/admin/v1/workspaces/")
                .filter(|id| !id.is_empty() && !id.contains('/'))
            else {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "workspace endpoint not found",
                    &ctx.request_id,
                )
                .await;
            };
            return self
                .handle_admin_workspace_by_id(session, ctx, headers, method, id)
                .await;
        }
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => match state.list_workspaces().await {
                    Ok(workspaces) => {
                        let workspaces = ferrogate_gateway::auth::filter_by_tenant_scope(
                            &auth,
                            workspaces,
                            |workspace| workspace.tenant_id.as_str(),
                        );
                        let search = query_value(query, "search");
                        let tenant_id = query_value(query, "tenant_id");
                        let project_id = query_value(query, "project_id");
                        let workspaces = workspaces
                            .into_iter()
                            .filter(|workspace| {
                                tenant_id
                                    .as_deref()
                                    .is_none_or(|tenant_id| workspace.tenant_id == tenant_id)
                                    && project_id
                                        .as_deref()
                                        .is_none_or(|project_id| workspace.project_id == project_id)
                                    && matches_search(
                                        search.as_deref(),
                                        &[&workspace.id, &workspace.name, &workspace.slug],
                                    )
                            })
                            .map(|workspace| admin_workspace(&workspace))
                            .collect();
                        let body = list_response(workspaces, query, state.admin_pagination(query));
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
                let payload = match read_json_body::<AdminWorkspaceCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
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
                let Some(project) = state.get_project(&project_id).await.ok().flatten() else {
                    return write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "project_not_found",
                        format!("project {project_id} was not found"),
                        &ctx.request_id,
                    )
                    .await;
                };
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &project.tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                // #514 attach-time seam: no new workspace under a suspended
                // project, nor under an active project whose TENANT is
                // suspended -- the chain is checked whole, shallowest first.
                if let Err(error) = state
                    .require_usable_tenancy(
                        ferrogate_storage::LifecycleSeam::Attach,
                        ferrogate_storage::TenancyRefs::new(
                            Some(&project.tenant_id),
                            Some(&project_id),
                            None,
                        ),
                    )
                    .await
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
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
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let workspace = StoredWorkspace {
                    id: id.clone(),
                    project_id,
                    tenant_id: project.tenant_id,
                    name,
                    slug,
                    environment: payload.environment.unwrap_or_else(|| "default".into()),
                    status: status.unwrap_or_else(|| "active".into()),
                    created_at_unix: now,
                    updated_at_unix: now,
                };
                match state.upsert_workspace(workspace.clone()).await {
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

    /// `/admin/v1/workspaces/{id}` (issue #326): GET reads a single workspace;
    /// PUT/PATCH merge its mutable fields (name/slug/environment/status);
    /// DELETE removes it. Tenant-scoped throughout -- a tenant-scoped caller
    /// may only touch a workspace it owns (fail-closed per #185/#232). DELETE
    /// is reject-if-referenced: a workspace that still owns virtual keys cannot
    /// be deleted, so the schema's `ON DELETE CASCADE` never silently destroys
    /// live credentials.
    async fn handle_admin_workspace_by_id(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        id: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => match state.get_workspace(id).await {
                    Ok(Some(workspace)) => {
                        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(
                            &auth,
                            &workspace.tenant_id,
                        ) {
                            return write_json_error(
                                session,
                                error.status,
                                error.code,
                                error.message,
                                &ctx.request_id,
                            )
                            .await;
                        }
                        let body = AdminWorkspaceMutationResponse {
                            object: "workspace",
                            workspace: admin_workspace(&workspace),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(None) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "workspace_not_found",
                            format!("no workspace with id {id}"),
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
            // #514 finding 5: this is a lifecycle-status REVERSAL route, so it
            // authenticates against the Recovery seam. The request-time gate
            // runs inside `authenticate()`, before any handler body, and the
            // admin console's own key is tenant-scoped -- so gating `disabled`
            // here would make the tenant's own self-service off switch a
            // one-way door, reversible only by a platform operator.
            // `suspended`/`deleted` still deny: those are platform actions.
            Method::PUT | Method::PATCH => {
                let auth = match authenticate_for_lifecycle_recovery(
                    &state,
                    headers,
                    "admin.write",
                    &ctx.request_id,
                )
                .await
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
                let payload = match read_json_body::<AdminWorkspaceCreateRequest>(
                    session,
                    state.limits().admin_body_max_bytes(),
                    &ctx.request_id,
                )
                .await?
                {
                    Ok(payload) => payload,
                    Err(()) => return Ok(()),
                };
                let existing = match state.get_workspace(id).await {
                    Ok(Some(existing)) => existing,
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "workspace_not_found",
                            format!("no workspace with id {id}"),
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
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &existing.tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                // Reassigning a workspace to a different project (and thereby
                // potentially a different tenant) is not offered here: its
                // virtual keys carry a denormalized project_id/tenant_id that
                // would be left inconsistent. Reject the move fail-closed.
                if let Some(project_id) = payload.project_id.as_deref() {
                    if !project_id.trim().is_empty() && project_id != existing.project_id {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            "a workspace's project_id is immutable",
                            &ctx.request_id,
                        )
                        .await;
                    }
                }
                let status = match canonical_lifecycle_status(payload.status) {
                    Ok(status) => status,
                    Err(message) => {
                        return write_json_error(
                            session,
                            StatusCode::BAD_REQUEST,
                            "invalid_workspace",
                            message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                };
                let workspace = StoredWorkspace {
                    id: existing.id,
                    project_id: existing.project_id,
                    tenant_id: existing.tenant_id,
                    name: payload
                        .name
                        .filter(|name| !name.trim().is_empty())
                        .unwrap_or(existing.name),
                    slug: payload
                        .slug
                        .filter(|slug| !slug.trim().is_empty())
                        .unwrap_or(existing.slug),
                    environment: payload
                        .environment
                        .filter(|environment| !environment.trim().is_empty())
                        .unwrap_or(existing.environment),
                    status: status.unwrap_or(existing.status),
                    created_at_unix: existing.created_at_unix,
                    updated_at_unix: now_unix_seconds(),
                };
                match state.upsert_workspace(workspace.clone()).await {
                    Ok(()) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "workspace.update",
                            id,
                            "committed",
                            format!("workspace {id} updated"),
                        ));
                        let body = AdminWorkspaceMutationResponse {
                            object: "workspace",
                            workspace: admin_workspace(&workspace),
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
                let existing = match state.get_workspace(id).await {
                    Ok(Some(existing)) => existing,
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "workspace_not_found",
                            format!("no workspace with id {id}"),
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
                if let Err(error) =
                    ferrogate_gateway::auth::authorize_tenant_scope(&auth, &existing.tenant_id)
                {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                // Reject-if-referenced: a workspace that still owns virtual keys
                // cannot be deleted (the schema's ON DELETE CASCADE would
                // silently destroy live credentials otherwise). The count
                // check and the delete run atomically inside one transaction
                // (issue #328, finding 4) so a key created between them cannot
                // slip through the window and be cascade-deleted.
                match state.delete_workspace_if_unreferenced(id).await {
                    Ok(DeleteWorkspaceOutcome::Referenced { virtual_keys }) => {
                        write_json_error(
                            session,
                            StatusCode::CONFLICT,
                            "workspace_has_virtual_keys",
                            format!(
                                "workspace {id} still has {virtual_keys} virtual key(s); delete them first"
                            ),
                            &ctx.request_id,
                        )
                        .await
                    }
                    Ok(DeleteWorkspaceOutcome::Deleted) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "workspace.delete",
                            id,
                            "committed",
                            format!("workspace {id} deleted"),
                        ));
                        let body = crate::responses::AdminDeleteResponse {
                            object: "workspace",
                            id: id.to_string(),
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(DeleteWorkspaceOutcome::NotFound) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "workspace_not_found",
                            format!("no workspace with id {id}"),
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
                    "workspace endpoint supports GET, PUT, PATCH, and DELETE",
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
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id)
                    .await
                {
                    Ok(auth) => match state.list_virtual_api_keys().await {
                        Ok(keys) => {
                            let keys = ferrogate_gateway::auth::filter_by_tenant_scope(
                                &auth,
                                keys,
                                |key| key.tenant_id.as_str(),
                            );
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
                match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
                    Ok(auth) => match state.get_virtual_api_key(id).await {
                        Ok(Some(key)) => {
                            if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(
                                &auth,
                                &key.tenant_id,
                            ) {
                                return write_json_error(
                                    session,
                                    error.status,
                                    error.code,
                                    error.message,
                                    &ctx.request_id,
                                )
                                .await;
                            }
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
        let payload = match read_json_body::<AdminVirtualApiKeyCreateRequest>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
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
        // A virtual key is a data-plane credential; it must never carry a
        // privileged `admin.*` scope or the `*` all-access wildcard (defence in
        // depth for the empty-scope escalation fixed in AuthContext::has_scope).
        if let Some(forbidden) = payload.scopes.as_ref().and_then(|scopes| {
            scopes.iter().find(|scope| {
                scope.as_str() == ferrogate_gateway::auth::WILDCARD_SCOPE
                    || ferrogate_gateway::auth::AuthContext::is_privileged_scope(scope.as_str())
            })
        }) {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_virtual_key",
                format!("virtual keys may not hold the privileged scope '{forbidden}'"),
                &ctx.request_id,
            )
            .await;
        }
        let scope = match state.resolve_workspace_scope(&workspace_id).await {
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
        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, &scope.tenant_id)
        {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        // #514 attach-time seam, the exact hole the live probe walked through:
        // "mint a NEW virtual key under the suspended chain -> 201 + live
        // secret". The whole resolved chain is checked, so suspending at ANY
        // level (tenant, project or workspace) stops fresh credentials.
        if let Err(error) = state
            .require_usable_tenancy(
                ferrogate_storage::LifecycleSeam::Attach,
                ferrogate_storage::TenancyRefs::new(
                    Some(&scope.tenant_id),
                    Some(&scope.project_id),
                    Some(&scope.workspace_id),
                ),
            )
            .await
        {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }

        let id = payload
            .id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| next_hierarchy_id("vk"));
        let secret = match ferrogate_auth::generate_virtual_api_key_secret() {
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

        match state.upsert_virtual_api_key(key.clone()).await {
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
        let Some(mut key) = (match state.get_virtual_api_key(id).await {
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
        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, &key.tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        // #514 attach-time seam. Rotation issues FRESH secret material against
        // the same tenancy chain, so it is a mint in every way that matters to
        // suspension: without this, "suspend the tenant" is undone by rotating
        // an existing key instead of creating a new one. (This site was missed
        // when the seam first landed, which is what four hand-wired call sites
        // costs.)
        if let Err(error) = state
            .require_usable_tenancy(
                ferrogate_storage::LifecycleSeam::Attach,
                ferrogate_storage::TenancyRefs::new(
                    Some(&key.tenant_id),
                    Some(&key.project_id),
                    Some(&key.workspace_id),
                ),
            )
            .await
        {
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "virtual_key.rotate",
                id,
                "rejected",
                error.message.clone(),
            ));
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }

        let secret = match ferrogate_auth::generate_virtual_api_key_secret() {
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

        match state.upsert_virtual_api_key(key.clone()).await {
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
        let Some(mut key) = (match state.get_virtual_api_key(id).await {
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
        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, &key.tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        key.enabled = enabled;
        key.updated_at_unix = now_unix_seconds() as u64;

        let action = if enabled {
            "virtual_key.enable"
        } else {
            "virtual_key.disable"
        };
        match state.upsert_virtual_api_key(key.clone()).await {
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
        let Some(mut key) = (match state.get_virtual_api_key(id).await {
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
        if let Err(error) = ferrogate_gateway::auth::authorize_tenant_scope(&auth, &key.tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let now = now_unix_seconds() as u64;
        key.enabled = false;
        key.revoked_at_unix = Some(now);
        key.updated_at_unix = now;

        match state.upsert_virtual_api_key(key.clone()).await {
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

fn admin_tenant_account(tenant: &StoredTenantAccount) -> AdminTenantAccount {
    AdminTenantAccount {
        id: tenant.id.clone(),
        name: tenant.name.clone(),
        slug: tenant.slug.clone(),
        status: tenant.status.clone(),
        plan_id: tenant.plan_id.clone(),
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
        let first = ferrogate_auth::generate_virtual_api_key_secret().expect("first secret");
        let second = ferrogate_auth::generate_virtual_api_key_secret().expect("second secret");

        assert!(first.starts_with("fg_"));
        assert_ne!(first, second, "secrets must not repeat across calls");
        assert_eq!(first.len(), "fg_".len() + 24 * 2, "192 bits hex-encoded");

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
