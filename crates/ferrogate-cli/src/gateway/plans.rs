// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Admin management surface for sellable subscription plans
// (issue #168): /admin/v1/plans. `StoredPlan` itself, quota-merge
// integration (`ferrogate_policy::resolve_effective_quota`), and
// plan-gated feature enforcement (MCP/self-hosted workers) already exist;
// this is the missing HTTP surface a CLI subcommand or admin-console view
// needs to create/list/assign plans instead of only being reachable via
// direct Rust calls.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_storage::StoredPlan;

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminList, AdminPlan,
        AdminPlanMutation, AdminPlanMutationResponse,
    },
};

const MAX_BODY_BYTES: usize = 64 * 1024;

impl FerroGateway {
    pub(super) async fn handle_admin_plans(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/plans" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(_) => match state.list_plans().await {
                        Ok(plans) => {
                            let body = AdminList::new(plans.iter().map(admin_plan).collect());
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
                Method::POST => self.handle_admin_plan_create(session, ctx, headers).await,
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "plans collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(id) = path
            .strip_prefix("/admin/v1/plans/")
            .filter(|id| !id.is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "plan endpoint not found",
                &ctx.request_id,
            )
            .await;
        };

        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(_) => match state.get_plan(id).await {
                    Ok(Some(plan)) => {
                        let body = AdminPlanMutationResponse {
                            object: "plan",
                            plan: admin_plan(&plan),
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(None) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "plan_not_found",
                            format!("no plan with id {id}"),
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
            Method::PUT => {
                self.handle_admin_plan_upsert_at_id(session, ctx, headers, id, false)
                    .await
            }
            Method::PATCH => {
                self.handle_admin_plan_upsert_at_id(session, ctx, headers, id, true)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "plan endpoint supports GET, PUT, and PATCH",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_plan_create(
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
        let payload = match read_json_body::<AdminPlanMutation>(session, &ctx.request_id).await? {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(slug) = payload.slug.clone().filter(|slug| !slug.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_plan",
                "field slug is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(name) = payload.name.clone().filter(|name| !name.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_plan",
                "field name is required",
                &ctx.request_id,
            )
            .await;
        };
        let id = payload
            .id
            .clone()
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| slug.clone());
        if state.get_plan(&id).await.ok().flatten().is_some() {
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "plan_already_exists",
                format!(
                    "plan {id} already exists; use PUT/PATCH /admin/v1/plans/{id} to update it"
                ),
                &ctx.request_id,
            )
            .await;
        }
        let now = now_unix_seconds();
        let plan = StoredPlan {
            id: id.clone(),
            name,
            slug,
            mcp_enabled: payload.mcp_enabled.unwrap_or(false),
            self_hosted_workers_enabled: payload.self_hosted_workers_enabled.unwrap_or(false),
            admin_console_seats: payload.admin_console_seats,
            default_model_allowlist: payload.default_model_allowlist.unwrap_or_default(),
            default_rpm_limit: payload.default_rpm_limit,
            default_tpm_limit: payload.default_tpm_limit,
            default_monthly_budget_usd: payload.default_monthly_budget_usd,
            asset_hosting_enabled: payload.asset_hosting_enabled.unwrap_or(false),
            default_asset_storage_quota_bytes: payload.default_asset_storage_quota_bytes,
            extension_tools_enabled: payload.extension_tools_enabled.unwrap_or(false),
            created_at_unix: now,
            updated_at_unix: now,
        };
        self.upsert_plan_and_respond(session, ctx, &state, &auth, plan, StatusCode::CREATED)
            .await
    }

    /// PUT (`merge = false`) replaces every field not present in the
    /// payload with its default; PATCH (`merge = true`) keeps the existing
    /// plan's value for any field the payload omits -- same distinction
    /// `handle_admin_quota_policy_upsert_at_scope` makes.
    async fn handle_admin_plan_upsert_at_id(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
        merge: bool,
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
        let payload = match read_json_body::<AdminPlanMutation>(session, &ctx.request_id).await? {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let existing = state.get_plan(id).await.ok().flatten();
        if !merge && existing.is_none() {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "plan_not_found",
                format!("no plan with id {id}; PUT only updates an existing plan"),
                &ctx.request_id,
            )
            .await;
        }
        let now = now_unix_seconds();
        let created_at_unix = existing
            .as_ref()
            .map_or(now, |existing| existing.created_at_unix);
        let plan = if merge {
            let existing = existing.unwrap_or_else(|| StoredPlan {
                id: id.to_string(),
                name: id.to_string(),
                slug: id.to_string(),
                mcp_enabled: false,
                self_hosted_workers_enabled: false,
                admin_console_seats: None,
                default_model_allowlist: Vec::new(),
                default_rpm_limit: None,
                default_tpm_limit: None,
                default_monthly_budget_usd: None,
                asset_hosting_enabled: false,
                default_asset_storage_quota_bytes: None,
                extension_tools_enabled: false,
                created_at_unix: now,
                updated_at_unix: now,
            });
            StoredPlan {
                id: id.to_string(),
                name: payload.name.unwrap_or(existing.name),
                slug: payload.slug.unwrap_or(existing.slug),
                mcp_enabled: payload.mcp_enabled.unwrap_or(existing.mcp_enabled),
                self_hosted_workers_enabled: payload
                    .self_hosted_workers_enabled
                    .unwrap_or(existing.self_hosted_workers_enabled),
                admin_console_seats: payload.admin_console_seats.or(existing.admin_console_seats),
                default_model_allowlist: payload
                    .default_model_allowlist
                    .unwrap_or(existing.default_model_allowlist),
                default_rpm_limit: payload.default_rpm_limit.or(existing.default_rpm_limit),
                default_tpm_limit: payload.default_tpm_limit.or(existing.default_tpm_limit),
                default_monthly_budget_usd: payload
                    .default_monthly_budget_usd
                    .or(existing.default_monthly_budget_usd),
                asset_hosting_enabled: payload
                    .asset_hosting_enabled
                    .unwrap_or(existing.asset_hosting_enabled),
                default_asset_storage_quota_bytes: payload
                    .default_asset_storage_quota_bytes
                    .or(existing.default_asset_storage_quota_bytes),
                extension_tools_enabled: payload
                    .extension_tools_enabled
                    .unwrap_or(existing.extension_tools_enabled),
                created_at_unix,
                updated_at_unix: now,
            }
        } else {
            StoredPlan {
                id: id.to_string(),
                name: payload.name.unwrap_or_else(|| id.to_string()),
                slug: payload.slug.unwrap_or_else(|| id.to_string()),
                mcp_enabled: payload.mcp_enabled.unwrap_or(false),
                self_hosted_workers_enabled: payload.self_hosted_workers_enabled.unwrap_or(false),
                admin_console_seats: payload.admin_console_seats,
                default_model_allowlist: payload.default_model_allowlist.unwrap_or_default(),
                default_rpm_limit: payload.default_rpm_limit,
                default_tpm_limit: payload.default_tpm_limit,
                default_monthly_budget_usd: payload.default_monthly_budget_usd,
                asset_hosting_enabled: payload.asset_hosting_enabled.unwrap_or(false),
                default_asset_storage_quota_bytes: payload.default_asset_storage_quota_bytes,
                extension_tools_enabled: payload.extension_tools_enabled.unwrap_or(false),
                created_at_unix,
                updated_at_unix: now,
            }
        };
        self.upsert_plan_and_respond(session, ctx, &state, &auth, plan, StatusCode::OK)
            .await
    }

    async fn upsert_plan_and_respond(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        state: &crate::state::AppState,
        auth: &crate::auth::AuthContext,
        plan: StoredPlan,
        success_status: StatusCode,
    ) -> PingoraResult<()> {
        let id = plan.id.clone();
        match state.upsert_plan(plan.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    auth,
                    "plan.upsert",
                    &id,
                    "committed",
                    format!("plan {id} upserted"),
                ));
                let body = AdminPlanMutationResponse {
                    object: "plan",
                    plan: admin_plan(&plan),
                };
                write_json_response(session, success_status, &body, &ctx.request_id).await
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

fn admin_plan(plan: &StoredPlan) -> AdminPlan {
    AdminPlan {
        id: plan.id.clone(),
        name: plan.name.clone(),
        slug: plan.slug.clone(),
        mcp_enabled: plan.mcp_enabled,
        self_hosted_workers_enabled: plan.self_hosted_workers_enabled,
        admin_console_seats: plan.admin_console_seats,
        default_model_allowlist: plan.default_model_allowlist.clone(),
        default_rpm_limit: plan.default_rpm_limit,
        default_tpm_limit: plan.default_tpm_limit,
        default_monthly_budget_usd: plan.default_monthly_budget_usd,
        asset_hosting_enabled: plan.asset_hosting_enabled,
        default_asset_storage_quota_bytes: plan.default_asset_storage_quota_bytes,
        extension_tools_enabled: plan.extension_tools_enabled,
        created_at_unix: plan.created_at_unix,
        updated_at_unix: plan.updated_at_unix,
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
