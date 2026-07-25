// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: Admin management surface for multi-level quota/rate-limit
// policies (P1-3): /admin/v1/quota-policies.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};

use ferrogate_storage::{QuotaScopeKind, StoredQuotaPolicy};

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::{authenticate, authorize_scoped_resource as authorize_quota_policy_scope},
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminList,
        AdminQuotaPolicy, AdminQuotaPolicyMutation, AdminQuotaPolicyMutationResponse,
    },
};

struct QuotaPolicyScope<'a> {
    scope_type: QuotaScopeKind,
    scope_id: &'a str,
    /// `false` (POST create, PUT replace): unspecified fields reset to their
    /// defaults. `true` (PATCH): unspecified fields keep whatever the
    /// existing policy at this scope already had.
    merge: bool,
}

impl FerroGateway {
    pub(super) async fn handle_admin_quota_policies(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/quota-policies" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id)
                    .await
                {
                    Ok(auth) => match state.list_quota_policies().await {
                        Ok(policies) => {
                            let mut authorized = Vec::with_capacity(policies.len());
                            for policy in policies {
                                if authorize_quota_policy_scope(
                                    &state,
                                    &auth,
                                    policy.scope_type,
                                    &policy.scope_id,
                                )
                                .await
                                .is_ok()
                                {
                                    authorized.push(policy);
                                }
                            }
                            let body =
                                AdminList::new(authorized.iter().map(admin_quota_policy).collect());
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
                    self.handle_admin_quota_policy_upsert(session, ctx, headers)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "quota policies collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(rest) = path.strip_prefix("/admin/v1/quota-policies/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "quota policy endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        let Some((scope_type_raw, scope_id)) = rest.split_once('/') else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "quota policy path must be /admin/v1/quota-policies/{scope_type}/{scope_id}",
                &ctx.request_id,
            )
            .await;
        };
        let Some(scope_type) = QuotaScopeKind::from_str_opt(scope_type_raw) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                format!(
                    "scope_type must be one of tenant, project, workspace, key; got {scope_type_raw}"
                ),
                &ctx.request_id,
            )
            .await;
        };
        if scope_id.is_empty() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "scope_id is required",
                &ctx.request_id,
            )
            .await;
        }

        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id).await
            {
                Ok(auth) => {
                    if let Err(error) =
                        authorize_quota_policy_scope(&state, &auth, scope_type, scope_id).await
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
                    match state.get_quota_policy(scope_type, scope_id).await {
                        Ok(Some(policy)) => {
                            let body = AdminQuotaPolicyMutationResponse {
                                object: "quota_policy",
                                policy: admin_quota_policy(&policy),
                            };
                            write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                .await
                        }
                        Ok(None) => {
                            write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "quota_policy_not_found",
                                format!("no quota policy at scope {scope_type_raw}/{scope_id}"),
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
            Method::PUT => {
                self.handle_admin_quota_policy_upsert_at_scope(
                    session, ctx, headers, scope_type, scope_id, false,
                )
                .await
            }
            Method::PATCH => {
                self.handle_admin_quota_policy_upsert_at_scope(
                    session, ctx, headers, scope_type, scope_id, true,
                )
                .await
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
                if let Err(error) =
                    authorize_quota_policy_scope(&state, &auth, scope_type, scope_id).await
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
                let target = format!("{scope_type_raw}/{scope_id}");
                match state.delete_quota_policy(scope_type, scope_id).await {
                    Ok(true) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "quota_policy.delete",
                            &target,
                            "committed",
                            format!("quota policy {target} deleted"),
                        ));
                        let body = crate::responses::AdminDeleteResponse {
                            object: "quota_policy",
                            id: target,
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(false) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "quota_policy_not_found",
                            format!("no quota policy at scope {target}"),
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
                    "quota policy endpoint supports GET, PUT, PATCH, and DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_quota_policy_upsert(
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
        let payload = match read_json_body::<AdminQuotaPolicyMutation>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(scope_type_raw) = payload.scope_type.as_deref() else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "field scope_type is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(scope_type) = QuotaScopeKind::from_str_opt(scope_type_raw) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                format!(
                    "scope_type must be one of tenant, project, workspace, key; got {scope_type_raw}"
                ),
                &ctx.request_id,
            )
            .await;
        };
        let Some(scope_id) = payload
            .scope_id
            .clone()
            .filter(|scope_id| !scope_id.trim().is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "field scope_id is required",
                &ctx.request_id,
            )
            .await;
        };
        self.upsert_quota_policy_and_respond(
            session,
            ctx,
            &state,
            &auth,
            QuotaPolicyScope {
                scope_type,
                scope_id: &scope_id,
                merge: false,
            },
            payload,
        )
        .await
    }

    async fn handle_admin_quota_policy_upsert_at_scope(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        merge: bool,
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
        let payload = match read_json_body::<AdminQuotaPolicyMutation>(
            session,
            state.limits().admin_body_max_bytes(),
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        if let Some(body_scope_type) = payload.scope_type.as_deref() {
            if body_scope_type != scope_type.as_str() {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_quota_policy",
                    "request path scope_type and body scope_type must match",
                    &ctx.request_id,
                )
                .await;
            }
        }
        if let Some(body_scope_id) = payload.scope_id.as_deref() {
            if body_scope_id != scope_id {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_quota_policy",
                    "request path scope_id and body scope_id must match",
                    &ctx.request_id,
                )
                .await;
            }
        }
        self.upsert_quota_policy_and_respond(
            session,
            ctx,
            &state,
            &auth,
            QuotaPolicyScope {
                scope_type,
                scope_id,
                merge,
            },
            payload,
        )
        .await
    }

    /// See [`QuotaPolicyScope::merge`] for the PUT-vs-PATCH distinction this
    /// implements.
    async fn upsert_quota_policy_and_respond(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        state: &crate::state::AppState,
        auth: &crate::auth::AuthContext,
        scope: QuotaPolicyScope<'_>,
        payload: AdminQuotaPolicyMutation,
    ) -> PingoraResult<()> {
        let QuotaPolicyScope {
            scope_type,
            scope_id,
            merge,
        } = scope;
        if let Err(error) = authorize_quota_policy_scope(state, auth, scope_type, scope_id).await {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        if let Some(alert_threshold_pcts) = payload.alert_threshold_pcts.as_ref() {
            if let Some(invalid) = alert_threshold_pcts
                .iter()
                .find(|threshold_pct| !(1..=100).contains(*threshold_pct))
            {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_quota_policy",
                    format!(
                        "alert_threshold_pcts entries must be between 1 and 100; got {invalid}"
                    ),
                    &ctx.request_id,
                )
                .await;
            }
        }
        if scope_type != QuotaScopeKind::Tenant && payload.asset_storage_quota_bytes.is_some() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "asset_storage_quota_bytes is tenant-only because stored assets and usage are tenant-owned",
                &ctx.request_id,
            )
            .await;
        }
        if scope_type != QuotaScopeKind::Tenant && payload.asset_max_object_bytes.is_some() {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_quota_policy",
                "asset_max_object_bytes is tenant-only because stored assets and usage are tenant-owned",
                &ctx.request_id,
            )
            .await;
        }
        let now = now_unix_seconds();
        let existing = state
            .get_quota_policy(scope_type, scope_id)
            .await
            .ok()
            .flatten();
        // Preserve the original created_at_unix across re-upserts of the
        // same scope; only a brand-new (scope_type, scope_id) gets `now`.
        let created_at_unix = existing
            .as_ref()
            .map_or(now, |existing| existing.created_at_unix);
        let policy = if merge {
            StoredQuotaPolicy {
                id: ferrogate_storage::quota_policy_id(scope_type, scope_id),
                scope_type,
                scope_id: scope_id.to_string(),
                model_allowlist: payload.model_allowlist.unwrap_or_else(|| {
                    existing
                        .as_ref()
                        .map(|existing| existing.model_allowlist.clone())
                        .unwrap_or_default()
                }),
                rpm_limit: payload
                    .rpm_limit
                    .or_else(|| existing.as_ref().and_then(|existing| existing.rpm_limit)),
                tpm_limit: payload
                    .tpm_limit
                    .or_else(|| existing.as_ref().and_then(|existing| existing.tpm_limit)),
                monthly_budget_usd: payload.monthly_budget_usd.or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|existing| existing.monthly_budget_usd)
                }),
                // #428: mirrors monthly_budget_usd -- settable at any scope,
                // merged min-across-the-chain (NOT tenant-only like the asset
                // ceilings), preserved from the existing policy on merge.
                agent_cost_budget_usd: payload.agent_cost_budget_usd.or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|existing| existing.agent_cost_budget_usd)
                }),
                asset_storage_quota_bytes: if scope_type == QuotaScopeKind::Tenant {
                    payload.asset_storage_quota_bytes.or_else(|| {
                        existing
                            .as_ref()
                            .and_then(|existing| existing.asset_storage_quota_bytes)
                    })
                } else {
                    None
                },
                asset_max_object_bytes: if scope_type == QuotaScopeKind::Tenant {
                    payload.asset_max_object_bytes.or_else(|| {
                        existing
                            .as_ref()
                            .and_then(|existing| existing.asset_max_object_bytes)
                    })
                } else {
                    None
                },
                alert_threshold_pcts: payload.alert_threshold_pcts.unwrap_or_else(|| {
                    existing
                        .as_ref()
                        .map(|existing| existing.alert_threshold_pcts.clone())
                        .unwrap_or_default()
                }),
                enabled: payload
                    .enabled
                    .unwrap_or_else(|| existing.as_ref().is_none_or(|existing| existing.enabled)),
                created_at_unix,
                updated_at_unix: now,
                monthly_egress_bytes_budget: payload.monthly_egress_bytes_budget.or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|existing| existing.monthly_egress_bytes_budget)
                }),
                download_rpm_limit: payload.download_rpm_limit.or_else(|| {
                    existing
                        .as_ref()
                        .and_then(|existing| existing.download_rpm_limit)
                }),
            }
        } else {
            StoredQuotaPolicy {
                id: ferrogate_storage::quota_policy_id(scope_type, scope_id),
                scope_type,
                scope_id: scope_id.to_string(),
                model_allowlist: payload.model_allowlist.unwrap_or_default(),
                rpm_limit: payload.rpm_limit,
                tpm_limit: payload.tpm_limit,
                monthly_budget_usd: payload.monthly_budget_usd,
                // #428: mirrors monthly_budget_usd (settable at any scope).
                agent_cost_budget_usd: payload.agent_cost_budget_usd,
                asset_storage_quota_bytes: if scope_type == QuotaScopeKind::Tenant {
                    payload.asset_storage_quota_bytes
                } else {
                    None
                },
                asset_max_object_bytes: if scope_type == QuotaScopeKind::Tenant {
                    payload.asset_max_object_bytes
                } else {
                    None
                },
                alert_threshold_pcts: payload.alert_threshold_pcts.unwrap_or_default(),
                enabled: payload.enabled.unwrap_or(true),
                created_at_unix,
                updated_at_unix: now,
                monthly_egress_bytes_budget: payload.monthly_egress_bytes_budget,
                download_rpm_limit: payload.download_rpm_limit,
            }
        };
        let target = format!("{}/{scope_id}", scope_type.as_str());
        match state.upsert_quota_policy(policy.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    auth,
                    "quota_policy.upsert",
                    &target,
                    "committed",
                    format!("quota policy {target} upserted"),
                ));
                let body = AdminQuotaPolicyMutationResponse {
                    object: "quota_policy",
                    policy: admin_quota_policy(&policy),
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

fn admin_quota_policy(policy: &StoredQuotaPolicy) -> AdminQuotaPolicy {
    AdminQuotaPolicy {
        id: policy.id.clone(),
        scope_type: policy.scope_type.as_str().to_string(),
        scope_id: policy.scope_id.clone(),
        model_allowlist: policy.model_allowlist.clone(),
        rpm_limit: policy.rpm_limit,
        tpm_limit: policy.tpm_limit,
        monthly_budget_usd: policy.monthly_budget_usd,
        agent_cost_budget_usd: policy.agent_cost_budget_usd,
        asset_storage_quota_bytes: policy.asset_storage_quota_bytes,
        asset_max_object_bytes: policy.asset_max_object_bytes,
        alert_threshold_pcts: policy.alert_threshold_pcts.clone(),
        monthly_egress_bytes_budget: policy.monthly_egress_bytes_budget,
        download_rpm_limit: policy.download_rpm_limit,
        enabled: policy.enabled,
        created_at_unix: policy.created_at_unix,
        updated_at_unix: policy.updated_at_unix,
    }
}

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
