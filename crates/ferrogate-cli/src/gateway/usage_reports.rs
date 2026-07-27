// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-04
// description: Admin usage/cost report surface (P1-4): /admin/v1/usage-reports,
// a read-only view over the `usage_monthly_rollups` table populated alongside
// every settled billing event, supporting scope + time-range filters and
// optional aggregation.

use http::StatusCode;
use pingora::{proxy::Session, Result as PingoraResult};

use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, AdminList},
    state::{UsageReportFilter, UsageReportGroupBy},
};

impl FerroGateway {
    pub(super) async fn handle_admin_usage_reports(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id).await {
            Ok(auth) => {
                let mut filter = UsageReportFilter::from_query(query);
                let is_metadata_group_by =
                    matches!(filter.group_by, Some(UsageReportGroupBy::Metadata(_)));
                // #515: the scope narrowing below is what a NON-operator gets.
                // Selecting it on `organization_id.is_some()` meant a credential
                // that declared no identity skipped the narrowing entirely and
                // read an unscoped, cross-tenant report.
                if let ferrogate_gateway::auth::CallerScope::Tenant(tenant_id) = auth.caller_scope()
                {
                    let tenant_id = tenant_id.to_string();
                    // `group_by=metadata.<key>` is served from
                    // `usage_metadata_rollups`, which is NOT keyed on the
                    // tenant/project/workspace/key scope chain, so the
                    // scope_type/scope_id narrowing below cannot constrain it.
                    // Instead, tenant isolation for the metadata breakdown is
                    // enforced by scoping the rollups to the caller's
                    // organization_id (issue #226, threaded into usage_report
                    // below); skip the scope narrowing in that case. (Before
                    // #226 this path returned 403 for tenant-scoped callers to
                    // contain a cross-tenant leak -- ea1040b -- which the
                    // per-tenant rollup column now closes properly.)
                    if !is_metadata_group_by {
                        match (filter.scope_type, filter.scope_id.as_deref()) {
                            (Some(scope_type), Some(scope_id)) => {
                                if let Err(error) = crate::auth::authorize_scoped_resource(
                                    &state, &auth, scope_type, scope_id,
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
                            }
                            _ => {
                                // No scope filter (or a scope_type without an id)
                                // was supplied: a tenant-scoped caller gets
                                // narrowed to their own tenant rather than an
                                // unscoped report spanning every tenant (#185).
                                filter.scope_type = Some(ferrogate_storage::QuotaScopeKind::Tenant);
                                filter.scope_id = Some(tenant_id);
                            }
                        }
                    }
                }
                // Tenant-scoped callers see only their own metadata breakdown;
                // a DECLARED platform operator (#515) keeps the global
                // cross-tenant view. `tenant_filter()` renders exactly that
                // distinction into the `None = every tenant` argument.
                let report_organization_id = auth.tenant_filter();
                match state.usage_report(&filter, report_organization_id).await {
                    Ok(rows) => {
                        let body = AdminList::new(rows);
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
}
