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
    state::UsageReportFilter,
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
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => {
                let mut filter = UsageReportFilter::from_query(query);
                if let Some(tenant_id) = auth.organization_id.clone() {
                    match (filter.scope_type, filter.scope_id.as_deref()) {
                        (Some(scope_type), Some(scope_id)) => {
                            if let Err(error) = crate::auth::authorize_scoped_resource(
                                &state, &auth, scope_type, scope_id,
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
                        }
                        _ => {
                            // No scope filter (or a scope_type without an id) was
                            // supplied: a tenant-scoped caller gets narrowed to
                            // their own tenant rather than an unscoped report
                            // spanning every tenant (issue #185).
                            filter.scope_type = Some(ferrogate_storage::QuotaScopeKind::Tenant);
                            filter.scope_id = Some(tenant_id);
                        }
                    }
                }
                match state.usage_report(&filter).await {
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
