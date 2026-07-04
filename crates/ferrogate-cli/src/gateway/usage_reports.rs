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
            Ok(_) => {
                let filter = UsageReportFilter::from_query(query);
                match state.usage_report(&filter) {
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
