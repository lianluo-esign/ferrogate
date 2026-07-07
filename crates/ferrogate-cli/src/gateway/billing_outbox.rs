// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Admin visibility for the durable billing-report outbox (issue
// #143): /admin/v1/billing-outbox-dead-letters lists reports that permanently
// failed delivery to the standalone billing service after the max retry
// attempts, so an operator can inspect (and, out of band, remediate) them
// instead of them silently accumulating.

use http::StatusCode;
use pingora::{proxy::Session, Result as PingoraResult};

use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response, AdminList},
};

impl FerroGateway {
    pub(super) async fn handle_admin_billing_outbox_dead_letters(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
    ) -> PingoraResult<()> {
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => match state.billing_outbox_dead_letters() {
                Ok(rows) => {
                    let rows = crate::auth::filter_by_tenant_scope(&auth, rows, |row| {
                        row.event.tenant.organization_id.as_deref().unwrap_or("")
                    });
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
}
