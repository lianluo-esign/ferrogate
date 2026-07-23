// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Admin surface for the durable billing-report outbox (issues
// #143 / #388). GET /admin/v1/billing-outbox-dead-letters lists reports that
// permanently failed delivery to the standalone billing service after the max
// retry attempts. POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay
// re-enqueues one such dead-letter for redelivery via a conditional (CAS)
// storage mutation, so an operator (or the #364 CLI) can drive remediation
// in-band instead of poking storage out of band.

use ferrogate_storage::ReplayDeadLetterOutcome;
use http::StatusCode;
use pingora::{proxy::Session, Result as PingoraResult};

use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::{authenticate, authorize_tenant_scope, filter_by_tenant_scope},
    responses::{
        write_json_error, write_json_response, AdminBillingOutboxReplayResponse, AdminList,
    },
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
            Ok(auth) => match state.billing_outbox_dead_letters().await {
                Ok(rows) => {
                    let rows = filter_by_tenant_scope(&auth, rows, |row| {
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

    /// `POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay` (issue
    /// #388): conditionally re-enqueue one dead-lettered billing report for
    /// redelivery. The state transition is a CAS in storage that only fires
    /// for a row that is actually dead-lettered; the handler tenant-authorizes
    /// against the report's own tenant *before* mutating (so a tenant-scoped
    /// admin key can never replay another tenant's report) and records audit
    /// evidence linking the replay to the report id, tenant, and request/trace
    /// id.
    pub(super) async fn handle_admin_billing_outbox_dead_letter_replay(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        report_id: &str,
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

        // Read-then-authorize before the CAS: the row's owning tenant never
        // changes, so this is a stable ownership check with no time-of-use
        // gap that matters (the CAS below re-checks the dead-letter state).
        let entry = match state.billing_outbox_entry(report_id).await {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "dead_letter_not_found",
                    format!("no billing-outbox report with id {report_id}"),
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
        let report_tenant = entry.event.tenant.organization_id.as_deref().unwrap_or("");
        if let Err(error) = authorize_tenant_scope(&auth, report_tenant) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }

        match state.replay_billing_outbox_dead_letter(report_id).await {
            Ok(ReplayDeadLetterOutcome::Replayed(replayed)) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "billing_outbox.replay",
                    report_id,
                    "committed",
                    format!("dead-lettered billing report {report_id} re-enqueued for redelivery"),
                ));
                let body = AdminBillingOutboxReplayResponse {
                    object: "billing_outbox_dead_letter_replay",
                    id: replayed.id,
                    replayed: true,
                    dead_lettered: replayed.dead_lettered_at_unix.is_some(),
                    attempts: replayed.attempts,
                    next_attempt_unix: replayed.next_attempt_unix,
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(ReplayDeadLetterOutcome::NotDeadLettered(_)) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "billing_outbox.replay",
                    report_id,
                    "rejected",
                    format!("billing report {report_id} is not dead-lettered; replay rejected"),
                ));
                write_json_error(
                    session,
                    StatusCode::CONFLICT,
                    "dead_letter_not_replayable",
                    format!("billing report {report_id} is not dead-lettered; nothing to replay"),
                    &ctx.request_id,
                )
                .await
            }
            // The row was deleted between the authorize read and the CAS
            // (e.g. a concurrent successful delivery). Report it as gone.
            Ok(ReplayDeadLetterOutcome::NotFound) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "dead_letter_not_found",
                    format!("no billing-outbox report with id {report_id}"),
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
}
