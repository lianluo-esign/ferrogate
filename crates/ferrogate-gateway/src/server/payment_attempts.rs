// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Narrow read-only Admin API over durable x402 payment attempts
// (issue #352): `GET /admin/v1/payment-attempts` (tenant-scoped, keyset
// paginated) and `GET /admin/v1/payment-attempts/{id}` (attempt joined to its
// wallet reservation and settlement). Read-only -- nothing here creates,
// mutates, releases, or captures anything.

//! Payment-attempt inspection surface (issue #352).
//!
//! The issue's `## Scope and ownership` bullet — *"`ferrogate-cli`: narrow Admin
//! API to list/get attempts and inspect linked wallet reservation/settlement"* —
//! and its E2E closure — *"Evidence: Admin API joins attempt, hold, wallet
//! settlement, policy revision, and transaction evidence"* — are what this file
//! builds. Without it the repository half was a dead seam: an operator holding a
//! customer's stuck `outcome_unknown` attempt (hold live against their wallet,
//! stablecoin possibly already moved) had no endpoint, no CLI and no console to
//! look at it, and acceptance box 5's "inspectable unknown attempt" meant
//! "write a Rust integration test".
//!
//! Two operations, both `GET`, both behind the existing `admin.read` bearer
//! scope:
//!
//! - `GET /admin/v1/payment-attempts?tenant_id=…&limit=…&cursor=…` — one BOUNDED
//!   page of a tenant's attempts, newest-first. The bound is not optional: see
//!   [`page_query`].
//! - `GET /admin/v1/payment-attempts/{id}` — the attempt plus its linked wallet
//!   reservation and captured settlement. `404` when the caller's tenant does
//!   not own it, because the storage predicate makes another tenant's attempt
//!   indistinguishable from a missing one.
//!
//! **Read-only, and nothing sensitive.** Responses are built from explicit,
//! closed projection structs — never a passthrough of the stored record — so a
//! field added upstream cannot silently appear on the admin surface. Money is
//! transported exactly as stored: `atomic_amount`/`settled_atomic_amount` stay
//! canonical decimal STRINGS (an on-chain `u64` exceeds `i64`) and credits stay
//! integers. Nothing here parses, rounds, or recomputes an amount.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use serde::Serialize;

use ferrogate_storage::{
    PaymentAttemptCursor, PaymentAttemptLinks, PaymentAttemptQuery, StoredPaymentAttempt,
    StoredWalletReservation, StoredWalletSettlement, PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT,
    PAYMENT_ATTEMPT_PAGE_MAX_LIMIT,
};

use super::admin_list_query::query_value;
use super::{FerroGateway, ProxyContext};
use crate::auth::authorize_tenant_scope;
use crate::{
    auth::authenticate,
    responses::{write_json_error, write_json_response},
};

// ---------------------------------------------------------------------------
// Response projections (explicit, closed)
// ---------------------------------------------------------------------------

/// One durable attempt as rendered on the admin surface. Every field is copied
/// explicitly from [`StoredPaymentAttempt`]; amounts keep their stored
/// representation verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AdminPaymentAttempt {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) project_id: Option<String>,
    pub(crate) workspace_id: Option<String>,
    pub(crate) run_id: Option<String>,
    pub(crate) worker_id: Option<String>,
    pub(crate) request_id: Option<String>,
    pub(crate) trace_id: Option<String>,
    pub(crate) method: String,
    pub(crate) resource_url: String,
    pub(crate) request_body_hash: Option<String>,
    pub(crate) challenge_hash: String,
    pub(crate) x402_version: i64,
    pub(crate) scheme: String,
    pub(crate) network_caip2: String,
    pub(crate) mint: String,
    /// ORIGINAL on-chain atomic units, canonical decimal string. Never a number:
    /// the full `u64` range does not survive JSON's double.
    pub(crate) atomic_amount: String,
    pub(crate) recipient: String,
    pub(crate) credits_amount: Option<i64>,
    pub(crate) conversion_version: Option<String>,
    pub(crate) policy_revision: i64,
    pub(crate) decision: String,
    pub(crate) reason_code: String,
    pub(crate) hold_id: Option<String>,
    pub(crate) state: String,
    /// Monotonic CAS operation token. Exposed so an operator comparing two reads
    /// can tell "unchanged" from "re-driven".
    pub(crate) generation: i64,
    pub(crate) submitted_at_unix: Option<i64>,
    pub(crate) transaction_signature: Option<String>,
    pub(crate) settled_atomic_amount: Option<String>,
    pub(crate) settlement_response: Option<String>,
    pub(crate) failure_code: Option<String>,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

/// The linked wallet hold, reported exactly as stored.
///
/// `status` and `expires_at_unix` are both carried because available balance
/// already ignores a hold past its expiry: a row can read `active` while no
/// longer counting against the wallet. Nothing is recomputed here — the
/// operator gets both facts and the scheduled orphan sweep
/// (`AppState::sweep_orphaned_x402_holds`) is what converges `status` for holds
/// no attempt owns, rather than the read surface papering over a stale row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AdminPaymentAttemptReservation {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) amount_credits: i64,
    pub(crate) status: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) settlement_id: Option<String>,
    pub(crate) created_at_unix: i64,
    pub(crate) updated_at_unix: i64,
}

/// The captured wallet settlement (the ledger charge this attempt produced).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AdminPaymentAttemptSettlement {
    pub(crate) object: &'static str,
    pub(crate) id: String,
    pub(crate) tenant_id: String,
    pub(crate) delta_credits: i64,
    pub(crate) balance_after_credits: Option<i64>,
    pub(crate) created_at_unix: i64,
}

/// The join an operator needs under incident pressure: what was attempted, what
/// is held, and what was charged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AdminPaymentAttemptLinks {
    pub(crate) object: &'static str,
    pub(crate) attempt: AdminPaymentAttempt,
    /// `None` when the attempt records no hold (a denied attempt) or the hold
    /// row is gone.
    pub(crate) reservation: Option<AdminPaymentAttemptReservation>,
    /// `None` until the hold is captured.
    pub(crate) settlement: Option<AdminPaymentAttemptSettlement>,
}

/// One bounded page. `next_cursor` is `None` at the definitive end of the
/// listing; a client pages by feeding it back as `?cursor=`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AdminPaymentAttemptPage {
    pub(crate) object: &'static str,
    pub(crate) data: Vec<AdminPaymentAttempt>,
    /// The limit actually applied, which may be lower than the one requested
    /// (it is clamped). Echoed so a caller can see the bound it got.
    pub(crate) limit: usize,
    pub(crate) next_cursor: Option<String>,
}

pub(crate) fn admin_payment_attempt(attempt: &StoredPaymentAttempt) -> AdminPaymentAttempt {
    AdminPaymentAttempt {
        object: "payment_attempt",
        id: attempt.id.clone(),
        tenant_id: attempt.tenant_id.clone(),
        project_id: attempt.project_id.clone(),
        workspace_id: attempt.workspace_id.clone(),
        run_id: attempt.run_id.clone(),
        worker_id: attempt.worker_id.clone(),
        request_id: attempt.request_id.clone(),
        trace_id: attempt.trace_id.clone(),
        method: attempt.method.clone(),
        resource_url: attempt.resource_url.clone(),
        request_body_hash: attempt.request_body_hash.clone(),
        challenge_hash: attempt.challenge_hash.clone(),
        x402_version: attempt.x402_version,
        scheme: attempt.scheme.clone(),
        network_caip2: attempt.network_caip2.clone(),
        mint: attempt.mint.clone(),
        atomic_amount: attempt.atomic_amount.clone(),
        recipient: attempt.recipient.clone(),
        credits_amount: attempt.credits_amount,
        conversion_version: attempt.conversion_version.clone(),
        policy_revision: attempt.policy_revision,
        decision: attempt.decision.clone(),
        reason_code: attempt.reason_code.clone(),
        hold_id: attempt.hold_id.clone(),
        state: attempt.state.clone(),
        generation: attempt.generation,
        submitted_at_unix: attempt.submitted_at_unix,
        transaction_signature: attempt.transaction_signature.clone(),
        settled_atomic_amount: attempt.settled_atomic_amount.clone(),
        settlement_response: attempt.settlement_response.clone(),
        failure_code: attempt.failure_code.clone(),
        created_at_unix: attempt.created_at_unix,
        updated_at_unix: attempt.updated_at_unix,
    }
}

fn admin_reservation(reservation: &StoredWalletReservation) -> AdminPaymentAttemptReservation {
    AdminPaymentAttemptReservation {
        object: "wallet_reservation",
        id: reservation.id.clone(),
        tenant_id: reservation.tenant_id.clone(),
        amount_credits: reservation.amount_credits,
        status: reservation.status.clone(),
        expires_at_unix: reservation.expires_at_unix,
        settlement_id: reservation.settlement_id.clone(),
        created_at_unix: reservation.created_at_unix,
        updated_at_unix: reservation.updated_at_unix,
    }
}

fn admin_settlement(settlement: &StoredWalletSettlement) -> AdminPaymentAttemptSettlement {
    AdminPaymentAttemptSettlement {
        object: "wallet_settlement",
        id: settlement.id.clone(),
        tenant_id: settlement.tenant_id.clone(),
        delta_credits: settlement.delta_credits,
        balance_after_credits: settlement.balance_after_credits,
        created_at_unix: settlement.created_at_unix,
    }
}

pub(crate) fn admin_payment_attempt_links(links: &PaymentAttemptLinks) -> AdminPaymentAttemptLinks {
    AdminPaymentAttemptLinks {
        object: "payment_attempt_links",
        attempt: admin_payment_attempt(&links.attempt),
        reservation: links.reservation.as_ref().map(admin_reservation),
        settlement: links.settlement.as_ref().map(admin_settlement),
    }
}

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

/// Why a listing query could not be turned into a bounded page request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PaymentAttemptQueryError {
    /// `tenant_id` absent or blank. Required: an admin listing with no tenant
    /// would be a cross-tenant scan.
    MissingTenant,
    /// `limit` present but not a positive integer. Refused rather than silently
    /// defaulted, so a caller sending `limit=abc` learns its paging is wrong
    /// instead of quietly receiving a different page size than it asked for.
    InvalidLimit(String),
    /// `cursor` present but not a `<created_at_unix>:<id>` pair. Refused rather
    /// than treated as "start from the beginning", which would make a paging
    /// client loop forever over page one.
    InvalidCursor(String),
}

impl PaymentAttemptQueryError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::MissingTenant => "invalid_query",
            Self::InvalidLimit(_) | Self::InvalidCursor(_) => "invalid_pagination",
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::MissingTenant => "query parameter tenant_id is required".to_string(),
            Self::InvalidLimit(raw) => format!(
                "query parameter limit must be a positive integer (max {PAYMENT_ATTEMPT_PAGE_MAX_LIMIT}), got {raw:?}"
            ),
            Self::InvalidCursor(raw) => format!(
                "query parameter cursor must be an opaque next_cursor returned by this endpoint, got {raw:?}"
            ),
        }
    }
}

/// Parses `?tenant_id=…&limit=…&cursor=…` into a tenant plus a BOUNDED page
/// request.
///
/// The bound is structural, not advisory: an omitted `limit` becomes
/// [`PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT`] and an oversized one is clamped by
/// [`PaymentAttemptQuery::new`] to [`PAYMENT_ATTEMPT_PAGE_MAX_LIMIT`]. There is
/// no "all rows" spelling — `payment_attempts` grows one row per paid egress
/// request, so an unbounded listing behind this endpoint would be a one-request
/// DoS on the admin plane.
///
/// Split out of the handler so it is reachable without a live `Session`: paging
/// arithmetic nobody can call in a test is paging arithmetic nobody can prove.
pub(crate) fn page_query(
    query: Option<&str>,
) -> Result<(String, PaymentAttemptQuery), PaymentAttemptQueryError> {
    let tenant_id =
        query_value(query, "tenant_id").ok_or(PaymentAttemptQueryError::MissingTenant)?;
    let limit = match query_value(query, "limit") {
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|limit| *limit > 0)
            .ok_or(PaymentAttemptQueryError::InvalidLimit(raw))?,
        None => PAYMENT_ATTEMPT_PAGE_DEFAULT_LIMIT,
    };
    let mut page = PaymentAttemptQuery::new(limit);
    if let Some(raw) = query_value(query, "cursor") {
        let cursor = PaymentAttemptCursor::decode(&raw)
            .ok_or(PaymentAttemptQueryError::InvalidCursor(raw))?;
        page = page.after(cursor);
    }
    Ok((tenant_id, page))
}

impl FerroGateway {
    /// Dispatches the two read-only payment-attempt operations.
    pub(super) async fn handle_admin_payment_attempts(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        if *method != Method::GET {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "payment attempts are read-only and support GET",
                &ctx.request_id,
            )
            .await;
        }
        if path == "/admin/v1/payment-attempts" {
            return self
                .handle_payment_attempt_list(session, ctx, headers, query)
                .await;
        }
        let Some(id) = path
            .strip_prefix("/admin/v1/payment-attempts/")
            .filter(|id| !id.is_empty() && !id.contains('/'))
        else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "payment attempt endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        self.handle_payment_attempt_get(session, ctx, headers, id, query)
            .await
    }

    /// `GET /admin/v1/payment-attempts?tenant_id=…&limit=…&cursor=…`.
    async fn handle_payment_attempt_list(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        query: Option<&str>,
    ) -> PingoraResult<()> {
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
                .await
            }
        };
        let (tenant_id, page) = match page_query(query) {
            Ok(parsed) => parsed,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    error.code(),
                    error.message(),
                    &ctx.request_id,
                )
                .await
            }
        };
        if let Err(error) = authorize_tenant_scope(&auth, &tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        match state.list_payment_attempts(&tenant_id, &page).await {
            Ok(result) => {
                let body = AdminPaymentAttemptPage {
                    object: "list",
                    data: result.attempts.iter().map(admin_payment_attempt).collect(),
                    limit: page.limit(),
                    next_cursor: result
                        .next_cursor
                        .as_ref()
                        .map(PaymentAttemptCursor::encode),
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

    /// `GET /admin/v1/payment-attempts/{id}` — attempt + reservation +
    /// settlement.
    ///
    /// Tenancy resolution, and why it fails closed both ways:
    ///
    /// * A tenant-scoped caller is scoped by its OWN tenant unless it names one
    ///   explicitly. Its read therefore goes through the storage predicate
    ///   `id = $1 AND tenant_id = $2`, so another tenant's attempt is
    ///   indistinguishable from a missing one and comes back `404` — the
    ///   existence of another tenant's payment is not disclosed.
    /// * A caller that explicitly names a tenant it does not own gets `403` from
    ///   `authorize_tenant_scope`, before any read runs.
    /// * A platform operator with no tenant of its own and no `tenant_id`
    ///   parameter has the owner resolved from the attempt itself. That lookup
    ///   is unfiltered by construction, which is exactly why it is reachable
    ///   only when the caller has no tenant scope to widen.
    async fn handle_payment_attempt_get(
        &self,
        session: &mut Session,
        ctx: &ProxyContext,
        headers: &http::HeaderMap,
        id: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
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
                .await
            }
        };
        // #515: the fallback is the caller's OWN tenant, and only a declared
        // platform operator may leave it unset and reach the "resolve the owner
        // from the attempt" arm below (which spans every tenant). Defaulting
        // from `organization_id` handed that arm to any credential that simply
        // never named a tenant.
        let requested_tenant =
            query_value(query, "tenant_id").or_else(|| auth.tenant_filter().map(ToOwned::to_owned));
        let tenant_id = match requested_tenant {
            Some(tenant_id) => {
                if let Err(error) = authorize_tenant_scope(&auth, &tenant_id) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                tenant_id
            }
            // Platform operator, no tenant named: resolve the owner from the
            // attempt. `None` here is a genuinely missing attempt.
            None => match state.payment_attempt_owner_tenant(id).await {
                Ok(Some(tenant_id)) => tenant_id,
                Ok(None) => return payment_attempt_not_found(session, ctx, id).await,
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "storage_unavailable",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await
                }
            },
        };
        match state.get_payment_attempt_links(id, &tenant_id).await {
            Ok(Some(links)) => {
                let body = admin_payment_attempt_links(&links);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(None) => payment_attempt_not_found(session, ctx, id).await,
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

/// The single `404` body. One spelling for "no such attempt" and "not yours", so
/// the two are indistinguishable to the caller.
async fn payment_attempt_not_found(
    session: &mut Session,
    ctx: &ProxyContext,
    id: &str,
) -> PingoraResult<()> {
    write_json_error(
        session,
        StatusCode::NOT_FOUND,
        "payment_attempt_not_found",
        format!("no payment attempt with id {id}"),
        &ctx.request_id,
    )
    .await
}

#[cfg(test)]
#[path = "payment_attempts_test.rs"]
mod payment_attempts_test;
