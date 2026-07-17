// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Admin management surface for prepaid-credit wallets and
// payment methods (issue #169): /admin/v1/wallets, /admin/v1/payment-methods.
// A wallet's balance only ever changes through the dedicated `/adjust`
// endpoint (atomic `balance_credits += delta`, never a blind overwrite
// through the general PATCH path) -- see `AdminWalletAdjustRequest`.

use http::{Method, StatusCode};
use pingora::{proxy::Session, Result as PingoraResult};
use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_storage::StoredPaymentMethod;

use super::body::read_request_body;
use super::local::admin_audit_event_draft_for_target;
use super::FerroGateway;
use crate::{
    auth::authenticate,
    responses::{
        write_json_error, write_json_error_and_close, write_json_response, AdminDeleteResponse,
        AdminList, AdminPaymentMethod, AdminPaymentMethodCreateRequest,
        AdminPaymentMethodMutationResponse, AdminWallet, AdminWalletAdjustRequest,
        AdminWalletMutation, AdminWalletMutationResponse,
    },
};

const MAX_BODY_BYTES: usize = 16 * 1024;

impl FerroGateway {
    pub(super) async fn handle_admin_wallets(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/wallets" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(auth) => match state.list_wallets().await {
                        Ok(wallets) => {
                            let wallets =
                                crate::auth::filter_by_tenant_scope(&auth, wallets, |wallet| {
                                    wallet.tenant_id.as_str()
                                });
                            let body = AdminList::new(wallets.iter().map(admin_wallet).collect());
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
                Method::POST => self.handle_admin_wallet_create(session, ctx, headers).await,
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "wallets collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(rest) = path.strip_prefix("/admin/v1/wallets/") else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "wallet endpoint not found",
                &ctx.request_id,
            )
            .await;
        };
        if let Some(tenant_id) = rest.strip_suffix("/adjust") {
            if tenant_id.is_empty() {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "wallet endpoint not found",
                    &ctx.request_id,
                )
                .await;
            }
            return self
                .handle_admin_wallet_adjust(session, ctx, headers, method, tenant_id)
                .await;
        }
        if let Some(tenant_id) = rest.strip_suffix("/charge") {
            if tenant_id.is_empty() {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "wallet endpoint not found",
                    &ctx.request_id,
                )
                .await;
            }
            return self
                .handle_admin_wallet_charge(session, ctx, headers, method, tenant_id)
                .await;
        }
        if let Some(tenant_id) = rest.strip_suffix("/ledger") {
            if tenant_id.is_empty() {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "wallet endpoint not found",
                    &ctx.request_id,
                )
                .await;
            }
            return self
                .handle_admin_wallet_ledger(session, ctx, headers, method, tenant_id)
                .await;
        }
        let tenant_id = rest;
        if tenant_id.is_empty() {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "wallet endpoint not found",
                &ctx.request_id,
            )
            .await;
        }

        match *method {
            Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                Ok(auth) => {
                    if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                        return write_json_error(
                            session,
                            error.status,
                            error.code,
                            error.message,
                            &ctx.request_id,
                        )
                        .await;
                    }
                    match state.get_wallet(tenant_id).await {
                        Ok(Some(wallet)) => {
                            let body = AdminWalletMutationResponse {
                                object: "wallet",
                                wallet: admin_wallet(&wallet),
                            };
                            write_json_response(session, StatusCode::OK, &body, &ctx.request_id)
                                .await
                        }
                        Ok(None) => {
                            write_json_error(
                                session,
                                StatusCode::NOT_FOUND,
                                "wallet_not_found",
                                format!("no wallet for tenant {tenant_id}"),
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
            Method::PATCH => {
                self.handle_admin_wallet_configure(session, ctx, headers, tenant_id)
                    .await
            }
            _ => {
                write_json_error(
                    session,
                    StatusCode::METHOD_NOT_ALLOWED,
                    "method_not_allowed",
                    "wallet endpoint supports GET and PATCH",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_wallet_create(
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
        let payload = match read_json_body::<AdminWalletMutation>(session, &ctx.request_id).await? {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(tenant_id) = payload
            .tenant_id
            .clone()
            .filter(|tenant_id| !tenant_id.trim().is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet",
                "field tenant_id is required",
                &ctx.request_id,
            )
            .await;
        };
        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, &tenant_id) {
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
                StatusCode::BAD_REQUEST,
                "invalid_wallet",
                format!("tenant {tenant_id} does not exist"),
                &ctx.request_id,
            )
            .await;
        }
        if state.get_wallet(&tenant_id).await.ok().flatten().is_some() {
            return write_json_error(
                session,
                StatusCode::CONFLICT,
                "wallet_already_exists",
                format!(
                    "tenant {tenant_id} already has a wallet; use PATCH /admin/v1/wallets/{tenant_id} to reconfigure it or POST /admin/v1/wallets/{tenant_id}/adjust to change its balance"
                ),
                &ctx.request_id,
            )
            .await;
        }
        if let Err(error) = validate_auto_recharge(&payload) {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet",
                error,
                &ctx.request_id,
            )
            .await;
        }
        let now = now_unix_seconds();
        let wallet = ferrogate_storage::StoredWallet {
            id: tenant_id.clone(),
            tenant_id: tenant_id.clone(),
            balance_credits: 0,
            auto_recharge_threshold_credits: payload.auto_recharge_threshold_credits,
            auto_recharge_amount_credits: payload.auto_recharge_amount_credits,
            dunning: false,
            created_at_unix: now,
            updated_at_unix: now,
        };
        self.upsert_wallet_and_respond(session, ctx, &state, &auth, wallet, StatusCode::CREATED)
            .await
    }

    async fn handle_admin_wallet_configure(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        tenant_id: &str,
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
        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload = match read_json_body::<AdminWalletMutation>(session, &ctx.request_id).await? {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(existing) = state.get_wallet(tenant_id).await.ok().flatten() else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "wallet_not_found",
                format!("no wallet for tenant {tenant_id}"),
                &ctx.request_id,
            )
            .await;
        };
        if let Err(error) = validate_auto_recharge(&payload) {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet",
                error,
                &ctx.request_id,
            )
            .await;
        }
        let wallet = ferrogate_storage::StoredWallet {
            auto_recharge_threshold_credits: payload
                .auto_recharge_threshold_credits
                .or(existing.auto_recharge_threshold_credits),
            auto_recharge_amount_credits: payload
                .auto_recharge_amount_credits
                .or(existing.auto_recharge_amount_credits),
            updated_at_unix: now_unix_seconds(),
            ..existing
        };
        self.upsert_wallet_and_respond(session, ctx, &state, &auth, wallet, StatusCode::OK)
            .await
    }

    async fn handle_admin_wallet_adjust(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant_id: &str,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "wallet adjust endpoint supports POST",
                &ctx.request_id,
            )
            .await;
        }
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
        // `/adjust` mints prepaid balance out of thin air (no charge, no
        // invoice obligation -- see the `.._charge` sibling for the paid,
        // tenant-safe top-up path). A tenant-scoped `admin.write` key --
        // exactly what every admin-console login provisions for its own
        // tenant -- would otherwise pass `authorize_tenant_scope` (own
        // tenant == target) and self-credit an unlimited balance, defeating
        // `wallet_balance_exhausted` and yielding unlimited free inference.
        // Restrict the free-credit primitive to platform operators, matching
        // the documented "operator-issued balance correction" intent and the
        // sibling privileged mutations.
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
        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload =
            match read_json_body::<AdminWalletAdjustRequest>(session, &ctx.request_id).await? {
                Ok(payload) => payload,
                Err(()) => return Ok(()),
            };
        if payload.delta_credits == 0 {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet_adjustment",
                "field delta_credits must be nonzero",
                &ctx.request_id,
            )
            .await;
        }
        match state
            .adjust_wallet_balance(tenant_id, payload.delta_credits)
            .await
        {
            Ok(Some(wallet)) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "wallet.adjust",
                    tenant_id,
                    "committed",
                    format!(
                        "wallet for tenant {tenant_id} adjusted by {} credits (new balance {})",
                        payload.delta_credits, wallet.balance_credits
                    ),
                ));
                let body = AdminWalletMutationResponse {
                    object: "wallet",
                    wallet: admin_wallet(&wallet),
                };
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
            }
            Ok(None) => {
                write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "wallet_not_found",
                    format!("no wallet for tenant {tenant_id}"),
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

    /// Triggers a real payment-provider charge and, on success, credits
    /// the wallet with the resulting amount (issue #169) -- the
    /// end-to-end "top up via Stripe" path, distinct from
    /// `handle_admin_wallet_adjust`'s operator-issued balance correction.
    /// Requires `FERROGATE_STRIPE_SECRET_KEY` to be set; without it this
    /// returns 503 rather than silently no-op'ing, since a caller
    /// expecting a real charge to have happened must never be told it
    /// succeeded when it didn't run at all.
    async fn handle_admin_wallet_charge(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        tenant_id: &str,
    ) -> PingoraResult<()> {
        if *method != Method::POST {
            return write_json_error(
                session,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "wallet charge endpoint supports POST",
                &ctx.request_id,
            )
            .await;
        }
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
        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let payload = match read_json_body::<crate::responses::AdminWalletChargeRequest>(
            session,
            &ctx.request_id,
        )
        .await?
        {
            Ok(payload) => payload,
            Err(()) => return Ok(()),
        };
        let Some(amount_usd_cents) = payload.amount_usd_cents.filter(|amount| *amount > 0) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet_charge",
                "field amount_usd_cents is required and must be positive",
                &ctx.request_id,
            )
            .await;
        };
        if state.get_wallet(tenant_id).await.ok().flatten().is_none() {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "wallet_not_found",
                format!("no wallet for tenant {tenant_id}"),
                &ctx.request_id,
            )
            .await;
        }
        let payment_method = match payload.payment_method_id {
            Some(id) => state
                .list_payment_methods(tenant_id)
                .await
                .ok()
                .and_then(|methods| methods.into_iter().find(|method| method.id == id)),
            None => state
                .list_payment_methods(tenant_id)
                .await
                .ok()
                .and_then(|methods| methods.into_iter().find(|method| method.is_default)),
        };
        let Some(payment_method) = payment_method else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_wallet_charge",
                format!("tenant {tenant_id} has no matching payment method on file"),
                &ctx.request_id,
            )
            .await;
        };
        let Ok(secret_key) = std::env::var("FERROGATE_STRIPE_SECRET_KEY") else {
            return write_json_error(
                session,
                StatusCode::SERVICE_UNAVAILABLE,
                "payment_provider_not_configured",
                "FERROGATE_STRIPE_SECRET_KEY is not set; no payment provider is configured",
                &ctx.request_id,
            )
            .await;
        };
        let adapter = super::payments::StripePaymentProviderAdapter::new(secret_key);
        let idempotency_key = format!("wallet-charge:{}", ctx.request_id);
        let outcome = match super::payments::PaymentProviderAdapter::charge(
            &adapter,
            &payment_method.provider_customer_id,
            &payment_method.provider_payment_method_id,
            amount_usd_cents,
            &idempotency_key,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                return write_json_error(
                    session,
                    StatusCode::BAD_GATEWAY,
                    "payment_provider_error",
                    error.to_string(),
                    &ctx.request_id,
                )
                .await;
            }
        };
        if outcome.succeeded {
            // amount_usd_cents -> credits: $1 = 100 cents =
            // DEFAULT_CREDITS_PER_USD credits, so 1 cent =
            // DEFAULT_CREDITS_PER_USD / 100 credits.
            let credited = (amount_usd_cents as f64
                * (ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD / 100.0))
                .round() as i64;
            let _ = state.set_wallet_dunning(tenant_id, false).await;
            match state.adjust_wallet_balance(tenant_id, credited).await {
                Ok(Some(wallet)) => {
                    state.record_admin_audit_event(admin_audit_event_draft_for_target(
                        ctx,
                        &auth,
                        "wallet.charge",
                        tenant_id,
                        "committed",
                        format!(
                            "wallet for tenant {tenant_id} charged {amount_usd_cents} cents via stripe, credited {credited} credits"
                        ),
                    ));
                    let body = crate::responses::AdminWalletChargeResponse {
                        object: "wallet_charge",
                        succeeded: true,
                        provider_charge_id: outcome.provider_charge_id,
                        decline_reason: None,
                        wallet: admin_wallet(&wallet),
                    };
                    write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                }
                Ok(None) => {
                    write_json_error(
                        session,
                        StatusCode::NOT_FOUND,
                        "wallet_not_found",
                        format!("no wallet for tenant {tenant_id}"),
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
        } else {
            // A declined charge leaves the tenant in a visible dunning
            // state rather than either silently blocking all traffic or
            // silently granting unlimited credit.
            let _ = state.set_wallet_dunning(tenant_id, true).await;
            state.record_admin_audit_event(admin_audit_event_draft_for_target(
                ctx,
                &auth,
                "wallet.charge",
                tenant_id,
                "declined",
                format!(
                    "wallet charge for tenant {tenant_id} declined: {}",
                    outcome.decline_reason.clone().unwrap_or_default()
                ),
            ));
            let wallet = state
                .get_wallet(tenant_id)
                .await
                .ok()
                .flatten()
                .map(|wallet| admin_wallet(&wallet));
            let Some(wallet) = wallet else {
                return write_json_error(
                    session,
                    StatusCode::NOT_FOUND,
                    "wallet_not_found",
                    format!("no wallet for tenant {tenant_id}"),
                    &ctx.request_id,
                )
                .await;
            };
            let body = crate::responses::AdminWalletChargeResponse {
                object: "wallet_charge",
                succeeded: false,
                provider_charge_id: outcome.provider_charge_id,
                decline_reason: outcome.decline_reason,
                wallet,
            };
            write_json_response(
                session,
                StatusCode::PAYMENT_REQUIRED,
                &body,
                &ctx.request_id,
            )
            .await
        }
    }

    /// Wallet transaction ledger (issue #169): every recorded balance
    /// change for `tenant_id` -- manual adjustments and live charges from
    /// this file's own handlers, plus settlement debits and auto-recharge
    /// attempts recorded from `state.rs`'s background settlement path.
    /// Read-only, so `admin.read` rather than `admin.write`.
    async fn handle_admin_wallet_ledger(
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
                "wallet ledger endpoint supports GET",
                &ctx.request_id,
            )
            .await;
        }
        let state = self.state.current();
        match authenticate(&state, headers, "admin.read", &ctx.request_id) {
            Ok(auth) => {
                if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                    return write_json_error(
                        session,
                        error.status,
                        error.code,
                        error.message,
                        &ctx.request_id,
                    )
                    .await;
                }
                let events = state.wallet_ledger_events(tenant_id);
                let body = AdminList::new(events);
                write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
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

    async fn upsert_wallet_and_respond(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        state: &crate::state::AppState,
        auth: &crate::auth::AuthContext,
        wallet: ferrogate_storage::StoredWallet,
        success_status: StatusCode,
    ) -> PingoraResult<()> {
        let tenant_id = wallet.tenant_id.clone();
        match state.upsert_wallet(wallet.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    auth,
                    "wallet.upsert",
                    &tenant_id,
                    "committed",
                    format!("wallet for tenant {tenant_id} upserted"),
                ));
                let body = AdminWalletMutationResponse {
                    object: "wallet",
                    wallet: admin_wallet(&wallet),
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

    pub(super) async fn handle_admin_payment_methods(
        &self,
        session: &mut Session,
        ctx: &super::ProxyContext,
        headers: &http::HeaderMap,
        method: &Method,
        path: &str,
        query: Option<&str>,
    ) -> PingoraResult<()> {
        let state = self.state.current();

        if path == "/admin/v1/payment-methods" {
            return match *method {
                Method::GET => match authenticate(&state, headers, "admin.read", &ctx.request_id) {
                    Ok(auth) => {
                        let Some(tenant_id) = query
                            .and_then(|query| {
                                query
                                    .split('&')
                                    .find_map(|pair| pair.strip_prefix("tenant_id="))
                            })
                            .filter(|tenant_id| !tenant_id.is_empty())
                        else {
                            return write_json_error(
                                session,
                                StatusCode::BAD_REQUEST,
                                "invalid_query",
                                "query parameter tenant_id is required",
                                &ctx.request_id,
                            )
                            .await;
                        };
                        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, tenant_id) {
                            return write_json_error(
                                session,
                                error.status,
                                error.code,
                                error.message,
                                &ctx.request_id,
                            )
                            .await;
                        }
                        match state.list_payment_methods(tenant_id).await {
                            Ok(payment_methods) => {
                                let body = AdminList::new(
                                    payment_methods.iter().map(admin_payment_method).collect(),
                                );
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
                Method::POST => {
                    self.handle_admin_payment_method_create(session, ctx, headers)
                        .await
                }
                _ => {
                    write_json_error(
                        session,
                        StatusCode::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        "payment methods collection supports GET and POST",
                        &ctx.request_id,
                    )
                    .await
                }
            };
        }

        let Some(id) = path
            .strip_prefix("/admin/v1/payment-methods/")
            .filter(|id| !id.is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::NOT_FOUND,
                "not_found",
                "payment method endpoint not found",
                &ctx.request_id,
            )
            .await;
        };

        match *method {
            Method::DELETE => {
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
                // Issue #185: the id alone doesn't reveal which tenant owns
                // this payment method, so it must be looked up before the
                // tenant-ownership check can run -- unlike every other
                // handler here, where the tenant_id is already known from
                // the path/query/body.
                match state.get_payment_method(id).await {
                    Ok(Some(existing)) => {
                        if let Err(error) =
                            crate::auth::authorize_tenant_scope(&auth, &existing.tenant_id)
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
                    Ok(None) => {
                        return write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "payment_method_not_found",
                            format!("no payment method with id {id}"),
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
                }
                match state.delete_payment_method(id).await {
                    Ok(true) => {
                        state.record_admin_audit_event(admin_audit_event_draft_for_target(
                            ctx,
                            &auth,
                            "payment_method.delete",
                            id,
                            "committed",
                            format!("payment method {id} deleted"),
                        ));
                        let body = AdminDeleteResponse {
                            object: "payment_method",
                            id: id.to_string(),
                            deleted: true,
                        };
                        write_json_response(session, StatusCode::OK, &body, &ctx.request_id).await
                    }
                    Ok(false) => {
                        write_json_error(
                            session,
                            StatusCode::NOT_FOUND,
                            "payment_method_not_found",
                            format!("no payment method with id {id}"),
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
                    "payment method endpoint supports DELETE",
                    &ctx.request_id,
                )
                .await
            }
        }
    }

    async fn handle_admin_payment_method_create(
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
            match read_json_body::<AdminPaymentMethodCreateRequest>(session, &ctx.request_id)
                .await?
            {
                Ok(payload) => payload,
                Err(()) => return Ok(()),
            };
        let Some(tenant_id) = payload
            .tenant_id
            .filter(|tenant_id| !tenant_id.trim().is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_payment_method",
                "field tenant_id is required",
                &ctx.request_id,
            )
            .await;
        };
        if let Err(error) = crate::auth::authorize_tenant_scope(&auth, &tenant_id) {
            return write_json_error(
                session,
                error.status,
                error.code,
                error.message,
                &ctx.request_id,
            )
            .await;
        }
        let Some(provider) = payload.provider.filter(|value| !value.trim().is_empty()) else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_payment_method",
                "field provider is required",
                &ctx.request_id,
            )
            .await;
        };
        let Some(provider_payment_method_id) = payload
            .provider_payment_method_id
            .filter(|value| !value.trim().is_empty())
        else {
            return write_json_error(
                session,
                StatusCode::BAD_REQUEST,
                "invalid_payment_method",
                "field provider_payment_method_id is required",
                &ctx.request_id,
            )
            .await;
        };
        let requested_customer_id = payload
            .provider_customer_id
            .filter(|value| !value.trim().is_empty());
        // For Stripe, `provider_payment_method_id` is a client-collected
        // payment-method token (e.g. from Stripe.js) that still needs to
        // be attached to a customer server-side -- when the caller didn't
        // already do that out-of-band and hand us a `provider_customer_id`,
        // create the customer and attach the token here.
        let (provider_customer_id, provider_payment_method_id) = if requested_customer_id.is_none()
            && provider == super::payments::StripePaymentProviderAdapter::PROVIDER_NAME
        {
            let Ok(secret_key) = std::env::var("FERROGATE_STRIPE_SECRET_KEY") else {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_payment_method",
                    "field provider_customer_id is required (FERROGATE_STRIPE_SECRET_KEY \
                         is not set, so a customer can't be created automatically)",
                    &ctx.request_id,
                )
                .await;
            };
            let adapter = super::payments::StripePaymentProviderAdapter::new(secret_key);
            debug_assert_eq!(
                super::payments::PaymentProviderAdapter::provider_name(&adapter),
                provider
            );
            let customer_id = match super::payments::PaymentProviderAdapter::create_customer(
                &adapter, &tenant_id,
            )
            .await
            {
                Ok(id) => id,
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::BAD_GATEWAY,
                        "payment_provider_error",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            };
            match super::payments::PaymentProviderAdapter::attach_payment_method(
                &adapter,
                &customer_id,
                &provider_payment_method_id,
            )
            .await
            {
                Ok(attached_id) => (customer_id, attached_id),
                Err(error) => {
                    return write_json_error(
                        session,
                        StatusCode::BAD_GATEWAY,
                        "payment_provider_error",
                        error.to_string(),
                        &ctx.request_id,
                    )
                    .await;
                }
            }
        } else {
            let Some(provider_customer_id) = requested_customer_id else {
                return write_json_error(
                    session,
                    StatusCode::BAD_REQUEST,
                    "invalid_payment_method",
                    "field provider_customer_id is required",
                    &ctx.request_id,
                )
                .await;
            };
            (provider_customer_id, provider_payment_method_id)
        };
        let payment_method = StoredPaymentMethod {
            id: ferrogate_storage::payment_method_id(
                &tenant_id,
                &provider,
                &provider_payment_method_id,
            ),
            tenant_id,
            provider,
            provider_customer_id,
            provider_payment_method_id,
            is_default: payload.is_default,
            created_at_unix: now_unix_seconds(),
        };
        let id = payment_method.id.clone();
        match state.upsert_payment_method(payment_method.clone()).await {
            Ok(()) => {
                state.record_admin_audit_event(admin_audit_event_draft_for_target(
                    ctx,
                    &auth,
                    "payment_method.upsert",
                    &id,
                    "committed",
                    format!("payment method {id} upserted"),
                ));
                let body = AdminPaymentMethodMutationResponse {
                    object: "payment_method",
                    payment_method: admin_payment_method(&payment_method),
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
}

fn validate_auto_recharge(payload: &AdminWalletMutation) -> Result<(), &'static str> {
    if let Some(threshold) = payload.auto_recharge_threshold_credits {
        if threshold < 0 {
            return Err("field auto_recharge_threshold_credits must not be negative");
        }
    }
    if let Some(amount) = payload.auto_recharge_amount_credits {
        if amount <= 0 {
            return Err("field auto_recharge_amount_credits must be positive");
        }
    }
    Ok(())
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

fn admin_wallet(wallet: &ferrogate_storage::StoredWallet) -> AdminWallet {
    AdminWallet {
        tenant_id: wallet.tenant_id.clone(),
        balance_credits: wallet.balance_credits,
        auto_recharge_threshold_credits: wallet.auto_recharge_threshold_credits,
        auto_recharge_amount_credits: wallet.auto_recharge_amount_credits,
        dunning: wallet.dunning,
        created_at_unix: wallet.created_at_unix,
        updated_at_unix: wallet.updated_at_unix,
    }
}

fn admin_payment_method(payment_method: &StoredPaymentMethod) -> AdminPaymentMethod {
    AdminPaymentMethod {
        id: payment_method.id.clone(),
        tenant_id: payment_method.tenant_id.clone(),
        provider: payment_method.provider.clone(),
        provider_customer_id: payment_method.provider_customer_id.clone(),
        provider_payment_method_id: payment_method.provider_payment_method_id.clone(),
        is_default: payment_method.is_default,
        created_at_unix: payment_method.created_at_unix,
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
