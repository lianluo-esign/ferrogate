// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: AppState methods for prepaid-credit wallets (issue #169) --
// CRUD, payment methods, budget/debit settlement, ledger, and
// auto-recharge.

use super::*;

/// The result of one `AppState::debit_wallet_for_settled_cost` call
/// (issue #169): threaded into the `BillingEvent` the caller is about to
/// build so it can be mirrored, not recomputed, in the standalone billing
/// service's ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WalletDebitOutcome {
    pub(crate) delta_credits: i64,
    pub(crate) balance_after_credits: i64,
}

impl AppState {
    pub(crate) async fn list_wallets(&self) -> anyhow::Result<Vec<StoredWallet>> {
        Ok(self.repositories.list_wallets().await?)
    }

    pub(crate) async fn get_wallet(&self, tenant_id: &str) -> anyhow::Result<Option<StoredWallet>> {
        Ok(self.repositories.get_wallet(tenant_id).await?)
    }

    pub(crate) async fn upsert_wallet(&self, wallet: StoredWallet) -> anyhow::Result<()> {
        Ok(self.repositories.upsert_wallet(wallet).await?)
    }

    pub(crate) async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
    ) -> anyhow::Result<Option<StoredWallet>> {
        let now = now_unix_seconds().unwrap_or_default() as i64;
        Ok(self
            .repositories
            .adjust_wallet_balance(tenant_id, delta_credits, now)
            .await?)
    }

    pub(crate) async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
    ) -> anyhow::Result<()> {
        let now = now_unix_seconds().unwrap_or_default() as i64;
        Ok(self
            .repositories
            .set_wallet_dunning(tenant_id, dunning, now)
            .await?)
    }

    pub(crate) async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<StoredPaymentMethod>> {
        Ok(self.repositories.list_payment_methods(tenant_id).await?)
    }

    pub(crate) async fn get_payment_method(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<StoredPaymentMethod>> {
        Ok(self.repositories.get_payment_method(id).await?)
    }

    pub(crate) async fn upsert_payment_method(
        &self,
        payment_method: StoredPaymentMethod,
    ) -> anyhow::Result<()> {
        Ok(self
            .repositories
            .upsert_payment_method(payment_method)
            .await?)
    }

    pub(crate) async fn delete_payment_method(&self, id: &str) -> anyhow::Result<bool> {
        Ok(self.repositories.delete_payment_method(id).await?)
    }
    /// The current UTC calendar month in `YYYY-MM` form, for monthly-budget
    /// checks and default report windows.
    pub(crate) fn current_period_month(&self) -> String {
        ferrogate_storage::period_month_from_unix(now_unix_seconds().unwrap_or_default() as i64)
    }

    /// Checks a P1-3 `EffectiveQuota.monthly_budget_usd` cap (the tightest
    /// budget defined anywhere in the tenant/project/workspace/key chain)
    /// against real accumulated spend for the current calendar month,
    /// closing the loop P1-3 deferred to P1-4.
    ///
    /// `budget_scope` is the scope whose `monthly_budget_usd` won the chain's
    /// `min` (recorded by `resolve_effective_quota`). Spend is measured
    /// against THAT scope's aggregate monthly rollup, so a tenant/project/
    /// workspace budget is enforced across every key under it, not counted
    /// per key -- which would let N keys each spend the full cap. When the
    /// winning scope is the key, this is exactly the key's own spend, so
    /// per-key budgets are unchanged. `None` (a budget with no recorded
    /// scope, e.g. a legacy caller) falls back to the pre-fix behavior of
    /// checking the most specific attributed scope.
    pub(crate) fn monthly_budget_exceeded(
        &self,
        tenant: &ferrogate_core::TenantContext,
        budget_scope: Option<&ferrogate_policy::QuotaScopeSelector>,
        budget_usd: f64,
    ) -> anyhow::Result<bool> {
        let Some((scope_type, scope_id)) = budget_scope
            .map(|scope| (scope.kind, scope.id.as_str()))
            .or_else(|| {
                [
                    (QuotaScopeKind::Key, tenant.api_key_id.as_deref()),
                    (QuotaScopeKind::Workspace, tenant.workspace_id.as_deref()),
                    (QuotaScopeKind::Project, tenant.project_id.as_deref()),
                    (QuotaScopeKind::Tenant, tenant.organization_id.as_deref()),
                ]
                .into_iter()
                .find_map(|(scope_type, scope_id)| scope_id.map(|scope_id| (scope_type, scope_id)))
            })
        else {
            // No attribution at all to check spend against; nothing to fail
            // closed on, so let quota model_allowlist/rpm/tpm/disabled checks
            // (which already ran) be the only governance for this request.
            return Ok(false);
        };
        let period_month = self.current_period_month();
        let spent = crate::gateway::block_on_sync_bridge(
            self.repositories
                .get_usage_monthly_rollup(scope_type, scope_id, &period_month),
        )?
        .map(|rollup| rollup.cost_usd)
        .unwrap_or(0.0);
        Ok(spent >= budget_usd)
    }

    /// Prepaid-credit wallet balance check (issue #169), keyed by the
    /// tenant (`organization_id`) alone -- wallets are 1:1 with a tenant,
    /// not scoped per project/workspace/key the way `quota_policies` is.
    /// Opt-in: `Ok(false)` (never denies) both when the request has no
    /// tenant attribution and when the tenant has no wallet row at all,
    /// so this is purely additive for every tenant that hasn't adopted
    /// prepaid billing.
    /// Stays sync (unlike the rest of this file's storage-backed methods)
    /// because its only caller, `auth::finalize_auth`, is itself sync and
    /// shared by ~150 call sites plus a batch of sync `#[test]` fns --
    /// converting the whole `authenticate` chain to async is out of scope
    /// for issue #221's storage migration. Bridges via the same
    /// `block_on_sync_bridge` helper already used for the RBAC permission
    /// check in `gateway/mod.rs` rather than duplicating that pattern.
    pub(crate) fn wallet_balance_exhausted(
        &self,
        tenant: &ferrogate_core::TenantContext,
    ) -> anyhow::Result<bool> {
        let Some(tenant_id) = tenant.organization_id.as_deref() else {
            return Ok(false);
        };
        let Some(wallet) =
            crate::gateway::block_on_sync_bridge(self.repositories.get_wallet(tenant_id))?
        else {
            return Ok(false);
        };
        // Account for credits already held by in-flight requests from this
        // tenant (issue #169 concurrent-overdraft fix), not just the settled
        // balance: once outstanding reservations have consumed the funded
        // balance the wallet is effectively exhausted even though no debit
        // has landed yet, so a fresh request must be rejected here rather
        // than admitted to race the ones already dispatched.
        let reserved = self.cluster_counters.reserved_wallet_credits(tenant_id);
        Ok(wallet.balance_credits.saturating_sub(reserved) <= 0)
    }

    /// Atomically reserve the estimated credit cost of one request against the
    /// tenant's prepaid wallet *before* dispatch (issue #169's
    /// concurrent-overdraft fix). This is the wallet analogue of
    /// [`AppState::try_reserve_api_key_tokens`]: it reads the tenant's funded
    /// balance and asks the shared counter backend to hold `estimated_credits`
    /// against `balance_credits - outstanding_reservations`, so N concurrent
    /// requests can no longer all observe a positive balance and all dispatch.
    ///
    /// Opt-in and purely additive: returns
    /// [`WalletReservationOutcome::NotApplicable`] (never blocks) when the
    /// request has no tenant attribution, the tenant has no wallet row, or the
    /// route is unpriced (a zero estimate that will produce no debit).
    /// Returns [`WalletReservationOutcome::Insufficient`] when a real wallet
    /// cannot cover the estimate, which the caller maps to the same
    /// `wallet_balance_exhausted` denial the pre-request gate raises. The
    /// returned guard releases its hold on drop, so a cancelled or errored
    /// request never leaks a reservation.
    pub(crate) async fn try_reserve_wallet_credits(
        &self,
        tenant: &ferrogate_core::TenantContext,
        estimated_credits: i64,
    ) -> anyhow::Result<WalletReservationOutcome> {
        if estimated_credits <= 0 {
            return Ok(WalletReservationOutcome::NotApplicable);
        }
        let Some(tenant_id) = tenant.organization_id.as_deref() else {
            return Ok(WalletReservationOutcome::NotApplicable);
        };
        let Some(wallet) = self.repositories.get_wallet(tenant_id).await? else {
            return Ok(WalletReservationOutcome::NotApplicable);
        };
        match self.cluster_counters.try_reserve_wallet_credits(
            tenant_id,
            wallet.balance_credits,
            estimated_credits,
        )? {
            Some(reservation) => Ok(WalletReservationOutcome::Reserved(reservation)),
            None => Ok(WalletReservationOutcome::Insufficient),
        }
    }

    /// Debits a settled request's cost from the tenant's wallet, if one
    /// exists (issue #169) -- a no-op (not an error) for the common case
    /// of a tenant that hasn't adopted prepaid billing. Converts
    /// `cost_usd` to credits via the same
    /// `ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD` unit the
    /// standalone billing service's `PriceBook` uses, so "credits" means
    /// the same thing everywhere in the system. Best-effort: a storage
    /// error here is logged and swallowed, matching the budget-alert
    /// webhook's "a bookkeeping side-effect must never fail the
    /// triggering request" precedent (issue #170).
    ///
    /// Returns the debit's outcome (delta + resulting balance) so the
    /// caller can attach it to the `BillingEvent` it's about to build and
    /// carry it through to the standalone billing service's ledger
    /// (issue #169's `GET /v1/billing/ledger` acceptance criterion) --
    /// `None` covers every "nothing happened" case (no cost, no tenant
    /// attribution, no wallet row, or a storage error), matching the
    /// pre-existing best-effort/no-op-by-default semantics exactly.
    pub(crate) async fn debit_wallet_for_settled_cost(
        &self,
        tenant: &ferrogate_core::TenantContext,
        cost_usd: f64,
        settlement_id: &str,
    ) -> Option<WalletDebitOutcome> {
        if cost_usd <= 0.0 {
            return None;
        }
        let tenant_id = tenant.organization_id.as_deref()?;
        let delta_credits =
            -((cost_usd * ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD).round() as i64);
        if delta_credits == 0 {
            return None;
        }
        let now = now_unix_seconds().unwrap_or_default() as i64;
        match self
            .repositories
            .settle_wallet_balance(settlement_id, tenant_id, delta_credits, now)
            .await
        {
            Ok(outcome) => {
                let balance_after_credits = outcome.settlement.balance_after_credits?;
                if outcome.newly_applied {
                    self.record_wallet_ledger_event(
                        tenant_id,
                        "wallet.settle",
                        "debited",
                        format!(
                            "settled request cost ${cost_usd:.6} debited {} credits; balance now {}",
                            -delta_credits, balance_after_credits
                        ),
                    );
                    match self.repositories.get_wallet(tenant_id).await {
                        Ok(Some(wallet)) => self.maybe_trigger_auto_recharge(wallet),
                        Ok(None) => {}
                        Err(error) => warn!(
                            tenant_id = %tenant_id,
                            error = %error,
                            "failed to reload wallet after settlement"
                        ),
                    }
                }
                let outcome = WalletDebitOutcome {
                    delta_credits,
                    balance_after_credits,
                };
                Some(outcome)
            }
            Err(error) => {
                warn!(
                    tenant_id = %tenant_id,
                    settlement_id = %settlement_id,
                    error = %error,
                    "failed to debit tenant wallet for settled request cost"
                );
                None
            }
        }
    }

    /// Records a wallet balance-changing event to the same admin
    /// audit-event log every `/admin/v1/wallets/*` handler already
    /// writes to (issue #169's ledger surfacing) -- specifically so
    /// `GET /admin/v1/wallets/{tenant_id}/ledger` (`wallet_ledger_events`
    /// below) shows a complete transaction history, not just the
    /// operator-initiated ones that happen to go through an admin
    /// handler. Called from background/settlement code paths that have
    /// no live `AuthContext`/`ProxyContext` (unlike
    /// `admin_audit_event_draft_for_target`, which requires both), so
    /// this builds the draft directly with `actor_api_key_id: None` --
    /// the struct itself has no such requirement, only the admin-handler
    /// convenience wrapper does.
    fn record_wallet_ledger_event(
        &self,
        tenant_id: &str,
        action: &'static str,
        outcome: &'static str,
        message: String,
    ) {
        self.record_admin_audit_event(AdminAuditEventDraft {
            request_id: self.next_request_id(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            actor_api_key_id: None,
            tenant: ferrogate_core::TenantContext {
                organization_id: Some(tenant_id.to_string()),
                ..Default::default()
            },
            action: action.to_string(),
            target: tenant_id.to_string(),
            outcome: outcome.to_string(),
            message,
        });
    }

    /// Wallet transaction ledger (issue #169): every `"wallet.*"`-actioned
    /// audit event recorded for `tenant_id` -- manual adjustments and
    /// live charges (both recorded by the `/admin/v1/wallets/*` HTTP
    /// handlers), plus settlement debits and auto-recharge attempts
    /// (recorded via `record_wallet_ledger_event` above). Same
    /// fetch-then-filter-in-Rust pattern `tool_session_events` already
    /// uses for the same audit-event store; unpaginated like that
    /// precedent, since a per-tenant wallet's event volume is expected
    /// to be small relative to the full audit-event table.
    pub(crate) fn wallet_ledger_events(
        &self,
        tenant_id: &str,
    ) -> Vec<ferrogate_storage::StoredAuditEvent> {
        crate::gateway::block_on_sync_bridge(self.repositories.audit_events())
            .into_iter()
            .filter(|event| event.action.starts_with("wallet.") && event.target == tenant_id)
            .collect()
    }

    /// Fires an auto-recharge charge in the background when a debit just
    /// dropped a wallet's balance to or below its configured threshold
    /// (issue #169) -- spawned via `tokio::spawn` rather than awaited
    /// inline, so a slow or unreachable payment provider can never add
    /// latency to (or fail) the request whose settlement triggered it.
    ///
    /// Skips firing when the wallet is already in a dunning state: a
    /// declined charge sets `dunning = true` specifically so this doesn't
    /// hammer the payment provider with a retry on every single
    /// subsequent request while the balance stays below threshold --
    /// recovery requires an operator (or an updated payment method) to
    /// clear the dunning state, at which point the next debit that
    /// crosses the threshold will retry.
    fn maybe_trigger_auto_recharge(&self, wallet: ferrogate_storage::StoredWallet) {
        if wallet.dunning {
            return;
        }
        let Some(threshold) = wallet.auto_recharge_threshold_credits else {
            return;
        };
        if wallet.balance_credits > threshold {
            return;
        }
        let Some(amount_credits) = wallet
            .auto_recharge_amount_credits
            .filter(|amount| *amount > 0)
        else {
            return;
        };
        let state = self.clone();
        tokio::spawn(async move {
            state
                .execute_auto_recharge(&wallet.tenant_id, amount_credits)
                .await;
        });
    }

    /// Executes one auto-recharge attempt (issue #169): resolves the
    /// tenant's default payment method and the configured Stripe secret,
    /// charges `amount_credits` worth of USD, and credits the wallet on
    /// success or marks it `dunning` on failure/decline/misconfiguration.
    /// Async and only ever called via `tokio::spawn` from
    /// `maybe_trigger_auto_recharge` -- never awaited inline on the
    /// request path.
    async fn execute_auto_recharge(&self, tenant_id: &str, amount_credits: i64) {
        use crate::gateway::payments::PaymentProviderAdapter;

        let Ok(secret_key) = std::env::var("FERROGATE_STRIPE_SECRET_KEY") else {
            warn!(
                tenant_id = %tenant_id,
                "auto-recharge threshold crossed but FERROGATE_STRIPE_SECRET_KEY is not set; \
                 marking wallet dunning rather than silently skipping"
            );
            let _ = self.set_wallet_dunning(tenant_id, true).await;
            return;
        };
        let Some(payment_method) = self
            .list_payment_methods(tenant_id)
            .await
            .ok()
            .and_then(|methods| methods.into_iter().find(|method| method.is_default))
        else {
            warn!(
                tenant_id = %tenant_id,
                "auto-recharge threshold crossed but the tenant has no default payment method"
            );
            let _ = self.set_wallet_dunning(tenant_id, true).await;
            return;
        };
        let amount_usd_cents = ((amount_credits as f64)
            / (ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD / 100.0))
            .round() as u64;
        let adapter = crate::gateway::payments::StripePaymentProviderAdapter::new(secret_key);
        let idempotency_key = format!(
            "auto-recharge:{tenant_id}:{}",
            now_unix_seconds().unwrap_or_default()
        );
        let outcome = adapter
            .charge(
                &payment_method.provider_customer_id,
                &payment_method.provider_payment_method_id,
                amount_usd_cents,
                &idempotency_key,
            )
            .await;
        match outcome {
            Ok(outcome) if outcome.succeeded => {
                let _ = self.set_wallet_dunning(tenant_id, false).await;
                // Credit the wallet IDEMPOTENTLY, keyed on the Stripe charge id.
                // The prior `adjust_wallet_balance` was an unconditional
                // `balance += amount` with no dedup, so if two concurrent
                // same-second recharge tasks shared one Stripe idempotency key
                // (Stripe charges the card ONCE and returns the same
                // provider_charge_id to both) each still credited the wallet --
                // netting the tenant free credits. Routing the credit through
                // settle_wallet_balance (which dedups on the settlement id via
                // wallet_settlements, exactly like the debit path) means a
                // duplicated/replayed successful charge credits at most once.
                let credit_settlement_id =
                    format!("auto-recharge-credit:{}", outcome.provider_charge_id);
                let now = now_unix_seconds().unwrap_or_default() as i64;
                match self
                    .repositories
                    .settle_wallet_balance(&credit_settlement_id, tenant_id, amount_credits, now)
                    .await
                {
                    Ok(settlement) if settlement.newly_applied => {
                        self.record_wallet_ledger_event(
                            tenant_id,
                            "wallet.auto_recharge",
                            "committed",
                            format!(
                                "auto-recharge credited {amount_credits} credits \
                                 ({amount_usd_cents} USD cents charged, provider_charge_id={})",
                                outcome.provider_charge_id
                            ),
                        );
                    }
                    Ok(_) => {
                        // A duplicate of an already-credited charge (e.g. a
                        // concurrent same-key recharge): the card was charged
                        // once and credited once; skip the duplicate credit.
                        warn!(
                            tenant_id = %tenant_id,
                            provider_charge_id = %outcome.provider_charge_id,
                            "auto-recharge credit already applied for this charge; skipping duplicate"
                        );
                    }
                    Err(error) => {
                        warn!(
                            tenant_id = %tenant_id,
                            error = %error,
                            "auto-recharge charge succeeded but crediting the wallet failed"
                        );
                    }
                }
            }
            Ok(outcome) => {
                warn!(
                    tenant_id = %tenant_id,
                    decline_reason = ?outcome.decline_reason,
                    "auto-recharge charge was declined"
                );
                let _ = self.set_wallet_dunning(tenant_id, true).await;
                self.record_wallet_ledger_event(
                    tenant_id,
                    "wallet.auto_recharge",
                    "declined",
                    format!(
                        "auto-recharge charge for {amount_credits} credits declined: {}",
                        outcome
                            .decline_reason
                            .as_deref()
                            .unwrap_or("no reason given")
                    ),
                );
            }
            Err(error) => {
                warn!(
                    tenant_id = %tenant_id,
                    error = %error,
                    "auto-recharge charge request failed"
                );
                let _ = self.set_wallet_dunning(tenant_id, true).await;
                self.record_wallet_ledger_event(
                    tenant_id,
                    "wallet.auto_recharge",
                    "error",
                    format!("auto-recharge charge for {amount_credits} credits failed: {error}"),
                );
            }
        }
    }

    /// Best-effort proactive budget-threshold alerting (issue #170): checks
    /// every attributed scope's `StoredQuotaPolicy::alert_threshold_pcts`
    /// against its current-period spend and fires a webhook the first time
    /// each tier is crossed -- strictly before [`Self::monthly_budget_exceeded`]'s
    /// unconditional 100% hard-deny. Unlike that hard-deny (which stops at
    /// the *nearest* attributed scope), every scope in the chain is checked
    /// independently, since a key-level and tenant-level policy may each
    /// configure different tiers.
    ///
    /// An alert is a courtesy notice, not a governance decision: any
    /// failure here (storage error, unreachable webhook) is logged and
    /// swallowed rather than propagated, so it can never affect whether the
    /// triggering request succeeded.
    pub(crate) async fn dispatch_budget_threshold_alerts(
        &self,
        tenant: &ferrogate_core::TenantContext,
    ) {
        let Some(webhook_url) = self.config.billing_alerts.webhook_url.clone() else {
            return;
        };
        let period_month = self.current_period_month();
        let timeout = Duration::from_secs(self.config.billing_alerts.webhook_timeout_secs);
        let scopes: [(QuotaScopeKind, Option<&str>); 4] = [
            (QuotaScopeKind::Key, tenant.api_key_id.as_deref()),
            (QuotaScopeKind::Workspace, tenant.workspace_id.as_deref()),
            (QuotaScopeKind::Project, tenant.project_id.as_deref()),
            (QuotaScopeKind::Tenant, tenant.organization_id.as_deref()),
        ];
        for (scope_type, scope_id) in scopes.into_iter() {
            let Some(scope_id) = scope_id else { continue };
            self.dispatch_budget_threshold_alerts_for_scope(
                scope_type,
                scope_id,
                &period_month,
                &webhook_url,
                timeout,
            )
            .await;
        }
    }

    async fn dispatch_budget_threshold_alerts_for_scope(
        &self,
        scope_type: QuotaScopeKind,
        scope_id: &str,
        period_month: &str,
        webhook_url: &str,
        timeout: Duration,
    ) {
        let policy = match self
            .repositories
            .get_quota_policy(scope_type, scope_id)
            .await
        {
            Ok(Some(policy)) => policy,
            Ok(None) => return,
            Err(error) => {
                warn!(
                    scope_type = %scope_type.as_str(),
                    scope_id = %scope_id,
                    error = %error,
                    "failed to load quota policy for budget threshold alert check"
                );
                return;
            }
        };
        let Some(budget_usd) = policy.monthly_budget_usd.filter(|budget| *budget > 0.0) else {
            return;
        };
        if policy.alert_threshold_pcts.is_empty() {
            return;
        }
        let spent_usd = match self
            .repositories
            .get_usage_monthly_rollup(scope_type, scope_id, period_month)
            .await
        {
            Ok(rollup) => rollup.map(|rollup| rollup.cost_usd).unwrap_or(0.0),
            Err(error) => {
                warn!(
                    scope_type = %scope_type.as_str(),
                    scope_id = %scope_id,
                    error = %error,
                    "failed to load usage rollup for budget threshold alert check"
                );
                return;
            }
        };
        let percent_spent = (spent_usd / budget_usd) * 100.0;
        for threshold_pct in policy.alert_threshold_pcts.iter().copied() {
            if percent_spent + f64::EPSILON < f64::from(threshold_pct) {
                continue;
            }
            let notification_id =
                budget_alert_notification_id(scope_type, scope_id, period_month, threshold_pct);
            match self
                .repositories
                .budget_alert_already_notified(&notification_id)
                .await
            {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    warn!(
                        scope_type = %scope_type.as_str(),
                        scope_id = %scope_id,
                        threshold_pct,
                        error = %error,
                        "failed to check budget alert idempotency ledger"
                    );
                    continue;
                }
            }
            let fired_at_unix = now_unix_seconds().unwrap_or_default() as i64;
            let payload = crate::budget_alerts::BudgetAlertWebhookPayload::new(
                scope_type,
                scope_id,
                period_month,
                threshold_pct,
                spent_usd,
                budget_usd,
                fired_at_unix,
            );
            if let Err(error) =
                crate::budget_alerts::dispatch_budget_alert_webhook(webhook_url, timeout, &payload)
            {
                warn!(
                    scope_type = %scope_type.as_str(),
                    scope_id = %scope_id,
                    threshold_pct,
                    error = %error,
                    "failed to deliver budget threshold alert webhook"
                );
            }
            // Recorded regardless of delivery success: retrying a
            // permanently-unreachable webhook on every subsequent request
            // for the rest of the billing period would be worse than a
            // single missed notification, and this matches the "fire
            // (attempt) exactly once per tier" contract in issue #170.
            if let Err(error) = self
                .repositories
                .record_budget_alert_notification(StoredBudgetAlertNotification {
                    id: notification_id,
                    scope_type,
                    scope_id: scope_id.to_string(),
                    period_month: period_month.to_string(),
                    threshold_pct,
                    notified_at_unix: fired_at_unix,
                })
                .await
            {
                warn!(
                    scope_type = %scope_type.as_str(),
                    scope_id = %scope_id,
                    threshold_pct,
                    error = %error,
                    "failed to record budget alert notification"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "state_wallet_settlement_test.rs"]
mod settlement_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    fn test_provider() -> Provider {
        Provider {
            region: None,
            aws_access_key_id: None,
            aws_secret_access_key_env: None,
            aws_session_token_env: None,
            gcp_project_id: None,
            gcp_access_token_env: None,
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "http://127.0.0.1:10001/v1".into(),
            api_key_env: None,
            secret_ref: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            enabled: true,
        }
    }

    fn test_model() -> Model {
        Model {
            name: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-test".into(),
            routing_strategy: RoutingStrategy::default(),
            fallbacks: Vec::new(),
            visible_organization_ids: Vec::new(),
            visible_project_ids: Vec::new(),
            capabilities: Vec::new(),
            context_window: None,
            input_price_per_1m: None,
            output_price_per_1m: None,
            enabled: true,
            cache_enabled: None,
        }
    }

    /// Spawns a plain-HTTP mock webhook receiver on `127.0.0.1` that
    /// accepts any number of sequential `Connection: close` requests
    /// (unlike `spawn_guardrail_provider_mock`, which is one-shot),
    /// recording each JSON body in arrival order (issue #170).
    fn spawn_webhook_capture_server() -> (String, Arc<Mutex<Vec<serde_json::Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/budget-alerts", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(Vec::new()));
        let server_captured = Arc::clone(&captured);

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut raw = Vec::new();
                let mut buffer = [0_u8; 4096];
                let header_end = loop {
                    let read = stream.read(&mut buffer).unwrap();
                    if read == 0 {
                        return;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        break position + 4;
                    }
                };
                let content_length: usize = String::from_utf8_lossy(&raw[..header_end])
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                while raw.len() < header_end + content_length {
                    let read = stream.read(&mut buffer).unwrap();
                    assert!(read > 0, "connection closed before body was complete");
                    raw.extend_from_slice(&buffer[..read]);
                }
                let body = &raw[header_end..header_end + content_length];
                server_captured
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(body).unwrap());

                let response =
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
                let _ = stream.write_all(response.as_bytes());
            }
        });

        (endpoint, captured)
    }

    fn budget_alert_test_request(request_id: &str) -> RequestContext {
        RequestContext {
            request_id: request_id.into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            route: Some("openai.chat.completions".into()),
            upstream: Some("openai".into()),
            tenant: ferrogate_core::TenantContext {
                organization_id: Some("tenant-budget-alerts".into()),
                team_id: None,
                project_id: Some("project-budget-alerts".into()),
                workspace_id: Some("workspace-budget-alerts".into()),
                user_id: None,
                api_key_id: Some("vk-budget-alerts".into()),
            },
        }
    }

    /// Settles `prompt_tokens` worth of spend (at the fixed $1/1M input
    /// price configured in the test's `Model`, zero output cost) against
    /// the fixed tenant/project/workspace/key attribution from
    /// [`budget_alert_test_request`].
    fn settle_budget_alert_spend(state: &AppState, request_id: &str, prompt_tokens: u64) {
        let request = budget_alert_test_request(request_id);
        block_on(state.record_billing_event(
            BillingEventDraft {
                request: &request,
                logical_model: "fast-chat",
                provider: "openai",
                provider_model: "gpt-test",
                status_code: 200,
                latency_ms: Some(10),
                metadata: None,
            },
            &ProviderUsage {
                prompt_tokens: Some(prompt_tokens),
                completion_tokens: Some(0),
                total_tokens: Some(prompt_tokens),
            },
        ))
        .unwrap();
    }

    #[test]
    fn budget_threshold_alert_fires_once_per_tier_and_is_idempotent() {
        let (webhook_url, captured) = spawn_webhook_capture_server();
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![Model {
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(0.0),
                ..test_model()
            }],
            billing_alerts: crate::config::BillingAlertsConfig {
                webhook_url: Some(webhook_url),
                webhook_timeout_secs: 5,
            },
            ..Config::default()
        });
        block_on(state.upsert_quota_policy(StoredQuotaPolicy {
            id: "tenant:tenant-budget-alerts".into(),
            scope_type: QuotaScopeKind::Tenant,
            scope_id: "tenant-budget-alerts".into(),
            model_allowlist: vec![],
            rpm_limit: None,
            tpm_limit: None,
            monthly_budget_usd: Some(1.0),
            asset_storage_quota_bytes: None,
            alert_threshold_pcts: vec![50, 90],
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        // 500_000 prompt tokens at $1/1M = $0.50 spend = 50% of the $1
        // budget: crosses the 50% tier, not yet the 90% one.
        settle_budget_alert_spend(&state, "req-1", 500_000);
        {
            let captured = captured.lock().unwrap();
            assert_eq!(
                captured.len(),
                1,
                "crossing 50% must fire exactly one webhook: {captured:?}"
            );
            assert_eq!(captured[0]["threshold_pct"], 50);
            assert_eq!(captured[0]["scope_type"], "tenant");
            assert_eq!(captured[0]["scope_id"], "tenant-budget-alerts");
            assert_eq!(captured[0]["event"], "budget_threshold_crossed");
        }

        // +450_000 more prompt tokens = $0.95 total = 95%: crosses the 90%
        // tier. The already-notified 50% tier must not refire.
        settle_budget_alert_spend(&state, "req-2", 450_000);
        {
            let captured = captured.lock().unwrap();
            assert_eq!(
                captured.len(),
                2,
                "crossing 90% must fire exactly one more webhook, and 50% must not repeat: {captured:?}"
            );
            assert_eq!(captured[1]["threshold_pct"], 90);
        }

        // A further request that keeps spend above both already-crossed
        // tiers (and even past the 100% hard-deny threshold, though that's
        // enforced separately in auth.rs) must not fire either tier again.
        settle_budget_alert_spend(&state, "req-3", 100_000);
        {
            let captured = captured.lock().unwrap();
            assert_eq!(
                captured.len(),
                2,
                "no tier may fire twice in the same billing period: {captured:?}"
            );
        }

        assert!(block_on(state.repositories.budget_alert_already_notified(
            &budget_alert_notification_id(
                QuotaScopeKind::Tenant,
                "tenant-budget-alerts",
                &state.current_period_month(),
                50,
            )
        ))
        .unwrap());
        assert!(block_on(state.repositories.budget_alert_already_notified(
            &budget_alert_notification_id(
                QuotaScopeKind::Tenant,
                "tenant-budget-alerts",
                &state.current_period_month(),
                90,
            )
        ))
        .unwrap());
    }

    #[test]
    fn budget_threshold_alert_never_fires_when_thresholds_are_unset() {
        let (webhook_url, captured) = spawn_webhook_capture_server();
        let state = AppState::new(Config {
            providers: vec![test_provider()],
            models: vec![Model {
                input_price_per_1m: Some(1.0),
                output_price_per_1m: Some(0.0),
                ..test_model()
            }],
            billing_alerts: crate::config::BillingAlertsConfig {
                webhook_url: Some(webhook_url),
                webhook_timeout_secs: 5,
            },
            ..Config::default()
        });
        // No alert_threshold_pcts configured -- backward compatible with
        // pre-#170 StoredQuotaPolicy rows/tests: a budget cap alone must
        // never imply implicit alert tiers.
        block_on(state.upsert_quota_policy(StoredQuotaPolicy {
            id: "tenant:tenant-budget-alerts".into(),
            scope_type: QuotaScopeKind::Tenant,
            scope_id: "tenant-budget-alerts".into(),
            model_allowlist: vec![],
            rpm_limit: None,
            tpm_limit: None,
            monthly_budget_usd: Some(1.0),
            asset_storage_quota_bytes: None,
            alert_threshold_pcts: vec![],
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        }))
        .unwrap();

        // Spend well past 100% of budget -- the hard-deny is a separate
        // concern (auth.rs); this call itself must not fire any webhook.
        settle_budget_alert_spend(&state, "req-1", 2_000_000);

        assert!(
            captured.lock().unwrap().is_empty(),
            "no alert_threshold_pcts configured means no webhook ever fires"
        );
    }
}
