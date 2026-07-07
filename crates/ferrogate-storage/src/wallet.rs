// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Prepaid-credit wallet and payment-method storage (issue
// #169): lets an operator resell metered AI access as their own self-serve
// SaaS product, distinct from (and enforced independently of)
// `StoredQuotaPolicy::monthly_budget_usd`, which only throttles spend
// against a number nobody ever paid. A tenant's wallet is opt-in -- no row
// means no wallet-balance enforcement applies to that tenant, same
// only-enforce-when-a-formal-record-exists pattern already used for plan
// feature flags (issue #182/#183). Split into its own file per the "one
// business entity per file" convention -- see `budget_alerts.rs`/`rbac.rs`
// for the pattern this mirrors.

use super::{
    PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError,
};

/// A tenant's prepaid-credit balance (issue #169). Balances are integer
/// credits (matching `ferrogate_billing::pricing::DEFAULT_CREDITS_PER_USD`'s
/// unit), not floating-point USD, so repeated debits never accumulate
/// rounding drift the way summing `f64` cost deltas would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWallet {
    /// Deterministic and equal to `tenant_id` -- a tenant has at most one
    /// wallet, so there's no separate id-generation step (mirrors how
    /// `quota_policy_id`/`tenant_role_binding_id` compose deterministic ids
    /// from their owning entity rather than issuing a random one).
    pub id: String,
    pub tenant_id: String,
    pub balance_credits: i64,
    /// Fire an auto-recharge charge once `balance_credits` drops to or
    /// below this threshold. `None` disables auto-recharge for this
    /// wallet (manual top-up only).
    pub auto_recharge_threshold_credits: Option<i64>,
    /// Credits to purchase per auto-recharge charge. Required (enforced
    /// at the admin API layer) whenever `auto_recharge_threshold_credits`
    /// is set.
    pub auto_recharge_amount_credits: Option<i64>,
    /// Set when the most recent auto-recharge charge attempt was
    /// declined -- a declined charge leaves the tenant in a visible
    /// dunning state rather than either silently blocking all traffic or
    /// silently granting unlimited credit. Cleared on the next
    /// successful charge (auto or manual top-up).
    pub dunning: bool,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// An opaque reference to a payment-provider-side payment method (issue
/// #169) -- e.g. a Stripe `payment_method`/`customer` id pair. Never
/// stores raw card data; that stays entirely on the payment provider's
/// side, matching PCI-scope-avoidance practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaymentMethod {
    pub id: String,
    pub tenant_id: String,
    /// Payment-provider adapter kind, e.g. `"stripe"` -- matches
    /// `PaymentProviderAdapter::provider_name()` in `ferrogate-billing`.
    pub provider: String,
    pub provider_customer_id: String,
    pub provider_payment_method_id: String,
    pub is_default: bool,
    pub created_at_unix: i64,
}

/// Deterministic id for a payment method row, mirroring
/// `tenant_role_binding_id`: idempotent re-attachment of the same
/// provider-side payment method is a no-op rather than a duplicate row.
pub fn payment_method_id(
    tenant_id: &str,
    provider: &str,
    provider_payment_method_id: &str,
) -> String {
    format!("{tenant_id}:{provider}:{provider_payment_method_id}")
}

fn wallet_from_row(row: &PostgresRow) -> StoredWallet {
    StoredWallet {
        id: row.get(0),
        tenant_id: row.get(1),
        balance_credits: row.get(2),
        auto_recharge_threshold_credits: row.get(3),
        auto_recharge_amount_credits: row.get(4),
        dunning: row.get(5),
        created_at_unix: row.get(6),
        updated_at_unix: row.get(7),
    }
}

fn payment_method_from_row(row: &PostgresRow) -> StoredPaymentMethod {
    StoredPaymentMethod {
        id: row.get(0),
        tenant_id: row.get(1),
        provider: row.get(2),
        provider_customer_id: row.get(3),
        provider_payment_method_id: row.get(4),
        is_default: row.get(5),
        created_at_unix: row.get(6),
    }
}

fn wallet_supabase_only_error() -> StorageError {
    StorageError::Runtime(
        "wallets/payment methods are Supabase/Postgres-only; set storage.provider = supabase"
            .into(),
    )
}

impl PostgresControlPlaneStore {
    pub(super) fn upsert_wallet(&self, wallet: &StoredWallet) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO wallets \
                 (id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                  auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (id) DO UPDATE SET \
                 balance_credits = EXCLUDED.balance_credits, \
                 auto_recharge_threshold_credits = EXCLUDED.auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits = EXCLUDED.auto_recharge_amount_credits, \
                 dunning = EXCLUDED.dunning, \
                 updated_at_unix = EXCLUDED.updated_at_unix",
                &[
                    &wallet.id,
                    &wallet.tenant_id,
                    &wallet.balance_credits,
                    &wallet.auto_recharge_threshold_credits,
                    &wallet.auto_recharge_amount_credits,
                    &wallet.dunning,
                    &wallet.created_at_unix,
                    &wallet.updated_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        let row = self.with_client(|client| {
            client.query_opt(
                "SELECT id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix \
                 FROM wallets WHERE tenant_id = $1",
                &[&tenant_id],
            )
        })?;
        Ok(row.as_ref().map(wallet_from_row))
    }

    pub(super) fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix \
                 FROM wallets ORDER BY tenant_id ASC",
                &[],
            )
        })?;
        Ok(rows.iter().map(wallet_from_row).collect())
    }

    /// Atomically applies `delta_credits` (negative to debit, positive to
    /// credit/top-up) to an EXISTING wallet row and returns the row after
    /// the update -- a single `UPDATE ... SET balance_credits =
    /// balance_credits + $delta` rather than read-then-write, so
    /// concurrent settlements against the same tenant can't race each
    /// other's balance update. Returns `Ok(None)` when the tenant has no
    /// wallet row (not an error: wallets are opt-in).
    pub(super) fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        let row = self.with_client(|client| {
            client.query_opt(
                "UPDATE wallets SET balance_credits = balance_credits + $1, \
                 updated_at_unix = $2 WHERE tenant_id = $3 \
                 RETURNING id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix",
                &[&delta_credits, &now_unix, &tenant_id],
            )
        })?;
        Ok(row.as_ref().map(wallet_from_row))
    }

    pub(super) fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "UPDATE wallets SET dunning = $1, updated_at_unix = $2 WHERE tenant_id = $3",
                &[&dunning, &now_unix, &tenant_id],
            )?;
            Ok(())
        })
    }

    pub(super) fn upsert_payment_method(
        &self,
        payment_method: &StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        self.with_client(|client| {
            client.execute(
                "INSERT INTO payment_methods \
                 (id, tenant_id, provider, provider_customer_id, provider_payment_method_id, \
                  is_default, created_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (id) DO UPDATE SET is_default = EXCLUDED.is_default",
                &[
                    &payment_method.id,
                    &payment_method.tenant_id,
                    &payment_method.provider,
                    &payment_method.provider_customer_id,
                    &payment_method.provider_payment_method_id,
                    &payment_method.is_default,
                    &payment_method.created_at_unix,
                ],
            )?;
            Ok(())
        })
    }

    pub(super) fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        let rows = self.with_client(|client| {
            client.query(
                "SELECT id, tenant_id, provider, provider_customer_id, \
                 provider_payment_method_id, is_default, created_at_unix \
                 FROM payment_methods WHERE tenant_id = $1 ORDER BY created_at_unix ASC",
                &[&tenant_id],
            )
        })?;
        Ok(rows.iter().map(payment_method_from_row).collect())
    }

    pub(super) fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        let affected = self.with_client(|client| {
            client.execute("DELETE FROM payment_methods WHERE id = $1", &[&id])
        })?;
        Ok(affected > 0)
    }
}

impl RuntimeControlPlaneState {
    pub fn upsert_wallet(&mut self, wallet: StoredWallet) {
        self.wallets.insert(wallet.id.clone(), wallet);
    }

    pub fn get_wallet(&self, tenant_id: &str) -> Option<StoredWallet> {
        self.wallets.get(tenant_id)
    }

    pub fn list_wallets(&self) -> Vec<StoredWallet> {
        self.wallets.list()
    }

    pub fn adjust_wallet_balance(
        &mut self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Option<StoredWallet> {
        let mut wallet = self.wallets.get(tenant_id)?;
        wallet.balance_credits += delta_credits;
        wallet.updated_at_unix = now_unix;
        self.wallets.insert(wallet.id.clone(), wallet.clone());
        Some(wallet)
    }

    pub fn set_wallet_dunning(&mut self, tenant_id: &str, dunning: bool, now_unix: i64) {
        if let Some(mut wallet) = self.wallets.get(tenant_id) {
            wallet.dunning = dunning;
            wallet.updated_at_unix = now_unix;
            self.wallets.insert(wallet.id.clone(), wallet);
        }
    }

    pub fn upsert_payment_method(&mut self, payment_method: StoredPaymentMethod) {
        self.payment_methods
            .insert(payment_method.id.clone(), payment_method);
    }

    pub fn list_payment_methods(&self, tenant_id: &str) -> Vec<StoredPaymentMethod> {
        self.payment_methods
            .list()
            .into_iter()
            .filter(|payment_method| payment_method.tenant_id == tenant_id)
            .collect()
    }

    pub fn delete_payment_method(&mut self, id: &str) -> bool {
        self.payment_methods.remove(id).is_some()
    }
}

impl RuntimeStorageRepositories {
    /// Creates or replaces a wallet's configuration (issue #169). Use
    /// [`Self::adjust_wallet_balance`] for balance changes instead of
    /// read-modify-write through this method -- it's the atomic,
    /// race-safe path.
    pub fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_wallet(wallet);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_wallet(&wallet)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_wallet(tenant_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_wallet(tenant_id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_wallets())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => control_plane.list_wallets(),
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    /// Atomically applies `delta_credits` to an existing wallet (negative
    /// to debit a settled request, positive to credit a top-up).
    /// `Ok(None)` means the tenant has no wallet row -- not an error,
    /// wallets are opt-in (issue #169).
    pub fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| {
                    control_plane.adjust_wallet_balance(tenant_id, delta_credits, now_unix)
                })
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.adjust_wallet_balance(tenant_id, delta_credits, now_unix)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.set_wallet_dunning(tenant_id, dunning, now_unix);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.set_wallet_dunning(tenant_id, dunning, now_unix)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn upsert_payment_method(
        &self,
        payment_method: StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_payment_method(payment_method);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_payment_method(&payment_method)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_payment_methods(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_payment_methods(tenant_id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }

    pub fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_payment_method(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_payment_method(id)
            }
            RuntimeControlPlaneBackend::Mysql(_) => Err(wallet_supabase_only_error()),
        }
    }
}
