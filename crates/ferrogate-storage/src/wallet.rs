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
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError, StorageOperation,
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

/// Durable result of applying one provider-attempt debit to a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWalletSettlement {
    pub id: String,
    pub tenant_id: String,
    pub delta_credits: i64,
    pub balance_after_credits: Option<i64>,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSettlementOutcome {
    pub settlement: StoredWalletSettlement,
    pub newly_applied: bool,
}

/// A reservation whose hold is live and still counts against available balance.
pub const WALLET_RESERVATION_ACTIVE: &str = "active";
/// A reservation that was converted into a real wallet debit (a ledger charge).
pub const WALLET_RESERVATION_SETTLED: &str = "settled";
/// A reservation that was cancelled or swept after its TTL -- no longer holds
/// funds, and can never be settled.
pub const WALLET_RESERVATION_RELEASED: &str = "released";

/// A durable reserve/hold on a wallet for an exact-amount, irreversible spend
/// (issue #281). A hold reduces a wallet's AVAILABLE (not actual) balance so
/// concurrent spends can't oversubscribe a prepaid balance the way the
/// check-then-debit `adjust_wallet_balance` path can. It moves through
/// `active -> settled` (captured into a real debit) or `active -> released`
/// (cancelled / TTL-swept); those transitions are terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWalletReservation {
    /// Caller-supplied idempotency key. Re-reserving the same id is a no-op
    /// that returns the existing hold; the settlement produced on capture
    /// reuses this id, so the ledger charge and its originating hold reference
    /// each other (acceptance: "Ledger entries reference their originating
    /// hold").
    pub id: String,
    pub tenant_id: String,
    pub amount_credits: i64,
    /// One of [`WALLET_RESERVATION_ACTIVE`] / `_SETTLED` / `_RELEASED`.
    pub status: String,
    /// Unix seconds after which an `active` hold no longer counts against
    /// available balance and is eligible for the sweeper.
    pub expires_at_unix: i64,
    /// The `wallet_settlements.id` this hold produced on capture (equals `id`);
    /// `None` while active or released.
    pub settlement_id: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Outcome of [`RuntimeStorageRepositories::reserve_wallet_credits`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletReservationResult {
    /// The hold was taken (or already existed for this idempotency key).
    Reserved(StoredWalletReservation),
    /// A wallet exists but its available balance (net of other live holds)
    /// cannot cover the request -- the exact-amount, no-oversell rejection.
    Insufficient {
        available_credits: i64,
        requested_credits: i64,
    },
    /// No wallet governs this tenant (wallets are opt-in, issue #169) -- the
    /// caller proceeds without a hold, matching the additive wallet gate.
    NoWallet,
}

/// Outcome of capturing a hold via
/// [`RuntimeStorageRepositories::settle_wallet_reservation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletReservationSettlement {
    pub reservation: StoredWalletReservation,
    pub settlement: StoredWalletSettlement,
    /// `false` on an idempotent replay of an already-captured hold.
    pub newly_applied: bool,
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

pub(super) fn wallet_settlement_from_row(row: &PostgresRow) -> StoredWalletSettlement {
    StoredWalletSettlement {
        id: row.get(0),
        tenant_id: row.get(1),
        delta_credits: row.get(2),
        balance_after_credits: row.get(3),
        created_at_unix: row.get(4),
    }
}

pub(super) fn wallet_reservation_from_row(row: &PostgresRow) -> StoredWalletReservation {
    StoredWalletReservation {
        id: row.get(0),
        tenant_id: row.get(1),
        amount_credits: row.get(2),
        status: row.get(3),
        expires_at_unix: row.get(4),
        settlement_id: row.get(5),
        created_at_unix: row.get(6),
        updated_at_unix: row.get(7),
    }
}

/// Column list shared by every `wallet_reservations` read so the positional
/// [`wallet_reservation_from_row`] indices stay in lockstep.
pub(super) const WALLET_RESERVATION_COLUMNS: &str = "id, tenant_id, amount_credits, status, \
     expires_at_unix, settlement_id, created_at_unix, updated_at_unix";

/// Column list shared by every `wallet_settlements` read so the positional
/// [`wallet_settlement_from_row`] indices stay in lockstep.
pub(super) const WALLET_SETTLEMENT_COLUMNS: &str =
    "id, tenant_id, delta_credits, balance_after_credits, created_at_unix";

impl PostgresControlPlaneStore {
    fn wallet_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        let operation = self.wallet_operation("settle wallet balance");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239 follow-up)
        // as the FIRST statement inside this multi-statement settlement
        // transaction so `wallet_settlements` and `wallets` resolve in the same
        // schema every other wallet accessor (get/upsert/adjust/list) uses, not
        // the connection default (`public` on stock Supabase roles). A bare
        // transaction here split durable wallet balances across schemas.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO wallet_settlements \
                 (id, tenant_id, delta_credits, balance_after_credits, created_at_unix) \
                 VALUES ($1, $2, $3, NULL, $4) ON CONFLICT (id) DO NOTHING",
                &[&settlement_id, &tenant_id, &delta_credits, &now_unix],
            )
            .await
            .map_err(postgres_error)?;

        if inserted == 0 {
            let row = transaction
                .query_one(
                    "SELECT id, tenant_id, delta_credits, balance_after_credits, \
                     created_at_unix FROM wallet_settlements WHERE id = $1",
                    &[&settlement_id],
                )
                .await
                .map_err(postgres_error)?;
            let settlement = wallet_settlement_from_row(&row);
            if settlement.tenant_id != tenant_id || settlement.delta_credits != delta_credits {
                return Err(StorageError::Conflict(format!(
                    "wallet settlement {settlement_id} replay changed tenant or amount"
                )));
            }
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(WalletSettlementOutcome {
                settlement,
                newly_applied: false,
            });
        }

        let balance_after_credits = transaction
            .query_opt(
                "UPDATE wallets SET balance_credits = balance_credits + $1, \
                 updated_at_unix = $2 WHERE tenant_id = $3 RETURNING balance_credits",
                &[&delta_credits, &now_unix, &tenant_id],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get(0));
        transaction
            .execute(
                "UPDATE wallet_settlements SET balance_after_credits = $2 WHERE id = $1",
                &[&settlement_id, &balance_after_credits],
            )
            .await
            .map_err(postgres_error)?;
        let settlement = StoredWalletSettlement {
            id: settlement_id.to_string(),
            tenant_id: tenant_id.to_string(),
            delta_credits,
            balance_after_credits,
            created_at_unix: now_unix,
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(WalletSettlementOutcome {
            settlement,
            newly_applied: true,
        })
    }

    /// Atomically places an exact-amount hold against a wallet's AVAILABLE
    /// balance (issue #281). Serializes concurrent reservers for a tenant by
    /// taking a `SELECT ... FOR UPDATE` row lock on the `wallets` row before
    /// reading the outstanding-holds total, so N parallel reserves against a
    /// balance that only affords N-1 let exactly N-1 through -- no oversell.
    /// Re-reserving the same `reservation_id` returns the existing hold
    /// (idempotent). Returns [`WalletReservationResult::NoWallet`] when the
    /// tenant has no wallet (opt-in) and `Insufficient` when the available
    /// balance can't cover the request.
    pub(super) async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        if amount_credits <= 0 {
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} amount must be positive"
            )));
        }
        let operation = self.wallet_operation("reserve wallet credits");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) as the
        // FIRST statement so `wallets`/`wallet_reservations` resolve in the same
        // schema every other wallet accessor uses (see `settle_wallet_balance`).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }

        // Idempotent replay: a hold already exists for this id. Return it as-is
        // rather than double-holding, mirroring `settle_wallet_balance`'s
        // claim-then-return-first-outcome contract.
        let existing = transaction
            .query_opt(
                &format!(
                    "SELECT {WALLET_RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = $1"
                ),
                &[&reservation_id],
            )
            .await
            .map_err(postgres_error)?;
        if let Some(row) = existing {
            let reservation = wallet_reservation_from_row(&row);
            transaction.commit().await.map_err(postgres_error)?;
            if reservation.tenant_id != tenant_id || reservation.amount_credits != amount_credits {
                return Err(StorageError::Conflict(format!(
                    "wallet reservation {reservation_id} replay changed tenant or amount"
                )));
            }
            return Ok(WalletReservationResult::Reserved(reservation));
        }

        // Serialize concurrent reservers for this tenant on the wallet row.
        let wallet_row = transaction
            .query_opt(
                "SELECT balance_credits FROM wallets WHERE tenant_id = $1 FOR UPDATE",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(wallet_row) = wallet_row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(WalletReservationResult::NoWallet);
        };
        let balance_credits: i64 = wallet_row.get(0);

        // Sum only live (active, unexpired) holds: an expired hold self-releases
        // for availability even before the sweeper marks it released, so a crash
        // between reserve and settle never permanently strands funds.
        let outstanding: i64 = transaction
            .query_one(
                "SELECT COALESCE(SUM(amount_credits), 0)::BIGINT FROM wallet_reservations \
                 WHERE tenant_id = $1 AND status = 'active' AND expires_at_unix > $2",
                &[&tenant_id, &now_unix],
            )
            .await
            .map_err(postgres_error)?
            .get(0);
        let available_credits = balance_credits - outstanding;
        if amount_credits > available_credits {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(WalletReservationResult::Insufficient {
                available_credits,
                requested_credits: amount_credits,
            });
        }

        transaction
            .execute(
                "INSERT INTO wallet_reservations \
                 (id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, \
                  created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, 'active', $4, NULL, $5, $5)",
                &[
                    &reservation_id,
                    &tenant_id,
                    &amount_credits,
                    &expires_at_unix,
                    &now_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(WalletReservationResult::Reserved(StoredWalletReservation {
            id: reservation_id.to_string(),
            tenant_id: tenant_id.to_string(),
            amount_credits,
            status: WALLET_RESERVATION_ACTIVE.to_string(),
            expires_at_unix,
            settlement_id: None,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
        }))
    }

    /// Captures an active hold: debits the wallet by the exact reserved amount,
    /// records a `wallet_settlements` ledger row whose id equals the hold id
    /// (the evidence link), and marks the hold `settled` -- all in one
    /// transaction. Idempotent: replaying a settled hold returns the first
    /// outcome; settling a released or TTL-expired hold is rejected (an expired
    /// hold is released in-line first). `Err(NotFound)` if the hold is unknown.
    pub(super) async fn settle_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        let operation = self.wallet_operation("settle wallet reservation");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {WALLET_RESERVATION_COLUMNS} FROM wallet_reservations \
                     WHERE id = $1 FOR UPDATE"
                ),
                &[&reservation_id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };
        let mut reservation = wallet_reservation_from_row(&row);

        if reservation.status == WALLET_RESERVATION_SETTLED {
            // Idempotent replay: return the durable settlement recorded the
            // first time this hold was captured.
            let settlement_row = transaction
                .query_one(
                    "SELECT id, tenant_id, delta_credits, balance_after_credits, created_at_unix \
                     FROM wallet_settlements WHERE id = $1",
                    &[&reservation_id],
                )
                .await
                .map_err(postgres_error)?;
            let settlement = wallet_settlement_from_row(&settlement_row);
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(WalletReservationSettlement {
                reservation,
                settlement,
                newly_applied: false,
            });
        }
        if reservation.status == WALLET_RESERVATION_RELEASED {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} was released; cannot settle"
            )));
        }
        // status == active
        if reservation.expires_at_unix <= now_unix {
            // Expired before capture: release in-line and reject, so a settle
            // that races the sweeper still fails closed.
            transaction
                .execute(
                    "UPDATE wallet_reservations SET status = 'released', updated_at_unix = $2 \
                     WHERE id = $1",
                    &[&reservation_id, &now_unix],
                )
                .await
                .map_err(postgres_error)?;
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} expired; cannot settle"
            )));
        }

        let delta_credits = -reservation.amount_credits;
        let balance_after_credits: Option<i64> = transaction
            .query_opt(
                "UPDATE wallets SET balance_credits = balance_credits + $1, updated_at_unix = $2 \
                 WHERE tenant_id = $3 RETURNING balance_credits",
                &[&delta_credits, &now_unix, &reservation.tenant_id],
            )
            .await
            .map_err(postgres_error)?
            .map(|row| row.get(0));
        transaction
            .execute(
                "INSERT INTO wallet_settlements \
                 (id, tenant_id, delta_credits, balance_after_credits, created_at_unix) \
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING",
                &[
                    &reservation_id,
                    &reservation.tenant_id,
                    &delta_credits,
                    &balance_after_credits,
                    &now_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;
        transaction
            .execute(
                "UPDATE wallet_reservations SET status = 'settled', settlement_id = $1, \
                 updated_at_unix = $2 WHERE id = $1",
                &[&reservation_id, &now_unix],
            )
            .await
            .map_err(postgres_error)?;
        let settlement = StoredWalletSettlement {
            id: reservation_id.to_string(),
            tenant_id: reservation.tenant_id.clone(),
            delta_credits,
            balance_after_credits,
            created_at_unix: now_unix,
        };
        transaction.commit().await.map_err(postgres_error)?;
        reservation.status = WALLET_RESERVATION_SETTLED.to_string();
        reservation.settlement_id = Some(reservation_id.to_string());
        reservation.updated_at_unix = now_unix;
        Ok(WalletReservationSettlement {
            reservation,
            settlement,
            newly_applied: true,
        })
    }

    /// Cancels an active hold, restoring its credits to available balance.
    /// Idempotent on an already-released hold; rejects a settled one (a
    /// captured spend is irreversible). `Err(NotFound)` if unknown.
    pub(super) async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        let operation = self.wallet_operation("release wallet reservation");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                &format!(
                    "SELECT {WALLET_RESERVATION_COLUMNS} FROM wallet_reservations \
                     WHERE id = $1 FOR UPDATE"
                ),
                &[&reservation_id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };
        let mut reservation = wallet_reservation_from_row(&row);
        if reservation.status == WALLET_RESERVATION_SETTLED {
            transaction.commit().await.map_err(postgres_error)?;
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} was settled; cannot release"
            )));
        }
        if reservation.status == WALLET_RESERVATION_ACTIVE {
            transaction
                .execute(
                    "UPDATE wallet_reservations SET status = 'released', updated_at_unix = $2 \
                     WHERE id = $1",
                    &[&reservation_id, &now_unix],
                )
                .await
                .map_err(postgres_error)?;
            reservation.status = WALLET_RESERVATION_RELEASED.to_string();
            reservation.updated_at_unix = now_unix;
        }
        transaction.commit().await.map_err(postgres_error)?;
        Ok(reservation)
    }

    /// Sweeper (billing-outbox pattern): marks every active hold past its TTL
    /// `released` and returns the swept ids. Available balance already ignores
    /// expired holds; this reclaims their rows and surfaces expiry metrics.
    pub(super) async fn sweep_expired_wallet_reservations(
        &self,
        now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        let operation = self.wallet_operation("sweep expired wallet reservations");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "UPDATE wallet_reservations SET status = 'released', updated_at_unix = $1 \
                 WHERE status = 'active' AND expires_at_unix <= $1 RETURNING id",
                &[&now_unix],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    /// Lists a tenant's holds newest-first for the admin inspect/metrics view.
    pub(super) async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        let operation = self.wallet_operation("list wallet reservations");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                &format!(
                    "SELECT {WALLET_RESERVATION_COLUMNS} FROM wallet_reservations \
                     WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(wallet_reservation_from_row).collect())
    }

    pub(super) async fn upsert_wallet(&self, wallet: &StoredWallet) -> Result<(), StorageError> {
        let operation = self.wallet_operation("upsert wallet");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
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
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn get_wallet(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredWallet>, StorageError> {
        let operation = self.wallet_operation("get wallet");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix \
                 FROM wallets WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(wallet_from_row))
    }

    pub(super) async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        let operation = self.wallet_operation("list wallets");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix \
                 FROM wallets ORDER BY tenant_id ASC",
                &[],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(wallet_from_row).collect())
    }

    /// Atomically applies `delta_credits` (negative to debit, positive to
    /// credit/top-up) to an EXISTING wallet row and returns the row after
    /// the update -- a single `UPDATE ... SET balance_credits =
    /// balance_credits + $delta` rather than read-then-write, so
    /// concurrent settlements against the same tenant can't race each
    /// other's balance update. Returns `Ok(None)` when the tenant has no
    /// wallet row (not an error: wallets are opt-in).
    pub(super) async fn adjust_wallet_balance(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        let operation = self.wallet_operation("adjust wallet balance");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "UPDATE wallets SET balance_credits = balance_credits + $1, \
                 updated_at_unix = $2 WHERE tenant_id = $3 \
                 RETURNING id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
                 auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix",
                &[&delta_credits, &now_unix, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(wallet_from_row))
    }

    pub(super) async fn set_wallet_dunning(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        let operation = self.wallet_operation("set wallet dunning");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
                "UPDATE wallets SET dunning = $1, updated_at_unix = $2 WHERE tenant_id = $3",
                &[&dunning, &now_unix, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn upsert_payment_method(
        &self,
        payment_method: &StoredPaymentMethod,
    ) -> Result<(), StorageError> {
        let operation = self.wallet_operation("upsert payment method");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        transaction
            .execute(
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
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(())
    }

    pub(super) async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        let operation = self.wallet_operation("list payment methods");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let rows = transaction
            .query(
                "SELECT id, tenant_id, provider, provider_customer_id, \
                 provider_payment_method_id, is_default, created_at_unix \
                 FROM payment_methods WHERE tenant_id = $1 ORDER BY created_at_unix ASC",
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(payment_method_from_row).collect())
    }

    /// Single-row lookup by id (issue #185): callers that only have a
    /// payment-method id (e.g. a DELETE request) need this to discover
    /// which tenant owns it *before* authorizing the request, since
    /// `list_payment_methods` requires already knowing the tenant.
    pub(super) async fn get_payment_method(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError> {
        let operation = self.wallet_operation("get payment method");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let row = transaction
            .query_opt(
                "SELECT id, tenant_id, provider, provider_customer_id, \
                 provider_payment_method_id, is_default, created_at_unix \
                 FROM payment_methods WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(payment_method_from_row))
    }

    pub(super) async fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        let operation = self.wallet_operation("delete payment method");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` to the configured `postgres_schema` (#239) so this
        // control-plane query resolves its table in the configured schema, not
        // the connection default (`public` on stock Supabase roles).
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let affected = transaction
            .execute("DELETE FROM payment_methods WHERE id = $1", &[&id])
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(affected > 0)
    }
}

impl RuntimeControlPlaneState {
    pub fn settle_wallet_balance(
        &mut self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        if let Some(settlement) = self.wallet_settlements.get(settlement_id) {
            if settlement.tenant_id != tenant_id || settlement.delta_credits != delta_credits {
                return Err(StorageError::Conflict(format!(
                    "wallet settlement {settlement_id} replay changed tenant or amount"
                )));
            }
            return Ok(WalletSettlementOutcome {
                settlement,
                newly_applied: false,
            });
        }

        let balance_after_credits = self
            .adjust_wallet_balance(tenant_id, delta_credits, now_unix)
            .map(|wallet| wallet.balance_credits);
        let settlement = StoredWalletSettlement {
            id: settlement_id.to_string(),
            tenant_id: tenant_id.to_string(),
            delta_credits,
            balance_after_credits,
            created_at_unix: now_unix,
        };
        self.wallet_settlements
            .insert(settlement.id.clone(), settlement.clone());
        Ok(WalletSettlementOutcome {
            settlement,
            newly_applied: true,
        })
    }

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

    /// In-memory analogue of [`PostgresControlPlaneStore::reserve_wallet_credits`]
    /// (issue #281). The `RuntimeStorageRepositories` mutex that guards this
    /// state serializes concurrent reservers -- the same no-oversell guarantee
    /// the Postgres `FOR UPDATE` row lock provides.
    pub fn reserve_wallet_credits(
        &mut self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        if amount_credits <= 0 {
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} amount must be positive"
            )));
        }
        if let Some(existing) = self.wallet_reservations.get(reservation_id) {
            if existing.tenant_id != tenant_id || existing.amount_credits != amount_credits {
                return Err(StorageError::Conflict(format!(
                    "wallet reservation {reservation_id} replay changed tenant or amount"
                )));
            }
            return Ok(WalletReservationResult::Reserved(existing));
        }
        let Some(wallet) = self.wallets.get(tenant_id) else {
            return Ok(WalletReservationResult::NoWallet);
        };
        let outstanding: i64 = self
            .wallet_reservations
            .list()
            .into_iter()
            .filter(|r| {
                r.tenant_id == tenant_id
                    && r.status == WALLET_RESERVATION_ACTIVE
                    && r.expires_at_unix > now_unix
            })
            .map(|r| r.amount_credits)
            .sum();
        let available_credits = wallet.balance_credits - outstanding;
        if amount_credits > available_credits {
            return Ok(WalletReservationResult::Insufficient {
                available_credits,
                requested_credits: amount_credits,
            });
        }
        let reservation = StoredWalletReservation {
            id: reservation_id.to_string(),
            tenant_id: tenant_id.to_string(),
            amount_credits,
            status: WALLET_RESERVATION_ACTIVE.to_string(),
            expires_at_unix,
            settlement_id: None,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
        };
        self.wallet_reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(WalletReservationResult::Reserved(reservation))
    }

    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::settle_wallet_reservation`] (issue #281).
    pub fn settle_wallet_reservation(
        &mut self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        let Some(mut reservation) = self.wallet_reservations.get(reservation_id) else {
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };
        if reservation.status == WALLET_RESERVATION_SETTLED {
            let settlement = self.wallet_settlements.get(reservation_id).ok_or_else(|| {
                StorageError::Runtime(format!(
                    "wallet reservation {reservation_id} is settled but its settlement is missing"
                ))
            })?;
            return Ok(WalletReservationSettlement {
                reservation,
                settlement,
                newly_applied: false,
            });
        }
        if reservation.status == WALLET_RESERVATION_RELEASED {
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} was released; cannot settle"
            )));
        }
        if reservation.expires_at_unix <= now_unix {
            reservation.status = WALLET_RESERVATION_RELEASED.to_string();
            reservation.updated_at_unix = now_unix;
            self.wallet_reservations
                .insert(reservation.id.clone(), reservation);
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} expired; cannot settle"
            )));
        }
        let delta_credits = -reservation.amount_credits;
        let balance_after_credits = self
            .adjust_wallet_balance(&reservation.tenant_id, delta_credits, now_unix)
            .map(|wallet| wallet.balance_credits);
        let settlement = StoredWalletSettlement {
            id: reservation_id.to_string(),
            tenant_id: reservation.tenant_id.clone(),
            delta_credits,
            balance_after_credits,
            created_at_unix: now_unix,
        };
        self.wallet_settlements
            .insert(settlement.id.clone(), settlement.clone());
        reservation.status = WALLET_RESERVATION_SETTLED.to_string();
        reservation.settlement_id = Some(reservation_id.to_string());
        reservation.updated_at_unix = now_unix;
        self.wallet_reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(WalletReservationSettlement {
            reservation,
            settlement,
            newly_applied: true,
        })
    }

    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::release_wallet_reservation`] (issue #281).
    pub fn release_wallet_reservation(
        &mut self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        let Some(mut reservation) = self.wallet_reservations.get(reservation_id) else {
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };
        if reservation.status == WALLET_RESERVATION_SETTLED {
            return Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} was settled; cannot release"
            )));
        }
        if reservation.status == WALLET_RESERVATION_ACTIVE {
            reservation.status = WALLET_RESERVATION_RELEASED.to_string();
            reservation.updated_at_unix = now_unix;
            self.wallet_reservations
                .insert(reservation.id.clone(), reservation.clone());
        }
        Ok(reservation)
    }

    /// In-memory analogue of
    /// [`PostgresControlPlaneStore::sweep_expired_wallet_reservations`]
    /// (issue #281). Returns the swept ids sorted for deterministic tests.
    pub fn sweep_expired_wallet_reservations(&mut self, now_unix: i64) -> Vec<String> {
        let expired: Vec<StoredWalletReservation> = self
            .wallet_reservations
            .list()
            .into_iter()
            .filter(|r| r.status == WALLET_RESERVATION_ACTIVE && r.expires_at_unix <= now_unix)
            .collect();
        let mut ids = Vec::with_capacity(expired.len());
        for mut reservation in expired {
            reservation.status = WALLET_RESERVATION_RELEASED.to_string();
            reservation.updated_at_unix = now_unix;
            ids.push(reservation.id.clone());
            self.wallet_reservations
                .insert(reservation.id.clone(), reservation);
        }
        ids.sort();
        ids
    }

    pub fn list_wallet_reservations(&self, tenant_id: &str) -> Vec<StoredWalletReservation> {
        let mut reservations: Vec<StoredWalletReservation> = self
            .wallet_reservations
            .list()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect();
        reservations.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        reservations
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

    pub fn get_payment_method(&self, id: &str) -> Option<StoredPaymentMethod> {
        self.payment_methods.get(id)
    }

    pub fn delete_payment_method(&mut self, id: &str) -> bool {
        self.payment_methods.remove(id).is_some()
    }
}

impl RuntimeStorageRepositories {
    /// Applies `delta_credits` at most once for `settlement_id`, returning the
    /// first transaction's durable outcome on every replay.
    pub async fn settle_wallet_balance(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .settle_wallet_balance(settlement_id, tenant_id, delta_credits, now_unix),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .settle_wallet_balance(settlement_id, tenant_id, delta_credits, now_unix)
                    .await
            }
        }
    }

    /// Creates or replaces a wallet's configuration (issue #169). Use
    /// [`Self::adjust_wallet_balance`] for balance changes instead of
    /// read-modify-write through this method -- it's the atomic,
    /// race-safe path.
    pub async fn upsert_wallet(&self, wallet: StoredWallet) -> Result<(), StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => {
                if let Ok(mut control_plane) = control_plane.lock() {
                    control_plane.upsert_wallet(wallet);
                }
                Ok(())
            }
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.upsert_wallet(&wallet).await
            }
        }
    }

    pub async fn get_wallet(&self, tenant_id: &str) -> Result<Option<StoredWallet>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_wallet(tenant_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_wallet(tenant_id).await
            }
        }
    }

    pub async fn list_wallets(&self) -> Result<Vec<StoredWallet>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_wallets())
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_wallets().await
            }
        }
    }

    /// Atomically applies `delta_credits` to an existing wallet (negative
    /// to debit a settled request, positive to credit a top-up).
    /// `Ok(None)` means the tenant has no wallet row -- not an error,
    /// wallets are opt-in (issue #169).
    pub async fn adjust_wallet_balance(
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
                control_plane
                    .adjust_wallet_balance(tenant_id, delta_credits, now_unix)
                    .await
            }
        }
    }

    pub async fn set_wallet_dunning(
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
                control_plane
                    .set_wallet_dunning(tenant_id, dunning, now_unix)
                    .await
            }
        }
    }

    /// Places an exact-amount durable hold against a wallet's available balance
    /// (issue #281). Atomic and no-oversell across concurrent callers on both
    /// backends -- see [`PostgresControlPlaneStore::reserve_wallet_credits`].
    pub async fn reserve_wallet_credits(
        &self,
        reservation_id: &str,
        tenant_id: &str,
        amount_credits: i64,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<WalletReservationResult, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .reserve_wallet_credits(
                    reservation_id,
                    tenant_id,
                    amount_credits,
                    expires_at_unix,
                    now_unix,
                ),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .reserve_wallet_credits(
                        reservation_id,
                        tenant_id,
                        amount_credits,
                        expires_at_unix,
                        now_unix,
                    )
                    .await
            }
        }
    }

    /// Captures an active hold into a real, idempotent wallet debit whose ledger
    /// row references the hold (issue #281).
    pub async fn settle_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .settle_wallet_reservation(reservation_id, now_unix),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .settle_wallet_reservation(reservation_id, now_unix)
                    .await
            }
        }
    }

    /// Cancels an active hold, restoring its credits (issue #281).
    pub async fn release_wallet_reservation(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .release_wallet_reservation(reservation_id, now_unix),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .release_wallet_reservation(reservation_id, now_unix)
                    .await
            }
        }
    }

    /// Releases every hold past its TTL and returns the swept ids (issue #281).
    pub async fn sweep_expired_wallet_reservations(
        &self,
        now_unix: i64,
    ) -> Result<Vec<String>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .sweep_expired_wallet_reservations(now_unix)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .sweep_expired_wallet_reservations(now_unix)
                    .await
            }
        }
    }

    /// Lists a tenant's holds newest-first for admin inspect/metrics (issue #281).
    pub async fn list_wallet_reservations(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_wallet_reservations(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_wallet_reservations(tenant_id).await
            }
        }
    }

    pub async fn upsert_payment_method(
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
                control_plane.upsert_payment_method(&payment_method).await
            }
        }
    }

    pub async fn list_payment_methods(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentMethod>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_payment_methods(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_payment_methods(tenant_id).await
            }
        }
    }

    pub async fn get_payment_method(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentMethod>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_payment_method(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_payment_method(id).await
            }
        }
    }

    pub async fn delete_payment_method(&self, id: &str) -> Result<bool, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|mut control_plane| control_plane.delete_payment_method(id))
                .unwrap_or(false)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.delete_payment_method(id).await
            }
        }
    }
}
