// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 backend: tenant-scoped prepaid-credit wallets + reservations (issue #455).

//! D1 backend: tenant-scoped prepaid-credit wallets + reservations (issue #455).
//!
//! The FIRST **tenant-scoped** atomic family routed through the proxy-Worker
//! binding (issue #450). Unlike the account-global billing/guardrail families
//! (which route to the fixed control-DB `env.DB` binding), a tenant's wallet,
//! its live holds, and its settlement ledger live in THAT tenant's own D1
//! database in the database-per-tenant topology. The proxy Worker reaches a
//! tenant database by NAME — the Workers runtime has no select-a-database-by-id
//! API — so every op here selects `tenant_database_binding(tenant_id)` onto the
//! proxy `/d1/batch` + `/d1/query` calls (issue #455 per-tenant routing).
//!
//! ## reserve-no-oversell (the keystone proof)
//!
//! `reserve_wallet_credits` mirrors the Postgres `SELECT ... FOR UPDATE` +
//! sum-live-holds + conditional-insert as ONE atomic `/d1/batch`: a guarded
//! `INSERT ... SELECT ... WHERE ? <= balance - SUM(active holds) ... RETURNING`.
//! D1 has no row lock, but a batch is one implicit transaction and SQLite
//! serializes writers per database, so N parallel reserves against a balance
//! that only affords N-1 admit exactly N-1 — no oversell. An empty `RETURNING`
//! set on the guarded insert is the "guard did not admit it" signal; a sibling
//! wallet-state read in the same batch distinguishes NoWallet from Insufficient.
//!
//! `settle`/`release` carry only a reservation id (no tenant) in their trait
//! signature, so they FAN OUT over the provisioned tenant bindings to locate the
//! database holding the hold (the established id-only-read fan-out), then run the
//! guarded atomic transition on it. `settle` captures the hold into a wallet
//! debit + ledger row + `active -> settled` flip as one `/d1/batch`; `release`
//! is a single guarded `UPDATE ... WHERE status = 'active' RETURNING` CAS.
//!
//! Every op fails closed with the typed unimplemented-surface error when no
//! proxy Worker is bound, exactly like the still-deferred atomic families. The
//! remaining wallet/payment/workflow-budget surface stays deferred (see the
//! `mod.rs` module docs enumeration).

use serde::de::DeserializeOwned;

use super::*;

/// Column list shared by every `wallet_reservations` read, so the projection
/// stays in lockstep with [`WalletReservationD1Row`].
const RESERVATION_COLUMNS: &str = "id, tenant_id, amount_credits, status, expires_at_unix, \
     settlement_id, created_at_unix, updated_at_unix";

/// Column list shared by every `wallet_settlements` read, matching
/// [`WalletSettlementD1Row`].
const SETTLEMENT_COLUMNS: &str =
    "id, tenant_id, delta_credits, balance_after_credits, created_at_unix";

/// Column list shared by every `wallets` read, matching [`WalletD1Row`].
const WALLET_COLUMNS: &str = "id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
     auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix";

/// One `wallets` row (SQLite integer/boolean affinities decoded back to the
/// `Stored*` shape, mirroring the Postgres `wallet_from_row`).
#[derive(serde::Deserialize)]
struct WalletD1Row {
    id: String,
    tenant_id: String,
    balance_credits: i64,
    auto_recharge_threshold_credits: Option<i64>,
    auto_recharge_amount_credits: Option<i64>,
    dunning: i64,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<WalletD1Row> for StoredWallet {
    fn from(row: WalletD1Row) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            balance_credits: row.balance_credits,
            auto_recharge_threshold_credits: row.auto_recharge_threshold_credits,
            auto_recharge_amount_credits: row.auto_recharge_amount_credits,
            dunning: row.dunning != 0,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// One `wallet_reservations` row.
#[derive(serde::Deserialize)]
struct WalletReservationD1Row {
    id: String,
    tenant_id: String,
    amount_credits: i64,
    status: String,
    expires_at_unix: i64,
    settlement_id: Option<String>,
    created_at_unix: i64,
    updated_at_unix: i64,
}

impl From<WalletReservationD1Row> for StoredWalletReservation {
    fn from(row: WalletReservationD1Row) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            amount_credits: row.amount_credits,
            status: row.status,
            expires_at_unix: row.expires_at_unix,
            settlement_id: row.settlement_id,
            created_at_unix: row.created_at_unix,
            updated_at_unix: row.updated_at_unix,
        }
    }
}

/// One `wallet_settlements` row.
#[derive(serde::Deserialize)]
struct WalletSettlementD1Row {
    id: String,
    tenant_id: String,
    delta_credits: i64,
    balance_after_credits: Option<i64>,
    created_at_unix: i64,
}

impl From<WalletSettlementD1Row> for StoredWalletSettlement {
    fn from(row: WalletSettlementD1Row) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            delta_credits: row.delta_credits,
            balance_after_credits: row.balance_after_credits,
            created_at_unix: row.created_at_unix,
        }
    }
}

/// The wallet's balance plus its outstanding (active, unexpired) hold total —
/// read alongside a failed reserve to report NoWallet vs Insufficient.
#[derive(serde::Deserialize)]
struct ReserveWalletStateRow {
    balance_credits: i64,
    outstanding_credits: i64,
}

/// Just the `balance_after_credits` a settle capture's ledger insert returns.
#[derive(serde::Deserialize)]
struct SettlementBalanceRow {
    balance_after_credits: Option<i64>,
}

/// Deserialize one D1 result row (`serde_json::Value` keyed by column) into a
/// typed DTO.
fn decode_row<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, StorageError> {
    serde_json::from_value(value.clone())
        .map_err(|error| StorageError::Serialization(error.to_string()))
}

impl D1ControlPlaneStore {
    // --- Wallets + reservations over the proxy binding, tenant-DB routed
    // (issue #455) ---

    /// Upsert a tenant's wallet configuration into that tenant's D1 database.
    /// A single statement (no CAS), but routed through the proxy's tenant
    /// binding so the whole wallet family shares one tenant-DB routing path;
    /// fails closed without a proxy.
    pub(super) async fn upsert_wallet_d1_async(
        &self,
        wallet: &StoredWallet,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("upsert_wallet")?;
        let binding = self.tenant_proxy_binding(&wallet.tenant_id)?;
        let statement = D1ProxyStatement::with_params(
            "INSERT INTO wallets \
             (id, tenant_id, balance_credits, auto_recharge_threshold_credits, \
              auto_recharge_amount_credits, dunning, created_at_unix, updated_at_unix) \
             VALUES (?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, ?, ?) \
             ON CONFLICT (id) DO UPDATE SET \
             balance_credits = excluded.balance_credits, \
             auto_recharge_threshold_credits = excluded.auto_recharge_threshold_credits, \
             auto_recharge_amount_credits = excluded.auto_recharge_amount_credits, \
             dunning = excluded.dunning, \
             updated_at_unix = excluded.updated_at_unix",
            vec![
                wallet.id.clone(),
                wallet.tenant_id.clone(),
                wallet.balance_credits.to_string(),
                optional_number_param(wallet.auto_recharge_threshold_credits),
                optional_number_param(wallet.auto_recharge_amount_credits),
                bool_param(wallet.dunning),
                wallet.created_at_unix.to_string(),
                wallet.updated_at_unix.to_string(),
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// Read a tenant's wallet from that tenant's D1 database. Opt-in (issue
    /// #169): a tenant with no provisioned database or no wallet row is
    /// `Ok(None)`, not an error — mirroring the Postgres `get_wallet` contract.
    pub(super) async fn get_wallet_d1_async(
        &self,
        tenant_id: &str,
    ) -> Result<Option<StoredWallet>, StorageError> {
        let proxy = self.proxy_client("get_wallet")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(None);
        };
        let statement = D1ProxyStatement::with_params(
            format!("SELECT {WALLET_COLUMNS} FROM wallets WHERE tenant_id = ?"),
            vec![tenant_id.to_string()],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WalletD1Row>(row).map(StoredWallet::from))
            .transpose()
    }

    /// List a tenant's holds newest-first (admin inspect/metrics). Empty for an
    /// unprovisioned tenant; fails closed without a proxy.
    pub(super) async fn list_wallet_reservations_d1_async(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredWalletReservation>, StorageError> {
        let proxy = self.proxy_client("list_wallet_reservations")?;
        let Some(binding) = self.tenant_proxy_binding_optional(tenant_id)? else {
            return Ok(Vec::new());
        };
        let statement = D1ProxyStatement::with_params(
            format!(
                "SELECT {RESERVATION_COLUMNS} FROM wallet_reservations \
                 WHERE tenant_id = ? ORDER BY created_at_unix DESC, id ASC"
            ),
            vec![tenant_id.to_string()],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .iter()
            .map(|row| decode_row::<WalletReservationD1Row>(row).map(StoredWalletReservation::from))
            .collect()
    }

    /// List EVERY provisioned tenant's wallet (issue #169, admin cross-tenant
    /// read). D1 is database-per-tenant, so a tenant's single `wallets` row lives
    /// in THAT tenant's own database — there is no one table to scan. This fans
    /// out over the provisioned tenant bindings (the SAME id-only fan-out
    /// `settle`/`release` use to locate a hold), reads each tenant DB's `wallets`
    /// row, then orders by `tenant_id` ASC to match the Postgres `list_wallets`
    /// contract row-for-row. Fails closed (typed unimplemented-surface) without a
    /// proxy Worker.
    pub(super) async fn list_wallets_d1_async(&self) -> Result<Vec<StoredWallet>, StorageError> {
        let proxy = self.proxy_client("list_wallets")?;
        let mut wallets = Vec::new();
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::new(format!("SELECT {WALLET_COLUMNS} FROM wallets"));
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            for row in &result.results {
                wallets.push(decode_row::<WalletD1Row>(row).map(StoredWallet::from)?);
            }
        }
        // The provisioned bindings already iterate in registry (BTreeMap) key
        // order, but sort explicitly so the cross-tenant list matches the
        // Postgres `ORDER BY tenant_id ASC` regardless of registry shape.
        wallets.sort_by(|left, right| left.tenant_id.cmp(&right.tenant_id));
        Ok(wallets)
    }

    /// Apply one provider-attempt debit/credit to a tenant's wallet, recording an
    /// idempotent settlement ledger row (issue #169), as ONE atomic `/d1/batch`
    /// on that tenant's database (issue #456). Mirrors the Postgres
    /// `settle_wallet_balance`: claiming the `settlement_id` and moving the
    /// balance commit together, so a replay returns the FIRST outcome
    /// (`newly_applied = false`) instead of debiting twice; a replay whose tenant
    /// or delta changed is a typed `Conflict`. Unlike `reserve`, a settlement is
    /// recorded even when the tenant has no wallet row (`balance_after_credits`
    /// stays NULL) — matching Postgres.
    ///
    /// The batch is three statements: a GUARDED wallet debit (skipped on replay,
    /// so it never re-debits), the GUARDED settlement claim (`INSERT ... SELECT
    /// ... WHERE NOT EXISTS(settlement) ... RETURNING` — a returned row is the
    /// "this call recorded it" signal, reading the POST-debit balance), and a
    /// read-back of the durable settlement for the outcome + the replay guard.
    ///
    /// Divergence: an UNPROVISIONED tenant (no tenant DB to hold the ledger) is a
    /// typed `NotFound`, where Postgres would still record the settlement — the
    /// same database-per-tenant divergence `reserve` makes (issue #455).
    pub(super) async fn settle_wallet_balance_d1_async(
        &self,
        settlement_id: &str,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<WalletSettlementOutcome, StorageError> {
        let proxy = self.proxy_client("settle_wallet_balance")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        let now = now_unix.to_string();
        let delta = delta_credits.to_string();

        let statements = vec![
            // S0: debit the wallet, guarded on the settlement not already
            // existing (so a replay never re-debits). CAST the delta: D1 binds
            // params as TEXT and this adds the bound `?` to an INTEGER column in
            // an arithmetic expression (the issue #455 numeric-affinity lesson).
            D1ProxyStatement::with_params(
                "UPDATE wallets SET balance_credits = balance_credits + CAST(? AS INTEGER), \
                 updated_at_unix = ? WHERE tenant_id = ? \
                 AND NOT EXISTS(SELECT 1 FROM wallet_settlements WHERE id = ?)",
                vec![
                    delta.clone(),
                    now.clone(),
                    tenant_id.to_string(),
                    settlement_id.to_string(),
                ],
            ),
            // S1: claim the settlement id, reading the POST-debit balance (S0 ran
            // first in this batch). Guarded on NOT EXISTS + ON CONFLICT DO
            // NOTHING so a replay inserts nothing; a RETURNING row means THIS call
            // recorded it. The balance_after subquery yields NULL (recorded, but
            // no balance) when the tenant has no wallet row.
            D1ProxyStatement::with_params(
                "INSERT INTO wallet_settlements \
                 (id, tenant_id, delta_credits, balance_after_credits, created_at_unix) \
                 SELECT ?, ?, ?, (SELECT balance_credits FROM wallets WHERE tenant_id = ?), ? \
                 WHERE NOT EXISTS(SELECT 1 FROM wallet_settlements WHERE id = ?) \
                 ON CONFLICT (id) DO NOTHING \
                 RETURNING balance_after_credits",
                vec![
                    settlement_id.to_string(),
                    tenant_id.to_string(),
                    delta.clone(),
                    tenant_id.to_string(),
                    now.clone(),
                    settlement_id.to_string(),
                ],
            ),
            // S2: read back the durable settlement (ours, or a concurrent
            // writer's that won the race) for the outcome + replay tenant/delta
            // guard.
            D1ProxyStatement::with_params(
                format!("SELECT {SETTLEMENT_COLUMNS} FROM wallet_settlements WHERE id = ?"),
                vec![settlement_id.to_string()],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 3 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: settle_wallet_balance batch returned fewer than 3 \
                 per-statement results"
                    .to_string(),
            ));
        }

        // S1 RETURNING a row -> this call is the one that recorded the settlement.
        let newly_applied = !results[1].results.is_empty();
        let Some(row) = results[2].results.first() else {
            return Err(StorageError::Runtime(format!(
                "cloudflare d1: wallet settlement {settlement_id} vanished inside its settle batch"
            )));
        };
        let settlement: StoredWalletSettlement = decode_row::<WalletSettlementD1Row>(row)?.into();
        // Only a replay can disagree with the request (a fresh insert carries the
        // request's own values), so guard the tenant/delta mismatch there.
        if !newly_applied
            && (settlement.tenant_id != tenant_id || settlement.delta_credits != delta_credits)
        {
            return Err(StorageError::Conflict(format!(
                "wallet settlement {settlement_id} replay changed tenant or amount"
            )));
        }
        Ok(WalletSettlementOutcome {
            settlement,
            newly_applied,
        })
    }

    /// Atomically apply `delta_credits` (negative to debit, positive to
    /// credit/top-up) to an EXISTING wallet and return the row after the update
    /// (issue #169) — a single `UPDATE ... RETURNING` on the tenant's database,
    /// mirroring the Postgres `adjust_wallet_balance`. `Ok(None)` when the
    /// (provisioned) tenant has no wallet row (opt-in), not an error.
    ///
    /// Divergence: an UNPROVISIONED tenant is `NotFound` (the issue #455
    /// convention, `tenant_proxy_binding` required), where Postgres returns
    /// `Ok(None)`.
    pub(super) async fn adjust_wallet_balance_d1_async(
        &self,
        tenant_id: &str,
        delta_credits: i64,
        now_unix: i64,
    ) -> Result<Option<StoredWallet>, StorageError> {
        let proxy = self.proxy_client("adjust_wallet_balance")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        // CAST the delta: it is added to an INTEGER column in an arithmetic
        // expression, and D1 binds params as TEXT (the issue #455 lesson).
        let statement = D1ProxyStatement::with_params(
            format!(
                "UPDATE wallets SET balance_credits = balance_credits + CAST(? AS INTEGER), \
                 updated_at_unix = ? WHERE tenant_id = ? RETURNING {WALLET_COLUMNS}"
            ),
            vec![
                delta_credits.to_string(),
                now_unix.to_string(),
                tenant_id.to_string(),
            ],
        );
        let result = proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WalletD1Row>(row).map(StoredWallet::from))
            .transpose()
    }

    /// Set a tenant wallet's dunning flag (issue #169) — a single `UPDATE` on the
    /// tenant's database, mirroring the Postgres `set_wallet_dunning`. A no-op
    /// when the (provisioned) tenant has no wallet row.
    ///
    /// Divergence: an UNPROVISIONED tenant is `NotFound` (the issue #455
    /// convention), where Postgres is a silent no-op.
    pub(super) async fn set_wallet_dunning_d1_async(
        &self,
        tenant_id: &str,
        dunning: bool,
        now_unix: i64,
    ) -> Result<(), StorageError> {
        let proxy = self.proxy_client("set_wallet_dunning")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        // `dunning` binds as SQLite's 0/1 integer affinity; it is a stored value
        // (column-affinity coerced on write), not compared against an expression,
        // so no CAST is needed — same as `upsert_wallet`.
        let statement = D1ProxyStatement::with_params(
            "UPDATE wallets SET dunning = ?, updated_at_unix = ? WHERE tenant_id = ?",
            vec![
                bool_param(dunning),
                now_unix.to_string(),
                tenant_id.to_string(),
            ],
        );
        proxy
            .query_on(Some(&binding), &statement)
            .await
            .map_err(d1_error)?;
        Ok(())
    }

    /// Place an exact-amount, no-oversell hold against a tenant's wallet
    /// (issue #281) as ONE atomic `/d1/batch` on that tenant's database
    /// (issue #455). See the module docs for the reserve-no-oversell proof.
    ///
    /// The batch is three statements: an idempotency PROBE by hold id, the
    /// GUARDED conditional insert (`INSERT ... SELECT ... WHERE amount <=
    /// balance - SUM(live holds) ... ON CONFLICT DO NOTHING RETURNING id`), and
    /// a wallet-STATE read. The RETURNING row on the guarded insert means the
    /// hold was admitted; an empty set plus the state read distinguishes
    /// [`NoWallet`](WalletReservationResult::NoWallet) (no wallet row) from
    /// [`Insufficient`](WalletReservationResult::Insufficient). An
    /// already-present hold (probe hit) returns the existing hold (idempotent),
    /// or a typed `Conflict` when the replay changed tenant or amount.
    pub(super) async fn reserve_wallet_credits_d1_async(
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
        let proxy = self.proxy_client("reserve_wallet_credits")?;
        let binding = self.tenant_proxy_binding(tenant_id)?;
        let now = now_unix.to_string();
        let amount = amount_credits.to_string();

        let statements = vec![
            // S0: idempotency probe by hold id.
            D1ProxyStatement::with_params(
                format!("SELECT {RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = ?"),
                vec![reservation_id.to_string()],
            ),
            // S1: the no-oversell guarded conditional insert. Inserts iff a
            // wallet row exists AND the request fits inside available balance
            // (balance minus the SUM of live holds). ON CONFLICT DO NOTHING
            // keeps a replay from erroring; RETURNING id is the admitted signal.
            D1ProxyStatement::with_params(
                "INSERT INTO wallet_reservations \
                 (id, tenant_id, amount_credits, status, expires_at_unix, settlement_id, \
                  created_at_unix, updated_at_unix) \
                 SELECT ?, ?, ?, 'active', ?, NULL, ?, ? \
                 FROM wallets w \
                 WHERE w.tenant_id = ? \
                   AND CAST(? AS INTEGER) <= w.balance_credits - COALESCE(( \
                       SELECT SUM(r.amount_credits) FROM wallet_reservations r \
                       WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ? \
                   ), 0) \
                 ON CONFLICT (id) DO NOTHING \
                 RETURNING id",
                vec![
                    reservation_id.to_string(),
                    tenant_id.to_string(),
                    amount.clone(),
                    expires_at_unix.to_string(),
                    now.clone(),
                    now.clone(),
                    tenant_id.to_string(),
                    amount.clone(),
                    tenant_id.to_string(),
                    now.clone(),
                ],
            ),
            // S2: wallet-state read for the NoWallet vs Insufficient decision.
            D1ProxyStatement::with_params(
                "SELECT w.balance_credits AS balance_credits, \
                 COALESCE(( \
                     SELECT SUM(r.amount_credits) FROM wallet_reservations r \
                     WHERE r.tenant_id = ? AND r.status = 'active' AND r.expires_at_unix > ? \
                 ), 0) AS outstanding_credits \
                 FROM wallets w WHERE w.tenant_id = ?",
                vec![tenant_id.to_string(), now.clone(), tenant_id.to_string()],
            ),
        ];

        let results = proxy
            .batch_on(Some(&binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 3 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: reserve batch returned fewer than 3 per-statement results"
                    .to_string(),
            ));
        }

        // S0: an existing hold for this id is an idempotent replay.
        if let Some(row) = results[0].results.first() {
            let existing: StoredWalletReservation =
                decode_row::<WalletReservationD1Row>(row)?.into();
            if existing.tenant_id != tenant_id || existing.amount_credits != amount_credits {
                return Err(StorageError::Conflict(format!(
                    "wallet reservation {reservation_id} replay changed tenant or amount"
                )));
            }
            return Ok(WalletReservationResult::Reserved(existing));
        }

        // S1: a RETURNING row means the guard admitted the hold.
        if !results[1].results.is_empty() {
            return Ok(WalletReservationResult::Reserved(StoredWalletReservation {
                id: reservation_id.to_string(),
                tenant_id: tenant_id.to_string(),
                amount_credits,
                status: crate::WALLET_RESERVATION_ACTIVE.to_string(),
                expires_at_unix,
                settlement_id: None,
                created_at_unix: now_unix,
                updated_at_unix: now_unix,
            }));
        }

        // Not admitted, no prior hold: S2 says whether a wallet even exists.
        match results[2].results.first() {
            None => Ok(WalletReservationResult::NoWallet),
            Some(row) => {
                let state: ReserveWalletStateRow = decode_row(row)?;
                Ok(WalletReservationResult::Insufficient {
                    available_credits: state.balance_credits - state.outstanding_credits,
                    requested_credits: amount_credits,
                })
            }
        }
    }

    /// Capture an active hold into a real, idempotent wallet debit whose ledger
    /// row references the hold (issue #281). Locates the tenant database holding
    /// the hold (fan-out over provisioned tenant bindings), then runs the
    /// capture as one atomic `/d1/batch`. Replaying a settled hold returns the
    /// first outcome; a released/expired hold is rejected (`Conflict`); an
    /// unknown hold is `NotFound`.
    pub(super) async fn settle_wallet_reservation_d1_async(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        // Fail closed before any network round trip when no proxy is bound.
        self.proxy_client("settle_wallet_reservation")?;
        let Some((binding, reservation)) = self
            .locate_wallet_reservation("settle_wallet_reservation", reservation_id)
            .await?
        else {
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };

        match reservation.status.as_str() {
            crate::WALLET_RESERVATION_SETTLED => {
                let settlement = self
                    .load_wallet_settlement(&binding, reservation_id)
                    .await?
                    .ok_or_else(|| {
                        StorageError::Runtime(format!(
                            "wallet reservation {reservation_id} is settled but its settlement is \
                             missing"
                        ))
                    })?;
                Ok(WalletReservationSettlement {
                    reservation,
                    settlement,
                    newly_applied: false,
                })
            }
            crate::WALLET_RESERVATION_RELEASED => Err(StorageError::WalletHoldReleased {
                reservation_id: reservation_id.to_string(),
                released_by_expiry: false,
            }),
            _ if reservation.expires_at_unix <= now_unix => {
                // Expired before capture: release in-line and reject, so a
                // settle that races the sweeper still fails closed. The release
                // COMMITS, so the error says the hold is gone rather than merely
                // conflicting -- same contract as the Postgres and in-memory
                // stores (#507).
                self.release_reservation_cas(&binding, reservation_id, now_unix)
                    .await?;
                Err(StorageError::WalletHoldReleased {
                    reservation_id: reservation_id.to_string(),
                    released_by_expiry: true,
                })
            }
            _ => {
                self.capture_wallet_reservation(&binding, &reservation, now_unix)
                    .await
            }
        }
    }

    /// Cancel an active hold, restoring its credits to available balance
    /// (issue #281). Idempotent on an already-released hold; rejects a settled
    /// one. Locates the holding tenant database, then runs the guarded CAS.
    pub(super) async fn release_wallet_reservation_d1_async(
        &self,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<StoredWalletReservation, StorageError> {
        // Fail closed before any network round trip when no proxy is bound.
        self.proxy_client("release_wallet_reservation")?;
        let Some((binding, reservation)) = self
            .locate_wallet_reservation("release_wallet_reservation", reservation_id)
            .await?
        else {
            return Err(StorageError::NotFound(format!(
                "wallet reservation {reservation_id} does not exist"
            )));
        };

        match reservation.status.as_str() {
            crate::WALLET_RESERVATION_SETTLED => Err(StorageError::Conflict(format!(
                "wallet reservation {reservation_id} was settled; cannot release"
            ))),
            crate::WALLET_RESERVATION_RELEASED => Ok(reservation),
            _ => {
                match self
                    .release_reservation_cas(&binding, reservation_id, now_unix)
                    .await?
                {
                    Some(released) => Ok(released),
                    // The guard missed: a concurrent transition moved it. Re-read
                    // and report the terminal state faithfully.
                    None => {
                        let reloaded = self
                            .load_wallet_reservation(&binding, reservation_id)
                            .await?
                            .ok_or_else(|| {
                                StorageError::NotFound(format!(
                                    "wallet reservation {reservation_id} does not exist"
                                ))
                            })?;
                        if reloaded.status == crate::WALLET_RESERVATION_SETTLED {
                            return Err(StorageError::Conflict(format!(
                                "wallet reservation {reservation_id} was settled; cannot release"
                            )));
                        }
                        Ok(reloaded)
                    }
                }
            }
        }
    }

    // --- tenant-DB helpers ---

    /// Fan out over the provisioned tenant bindings to find the database holding
    /// `reservation_id`, returning `(binding, reservation)` or `None`.
    async fn locate_wallet_reservation(
        &self,
        method: &'static str,
        reservation_id: &str,
    ) -> Result<Option<(String, StoredWalletReservation)>, StorageError> {
        let proxy = self.proxy_client(method)?;
        for (_tenant_id, binding) in self.provisioned_tenant_bindings()? {
            let statement = D1ProxyStatement::with_params(
                format!("SELECT {RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = ?"),
                vec![reservation_id.to_string()],
            );
            let result = proxy
                .query_on(Some(&binding), &statement)
                .await
                .map_err(d1_error)?;
            if let Some(row) = result.results.first() {
                let reservation: StoredWalletReservation =
                    decode_row::<WalletReservationD1Row>(row)?.into();
                return Ok(Some((binding, reservation)));
            }
        }
        Ok(None)
    }

    /// Capture an active hold on the located tenant database as one atomic batch:
    /// debit the wallet, insert the settlement (idempotent), flip the hold to
    /// settled — all guarded on the hold still being `active`, so a concurrent
    /// settle can never double-debit.
    async fn capture_wallet_reservation(
        &self,
        binding: &str,
        reservation: &StoredWalletReservation,
        now_unix: i64,
    ) -> Result<WalletReservationSettlement, StorageError> {
        let proxy = self.proxy_client("settle_wallet_reservation")?;
        let now = now_unix.to_string();
        let delta_credits = -reservation.amount_credits;
        let delta = delta_credits.to_string();
        let reservation_id = reservation.id.clone();
        let tenant_id = reservation.tenant_id.clone();

        let statements = vec![
            // S0: debit the wallet, guarded on the hold still being active.
            D1ProxyStatement::with_params(
                "UPDATE wallets SET balance_credits = balance_credits + ?, updated_at_unix = ? \
                 WHERE tenant_id = ? \
                   AND EXISTS(SELECT 1 FROM wallet_reservations \
                              WHERE id = ? AND status = 'active')",
                vec![
                    delta.clone(),
                    now.clone(),
                    tenant_id.clone(),
                    reservation_id.clone(),
                ],
            ),
            // S1: record the ledger row; balance_after is read AFTER the debit
            // (this runs after S0 in the batch). Idempotent on the hold id.
            D1ProxyStatement::with_params(
                "INSERT INTO wallet_settlements \
                 (id, tenant_id, delta_credits, balance_after_credits, created_at_unix) \
                 SELECT ?, ?, ?, (SELECT balance_credits FROM wallets WHERE tenant_id = ?), ? \
                 WHERE EXISTS(SELECT 1 FROM wallet_reservations WHERE id = ? AND status = 'active') \
                 ON CONFLICT (id) DO NOTHING \
                 RETURNING balance_after_credits",
                vec![
                    reservation_id.clone(),
                    tenant_id.clone(),
                    delta.clone(),
                    tenant_id.clone(),
                    now.clone(),
                    reservation_id.clone(),
                ],
            ),
            // S2: flip the hold active -> settled, the CAS that decides the race.
            D1ProxyStatement::with_params(
                format!(
                    "UPDATE wallet_reservations SET status = 'settled', settlement_id = ?, \
                     updated_at_unix = ? WHERE id = ? AND status = 'active' \
                     RETURNING {RESERVATION_COLUMNS}"
                ),
                vec![reservation_id.clone(), now.clone(), reservation_id.clone()],
            ),
        ];

        let results = proxy
            .batch_on(Some(binding), &statements)
            .await
            .map_err(d1_error)?;
        if results.len() < 3 {
            return Err(StorageError::Runtime(
                "cloudflare d1 proxy: settle batch returned fewer than 3 per-statement results"
                    .to_string(),
            ));
        }

        // S2 RETURNING present -> this call captured the hold.
        if let Some(row) = results[2].results.first() {
            let captured: StoredWalletReservation =
                decode_row::<WalletReservationD1Row>(row)?.into();
            let balance_after_credits = results[1]
                .results
                .first()
                .map(decode_row::<SettlementBalanceRow>)
                .transpose()?
                .and_then(|row| row.balance_after_credits);
            let settlement = StoredWalletSettlement {
                id: reservation_id.clone(),
                tenant_id: tenant_id.clone(),
                delta_credits,
                balance_after_credits,
                created_at_unix: now_unix,
            };
            return Ok(WalletReservationSettlement {
                reservation: captured,
                settlement,
                newly_applied: true,
            });
        }

        // The active guard missed: a concurrent settle/release won the race.
        // Re-read and report the durable outcome (settled -> the first
        // settlement; released -> the hold is gone, `WalletHoldReleased`).
        let reloaded = self
            .load_wallet_reservation(binding, &reservation_id)
            .await?
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "wallet reservation {reservation_id} does not exist"
                ))
            })?;
        if reloaded.status == crate::WALLET_RESERVATION_SETTLED {
            let settlement = self
                .load_wallet_settlement(binding, &reservation_id)
                .await?
                .ok_or_else(|| {
                    StorageError::Runtime(format!(
                        "wallet reservation {reservation_id} is settled but its settlement is \
                         missing"
                    ))
                })?;
            return Ok(WalletReservationSettlement {
                reservation: reloaded,
                settlement,
                newly_applied: false,
            });
        }
        Err(StorageError::WalletHoldReleased {
            reservation_id: reservation_id.to_string(),
            released_by_expiry: false,
        })
    }

    /// The guarded release CAS: `UPDATE ... WHERE status = 'active' RETURNING`.
    /// `Some(reservation)` when this call flipped it, `None` when the guard
    /// missed (already settled/released).
    async fn release_reservation_cas(
        &self,
        binding: &str,
        reservation_id: &str,
        now_unix: i64,
    ) -> Result<Option<StoredWalletReservation>, StorageError> {
        let proxy = self.proxy_client("release_wallet_reservation")?;
        let statement = D1ProxyStatement::with_params(
            format!(
                "UPDATE wallet_reservations SET status = 'released', updated_at_unix = ? \
                 WHERE id = ? AND status = 'active' RETURNING {RESERVATION_COLUMNS}"
            ),
            vec![now_unix.to_string(), reservation_id.to_string()],
        );
        let result = proxy
            .query_on(Some(binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WalletReservationD1Row>(row).map(StoredWalletReservation::from))
            .transpose()
    }

    /// Single-hold read on a specific tenant binding.
    async fn load_wallet_reservation(
        &self,
        binding: &str,
        reservation_id: &str,
    ) -> Result<Option<StoredWalletReservation>, StorageError> {
        let proxy = self.proxy_client("settle_wallet_reservation")?;
        let statement = D1ProxyStatement::with_params(
            format!("SELECT {RESERVATION_COLUMNS} FROM wallet_reservations WHERE id = ?"),
            vec![reservation_id.to_string()],
        );
        let result = proxy
            .query_on(Some(binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WalletReservationD1Row>(row).map(StoredWalletReservation::from))
            .transpose()
    }

    /// Single-settlement read on a specific tenant binding.
    async fn load_wallet_settlement(
        &self,
        binding: &str,
        settlement_id: &str,
    ) -> Result<Option<StoredWalletSettlement>, StorageError> {
        let proxy = self.proxy_client("settle_wallet_reservation")?;
        let statement = D1ProxyStatement::with_params(
            format!("SELECT {SETTLEMENT_COLUMNS} FROM wallet_settlements WHERE id = ?"),
            vec![settlement_id.to_string()],
        );
        let result = proxy
            .query_on(Some(binding), &statement)
            .await
            .map_err(d1_error)?;
        result
            .results
            .first()
            .map(|row| decode_row::<WalletSettlementD1Row>(row).map(StoredWalletSettlement::from))
            .transpose()
    }
}
