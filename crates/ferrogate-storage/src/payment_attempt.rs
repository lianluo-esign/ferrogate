// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Durable x402 payment-attempt persistence and its wallet coupling
// (issue #352). A wallet hold alone cannot explain or reconcile an on-chain
// payment, so this module gives every attempt a durable identity carrying the
// complete immutable audit tuple (the frozen #350 wire contract fields plus the
// #351 policy decision output) and an explicit state machine whose every
// transition is one short conditional CAS. #354 owns the runtime settle/release
// loop that drives these primitives; this file is only the storage foundation.
//
// Split into its own file per the "one business entity per file" convention --
// see `wallet.rs`/`workflow_budget.rs` for the pattern this mirrors.

use super::{
    postgres_error, PostgresControlPlaneStore, PostgresRow, Repository, RuntimeControlPlaneBackend,
    RuntimeControlPlaneState, RuntimeStorageRepositories, StorageError, StorageOperation,
    StoredWalletReservation, StoredWalletSettlement,
};

// ---------------------------------------------------------------------------
// State truth table
// ---------------------------------------------------------------------------
//
// challenged --authorize--> authorized --submit--> submitted --settle--> settled (terminal)
//     |                          |                     |
//     |                          |                     +--outcome_unknown--> outcome_unknown
//     |                          |                             |  (post-submission ambiguity;
//     |                          |                             |   HOLD RETAINED)
//     |                          |                             +--settle--> settled (terminal)
//     |                          |                             +--fail----> failed (terminal)
//     |                          +--release--> released (terminal, pre-submission)
//     |                          +--fail-----> failed   (terminal)
//     +--deny-----> denied   (terminal, pre-authorization policy refusal)
//     +--release--> released (terminal, pre-submission cancel/expiry)
//
// Wallet coupling (see `wallet.rs`, issue #281): an authorized attempt references
// its active hold via `hold_id`. Crossing into `settled` couples to capturing
// that hold (`settle_wallet_reservation`); `released`/`failed`/`denied` couple to
// releasing it (`release_wallet_reservation`). `outcome_unknown` is the ONE state
// that must RETAIN the hold: after proof submission a timeout / RPC ambiguity is
// not proof the money did not move, so releasing the hold there could spend
// stablecoin without charging the wallet. Which primitive runs for each edge is
// #354's runtime orchestration; this layer only provides the idempotent,
// re-drivable attempt-state CAS and stores the linkage.
//
// Note the two distinct "unknown" concepts, deliberately not conflated:
//   * `PAYMENT_ATTEMPT_OUTCOME_UNKNOWN` -- a durable BUSINESS state (above): the
//     on-chain settlement result is ambiguous; retain the hold until durable
//     evidence proves settled or not-submitted.
//   * `StorageError::OperationCommitOutcomeUnknown` -- the generic storage
//     scheduler's report that a single DML's COMMIT outcome across an async
//     timeout is itself unknown (AGENTS.md CommitInFlight/OutcomeUnknown). Every
//     transition here is idempotent and re-readable by design, so re-issuing or
//     re-reading after that report returns the durable truth (`Applied` the first
//     time, `Idempotent` on replay) instead of a false failure. `generation`
//     is the per-attempt operation token that survives the generic scheduler.

/// The attempt exists but has not yet been authorized by policy.
pub const PAYMENT_ATTEMPT_CHALLENGED: &str = "challenged";
/// Policy allowed the payment and credits are held (`hold_id` is set).
pub const PAYMENT_ATTEMPT_AUTHORIZED: &str = "authorized";
/// The signed proof was submitted; from here a timeout is `outcome_unknown`.
pub const PAYMENT_ATTEMPT_SUBMITTED: &str = "submitted";
/// Durable on-chain evidence captured the hold. Terminal.
pub const PAYMENT_ATTEMPT_SETTLED: &str = "settled";
/// Policy refused the payment before authorization. Terminal.
pub const PAYMENT_ATTEMPT_DENIED: &str = "denied";
/// A pre-submission cancel/expiry released the hold. Terminal.
pub const PAYMENT_ATTEMPT_RELEASED: &str = "released";
/// Durable evidence proved the payment did not settle. Terminal.
pub const PAYMENT_ATTEMPT_FAILED: &str = "failed";
/// Post-submission ambiguity; the hold is RETAINED. Non-terminal.
pub const PAYMENT_ATTEMPT_OUTCOME_UNKNOWN: &str = "outcome_unknown";

/// States an attempt may be created in (the entry points of the machine).
pub const PAYMENT_ATTEMPT_INITIAL_STATES: &[&str] = &[
    PAYMENT_ATTEMPT_CHALLENGED,
    PAYMENT_ATTEMPT_AUTHORIZED,
    PAYMENT_ATTEMPT_DENIED,
];

/// True for the four terminal states no transition may leave.
pub fn payment_attempt_state_is_terminal(state: &str) -> bool {
    matches!(
        state,
        PAYMENT_ATTEMPT_SETTLED
            | PAYMENT_ATTEMPT_DENIED
            | PAYMENT_ATTEMPT_RELEASED
            | PAYMENT_ATTEMPT_FAILED
    )
}

/// The pre-submission states a TTL sweep may expire (release the hold), and
/// exactly the states `X402SettlementLoop::expire_if_due` acts on (#354). A
/// `submitted` attempt is deliberately excluded: after proof submission a
/// timed-out attempt is ambiguous, its stablecoin may already have moved
/// on-chain, so releasing its hold could spend without charging the wallet --
/// that case is `outcome_unknown` (hold retained), never a sweep release. The
/// terminal states hold no live money to reclaim. Keep in lockstep with the
/// `release_payment_attempt` allowed-from set and the loop's `pre_submission`
/// check.
pub const PAYMENT_ATTEMPT_EXPIRABLE_STATES: &[&str] =
    &[PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED];

/// The non-terminal post-submission states the on-chain settlement reconciler
/// (#354) drives toward a definite terminal. A `submitted` attempt's proof went
/// on-chain but was never finalized; an `outcome_unknown` attempt was parked
/// under post-submission ambiguity with its hold RETAINED. Both need on-chain
/// evidence to resolve: a confirmed exact-amount transfer settles them (capture),
/// a definitively-failed/absent-past-deadline transfer fails them (release), and
/// anything still pending leaves them `outcome_unknown` with the hold retained.
/// Deliberately DISJOINT from [`PAYMENT_ATTEMPT_EXPIRABLE_STATES`]: the TTL
/// sweeper only ever releases pre-submission holds, the reconciler only ever
/// touches post-submission ones, so the two background loops can never both act
/// on the same attempt. Keep in lockstep with the `settle`/`fail`/
/// `mark_outcome_unknown` allowed-from sets the loop drives for these edges.
pub const PAYMENT_ATTEMPT_RECONCILABLE_STATES: &[&str] =
    &[PAYMENT_ATTEMPT_SUBMITTED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN];

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// One durable x402 payment attempt (issue #352). Every field except the
/// mutable state/evidence tail is immutable after [`create`]; a replayed create
/// with a different immutable tuple fails closed. Amounts follow the frozen wire
/// contract's domains: `atomic_amount`/`settled_atomic_amount` are canonical
/// decimal strings of the on-chain `u64` atomic units (TEXT so the full `u64`
/// range survives a `BIGINT` that only spans `i64`), while `credits_amount` is
/// the internal wallet-credit hold size in the same `i64` domain as
/// [`StoredWalletReservation::amount_credits`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPaymentAttempt {
    /// Attempt / idempotency id (primary key). Re-creating this id is a no-op.
    pub id: String,
    pub tenant_id: String,
    pub project_id: Option<String>,
    pub workspace_id: Option<String>,
    pub run_id: Option<String>,
    pub worker_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    /// HTTP method of the egress request the payment unlocks.
    pub method: String,
    /// Canonical resource URL FerroGate authorized egress to.
    pub resource_url: String,
    /// Hex SHA-256 of the request body, when captured.
    pub request_body_hash: Option<String>,
    /// Hex challenge hash from the wire contract (`SelectedPayment::challenge_hash_hex`).
    pub challenge_hash: String,
    /// x402 protocol version (frozen contract: 2).
    pub x402_version: i64,
    /// Payment scheme (frozen contract: `exact`).
    pub scheme: String,
    /// CAIP-2 network identifier (self-describing string, never a Rust variant).
    pub network_caip2: String,
    /// SPL token mint (base58).
    pub mint: String,
    /// On-chain atomic amount as a canonical decimal string (`u64` range).
    pub atomic_amount: String,
    /// Recipient (`payTo`, base58).
    pub recipient: String,
    /// Internal wallet credits held for this payment (the #281 hold size).
    pub credits_amount: Option<i64>,
    /// Conversion-rule version tag in effect at decision time (#351).
    pub conversion_version: Option<String>,
    /// Policy revision that produced the decision (#351).
    pub policy_revision: i64,
    /// Policy decision: `allow` / `approval_required` / `deny` (#351).
    pub decision: String,
    /// Stable policy reason code (one of the `REASON_*` constants, #351).
    pub reason_code: String,
    /// Linked `wallet_reservations.id` hold (#281). `None` on a denied attempt.
    pub hold_id: Option<String>,
    /// Current state (one of the `PAYMENT_ATTEMPT_*` constants).
    pub state: String,
    /// Monotonic operation token bumped by every applied transition. Preserved
    /// through the generic storage scheduler so a stale reread across an async
    /// timeout is never mistaken for a failed transition.
    pub generation: i64,
    pub submitted_at_unix: Option<i64>,
    /// Base58 transaction signature recorded on settle.
    pub transaction_signature: Option<String>,
    /// Actual settled on-chain atomic amount (decimal string), when reported.
    pub settled_atomic_amount: Option<String>,
    /// Raw settlement response / evidence blob, when captured.
    pub settlement_response: Option<String>,
    /// Machine-readable failure reason on a failed/denied attempt.
    pub failure_code: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// An attempt joined to its live wallet hold and captured settlement (issue
/// #352 admin evidence: "Admin API joins attempt, hold, wallet settlement").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAttemptLinks {
    pub attempt: StoredPaymentAttempt,
    /// The linked reservation/hold, if `hold_id` is set and the row exists.
    pub reservation: Option<StoredWalletReservation>,
    /// The captured wallet settlement, if the hold was settled.
    pub settlement: Option<StoredWalletSettlement>,
}

/// Outcome of [`RuntimeStorageRepositories::create_payment_attempt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentAttemptCreation {
    /// A new attempt row was inserted.
    Created(StoredPaymentAttempt),
    /// The id already existed with a byte-equivalent immutable tuple; the
    /// existing row is returned (idempotent replay).
    Existing(StoredPaymentAttempt),
}

/// Outcome of a state transition CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentAttemptTransition {
    /// The CAS won: the attempt advanced into the target state.
    Applied(StoredPaymentAttempt),
    /// The attempt was already in the target state with matching evidence; the
    /// durable row is returned unchanged (idempotent replay).
    Idempotent(StoredPaymentAttempt),
}

/// Write-once evidence a transition records. `None` leaves the column unchanged
/// (`COALESCE(new, old)` in Postgres); a `Some` that would overwrite a differing
/// stored value on an idempotent replay fails closed as a `Conflict`.
#[derive(Debug, Clone, Default)]
struct TransitionEvidence<'a> {
    submitted_at_unix: Option<i64>,
    transaction_signature: Option<&'a str>,
    settled_atomic_amount: Option<&'a str>,
    settlement_response: Option<&'a str>,
    failure_code: Option<&'a str>,
}

/// Ordered column list shared by every `payment_attempts` read so the positional
/// [`payment_attempt_from_row`] indices stay in lockstep with the SQL.
const PAYMENT_ATTEMPT_COLUMNS: &str =
    "id, tenant_id, project_id, workspace_id, run_id, worker_id, \
     request_id, trace_id, method, resource_url, request_body_hash, challenge_hash, x402_version, \
     scheme, network_caip2, mint, atomic_amount, recipient, credits_amount, conversion_version, \
     policy_revision, decision, reason_code, hold_id, state, generation, submitted_at_unix, \
     transaction_signature, settled_atomic_amount, settlement_response, failure_code, \
     created_at_unix, updated_at_unix";

/// The shared [`PAYMENT_ATTEMPT_COLUMNS`] list, each column table-qualified
/// with `alias`. Needed only where `payment_attempts` is JOINed against
/// `wallet_reservations` (whose `id`/`tenant_id`/`created_at_unix`/
/// `updated_at_unix` collide), so the positional [`payment_attempt_from_row`]
/// indices still line up. The const is a single spaced line at compile time
/// (the source `\` line-continuations swallow the newlines), so a plain
/// comma-split + trim yields clean column names.
fn qualified_payment_attempt_columns(alias: &str) -> String {
    PAYMENT_ATTEMPT_COLUMNS
        .split(',')
        .map(|column| format!("{alias}.{}", column.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn payment_attempt_from_row(row: &PostgresRow) -> StoredPaymentAttempt {
    StoredPaymentAttempt {
        id: row.get(0),
        tenant_id: row.get(1),
        project_id: row.get(2),
        workspace_id: row.get(3),
        run_id: row.get(4),
        worker_id: row.get(5),
        request_id: row.get(6),
        trace_id: row.get(7),
        method: row.get(8),
        resource_url: row.get(9),
        request_body_hash: row.get(10),
        challenge_hash: row.get(11),
        x402_version: row.get(12),
        scheme: row.get(13),
        network_caip2: row.get(14),
        mint: row.get(15),
        atomic_amount: row.get(16),
        recipient: row.get(17),
        credits_amount: row.get(18),
        conversion_version: row.get(19),
        policy_revision: row.get(20),
        decision: row.get(21),
        reason_code: row.get(22),
        hold_id: row.get(23),
        state: row.get(24),
        generation: row.get(25),
        submitted_at_unix: row.get(26),
        transaction_signature: row.get(27),
        settled_atomic_amount: row.get(28),
        settlement_response: row.get(29),
        failure_code: row.get(30),
        created_at_unix: row.get(31),
        updated_at_unix: row.get(32),
    }
}

/// The immutable identity tuple. A create replay whose tuple differs from the
/// stored row is a conflicting challenge/transaction under the same idempotency
/// id and must fail closed.
fn immutable_tuple(a: &StoredPaymentAttempt) -> (&str, &str, i64, &str, &str, &str, &str, &str) {
    (
        &a.tenant_id,
        &a.challenge_hash,
        a.x402_version,
        &a.network_caip2,
        &a.mint,
        &a.atomic_amount,
        &a.recipient,
        &a.resource_url,
    )
}

/// On an idempotent replay (row already in the target state), a `Some` evidence
/// value that disagrees with the stored value is a conflict (e.g. a second,
/// different transaction signature for an already-settled attempt). Returns the
/// offending field name, or `None` when the replay is byte-equivalent.
fn evidence_conflict(
    stored: &StoredPaymentAttempt,
    evidence: &TransitionEvidence<'_>,
) -> Option<&'static str> {
    if let (Some(new), Some(old)) = (
        evidence.transaction_signature,
        stored.transaction_signature.as_deref(),
    ) {
        if new != old {
            return Some("transaction_signature");
        }
    }
    if let (Some(new), Some(old)) = (
        evidence.settled_atomic_amount,
        stored.settled_atomic_amount.as_deref(),
    ) {
        if new != old {
            return Some("settled_atomic_amount");
        }
    }
    if let (Some(new), Some(old)) = (evidence.failure_code, stored.failure_code.as_deref()) {
        if new != old {
            return Some("failure_code");
        }
    }
    None
}

/// Apply an already-fetched record's transition in memory, sharing the exact
/// classification logic the Postgres path uses. `record` is the current row.
fn apply_memory_transition(
    record: &StoredPaymentAttempt,
    allowed_from: &[&str],
    to_state: &str,
    evidence: &TransitionEvidence<'_>,
    now_unix: i64,
) -> Result<PaymentAttemptTransition, StorageError> {
    if allowed_from.contains(&record.state.as_str()) {
        let mut next = record.clone();
        next.state = to_state.to_string();
        next.generation += 1;
        next.updated_at_unix = now_unix;
        if let Some(v) = evidence.submitted_at_unix {
            next.submitted_at_unix = Some(v);
        }
        if let Some(v) = evidence.transaction_signature {
            next.transaction_signature = Some(v.to_string());
        }
        if let Some(v) = evidence.settled_atomic_amount {
            next.settled_atomic_amount = Some(v.to_string());
        }
        if let Some(v) = evidence.settlement_response {
            next.settlement_response = Some(v.to_string());
        }
        if let Some(v) = evidence.failure_code {
            next.failure_code = Some(v.to_string());
        }
        return Ok(PaymentAttemptTransition::Applied(next));
    }
    if record.state == to_state {
        if let Some(field) = evidence_conflict(record, evidence) {
            return Err(StorageError::Conflict(format!(
                "payment attempt {} replay into {to_state} changed {field}",
                record.id
            )));
        }
        return Ok(PaymentAttemptTransition::Idempotent(record.clone()));
    }
    Err(StorageError::Conflict(format!(
        "payment attempt {} cannot transition {} -> {to_state}",
        record.id, record.state
    )))
}

impl PostgresControlPlaneStore {
    fn payment_attempt_operation(&self, name: &'static str) -> StorageOperation {
        StorageOperation::new(name, self.async_pool.statement_timeout())
    }

    pub(super) async fn create_payment_attempt(
        &self,
        attempt: &StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        if !PAYMENT_ATTEMPT_INITIAL_STATES.contains(&attempt.state.as_str()) {
            return Err(StorageError::Conflict(format!(
                "payment attempt {} cannot be created in state {}",
                attempt.id, attempt.state
            )));
        }
        let operation = self.payment_attempt_operation("create payment attempt");
        let mut client = self
            .async_pool
            .acquire(operation.name(), operation.remaining("pool acquisition")?)
            .await?;
        // Pin `search_path` (#239) as the FIRST statement so `payment_attempts`
        // resolves in the configured schema, matching every wallet accessor.
        let transaction = client.transaction().await.map_err(postgres_error)?;
        if let Some(search_path_sql) = self.async_pool.transaction_search_path_sql() {
            transaction
                .batch_execute(search_path_sql)
                .await
                .map_err(postgres_error)?;
        }
        let inserted = transaction
            .execute(
                "INSERT INTO payment_attempts \
                 (id, tenant_id, project_id, workspace_id, run_id, worker_id, request_id, \
                  trace_id, method, resource_url, request_body_hash, challenge_hash, x402_version, \
                  scheme, network_caip2, mint, atomic_amount, recipient, credits_amount, \
                  conversion_version, policy_revision, decision, reason_code, hold_id, state, \
                  generation, submitted_at_unix, transaction_signature, settled_atomic_amount, \
                  settlement_response, failure_code, created_at_unix, updated_at_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
                  $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, \
                  $33) ON CONFLICT (id) DO NOTHING",
                &[
                    &attempt.id,
                    &attempt.tenant_id,
                    &attempt.project_id,
                    &attempt.workspace_id,
                    &attempt.run_id,
                    &attempt.worker_id,
                    &attempt.request_id,
                    &attempt.trace_id,
                    &attempt.method,
                    &attempt.resource_url,
                    &attempt.request_body_hash,
                    &attempt.challenge_hash,
                    &attempt.x402_version,
                    &attempt.scheme,
                    &attempt.network_caip2,
                    &attempt.mint,
                    &attempt.atomic_amount,
                    &attempt.recipient,
                    &attempt.credits_amount,
                    &attempt.conversion_version,
                    &attempt.policy_revision,
                    &attempt.decision,
                    &attempt.reason_code,
                    &attempt.hold_id,
                    &attempt.state,
                    &attempt.generation,
                    &attempt.submitted_at_unix,
                    &attempt.transaction_signature,
                    &attempt.settled_atomic_amount,
                    &attempt.settlement_response,
                    &attempt.failure_code,
                    &attempt.created_at_unix,
                    &attempt.updated_at_unix,
                ],
            )
            .await
            .map_err(postgres_error)?;

        if inserted == 1 {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(PaymentAttemptCreation::Created(attempt.clone()));
        }

        // Idempotent replay: the id already exists. Fail closed unless the
        // immutable identity tuple is byte-equivalent.
        let row = transaction
            .query_one(
                &format!("SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts WHERE id = $1"),
                &[&attempt.id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let existing = payment_attempt_from_row(&row);
        if immutable_tuple(&existing) != immutable_tuple(attempt) {
            return Err(StorageError::Conflict(format!(
                "payment attempt {} replay changed its immutable challenge tuple",
                attempt.id
            )));
        }
        Ok(PaymentAttemptCreation::Existing(existing))
    }

    #[allow(clippy::too_many_arguments)]
    async fn transition_payment_attempt(
        &self,
        op_name: &'static str,
        id: &str,
        allowed_from: &[&str],
        to_state: &str,
        evidence: &TransitionEvidence<'_>,
        now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError> {
        let operation = self.payment_attempt_operation(op_name);
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
        // One conditional CAS: advance the state and bump the generation only
        // while the row is still in an allowed source state. `COALESCE` keeps
        // write-once evidence fields immutable across replays.
        let allowed: Vec<&str> = allowed_from.to_vec();
        let updated = transaction
            .query_opt(
                &format!(
                    "UPDATE payment_attempts SET \
                     state = $1, generation = generation + 1, \
                     submitted_at_unix = COALESCE($2, submitted_at_unix), \
                     transaction_signature = COALESCE($3, transaction_signature), \
                     settled_atomic_amount = COALESCE($4, settled_atomic_amount), \
                     settlement_response = COALESCE($5, settlement_response), \
                     failure_code = COALESCE($6, failure_code), \
                     updated_at_unix = $7 \
                     WHERE id = $8 AND state = ANY($9) \
                     RETURNING {PAYMENT_ATTEMPT_COLUMNS}"
                ),
                &[
                    &to_state,
                    &evidence.submitted_at_unix,
                    &evidence.transaction_signature,
                    &evidence.settled_atomic_amount,
                    &evidence.settlement_response,
                    &evidence.failure_code,
                    &now_unix,
                    &id,
                    &allowed,
                ],
            )
            .await
            .map_err(postgres_error)?;
        if let Some(row) = updated {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(PaymentAttemptTransition::Applied(payment_attempt_from_row(
                &row,
            )));
        }

        // CAS did not apply: classify idempotent replay vs conflict vs missing.
        // This is a bounded classification read, never a wait/retry loop.
        let existing = transaction
            .query_opt(
                &format!("SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts WHERE id = $1"),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        let Some(row) = existing else {
            return Err(StorageError::NotFound(format!(
                "payment attempt {id} does not exist"
            )));
        };
        let record = payment_attempt_from_row(&row);
        if record.state == to_state {
            if let Some(field) = evidence_conflict(&record, evidence) {
                return Err(StorageError::Conflict(format!(
                    "payment attempt {id} replay into {to_state} changed {field}"
                )));
            }
            return Ok(PaymentAttemptTransition::Idempotent(record));
        }
        Err(StorageError::Conflict(format!(
            "payment attempt {id} cannot transition {} -> {to_state}",
            record.state
        )))
    }

    pub(super) async fn get_payment_attempt(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError> {
        let operation = self.payment_attempt_operation("get payment attempt");
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
                &format!("SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts WHERE id = $1"),
                &[&id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(row.as_ref().map(payment_attempt_from_row))
    }

    pub(super) async fn list_payment_attempts(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        let operation = self.payment_attempt_operation("list payment attempts");
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
        // Tenant-scoped BEFORE ordering, served by idx_payment_attempts_tenant_time.
        let rows = transaction
            .query(
                &format!(
                    "SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts \
                     WHERE tenant_id = $1 ORDER BY created_at_unix DESC, id ASC"
                ),
                &[&tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(payment_attempt_from_row).collect())
    }

    pub(super) async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError> {
        let operation = self.payment_attempt_operation("get payment attempt links");
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
        // Tenant ownership is enforced in the predicate: an attempt owned by
        // another tenant is indistinguishable from a missing one.
        let attempt_row = transaction
            .query_opt(
                &format!(
                    "SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts \
                     WHERE id = $1 AND tenant_id = $2"
                ),
                &[&id, &tenant_id],
            )
            .await
            .map_err(postgres_error)?;
        let Some(attempt_row) = attempt_row else {
            transaction.commit().await.map_err(postgres_error)?;
            return Ok(None);
        };
        let attempt = payment_attempt_from_row(&attempt_row);

        let (reservation, settlement) = if let Some(hold_id) = attempt.hold_id.as_deref() {
            let reservation_row = transaction
                .query_opt(
                    &format!(
                        "SELECT {} FROM wallet_reservations WHERE id = $1",
                        super::wallet::WALLET_RESERVATION_COLUMNS
                    ),
                    &[&hold_id],
                )
                .await
                .map_err(postgres_error)?;
            let settlement_row = transaction
                .query_opt(
                    &format!(
                        "SELECT {} FROM wallet_settlements WHERE id = $1",
                        super::wallet::WALLET_SETTLEMENT_COLUMNS
                    ),
                    &[&hold_id],
                )
                .await
                .map_err(postgres_error)?;
            (
                reservation_row
                    .as_ref()
                    .map(super::wallet::wallet_reservation_from_row),
                settlement_row
                    .as_ref()
                    .map(super::wallet::wallet_settlement_from_row),
            )
        } else {
            (None, None)
        };
        transaction.commit().await.map_err(postgres_error)?;
        Ok(Some(PaymentAttemptLinks {
            attempt,
            reservation,
            settlement,
        }))
    }

    /// TTL sweep read (#354): a bounded, indexed batch of attempts still in a
    /// pre-submission [`PAYMENT_ATTEMPT_EXPIRABLE_STATES`] state whose live
    /// (`active`) wallet hold expired at or before `due_at_or_before_unix`.
    /// Never scans the whole table: `LIMIT` caps the batch and the JOIN filters
    /// to only holds that are still live and past due. A `submitted`/terminal
    /// attempt, or one whose hold is already `settled`/`released`, is excluded
    /// so the sweeper can never release a hold whose money may have moved.
    /// Ordered oldest-due first for deterministic, drainable paging.
    pub(super) async fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        let operation = self.payment_attempt_operation("list expirable due payment attempts");
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
        let columns = qualified_payment_attempt_columns("pa");
        let expirable: Vec<&str> = PAYMENT_ATTEMPT_EXPIRABLE_STATES.to_vec();
        let rows = transaction
            .query(
                &format!(
                    "SELECT {columns} FROM payment_attempts pa \
                     JOIN wallet_reservations wr ON wr.id = pa.hold_id \
                     WHERE pa.state = ANY($1) AND wr.status = 'active' \
                       AND wr.expires_at_unix <= $2 \
                     ORDER BY wr.expires_at_unix ASC, pa.id ASC \
                     LIMIT $3"
                ),
                &[&expirable, &due_at_or_before_unix, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(payment_attempt_from_row).collect())
    }

    /// Reconcile read (#354): a bounded, indexed batch of post-submission
    /// attempts still in a non-terminal [`PAYMENT_ATTEMPT_RECONCILABLE_STATES`]
    /// state (`submitted`/`outcome_unknown`) that have not been re-checked since
    /// `checked_at_or_before_unix` (their `updated_at_unix` cursor). Never scans
    /// the whole table: the `state IN (...)` predicate is served by the partial
    /// `idx_payment_attempts_reconcile(updated_at_unix)` index over exactly those
    /// two in-flight states, and `LIMIT` caps the batch. Ordered
    /// oldest-checked-first so a due backlog drains deterministically and the
    /// most-overdue attempts reconcile first. No wallet JOIN: the reconciler
    /// resolves settlement from the attempt's own `transaction_signature` via an
    /// injected on-chain RPC seam, not from the hold row.
    pub(super) async fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: i64,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        let operation = self.payment_attempt_operation("list reconcilable payment attempts");
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
        let reconcilable: Vec<&str> = PAYMENT_ATTEMPT_RECONCILABLE_STATES.to_vec();
        let rows = transaction
            .query(
                &format!(
                    "SELECT {PAYMENT_ATTEMPT_COLUMNS} FROM payment_attempts \
                     WHERE state = ANY($1) AND updated_at_unix <= $2 \
                     ORDER BY updated_at_unix ASC, id ASC \
                     LIMIT $3"
                ),
                &[&reconcilable, &checked_at_or_before_unix, &limit],
            )
            .await
            .map_err(postgres_error)?;
        transaction.commit().await.map_err(postgres_error)?;
        Ok(rows.iter().map(payment_attempt_from_row).collect())
    }
}

impl RuntimeControlPlaneState {
    pub fn create_payment_attempt(
        &mut self,
        attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        if !PAYMENT_ATTEMPT_INITIAL_STATES.contains(&attempt.state.as_str()) {
            return Err(StorageError::Conflict(format!(
                "payment attempt {} cannot be created in state {}",
                attempt.id, attempt.state
            )));
        }
        if let Some(existing) = self.payment_attempts.get(&attempt.id) {
            if immutable_tuple(&existing) != immutable_tuple(&attempt) {
                return Err(StorageError::Conflict(format!(
                    "payment attempt {} replay changed its immutable challenge tuple",
                    attempt.id
                )));
            }
            return Ok(PaymentAttemptCreation::Existing(existing));
        }
        self.payment_attempts
            .insert(attempt.id.clone(), attempt.clone());
        Ok(PaymentAttemptCreation::Created(attempt))
    }

    fn transition_payment_attempt(
        &mut self,
        id: &str,
        allowed_from: &[&str],
        to_state: &str,
        evidence: &TransitionEvidence<'_>,
        now_unix: i64,
    ) -> Result<PaymentAttemptTransition, StorageError> {
        let Some(record) = self.payment_attempts.get(id) else {
            return Err(StorageError::NotFound(format!(
                "payment attempt {id} does not exist"
            )));
        };
        let outcome = apply_memory_transition(&record, allowed_from, to_state, evidence, now_unix)?;
        if let PaymentAttemptTransition::Applied(next) = &outcome {
            self.payment_attempts.insert(next.id.clone(), next.clone());
        }
        Ok(outcome)
    }

    pub fn get_payment_attempt(&self, id: &str) -> Option<StoredPaymentAttempt> {
        self.payment_attempts.get(id)
    }

    pub fn list_payment_attempts(&self, tenant_id: &str) -> Vec<StoredPaymentAttempt> {
        let mut attempts: Vec<StoredPaymentAttempt> = self
            .payment_attempts
            .list()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect();
        attempts.sort_by(|a, b| {
            b.created_at_unix
                .cmp(&a.created_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        attempts
    }

    pub fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Option<PaymentAttemptLinks> {
        let attempt = self.payment_attempts.get(id)?;
        if attempt.tenant_id != tenant_id {
            return None;
        }
        let (reservation, settlement) = match attempt.hold_id.as_deref() {
            Some(hold_id) => (
                self.wallet_reservations.get(hold_id),
                self.wallet_settlements.get(hold_id),
            ),
            None => (None, None),
        };
        Some(PaymentAttemptLinks {
            attempt,
            reservation,
            settlement,
        })
    }

    /// Memory twin of the Postgres TTL sweep read (#354). Same predicate
    /// (pre-submission state + live hold past due), same oldest-due-first order
    /// and `limit` cap, so a bounded batch drains identically across backends.
    pub fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: usize,
    ) -> Vec<StoredPaymentAttempt> {
        let mut due: Vec<(i64, StoredPaymentAttempt)> = self
            .payment_attempts
            .list()
            .into_iter()
            .filter(|attempt| PAYMENT_ATTEMPT_EXPIRABLE_STATES.contains(&attempt.state.as_str()))
            .filter_map(|attempt| {
                let hold_id = attempt.hold_id.as_deref()?;
                let reservation = self.wallet_reservations.get(hold_id)?;
                (reservation.status == super::wallet::WALLET_RESERVATION_ACTIVE
                    && reservation.expires_at_unix <= due_at_or_before_unix)
                    .then_some((reservation.expires_at_unix, attempt))
            })
            .collect();
        due.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
        due.into_iter()
            .take(limit)
            .map(|(_, attempt)| attempt)
            .collect()
    }

    /// Memory twin of the Postgres reconcile read (#354). Same predicate
    /// (post-submission reconcilable state whose `updated_at_unix` cursor is at
    /// or before the reconcile-check horizon), same oldest-checked-first order
    /// and `limit` cap, so a bounded batch drains identically across backends.
    pub fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: usize,
    ) -> Vec<StoredPaymentAttempt> {
        let mut due: Vec<StoredPaymentAttempt> = self
            .payment_attempts
            .list()
            .into_iter()
            .filter(|attempt| {
                PAYMENT_ATTEMPT_RECONCILABLE_STATES.contains(&attempt.state.as_str())
                    && attempt.updated_at_unix <= checked_at_or_before_unix
            })
            .collect();
        due.sort_by(|a, b| {
            a.updated_at_unix
                .cmp(&b.updated_at_unix)
                .then_with(|| a.id.cmp(&b.id))
        });
        due.into_iter().take(limit).collect()
    }
}

/// The typed transition edges of the truth table. Each maps to exactly one CAS
/// against a fixed set of allowed source states; callers cannot express an
/// arbitrary transition.
macro_rules! payment_attempt_transitions {
    ($( $(#[$meta:meta])* $method:ident, $op:literal, [$($from:expr),+], $to:expr, $ev:ident => $build:block );+ $(;)?) => {
        impl RuntimeStorageRepositories {
            $(
                $(#[$meta])*
                pub async fn $method(
                    &self,
                    id: &str,
                    evidence_args: PaymentAttemptEvidenceArgs<'_>,
                    now_unix: i64,
                ) -> Result<PaymentAttemptTransition, StorageError> {
                    #[allow(unused_variables)]
                    let $ev = &evidence_args;
                    let evidence: TransitionEvidence<'_> = $build;
                    const ALLOWED: &[&str] = &[$($from),+];
                    match &self.control_plane {
                        RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                            .lock()
                            .map_err(|_| StorageError::Runtime(
                                "memory control-plane lock poisoned".into(),
                            ))?
                            .transition_payment_attempt(id, ALLOWED, $to, &evidence, now_unix),
                        RuntimeControlPlaneBackend::Postgres(control_plane) => {
                            control_plane
                                .transition_payment_attempt(
                                    $op, id, ALLOWED, $to, &evidence, now_unix,
                                )
                                .await
                        }
                        RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                            super::control_plane_store_d1::unimplemented_surface(
                                "transition_payment_attempt",
                            ),
                        ),
                    }
                }
            )+
        }
    };
}

/// Evidence a caller supplies to a transition. Only the fields relevant to a
/// given edge are read; the rest are ignored by that edge's builder.
#[derive(Debug, Clone, Default)]
pub struct PaymentAttemptEvidenceArgs<'a> {
    pub submitted_at_unix: Option<i64>,
    pub transaction_signature: Option<&'a str>,
    pub settled_atomic_amount: Option<&'a str>,
    pub settlement_response: Option<&'a str>,
    pub failure_code: Option<&'a str>,
}

payment_attempt_transitions! {
    /// `challenged -> authorized` once policy allows and the hold is placed.
    authorize_payment_attempt, "authorize payment attempt",
        [PAYMENT_ATTEMPT_CHALLENGED], PAYMENT_ATTEMPT_AUTHORIZED,
        a => { TransitionEvidence::default() };

    /// `authorized -> submitted`: the signed proof went on-chain. After this a
    /// timeout is `outcome_unknown`, never a release. Persists the transaction
    /// signature the reconciler (#354) needs the moment it is known at submit,
    /// coupled to this same CAS (#399): a `submitted`/`outcome_unknown` attempt
    /// then carries a recoverable signature without waiting for a settle. The
    /// column is write-once (`COALESCE`); a differing signature on an idempotent
    /// replay fails closed via [`evidence_conflict`].
    submit_payment_attempt, "submit payment attempt",
        [PAYMENT_ATTEMPT_AUTHORIZED], PAYMENT_ATTEMPT_SUBMITTED,
        a => { TransitionEvidence {
            submitted_at_unix: a.submitted_at_unix,
            transaction_signature: a.transaction_signature,
            ..Default::default()
        } };

    /// `submitted | outcome_unknown -> settled`: durable on-chain evidence.
    /// Records the transaction signature; a second, differing signature for an
    /// already-settled attempt fails closed.
    settle_payment_attempt, "settle payment attempt",
        [PAYMENT_ATTEMPT_SUBMITTED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN], PAYMENT_ATTEMPT_SETTLED,
        a => { TransitionEvidence {
            transaction_signature: a.transaction_signature,
            settled_atomic_amount: a.settled_atomic_amount,
            settlement_response: a.settlement_response,
            ..Default::default()
        } };

    /// `submitted | outcome_unknown -> outcome_unknown`: post-submission
    /// ambiguity; retain the hold. The `outcome_unknown` self-edge is
    /// deliberate and load-bearing for the #354 reconciler: re-parking an
    /// already-`outcome_unknown` attempt is an *applied* transition (it bumps
    /// `generation` and `updated_at_unix`), not a no-op. `updated_at_unix` is
    /// the reconciler's bounded-backoff cursor -- its due-query only re-picks an
    /// attempt whose `updated_at_unix` is older than the reconcile-check delay,
    /// so advancing it on every "still pending" pass spaces the next on-chain
    /// re-check by that delay instead of hammering the RPC every tick. Still
    /// non-terminal, still hold-retained; only durable Settled/Failed evidence
    /// ever leaves this state.
    mark_payment_attempt_outcome_unknown, "mark payment attempt outcome unknown",
        [PAYMENT_ATTEMPT_SUBMITTED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN],
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
        a => { TransitionEvidence {
            transaction_signature: a.transaction_signature,
            settlement_response: a.settlement_response,
            ..Default::default()
        } };

    /// `challenged | authorized -> released`: definitive pre-submission
    /// cancellation/expiry. Never valid after submission.
    release_payment_attempt, "release payment attempt",
        [PAYMENT_ATTEMPT_CHALLENGED, PAYMENT_ATTEMPT_AUTHORIZED], PAYMENT_ATTEMPT_RELEASED,
        a => { TransitionEvidence { failure_code: a.failure_code, ..Default::default() } };

    /// `challenged -> denied`: policy refusal recorded for audit.
    deny_payment_attempt, "deny payment attempt",
        [PAYMENT_ATTEMPT_CHALLENGED], PAYMENT_ATTEMPT_DENIED,
        a => { TransitionEvidence { failure_code: a.failure_code, ..Default::default() } };

    /// `authorized | submitted | outcome_unknown -> failed`: durable evidence
    /// the payment did not settle.
    fail_payment_attempt, "fail payment attempt",
        [PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_SUBMITTED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN],
        PAYMENT_ATTEMPT_FAILED,
        a => { TransitionEvidence {
            failure_code: a.failure_code,
            settlement_response: a.settlement_response,
            ..Default::default()
        } };
}

impl RuntimeStorageRepositories {
    /// Creates a durable attempt row (idempotent on its id). See
    /// [`StoredPaymentAttempt`] for the immutable-tuple fail-closed contract.
    pub async fn create_payment_attempt(
        &self,
        attempt: StoredPaymentAttempt,
    ) -> Result<PaymentAttemptCreation, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .create_payment_attempt(attempt),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.create_payment_attempt(&attempt).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("create_payment_attempt"),
            ),
        }
    }

    pub async fn get_payment_attempt(
        &self,
        id: &str,
    ) -> Result<Option<StoredPaymentAttempt>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_payment_attempt(id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_payment_attempt(id).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("get_payment_attempt"),
            ),
        }
    }

    /// Lists a tenant's attempts newest-first for admin inspect (issue #352).
    /// Tenant-scoped before ordering; no blocking Postgres bridge in the path.
    pub async fn list_payment_attempts(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.list_payment_attempts(tenant_id))
                .unwrap_or_default()),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.list_payment_attempts(tenant_id).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("list_payment_attempts"),
            ),
        }
    }

    /// Joins an attempt to its wallet hold and captured settlement, enforcing
    /// tenant ownership (issue #352 admin evidence). `Ok(None)` when no such
    /// attempt is owned by `tenant_id`.
    pub async fn get_payment_attempt_links(
        &self,
        id: &str,
        tenant_id: &str,
    ) -> Result<Option<PaymentAttemptLinks>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map(|control_plane| control_plane.get_payment_attempt_links(id, tenant_id))
                .unwrap_or(None)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane.get_payment_attempt_links(id, tenant_id).await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => Err(
                super::control_plane_store_d1::unimplemented_surface("get_payment_attempt_links"),
            ),
        }
    }

    /// Bounded TTL sweep read (#354): up to `limit` attempts still in a
    /// pre-submission expirable state whose live wallet hold expired at or
    /// before `due_at_or_before_unix`, oldest-due first. The runtime sweeper
    /// feeds each id back through `X402SettlementLoop::expire_if_due`, which
    /// re-reads and re-checks under a fresh transaction, so a candidate that
    /// raced into `submitted` between this read and the release is still safe.
    pub async fn list_expirable_due_payment_attempts(
        &self,
        due_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .list_expirable_due_payment_attempts(due_at_or_before_unix, limit)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_expirable_due_payment_attempts(due_at_or_before_unix, limit as i64)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "list_expirable_due_payment_attempts",
                ))
            }
        }
    }

    /// Bounded reconcile read (#354): up to `limit` post-submission attempts in
    /// a non-terminal `submitted`/`outcome_unknown` state whose `updated_at_unix`
    /// re-check cursor is at or before `checked_at_or_before_unix`, oldest-first.
    /// The runtime reconciler queries an injected on-chain RPC seam for each
    /// attempt's `transaction_signature` and re-drives the settlement loop's
    /// SETTLE/FAIL edge (or re-parks `outcome_unknown`, advancing the cursor for
    /// bounded backoff) under the CAS `generation` token -- never a false
    /// terminal.
    pub async fn list_reconcilable_payment_attempts(
        &self,
        checked_at_or_before_unix: i64,
        limit: usize,
    ) -> Result<Vec<StoredPaymentAttempt>, StorageError> {
        match &self.control_plane {
            RuntimeControlPlaneBackend::Memory(control_plane) => Ok(control_plane
                .lock()
                .map_err(|_| StorageError::Runtime("memory control-plane lock poisoned".into()))?
                .list_reconcilable_payment_attempts(checked_at_or_before_unix, limit)),
            RuntimeControlPlaneBackend::Postgres(control_plane) => {
                control_plane
                    .list_reconcilable_payment_attempts(checked_at_or_before_unix, limit as i64)
                    .await
            }
            RuntimeControlPlaneBackend::CloudflareD1(_) => {
                Err(super::control_plane_store_d1::unimplemented_surface(
                    "list_reconcilable_payment_attempts",
                ))
            }
        }
    }
}
