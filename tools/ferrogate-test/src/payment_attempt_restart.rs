// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Durable x402 payment-attempt + wallet-hold restart coverage for
// the `*-restart` harness scenarios (issue #352 acceptance: "Postgres
// restart/durability coverage proves attempts and links survive restart").

//! # What this proves
//!
//! The `#352` storage slice landed the `payment_attempts` table (migration 52),
//! its state-machine CAS, and `get_payment_attempt_links` (attempt -> wallet
//! reservation -> wallet settlement). Its proof was in-memory plus SQL
//! inspection: the live-Postgres migration and CAS path stayed unproven, and no
//! `ferrogate-test *-restart` scenario carried payment attempts or their holds
//! in its verified set. This module closes exactly that gap.
//!
//! It seeds two attempts against the SAME live database the restart scenario's
//! gateway is configured for, through the SAME `ferrogate-storage` repository
//! API the runtime uses (the #188 guard: the harness must not re-derive the
//! write path in a second dialect), then re-opens a FRESH repository handle
//! after every gateway restart and asserts the durable rows read back
//! byte-identically to a locally computed expectation:
//!
//! * the **settled** leg -- `challenged -> authorized -> submitted -> settled`
//!   with its hold captured -- proves the full audit tuple, the terminal state,
//!   the recorded transaction signature, and the attempt -> reservation ->
//!   settlement join all survive restart;
//! * the **outcome_unknown** leg -- `challenged -> authorized -> submitted ->
//!   outcome_unknown` -- proves the money-critical invariant survives restart:
//!   a post-submission ambiguity is NOT reported as failed/released, and its
//!   wallet hold is still `active` (RETAINED) after the process comes back.
//!
//! After the restart it also re-drives the two edges an operator/reconciler
//! would replay against the recovered rows, because a restart is precisely when
//! a duplicate replay happens: settling again with the same signature is
//! `Idempotent` (never a second capture), and settling with a CONFLICTING
//! signature fails closed with `StorageError::Conflict`.
//!
//! # Why the repository API and not an Admin API
//!
//! There is no create-side Admin API for payment attempts, and the x402
//! negotiation transport binding is still open (`state_x402_negotiation.rs`
//! has no non-test caller yet, issue #381), so no operator-visible request can
//! mint an attempt at the time of writing. The harness is a Rust workspace
//! member exactly so it can drive the gateway's own contracts in that case
//! (AGENTS.md "Testing Architecture"). The wallet the holds are taken against
//! IS provisioned through the Admin API, so the tenant/wallet half of the fixture
//! is real operator input.

use anyhow::{bail, Context, Result};
use ferrogate_storage::{
    ControlPlaneDocuments, PaymentAttemptCreation, PaymentAttemptEvidenceArgs, PaymentAttemptLinks,
    PaymentAttemptTransition, PostgresStorageConfig, PostgresTlsMode, RuntimeStorageOptions,
    RuntimeStorageRepositories, StorageError, StorageProviderKind, StoredPaymentAttempt,
    WalletReservationResult, PAYMENT_ATTEMPT_CHALLENGED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
    PAYMENT_ATTEMPT_SETTLED, WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_SETTLED,
};
use sha2::{Digest, Sha256};
use tokio::runtime::{Builder, Runtime};

use crate::{
    constants::{ADMIN_AUTH, JSON_CONTENT},
    storage::{ControlPlaneRestartStorage, TursoRestartHarness, POSTGRES_RESTART_SCHEMA},
};

// ---------------------------------------------------------------------------
// The frozen money tuple (#350 wire contract / #351 policy output)
// ---------------------------------------------------------------------------
//
// Reused from the #351 spend-policy compliance fixture so the restart fixture
// and the policy fixture can never drift into describing two different
// payments.
use crate::x402_spend_policy::{CAIP2_DEVNET, MERCHANT, RESOURCE_URL, USDC_DEVNET_MINT};

/// Frozen x402 protocol version (the wire contract pins 2).
const X402_VERSION: i64 = 2;
/// Frozen scheme (the wire contract pins `exact`).
const SCHEME: &str = "exact";
/// Spend-policy revision that authorized these payments (#351).
const POLICY_REVISION: i64 = 7;
const DECISION_ALLOW: &str = "allow";
const REASON_ALLOWED: &str = "allowed";
const CONVERSION_VERSION: &str = "usdc-devnet-v1";

/// Fixed clock. Every timestamp the fixture writes is derived from this, so the
/// post-restart expectation is exact rather than "something recent".
const SEED_UNIX: i64 = 1_783_641_600;
const AUTHORIZE_UNIX: i64 = SEED_UNIX + 1;
const SUBMIT_UNIX: i64 = SEED_UNIX + 2;
const FINALIZE_UNIX: i64 = SEED_UNIX + 3;
/// Hold TTL. Deliberately long: this fixture must never be swept mid-scenario,
/// and the `outcome_unknown` leg's hold has to still be `active` after restart.
const HOLD_TTL_SECONDS: i64 = 86_400;

/// Wallet balance provisioned through the Admin API. Comfortably covers both
/// holds so the fixture never exercises the insufficient-funds path.
const WALLET_BALANCE_CREDITS: i64 = 10_000;

/// The settled leg: 250_000 atomic units of devnet USDC == 250 credits at the
/// fixture's 1/1000 conversion.
const SETTLED_ATOMIC_AMOUNT: &str = "250000";
const SETTLED_CREDITS: i64 = 250;
const SETTLED_SIGNATURE: &str = "5PaYmEnTaTtEmPtReStArTsEtTlEdSiGnAtUrE111111111111111111111111111";
const SETTLED_RESPONSE: &str = r#"{"success":true,"network":"solana-devnet"}"#;
/// A DIFFERENT signature for the same settled attempt. Replaying `settle` with
/// this must fail closed after the restart, never overwrite the recorded one.
const CONFLICTING_SIGNATURE: &str =
    "5cOnFlIcTiNgSiGnAtUrEfOrThEsAmEaTtEmPt2222222222222222222222222222";

/// The outcome_unknown leg: 125_000 atomic units == 125 credits.
const UNKNOWN_ATOMIC_AMOUNT: &str = "125000";
const UNKNOWN_CREDITS: i64 = 125;
const UNKNOWN_SIGNATURE: &str = "5uNkNoWnOuTcOmEsIgNaTuRePaRkEdAfTeRsUbMiT33333333333333333333333";
const UNKNOWN_RESPONSE: &str = r#"{"status":"pending","reason":"rpc_timeout"}"#;

/// The egress request body the payment unlocks; its SHA-256 is the durable
/// `request_body_hash`.
const REQUEST_BODY: &str = r#"{"city":"lisbon"}"#;
const REQUEST_METHOD: &str = "POST";

fn request_body_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_BODY.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Deterministic per-attempt challenge hash. The challenge hash is part of the
/// immutable identity tuple, so it must differ between the two legs -- two
/// distinct payments may never share one challenge.
fn challenge_hash(attempt_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"x402-restart-challenge:");
    hasher.update(attempt_id.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Ids + expectations for the two durable attempts a restart scenario carries.
/// Every id is derived from the scenario's per-run `resource_id`, so concurrent
/// scenarios (and repeated runs against a retained database) never collide.
pub(crate) struct DurablePaymentAttemptFixture {
    tenant_id: String,
    settled_attempt_id: String,
    settled_hold_id: String,
    unknown_attempt_id: String,
    unknown_hold_id: String,
}

impl DurablePaymentAttemptFixture {
    pub(crate) fn new(resource_id: &str) -> Self {
        Self {
            tenant_id: format!("{resource_id}-x402-tenant"),
            settled_attempt_id: format!("{resource_id}-x402-settled"),
            settled_hold_id: format!("{resource_id}-x402-settled-hold"),
            unknown_attempt_id: format!("{resource_id}-x402-unknown"),
            unknown_hold_id: format!("{resource_id}-x402-unknown-hold"),
        }
    }

    /// Operator input: register the tenant and fund its wallet through the
    /// Admin API. `payment_attempts.tenant_id` has a FK onto `tenants(id)`, so
    /// this also proves the attempt rows are tenant-owned by the database, not
    /// only by convention.
    pub(crate) fn provision_wallet(&self, case: &TursoRestartHarness) -> Result<()> {
        let tenant_id = &self.tenant_id;
        case.expect_json(
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &serde_json::json!({
                "id": tenant_id,
                "name": "Durable x402 restart tenant",
                "slug": tenant_id,
            })
            .to_string(),
            201,
            |body| {
                if body["tenant"]["id"] != tenant_id.as_str() {
                    bail!("tenant account create returned {}", body["tenant"]["id"]);
                }
                Ok(())
            },
        )?;
        case.expect_json(
            "POST",
            "/admin/v1/wallets",
            &[ADMIN_AUTH, JSON_CONTENT],
            &serde_json::json!({ "tenant_id": tenant_id }).to_string(),
            201,
            |_| Ok(()),
        )?;
        case.expect_json(
            "POST",
            &format!("/admin/v1/wallets/{tenant_id}/adjust"),
            &[ADMIN_AUTH, JSON_CONTENT],
            &serde_json::json!({ "delta_credits": WALLET_BALANCE_CREDITS }).to_string(),
            200,
            |body| {
                if body["wallet"]["balance_credits"] != WALLET_BALANCE_CREDITS {
                    bail!(
                        "wallet funding returned balance {}",
                        body["wallet"]["balance_credits"]
                    );
                }
                Ok(())
            },
        )
    }

    /// The row as it is first created: `challenged`, generation 0, no evidence.
    /// Both expectations below are derived from this by applying exactly the
    /// mutations the transitions apply, so the immutable audit tuple is
    /// identical by construction and a drift is a compile-time-visible edit.
    fn seed_record(&self, leg: AttemptLeg) -> StoredPaymentAttempt {
        let (id, hold_id, atomic_amount, credits) = match leg {
            AttemptLeg::Settled => (
                &self.settled_attempt_id,
                &self.settled_hold_id,
                SETTLED_ATOMIC_AMOUNT,
                SETTLED_CREDITS,
            ),
            AttemptLeg::OutcomeUnknown => (
                &self.unknown_attempt_id,
                &self.unknown_hold_id,
                UNKNOWN_ATOMIC_AMOUNT,
                UNKNOWN_CREDITS,
            ),
        };
        StoredPaymentAttempt {
            id: id.clone(),
            tenant_id: self.tenant_id.clone(),
            project_id: Some(format!("{}-project", self.tenant_id)),
            workspace_id: Some(format!("{}-workspace", self.tenant_id)),
            run_id: Some(format!("{id}-run")),
            worker_id: Some(format!("{id}-worker")),
            request_id: Some(format!("{id}-request")),
            trace_id: Some(format!("{id}-trace")),
            method: REQUEST_METHOD.to_string(),
            resource_url: RESOURCE_URL.to_string(),
            request_body_hash: Some(request_body_hash()),
            challenge_hash: challenge_hash(id),
            x402_version: X402_VERSION,
            scheme: SCHEME.to_string(),
            network_caip2: CAIP2_DEVNET.to_string(),
            mint: USDC_DEVNET_MINT.to_string(),
            atomic_amount: atomic_amount.to_string(),
            recipient: MERCHANT.to_string(),
            credits_amount: Some(credits),
            conversion_version: Some(CONVERSION_VERSION.to_string()),
            policy_revision: POLICY_REVISION,
            decision: DECISION_ALLOW.to_string(),
            reason_code: REASON_ALLOWED.to_string(),
            hold_id: Some(hold_id.clone()),
            state: PAYMENT_ATTEMPT_CHALLENGED.to_string(),
            generation: 0,
            submitted_at_unix: None,
            transaction_signature: None,
            settled_atomic_amount: None,
            settlement_response: None,
            failure_code: None,
            created_at_unix: SEED_UNIX,
            updated_at_unix: SEED_UNIX,
        }
    }

    /// `challenged -> authorized -> submitted -> settled`: three applied
    /// transitions, so `generation` is 3.
    pub(crate) fn expected_settled(&self) -> StoredPaymentAttempt {
        let mut record = self.seed_record(AttemptLeg::Settled);
        record.state = PAYMENT_ATTEMPT_SETTLED.to_string();
        record.generation = 3;
        record.submitted_at_unix = Some(SUBMIT_UNIX);
        record.transaction_signature = Some(SETTLED_SIGNATURE.to_string());
        record.settled_atomic_amount = Some(SETTLED_ATOMIC_AMOUNT.to_string());
        record.settlement_response = Some(SETTLED_RESPONSE.to_string());
        record.updated_at_unix = FINALIZE_UNIX;
        record
    }

    /// `challenged -> authorized -> submitted -> outcome_unknown`: also three
    /// applied transitions. Non-terminal, and its hold must stay `active`.
    pub(crate) fn expected_outcome_unknown(&self) -> StoredPaymentAttempt {
        let mut record = self.seed_record(AttemptLeg::OutcomeUnknown);
        record.state = PAYMENT_ATTEMPT_OUTCOME_UNKNOWN.to_string();
        record.generation = 3;
        record.submitted_at_unix = Some(SUBMIT_UNIX);
        record.transaction_signature = Some(UNKNOWN_SIGNATURE.to_string());
        record.settlement_response = Some(UNKNOWN_RESPONSE.to_string());
        record.updated_at_unix = FINALIZE_UNIX;
        record
    }

    /// Writes both legs through the runtime's own repository API against the
    /// live database, then drops the pool. Called while the FIRST gateway of a
    /// restart scenario is up.
    pub(crate) fn seed(&self, storage: ControlPlaneRestartStorage<'_>) -> Result<()> {
        let (runtime, repositories) = open_repositories(storage)?;
        runtime.block_on(async {
            self.seed_settled(&repositories).await?;
            self.seed_outcome_unknown(&repositories).await
        })
    }

    async fn seed_settled(&self, repositories: &RuntimeStorageRepositories) -> Result<()> {
        expect_reserved(
            repositories,
            &self.settled_hold_id,
            &self.tenant_id,
            SETTLED_CREDITS,
        )
        .await?;

        let created = repositories
            .create_payment_attempt(self.seed_record(AttemptLeg::Settled))
            .await
            .context("create settled payment attempt")?;
        if !matches!(created, PaymentAttemptCreation::Created(_)) {
            bail!(
                "settled payment attempt {} already existed",
                self.settled_attempt_id
            );
        }

        expect_applied(
            repositories
                .authorize_payment_attempt(
                    &self.settled_attempt_id,
                    PaymentAttemptEvidenceArgs::default(),
                    AUTHORIZE_UNIX,
                )
                .await,
            "authorize settled attempt",
        )?;
        expect_applied(
            repositories
                .submit_payment_attempt(
                    &self.settled_attempt_id,
                    PaymentAttemptEvidenceArgs {
                        submitted_at_unix: Some(SUBMIT_UNIX),
                        transaction_signature: Some(SETTLED_SIGNATURE),
                        ..Default::default()
                    },
                    SUBMIT_UNIX,
                )
                .await,
            "submit settled attempt",
        )?;
        expect_applied(
            repositories
                .settle_payment_attempt(
                    &self.settled_attempt_id,
                    PaymentAttemptEvidenceArgs {
                        transaction_signature: Some(SETTLED_SIGNATURE),
                        settled_atomic_amount: Some(SETTLED_ATOMIC_AMOUNT),
                        settlement_response: Some(SETTLED_RESPONSE),
                        ..Default::default()
                    },
                    FINALIZE_UNIX,
                )
                .await,
            "settle settled attempt",
        )?;

        // Crossing into `settled` captures exactly the one linked hold (#281).
        let capture = repositories
            .settle_wallet_reservation(&self.settled_hold_id, FINALIZE_UNIX)
            .await
            .context("capture the settled attempt's wallet hold")?;
        if !capture.newly_applied || capture.settlement.delta_credits != -SETTLED_CREDITS {
            bail!("settled hold capture was not a single exact-amount debit: {capture:?}");
        }
        Ok(())
    }

    async fn seed_outcome_unknown(&self, repositories: &RuntimeStorageRepositories) -> Result<()> {
        expect_reserved(
            repositories,
            &self.unknown_hold_id,
            &self.tenant_id,
            UNKNOWN_CREDITS,
        )
        .await?;

        let created = repositories
            .create_payment_attempt(self.seed_record(AttemptLeg::OutcomeUnknown))
            .await
            .context("create outcome_unknown payment attempt")?;
        if !matches!(created, PaymentAttemptCreation::Created(_)) {
            bail!(
                "outcome_unknown payment attempt {} already existed",
                self.unknown_attempt_id
            );
        }

        expect_applied(
            repositories
                .authorize_payment_attempt(
                    &self.unknown_attempt_id,
                    PaymentAttemptEvidenceArgs::default(),
                    AUTHORIZE_UNIX,
                )
                .await,
            "authorize outcome_unknown attempt",
        )?;
        expect_applied(
            repositories
                .submit_payment_attempt(
                    &self.unknown_attempt_id,
                    PaymentAttemptEvidenceArgs {
                        submitted_at_unix: Some(SUBMIT_UNIX),
                        transaction_signature: Some(UNKNOWN_SIGNATURE),
                        ..Default::default()
                    },
                    SUBMIT_UNIX,
                )
                .await,
            "submit outcome_unknown attempt",
        )?;
        // Post-submission ambiguity. The hold is deliberately NOT released.
        expect_applied(
            repositories
                .mark_payment_attempt_outcome_unknown(
                    &self.unknown_attempt_id,
                    PaymentAttemptEvidenceArgs {
                        transaction_signature: Some(UNKNOWN_SIGNATURE),
                        settlement_response: Some(UNKNOWN_RESPONSE),
                        ..Default::default()
                    },
                    FINALIZE_UNIX,
                )
                .await,
            "park outcome_unknown attempt",
        )?;
        Ok(())
    }

    /// Re-opens a FRESH repository handle (new pool, new connections, after the
    /// gateway process was killed and restarted) and asserts both durable rows
    /// and their wallet links read back exactly as seeded.
    pub(crate) fn expect_durable_after_restart(
        &self,
        storage: ControlPlaneRestartStorage<'_>,
        label: &str,
    ) -> Result<()> {
        let (runtime, repositories) = open_repositories(storage)?;
        runtime.block_on(async {
            let settled = self.expect_links(&repositories, &self.settled_attempt_id, label).await?;
            expect_attempt_eq(&settled.attempt, &self.expected_settled(), label)?;
            expect_reservation(
                &settled,
                &self.settled_hold_id,
                SETTLED_CREDITS,
                WALLET_RESERVATION_SETTLED,
                label,
            )?;
            match settled.settlement.as_ref() {
                Some(settlement) if settlement.delta_credits == -SETTLED_CREDITS => {}
                other => bail!(
                    "{label}: settled attempt {} lost its wallet settlement across restart: {other:?}",
                    self.settled_attempt_id
                ),
            }

            let unknown = self.expect_links(&repositories, &self.unknown_attempt_id, label).await?;
            expect_attempt_eq(&unknown.attempt, &self.expected_outcome_unknown(), label)?;
            // The load-bearing money invariant: post-submission ambiguity is not
            // proof the money did not move, so the hold must still be live and
            // uncaptured after the restart.
            expect_reservation(
                &unknown,
                &self.unknown_hold_id,
                UNKNOWN_CREDITS,
                WALLET_RESERVATION_ACTIVE,
                label,
            )?;
            if unknown.settlement.is_some() {
                bail!(
                    "{label}: outcome_unknown attempt {} captured its hold across restart",
                    self.unknown_attempt_id
                );
            }

            // Tenant ownership is enforced on the join, not assumed.
            if repositories
                .get_payment_attempt_links(&self.settled_attempt_id, "some-other-tenant")
                .await
                .context("cross-tenant payment attempt link read")?
                .is_some()
            {
                bail!(
                    "{label}: payment attempt {} is readable by a foreign tenant",
                    self.settled_attempt_id
                );
            }

            // The tenant-scoped admin listing recovers both attempts.
            let listed = repositories
                .list_payment_attempts(
                    &self.tenant_id,
                    &ferrogate_storage::PaymentAttemptQuery::new(16),
                )
                .await
                .context("list payment attempts after restart")?;
            if listed.next_cursor.is_some() {
                bail!("{label}: a 16-row page over 2 attempts must end the listing");
            }
            let mut listed_ids: Vec<&str> = listed.attempts.iter().map(|a| a.id.as_str()).collect();
            listed_ids.sort_unstable();
            let mut expected_ids = [
                self.settled_attempt_id.as_str(),
                self.unknown_attempt_id.as_str(),
            ];
            expected_ids.sort_unstable();
            if listed_ids != expected_ids {
                bail!("{label}: tenant listing returned {listed_ids:?}, expected {expected_ids:?}");
            }

            self.expect_replay_after_restart(&repositories, label).await
        })
    }

    /// A restart is exactly when a duplicate settle-evidence replay happens: the
    /// caller that crashed mid-finalize comes back and re-drives its edge.
    /// Replaying the SAME evidence must be idempotent; a CONFLICTING
    /// transaction signature must fail closed instead of rewriting the record.
    async fn expect_replay_after_restart(
        &self,
        repositories: &RuntimeStorageRepositories,
        label: &str,
    ) -> Result<()> {
        let replay = repositories
            .settle_payment_attempt(
                &self.settled_attempt_id,
                PaymentAttemptEvidenceArgs {
                    transaction_signature: Some(SETTLED_SIGNATURE),
                    settled_atomic_amount: Some(SETTLED_ATOMIC_AMOUNT),
                    settlement_response: Some(SETTLED_RESPONSE),
                    ..Default::default()
                },
                FINALIZE_UNIX + 10,
            )
            .await
            .context("replay settle after restart")?;
        match replay {
            PaymentAttemptTransition::Idempotent(record) => {
                expect_attempt_eq(&record, &self.expected_settled(), label)?;
            }
            PaymentAttemptTransition::Applied(_) => bail!(
                "{label}: replayed settle of {} applied a SECOND capture",
                self.settled_attempt_id
            ),
        }

        match repositories
            .settle_payment_attempt(
                &self.settled_attempt_id,
                PaymentAttemptEvidenceArgs {
                    transaction_signature: Some(CONFLICTING_SIGNATURE),
                    settled_atomic_amount: Some(SETTLED_ATOMIC_AMOUNT),
                    ..Default::default()
                },
                FINALIZE_UNIX + 11,
            )
            .await
        {
            Err(StorageError::Conflict(_)) => {}
            other => bail!(
                "{label}: conflicting transaction evidence for {} did not fail closed: {other:?}",
                self.settled_attempt_id
            ),
        }

        // The failed-closed conflict changed nothing.
        let after = repositories
            .get_payment_attempt(&self.settled_attempt_id)
            .await
            .context("reread settled attempt after conflicting evidence")?
            .with_context(|| {
                format!("{label}: settled attempt vanished after a rejected replay")
            })?;
        expect_attempt_eq(&after, &self.expected_settled(), label)
    }

    async fn expect_links(
        &self,
        repositories: &RuntimeStorageRepositories,
        attempt_id: &str,
        label: &str,
    ) -> Result<PaymentAttemptLinks> {
        repositories
            .get_payment_attempt_links(attempt_id, &self.tenant_id)
            .await
            .with_context(|| format!("{label}: read payment attempt links for {attempt_id}"))?
            .with_context(|| {
                format!("{label}: payment attempt {attempt_id} did not survive the restart")
            })
    }
}

#[derive(Clone, Copy)]
enum AttemptLeg {
    Settled,
    OutcomeUnknown,
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Field-by-field so a durability regression names the column that drifted
/// instead of dumping two 33-field structs.
fn expect_attempt_eq(
    actual: &StoredPaymentAttempt,
    expected: &StoredPaymentAttempt,
    label: &str,
) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    let mut drift = Vec::new();
    let mut compare = |field: &str, actual: String, expected: String| {
        if actual != expected {
            drift.push(format!("{field}: got {actual}, expected {expected}"));
        }
    };
    compare("state", actual.state.clone(), expected.state.clone());
    compare(
        "generation",
        actual.generation.to_string(),
        expected.generation.to_string(),
    );
    compare(
        "hold_id",
        format!("{:?}", actual.hold_id),
        format!("{:?}", expected.hold_id),
    );
    compare(
        "transaction_signature",
        format!("{:?}", actual.transaction_signature),
        format!("{:?}", expected.transaction_signature),
    );
    compare(
        "settled_atomic_amount",
        format!("{:?}", actual.settled_atomic_amount),
        format!("{:?}", expected.settled_atomic_amount),
    );
    compare(
        "atomic_amount",
        actual.atomic_amount.clone(),
        expected.atomic_amount.clone(),
    );
    compare(
        "challenge_hash",
        actual.challenge_hash.clone(),
        expected.challenge_hash.clone(),
    );
    compare(
        "submitted_at_unix",
        format!("{:?}", actual.submitted_at_unix),
        format!("{:?}", expected.submitted_at_unix),
    );
    compare(
        "updated_at_unix",
        actual.updated_at_unix.to_string(),
        expected.updated_at_unix.to_string(),
    );
    if drift.is_empty() {
        drift.push(format!("got {actual:?}, expected {expected:?}"));
    }
    bail!(
        "{label}: payment attempt {} did not read back identically after restart: {}",
        expected.id,
        drift.join("; ")
    )
}

fn expect_reservation(
    links: &PaymentAttemptLinks,
    hold_id: &str,
    amount_credits: i64,
    status: &str,
    label: &str,
) -> Result<()> {
    let Some(reservation) = links.reservation.as_ref() else {
        bail!(
            "{label}: attempt {} lost its wallet reservation link across restart",
            links.attempt.id
        );
    };
    if reservation.id != hold_id
        || reservation.amount_credits != amount_credits
        || reservation.status != status
    {
        bail!(
            "{label}: attempt {} linked hold is {:?}, expected id {hold_id} amount {amount_credits} status {status}",
            links.attempt.id,
            reservation
        );
    }
    Ok(())
}

async fn expect_reserved(
    repositories: &RuntimeStorageRepositories,
    hold_id: &str,
    tenant_id: &str,
    amount_credits: i64,
) -> Result<()> {
    let result = repositories
        .reserve_wallet_credits(
            hold_id,
            tenant_id,
            amount_credits,
            SEED_UNIX + HOLD_TTL_SECONDS,
            SEED_UNIX,
        )
        .await
        .with_context(|| format!("reserve wallet credits for hold {hold_id}"))?;
    match result {
        WalletReservationResult::Reserved(reservation)
            if reservation.amount_credits == amount_credits
                && reservation.status == WALLET_RESERVATION_ACTIVE => {}
        other => bail!("hold {hold_id} was not reserved as an active exact-amount hold: {other:?}"),
    }
    Ok(())
}

fn expect_applied(
    result: Result<PaymentAttemptTransition, StorageError>,
    what: &str,
) -> Result<()> {
    match result.with_context(|| what.to_string())? {
        PaymentAttemptTransition::Applied(_) => Ok(()),
        PaymentAttemptTransition::Idempotent(record) => bail!(
            "{what} was an idempotent replay, not a fresh transition: {}",
            record.state
        ),
    }
}

// ---------------------------------------------------------------------------
// Repository handle
// ---------------------------------------------------------------------------

/// Opens a repository handle against the SAME database the restart scenario's
/// gateway uses. `initialize_schema: false` + `validate_only` because the
/// gateway already applied (and validated) the migrations; this handle must
/// never race the gateway on DDL.
///
/// The `ferrogate-test` binary has a plain sync `main`, so the async repository
/// API is bridged with a dedicated current-thread runtime -- the same pattern
/// `compliance.rs` uses for its live-repository replay contract. The runtime is
/// returned alongside the repositories so both drop together, which is what
/// makes the post-restart read a genuinely fresh pool.
fn open_repositories(
    storage: ControlPlaneRestartStorage<'_>,
) -> Result<(Runtime, RuntimeStorageRepositories)> {
    let (dsn, tls, schema, provider) = match storage {
        ControlPlaneRestartStorage::Postgres { dsn, tls } => (
            dsn,
            tls,
            POSTGRES_RESTART_SCHEMA.to_string(),
            StorageProviderKind::Postgres,
        ),
        ControlPlaneRestartStorage::Supabase {
            dsn, tls, schema, ..
        } => (dsn, tls, schema.to_string(), StorageProviderKind::Supabase),
    };
    let tls_mode = match tls.mode {
        "disable" => PostgresTlsMode::Disable,
        "prefer" => PostgresTlsMode::Prefer,
        "require" => PostgresTlsMode::Require,
        "verify_ca" => PostgresTlsMode::VerifyCa,
        "verify_full" => PostgresTlsMode::VerifyFull,
        other => bail!("unsupported restart TLS mode {other} for the payment-attempt fixture"),
    };
    let config = PostgresStorageConfig {
        dsn: dsn.to_string(),
        // One connection: this handle runs alongside a live gateway and must not
        // compete with it for the database's connection budget.
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode,
        tls_ca_cert_path: tls
            .ca_cert_path
            .map(|path| path.to_string_lossy().into_owned()),
        connect_timeout_secs: 10,
        statement_timeout_millis: 30_000,
        schema: Some(schema),
        search_path: vec!["public".into()],
    };
    let options = RuntimeStorageOptions {
        provider_order: vec![StorageProviderKind::Supabase, StorageProviderKind::Postgres],
        required: true,
        initialize_schema: false,
        migration_mode: "validate_only".into(),
        control_plane: ControlPlaneDocuments::default(),
        request_log_retention_records: 0,
        audit_event_retention_records: 0,
    };
    let repositories = match provider {
        StorageProviderKind::Supabase => RuntimeStorageRepositories::supabase(config, options),
        _ => RuntimeStorageRepositories::postgres(config, options),
    }
    .context("open a payment-attempt repository handle against the restart database")?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build the payment-attempt async bridge runtime")?;
    Ok((runtime, repositories))
}

#[cfg(test)]
#[path = "payment_attempt_restart_test.rs"]
mod payment_attempt_restart_test;
