// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: The narrow cross-component paid-egress chain command promised by
// issue #354's Verification section: operator config -> gateway policy decision
// -> deterministic paid-origin double -> durable payment-attempt/wallet-hold
// ledger -> re-drive/reconcile, proving the loop-closure boxes end to end.

//! # `x402-paid-egress-chain`
//!
//! ## What this command closes
//!
//! `#354` landed the settle/release/outcome-unknown state machine, the TTL
//! sweeper, and the on-chain reconciler, each with unit coverage. Its own
//! Verification section additionally promises "the narrow cross-component chain
//! command added by this slice", and the loop-closure acceptance boxes are
//! chain-shaped rather than unit-shaped:
//!
//! * **exactly one** origin side effect, **one** settlement evidence record and
//!   **one** wallet capture per authorized payment -- including under a re-drive;
//! * a policy **denial never invokes the signer or the paid replay**;
//! * post-submission ambiguity parks `outcome_unknown` with the hold
//!   **RETAINED**, and a restart lands every attempt in a **documented** state,
//!   never an invented one;
//! * **reconciliation is idempotent**: re-running it converges rather than
//!   double-capturing or falsely releasing.
//!
//! Those are statements about three components agreeing -- the gateway that
//! authorizes, the merchant that charges, and the ledger that holds and captures
//! the money -- so they are provable only by driving all three in one run. This
//! command does exactly that and nothing wider.
//!
//! ## The three components, and where each one really is
//!
//! 1. **The gateway.** A real `ferrogate` process started from the harness's own
//!    operator config, which already declares the `#351` scoped x402 spend
//!    policies (`fixtures.rs` embeds [`x402_spend_policies_toml`]). Every payment
//!    in this chain is authorized by `POST
//!    /admin/v1/x402-spend-policies/evaluate` against the untrusted challenge the
//!    merchant actually sent -- the same policy evaluation the payment path runs.
//!    Nothing is paid that the gateway did not answer `allow` for.
//!
//! 2. **The merchant.** [`PaidOriginDouble`], a deterministic local origin +
//!    facilitator double. It answers an unpaid dispatch with a `402` carrying a
//!    real V2 Solana `exact` challenge, serves the resource on a paid replay, and
//!    -- the load-bearing part -- **counts side effects by payment identity**, so
//!    a duplicate replay of the same proof is served from its idempotency cache
//!    without producing a second side effect. Its facilitator endpoint answers
//!    the reconciler's on-chain question, `pending` first and `confirmed` after,
//!    so bounded backoff and convergence are both exercised.
//!
//! 3. **The ledger.** The runtime's own [`RuntimeStorageRepositories`] -- the
//!    same repository API `X402SettlementLoop`, the TTL sweeper and the on-chain
//!    reconciler drive -- carrying the `payment_attempts` CAS (#352) and the
//!    wallet holds (#281).
//!
//! ## Why the ledger is driven through the repository API
//!
//! There is no operator-visible request that can mint a payment attempt yet: the
//! x402 transport binding is still open (`state_x402_negotiation.rs` has no
//! non-test caller, issue #381), and `ferrogate-cli` is a binary-only crate, so
//! the harness cannot call `X402SettlementLoop` in-process either. The harness is
//! a Rust workspace member precisely so that in this case it can drive the
//! gateway's own contracts rather than re-derive the write path in a second
//! dialect (AGENTS.md "Testing Architecture"); `payment_attempt_restart.rs`
//! established the same seam for the `*-restart` scenarios. The money tuple is
//! not invented here either: the atomic amount and the integer credits this
//! command holds and captures are the ones the **gateway** computed and returned,
//! and the settlement evidence is the one the **merchant** actually sent.
//!
//! ## What this command does NOT prove
//!
//! Durable survival of these rows across a real process restart. That needs a
//! live database, and it is already covered by `payment_attempt_restart.rs`
//! inside the `postgres-restart` / `supabase-restart` scenarios. What the restart
//! stage here proves instead is the property that does not need a database: the
//! gateway comes back and re-issues a **byte-identical authorization** for the
//! same challenge, and every attempt the chain produced sits in a member of the
//! **documented** state set with the hold disposition that state documents -- so
//! a post-restart re-drive is attributable to the same authorization and cannot
//! double-charge.

use std::{
    collections::HashMap,
    io::Write as _,
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ferrogate_storage::{
    PaymentAttemptCreation, PaymentAttemptEvidenceArgs, PaymentAttemptLinks,
    PaymentAttemptTransition, RuntimeStorageRepositories, StoredPaymentAttempt, StoredWallet,
    WalletReservationResult, PAYMENT_ATTEMPT_AUTHORIZED, PAYMENT_ATTEMPT_CHALLENGED,
    PAYMENT_ATTEMPT_DENIED, PAYMENT_ATTEMPT_FAILED, PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
    PAYMENT_ATTEMPT_RELEASED, PAYMENT_ATTEMPT_SETTLED, PAYMENT_ATTEMPT_SUBMITTED,
    WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_SETTLED,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::runtime::{Builder, Runtime};

use crate::{
    cli::LocalArgs,
    constants::{ADMIN_AUTH, JSON_CONTENT},
    http::http_request_addr,
    local::LocalHarness,
    x402_spend_policy::{
        challenge_header, CAIP2_DEVNET, MERCHANT, RESOURCE_URL, TENANT_ID, TENANT_REVISION,
        USDC_DEVNET_MINT,
    },
};

// ---------------------------------------------------------------------------
// The frozen money tuple
// ---------------------------------------------------------------------------
//
// Reused wholesale from the #351 spend-policy fixture (network, mint, merchant,
// resource URL, tenant scope) so the chain and the policy contract can never
// drift into describing two different payments. Only the per-leg amounts are
// local, and each one is chosen to land on a DIFFERENT side of the declared
// caps.

/// 2500 atomic units / 1000 = 3 credits: inside every declared cap and below the
/// approval threshold, so the tenant-scope policy answers `allow`.
const ALLOWED_ATOMIC_AMOUNT: u64 = 2_500;
/// The gateway's own integer conversion of [`ALLOWED_ATOMIC_AMOUNT`]. Asserted
/// against what the gateway reports rather than trusted -- it is here so a
/// silent conversion change is a chain failure, not a quietly different charge.
const ALLOWED_CREDITS: i64 = 3;
/// 1_500_000 atomic = 1500 credits: over the 1000-credit per-payment cap, so the
/// same policy answers `deny`. This payment must never reach the merchant.
const DENIED_ATOMIC_AMOUNT: u64 = 1_500_000;

/// Starting prepaid balance. Large enough that no leg is ever refused for funds,
/// so a balance drift can only come from a capture.
const WALLET_BALANCE_CREDITS: i64 = 10_000;
/// Every authorized payment in this chain costs the same 3 credits, and exactly
/// two of them are ever captured (the settled leg and the reconciled leg), so
/// the whole-chain expectation is one exact integer.
const EXPECTED_CAPTURES: i64 = 2;

/// Fixed clock. Every timestamp the chain writes derives from this, so an
/// assertion is an exact equality rather than "something recent".
const CHAIN_UNIX: i64 = 1_783_641_600;
const HOLD_TTL_SECONDS: i64 = 86_400;
/// The reconciler's bounded re-check delay, mirrored from `X402ReconcilerConfig`'s
/// default so the due-query cursor assertions describe the shipped behaviour.
const RECONCILE_CHECK_DELAY_SECONDS: i64 = 60;
/// The chain's clock never runs backwards: every edge is stamped from one
/// ordered sequence, so `updated_at_unix` -- which is the reconciler's own
/// backoff cursor -- stays monotonic across legs. A leg that rewound the cursor
/// would make the due-query assertions describe an ordering the runtime never
/// produces.
const SETTLE_UNIX: i64 = CHAIN_UNIX + 4;
/// The reconciled leg settles only AFTER a full pending/backoff pass.
const RECONCILE_SETTLE_UNIX: i64 = CHAIN_UNIX + 3 + RECONCILE_CHECK_DELAY_SECONDS + 1;
/// Well past every in-run edge: the post-restart replay is the last write.
const RESTART_REPLAY_UNIX: i64 = CHAIN_UNIX + 3 + RECONCILE_CHECK_DELAY_SECONDS + 100;

const REQUEST_METHOD: &str = "GET";
const X402_VERSION: i64 = 2;
const SCHEME: &str = "exact";
const CONVERSION_VERSION: &str = "usdc-devnet-v1";
const DECISION_ALLOW: &str = "allow";
const DECISION_DENY: &str = "deny";
const REASON_ALLOWED: &str = "x402_allowed";
const REASON_OVER_CAP: &str = "x402_over_per_payment_cap";

/// Every state the `#354` loop can leave an attempt in. A restart must land in
/// one of these; anything else is an invented state and fails the chain.
const DOCUMENTED_ATTEMPT_STATES: &[&str] = &[
    PAYMENT_ATTEMPT_CHALLENGED,
    PAYMENT_ATTEMPT_AUTHORIZED,
    PAYMENT_ATTEMPT_SUBMITTED,
    PAYMENT_ATTEMPT_SETTLED,
    PAYMENT_ATTEMPT_DENIED,
    PAYMENT_ATTEMPT_RELEASED,
    PAYMENT_ATTEMPT_FAILED,
    PAYMENT_ATTEMPT_OUTCOME_UNKNOWN,
];

/// Transport paths on the merchant double. The *logical* resource every
/// challenge names is always [`RESOURCE_URL`] -- the declared, policy-allowlisted
/// one -- because the policy binds payment to a resource identity, not to
/// whichever loopback port the double happened to get.
const PATH_SETTLED: &str = "/weather";
const PATH_AMBIGUOUS: &str = "/weather/ambiguous";
const PATH_PREMIUM: &str = "/weather/premium";

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(crate) fn run_x402_paid_egress_chain(args: &LocalArgs) -> Result<()> {
    let origin = PaidOriginDouble::start().context("start the paid-origin double")?;
    let harness = LocalHarness::start(&args.ferrogate_bin, 0)
        .context("start the gateway for the x402 paid-egress chain")?;

    // The harness binary has a plain sync `main`, so the async repository API is
    // bridged with one dedicated current-thread runtime -- the same pattern
    // `payment_attempt_restart.rs` and `compliance.rs` use.
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build the chain's async bridge runtime")?;
    let ledger = RuntimeStorageRepositories::in_memory(Vec::new(), 0, 0);
    runtime.block_on(provision_wallet(&ledger))?;

    let settled = run_settled_leg(&harness.gateway_addr, &origin, &runtime, &ledger)?;
    run_denied_leg(&harness.gateway_addr, &origin, &runtime, &ledger)?;
    let unknown = run_outcome_unknown_leg(&harness.gateway_addr, &origin, &runtime, &ledger)?;
    run_reconcile_leg(&origin, &runtime, &ledger, &unknown)?;
    run_restart_leg(args, harness, &runtime, &ledger, &[&settled, &unknown])?;
    runtime.block_on(assert_chain_accounting(&ledger))?;
    origin.assert_no_unauthorized_payment()?;

    println!("x402-paid-egress-chain scenario passed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Leg 1 -- the happy path, and the re-drive that must not charge twice
// ---------------------------------------------------------------------------

/// Acceptance: "Happy path produces exactly one origin side effect, one on-chain
/// settlement evidence record, and one internal wallet capture" and "Duplicate
/// request/idempotency replay cannot sign, settle, or capture twice".
fn run_settled_leg(
    gateway_addr: &str,
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
) -> Result<Leg> {
    let leg = Leg::new("chain-settled", PATH_SETTLED);

    // 1. The unpaid dispatch. The merchant refuses and states its price.
    let challenge = origin.unpaid_dispatch(leg.transport_path)?;

    // 2. The gateway authorizes THAT challenge -- untrusted merchant input,
    //    evaluated by the policy the operator declared.
    let authorization = authorize(gateway_addr, &challenge)?;
    authorization.expect_allowed(ALLOWED_ATOMIC_AMOUNT, ALLOWED_CREDITS)?;

    // 3. Hold, attempt, submit -- the money is committed to before the proof
    //    goes out, and for exactly the credits the gateway computed.
    runtime.block_on(open_and_submit(ledger, &leg, &authorization))?;

    // 4. The single paid replay. One dispatch, one side effect.
    let paid = origin.paid_replay(leg.transport_path, &leg.transaction_signature)?;
    let evidence = paid.expect_settlement_evidence()?;
    evidence.expect_pays_at_least(authorization.atomic_amount)?;

    // 5. SETTLE: capture the hold, THEN mark the attempt settled. That order is
    //    the money-safe one -- an interruption between the two leaves a captured
    //    hold and a re-drivable attempt, never a settled attempt with free money.
    runtime.block_on(settle(ledger, &leg, &evidence, SETTLE_UNIX))?;

    // 6. The re-drive. A retried external action replays the identical request;
    //    a crashed caller replays the identical settle. Neither may charge again.
    let replayed = origin.paid_replay(leg.transport_path, &leg.transaction_signature)?;
    let replayed_evidence = replayed.expect_settlement_evidence()?;
    if replayed_evidence.raw != evidence.raw {
        bail!(
            "settled leg: the merchant returned DIFFERENT settlement evidence for a replay of the same proof: {} then {}",
            evidence.raw,
            replayed_evidence.raw
        );
    }
    runtime.block_on(expect_settle_is_idempotent(
        ledger,
        &leg,
        &evidence,
        SETTLE_UNIX + 1,
    ))?;

    // 7. The three "exactly one" counters, read from the three components.
    let side_effects = origin.side_effects(leg.transport_path)?;
    if side_effects != 1 {
        bail!(
            "settled leg: one authorized payment produced {side_effects} origin side effects, expected exactly 1"
        );
    }
    runtime.block_on(expect_exactly_one_capture(ledger, &leg))?;
    Ok(leg)
}

// ---------------------------------------------------------------------------
// Leg 2 -- a denial must never reach the merchant
// ---------------------------------------------------------------------------

/// Acceptance: "Policy denial/insufficient funds never invokes signer or paid
/// replay." The proof is negative and therefore has to be counted at the
/// merchant: the double records every request carrying an `X-PAYMENT` header per
/// path, and the denied path's count must still be zero at the end of the run.
fn run_denied_leg(
    gateway_addr: &str,
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
) -> Result<()> {
    let leg = Leg::new("chain-denied", PATH_PREMIUM);
    let challenge = origin.unpaid_dispatch(leg.transport_path)?;
    let authorization = authorize(gateway_addr, &challenge)?;
    authorization.expect_denied(DENIED_ATOMIC_AMOUNT, REASON_OVER_CAP)?;

    // A refusal is still durable evidence: the attempt is recorded `denied` for
    // audit, and -- the money-relevant half -- no hold is ever taken for it.
    runtime.block_on(async {
        let created = ledger
            .create_payment_attempt(leg.attempt_record(&authorization, None))
            .await
            .context("create the denied attempt")?;
        if !matches!(created, PaymentAttemptCreation::Created(_)) {
            bail!("denied attempt {} already existed", leg.attempt_id);
        }
        expect_applied(
            ledger
                .deny_payment_attempt(
                    &leg.attempt_id,
                    PaymentAttemptEvidenceArgs {
                        failure_code: Some(REASON_OVER_CAP),
                        ..Default::default()
                    },
                    CHAIN_UNIX,
                )
                .await,
            "deny the over-cap attempt",
        )?;
        let links = expect_links(ledger, &leg).await?;
        if links.attempt.state != PAYMENT_ATTEMPT_DENIED {
            bail!(
                "denied leg: attempt landed in {}, expected {PAYMENT_ATTEMPT_DENIED}",
                links.attempt.state
            );
        }
        if links.reservation.is_some() || links.settlement.is_some() {
            bail!(
                "denied leg: a refused payment took wallet money: {:?} / {:?}",
                links.reservation,
                links.settlement
            );
        }
        anyhow::Ok(())
    })?;

    // The merchant must never have been asked to fulfil this one.
    let paid_requests = origin.paid_requests(leg.transport_path)?;
    if paid_requests != 0 {
        bail!(
            "denied leg: the merchant received {paid_requests} paid requests for a payment policy DENIED"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Leg 3 -- post-submission ambiguity retains the hold
// ---------------------------------------------------------------------------

/// Acceptance: "missing/invalid `PAYMENT-RESPONSE` ... land in the documented
/// state without silent loss". The merchant serves the resource but omits the
/// settlement header, so the caller knows the side effect happened and knows
/// nothing about the money. Releasing here could spend stablecoin without ever
/// charging the wallet, so the hold is RETAINED and the attempt parks
/// `outcome_unknown` -- non-terminal, operator-visible, reconciler's business.
fn run_outcome_unknown_leg(
    gateway_addr: &str,
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
) -> Result<Leg> {
    let leg = Leg::new("chain-unknown", PATH_AMBIGUOUS);
    let challenge = origin.unpaid_dispatch(leg.transport_path)?;
    let authorization = authorize(gateway_addr, &challenge)?;
    authorization.expect_allowed(ALLOWED_ATOMIC_AMOUNT, ALLOWED_CREDITS)?;

    runtime.block_on(open_and_submit(ledger, &leg, &authorization))?;

    let paid = origin.paid_replay(leg.transport_path, &leg.transaction_signature)?;
    if paid.settlement_evidence().is_some() {
        bail!("the ambiguous path unexpectedly returned settlement evidence");
    }

    runtime.block_on(async {
        expect_applied(
            ledger
                .mark_payment_attempt_outcome_unknown(
                    &leg.attempt_id,
                    PaymentAttemptEvidenceArgs {
                        transaction_signature: Some(&leg.transaction_signature),
                        settlement_response: Some(MISSING_EVIDENCE_RESPONSE),
                        ..Default::default()
                    },
                    CHAIN_UNIX + 3,
                )
                .await,
            "park the ambiguous attempt outcome_unknown",
        )?;
        expect_hold_retained(ledger, &leg, "after parking outcome_unknown").await
    })?;

    // The TTL sweeper's own due-query must refuse to see this attempt: only
    // PRE-submission holds may be reclaimed, and this one's proof is already out.
    // A far-future cutoff makes the query maximally eager, so a hit here would be
    // a real money-safety regression rather than a timing artefact.
    runtime.block_on(async {
        let due = ledger
            .list_expirable_due_payment_attempts(CHAIN_UNIX + HOLD_TTL_SECONDS * 10, 100)
            .await
            .context("read the TTL sweeper due-query")?;
        if due.iter().any(|attempt| attempt.id == leg.attempt_id) {
            bail!(
                "the TTL sweeper's due-query offered post-submission attempt {} for release",
                leg.attempt_id
            );
        }
        anyhow::Ok(())
    })?;
    Ok(leg)
}

// ---------------------------------------------------------------------------
// Leg 4 -- reconciliation converges, and converges only once
// ---------------------------------------------------------------------------

/// Acceptance: "Reconciliation converges settled/not-submitted outcomes
/// idempotently; unresolved attempts remain operator-visible with metrics and
/// hold age."
///
/// Drives the reconciler's decision shape against the merchant's facilitator:
/// the first on-chain answer is `pending` (still propagating) and every later one
/// is `confirmed` for the exact owed amount. Trust order is on-chain-authoritative
/// -- the merchant's earlier silence never mattered, and the confirmed amount is
/// compared against what is OWED on parsed integers before anything is captured.
fn run_reconcile_leg(
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
) -> Result<()> {
    // Pass 1: pending. Re-park (bounded backoff), never a terminal, hold kept.
    let pending = origin.facilitator_lookup(&leg.transaction_signature)?;
    if pending.status != "pending" {
        bail!("the facilitator's first answer was {pending:?}, expected a pending transfer");
    }
    let before = runtime.block_on(expect_attempt(ledger, leg))?;
    runtime.block_on(async {
        expect_applied(
            ledger
                .mark_payment_attempt_outcome_unknown(
                    &leg.attempt_id,
                    PaymentAttemptEvidenceArgs {
                        transaction_signature: Some(&leg.transaction_signature),
                        ..Default::default()
                    },
                    CHAIN_UNIX + 3 + RECONCILE_CHECK_DELAY_SECONDS,
                )
                .await,
            "re-park the still-pending attempt",
        )?;
        expect_hold_retained(ledger, leg, "after a pending reconcile pass").await
    })?;
    let after = runtime.block_on(expect_attempt(ledger, leg))?;
    if after.state != PAYMENT_ATTEMPT_OUTCOME_UNKNOWN {
        bail!(
            "a pending on-chain answer moved attempt {} to {}",
            leg.attempt_id,
            after.state
        );
    }
    // The self-edge is what spaces the next RPC query; a cursor that did not move
    // would busy-poll the chain every tick.
    if after.updated_at_unix <= before.updated_at_unix || after.generation <= before.generation {
        bail!(
            "a pending reconcile pass did not advance the backoff cursor for {}: {} -> {} (generation {} -> {})",
            leg.attempt_id,
            before.updated_at_unix,
            after.updated_at_unix,
            before.generation,
            after.generation
        );
    }

    // Pass 2: confirmed for the exact owed amount -> SETTLE (capture, then mark).
    let confirmed = origin.facilitator_lookup(&leg.transaction_signature)?;
    if confirmed.status != "confirmed" {
        bail!("the facilitator did not converge to confirmed: {confirmed:?}");
    }
    let owed = after.atomic_amount.clone();
    if confirmed.amount.as_deref() != Some(owed.as_str()) {
        bail!(
            "on-chain confirmation reports {:?} atomic units, the attempt owes {owed} -- a mismatch must NOT capture",
            confirmed.amount
        );
    }
    let evidence = SettlementEvidence {
        transaction_signature: leg.transaction_signature.clone(),
        atomic_amount: owed.clone(),
        raw: confirmed.raw.clone(),
    };
    runtime.block_on(settle(ledger, leg, &evidence, RECONCILE_SETTLE_UNIX))?;

    // Passes 3 and 4: the reconciler runs again, as a bounded background loop
    // always will. Convergence means these are no-ops, not a second capture.
    for pass in 3..=4 {
        runtime
            .block_on(expect_settle_is_idempotent(
                ledger,
                leg,
                &evidence,
                RECONCILE_SETTLE_UNIX + pass,
            ))
            .with_context(|| format!("reconcile pass {pass}"))?;
    }
    runtime.block_on(expect_exactly_one_capture(ledger, leg))?;

    // Converged attempts leave the reconciler's bounded due-query, so a settled
    // payment can never be re-examined (and can never be falsely released).
    runtime.block_on(async {
        let due = ledger
            .list_reconcilable_payment_attempts(CHAIN_UNIX + HOLD_TTL_SECONDS * 10, 100)
            .await
            .context("read the reconciler due-query after convergence")?;
        if due.iter().any(|attempt| attempt.id == leg.attempt_id) {
            bail!(
                "settled attempt {} is still offered to the reconciler",
                leg.attempt_id
            );
        }
        anyhow::Ok(())
    })
}

// ---------------------------------------------------------------------------
// Leg 5 -- restart lands in a documented state
// ---------------------------------------------------------------------------

/// Acceptance: "... and process restart all land in the documented state without
/// silent loss."
///
/// Two halves, because "documented" has two halves:
///
/// * the **authorization** an attempt was opened under must survive the restart
///   unchanged -- same policy revision, same decision seal for the same
///   challenge -- otherwise a post-restart re-drive would be charging under an
///   authorization nobody can reproduce;
/// * every attempt the chain produced must read back in a member of
///   [`DOCUMENTED_ATTEMPT_STATES`], with the hold disposition that state
///   documents, and a re-driven settle must still be idempotent.
fn run_restart_leg(
    args: &LocalArgs,
    harness: LocalHarness,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
    legs: &[&Leg],
) -> Result<()> {
    let challenge = challenge_header(ALLOWED_ATOMIC_AMOUNT, MERCHANT, RESOURCE_URL);
    let before = authorize(&harness.gateway_addr, &challenge)?;
    drop(harness);

    let restarted = LocalHarness::start(&args.ferrogate_bin, 0)
        .context("restart the gateway for the x402 paid-egress chain")?;
    let after = authorize(&restarted.gateway_addr, &challenge)?;
    if after.policy_revision != before.policy_revision
        || after.decision_hash_hex != before.decision_hash_hex
        || after.challenge_hash_hex != before.challenge_hash_hex
        || after.computed_credits != before.computed_credits
    {
        bail!(
            "the restarted gateway re-authorized the same challenge differently: {before:?} then {after:?}"
        );
    }

    runtime.block_on(async {
        for leg in legs {
            let links = expect_links(ledger, leg).await?;
            let state = links.attempt.state.as_str();
            if !DOCUMENTED_ATTEMPT_STATES.contains(&state) {
                bail!(
                    "attempt {} came back in the invented state {state:?}",
                    leg.attempt_id
                );
            }
            expect_documented_hold_disposition(&links)?;
        }
        anyhow::Ok(())
    })?;

    // A restart is exactly when a duplicate finalize replay happens: the caller
    // that crashed mid-settle comes back and re-drives its edge.
    runtime.block_on(async {
        for leg in legs {
            let attempt = expect_attempt(ledger, leg).await?;
            if attempt.state != PAYMENT_ATTEMPT_SETTLED {
                continue;
            }
            let evidence = SettlementEvidence {
                transaction_signature: leg.transaction_signature.clone(),
                atomic_amount: attempt.atomic_amount.clone(),
                raw: attempt.settlement_response.clone().unwrap_or_default(),
            };
            expect_settle_is_idempotent(ledger, leg, &evidence, RESTART_REPLAY_UNIX).await?;
            expect_exactly_one_capture(ledger, leg).await?;
        }
        anyhow::Ok(())
    })?;
    drop(restarted);
    Ok(())
}

// ---------------------------------------------------------------------------
// Whole-chain accounting
// ---------------------------------------------------------------------------

/// The single arithmetic statement the whole chain reduces to: the wallet moved
/// by exactly the captures the chain authorized, and by nothing else. Integer
/// credits, checked arithmetic -- money is never `f64` here.
async fn assert_chain_accounting(ledger: &RuntimeStorageRepositories) -> Result<()> {
    let expected_debit = ALLOWED_CREDITS
        .checked_mul(EXPECTED_CAPTURES)
        .context("expected chain debit overflowed")?;
    let expected_balance = WALLET_BALANCE_CREDITS
        .checked_sub(expected_debit)
        .context("expected chain balance underflowed")?;

    let wallet = ledger
        .get_wallet(TENANT_ID)
        .await
        .context("read the chain wallet")?
        .context("the chain wallet vanished")?;
    if wallet.balance_credits != expected_balance {
        bail!(
            "the chain wallet balance is {} credits, expected {expected_balance} ({WALLET_BALANCE_CREDITS} less {EXPECTED_CAPTURES} captures of {ALLOWED_CREDITS})",
            wallet.balance_credits
        );
    }

    let reservations = ledger
        .list_wallet_reservations(TENANT_ID)
        .await
        .context("list the chain's wallet holds")?;
    let captured = reservations
        .iter()
        .filter(|hold| hold.status == WALLET_RESERVATION_SETTLED)
        .count();
    if captured as i64 != EXPECTED_CAPTURES {
        bail!("the chain captured {captured} holds, expected exactly {EXPECTED_CAPTURES}");
    }
    if reservations
        .iter()
        .any(|hold| hold.status == WALLET_RESERVATION_ACTIVE)
    {
        bail!("the chain left a live hold behind: {reservations:?}");
    }

    // Operator visibility: every attempt the chain made is listable under its
    // tenant, in a documented state. "Why was this payment made and what
    // happened to it?" is answerable from durable evidence, not log scraping.
    let attempts = ledger
        .list_payment_attempts(TENANT_ID)
        .await
        .context("list the chain's payment attempts")?;
    if attempts.len() != 3 {
        bail!(
            "the chain recorded {} attempts, expected 3 (settled, denied, reconciled)",
            attempts.len()
        );
    }
    for attempt in &attempts {
        if !DOCUMENTED_ATTEMPT_STATES.contains(&attempt.state.as_str()) {
            bail!(
                "attempt {} is listed in the invented state {:?}",
                attempt.id,
                attempt.state
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// One leg of the chain
// ---------------------------------------------------------------------------

/// The ids one payment owns end to end. Derived from a single name so an
/// assertion failure names the leg rather than a random identifier, and so the
/// hold, the attempt and the proof can never be crossed between legs.
struct Leg {
    attempt_id: String,
    hold_id: String,
    transaction_signature: String,
    transport_path: &'static str,
}

impl Leg {
    fn new(name: &str, transport_path: &'static str) -> Self {
        Self {
            attempt_id: name.to_string(),
            hold_id: format!("{name}-hold"),
            transaction_signature: transaction_signature(name),
            transport_path,
        }
    }

    /// The attempt row as first created: `challenged`, generation 0, no evidence.
    /// Every immutable field is either the gateway's decision output or the
    /// merchant's challenge -- nothing about the money originates here.
    fn attempt_record(
        &self,
        authorization: &Authorization,
        hold_id: Option<&str>,
    ) -> StoredPaymentAttempt {
        StoredPaymentAttempt {
            id: self.attempt_id.clone(),
            tenant_id: TENANT_ID.to_string(),
            project_id: None,
            workspace_id: None,
            run_id: Some(format!("{}-run", self.attempt_id)),
            worker_id: Some(format!("{}-worker", self.attempt_id)),
            request_id: Some(format!("{}-request", self.attempt_id)),
            trace_id: Some(format!("{}-trace", self.attempt_id)),
            method: REQUEST_METHOD.to_string(),
            resource_url: RESOURCE_URL.to_string(),
            request_body_hash: Some(authorization.request_body_sha256_hex.clone()),
            challenge_hash: authorization.challenge_hash_hex.clone(),
            x402_version: X402_VERSION,
            scheme: SCHEME.to_string(),
            network_caip2: CAIP2_DEVNET.to_string(),
            mint: USDC_DEVNET_MINT.to_string(),
            atomic_amount: authorization.atomic_amount.to_string(),
            recipient: MERCHANT.to_string(),
            credits_amount: authorization.computed_credits,
            conversion_version: Some(CONVERSION_VERSION.to_string()),
            policy_revision: authorization.policy_revision as i64,
            decision: authorization.decision.clone(),
            reason_code: authorization.reason_code.clone(),
            hold_id: hold_id.map(str::to_string),
            state: PAYMENT_ATTEMPT_CHALLENGED.to_string(),
            generation: 0,
            submitted_at_unix: None,
            transaction_signature: None,
            settled_atomic_amount: None,
            settlement_response: None,
            failure_code: None,
            created_at_unix: CHAIN_UNIX,
            updated_at_unix: CHAIN_UNIX,
        }
    }
}

/// A deterministic, base58-alphabet-shaped signature per leg. Only its identity
/// matters here: it is the token that joins the merchant's side-effect cache,
/// the durable attempt row, and the facilitator's on-chain answer.
fn transaction_signature(name: &str) -> String {
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(name.as_bytes()) {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Ledger edges -- exactly the primitives the #354 loop drives
// ---------------------------------------------------------------------------

async fn provision_wallet(ledger: &RuntimeStorageRepositories) -> Result<()> {
    ledger
        .upsert_wallet(StoredWallet {
            id: TENANT_ID.to_string(),
            tenant_id: TENANT_ID.to_string(),
            balance_credits: WALLET_BALANCE_CREDITS,
            auto_recharge_threshold_credits: None,
            auto_recharge_amount_credits: None,
            dunning: false,
            created_at_unix: CHAIN_UNIX,
            updated_at_unix: CHAIN_UNIX,
        })
        .await
        .context("provision the chain wallet")
}

/// `reserve hold -> create attempt -> authorize -> submit`. The hold is placed
/// BEFORE any proof exists, so an insufficient balance is refused without ever
/// reaching a signer.
async fn open_and_submit(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
    authorization: &Authorization,
) -> Result<()> {
    let credits = authorization
        .computed_credits
        .context("an allowed payment must carry the credits the gateway computed")?;
    let reserved = ledger
        .reserve_wallet_credits(
            &leg.hold_id,
            TENANT_ID,
            credits,
            CHAIN_UNIX + HOLD_TTL_SECONDS,
            CHAIN_UNIX,
        )
        .await
        .with_context(|| format!("reserve the hold for {}", leg.attempt_id))?;
    match reserved {
        WalletReservationResult::Reserved(hold)
            if hold.amount_credits == credits && hold.status == WALLET_RESERVATION_ACTIVE => {}
        other => bail!(
            "the hold for {} was not an exact-amount active reservation: {other:?}",
            leg.attempt_id
        ),
    }

    let created = ledger
        .create_payment_attempt(leg.attempt_record(authorization, Some(&leg.hold_id)))
        .await
        .with_context(|| format!("create attempt {}", leg.attempt_id))?;
    if !matches!(created, PaymentAttemptCreation::Created(_)) {
        bail!("attempt {} already existed", leg.attempt_id);
    }

    expect_applied(
        ledger
            .authorize_payment_attempt(
                &leg.attempt_id,
                PaymentAttemptEvidenceArgs::default(),
                CHAIN_UNIX + 1,
            )
            .await,
        "authorize the attempt",
    )?;
    expect_applied(
        ledger
            .submit_payment_attempt(
                &leg.attempt_id,
                PaymentAttemptEvidenceArgs {
                    submitted_at_unix: Some(CHAIN_UNIX + 2),
                    // #399: the signature is persisted at SUBMIT, so an attempt
                    // that goes ambiguous still carries the token the reconciler
                    // needs to ask the chain what happened.
                    transaction_signature: Some(&leg.transaction_signature),
                    ..Default::default()
                },
                CHAIN_UNIX + 2,
            )
            .await,
        "submit the attempt",
    )
}

/// SETTLE: capture the hold FIRST, then mark the attempt settled. Both
/// primitives are idempotent on the shared (id + generation) token, so a caller
/// interrupted between them converges on re-entry instead of charging twice.
async fn settle(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
    evidence: &SettlementEvidence,
    now_unix: i64,
) -> Result<()> {
    let capture = ledger
        .settle_wallet_reservation(&leg.hold_id, now_unix)
        .await
        .with_context(|| format!("capture the hold for {}", leg.attempt_id))?;
    if !capture.newly_applied {
        bail!(
            "the first capture of hold {} was already applied: {capture:?}",
            leg.hold_id
        );
    }
    expect_applied(
        ledger
            .settle_payment_attempt(
                &leg.attempt_id,
                PaymentAttemptEvidenceArgs {
                    transaction_signature: Some(&evidence.transaction_signature),
                    settled_atomic_amount: Some(&evidence.atomic_amount),
                    settlement_response: Some(&evidence.raw),
                    ..Default::default()
                },
                now_unix,
            )
            .await,
        "settle the attempt",
    )
}

/// Re-driving SETTLE with the SAME evidence: both primitives must report an
/// idempotent replay rather than applying a second charge.
async fn expect_settle_is_idempotent(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
    evidence: &SettlementEvidence,
    now_unix: i64,
) -> Result<()> {
    let capture = ledger
        .settle_wallet_reservation(&leg.hold_id, now_unix)
        .await
        .with_context(|| format!("replay the capture of hold {}", leg.hold_id))?;
    if capture.newly_applied {
        bail!(
            "replaying the capture of hold {} applied a SECOND debit: {capture:?}",
            leg.hold_id
        );
    }
    match ledger
        .settle_payment_attempt(
            &leg.attempt_id,
            PaymentAttemptEvidenceArgs {
                transaction_signature: Some(&evidence.transaction_signature),
                settled_atomic_amount: Some(&evidence.atomic_amount),
                settlement_response: Some(&evidence.raw),
                ..Default::default()
            },
            now_unix,
        )
        .await
        .with_context(|| format!("replay the settle of {}", leg.attempt_id))?
    {
        PaymentAttemptTransition::Idempotent(_) => Ok(()),
        PaymentAttemptTransition::Applied(record) => bail!(
            "replaying the settle of {} applied a SECOND transition into {}",
            leg.attempt_id,
            record.state
        ),
    }
}

/// One authorized payment, one wallet capture: the hold is `settled`, its
/// settlement debits exactly the held credits, and no second settlement exists.
async fn expect_exactly_one_capture(ledger: &RuntimeStorageRepositories, leg: &Leg) -> Result<()> {
    let links = expect_links(ledger, leg).await?;
    let Some(hold) = links.reservation.as_ref() else {
        bail!("attempt {} lost its wallet hold", leg.attempt_id);
    };
    if hold.status != WALLET_RESERVATION_SETTLED {
        bail!(
            "attempt {} settled but its hold is {}, expected {WALLET_RESERVATION_SETTLED}",
            leg.attempt_id,
            hold.status
        );
    }
    let Some(settlement) = links.settlement.as_ref() else {
        bail!(
            "attempt {} settled without a wallet settlement record",
            leg.attempt_id
        );
    };
    let expected_delta = hold
        .amount_credits
        .checked_neg()
        .context("hold amount negation overflowed")?;
    if settlement.delta_credits != expected_delta {
        bail!(
            "attempt {} debited {} credits, its hold held {}",
            leg.attempt_id,
            settlement.delta_credits,
            hold.amount_credits
        );
    }
    Ok(())
}

/// `outcome_unknown` is non-terminal and RETAINS the hold: post-submission
/// ambiguity is not proof the money did not move.
async fn expect_hold_retained(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
    when: &str,
) -> Result<()> {
    let links = expect_links(ledger, leg).await?;
    if links.attempt.state != PAYMENT_ATTEMPT_OUTCOME_UNKNOWN {
        bail!(
            "{when}: attempt {} is {}, expected {PAYMENT_ATTEMPT_OUTCOME_UNKNOWN}",
            leg.attempt_id,
            links.attempt.state
        );
    }
    match links.reservation.as_ref() {
        Some(hold) if hold.status == WALLET_RESERVATION_ACTIVE => {}
        other => bail!(
            "{when}: attempt {} did not retain its hold: {other:?}",
            leg.attempt_id
        ),
    }
    if links.settlement.is_some() {
        bail!(
            "{when}: an ambiguous attempt {} captured its hold",
            leg.attempt_id
        );
    }
    Ok(())
}

/// The hold disposition each documented state mandates. This is the assertion
/// that makes "documented" mean something: a state whose money disposition
/// contradicts its documentation is exactly as bad as an invented state.
fn expect_documented_hold_disposition(links: &PaymentAttemptLinks) -> Result<()> {
    let id = &links.attempt.id;
    let hold_status = links.reservation.as_ref().map(|hold| hold.status.as_str());
    match links.attempt.state.as_str() {
        PAYMENT_ATTEMPT_SETTLED => {
            if hold_status != Some(WALLET_RESERVATION_SETTLED) || links.settlement.is_none() {
                bail!("settled attempt {id} does not own exactly one captured hold: {links:?}");
            }
        }
        PAYMENT_ATTEMPT_OUTCOME_UNKNOWN => {
            if hold_status != Some(WALLET_RESERVATION_ACTIVE) || links.settlement.is_some() {
                bail!("outcome_unknown attempt {id} did not retain an uncaptured hold: {links:?}");
            }
        }
        PAYMENT_ATTEMPT_DENIED => {
            if links.reservation.is_some() || links.settlement.is_some() {
                bail!("denied attempt {id} holds wallet money: {links:?}");
            }
        }
        PAYMENT_ATTEMPT_RELEASED | PAYMENT_ATTEMPT_FAILED => {
            if links.settlement.is_some() {
                bail!("attempt {id} is terminal-without-payment yet captured its hold: {links:?}");
            }
        }
        // Pre-terminal states hold live money by design; the settled/released
        // question is not yet answered for them.
        _ => {}
    }
    Ok(())
}

async fn expect_attempt(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
) -> Result<StoredPaymentAttempt> {
    ledger
        .get_payment_attempt(&leg.attempt_id)
        .await
        .with_context(|| format!("read attempt {}", leg.attempt_id))?
        .with_context(|| format!("attempt {} does not exist", leg.attempt_id))
}

async fn expect_links(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
) -> Result<PaymentAttemptLinks> {
    ledger
        .get_payment_attempt_links(&leg.attempt_id, TENANT_ID)
        .await
        .with_context(|| format!("read links for attempt {}", leg.attempt_id))?
        .with_context(|| format!("attempt {} is not owned by {TENANT_ID}", leg.attempt_id))
}

fn expect_applied(
    result: Result<PaymentAttemptTransition, ferrogate_storage::StorageError>,
    what: &str,
) -> Result<()> {
    match result.with_context(|| what.to_string())? {
        PaymentAttemptTransition::Applied(_) => Ok(()),
        PaymentAttemptTransition::Idempotent(record) => bail!(
            "{what} was an idempotent replay, not a fresh transition (state {})",
            record.state
        ),
    }
}

// ---------------------------------------------------------------------------
// The gateway's authorization
// ---------------------------------------------------------------------------

/// What the gateway decided about one untrusted merchant challenge. Every money
/// figure the chain then acts on is read from here -- the harness never invents
/// an amount or a conversion.
#[derive(Debug, Clone)]
struct Authorization {
    decision: String,
    reason_code: String,
    policy_revision: u64,
    atomic_amount: u64,
    computed_credits: Option<i64>,
    challenge_hash_hex: String,
    request_body_sha256_hex: String,
    decision_hash_hex: String,
}

impl Authorization {
    fn expect_allowed(&self, atomic_amount: u64, credits: i64) -> Result<()> {
        if self.decision != DECISION_ALLOW || self.reason_code != REASON_ALLOWED {
            bail!(
                "expected the gateway to allow this payment, got {} ({})",
                self.decision,
                self.reason_code
            );
        }
        if self.atomic_amount != atomic_amount {
            bail!(
                "the gateway authorized {} atomic units, the merchant asked for {atomic_amount}",
                self.atomic_amount
            );
        }
        if self.computed_credits != Some(credits) {
            bail!(
                "the gateway converted the challenge to {:?} credits, expected {credits}",
                self.computed_credits
            );
        }
        if self.policy_revision != TENANT_REVISION {
            bail!(
                "the payment was authorized under policy revision {}, expected the declared {TENANT_REVISION}",
                self.policy_revision
            );
        }
        Ok(())
    }

    fn expect_denied(&self, atomic_amount: u64, reason_code: &str) -> Result<()> {
        if self.decision != DECISION_DENY {
            bail!(
                "expected the gateway to deny this payment, got {} ({})",
                self.decision,
                self.reason_code
            );
        }
        if self.reason_code != reason_code {
            bail!(
                "expected denial reason {reason_code}, got {}",
                self.reason_code
            );
        }
        if self.atomic_amount != atomic_amount {
            bail!(
                "the denied decision reports {} atomic units, the merchant asked for {atomic_amount}",
                self.atomic_amount
            );
        }
        Ok(())
    }
}

/// Runs the merchant's challenge through the SAME policy evaluation the payment
/// path uses, at the tenant scope the fixture declares.
fn authorize(gateway_addr: &str, challenge: &str) -> Result<Authorization> {
    let request = json!({
        "scope": { "tenant_id": TENANT_ID },
        "payment_required": challenge,
        "authorized_resource_url": RESOURCE_URL,
        "authorized_method": REQUEST_METHOD,
        "authorized_request_body_sha256_hex": Value::Null,
        "spent": { "run_spent_credits": 0, "window_spent_credits": 0 }
    })
    .to_string();
    let response = http_request_addr(
        gateway_addr,
        "POST",
        "/admin/v1/x402-spend-policies/evaluate",
        &[ADMIN_AUTH, JSON_CONTENT],
        &request,
    )?;
    if response.status != 200 {
        bail!(
            "x402 policy evaluation returned {}: {}",
            response.status,
            response.body
        );
    }
    let body: Value = serde_json::from_str(&response.body).with_context(|| {
        format!(
            "x402 policy evaluation returned invalid JSON: {}",
            response.body
        )
    })?;
    let decision = &body["decision"];
    Ok(Authorization {
        decision: string_field(decision, "decision")?,
        reason_code: string_field(decision, "reason_code")?,
        policy_revision: u64_field(&decision["policy_revision"], "policy_revision")?,
        atomic_amount: u64_field(&decision["atomic_amount"], "atomic_amount")?,
        computed_credits: match &decision["computed_credits"] {
            Value::Null => None,
            value => Some(
                value
                    .as_i64()
                    .with_context(|| format!("computed_credits must be an integer, got {value}"))?,
            ),
        },
        challenge_hash_hex: string_field(decision, "challenge_hash_hex")?,
        request_body_sha256_hex: string_field(decision, "request_body_sha256_hex")?,
        decision_hash_hex: string_field(decision, "decision_hash_hex")?,
    })
}

fn string_field(value: &Value, field: &str) -> Result<String> {
    value[field]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("{field} must be a string, got {}", value[field]))
}

fn u64_field(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .with_context(|| format!("{field} must be a non-negative integer, got {value}"))
}

// ---------------------------------------------------------------------------
// The merchant + facilitator double
// ---------------------------------------------------------------------------

/// The merchant's `PAYMENT-RESPONSE` for one payment, as the caller reads it off
/// the paid replay.
#[derive(Debug, Clone)]
struct SettlementEvidence {
    transaction_signature: String,
    atomic_amount: String,
    raw: String,
}

impl SettlementEvidence {
    /// A merchant claiming success is never taken at its word about HOW MUCH it
    /// settled: the reported amount is compared against the owed amount on
    /// parsed integers. A report short of what is owed must not capture.
    fn expect_pays_at_least(&self, owed_atomic: u64) -> Result<()> {
        let reported: u64 = self.atomic_amount.parse().with_context(|| {
            format!(
                "settlement evidence reported a non-integer amount {:?}",
                self.atomic_amount
            )
        })?;
        if reported < owed_atomic {
            bail!(
                "the merchant reported settling {reported} atomic units against {owed_atomic} owed"
            );
        }
        Ok(())
    }
}

/// The on-chain answer the reconciler's RPC seam would return.
#[derive(Debug, Clone)]
struct FacilitatorAnswer {
    status: String,
    amount: Option<String>,
    raw: String,
}

/// A response read off the merchant double, headers included.
struct OriginResponse {
    status: u16,
    raw: String,
}

impl OriginResponse {
    fn settlement_evidence(&self) -> Option<SettlementEvidence> {
        let header = header_value(&self.raw, "payment-response")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header.as_bytes())
            .ok()?;
        let parsed: Value = serde_json::from_slice(&decoded).ok()?;
        Some(SettlementEvidence {
            transaction_signature: parsed["transaction"].as_str()?.to_string(),
            atomic_amount: parsed["amount"].as_str()?.to_string(),
            raw: String::from_utf8(decoded).ok()?,
        })
    }

    fn expect_settlement_evidence(&self) -> Result<SettlementEvidence> {
        if self.status != 200 {
            bail!(
                "the paid replay returned {} instead of the resource",
                self.status
            );
        }
        self.settlement_evidence()
            .context("the paid replay carried no decodable PAYMENT-RESPONSE evidence")
    }
}

#[derive(Default)]
struct OriginState {
    /// Fulfilled payments per transport path, counted by payment identity: a
    /// replay of an already-served proof does NOT increment this.
    side_effects: HashMap<String, u64>,
    /// Every request carrying an `X-PAYMENT` header, per path -- including
    /// replays. A non-zero count on a DENIED path is a capability-boundary
    /// failure, so this counts attempts, not successes.
    paid_requests: HashMap<String, u64>,
    /// Payment identity -> the settlement evidence first returned for it. A
    /// replay is served from here, byte-identically.
    served: HashMap<String, String>,
    /// How many times the facilitator has been asked about each signature, so
    /// "pending first, confirmed after" is deterministic rather than timed.
    facilitator_queries: HashMap<String, u64>,
}

/// A deterministic local x402 merchant + facilitator. Single-threaded accept
/// loop, no sleeps in its decision path, every answer a pure function of the
/// request and the counters above.
pub(crate) struct PaidOriginDouble {
    addr: String,
    state: Arc<Mutex<OriginState>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PaidOriginDouble {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?.to_string();
        let state = Arc::new(Mutex::new(OriginState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let Ok(request) = crate::mocks::read_http_request(&mut stream) else {
                            continue;
                        };
                        let response = {
                            let mut guard = match worker_state.lock() {
                                Ok(guard) => guard,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            respond(&mut guard, &request)
                        };
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            state,
            stop,
            handle: Some(handle),
        })
    }

    /// The first, unpaid dispatch. Returns the merchant's base64 challenge.
    fn unpaid_dispatch(&self, path: &str) -> Result<String> {
        let response = http_request_addr(&self.addr, REQUEST_METHOD, path, &[], "")?;
        if response.status != 402 {
            bail!(
                "the unpaid dispatch to {path} returned {}, expected 402",
                response.status
            );
        }
        header_value(&response.raw, "x-payment-required")
            .with_context(|| format!("the 402 from {path} carried no challenge header"))
    }

    /// The single paid replay, carrying the proof for `signature`.
    fn paid_replay(&self, path: &str, signature: &str) -> Result<OriginResponse> {
        let proof = base64::engine::general_purpose::STANDARD.encode(
            json!({
                "x402Version": X402_VERSION,
                "scheme": SCHEME,
                "network": CAIP2_DEVNET,
                "payload": { "transaction": signature }
            })
            .to_string(),
        );
        let header = format!("X-PAYMENT: {proof}");
        let response = http_request_addr(&self.addr, REQUEST_METHOD, path, &[&header], "")?;
        Ok(OriginResponse {
            status: response.status,
            raw: response.raw,
        })
    }

    /// The reconciler's on-chain question. Answers `pending` the first time and
    /// `confirmed` afterwards, deterministically.
    fn facilitator_lookup(&self, signature: &str) -> Result<FacilitatorAnswer> {
        let response = http_request_addr(
            &self.addr,
            "GET",
            &format!("/facilitator/settlement?signature={signature}"),
            &[],
            "",
        )?;
        if response.status != 200 {
            bail!(
                "the facilitator returned {} for {signature}",
                response.status
            );
        }
        let parsed: Value = serde_json::from_str(&response.body)
            .with_context(|| format!("facilitator returned invalid JSON: {}", response.body))?;
        Ok(FacilitatorAnswer {
            status: string_field(&parsed, "status")?,
            amount: parsed["amount"].as_str().map(str::to_string),
            raw: response.body,
        })
    }

    fn side_effects(&self, path: &str) -> Result<u64> {
        Ok(self
            .snapshot()?
            .side_effects
            .get(path)
            .copied()
            .unwrap_or(0))
    }

    fn paid_requests(&self, path: &str) -> Result<u64> {
        Ok(self
            .snapshot()?
            .paid_requests
            .get(path)
            .copied()
            .unwrap_or(0))
    }

    /// Final capability-boundary check: the merchant was never paid for anything
    /// beyond the two payments the gateway authorized.
    fn assert_no_unauthorized_payment(&self) -> Result<()> {
        let snapshot = self.snapshot()?;
        let unauthorized: Vec<(&String, &u64)> = snapshot
            .paid_requests
            .iter()
            .filter(|(path, _)| path.as_str() != PATH_SETTLED && path.as_str() != PATH_AMBIGUOUS)
            .collect();
        if !unauthorized.is_empty() {
            bail!("the merchant was paid on unauthorized paths: {unauthorized:?}");
        }
        let total_side_effects: u64 = snapshot.side_effects.values().copied().sum();
        if total_side_effects != EXPECTED_CAPTURES as u64 {
            bail!(
                "the chain produced {total_side_effects} origin side effects, expected exactly {EXPECTED_CAPTURES}"
            );
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<OriginSnapshot> {
        let guard = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("the paid-origin double's state lock was poisoned"))?;
        Ok(OriginSnapshot {
            side_effects: guard.side_effects.clone(),
            paid_requests: guard.paid_requests.clone(),
        })
    }
}

impl Drop for PaidOriginDouble {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

struct OriginSnapshot {
    side_effects: HashMap<String, u64>,
    paid_requests: HashMap<String, u64>,
}

/// The merchant's whole decision table, as a pure function of the request and
/// the accumulated counters. Split out so it is unit-testable without a socket.
fn respond(state: &mut OriginState, request: &str) -> String {
    let Some((_method, target)) = request_line(request) else {
        return http_response(400, r#"{"error":"malformed request"}"#, None);
    };

    if let Some(signature) = target.strip_prefix("/facilitator/settlement?signature=") {
        let queries = state
            .facilitator_queries
            .entry(signature.to_string())
            .or_insert(0);
        *queries = queries.saturating_add(1);
        // The first look is genuinely too early: a freshly submitted proof may
        // still be propagating, which is exactly the case that must NOT fail.
        let body = if *queries <= 1 {
            json!({ "status": "pending", "signature": signature }).to_string()
        } else {
            json!({
                "status": "confirmed",
                "signature": signature,
                "amount": ALLOWED_ATOMIC_AMOUNT.to_string(),
                "network": CAIP2_DEVNET
            })
            .to_string()
        };
        return http_response(200, &body, None);
    }

    let path = target.split('?').next().unwrap_or(target).to_string();
    let Some(proof) = header_value(request, "x-payment") else {
        // Unpaid: state the price. The challenge names the DECLARED resource,
        // never the loopback transport address.
        let atomic_amount = if path == PATH_PREMIUM {
            DENIED_ATOMIC_AMOUNT
        } else {
            ALLOWED_ATOMIC_AMOUNT
        };
        let challenge = challenge_header(atomic_amount, MERCHANT, RESOURCE_URL);
        return http_response(
            402,
            r#"{"error":"payment required"}"#,
            Some(&format!("X-Payment-Required: {challenge}")),
        );
    };

    let counter = state.paid_requests.entry(path.clone()).or_insert(0);
    *counter = counter.saturating_add(1);

    let Some(signature) = proof_signature(&proof) else {
        return http_response(400, r#"{"error":"undecodable payment proof"}"#, None);
    };

    if path == PATH_AMBIGUOUS {
        // The resource IS delivered, and the settlement header is missing. The
        // caller therefore knows the side effect happened and knows nothing
        // about the money -- the ambiguity that must retain the hold.
        if let std::collections::hash_map::Entry::Vacant(slot) = state.served.entry(signature) {
            slot.insert(String::new());
            let effects = state.side_effects.entry(path).or_insert(0);
            *effects = effects.saturating_add(1);
        }
        return http_response(200, r#"{"weather":"cloudy"}"#, None);
    }

    let evidence = match state.served.get(&signature) {
        // A replay of an already-fulfilled payment: same evidence, no second
        // side effect. This is the merchant half of "cannot pay twice".
        Some(existing) => existing.clone(),
        None => {
            let evidence = json!({
                "success": true,
                "transaction": signature,
                "amount": ALLOWED_ATOMIC_AMOUNT.to_string(),
                "network": CAIP2_DEVNET
            })
            .to_string();
            state.served.insert(signature, evidence.clone());
            let effects = state.side_effects.entry(path).or_insert(0);
            *effects = effects.saturating_add(1);
            evidence
        }
    };
    let header = format!(
        "PAYMENT-RESPONSE: {}",
        base64::engine::general_purpose::STANDARD.encode(&evidence)
    );
    http_response(200, r#"{"weather":"sunny"}"#, Some(&header))
}

/// The `settlement_response` recorded when the merchant served the resource but
/// said nothing about the money.
const MISSING_EVIDENCE_RESPONSE: &str = r#"{"reason":"missing_payment_response_header"}"#;

fn request_line(request: &str) -> Option<(&str, &str)> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    Some((method, target))
}

fn proof_signature(proof: &str) -> Option<String> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(proof.as_bytes())
        .ok()?;
    let parsed: Value = serde_json::from_slice(&decoded).ok()?;
    parsed["payload"]["transaction"]
        .as_str()
        .map(str::to_string)
}

/// Case-insensitive header lookup over a raw HTTP message.
fn header_value(raw: &str, name: &str) -> Option<String> {
    raw.lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
}

fn http_response(status: u16, body: &str, extra_header: Option<&str>) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        402 => "Payment Required",
        _ => "Unknown",
    };
    let extra = extra_header
        .map(|header| format!("{header}\r\n"))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[cfg(test)]
#[path = "x402_paid_egress_chain_test.rs"]
mod x402_paid_egress_chain_test;
