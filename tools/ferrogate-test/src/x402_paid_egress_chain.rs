// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: The narrow cross-component paid-egress chain command promised by
// issue #354's Verification section: operator config -> gateway policy decision
// -> deterministic paid-origin double -> durable payment-attempt/wallet-hold
// ledger -> re-drive/reconcile. Each leg states the box it closes and the boxes
// it deliberately leaves to their real owners; see the module doc.

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
//! * post-submission ambiguity parks `outcome_unknown` with the hold
//!   **RETAINED**, and the TTL sweep's due-query offers a pre-submission hold
//!   while refusing a post-submission one;
//! * **reconciliation is idempotent**: the reconcile due-query offers the
//!   unresolved attempt, a pending on-chain answer re-parks it with the backoff
//!   cursor advanced, a confirmed one settles it, and every later pass converges
//!   rather than double-capturing or falsely releasing;
//! * every attempt the chain produces ends in the **exact** state its leg
//!   demands, with the hold disposition that state mandates.
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
//! ## What this command does NOT prove, stated before anything it does
//!
//! 1. **It proves nothing about restart recovery, and does not claim to.** The
//!    ledger this command drives is an in-process
//!    [`RuntimeStorageRepositories::in_memory`] living in the *ferrogate-test*
//!    process; restarting the gateway process cannot touch it, so an assertion
//!    read back from it after a gateway restart would be exactly as green with
//!    every restart-recovery path deleted. The restart box --
//!    "... and process restart all land in the documented state without silent
//!    loss" -- is owned by `payment_attempt_restart.rs` under the
//!    `postgres-restart` / `supabase-restart` scenarios, which restart against a
//!    real database. Folding that in here would have turned an always-running
//!    command into one that silently skips when Docker is absent.
//!    [`run_gateway_reauthorization_leg`] therefore claims only the property
//!    that genuinely survives a gateway restart with no database in the picture:
//!    the restarted gateway re-issues a **byte-identical authorization** for the
//!    same challenge, so a later re-drive is attributable to an authorization
//!    that can be reproduced.
//!
//! 2. **It does not prove that a policy denial never reaches the signer or the
//!    paid replay.** Nothing in production links the two yet:
//!    `state_x402_negotiation.rs` has no non-test caller (#381), so no system
//!    decision stands between "policy denied" and "pay anyway" for this command
//!    to observe. What [`run_denied_leg`] proves is what it can: the gateway
//!    really answers `deny` with the over-cap reason for the challenge the
//!    merchant really sent, and a refusal takes **no wallet money**. The
//!    merchant's zero paid-request count on that path is a self-check on this
//!    harness (it never dispatches a denied payment), not a system property --
//!    it is asserted so a future edit to this file cannot quietly start paying,
//!    and it is labelled that way at the call site.
//!
//! 3. **It does not prove the production loop's edge ORDERING.** `ferrogate-cli`
//!    is a binary-only crate, so `X402SettlementLoop` cannot be linked here and
//!    the SETTLE ordering (capture-then-mark) is a **second copy** in [`settle`].
//!    Inverting that ordering in production leaves this command green. The
//!    storage primitives it drives are the real ones; the orchestration around
//!    them is not. `state_x402_settlement_test.rs` owns the ordering.
//!
//! 4. **Amount coverage is a mirror, not the shipped function.** For the same
//!    binary-only reason, [`covers_owed_amount`] mirrors
//!    `state_x402_settlement.rs::classify_settled_amount` rather than calling it.
//!    It is kept deliberately trivial so the mirror is auditable by eye, and the
//!    sibling unit tests pin the same cases the shipped function's tests do.

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
    WALLET_RESERVATION_ACTIVE, WALLET_RESERVATION_RELEASED, WALLET_RESERVATION_SETTLED,
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
/// Origin side effects the chain must produce: one for the settled leg's paid
/// replay and one for the ambiguous leg's. Deliberately a SEPARATE constant from
/// [`EXPECTED_CAPTURES`] even though both are 2 today -- a side effect is the
/// merchant fulfilling a request and a capture is the wallet being debited, and
/// the ambiguous leg is precisely a case where the two do not coincide in time.
/// Adding one leg must not silently make either count assert the other quantity.
const EXPECTED_ORIGIN_SIDE_EFFECTS: u64 = 2;

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
/// Well past every in-run edge: the duplicate-finalize replay is the last write.
const DUPLICATE_FINALIZE_UNIX: i64 = CHAIN_UNIX + 3 + RECONCILE_CHECK_DELAY_SECONDS + 100;

const REQUEST_METHOD: &str = "GET";
const X402_VERSION: i64 = 2;
const SCHEME: &str = "exact";
const CONVERSION_VERSION: &str = "usdc-devnet-v1";
const DECISION_ALLOW: &str = "allow";
const DECISION_DENY: &str = "deny";
const REASON_ALLOWED: &str = "x402_allowed";
const REASON_OVER_CAP: &str = "x402_over_per_payment_cap";

/// Failure code the TTL-sweep control leg records when its pre-submission hold
/// is reclaimed, mirroring the sweeper's own `x402.hold.ttl_expired` edge.
const REASON_TTL_EXPIRED: &str = "x402_hold_ttl_expired";

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
    let denied = run_denied_leg(&harness.gateway_addr, &origin, &runtime, &ledger)?;
    let unknown = run_outcome_unknown_leg(&harness.gateway_addr, &origin, &runtime, &ledger)?;
    let swept = run_ttl_sweep_leg(&harness.gateway_addr, &runtime, &ledger, &unknown)?;
    run_reconcile_leg(&origin, &runtime, &ledger, &unknown)?;
    run_gateway_reauthorization_leg(args, harness)?;

    // The exact state each leg must have come to rest in. Not "a documented
    // state" -- an all-states membership test cannot distinguish a settled
    // attempt from one a regression left `authorized`, so it is the named
    // terminal per leg or nothing.
    let finals: [(&Leg, &str); 4] = [
        (&settled, PAYMENT_ATTEMPT_SETTLED),
        (&denied, PAYMENT_ATTEMPT_DENIED),
        // The ambiguous leg is `outcome_unknown` from its own leg until the
        // reconciler converges it; by here the confirmed on-chain answer has
        // settled it, and anything else means reconciliation did not converge.
        (&unknown, PAYMENT_ATTEMPT_SETTLED),
        (&swept, PAYMENT_ATTEMPT_RELEASED),
    ];
    runtime.block_on(assert_final_ledger_state(&ledger, &finals))?;
    runtime.block_on(assert_chain_accounting(&ledger, &finals))?;
    origin.assert_no_unauthorized_payment()?;

    println!("x402-paid-egress-chain scenario passed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Leg 1 -- the happy path, and the re-drive that must not charge twice
// ---------------------------------------------------------------------------

/// Acceptance: "Happy path produces exactly one origin side effect, one on-chain
/// settlement evidence record, and one internal wallet capture", plus the
/// SETTLE and CAPTURE halves of "duplicate request/idempotency replay cannot
/// sign, settle, or capture twice".
///
/// The SIGN half is deliberately not claimed here and is not proven by this
/// chain: there is no signer anywhere in it. It is proven at the negotiation
/// core instead, by `a_replayed_negotiation_never_signs_a_second_proof` in
/// `crates/ferrogate-gateway/src/state_x402_negotiation_test.rs`, which counts
/// proofs built across a replay against an instrumented signer. Quoting the box
/// verbatim here previously implied this leg covered signing (#354 doc nit).
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
    // A gate, not a proof: this double always reports the full authorized
    // amount, so a short settlement cannot arise here and this call cannot fail
    // inside a scenario run. It is kept because it is the thing that would catch
    // a future double (or a real merchant) reporting less -- and the property
    // itself is pinned non-vacuously by
    // `settlement_evidence_short_of_the_owed_amount_is_refused` in the sibling
    // unit tests, which feeds it an amount that IS short.
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
// Leg 2 -- the gateway refuses an over-cap challenge, and a refusal costs
//          nothing
// ---------------------------------------------------------------------------

/// **What this leg proves:** the gateway, running the operator's declared #351
/// policy, answers `deny` with `x402_over_per_payment_cap` for the over-cap
/// challenge the merchant actually sent, and the refusal is recorded durably as
/// a `denied` attempt that owns **no wallet hold and no settlement**.
///
/// **What it does NOT prove, and the acceptance box it therefore leaves open:**
/// "Policy denial/insufficient funds never invokes signer or paid replay". That
/// is a claim about a production edge that does not exist yet --
/// `state_x402_negotiation.rs` has no non-test caller (#381), so no shipped code
/// path consults a decision before paying. The merchant's paid-request counter
/// for this path is asserted zero below, but it is zero because THIS FUNCTION
/// never calls [`PaidOriginDouble::paid_replay`] on it: the assertion is a guard
/// against a future edit to this file quietly paying for a denied challenge, not
/// evidence of a system decision. The box closes when #381 wires the negotiation
/// path and this leg can drive the real egress handler instead.
fn run_denied_leg(
    gateway_addr: &str,
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
) -> Result<Leg> {
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

    // Harness self-check, not a system property -- see this function's doc.
    let paid_requests = origin.paid_requests(leg.transport_path)?;
    if paid_requests != 0 {
        bail!(
            "denied leg: this scenario dispatched {paid_requests} paid requests for a challenge the gateway DENIED"
        );
    }
    Ok(leg)
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
///
/// **Precisely what the retained hold assertion pins.** This leg calls
/// [`RuntimeStorageRepositories::mark_payment_attempt_outcome_unknown`]
/// directly, so what it proves is that the shipped **storage primitive** for the
/// UNKNOWN edge performs no wallet mutation. It does not run
/// `X402SettlementLoop::finalize` -- that is unreachable from here (#381,
/// binary-only crate) -- so changing *the loop* to release on ambiguity would
/// leave this leg green. `state_x402_settlement_test.rs` owns the loop's edge.
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

    Ok(leg)
}

// ---------------------------------------------------------------------------
// Leg 3b -- the TTL sweep sees pre-submission holds and ONLY those
// ---------------------------------------------------------------------------

/// Acceptance: "only pre-submission holds may be released" -- the money-safety
/// rule the #354 sweeper is built around.
///
/// The interesting assertion is a negative one (the post-submission ambiguous
/// attempt must NOT be offered for release), and a negative assertion against a
/// bounded query is worthless without a **positive control**: stub
/// `list_expirable_due_payment_attempts` to `vec![]` and a lone negative check
/// stays green forever. So this leg opens a second, deliberately
/// pre-submission attempt (`authorized`, live hold, already past its TTL under
/// the cutoff used) and asserts **one query answers both questions**: the
/// pre-submission attempt IS offered, and the post-submission one is NOT. An
/// always-empty due-query now fails the first half.
///
/// It then drives the sweeper's own RELEASE edge over the control attempt --
/// release the hold, then mark the attempt `released`, the money-safe order --
/// so the control leaves no live hold behind and the chain's accounting stays
/// one exact integer. Re-querying afterwards proves a released attempt leaves
/// the due-query rather than being offered again on every tick.
fn run_ttl_sweep_leg(
    gateway_addr: &str,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
    post_submission: &Leg,
) -> Result<Leg> {
    // The transport path is inert for this leg: the control never dispatches to
    // the merchant at all -- it exists only to put a live PRE-submission hold in
    // front of the sweeper's due-query.
    let leg = Leg::new("chain-ttl-control", PATH_SETTLED);
    // Authorized through the same gateway evaluation as every other leg, so the
    // control's hold is for credits the gateway computed, not an invented figure.
    let challenge = challenge_header(ALLOWED_ATOMIC_AMOUNT, MERCHANT, RESOURCE_URL);
    let authorization = authorize(gateway_addr, &challenge)?;
    authorization.expect_allowed(ALLOWED_ATOMIC_AMOUNT, ALLOWED_CREDITS)?;

    // A maximally eager cutoff: every hold in the chain is long past its TTL by
    // here, so anything the query withholds is withheld on STATE, never timing.
    let cutoff = CHAIN_UNIX + HOLD_TTL_SECONDS * 10;

    runtime.block_on(async {
        open_pre_submission(ledger, &leg, &authorization).await?;

        let due = ledger
            .list_expirable_due_payment_attempts(cutoff, 100)
            .await
            .context("read the TTL sweeper due-query")?;
        let offered = |id: &str| due.iter().any(|attempt| attempt.id == id);
        // Positive control.
        if !offered(&leg.attempt_id) {
            bail!(
                "the TTL sweeper's due-query did not offer PRE-submission attempt {} (hold expired at {}, cutoff {cutoff}); with this query answering nothing the negative check below would be vacuous",
                leg.attempt_id,
                CHAIN_UNIX + HOLD_TTL_SECONDS
            );
        }
        // The money-safety assertion the positive control just gave teeth to.
        if offered(&post_submission.attempt_id) {
            bail!(
                "the TTL sweeper's due-query offered post-submission attempt {} for release",
                post_submission.attempt_id
            );
        }

        // RELEASE: give the credits back FIRST, then mark the attempt terminal.
        let released = ledger
            .release_wallet_reservation(&leg.hold_id, CHAIN_UNIX + 3)
            .await
            .with_context(|| format!("release the hold for {}", leg.attempt_id))?;
        if released.status != WALLET_RESERVATION_RELEASED {
            bail!(
                "releasing hold {} left it {}, expected {WALLET_RESERVATION_RELEASED}",
                leg.hold_id,
                released.status
            );
        }
        expect_applied(
            ledger
                .release_payment_attempt(
                    &leg.attempt_id,
                    PaymentAttemptEvidenceArgs {
                        failure_code: Some(REASON_TTL_EXPIRED),
                        ..Default::default()
                    },
                    CHAIN_UNIX + 3,
                )
                .await,
            "release the expired pre-submission attempt",
        )?;

        let after = ledger
            .list_expirable_due_payment_attempts(cutoff, 100)
            .await
            .context("re-read the TTL sweeper due-query after the release")?;
        if after.iter().any(|attempt| attempt.id == leg.attempt_id) {
            bail!(
                "released attempt {} is still offered to the TTL sweeper",
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
/// is `confirmed`. Trust order is on-chain-authoritative -- the merchant's
/// earlier silence never mattered -- and the confirmed amount is put through
/// [`covers_owed_amount`], the mirror of the shipped
/// `classify_settled_amount`/`decide_confirmed_amount` decision, before anything
/// is captured.
fn run_reconcile_leg(
    origin: &PaidOriginDouble,
    runtime: &Runtime,
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
) -> Result<()> {
    // Positive control for the convergence check at the end of this function.
    // "A settled attempt is no longer offered" means nothing unless the
    // unresolved one IS offered first: an always-empty due-query would satisfy
    // the closing assertion on its own.
    runtime.block_on(async {
        let due = ledger
            .list_reconcilable_payment_attempts(CHAIN_UNIX + HOLD_TTL_SECONDS * 10, 100)
            .await
            .context("read the reconciler due-query before convergence")?;
        if !due.iter().any(|attempt| attempt.id == leg.attempt_id) {
            bail!(
                "the reconciler's due-query never offered unresolved attempt {} -- an unresolved payment that no bounded pass ever picks up is money stuck forever",
                leg.attempt_id
            );
        }
        anyhow::Ok(())
    })?;

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

    // Pass 2: a confirmed transfer that COVERS what is owed -> SETTLE (capture,
    // then mark). "Covers" is the runtime's decision, not equality: see
    // [`covers_owed_amount`].
    let confirmed = origin.facilitator_lookup(&leg.transaction_signature)?;
    if confirmed.status != "confirmed" {
        bail!("the facilitator did not converge to confirmed: {confirmed:?}");
    }
    let owed = after.atomic_amount.clone();
    let Some(settled_atomic_amount) = confirmed.amount.clone() else {
        bail!("a confirmed on-chain transfer reported no amount at all: {confirmed:?}");
    };
    if !covers_owed_amount(&owed, &settled_atomic_amount) {
        bail!(
            "on-chain confirmation reports {settled_atomic_amount} atomic units, the attempt owes {owed} -- a transfer SHORT of what is owed must NOT capture"
        );
    }
    // The evidence records what the CHAIN reported, not what was owed: an
    // overpayment must stay visible as an overpayment rather than be flattened
    // into an exact settlement (#469).
    let evidence = SettlementEvidence {
        transaction_signature: leg.transaction_signature.clone(),
        atomic_amount: settled_atomic_amount,
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
// Leg 5 -- a restarted gateway re-authorizes identically
// ---------------------------------------------------------------------------

/// **This leg does not claim the restart acceptance box.** "... and process
/// restart all land in the documented state without silent loss" is about
/// DURABLE rows surviving a process restart; the ledger this command drives is
/// an in-process [`RuntimeStorageRepositories::in_memory`] owned by the
/// *ferrogate-test* process, which restarting the *gateway* process cannot
/// touch. Reading attempts back from it after the restart would be exactly as
/// green with every restart-recovery path in the payment ledger deleted, so no
/// such read happens here. That box belongs to `payment_attempt_restart.rs`
/// under `postgres-restart` / `supabase-restart`, which restarts against a real
/// database; duplicating it here would make this command skip without Docker.
///
/// What IS a real restart property, and needs no database, is the one asserted
/// below: the gateway is stopped, started again from the same operator config,
/// and must re-issue a **byte-identical authorization** for the same challenge
/// -- same policy revision, same challenge hash, same decision seal, same
/// computed credits. Without that, a payment re-driven after a restart would be
/// charging under an authorization nobody can reproduce, and the durable
/// evidence chain that answers "why was this payment made?" would be broken at
/// its first link.
fn run_gateway_reauthorization_leg(args: &LocalArgs, harness: LocalHarness) -> Result<()> {
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
    drop(restarted);
    Ok(())
}

// ---------------------------------------------------------------------------
// Where the chain came to rest
// ---------------------------------------------------------------------------

/// Every leg must have come to rest in the **exact** state its own transitions
/// demand, holding exactly the money that state mandates, and a duplicate
/// finalize replay against a settled leg must still be a no-op.
///
/// The per-leg expected state is the point. An earlier revision asserted
/// membership in an all-eight-states list, which could only fire on a string
/// that was not any exported constant -- a regression leaving a settled attempt
/// `authorized`, or an ambiguous one `released`, passed it. Naming the terminal
/// per leg is what turns this into an assertion.
///
/// This runs after [`run_gateway_reauthorization_leg`] only because a crashed
/// caller re-driving its settle is the realistic occasion for a duplicate
/// finalize; the replay is proven by the CAS and the hold, not by the restart.
async fn assert_final_ledger_state(
    ledger: &RuntimeStorageRepositories,
    finals: &[(&Leg, &str)],
) -> Result<()> {
    for (leg, expected_state) in finals {
        let links = expect_links(ledger, leg).await?;
        if links.attempt.state != *expected_state {
            bail!(
                "attempt {} came to rest in {:?}, expected {expected_state:?}",
                leg.attempt_id,
                links.attempt.state
            );
        }
        expect_hold_disposition(&links, expected_state)?;

        if *expected_state != PAYMENT_ATTEMPT_SETTLED {
            continue;
        }
        // The duplicate finalize: same attempt, same evidence, re-driven. Both
        // primitives must report a replay rather than a second charge.
        let attempt = &links.attempt;
        let raw = attempt.settlement_response.clone().with_context(|| {
            format!(
                "settled attempt {} carries no settlement response to replay -- a settle replay must never be driven with invented evidence",
                leg.attempt_id
            )
        })?;
        let settled_atomic_amount = attempt.settled_atomic_amount.clone().with_context(|| {
            format!(
                "settled attempt {} carries no settled amount to replay",
                leg.attempt_id
            )
        })?;
        let evidence = SettlementEvidence {
            transaction_signature: leg.transaction_signature.clone(),
            atomic_amount: settled_atomic_amount,
            raw,
        };
        expect_settle_is_idempotent(ledger, leg, &evidence, DUPLICATE_FINALIZE_UNIX).await?;
        expect_exactly_one_capture(ledger, leg).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Whole-chain accounting
// ---------------------------------------------------------------------------

/// The single arithmetic statement the whole chain reduces to: the wallet moved
/// by exactly the captures the chain authorized, and by nothing else. Integer
/// credits, checked arithmetic -- money is never `f64` here.
async fn assert_chain_accounting(
    ledger: &RuntimeStorageRepositories,
    finals: &[(&Leg, &str)],
) -> Result<()> {
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
    // tenant, in the exact state its leg demands -- not merely in "a documented
    // state", which an all-states list can never refute. "Why was this payment
    // made and what happened to it?" is answerable from durable evidence, not
    // log scraping. The listing is BOUNDED (#352 box 6): a page carries at most
    // `limit` rows and resumes through a keyset cursor, so this asks for a page
    // comfortably wider than the attempts the chain makes and asserts the page
    // ends there rather than assuming an unbounded read.
    let page = ledger
        .list_payment_attempts(TENANT_ID, &ferrogate_storage::PaymentAttemptQuery::new(16))
        .await
        .context("list the chain's payment attempts")?;
    if page.next_cursor.is_some() {
        bail!(
            "a 16-row page over {} attempts must be the end of the listing",
            finals.len()
        );
    }
    let listed: HashMap<&str, &str> = page
        .attempts
        .iter()
        .map(|attempt| (attempt.id.as_str(), attempt.state.as_str()))
        .collect();
    let expected: HashMap<&str, &str> = finals
        .iter()
        .map(|(leg, state)| (leg.attempt_id.as_str(), *state))
        .collect();
    if listed != expected {
        bail!("the tenant's payment-attempt listing is {listed:?}, expected exactly {expected:?}");
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

/// `reserve hold -> create attempt -> authorize`. The hold is placed BEFORE any
/// proof exists, so an insufficient balance is refused without ever reaching a
/// signer. Stops short of SUBMIT: this is the state in which a hold is still the
/// TTL sweeper's to reclaim.
async fn open_pre_submission(
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
    )
}

/// [`open_pre_submission`] followed by SUBMIT: the proof is now out, so the hold
/// stops being reclaimable and becomes the reconciler's business.
async fn open_and_submit(
    ledger: &RuntimeStorageRepositories,
    leg: &Leg,
    authorization: &Authorization,
) -> Result<()> {
    open_pre_submission(ledger, leg, authorization).await?;
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

/// Does a reported/observed settled amount COVER what is owed, i.e. may the
/// hold be captured?
///
/// This is a **mirror** of the shipped decision, not the shipped decision
/// itself: `state_x402_settlement.rs::classify_settled_amount` is `pub(crate)`
/// in the binary-only `ferrogate-cli` crate and cannot be linked here, and
/// `state_x402_reconciler.rs::decide_confirmed_amount` is its only caller on the
/// reconcile path. The mirror is kept to a single expression so it is auditable
/// by eye against the original.
///
/// It is `settled >= owed` on PARSED INTEGERS, and both halves of that matter:
///
/// * **Not equality.** The x402 SVM `exact` scheme (`scheme_exact_svm.md` 1.4)
///   defines a matching transfer as one that MAY EXCEED the required amount, and
///   the runtime deliberately SETTLES a spec-valid overpayment (flagging
///   `overpaid`, #469). An earlier revision of this scenario required exact
///   string equality, so a facilitator reporting 2501 against 2500 owed would
///   have failed the chain on a case production settles -- describing a decision
///   the runtime does not make. A sibling slice hit the same trap from the other
///   side on #352: implementing literal equality broke 9 tests that assert an
///   overpayment settles.
/// * **Not strings.** Lexically `"10" < "9"`, which reads a spec-valid
///   overpayment as an underpayment AND a real underpayment as covering. Both
///   are money bugs, in opposite directions.
///
/// Fail-closed: an amount either side of which is not a canonical unsigned
/// decimal is never treated as covering. `u128` mirrors the shipped width (the
/// on-chain domain is `u64`, so nothing overflows). No float ever touches this.
fn covers_owed_amount(owed_atomic_amount: &str, settled_atomic_amount: &str) -> bool {
    match (
        owed_atomic_amount.parse::<u128>(),
        settled_atomic_amount.parse::<u128>(),
    ) {
        (Ok(owed), Ok(settled)) => settled >= owed,
        _ => false,
    }
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

/// The money disposition each resting state mandates. A state whose disposition
/// contradicts its definition is a money bug even when the state name itself is
/// perfectly ordinary, so this is checked separately from the state equality in
/// [`assert_final_ledger_state`].
///
/// There is no silent wildcard: `expected_state` has already been asserted equal
/// to `links.attempt.state`, and the chain must never come to rest mid-flight,
/// so `challenged`/`authorized`/`submitted` are an explicit failure rather than
/// an unexamined `_ => {}`.
fn expect_hold_disposition(links: &PaymentAttemptLinks, expected_state: &str) -> Result<()> {
    let id = &links.attempt.id;
    let hold_status = links.reservation.as_ref().map(|hold| hold.status.as_str());
    match expected_state {
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
            if hold_status == Some(WALLET_RESERVATION_ACTIVE) || links.settlement.is_some() {
                bail!(
                    "attempt {id} is terminal-without-payment yet its money is not given back: {links:?}"
                );
            }
        }
        PAYMENT_ATTEMPT_CHALLENGED | PAYMENT_ATTEMPT_AUTHORIZED | PAYMENT_ATTEMPT_SUBMITTED => {
            bail!("the chain came to rest with attempt {id} still mid-flight in {expected_state:?}")
        }
        other => bail!("attempt {id} came to rest in the invented state {other:?}"),
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

    /// Final sweep over the merchant's counters: no path outside the two this
    /// scenario deliberately pays was ever sent an `X-PAYMENT`, and the total
    /// number of fulfilments is the expected one. Like the denied leg's zero
    /// count, the path filter is a guard on this file rather than a system
    /// property (#381); the side-effect TOTAL, by contrast, is a real merchant
    /// observation -- it is what a duplicate replay would inflate.
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
        if total_side_effects != EXPECTED_ORIGIN_SIDE_EFFECTS {
            bail!(
                "the chain produced {total_side_effects} origin side effects, expected exactly {EXPECTED_ORIGIN_SIDE_EFFECTS}"
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
