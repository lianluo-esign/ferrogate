// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: x402 402-negotiation + single paid replay for the managed
// paid-egress consumer path (issue #381). Activates the #354 settlement loop:
// when an already-authorized egress dispatch returns `402 Payment Required`,
// this parses the #350 wire challenge, runs the #351 spend policy, and on
// `Allow` drives the loop (open -> submit -> finalize) + #352 attempt
// persistence, then performs exactly ONE paid replay of the original request.
//
// -------------------------------------------------------------------------
// Scope of THIS slice (the negotiation core of #381; the issue stays open)
// -------------------------------------------------------------------------
//
// This module owns the single-request negotiation state machine and nothing
// else. The real transport (the standalone agent-worker owns handler execution
// and the actual outbound HTTP) plugs in behind the injected
// [`PaidEgressTransport`] seam, exactly as the #350 signer plugs in behind
// [`SvmTransferSigner`]. That keeps the negotiation unit-testable against a fake
// upstream with no live network, and lets the worker/gateway transport binding
// land as a follow-up without reworking this logic. Streaming/backpressure on
// the paid body, the on-chain-vs-merchant reconciler, the TTL sweeper task, and
// admin/metrics surfacing all remain open on #381.
//
// -------------------------------------------------------------------------
// Invariants
// -------------------------------------------------------------------------
//
//   * SINGLE paid replay. At most two dispatches happen per context: the
//     initial unpaid dispatch and exactly one paid replay. There is no loop; a
//     second 402 after paying is a typed failure, never another attempt.
//   * Policy is authoritative. `Deny`/`ApprovalRequired` short-circuit BEFORE
//     any wallet hold, signer call, or dispatch -- the signer is never invoked
//     for a payment policy did not allow, and insufficient funds never reaches
//     the signer either (the hold is opened before the proof is built).
//   * Fail closed on ambiguity. After the proof is submitted (`submit`), any
//     outcome that is not durable on-chain-settlement proof is parked
//     `outcome_unknown` with the hold RETAINED (never a false release that could
//     spend stablecoin for free). A merchant-reported failure header is NOT
//     on-chain proof, so it too parks unknown; the definite FAIL/RELEASE edges
//     are reserved for the on-chain reconciler (remaining #381 work).
//   * The AMOUNT is verified before the hold is captured. A merchant claiming
//     success is never taken at its word about how much it settled: the reported
//     amount is compared against the owed `atomic_amount` on parsed integers,
//     through the SAME shared comparison the on-chain reconciler applies
//     (#469/#476). A report SHORT of what is owed -- or one that omits the amount
//     entirely -- parks `outcome_unknown` instead of capturing.
//   * Attribution + evidence preserved. Request/trace ids flow into the durable
//     attempt, and every terminal path returns the policy decision, the attempt
//     id, and the settlement edge outcome as inspectable evidence.
//
// Until the transport binding lands, the non-test build has no caller, so allow
// dead_code off the test path -- mirroring `state_x402_settlement.rs` (#354).
#![cfg_attr(not(test), allow(dead_code))]

use std::fmt;

use ferrogate_payments::{
    build_payment_signature, parse_payment_required, parse_payment_response, select_requirement,
    PaymentError, RequirementFilter, SelectedPayment, SvmTransferSigner, SCHEME_EXACT,
    X402_VERSION,
};
use ferrogate_policy::{
    authorize_x402_payment, PaymentAuthorization, PaymentAuthorizationRequest, PaymentDecision,
    SpendScope, SpendSnapshot, ValidatedX402SpendPolicy,
};
use ferrogate_storage::StorageError;

use super::state_x402_settlement::{
    classify_settled_amount, AmountCoverage, EdgeOutcome, OpenOutcome, PaidEgressOpen,
    SettlementEvidence, X402SettlementLoop,
};

/// HTTP status a paid-egress upstream returns to demand payment.
const STATUS_PAYMENT_REQUIRED: u16 = 402;

/// A bounded view of an upstream egress response, reduced to exactly what the
/// x402 negotiation needs. The transport is responsible for enforcing body-size
/// caps and for extracting the x402 headers; this struct never buffers an
/// unbounded body itself (the paid-body streaming path is separate #381 work).
#[derive(Debug, Clone, Default)]
pub(crate) struct EgressResponse {
    /// Upstream HTTP status code.
    pub status: u16,
    /// The `PAYMENT-REQUIRED` header value (base64), present on a 402.
    pub payment_required: Option<String>,
    /// The `PAYMENT-RESPONSE` settlement header value (base64), present on a
    /// paid replay the upstream honoured.
    pub payment_response: Option<String>,
}

impl EgressResponse {
    fn is_payment_required(&self) -> bool {
        self.status == STATUS_PAYMENT_REQUIRED
    }

    fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Transport-level failure of a dispatch (connection reset, timeout, TLS, ...).
/// Deliberately opaque: the negotiation only needs to know the dispatch did not
/// produce a response, so it can fail closed.
#[derive(Debug, Clone)]
pub(crate) struct X402TransportError {
    pub message: String,
}

impl X402TransportError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for X402TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x402 egress transport error: {}", self.message)
    }
}

impl std::error::Error for X402TransportError {}

/// The injected outbound-egress boundary. One implementation performs the real,
/// already-governed HTTP request (target validated + allowlisted upstream);
/// tests supply a fake upstream. When `payment_signature` is `Some`, the
/// implementation MUST attach it under the `PAYMENT-SIGNATURE` header and
/// otherwise replay the identical original request.
///
/// The negotiation calls this at most twice: once unpaid, then at most once
/// paid. It is the ONLY place network I/O happens, keeping the negotiation core
/// pure and unit-testable.
#[allow(async_fn_in_trait)]
pub(crate) trait PaidEgressTransport {
    /// Dispatch the (already-authorized) egress request. `payment_signature` is
    /// the base64 `PAYMENT-SIGNATURE` value to attach, or `None` for the initial
    /// unpaid dispatch.
    async fn dispatch(
        &self,
        payment_signature: Option<&str>,
    ) -> Result<EgressResponse, X402TransportError>;
}

/// Immutable, borrowed inputs describing the one egress request being
/// negotiated. All attribution flows into the durable payment attempt so a
/// settlement can always be tied back to the run/trace that triggered it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct X402NegotiationContext<'a> {
    pub tenant_id: &'a str,
    pub project_id: Option<&'a str>,
    pub workspace_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub worker_id: Option<&'a str>,
    pub key_id: Option<&'a str>,
    pub request_id: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    /// HTTP method of the original request.
    pub method: &'a str,
    /// The egress URL FerroGate already authorized. The challenge's own resource
    /// must canonically match this (the #351 policy enforces the binding); a
    /// challenge can never redirect payment to a different URL.
    pub authorized_resource_url: &'a str,
    /// Optional hash of the request body, recorded as attempt evidence.
    pub request_body_hash: Option<&'a str>,
    /// Seconds the wallet hold stays live before it is TTL-eligible for release.
    pub hold_ttl_secs: i64,
    /// Stable per-request idempotency token (e.g. the request id). Combined with
    /// the deterministic challenge hash to form the attempt id, so replaying the
    /// same request against the same challenge is idempotent on the loop.
    pub idempotency_key: &'a str,
}

/// Terminal result of a successful (non-error) negotiation.
#[derive(Debug)]
pub(crate) enum X402Negotiation {
    /// The upstream did not demand payment; its original response passes through
    /// untouched. No wallet, signer, or attempt was involved.
    NotRequired { response: EgressResponse },
    /// The paid replay completed. `settlement` is the loop edge outcome the
    /// settlement evidence drove (`Settled` on durable on-chain proof, otherwise
    /// `OutcomeUnknown` with the hold retained for the reconciler).
    Paid {
        response: EgressResponse,
        attempt_id: String,
        authorization: Box<PaymentAuthorization>,
        settlement: EdgeOutcome,
    },
}

/// Why an insufficiently-funded open could not proceed. Neither variant ever
/// reaches the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FundingRejection {
    /// The tenant wallet exists but cannot cover the hold.
    Insufficient {
        available_credits: i64,
        requested_credits: i64,
    },
    /// No wallet governs the tenant, so paid egress has no funding source.
    NoWallet,
}

/// The typed failure classes of a negotiation. Every non-happy path is one of
/// these variants so a caller/audit surface can branch without string matching;
/// each carries the evidence needed to explain the outcome after the fact.
#[derive(Debug)]
pub(crate) enum X402NegotiationError {
    /// The 402 carried no (or a malformed) `PAYMENT-REQUIRED` challenge header.
    MalformedChallenge { reason: String },
    /// The challenge parsed but no requirement was acceptable to the wire
    /// contract (unsupported scheme/network/mint, bad amount/recipient/timeout).
    ChallengeUnacceptable { source: PaymentError },
    /// The #351 spend policy refused the payment (`Deny`) or requires explicit
    /// out-of-band approval (`ApprovalRequired`). No hold, signer, or replay.
    PolicyRejected {
        authorization: Box<PaymentAuthorization>,
    },
    /// The wallet could not fund the hold. The signer was never invoked.
    Unfundable {
        rejection: FundingRejection,
        authorization: Box<PaymentAuthorization>,
    },
    /// The injected signer refused to build the proof. The pre-submission hold
    /// was released; nothing was submitted.
    SignerRejected {
        reason: String,
        attempt_id: String,
        authorization: Box<PaymentAuthorization>,
    },
    /// The upstream demanded payment AGAIN after a paid replay. This is never
    /// retried: the proof was already submitted, so the attempt is parked at
    /// `settlement` (retained hold) for the reconciler, and this typed failure
    /// is returned instead of looping.
    SecondPaymentRequired {
        attempt_id: String,
        authorization: Box<PaymentAuthorization>,
        settlement: EdgeOutcome,
    },
    /// The paid replay failed for a non-payment reason (a non-2xx, non-402
    /// status). The proof was already submitted, so the attempt is parked at
    /// `settlement` (retained hold) for the reconciler.
    ReplayFailed {
        status: u16,
        attempt_id: String,
        authorization: Box<PaymentAuthorization>,
        settlement: EdgeOutcome,
    },
    /// A transport dispatch failed. If it failed AFTER the proof was submitted,
    /// `settlement` records the parked (retained-hold) attempt.
    Transport {
        source: X402TransportError,
        attempt_id: Option<String>,
        settlement: Option<EdgeOutcome>,
    },
    /// An internal invariant was violated (e.g. an `Allow` decision with no
    /// computed credits, or credits that overflow the wallet integer domain).
    /// Fails closed.
    Internal { reason: String },
    /// A durable storage primitive returned an error while driving the loop.
    Storage { source: StorageError },
}

impl fmt::Display for X402NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedChallenge { reason } => {
                write!(f, "x402 challenge is malformed: {reason}")
            }
            Self::ChallengeUnacceptable { source } => {
                write!(f, "x402 challenge has no acceptable requirement: {source}")
            }
            Self::PolicyRejected { authorization } => write!(
                f,
                "x402 payment rejected by policy ({}): {}",
                authorization.reason_code, authorization.message
            ),
            Self::Unfundable { rejection, .. } => match rejection {
                FundingRejection::Insufficient {
                    available_credits,
                    requested_credits,
                } => write!(
                    f,
                    "x402 payment unfunded: wallet has {available_credits} credits, needs {requested_credits}"
                ),
                FundingRejection::NoWallet => {
                    write!(f, "x402 payment unfunded: no wallet governs the tenant")
                }
            },
            Self::SignerRejected { reason, .. } => {
                write!(f, "x402 signer refused to build the proof: {reason}")
            }
            Self::SecondPaymentRequired { .. } => write!(
                f,
                "x402 upstream demanded payment again after a paid replay (not retried)"
            ),
            Self::ReplayFailed { status, .. } => {
                write!(f, "x402 paid replay failed with status {status}")
            }
            Self::Transport { source, .. } => write!(f, "{source}"),
            Self::Internal { reason } => write!(f, "x402 negotiation internal error: {reason}"),
            Self::Storage { source } => write!(f, "x402 negotiation storage error: {source}"),
        }
    }
}

impl std::error::Error for X402NegotiationError {}

impl From<StorageError> for X402NegotiationError {
    fn from(source: StorageError) -> Self {
        Self::Storage { source }
    }
}

/// Drive the full 402-negotiation + single paid replay for one egress request.
///
/// Dispatches the request once unpaid; if the upstream does not demand payment
/// the original response passes straight through. On a 402 it parses the #350
/// challenge, runs the #351 policy, and on `Allow` opens the #354 loop (wallet
/// hold + `authorized` attempt), builds the proof with the injected signer,
/// marks the attempt `submitted`, then replays the request EXACTLY ONCE with the
/// `PAYMENT-SIGNATURE` attached. The paid replay's outcome drives the loop's
/// finalize edge and is returned as inspectable evidence.
///
/// `now_unix` is supplied by the caller (matching the loop's convention) so the
/// negotiation stays deterministic and testable.
pub(crate) async fn negotiate_paid_egress<T: PaidEgressTransport>(
    loop_: &X402SettlementLoop,
    policy: &ValidatedX402SpendPolicy,
    spent: &SpendSnapshot,
    ctx: &X402NegotiationContext<'_>,
    transport: &T,
    signer: &dyn SvmTransferSigner,
    now_unix: i64,
) -> Result<X402Negotiation, X402NegotiationError> {
    // 1. Initial, unpaid dispatch. Nothing to clean up if it fails.
    let first =
        transport
            .dispatch(None)
            .await
            .map_err(|source| X402NegotiationError::Transport {
                source,
                attempt_id: None,
                settlement: None,
            })?;
    if !first.is_payment_required() {
        return Ok(X402Negotiation::NotRequired { response: first });
    }

    // 2. Parse + select the challenge (#350). A missing header on a 402 is a
    //    malformed challenge; a parse/selection error is a typed failure.
    let header = first.payment_required.as_deref().ok_or_else(|| {
        X402NegotiationError::MalformedChallenge {
            reason: "402 response carried no PAYMENT-REQUIRED header".to_string(),
        }
    })?;
    let required = parse_payment_required(header)
        .map_err(|source| X402NegotiationError::ChallengeUnacceptable { source })?;
    let filter = build_requirement_filter(policy);
    let selected = select_requirement(&required, &filter)
        .map_err(|source| X402NegotiationError::ChallengeUnacceptable { source })?;

    // 3. Spend policy decision (#351). This is the sole payment authority and
    //    runs BEFORE any wallet hold, signer call, or replay.
    let scope = SpendScope {
        tenant_id: ctx.tenant_id,
        project_id: ctx.project_id,
        workspace_id: ctx.workspace_id,
        key_id: ctx.key_id,
        run_id: ctx.run_id,
    };
    let request = PaymentAuthorizationRequest {
        selected: &selected,
        authorized_resource_url: ctx.authorized_resource_url,
        scope,
    };
    let authorization = authorize_x402_payment(policy, &request, spent);
    if !matches!(authorization.decision, PaymentDecision::Allow) {
        // Deny AND ApprovalRequired short-circuit without paying.
        return Err(X402NegotiationError::PolicyRejected {
            authorization: Box::new(authorization),
        });
    }
    let authorization = Box::new(authorization);

    // 4. Open the loop: wallet hold (#281) + durable `authorized` attempt (#352).
    //    Insufficient funds / no wallet never reaches the signer below.
    let credits_amount = credits_i64(&authorization)?;
    let attempt_id = format!("{}:{}", ctx.idempotency_key, selected.challenge_hash_hex());
    let open = build_open(ctx, &selected, &authorization, &attempt_id, credits_amount);
    match loop_.open(&open, now_unix).await? {
        OpenOutcome::Opened(_) => {}
        OpenOutcome::Insufficient {
            available_credits,
            requested_credits,
        } => {
            return Err(X402NegotiationError::Unfundable {
                rejection: FundingRejection::Insufficient {
                    available_credits,
                    requested_credits,
                },
                authorization,
            });
        }
        OpenOutcome::NoWallet => {
            return Err(X402NegotiationError::Unfundable {
                rejection: FundingRejection::NoWallet,
                authorization,
            });
        }
    }

    // 5. Build the proof via the injected signer (#350/#353). A refusal releases
    //    the still-pre-submission hold and nothing is submitted.
    let payment_signature = match build_payment_signature(&selected, signer) {
        Ok(signature) => signature,
        Err(error) => {
            // Best-effort release of the pre-submission hold; a release failure
            // is swallowed in favour of surfacing the original signer refusal
            // (the hold is TTL-swept as a fallback).
            let _ = loop_
                .cancel(&attempt_id, "x402_signer_rejected", now_unix)
                .await;
            return Err(X402NegotiationError::SignerRejected {
                reason: error.to_string(),
                attempt_id,
                authorization,
            });
        }
    };

    // 6. Mark the attempt submitted (proof is going on-chain). After this a
    //    non-settlement outcome is `outcome_unknown`, never a release. The submit
    //    CAS also persists the on-chain transaction signature when it is already
    //    known here (#399). In the SVM `exact` facilitator flow the base64
    //    `PAYMENT-SIGNATURE` proof built above is NOT the base58 on-chain
    //    transaction signature (the facilitator co-signs as fee payer and reports
    //    the settled signature only in the `PAYMENT-RESPONSE` header), so there is
    //    no chain-queryable signature to persist yet -- pass `None` and let the
    //    finalize/park edge below persist it the moment the merchant reports one.
    //    Storing the proof here would poison the reconciler's chain lookup, so it
    //    is deliberately not done.
    loop_.submit(&attempt_id, None, now_unix, now_unix).await?;

    // 7. The SINGLE paid replay. There is no loop here: at most one paid attempt.
    let paid = match transport.dispatch(Some(&payment_signature)).await {
        Ok(response) => response,
        Err(source) => {
            // Dispatch failed after submit: we cannot know the on-chain outcome,
            // so park unknown (retain the hold) for the reconciler.
            let settlement = finalize_settlement(loop_, &attempt_id, &selected, None, now_unix)
                .await
                .ok();
            return Err(X402NegotiationError::Transport {
                source,
                attempt_id: Some(attempt_id),
                settlement,
            });
        }
    };

    // 8. Classify the paid replay and drive the matching finalize edge.
    if paid.is_payment_required() {
        // A second 402 is a typed failure -- NEVER a third attempt. The proof was
        // already submitted, so this parks unknown (retained hold), never a
        // release.
        let settlement = finalize_settlement(
            loop_,
            &attempt_id,
            &selected,
            paid.payment_response.as_deref(),
            now_unix,
        )
        .await?;
        return Err(X402NegotiationError::SecondPaymentRequired {
            attempt_id,
            authorization,
            settlement,
        });
    }

    if !paid.is_success() {
        let settlement = finalize_settlement(
            loop_,
            &attempt_id,
            &selected,
            paid.payment_response.as_deref(),
            now_unix,
        )
        .await?;
        return Err(X402NegotiationError::ReplayFailed {
            status: paid.status,
            attempt_id,
            authorization,
            settlement,
        });
    }

    // 2xx: the resource was served. Drive the settlement edge from whatever
    // evidence the PAYMENT-RESPONSE carried (durable on-chain proof -> Settled;
    // anything ambiguous -> outcome_unknown with the hold retained).
    let settlement = finalize_settlement(
        loop_,
        &attempt_id,
        &selected,
        paid.payment_response.as_deref(),
        now_unix,
    )
    .await?;
    Ok(X402Negotiation::Paid {
        response: paid,
        attempt_id,
        authorization,
        settlement,
    })
}

/// Build the wire-contract requirement filter from the validated policy so
/// selection prefers a requirement the policy can actually authorize. The #351
/// decision remains the authoritative gate regardless.
fn build_requirement_filter(policy: &ValidatedX402SpendPolicy) -> RequirementFilter<'static> {
    // A `RequirementFilter` borrows its slices; rather than thread lifetimes for
    // a preference-only filter, fall back to the permissive (any recognised
    // network/mint) filter and let `authorize_x402_payment` be the single
    // authority. This keeps the policy source of truth in exactly one place.
    let _ = policy;
    RequirementFilter::default()
}

/// Convert the authorized payment's computed credits into the wallet integer
/// domain. An `Allow` decision always carries computed credits (policy only
/// allows after a successful conversion), so a missing/overflowing value is an
/// internal invariant violation that fails closed.
fn credits_i64(authorization: &PaymentAuthorization) -> Result<i64, X402NegotiationError> {
    let credits =
        authorization
            .computed_credits()
            .ok_or_else(|| X402NegotiationError::Internal {
                reason: "allowed payment has no computed credits".to_string(),
            })?;
    i64::try_from(credits.0).map_err(|_| X402NegotiationError::Internal {
        reason: format!(
            "computed credits {} overflow the wallet integer domain",
            credits.0
        ),
    })
}

/// Assemble the loop's [`PaidEgressOpen`] from the negotiation context, the
/// selected requirement, and the policy decision. All attribution is preserved.
fn build_open(
    ctx: &X402NegotiationContext<'_>,
    selected: &SelectedPayment,
    authorization: &PaymentAuthorization,
    attempt_id: &str,
    credits_amount: i64,
) -> PaidEgressOpen {
    PaidEgressOpen {
        attempt_id: attempt_id.to_string(),
        tenant_id: ctx.tenant_id.to_string(),
        project_id: ctx.project_id.map(str::to_string),
        workspace_id: ctx.workspace_id.map(str::to_string),
        run_id: ctx.run_id.map(str::to_string),
        worker_id: ctx.worker_id.map(str::to_string),
        request_id: ctx.request_id.map(str::to_string),
        trace_id: ctx.trace_id.map(str::to_string),
        method: ctx.method.to_string(),
        // Bind the durable attempt to the URL FerroGate authorized (which the
        // policy proved equals the challenge resource), not the untrusted
        // challenge-echoed URL.
        resource_url: ctx.authorized_resource_url.to_string(),
        request_body_hash: ctx.request_body_hash.map(str::to_string),
        challenge_hash: selected.challenge_hash_hex(),
        x402_version: X402_VERSION as i64,
        scheme: SCHEME_EXACT.to_string(),
        network_caip2: selected.network.caip2().to_string(),
        mint: selected.mint.clone(),
        atomic_amount: selected.atomic_amount.to_string(),
        recipient: selected.recipient.clone(),
        credits_amount,
        conversion_version: Some(authorization.conversion.version.clone()),
        policy_revision: authorization.policy_revision as i64,
        decision: "allow".to_string(),
        reason_code: authorization.reason_code.to_string(),
        hold_ttl_secs: ctx.hold_ttl_secs,
    }
}

/// How the merchant's REPORTED settled amount compares to what is owed. Only
/// [`Self::Covers`] may drive a capture; the other two are money-safety parks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReportedAmount {
    /// The reported amount COVERS what is owed (`settled >= owed`, exact or a
    /// spec-valid overpayment). Carries the amount actually OBSERVED (never the
    /// owed amount) so the durable evidence stays honest, plus the excess when
    /// the report exceeded what was owed.
    Covers {
        settled_atomic_amount: String,
        overpayment_atomic_amount: Option<String>,
    },
    /// The merchant reported LESS than what is owed (or an amount that does not
    /// parse as a canonical atomic value). Fail-closed: never captures.
    Short { observed_atomic_amount: String },
    /// The merchant reported success but NO amount at all. Fail-closed: never
    /// captures. (Before #476 this silently assumed the owed amount had been
    /// paid, which let an amount-less success claim capture the full hold.)
    Absent,
}

/// Classify the merchant-reported settled amount against what is owed, deferring
/// the comparison itself to [`classify_settled_amount`] -- the SAME `u128` parse
/// and `settled >= owed` test the on-chain reconciler applies (#469), so the two
/// paths that can capture a hold cannot drift apart again (#476).
///
/// Both inputs here are already integers (the frozen #350 wire parse yields `u64`
/// on each side, and rejects a non-canonical amount before it ever reaches this
/// function), so the shared string comparison can never see garbage on this path.
/// It is used regardless: the point is that ONE function decides "does this cover
/// what is owed", not that this path needs the parse.
fn classify_reported_amount(
    owed_atomic_amount: &str,
    reported_atomic_amount: Option<u64>,
) -> ReportedAmount {
    let Some(reported) = reported_atomic_amount else {
        return ReportedAmount::Absent;
    };
    let observed = reported.to_string();
    match classify_settled_amount(owed_atomic_amount, &observed) {
        AmountCoverage::Covers {
            overpayment_atomic_amount,
        } => ReportedAmount::Covers {
            settled_atomic_amount: observed,
            overpayment_atomic_amount,
        },
        AmountCoverage::Short => ReportedAmount::Short {
            observed_atomic_amount: observed,
        },
    }
}

/// Reduce a paid replay's `PAYMENT-RESPONSE` header (if any) to a settlement
/// edge and drive the loop's finalize.
///
/// Trust discipline: the ONLY evidence that drives the definite SETTLE edge
/// (capture the tenant's wallet hold) is a successful settlement header that
/// carries BOTH a valid on-chain transaction signature AND a reported settled
/// amount that COVERS the owed `atomic_amount` -- verified on parsed integers via
/// the shared [`classify_settled_amount`], exactly as the on-chain reconciler
/// verifies a confirmed transfer (#469/#476). Everything else -- a missing
/// header, a parse failure, a success flag without a signature, a merchant-
/// reported failure, a reported amount SHORT of what is owed, or a success claim
/// that omits the amount entirely -- is ambiguous and parks the attempt
/// `outcome_unknown` with the hold RETAINED.
///
/// Why underpayment and an ABSENT amount park rather than fail: the FAIL edge
/// RELEASES the hold, and a merchant claim is not on-chain proof in either
/// direction. A short/absent report may still correspond to a full transfer that
/// did land on-chain, so releasing here could spend stablecoin for free -- the
/// same reason a merchant-reported failure has never driven a release. Parking is
/// the outcome that composes with the rest of the machine: the #354 reconciler
/// picks up exactly `submitted`/`outcome_unknown` attempts and resolves them
/// against the chain (authoritative), the TTL sweeper deliberately never touches
/// them, and the signature (when the header carried one) is persisted at this
/// park CAS (#399) so the reconciler can query the chain from storage alone.
/// A definite FAIL/RELEASE therefore stays the on-chain reconciler's to drive.
///
/// NOT changed here (deliberately, and the residual risk of this path): a report
/// that COVERS the owed amount still settles inline on the merchant's word. The
/// chain is authoritative, but no on-chain RPC client is bound yet
/// (`UnboundOnChainRpc`), so deferring every capture to the reconciler today
/// would strand every paid attempt in `outcome_unknown` indefinitely -- the
/// sweeper never releases a post-submission hold. Verifying the amount removes
/// the "claim success, pay less, capture in full" hole; moving capture behind
/// on-chain confirmation is the separate design change that needs the live RPC
/// transport first (#354).
async fn finalize_settlement(
    loop_: &X402SettlementLoop,
    attempt_id: &str,
    selected: &SelectedPayment,
    payment_response: Option<&str>,
    now_unix: i64,
) -> Result<EdgeOutcome, StorageError> {
    let parsed =
        payment_response.and_then(|header| parse_payment_response(header, selected.network).ok());
    let owed_atomic_amount = selected.atomic_amount.to_string();

    // A merchant report is only a SETTLE candidate when it claims success AND
    // carries an on-chain signature; only then is its amount worth comparing.
    let claimed = parsed
        .as_ref()
        .filter(|evidence| evidence.success && evidence.transaction_signature.is_some());
    let reported = claimed
        .map(|evidence| classify_reported_amount(&owed_atomic_amount, evidence.settled_amount));

    let evidence = match (claimed, reported.as_ref()) {
        (
            Some(claimed),
            Some(ReportedAmount::Covers {
                settled_atomic_amount,
                overpayment_atomic_amount,
            }),
        ) => {
            if let Some(excess) = overpayment_atomic_amount.as_deref() {
                // Spec-valid overpayment: the hold captures only the amount it
                // reserved (the owed amount -- `settle_wallet_reservation` takes
                // no amount argument), so the excess is never captured. Logged so
                // an overpaid settle stays distinguishable from an exact one,
                // mirroring the reconciler (#469).
                tracing::info!(
                    attempt_id,
                    owed = %owed_atomic_amount,
                    settled = %settled_atomic_amount,
                    excess = %excess,
                    "x402 finalize: merchant reported an OVERPAYMENT (spec-valid, settled > \
                     owed); settling with the hold capturing the owed amount only"
                );
            }
            SettlementEvidence::Settled {
                transaction_signature: claimed
                    .transaction_signature
                    .as_deref()
                    .expect("checked is_some above"),
                // The amount OBSERVED in the merchant report, never the owed
                // amount: an overpaid settlement therefore persists a
                // `settled_atomic_amount` that differs from the attempt's
                // `atomic_amount`, keeping the two cases distinguishable in the
                // durable row (#469/#476).
                settled_atomic_amount,
                response: payment_response,
            }
        }
        // Ambiguous: park `outcome_unknown` (hold retained). If the merchant
        // header nonetheless carried a transaction signature, persist it into the
        // durable column at this park CAS (#399) so the on-chain reconciler can
        // resolve the attempt from storage instead of re-parsing the untrusted
        // header every tick -- the earliest edge a signature is known that is not
        // a settle.
        _ => {
            match reported.as_ref() {
                Some(ReportedAmount::Short {
                    observed_atomic_amount,
                }) => tracing::warn!(
                    attempt_id,
                    owed = %owed_atomic_amount,
                    observed = %observed_atomic_amount,
                    "x402 finalize: merchant claimed success for LESS than the owed amount; \
                     NOT capturing the hold, parking outcome_unknown for on-chain \
                     reconciliation (fail-closed)"
                ),
                Some(ReportedAmount::Absent) => tracing::warn!(
                    attempt_id,
                    owed = %owed_atomic_amount,
                    "x402 finalize: merchant claimed success but reported NO settled amount; \
                     NOT assuming the owed amount was paid, parking outcome_unknown for \
                     on-chain reconciliation (fail-closed)"
                ),
                _ => {}
            }
            SettlementEvidence::Unknown {
                response: payment_response,
                transaction_signature: parsed
                    .as_ref()
                    .and_then(|evidence| evidence.transaction_signature.as_deref()),
            }
        }
    };
    loop_.finalize(attempt_id, &evidence, now_unix).await
}

#[cfg(test)]
#[path = "state_x402_negotiation_test.rs"]
mod state_x402_negotiation_test;
