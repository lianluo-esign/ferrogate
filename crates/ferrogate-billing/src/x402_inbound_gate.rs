// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: The inbound x402 decision gate (issue #356): admission + settlement
// verification + forward-once claim + revenue recording, composed into one total
// decision the private FerroGate upstream can act on.

//! The inbound x402 gate (issue #356).
//!
//! [`InboundX402Gate::evaluate`] is the single decision point in front of the one
//! monetized route. It composes the three halves that each own one refusal
//! class:
//!
//! | Stage | Module | Refuses |
//! |---|---|---|
//! | Sidecar admission | [`crate::x402_inbound_admission`] | bypass, spoofed attribution, ambiguous headers |
//! | Fixed-price settlement | [`crate::x402_inbound`] | wrong network/mint/amount, unsuccessful settlement |
//! | Forward-once claim | [`crate::x402_inbound_forward`] | duplicate forwarding, replayed proof |
//!
//! ## `evaluate` is total on purpose
//!
//! It returns [`InboundX402Decision`] and never `Result`. Infrastructure faults
//! (a poisoned lock, a full claim guard, a revenue sink that refuses to write)
//! come back as [`InboundX402Decision::Refused`] with
//! [`InboundX402Refusal::Unavailable`], not as an `Err`. A `Result` invites a
//! caller to `?` its way past the gate; with a total decision the only value
//! that reaches the protected handler is [`InboundX402Decision::Forward`].
//!
//! ## Two different identities, and why the claim uses the sidecar's
//!
//! The claim owner is the **sidecar** request id, not FerroGate's. FerroGate
//! mints a fresh request id per HTTP request, so a sidecar timeout-and-retry of
//! the *same* paid call would arrive with a different FerroGate id and be
//! indistinguishable from a stolen proof. The sidecar id is stable across that
//! retry, which is exactly the distinction
//! [`ClaimOutcome::DuplicateRetry`] vs [`ClaimOutcome::ProofReplay`] rests on.
//! FerroGate's own request/trace ids stay on the revenue record as attribution.
//!
//! ## Durable backstop before the in-memory claim
//!
//! The claim guard is process-local and TTL-bounded, so a restart or an expiry
//! loses it. Before claiming, the gate asks the [`RevenueSink`] whether this
//! exact payment already produced a record. That closes replay across a claim
//! loss **to the extent the configured sink is durable** — with the in-memory
//! sink it is not, and that residual is stated in
//! `docs/x402-inbound-sidecar.md` rather than papered over.

use std::sync::Arc;

use ferrogate_payments::{parse_payment_response, PaymentError, HEADER_PAYMENT_RESPONSE};

use crate::x402_inbound::{
    settle_inbound_payment, InboundX402CallContext, InboundX402Challenge, InboundX402RevenueRecord,
    InboundX402SettlementError, RevenueSink, ValidatedInboundX402Endpoint,
};
use crate::x402_inbound_admission::{
    AdmittedRequest, ForwardedRequest, InboundX402AdmissionError, SidecarAdmissionPolicy,
};
use crate::x402_inbound_forward::{ClaimOutcome, ForwardClaimGuard};
use crate::BillingError;

/// FerroGate's own identity for the inbound call, minted by the gateway. Never
/// derived from a caller header — [`RESERVED_ATTRIBUTION_HEADERS`] refuses any
/// request that tries.
///
/// [`RESERVED_ATTRIBUTION_HEADERS`]: crate::x402_inbound_admission::RESERVED_ATTRIBUTION_HEADERS
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundCallIdentity {
    /// FerroGate request id for this HTTP request.
    pub request_id: String,
    /// Trace id, when tracing is on.
    pub trace_id: Option<String>,
}

/// What the private upstream must do with an inbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundX402Decision {
    /// No payment proof presented: answer 402 with this challenge.
    PaymentRequired(InboundX402Challenge),
    /// Settled, first claim: invoke the protected handler exactly once.
    Forward(Box<ForwardAuthorization>),
    /// The same sidecar request arriving again on an already-claimed payment.
    /// Idempotent: do NOT invoke the handler; answer 409.
    AlreadyForwarded {
        /// The revenue record id (challenge hash + transaction signature).
        payment_key: String,
        /// The sidecar request id that holds the claim.
        first_sidecar_request_id: String,
    },
    /// Refused. The protected handler is not reached.
    Refused(InboundX402Refusal),
}

impl InboundX402Decision {
    /// HTTP status the private upstream returns for this decision.
    /// [`Self::Forward`] has none — the handler's own response is returned.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::PaymentRequired(challenge) => Some(challenge.http_status),
            Self::Forward(_) => None,
            Self::AlreadyForwarded { .. } => Some(409),
            Self::Refused(refusal) => Some(refusal.http_status()),
        }
    }

    /// Whether the protected handler is invoked. True for exactly one variant.
    pub fn forwards(&self) -> bool {
        matches!(self, Self::Forward(_))
    }
}

/// Why a request was refused. Every variant means the handler was not reached
/// and no revenue was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402Refusal {
    /// The request is not an admissible sidecar forward.
    Admission(InboundX402AdmissionError),
    /// The `PAYMENT-RESPONSE` header is present but not parseable as settlement
    /// evidence for this endpoint's network.
    MalformedSettlement { reason: String },
    /// Settlement evidence did not match the fixed price.
    Settlement(InboundX402SettlementError),
    /// A different request presented an already-claimed payment.
    ProofReplay {
        /// The revenue record id that is already claimed.
        payment_key: String,
        /// The sidecar request id that legitimately holds the claim.
        first_sidecar_request_id: String,
    },
    /// The gate could not decide. Fails closed: the handler is not reached.
    Unavailable {
        /// Stable billing error code.
        code: String,
        /// Operator-facing detail.
        message: String,
    },
}

impl InboundX402Refusal {
    /// HTTP status for this refusal.
    ///
    /// A replayed proof is **402, not 403**: the caller may legitimately obtain
    /// a fresh payment for a fresh call, and the 402 hands back the challenge
    /// that lets it. A 403 would tell a paying client it is permanently barred.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Admission(error) => error.http_status(),
            Self::MalformedSettlement { .. } => 402,
            Self::Settlement(_) => 402,
            Self::ProofReplay { .. } => 402,
            Self::Unavailable { .. } => 503,
        }
    }

    /// Stable machine-readable code for logs and admin surfaces.
    pub fn code(&self) -> &str {
        match self {
            Self::Admission(error) => error.code(),
            Self::MalformedSettlement { .. } => "x402_inbound_malformed_settlement",
            Self::Settlement(_) => "x402_inbound_settlement_rejected",
            Self::ProofReplay { .. } => "x402_inbound_proof_replay",
            Self::Unavailable { code, .. } => code.as_str(),
        }
    }
}

/// Authorization to invoke the protected handler exactly once, plus everything
/// the gateway needs to forward safely and attribute the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardAuthorization {
    /// The settled revenue record. Its `id` is the forward-once claim key.
    pub record: InboundX402RevenueRecord,
    /// The admitted request, carrying the verified transport and the tenant.
    pub admitted: AdmittedRequest,
    /// Headers the gateway MUST remove before the request reaches the handler.
    pub headers_to_strip: Vec<&'static str>,
}

impl ForwardAuthorization {
    /// The forward-once claim key for this authorization.
    pub fn payment_key(&self) -> &str {
        &self.record.id
    }

    /// Correlated log/audit evidence: sidecar admission fields plus the payment
    /// identity. Excludes the sidecar credential and the raw payment proof —
    /// this surface exists to correlate a paid call, not to reproduce it.
    pub fn evidence_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.admitted.evidence_fields();
        fields.push(("request_id", self.record.request_id.clone()));
        if let Some(trace_id) = &self.record.trace_id {
            fields.push(("trace_id", trace_id.clone()));
        }
        fields.push(("x402_payment_key", self.record.id.clone()));
        fields.push((
            "x402_challenge_hash",
            self.record.challenge_hash_hex.clone(),
        ));
        fields.push((
            "x402_transaction",
            self.record.transaction_signature.clone(),
        ));
        fields.push(("x402_network", self.record.network_caip2.clone()));
        fields.push(("x402_amount_atomic", self.record.atomic_amount.to_string()));
        if let Some(payer) = &self.record.payer {
            fields.push(("x402_payer", payer.clone()));
        }
        fields
    }
}

/// The composed inbound gate. Cloneable and shareable: the claim guard and
/// revenue sink are behind `Arc`, and everything else is immutable config.
#[derive(Clone)]
pub struct InboundX402Gate {
    endpoint: ValidatedInboundX402Endpoint,
    policy: SidecarAdmissionPolicy,
    claims: Arc<dyn ForwardClaimGuard>,
    revenue: Arc<dyn RevenueSink>,
}

impl std::fmt::Debug for InboundX402Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundX402Gate")
            .field("endpoint", &self.endpoint)
            .field("policy", &self.policy)
            .field("claims", &"<dyn ForwardClaimGuard>")
            .field("revenue", &"<dyn RevenueSink>")
            .finish()
    }
}

impl InboundX402Gate {
    /// Compose a gate from a validated fixed-price endpoint, a sidecar admission
    /// policy, a forward-once claim guard, and a revenue sink.
    pub fn new(
        endpoint: ValidatedInboundX402Endpoint,
        policy: SidecarAdmissionPolicy,
        claims: Arc<dyn ForwardClaimGuard>,
        revenue: Arc<dyn RevenueSink>,
    ) -> Self {
        Self {
            endpoint,
            policy,
            claims,
            revenue,
        }
    }

    /// The fixed-price endpoint this gate protects.
    pub fn endpoint(&self) -> &ValidatedInboundX402Endpoint {
        &self.endpoint
    }

    /// The 402 challenge for this endpoint.
    pub fn challenge(&self) -> InboundX402Challenge {
        self.endpoint.challenge()
    }

    /// Decide what to do with one inbound request.
    ///
    /// Stage order is the refusal taxonomy: a request that is not a sidecar
    /// forward is refused before its payment proof is even parsed, so a direct
    /// caller can never learn whether a proof it stole is still valid.
    pub fn evaluate(
        &self,
        request: &ForwardedRequest<'_>,
        call: &InboundCallIdentity,
        now_unix: u64,
    ) -> InboundX402Decision {
        let admitted = match self.policy.admit(request) {
            Ok(admitted) => admitted,
            Err(error) => {
                return InboundX402Decision::Refused(InboundX402Refusal::Admission(error))
            }
        };

        let settlement_header = match request.single(HEADER_PAYMENT_RESPONSE) {
            Ok(value) => value,
            Err(error) => {
                return InboundX402Decision::Refused(InboundX402Refusal::Admission(error))
            }
        };
        let Some(settlement_header) = settlement_header else {
            return InboundX402Decision::PaymentRequired(self.challenge());
        };

        let evidence = match parse_payment_response(settlement_header, self.endpoint.network()) {
            Ok(evidence) => evidence,
            Err(error) => {
                return InboundX402Decision::Refused(malformed_settlement(&error));
            }
        };

        let ctx = InboundX402CallContext {
            request_id: call.request_id.clone(),
            trace_id: call.trace_id.clone(),
            method: admitted.method.clone(),
            tenant: admitted.tenant.clone(),
            occurred_at_unix: Some(now_unix),
        };
        let record = match settle_inbound_payment(&self.endpoint, &ctx, &evidence) {
            Ok(record) => record,
            Err(error) => {
                return InboundX402Decision::Refused(InboundX402Refusal::Settlement(error))
            }
        };

        // Durable backstop first: a claim lost to TTL expiry or a restart must
        // not turn a replay into a fresh forward. The sink is keyed by the same
        // id, so a record that exists means this payment was already forwarded.
        match self.revenue.get(&record.id) {
            Ok(Some(existing)) => {
                return if existing.request_id == record.request_id {
                    InboundX402Decision::AlreadyForwarded {
                        payment_key: record.id,
                        first_sidecar_request_id: admitted.sidecar_request_id,
                    }
                } else {
                    InboundX402Decision::Refused(InboundX402Refusal::ProofReplay {
                        payment_key: record.id,
                        first_sidecar_request_id: existing.request_id,
                    })
                };
            }
            Ok(None) => {}
            Err(error) => return InboundX402Decision::Refused(unavailable(&error)),
        }

        let outcome = match self
            .claims
            .claim(&record.id, &admitted.sidecar_request_id, now_unix)
        {
            Ok(outcome) => outcome,
            Err(error) => return InboundX402Decision::Refused(unavailable(&error)),
        };

        match outcome {
            ClaimOutcome::DuplicateRetry {
                first_request_id, ..
            } => {
                return InboundX402Decision::AlreadyForwarded {
                    payment_key: record.id,
                    first_sidecar_request_id: first_request_id,
                }
            }
            ClaimOutcome::ProofReplay {
                first_request_id, ..
            } => {
                return InboundX402Decision::Refused(InboundX402Refusal::ProofReplay {
                    payment_key: record.id,
                    first_sidecar_request_id: first_request_id,
                })
            }
            ClaimOutcome::Admitted => {}
        }

        // Revenue is recorded before the handler runs, not after: a crash
        // between the claim and the handler must leave evidence that the
        // payment was consumed, otherwise the durable backstop above cannot see
        // it. If the sink refuses, give the claim back so the payer can retry.
        if let Err(error) = self.revenue.record(&record) {
            let _ = self
                .claims
                .release(&record.id, &admitted.sidecar_request_id);
            return InboundX402Decision::Refused(unavailable(&error));
        }

        InboundX402Decision::Forward(Box::new(ForwardAuthorization {
            record,
            headers_to_strip: self.policy.headers_to_strip(),
            admitted,
        }))
    }

    /// Release a forward claim after the protected handler was demonstrably not
    /// served (connect failure, or an upstream 5xx produced before any bytes of
    /// the handler's response). The payer may then retry the same proof.
    ///
    /// Returns whether the claim was actually held by this authorization. The
    /// revenue record is deliberately NOT deleted: the payment did settle
    /// on-chain, and deleting the evidence would make a refund unprovable. The
    /// consequence — a released claim whose durable record still exists is
    /// re-refused by the backstop above — is why this is only safe to call with
    /// a sink that has not yet been made durable, and is stated as a known
    /// limitation in `docs/x402-inbound-sidecar.md` (tracked in #601).
    pub fn release_claim(
        &self,
        authorization: &ForwardAuthorization,
    ) -> Result<bool, BillingError> {
        self.claims.release(
            authorization.payment_key(),
            &authorization.admitted.sidecar_request_id,
        )
    }
}

fn malformed_settlement(error: &PaymentError) -> InboundX402Refusal {
    InboundX402Refusal::MalformedSettlement {
        reason: error.to_string(),
    }
}

fn unavailable(error: &BillingError) -> InboundX402Refusal {
    InboundX402Refusal::Unavailable {
        code: error.code.clone(),
        message: error.message.clone(),
    }
}

#[cfg(test)]
#[path = "x402_inbound_gate_test.rs"]
mod x402_inbound_gate_test;
