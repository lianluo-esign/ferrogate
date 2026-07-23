// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Non-custodial pay.sh / x402 client for the agent-worker (issue #353).
//!
//! When a worker's already-authorized REST/network egress action gets a `402
//! Payment Required`, the worker does NOT auto-pay it. This module owns the
//! narrow, non-custodial client boundary for that flow:
//!
//! 1. [`ParsedChallenge::parse`] decodes the merchant `PAYMENT-REQUIRED`
//!    challenge through the frozen #350 wire contract
//!    ([`ferrogate_payments`]) and binds it to the exact egress request the
//!    gateway already authorized. A challenge whose resource does not match the
//!    authorized egress URL is a payment redirect and fails closed.
//! 2. [`ParsedChallenge::spend_authorization_request`] builds the evidence the
//!    worker PRESENTS to the gateway/policy so it can make the allow / approval
//!    / deny decision ([`authorize_x402_payment`], #351). The worker never
//!    self-authorizes a spend.
//! 3. [`ParsedChallenge::authorize_spend`] CONSUMES that decision. It never
//!    overrides a `Deny`, refuses a headless `ApprovalRequired`, fails closed on
//!    any binding mismatch, and — the security-critical part — refuses any
//!    request to hold key material or sign locally. Signing stays behind an
//!    EXTERNAL authority ([`SignerBinding::ExternalAuthority`]); only then is an
//!    [`AuthorizedHandoff`] produced.
//!
//! # Non-custodial boundary
//!
//! No private key, seed phrase, raw signing key, or recoverable key material
//! ever crosses this module. There is no type, field, or parameter here that
//! can carry secret bytes: [`SpendAuthorizationRequest`] carries only public
//! evidence, and [`SignerBinding`] carries only an opaque authority handle plus
//! a PUBLIC signer address. Actual transaction construction and signing happen
//! entirely behind the injected [`SvmTransferSigner`] trait (a tenant KMS, OS
//! key store, or self-hosted signer daemon), which the worker reaches only
//! AFTER an `Allow`. A caller that asks the worker to hold a key and sign
//! locally ([`SignerBinding::LocalKeyCustody`]) is refused with
//! [`X402ClientError::KeyCustodyRefused`].
//!
//! # Scope of this slice (#353)
//!
//! This is the challenge-parse + non-custodial authorization-request build +
//! spend-authorization handoff contract, with the deny/approval/custody
//! fail-closed paths. The durable attempt/hold binding (#352/#354), the
//! short-lived cryptographically bound `SpendAuthorization` token minted by the
//! gateway, redirect re-authorization, and the exact-once paid replay +
//! settlement wiring are deferred to follow-up slices. Until a production
//! dispatch path consumes this client, the non-test build has no caller, so
//! `dead_code` is allowed off the test path — mirroring `state_x402_settlement.rs`
//! (#354).
#![cfg_attr(not(test), allow(dead_code))]

use ferrogate_payments::{
    parse_payment_required, select_requirement, validate_solana_address, PaymentError,
    RequirementFilter, SelectedPayment, SvmTransferIntent, SvmTransferSigner,
};
use ferrogate_policy::{PaymentAuthorization, PaymentAuthorizationRequest, PaymentDecision};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Typed failure surface for the non-custodial x402 client. Every rejection is a
/// distinct variant so a caller (the paid-egress handler, audit) can branch on
/// the failure class without string matching, and every ambiguity is a hard
/// error rather than a silent proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum X402ClientError {
    /// The merchant `PAYMENT-REQUIRED` challenge is unknown, malformed, or names
    /// no requirement this worker can satisfy (delegated to the frozen wire
    /// contract). Fails closed: an unparseable challenge is never paid.
    ChallengeParse(PaymentError),
    /// The challenge's protected resource does not match the egress URL the
    /// gateway already authorized. Paying it would redirect funds to a different
    /// origin, so it fails closed before any authorization is even requested.
    ResourceRedirect {
        challenge_resource: String,
        authorized_url: String,
    },
    /// The gateway/policy decision was `Deny`. The worker NEVER overrides a deny;
    /// it surfaces the stable reason code and stops.
    PolicyDenied {
        reason_code: &'static str,
        message: String,
    },
    /// The gateway/policy decision was `ApprovalRequired`. Headless auto-pay is
    /// forbidden; the worker stops and defers to the out-of-band approval path.
    ApprovalRequired { threshold_credits: u64 },
    /// The decision handed back was computed for a different challenge/payment
    /// than the one parsed here (challenge hash, network, mint, recipient, or
    /// resource differs). A decision that is not cryptographically bound to THIS
    /// challenge is never trusted.
    BindingMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    /// The caller asked the worker to hold raw key material and sign locally. A
    /// non-custodial worker refuses: signing must stay behind an external
    /// authority. This is the security-critical fail-closed path.
    KeyCustodyRefused { context: &'static str },
    /// The external signing authority is unusable: an empty authority handle or a
    /// public signer address that is not a valid base58 Solana address.
    InvalidSigner { reason: String },
    /// Assembling the outgoing `PAYMENT-SIGNATURE` through the external signer
    /// failed (signer refusal, or output the wire contract rejects).
    ProofHandoffFailed(PaymentError),
}

impl std::fmt::Display for X402ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeParse(e) => write!(f, "x402 challenge could not be parsed: {e}"),
            Self::ResourceRedirect {
                challenge_resource,
                authorized_url,
            } => write!(
                f,
                "x402 challenge resource {challenge_resource:?} does not match the \
                 authorized egress url {authorized_url:?} (payment redirect refused)"
            ),
            Self::PolicyDenied {
                reason_code,
                message,
            } => write!(f, "x402 spend denied by policy [{reason_code}]: {message}"),
            Self::ApprovalRequired { threshold_credits } => write!(
                f,
                "x402 spend requires approval (threshold {threshold_credits} credits); \
                 headless auto-pay refused"
            ),
            Self::BindingMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "x402 authorization is not bound to this challenge: {field} expected \
                 {expected:?}, decision carried {actual:?}"
            ),
            Self::KeyCustodyRefused { context } => write!(
                f,
                "x402 worker refuses local key custody ({context}); signing must stay \
                 behind an external authority"
            ),
            Self::InvalidSigner { reason } => {
                write!(f, "x402 external signer is invalid: {reason}")
            }
            Self::ProofHandoffFailed(e) => {
                write!(f, "x402 proof handoff to the external signer failed: {e}")
            }
        }
    }
}

impl std::error::Error for X402ClientError {}

/// The already-authorized egress request the worker detected a `402` on. This is
/// the request FerroGate governance already allowed; the payment only unlocks
/// the exact same request, so its identity is bound into the spend evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedRequest {
    /// HTTP method of the already-authorized egress action (e.g. `GET`).
    pub method: String,
    /// The canonical egress URL FerroGate authorized. The challenge's own
    /// `resource` must equal this — a challenge cannot redirect payment.
    pub canonical_url: String,
    /// Lowercase hex SHA-256 of the request body, if the action carried one.
    pub body_sha256_hex: Option<String>,
}

impl AuthorizedRequest {
    /// Build a request context, hashing the body (if any) locally. The body hash
    /// is evidence bound into the authorization; the raw body never leaves the
    /// caller.
    pub(crate) fn new(method: impl Into<String>, canonical_url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            canonical_url: canonical_url.into(),
            body_sha256_hex: None,
        }
    }

    /// Attach a body by hashing it with SHA-256 (lowercase hex).
    pub(crate) fn with_body(mut self, body: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        self.body_sha256_hex = Some(hex);
        self
    }
}

/// The identity a spend is attributed to. Carried as evidence so the gateway can
/// bind the authorization to tenant/workspace/run/worker/request; the worker
/// resolves the scope, the gateway makes the decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SpendPrincipal {
    pub tenant_id: String,
    pub workspace_id: Option<String>,
    pub run_id: Option<String>,
    pub worker_id: Option<String>,
    pub request_id: Option<String>,
}

/// The non-custodial spend-authorization handoff: the evidence the worker
/// PRESENTS to the gateway/policy so it can allow, require approval, or deny.
///
/// This is the shape that crosses the worker→gateway boundary. It carries the
/// full binding tuple (method, canonical URL, body hash, challenge hash,
/// network, mint, atomic amount, recipient, resource) plus principal identity,
/// and NOTHING else — no key material, no signer secret, no proof bytes. It
/// derives `Serialize` precisely because every field in it is safe to transmit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SpendAuthorizationRequest {
    pub method: String,
    pub canonical_url: String,
    pub body_sha256_hex: Option<String>,
    pub challenge_hash_hex: String,
    pub network_caip2: String,
    pub mint: String,
    pub atomic_amount: u64,
    pub recipient: String,
    pub fee_payer: String,
    pub resource_url: String,
    pub tenant_id: String,
    pub workspace_id: Option<String>,
    pub run_id: Option<String>,
    pub worker_id: Option<String>,
    pub request_id: Option<String>,
}

/// Where signing authority lives. A non-custodial worker only ever accepts an
/// EXTERNAL authority; the local-custody variant exists solely to name the
/// refused request path and carries no bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignerBinding {
    /// Signing authority lives entirely OUTSIDE the worker process: a tenant
    /// KMS, OS key store, or self-hosted signer daemon, named by an opaque
    /// handle and its PUBLIC signer (payer) address. No secret bytes are held.
    ExternalAuthority {
        authority_ref: String,
        public_signer_address: String,
    },
    /// A caller asked the worker to hold a raw key and sign locally. This carries
    /// NO bytes by construction; the non-custodial worker ALWAYS refuses it.
    LocalKeyCustody,
}

impl SignerBinding {
    /// Resolve to an external `(authority_ref, public_signer_address)`, or fail
    /// closed. `LocalKeyCustody` ALWAYS errors here, independent of any policy
    /// decision — the worker never holds key material.
    fn resolve_external(self) -> Result<(String, String), X402ClientError> {
        match self {
            Self::LocalKeyCustody => Err(X402ClientError::KeyCustodyRefused {
                context: "local signing key custody is not permitted for a non-custodial worker",
            }),
            Self::ExternalAuthority {
                authority_ref,
                public_signer_address,
            } => {
                if authority_ref.trim().is_empty() {
                    return Err(X402ClientError::InvalidSigner {
                        reason: "external authority reference is empty".to_string(),
                    });
                }
                validate_solana_address("public_signer_address", &public_signer_address).map_err(
                    |e| X402ClientError::InvalidSigner {
                        reason: e.to_string(),
                    },
                )?;
                Ok((authority_ref, public_signer_address))
            }
        }
    }
}

/// A parsed, wire-validated `402` challenge bound to the exact egress request
/// the gateway already authorized.
#[derive(Debug, Clone)]
pub(crate) struct ParsedChallenge {
    selected: SelectedPayment,
    request: AuthorizedRequest,
}

impl ParsedChallenge {
    /// Parse a merchant `PAYMENT-REQUIRED` header on an already-authorized egress
    /// action. Fails closed on any malformed/unknown challenge (delegated to the
    /// frozen wire contract) and on a challenge whose resource does not match the
    /// authorized egress URL (payment redirect).
    pub(crate) fn parse(
        payment_required_header: &str,
        request: AuthorizedRequest,
        filter: &RequirementFilter<'_>,
    ) -> Result<Self, X402ClientError> {
        let required = parse_payment_required(payment_required_header)
            .map_err(X402ClientError::ChallengeParse)?;
        let selected =
            select_requirement(&required, filter).map_err(X402ClientError::ChallengeParse)?;

        // Defense in depth: the challenge resource must equal the egress URL the
        // gateway authorized. The gateway's canonical resource match (#351) is
        // authoritative; this exact-equality guard fails closed on the obvious
        // redirect before any authorization is requested.
        if selected.resource_url != request.canonical_url {
            return Err(X402ClientError::ResourceRedirect {
                challenge_resource: selected.resource_url.clone(),
                authorized_url: request.canonical_url.clone(),
            });
        }

        Ok(Self { selected, request })
    }

    /// The selected, wire-validated payment requirement.
    pub(crate) fn selected(&self) -> &SelectedPayment {
        &self.selected
    }

    /// Lowercase-hex deterministic challenge hash from the wire contract — the
    /// stable idempotency / audit key that ties evidence and decision together.
    pub(crate) fn challenge_hash_hex(&self) -> String {
        self.selected.challenge_hash_hex()
    }

    /// Build the non-custodial handoff evidence presented to the gateway/policy.
    /// Carries no key material.
    pub(crate) fn spend_authorization_request(
        &self,
        principal: &SpendPrincipal,
    ) -> SpendAuthorizationRequest {
        SpendAuthorizationRequest {
            method: self.request.method.clone(),
            canonical_url: self.request.canonical_url.clone(),
            body_sha256_hex: self.request.body_sha256_hex.clone(),
            challenge_hash_hex: self.selected.challenge_hash_hex(),
            network_caip2: self.selected.network.caip2().to_string(),
            mint: self.selected.mint.clone(),
            atomic_amount: self.selected.atomic_amount,
            recipient: self.selected.recipient.clone(),
            fee_payer: self.selected.fee_payer.clone(),
            resource_url: self.selected.resource_url.clone(),
            tenant_id: principal.tenant_id.clone(),
            workspace_id: principal.workspace_id.clone(),
            run_id: principal.run_id.clone(),
            worker_id: principal.worker_id.clone(),
            request_id: principal.request_id.clone(),
        }
    }

    /// Build the pure #351 policy input for this challenge, pinning the
    /// authorized egress URL so the gateway's resource-redirect check binds to
    /// exactly what the worker authorized.
    pub(crate) fn policy_request<'a>(
        &'a self,
        scope: ferrogate_policy::SpendScope<'a>,
    ) -> PaymentAuthorizationRequest<'a> {
        PaymentAuthorizationRequest {
            selected: &self.selected,
            authorized_resource_url: &self.request.canonical_url,
            scope,
        }
    }

    /// Consume the gateway/policy decision and, only on an `Allow` that is
    /// cryptographically bound to THIS challenge and backed by an EXTERNAL
    /// signer, produce an [`AuthorizedHandoff`].
    ///
    /// Fails closed on: a decision bound to a different challenge (any binding
    /// field mismatch), a `Deny` (never overridden), an `ApprovalRequired` (no
    /// headless auto-pay), and a local key-custody request. The worker never
    /// proceeds unless every one of these gates passes.
    pub(crate) fn authorize_spend(
        &self,
        decision: &PaymentAuthorization,
        signer: SignerBinding,
    ) -> Result<AuthorizedHandoff, X402ClientError> {
        // 1. The decision must be bound to exactly this challenge. A decision
        //    computed for a different payment is never trusted, whatever it says.
        self.check_binding(
            "challenge_hash",
            &decision.challenge_hash_hex,
            &self.selected.challenge_hash_hex(),
        )?;
        self.check_binding(
            "network",
            &decision.network_caip2,
            self.selected.network.caip2(),
        )?;
        self.check_binding("mint", &decision.mint, &self.selected.mint)?;
        self.check_binding("recipient", &decision.recipient, &self.selected.recipient)?;
        self.check_binding(
            "resource_url",
            &decision.resource_url,
            &self.selected.resource_url,
        )?;

        // 2. Honor the decision. The worker never overrides a deny and never
        //    auto-pays what needs approval.
        match &decision.decision {
            PaymentDecision::Deny => {
                return Err(X402ClientError::PolicyDenied {
                    reason_code: decision.reason_code,
                    message: decision.message.clone(),
                });
            }
            PaymentDecision::ApprovalRequired { threshold_credits } => {
                return Err(X402ClientError::ApprovalRequired {
                    threshold_credits: *threshold_credits,
                });
            }
            PaymentDecision::Allow => {}
        }

        // 3. Non-custodial signer boundary. A local-custody request fails closed;
        //    only an external authority is accepted.
        let (authority_ref, public_signer_address) = signer.resolve_external()?;

        Ok(AuthorizedHandoff {
            intent: SvmTransferIntent::from_selected(&self.selected),
            selected: self.selected.clone(),
            authority_ref,
            public_signer_address,
        })
    }

    fn check_binding(
        &self,
        field: &'static str,
        decision_value: &str,
        expected: &str,
    ) -> Result<(), X402ClientError> {
        if decision_value != expected {
            return Err(X402ClientError::BindingMismatch {
                field,
                expected: expected.to_string(),
                actual: decision_value.to_string(),
            });
        }
        Ok(())
    }
}

/// The authorized, non-custodial payment handoff. Reached ONLY after an `Allow`
/// bound to the challenge and an external signer authority. It carries the
/// transfer intent to hand to the external signer plus the public authority
/// identity; it holds no key material.
#[derive(Debug, Clone)]
pub(crate) struct AuthorizedHandoff {
    intent: SvmTransferIntent,
    selected: SelectedPayment,
    authority_ref: String,
    public_signer_address: String,
}

impl AuthorizedHandoff {
    /// The signer-facing transfer intent derived from the validated requirement.
    pub(crate) fn intent(&self) -> &SvmTransferIntent {
        &self.intent
    }

    /// Opaque handle of the external signing authority (KMS key id, socket path,
    /// or daemon identity). Not secret; safe to log.
    pub(crate) fn authority_ref(&self) -> &str {
        &self.authority_ref
    }

    /// The public signer (payer) address the spend was authorized for.
    pub(crate) fn public_signer_address(&self) -> &str {
        &self.public_signer_address
    }

    /// Hand the transfer intent to the EXTERNAL signer and assemble the x402
    /// `PAYMENT-SIGNATURE` header value. All transaction construction and signing
    /// happen behind the injected trait; the worker never sees key material.
    ///
    /// Fails closed if the injected signer's public address differs from the one
    /// the spend was authorized for (wrong worker/signer), so a proof can never
    /// be produced by an unauthorized wallet.
    pub(crate) fn sign_via(
        &self,
        signer: &dyn SvmTransferSigner,
    ) -> Result<String, X402ClientError> {
        let signer_address = signer.payer_address();
        if signer_address != self.public_signer_address {
            return Err(X402ClientError::BindingMismatch {
                field: "signer_address",
                expected: self.public_signer_address.clone(),
                actual: signer_address,
            });
        }
        ferrogate_payments::build_payment_signature(&self.selected, signer)
            .map_err(X402ClientError::ProofHandoffFailed)
    }
}

#[cfg(test)]
#[path = "x402_client_test.rs"]
mod x402_client_test;
