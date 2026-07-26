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
//! fail-closed paths, plus the three pieces of it that
//! `external_actions.rs::run_authorized_rest_action` calls —
//! [`detect_payment_required`], [`redact_bearer_headers`] and
//! [`RequestWireStage`].
//!
//! ## What "wired" does and does not mean here — stated plainly
//!
//! An earlier revision of this doc called `run_authorized_rest_action` "the
//! worker's REAL egress path". That was wrong and is corrected here rather than
//! quietly dropped, because the boundary matters more than the claim did.
//!
//! `run_authorized_rest_action` is a **loopback smoke executor**, and it is one
//! by construction, not by configuration:
//!
//! * its only non-test caller is `governed_rest_execution_smoke_command`, a
//!   zero-argument CLI subcommand that spawns its own listener and points a
//!   hardcoded action at it (`external_actions.rs`);
//! * `parse_local_http_url` refuses anything that is not `http://`, and then
//!   refuses any endpoint that is not loopback;
//! * the dispatcher refuses any method other than `GET`.
//!
//! An x402 merchant is a public DNS name over HTTPS, so this executor can never
//! have one on the other side — regardless of what #381 lands. The 402 branch is
//! therefore genuinely unreachable in the shipped binary today. It is kept
//! because it is the correct behaviour for the executor to have *if* a 402 ever
//! arrives, and because the redaction and wire-stage work around it are
//! independently valuable; it is NOT evidence of live 402 detection.
//!
//! The only production code in this repository that can reach an arbitrary
//! public HTTPS host on an agent's behalf is the gateway's MCP tool client
//! (`ferrogate-mcp/src/http_client.rs`), which is in a different process and a
//! different crate, and has no payment handling. "Non-custodial 402 detection on
//! the live egress path" therefore cannot be satisfied inside `agent-worker`: it
//! is blocked on whichever issue gives the worker a real, non-hardcoded egress
//! executor.
//!
//! ## What is NOT here, and why it cannot be
//!
//! The gateway-minted short-lived `SpendAuthorization` token, the exact-once
//! paid replay, and the durable attempt/hold integration are NOT deferred out of
//! convenience — they are **unreachable from this process**. The durable attempt
//! API is `X402SettlementLoop` (`ferrogate-cli/src/state_x402_settlement.rs`:
//! `open` / `submit` / `finalize` / `cancel` / `expire_if_due`) over
//! `ferrogate_storage::RuntimeStorageRepositories`, and `agent-worker` depends on
//! neither `ferrogate-cli` nor `ferrogate-storage` (see this crate's
//! `Cargo.toml`). That is deliberate: the worker sits on the far side of the
//! gateway-mediated capability boundary, and handing it a durable ledger handle
//! would breach the very boundary the non-custody rule above exists to protect.
//! Driving the attempt state machine is therefore the gateway's job — the
//! negotiation core already exists (`state_x402_negotiation.rs`, issue #381) and
//! is waiting only on its transport binding.
//!
//! What the worker legitimately owns of that contract is the one fact only it
//! can observe: how far the outgoing request got on the wire before a dispatch
//! failed. That is [`RequestWireStage`], and it is what decides whether the
//! gateway may take the loop's RELEASE edge or must retain the hold as
//! `outcome_unknown`. It now lives in `ferrogate-runtime` and is emitted as a
//! typed discriminant in worker event metadata
//! ([`ferrogate_runtime::EGRESS_REQUEST_WIRE_STAGE_KEY`]), so a consumer reads a
//! frozen token instead of substring-matching an error sentence. That part is
//! executor-independent: it applies to whatever egress executor #381 ends up
//! binding.
//!
//! The rest of the module still has no production caller, so `dead_code` is
//! allowed off the test path — mirroring `state_x402_settlement.rs` (#354).
#![cfg_attr(not(test), allow(dead_code))]

use ferrogate_payments::{
    parse_payment_required, select_requirement, validate_solana_address, PaymentError,
    PaymentIntent, PaymentIntentDraft, PaymentIntentIdentity, RequestBodyHash, RequirementFilter,
    SelectedPayment, SvmTransferIntent, SvmTransferSigner, HEADER_PAYMENT_SIGNATURE, SCHEME_EXACT,
    X402_VERSION,
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

    /// The authorized request's method in the SAME canonical form
    /// [`PaymentIntent`] stores it (trimmed, uppercase), so the intent, the
    /// decision, and this binding check can never disagree over `get` vs `GET`.
    fn method(&self) -> String {
        self.request.method.trim().to_ascii_uppercase()
    }

    /// The authorized request's body hash, with a bodyless request represented
    /// by the canonical empty-body hash rather than an absence — "no body" is a
    /// concrete value the decision can be compared against.
    fn body_hash_hex(&self) -> String {
        self.request
            .body_sha256_hex
            .clone()
            .unwrap_or_else(|| RequestBodyHash::empty().as_hex())
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

    /// Build the immutable #351 [`PaymentIntent`] for this challenge: the
    /// already-authorized egress request (method, canonical URL, request-body
    /// hash) bound to the merchant's payment terms at this principal's identity.
    ///
    /// When the principal carries no `request_id` the deterministic challenge
    /// hash stands in as the request identity: it is stable, unique per payment,
    /// and never blank, which an intent requires. It is never invented from
    /// nothing.
    pub(crate) fn payment_intent(
        &self,
        principal: &SpendPrincipal,
    ) -> Result<PaymentIntent, X402ClientError> {
        let body_hash = match self.request.body_sha256_hex.as_deref() {
            Some(hex) => {
                RequestBodyHash::from_hex(hex).map_err(|error| X402ClientError::InvalidSigner {
                    reason: format!("request body hash is unusable: {error}"),
                })?
            }
            None => RequestBodyHash::empty(),
        };
        let request_id = principal
            .request_id
            .clone()
            .unwrap_or_else(|| self.selected.challenge_hash_hex());
        PaymentIntent::new(PaymentIntentDraft {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network_caip2: self.selected.network.caip2().to_string(),
            mint: self.selected.mint.clone(),
            atomic_amount: self.selected.atomic_amount,
            recipient: self.selected.recipient.clone(),
            authorized_resource_url: self.request.canonical_url.clone(),
            http_method: self.method(),
            request_body_hash: body_hash,
            challenge_hash_hex: self.selected.challenge_hash_hex(),
            max_timeout_seconds: self.selected.max_timeout_seconds,
            identity: PaymentIntentIdentity {
                tenant_id: principal.tenant_id.clone(),
                project_id: None,
                workspace_id: principal.workspace_id.clone(),
                key_id: None,
                run_id: principal.run_id.clone(),
                worker_id: principal.worker_id.clone(),
                request_id,
            },
        })
        .map_err(|error| X402ClientError::InvalidSigner {
            reason: format!("payment intent is not valid: {error}"),
        })
    }

    /// Build the pure #351 policy input for this challenge, pinning the
    /// immutable intent so the gateway's resource-redirect check binds to
    /// exactly the method, body, and URL the worker authorized.
    pub(crate) fn policy_request<'a>(
        &'a self,
        intent: &'a PaymentIntent,
        scope: ferrogate_policy::SpendScope<'a>,
    ) -> PaymentAuthorizationRequest<'a> {
        PaymentAuthorizationRequest {
            selected: &self.selected,
            intent,
            scope,
        }
    }

    /// Consume the gateway/policy decision and, only on an `Allow` that is
    /// cryptographically bound to THIS challenge AND to the exact request the
    /// gateway authorized, and backed by an EXTERNAL signer, produce an
    /// [`AuthorizedHandoff`].
    ///
    /// `intent` is the immutable [`PaymentIntent`] the decision was computed
    /// for ([`Self::payment_intent`]); its hash is compared against the one the
    /// decision names, so a decision computed for another intent — another
    /// identity, amount, or merchant timeout — can never be spent here.
    ///
    /// Fails closed on: a decision bound to a different challenge, a decision
    /// bound to a different METHOD or request BODY (the half of the invariant
    /// the challenge hash cannot cover, since neither is merchant input), a
    /// decision naming a different intent, a `Deny` (never overridden), an
    /// `ApprovalRequired` (no headless auto-pay), and a local key-custody
    /// request. The worker never proceeds unless every one of these gates
    /// passes.
    pub(crate) fn authorize_spend(
        &self,
        intent: &PaymentIntent,
        decision: &PaymentAuthorization,
        signer: SignerBinding,
    ) -> Result<AuthorizedHandoff, X402ClientError> {
        // 1. The decision must be bound to exactly this challenge. A decision
        //    computed for a different payment is never trusted, whatever it says.
        self.check_binding(
            "challenge_hash",
            decision.challenge_hash_hex(),
            &self.selected.challenge_hash_hex(),
        )?;
        self.check_binding(
            "network",
            decision.network_caip2(),
            self.selected.network.caip2(),
        )?;
        self.check_binding("mint", decision.mint(), &self.selected.mint)?;
        self.check_binding("recipient", decision.recipient(), &self.selected.recipient)?;
        self.check_binding(
            "resource_url",
            decision.resource_url(),
            &self.selected.resource_url,
        )?;

        // 2. The decision must also be bound to the exact egress request this
        //    worker is paying for. The merchant's challenge hash covers the
        //    payment terms, NOT the method or the body — neither is merchant
        //    input — so without these three comparisons an `Allow` computed for
        //    `GET https://pay.example.com/weather` would authorize a `POST` of
        //    an arbitrary body to the same URL carrying the same challenge.
        //    That is precisely the redirect the security invariant forbids.
        self.check_binding(
            "authorized_resource_url",
            decision.authorized_resource_url(),
            &self.request.canonical_url,
        )?;
        self.check_binding("http_method", decision.http_method(), &self.method())?;
        self.check_binding(
            "request_body_hash",
            decision.request_body_hash_hex(),
            &self.body_hash_hex(),
        )?;

        // 3. And to the exact intent it names: identity, amount and merchant
        //    timeout live in the intent hash, not in any field above.
        self.check_binding(
            "intent_hash",
            decision.intent_hash_hex(),
            &intent.intent_hash_hex(),
        )?;

        // 4. Honor the decision. The worker never overrides a deny and never
        //    auto-pays what needs approval.
        match decision.decision() {
            PaymentDecision::Deny => {
                return Err(X402ClientError::PolicyDenied {
                    reason_code: decision.reason_code(),
                    message: decision.message().to_string(),
                });
            }
            PaymentDecision::ApprovalRequired { threshold_credits } => {
                return Err(X402ClientError::ApprovalRequired {
                    threshold_credits: *threshold_credits,
                });
            }
            PaymentDecision::Allow => {}
        }

        // 5. Non-custodial signer boundary. A local-custody request fails closed;
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

// ---------------------------------------------------------------------------
// Worker-side `402` detection (#353)
// ---------------------------------------------------------------------------

/// The public evidence a worker surfaces when an already-authorized egress
/// action comes back `402 Payment Required`.
///
/// Every field here is public protocol data taken verbatim from the merchant's
/// own challenge. There is deliberately no proof, no signer, and no decision:
/// detecting a demand for payment is not authorizing one. The worker reports
/// this upward and stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetectedPaymentChallenge {
    /// Deterministic wire-contract challenge hash — the stable idempotency and
    /// audit key that joins this detection to the gateway's later decision,
    /// attempt, and hold.
    pub challenge_hash_hex: String,
    /// CAIP-2 network the merchant wants to be paid on.
    pub network_caip2: String,
    /// Atomic amount demanded (integer; never a float — this is money).
    pub atomic_amount: u64,
    /// Merchant payout address.
    pub recipient: String,
    /// The protected resource, which has already been proven equal to the
    /// egress URL FerroGate authorized.
    pub resource_url: String,
}

/// Detect and validate a merchant `402` challenge on an already-authorized
/// egress action, WITHOUT paying it and WITHOUT deciding whether it is
/// acceptable.
///
/// This is the worker's whole role at a `402`: prove the challenge is
/// well-formed against the frozen wire contract, prove it is not a payment
/// redirect (its resource must equal the egress URL the gateway authorized),
/// and hand the public evidence upward. Whether this spend is *allowed* — the
/// network, mint, amount and recipient allowlists, the caps, the approval
/// threshold — is policy, and policy is the gateway's
/// ([`ferrogate_policy::authorize_x402_payment`], #351). Accordingly the
/// requirement filter here is [`RequirementFilter::default`]: "any requirement
/// the wire contract itself considers valid". Narrowing it in the worker would
/// be the worker quietly making a policy decision.
pub(crate) fn detect_payment_required(
    payment_required_header: &str,
    request: AuthorizedRequest,
) -> Result<DetectedPaymentChallenge, X402ClientError> {
    let challenge = ParsedChallenge::parse(
        payment_required_header,
        request,
        &RequirementFilter::default(),
    )?;
    let selected = challenge.selected();
    Ok(DetectedPaymentChallenge {
        challenge_hash_hex: challenge.challenge_hash_hex(),
        network_caip2: selected.network.caip2().to_string(),
        atomic_amount: selected.atomic_amount,
        recipient: selected.recipient.clone(),
        resource_url: selected.resource_url.clone(),
    })
}

// ---------------------------------------------------------------------------
// Bearer-material redaction for recorded evidence (#353)
// ---------------------------------------------------------------------------

/// Replacement written in place of a bearer header value.
pub(crate) const REDACTED_HEADER_VALUE: &str = "<redacted>";

/// Header names whose VALUE is bearer material: possession of the value alone
/// is enough to spend money or impersonate the caller, so it must never reach
/// an event, a log line, or a worker's stdout.
///
/// `PAYMENT-SIGNATURE` leads the list because it is the worst case: it carries
/// the base64 **signed SVM transaction**. Anyone who captures it can submit that
/// transaction. It is not merely sensitive, it is spendable.
///
/// `PAYMENT-REQUIRED` and `PAYMENT-RESPONSE` are deliberately NOT here. The
/// first is the merchant's public challenge and the second is public settlement
/// evidence (an on-chain transaction signature); both are exactly the audit
/// trail #354 needs in order to answer "why was this payment made and what
/// happened to it?". Redacting them would destroy evidence without protecting
/// anything.
fn is_bearer_header(name: &str) -> bool {
    const BEARER_HEADERS: [&str; 7] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        // Not IANA-registered, but every one of these is a value whose mere
        // possession authenticates the holder — which is the whole criterion.
        "authentication",
        "x-api-key",
        "x-auth-token",
    ];
    name.eq_ignore_ascii_case(HEADER_PAYMENT_SIGNATURE)
        || BEARER_HEADERS
            .iter()
            .any(|bearer| name.eq_ignore_ascii_case(bearer))
}

/// Strip bearer header VALUES out of a raw HTTP message before any of it is
/// recorded as worker evidence.
///
/// Header NAMES are preserved, so the record still shows that a credential or a
/// payment proof was present — an operator can see the shape of the exchange
/// without the record itself becoming a way to spend the money.
///
/// Fail-safe by construction:
///
/// * Redaction happens BEFORE truncation at the call site, so a truncated
///   excerpt can never carry a surviving prefix of a proof.
/// * A message with no header/body separator (a truncated or malformed
///   response) is treated as ALL headers, which over-redacts rather than
///   under-redacts.
/// * An `obs-fold` continuation line (RFC 7230 §3.2.4 — deprecated, but still
///   emitted by real servers) has no colon of its own, so matching per line
///   would let the tail of a folded credential through untouched. A
///   continuation of a bearer header is redacted with it.
///
/// Scope limit, stated honestly: this redacts the header section only. A body
/// that echoes a credential back is not covered — guessing at secrets inside
/// arbitrary payloads is a different problem with a different failure mode.
pub(crate) fn redact_bearer_headers(raw_http_message: &str) -> String {
    let mut redacted = String::with_capacity(raw_http_message.len());
    let mut in_header_section = true;
    // Whether the field this line may be continuing is bearer material.
    let mut folding_bearer_header = false;
    for (index, line) in raw_http_message.split_inclusive('\n').enumerate() {
        // Index 0 is the status/request line, which is never a header even if
        // it happens to contain a colon.
        if !in_header_section || index == 0 {
            redacted.push_str(line);
            continue;
        }
        let content = line.trim_end_matches(['\r', '\n']);
        if content.is_empty() {
            in_header_section = false;
            folding_bearer_header = false;
            redacted.push_str(line);
            continue;
        }
        // A leading space/tab means this line continues the PREVIOUS field's
        // value, so it inherits that field's classification instead of being
        // parsed as a header in its own right.
        if content.starts_with([' ', '\t']) {
            if folding_bearer_header {
                redacted.push(' ');
                redacted.push_str(REDACTED_HEADER_VALUE);
                redacted.push_str(&line[content.len()..]);
            } else {
                redacted.push_str(line);
            }
            continue;
        }
        match content.split_once(':') {
            Some((name, _)) if is_bearer_header(name.trim()) => {
                folding_bearer_header = true;
                redacted.push_str(name);
                redacted.push_str(": ");
                redacted.push_str(REDACTED_HEADER_VALUE);
                redacted.push_str(&line[content.len()..]);
            }
            _ => {
                folding_bearer_header = false;
                redacted.push_str(line);
            }
        }
    }
    redacted
}

// ---------------------------------------------------------------------------
// Wire stage → hold disposition (#353's half of the cancellation contract)
// ---------------------------------------------------------------------------

/// The wire-stage vocabulary, re-exported from `ferrogate-runtime`.
///
/// It used to be defined here, privately, which meant the observation could
/// never leave this process as anything but English: `RestDispatchFailure`
/// discarded the stage and appended a sentence, so a gateway wanting the RELEASE
/// edge would have had to substring-match prose to make a money decision.
///
/// The types now live in [`ferrogate_runtime::egress_dispatch_stage`], the crate
/// BOTH `agent-worker` and `ferrogate-cli` already depend on, with frozen wire
/// tokens, fail-safe parsing/deserialization, and event-metadata helpers. That
/// is what makes the classification consumable across the boundary; the prose
/// stays as human diagnostics and stops being load-bearing.
///
/// Nothing about the asymmetry changed in the move: `RequestWireStage::default()`
/// is still `SentOrUnknown`, so every implicit conversion in
/// `external_actions.rs` still retains, and only an explicit `proven_not_sent`
/// can release.
pub(crate) use ferrogate_runtime::{HoldDisposition, RequestWireStage};

#[cfg(test)]
#[path = "x402_client_test.rs"]
mod x402_client_test;
