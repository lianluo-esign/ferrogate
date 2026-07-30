// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Inbound (merchant-side) fixed-price x402 monetization model for
// one FerroGate-hosted API (issue #356). Models the fixed price, the 402
// PAYMENT-REQUIRED challenge construction, and the settlement->revenue-record
// coupling in the billing layer, reusing the frozen #350 wire contract so the
// merchant-built challenge round-trips through the exact parser an x402 client
// uses.

//! Inbound x402 monetization: charge an external agent to call ONE fixed-price
//! FerroGate-hosted API (issue #356).
//!
//! This is the mirror image of the outbound agent-spend stack (#350–#354, where
//! FerroGate is the *payer*): here FerroGate is the *merchant/server*. The
//! product path is `external x402 client -> pay.sh sidecar -> private FerroGate
//! upstream`, and this module owns the billing-layer pieces of exactly one
//! fixed-price, non-streaming endpoint:
//!
//! 1. **Fixed price** — one [`InboundX402Endpoint`]: one atomic price, one SPL
//!    mint, one Solana network, one recipient, one resource. Validated once
//!    into a [`ValidatedInboundX402Endpoint`]; nothing else can build a
//!    challenge or settle.
//! 2. **402 challenge construction** — [`ValidatedInboundX402Endpoint::challenge`]
//!    builds the base64 `PAYMENT-REQUIRED` header an unpaid call receives. It is
//!    constructed so that the frozen #350 wire parser
//!    ([`ferrogate_payments::parse_payment_required`] +
//!    [`ferrogate_payments::select_requirement`]) recovers exactly the fixed
//!    price — the merchant and client see one canonical [`SelectedPayment`] and
//!    one deterministic challenge hash.
//! 3. **Settlement coupling** — [`settle_inbound_payment`] takes the wire-parsed
//!    [`ferrogate_payments::SettlementEvidence`] from the paid call and, only if
//!    it matches the fixed price on network + amount + success + signature,
//!    produces an immutable [`InboundX402RevenueRecord`]. Any mismatch fails
//!    closed (never records revenue at a wrong amount).
//!
//! Stablecoin revenue evidence is kept on its own [`RevenueSink`], strictly
//! separate from the token-usage ledger ([`crate::ledger`]), so inbound revenue
//! is never conflated with Stripe top-ups or outbound agent-spend records
//! (issue #356 acceptance).
//!
//! What is deliberately NOT here (deferred gateway/sidecar wiring): the actual
//! pay.sh sidecar deployment manifest, the private-upstream/mTLS bypass guard,
//! the live 402 route in the gateway server, and durable Postgres persistence of
//! the revenue record. This slice proves the fixed-price billing loop closes at
//! the billing layer; the runtime edge is another slice of #356.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use ferrogate_core::TenantContext;
use ferrogate_payments::{
    parse_payment_required, select_requirement, validate_solana_address, PaymentError,
    RequirementFilter, SelectedPayment, SettlementEvidence, SolanaNetwork, HEADER_PAYMENT_REQUIRED,
    MAX_MEMO_BYTES, MAX_TIMEOUT_SECONDS, SCHEME_EXACT, X402_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::BillingError;

/// HTTP status an unpaid call to the priced endpoint receives.
pub const PAYMENT_REQUIRED_STATUS: u16 = 402;

// ---------------------------------------------------------------------------
// Fixed-price endpoint config
// ---------------------------------------------------------------------------

/// The operator-authored fixed-price monetization config for ONE inbound
/// endpoint. Network is carried as its canonical CAIP-2 string (self-describing
/// on the wire, never a Rust variant name); every address is a canonical base58
/// value the wire contract validates. The price is a single atomic amount in the
/// mint's smallest unit — one fixed price, deliberately not token-metered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundX402Endpoint {
    /// The protected resource URL the payment unlocks.
    pub resource_url: String,
    /// Optional human-readable resource description surfaced in the challenge.
    #[serde(default)]
    pub resource_description: Option<String>,
    /// Optional resource MIME type surfaced in the challenge.
    #[serde(default)]
    pub resource_mime_type: Option<String>,
    /// CAIP-2 network identifier (e.g. Solana devnet/mainnet).
    pub network_caip2: String,
    /// SPL token mint (base58, validated 32 bytes) the price is denominated in.
    pub mint: String,
    /// Recipient wallet (`payTo`, base58) revenue settles to.
    pub recipient: String,
    /// Facilitator fee payer (`extra.feePayer`, base58) required by the SVM
    /// `exact` scheme.
    pub fee_payer: String,
    /// The single fixed price in atomic token units. Must be non-zero.
    pub price_atomic_amount: u64,
    /// Payment validity window in seconds (1..=86400).
    pub max_timeout_seconds: u64,
    /// Optional seller memo embedded in the challenge (<= 256 bytes).
    #[serde(default)]
    pub memo: Option<String>,
    /// Optional human-readable reason echoed in the 402 body's `error` field.
    #[serde(default)]
    pub challenge_error: Option<String>,
    /// HTTP methods the fixed price buys on [`Self::resource_url`]. Empty means
    /// the default set, [`DEFAULT_ALLOWED_METHODS`].
    ///
    /// The price is quoted for one resource, so the gate refuses a settled
    /// payment presented against a different method — otherwise a payment
    /// quoted for a read could authorize a write on the same path.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
}

/// Methods a fixed-price endpoint buys when the operator pins none.
pub const DEFAULT_ALLOWED_METHODS: &[&str] = &["POST"];

/// Structured validation failures for an [`InboundX402Endpoint`]. Each variant
/// is a distinct rejection class an operator/admin surface can render without
/// string matching.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402ConfigError {
    /// `network_caip2` is not a recognised Solana network.
    UnsupportedNetwork { network: String },
    /// A base58 address field (`mint` / `recipient` / `fee_payer`) is invalid.
    InvalidAddress { field: &'static str, value: String },
    /// The fixed price is zero (a free endpoint would not use this path).
    ZeroPrice,
    /// `max_timeout_seconds` is zero or above the wire safety cap.
    InvalidTimeout { reason: String },
    /// The seller memo exceeds the wire memo byte cap.
    MemoTooLong { len: usize },
    /// `resource_url` is empty, oversized, or carries no absolute path the gate
    /// could bind an arriving request to.
    InvalidResourceUrl { reason: String },
    /// An entry of `allowed_methods` is not a usable HTTP method token.
    InvalidAllowedMethod { value: String },
}

impl std::fmt::Display for InboundX402ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedNetwork { network } => {
                write!(f, "unrecognised CAIP-2 network {network:?}")
            }
            Self::InvalidAddress { field, value } => {
                write!(f, "{field} is not a valid base58 Solana address: {value:?}")
            }
            Self::ZeroPrice => write!(f, "fixed price must be non-zero"),
            Self::InvalidTimeout { reason } => write!(f, "invalid max_timeout_seconds: {reason}"),
            Self::MemoTooLong { len } => {
                write!(
                    f,
                    "memo is {len} bytes, exceeds the {MAX_MEMO_BYTES}-byte cap"
                )
            }
            Self::InvalidResourceUrl { reason } => write!(f, "invalid resource_url: {reason}"),
            Self::InvalidAllowedMethod { value } => {
                write!(f, "{value:?} is not a valid HTTP method token")
            }
        }
    }
}

impl std::error::Error for InboundX402ConfigError {}

impl InboundX402Endpoint {
    /// Structurally validate this config into a [`ValidatedInboundX402Endpoint`].
    /// Fails closed: every field the wire contract or the fixed-price model
    /// depends on is checked up front, so a challenge is only ever built from a
    /// sound endpoint. Checks run in a fixed order for a deterministic error.
    pub fn validate(self) -> Result<ValidatedInboundX402Endpoint, InboundX402ConfigError> {
        let network = SolanaNetwork::from_caip2(&self.network_caip2).ok_or_else(|| {
            InboundX402ConfigError::UnsupportedNetwork {
                network: self.network_caip2.clone(),
            }
        })?;

        if self.resource_url.is_empty() || self.resource_url.len() > 2048 {
            return Err(InboundX402ConfigError::InvalidResourceUrl {
                reason: "must be non-empty and <= 2048 bytes".to_string(),
            });
        }
        let resource_path = resource_path_of(&self.resource_url)?;
        let allowed_methods = normalize_allowed_methods(&self.allowed_methods)?;

        for (field, value) in [
            ("mint", &self.mint),
            ("recipient", &self.recipient),
            ("fee_payer", &self.fee_payer),
        ] {
            if validate_solana_address(field, value).is_err() {
                return Err(InboundX402ConfigError::InvalidAddress {
                    field,
                    value: value.clone(),
                });
            }
        }

        if self.price_atomic_amount == 0 {
            return Err(InboundX402ConfigError::ZeroPrice);
        }

        if self.max_timeout_seconds == 0 {
            return Err(InboundX402ConfigError::InvalidTimeout {
                reason: "zero (already expired)".to_string(),
            });
        }
        if self.max_timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(InboundX402ConfigError::InvalidTimeout {
                reason: format!("exceeds the safety cap of {MAX_TIMEOUT_SECONDS}s"),
            });
        }

        if let Some(memo) = &self.memo {
            if memo.len() > MAX_MEMO_BYTES {
                return Err(InboundX402ConfigError::MemoTooLong { len: memo.len() });
            }
        }

        Ok(ValidatedInboundX402Endpoint {
            endpoint: self,
            network,
            resource_path,
            allowed_methods,
        })
    }
}

/// Extract the absolute path `resource_url` prices, with any query or fragment
/// removed.
///
/// Deliberately hand-rolled rather than pulling in a URL parser: the only thing
/// the gate needs is the path component of an absolute `scheme://authority/path`
/// URL, and the check below is strict — anything it cannot resolve confidently
/// is rejected at config validation rather than guessed at request time.
fn resource_path_of(resource_url: &str) -> Result<String, InboundX402ConfigError> {
    let invalid = |reason: &str| InboundX402ConfigError::InvalidResourceUrl {
        reason: reason.to_string(),
    };

    let (scheme, rest) = resource_url
        .split_once("://")
        .ok_or_else(|| invalid("must be an absolute URL of the form scheme://host/path"))?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(invalid("scheme must be http or https"));
    }

    // Everything up to the first '/' is the authority; the remainder (with its
    // leading '/') is the path. A URL with no '/' at all prices the site root.
    let path = match rest.find('/') {
        Some(index) => &rest[index..],
        None => {
            if rest.is_empty() {
                return Err(invalid("has no host"));
            }
            "/"
        }
    };
    // `split` always yields at least one element, so the fallback is unreachable
    // in practice; it exists so this stays panic-free without an `unwrap`.
    let path = path.split(['?', '#']).next().unwrap_or("/");
    if path.is_empty() {
        return Ok("/".to_string());
    }
    Ok(path.to_string())
}

/// Uppercase and de-duplicate the operator's method list, substituting
/// [`DEFAULT_ALLOWED_METHODS`] when it is empty.
fn normalize_allowed_methods(configured: &[String]) -> Result<Vec<String>, InboundX402ConfigError> {
    if configured.is_empty() {
        return Ok(DEFAULT_ALLOWED_METHODS
            .iter()
            .map(|method| (*method).to_string())
            .collect());
    }
    let mut methods: Vec<String> = Vec::with_capacity(configured.len());
    for value in configured {
        // RFC 9110 methods are case-sensitive tokens; every registered method is
        // uppercase ASCII, so anything else is an operator typo, not a method.
        if value.is_empty()
            || value.len() > 32
            || !value.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
        {
            return Err(InboundX402ConfigError::InvalidAllowedMethod {
                value: value.clone(),
            });
        }
        let upper = value.to_ascii_uppercase();
        if !methods.contains(&upper) {
            methods.push(upper);
        }
    }
    Ok(methods)
}

/// An [`InboundX402Endpoint`] that has passed [`InboundX402Endpoint::validate`].
/// Only this type can build a 402 challenge or settle a payment, so the runtime
/// can never monetize an endpoint whose fixed price / addresses failed
/// validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInboundX402Endpoint {
    endpoint: InboundX402Endpoint,
    network: SolanaNetwork,
    /// Absolute path component of `endpoint.resource_url`, derived once at
    /// validation so the request-time comparison is a string equality rather
    /// than a parse that could fail on the hot path.
    resource_path: String,
    /// Uppercased, de-duplicated method set. Never empty.
    allowed_methods: Vec<String>,
}

/// The 402 challenge an unpaid call receives: HTTP status plus the base64
/// `PAYMENT-REQUIRED` header a #350-compatible client parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundX402Challenge {
    /// Always [`PAYMENT_REQUIRED_STATUS`] (402).
    pub http_status: u16,
    /// Always [`HEADER_PAYMENT_REQUIRED`] (`PAYMENT-REQUIRED`).
    pub header_name: &'static str,
    /// Base64 of the `PaymentRequired` JSON object.
    pub header_value: String,
}

impl ValidatedInboundX402Endpoint {
    /// Borrow the underlying validated config.
    pub fn endpoint(&self) -> &InboundX402Endpoint {
        &self.endpoint
    }

    /// The recognised Solana network the fixed price settles on.
    pub fn network(&self) -> SolanaNetwork {
        self.network
    }

    /// The absolute request path the fixed price buys, derived from
    /// `resource_url` at validation.
    pub fn resource_path(&self) -> &str {
        &self.resource_path
    }

    /// The uppercased HTTP methods the fixed price buys. Never empty.
    pub fn allowed_methods(&self) -> &[String] {
        &self.allowed_methods
    }

    /// Whether an arriving request's method is one the fixed price bought.
    /// Case-insensitive: the comparison set is uppercase by construction.
    pub fn allows_method(&self, method: &str) -> bool {
        self.allowed_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(method))
    }

    /// The single fixed price in atomic token units.
    pub fn price_atomic_amount(&self) -> u64 {
        self.endpoint.price_atomic_amount
    }

    /// Build the base64 `PAYMENT-REQUIRED` header value for this endpoint. Pure
    /// and infallible: it serialises a `serde_json::Value` (whose `Display` never
    /// fails) and base64-encodes it.
    pub fn build_payment_required(&self) -> String {
        let e = &self.endpoint;
        let mut extra = json!({ "feePayer": e.fee_payer });
        if let Some(memo) = &e.memo {
            extra["memo"] = json!(memo);
        }
        let accept = json!({
            "scheme": SCHEME_EXACT,
            "network": self.network.caip2(),
            "asset": e.mint,
            "amount": e.price_atomic_amount.to_string(),
            "payTo": e.recipient,
            "maxTimeoutSeconds": e.max_timeout_seconds,
            "extra": extra,
        });
        let mut resource = json!({ "url": e.resource_url });
        if let Some(desc) = &e.resource_description {
            resource["description"] = json!(desc);
        }
        if let Some(mime) = &e.resource_mime_type {
            resource["mimeType"] = json!(mime);
        }
        let mut root = json!({
            "x402Version": X402_VERSION,
            "resource": resource,
            "accepts": [accept],
        });
        if let Some(reason) = &e.challenge_error {
            root["error"] = json!(reason);
        }
        BASE64_STD.encode(Value::to_string(&root).as_bytes())
    }

    /// The full 402 challenge (status + header) an unpaid call receives.
    pub fn challenge(&self) -> InboundX402Challenge {
        InboundX402Challenge {
            http_status: PAYMENT_REQUIRED_STATUS,
            header_name: HEADER_PAYMENT_REQUIRED,
            header_value: self.build_payment_required(),
        }
    }

    /// The canonical [`SelectedPayment`] a #350 client recovers from this
    /// endpoint's own challenge — the single source of truth for the challenge
    /// hash and the fixed atomic amount. Built by round-tripping the merchant's
    /// own header through the frozen wire parser, so the merchant and the payer
    /// can never disagree on what was quoted. A validated endpoint always
    /// round-trips; the `Result` exists only so a future contract change cannot
    /// silently panic.
    pub fn expected_payment(&self) -> Result<SelectedPayment, PaymentError> {
        let header = self.build_payment_required();
        let required = parse_payment_required(&header)?;
        let filter = RequirementFilter {
            networks: std::slice::from_ref(&self.network),
            allowed_mints: None,
        };
        select_requirement(&required, &filter)
    }
}

// ---------------------------------------------------------------------------
// Settlement -> revenue-record coupling
// ---------------------------------------------------------------------------

/// The provenance of a settled revenue record. Kept on its own axis so inbound
/// stablecoin revenue is never conflated with Stripe prepaid top-ups or outbound
/// agent-spend records (issue #356). Those other sources live in their own
/// surfaces; this crate only mints [`RevenueSource::X402Inbound`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevenueSource {
    /// Revenue from an inbound x402 pay-per-call to a FerroGate-hosted API.
    X402Inbound,
}

impl RevenueSource {
    /// Stable string tag for the source (audit / admin rendering).
    pub fn as_str(self) -> &'static str {
        match self {
            RevenueSource::X402Inbound => "x402_inbound",
        }
    }
}

/// Per-call attribution the gateway resolves for an inbound paid request, mapped
/// into FerroGate's own request/tenant identity. The payer wallet identity is
/// carried separately on the settlement evidence and is NEVER used as the
/// FerroGate tenant (issue #356: do not silently mix payer wallet identity with
/// FerroGate tenant identity).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundX402CallContext {
    /// FerroGate request id for the paid call.
    pub request_id: String,
    /// The sidecar's own request id, taken from the admitted request. This — not
    /// [`Self::request_id`] — is what identifies "the same paid call" across a
    /// sidecar timeout-and-retry, because FerroGate mints a fresh
    /// [`Self::request_id`] per HTTP request. Forward-once attribution rests on
    /// it, so it is recorded on the revenue record rather than left as a
    /// process-local claim-guard detail.
    pub sidecar_request_id: String,
    /// Trace id, when present.
    pub trace_id: Option<String>,
    /// HTTP method of the priced call.
    pub method: String,
    /// The FerroGate tenant the priced endpoint is attributed to (product /
    /// public tenant), resolved from FerroGate auth — never from caller headers.
    pub tenant: TenantContext,
    /// Settlement time as observed by the gateway.
    pub occurred_at_unix: Option<u64>,
}

/// Immutable, self-describing evidence of one settled inbound paid call. Mirrors
/// the token-usage [`crate::ledger::LedgerEntry`] shape (idempotency id, tenant,
/// occurred_at) but records the on-chain atomic revenue and its coupling to the
/// 402 challenge instead of token cost. `atomic_amount` is ALWAYS the endpoint's
/// fixed price — the authoritative figure — not a caller-asserted number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundX402RevenueRecord {
    /// Idempotency key: `x402-inbound:<challenge_hash_hex>:<transaction_signature>`.
    /// Couples the settlement to the exact challenge that was quoted, so a
    /// duplicate forwarding / retry of the same paid call is a no-op.
    pub id: String,
    /// Always [`RevenueSource::X402Inbound`].
    pub revenue_source: RevenueSource,
    pub request_id: String,
    /// The sidecar request id that claimed this payment. The forward-once
    /// backstop compares against THIS field, never [`Self::request_id`]: a
    /// sidecar retry of the same paid call keeps its sidecar id but arrives with
    /// a fresh FerroGate request id.
    ///
    /// `#[serde(default)]` keeps records written before this field existed
    /// deserializable; such a record carries an empty sidecar id and therefore
    /// matches no live retry, which fails closed (refused as a replay) rather
    /// than open.
    #[serde(default)]
    pub sidecar_request_id: String,
    #[serde(default)]
    pub trace_id: Option<String>,
    pub method: String,
    pub tenant: TenantContext,
    /// The resource URL the payment unlocked.
    pub resource_url: String,
    /// CAIP-2 network the revenue settled on.
    pub network_caip2: String,
    /// SPL mint the revenue is denominated in.
    pub mint: String,
    /// Recipient (`payTo`) the revenue settled to.
    pub recipient: String,
    /// Settled revenue in atomic token units — ALWAYS equal to the fixed price.
    pub atomic_amount: u64,
    /// Hex challenge hash from the frozen wire contract — the audit/idempotency
    /// key tying this record to the 402 challenge that was issued.
    pub challenge_hash_hex: String,
    /// Base58 on-chain transaction signature from the settlement evidence.
    pub transaction_signature: String,
    /// The payer wallet, when the facilitator reported it. Attribution evidence
    /// ONLY; never the FerroGate tenant.
    #[serde(default)]
    pub payer: Option<String>,
    #[serde(default)]
    pub occurred_at_unix: Option<u64>,
}

/// Fail-closed reasons a paid call does not couple to a revenue record. Every
/// variant means NO revenue is recorded (the protected handler must not be
/// served / the forward is refused).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InboundX402SettlementError {
    /// The facilitator reported the settlement did not succeed.
    SettlementFailed { reason: Option<String> },
    /// The settlement network does not match the fixed-price endpoint's network.
    NetworkMismatch { expected: String, actual: String },
    /// A successful settlement carried no transaction signature.
    MissingTransactionSignature,
    /// The settlement did not report a settled amount, so the fixed price cannot
    /// be proven — fail closed rather than assume it matched.
    MissingSettledAmount,
    /// The settled amount differs from the endpoint's fixed price. THE core
    /// fail-closed guard: revenue is never recorded at a wrong amount.
    AmountMismatch { expected: u64, actual: u64 },
    /// The endpoint's own challenge could not be reconstructed to derive the
    /// coupling hash (should be impossible for a validated endpoint).
    ChallengeConstruction { reason: String },
}

impl std::fmt::Display for InboundX402SettlementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SettlementFailed { reason } => match reason {
                Some(r) => write!(f, "inbound x402 settlement failed: {r}"),
                None => write!(f, "inbound x402 settlement failed"),
            },
            Self::NetworkMismatch { expected, actual } => write!(
                f,
                "settlement network {actual} does not match endpoint network {expected}"
            ),
            Self::MissingTransactionSignature => {
                write!(f, "successful settlement carried no transaction signature")
            }
            Self::MissingSettledAmount => {
                write!(f, "settlement reported no amount; fixed price unprovable")
            }
            Self::AmountMismatch { expected, actual } => write!(
                f,
                "settled amount {actual} does not equal the fixed price {expected}"
            ),
            Self::ChallengeConstruction { reason } => {
                write!(f, "could not reconstruct challenge coupling: {reason}")
            }
        }
    }
}

impl std::error::Error for InboundX402SettlementError {}

/// Couple a paid call's wire-parsed [`SettlementEvidence`] to a fixed-price
/// endpoint, producing an immutable [`InboundX402RevenueRecord`] iff the
/// settlement matches the fixed price on success, network, signature, and
/// amount. Any mismatch fails closed with a distinct
/// [`InboundX402SettlementError`] and records nothing.
///
/// The recorded `atomic_amount` is the endpoint's fixed price (authoritative),
/// which by construction equals the verified settled amount.
pub fn settle_inbound_payment(
    endpoint: &ValidatedInboundX402Endpoint,
    ctx: &InboundX402CallContext,
    evidence: &SettlementEvidence,
) -> Result<InboundX402RevenueRecord, InboundX402SettlementError> {
    if !evidence.success {
        return Err(InboundX402SettlementError::SettlementFailed {
            reason: evidence.error_reason.clone(),
        });
    }
    if evidence.network != endpoint.network {
        return Err(InboundX402SettlementError::NetworkMismatch {
            expected: endpoint.network.caip2().to_string(),
            actual: evidence.network.caip2().to_string(),
        });
    }
    let transaction_signature = evidence
        .transaction_signature
        .clone()
        .ok_or(InboundX402SettlementError::MissingTransactionSignature)?;
    let settled = evidence
        .settled_amount
        .ok_or(InboundX402SettlementError::MissingSettledAmount)?;

    let price = endpoint.price_atomic_amount();
    if settled != price {
        return Err(InboundX402SettlementError::AmountMismatch {
            expected: price,
            actual: settled,
        });
    }

    let selected = endpoint.expected_payment().map_err(|error| {
        InboundX402SettlementError::ChallengeConstruction {
            reason: error.to_string(),
        }
    })?;
    let challenge_hash_hex = selected.challenge_hash_hex();
    let id = format!("x402-inbound:{challenge_hash_hex}:{transaction_signature}");

    Ok(InboundX402RevenueRecord {
        id,
        revenue_source: RevenueSource::X402Inbound,
        request_id: ctx.request_id.clone(),
        sidecar_request_id: ctx.sidecar_request_id.clone(),
        trace_id: ctx.trace_id.clone(),
        method: ctx.method.clone(),
        tenant: ctx.tenant.clone(),
        resource_url: endpoint.endpoint.resource_url.clone(),
        network_caip2: endpoint.network.caip2().to_string(),
        mint: endpoint.endpoint.mint.clone(),
        recipient: endpoint.endpoint.recipient.clone(),
        // The fixed price is the authoritative figure; it equals `settled` here.
        atomic_amount: price,
        challenge_hash_hex,
        transaction_signature,
        payer: evidence.payer.clone(),
        occurred_at_unix: ctx.occurred_at_unix,
    })
}

// ---------------------------------------------------------------------------
// Revenue persistence seam (separate from the token-usage ledger)
// ---------------------------------------------------------------------------

/// Aggregate inbound-revenue totals. `total_atomic_amount` is `u128` so summing
/// many `u64` atomic amounts cannot overflow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevenueTotals {
    pub records: usize,
    pub total_atomic_amount: u128,
}

/// Persistence seam for settled inbound revenue records, deliberately distinct
/// from [`crate::ledger::LedgerSink`] so stablecoin revenue evidence is queryable
/// without touching the token-usage ledger or the prepaid-credit wallet (issue
/// #356). Implementations must be idempotent on [`InboundX402RevenueRecord::id`]
/// so a duplicate forward of the same paid call does not double-count revenue.
pub trait RevenueSink: Send + Sync {
    /// Persist a settled record. Returns `true` if newly recorded, `false` on an
    /// idempotent replay of a byte-equivalent record.
    fn record(&self, record: &InboundX402RevenueRecord) -> Result<bool, BillingError>;
    /// List recorded revenue, oldest first, paginated.
    fn list(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<InboundX402RevenueRecord>, BillingError>;
    /// Fetch a single record by its idempotency id.
    fn get(&self, id: &str) -> Result<Option<InboundX402RevenueRecord>, BillingError>;
}

/// In-memory, idempotent [`RevenueSink`] with an optional retention bound.
#[derive(Debug, Default, Clone)]
pub struct InMemoryRevenueSink {
    inner: Arc<Mutex<InMemoryRevenueState>>,
}

#[derive(Debug, Default)]
struct InMemoryRevenueState {
    records: VecDeque<InboundX402RevenueRecord>,
    retention_limit: Option<usize>,
    recorded_total: u64,
}

fn revenue_poisoned() -> BillingError {
    BillingError::new(
        "billing_revenue_poisoned",
        "inbound revenue sink lock poisoned",
    )
}

impl InMemoryRevenueSink {
    pub fn with_retention_limit(retention_limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryRevenueState {
                records: VecDeque::new(),
                retention_limit: Some(retention_limit),
                recorded_total: 0,
            })),
        }
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.records.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .map(|state| state.records.is_empty())
            .unwrap_or(true)
    }

    pub fn recorded_total(&self) -> u64 {
        self.inner
            .lock()
            .map(|state| state.recorded_total)
            .unwrap_or_default()
    }

    pub fn totals(&self) -> RevenueTotals {
        self.inner
            .lock()
            .map(|state| {
                let mut totals = RevenueTotals {
                    records: state.records.len(),
                    total_atomic_amount: 0,
                };
                for record in &state.records {
                    totals.total_atomic_amount += u128::from(record.atomic_amount);
                }
                totals
            })
            .unwrap_or_default()
    }
}

impl RevenueSink for InMemoryRevenueSink {
    fn record(&self, record: &InboundX402RevenueRecord) -> Result<bool, BillingError> {
        let mut state = self.inner.lock().map_err(|_| revenue_poisoned())?;
        if let Some(existing) = state
            .records
            .iter()
            .find(|existing| existing.id == record.id)
        {
            if existing == record {
                return Ok(false);
            }
            return Err(BillingError::new(
                "billing_revenue_idempotency_conflict",
                format!(
                    "inbound revenue id {} was replayed with different settlement data",
                    record.id
                ),
            ));
        }
        state.records.push_back(record.clone());
        state.recorded_total = state.recorded_total.saturating_add(1);
        if let Some(limit) = state.retention_limit {
            while state.records.len() > limit {
                state.records.pop_front();
            }
        }
        Ok(true)
    }

    fn list(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<InboundX402RevenueRecord>, BillingError> {
        let state = self.inner.lock().map_err(|_| revenue_poisoned())?;
        Ok(state
            .records
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect())
    }

    fn get(&self, id: &str) -> Result<Option<InboundX402RevenueRecord>, BillingError> {
        let state = self.inner.lock().map_err(|_| revenue_poisoned())?;
        Ok(state.records.iter().find(|record| record.id == id).cloned())
    }
}

#[cfg(test)]
#[path = "x402_inbound_test.rs"]
mod x402_inbound_test;
