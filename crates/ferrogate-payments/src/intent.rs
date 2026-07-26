// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: The immutable x402 payment-intent contract (issue #351): the
// sealed, integer-only record binding one already-authorized egress request
// (HTTP method + request-body hash + canonical URL) to one merchant challenge
// (scheme, CAIP-2 network, mint, atomic amount, recipient, challenge hash,
// merchant timeout) at one caller identity (tenant/project/workspace/key/run/
// worker/request). Constructed only through validation; never mutated after.

//! The immutable payment intent (issue #351).
//!
//! A [`SelectedPayment`] says what a *merchant* is asking to be paid. It does
//! not say *which request of ours* is paying it. That gap is the one this type
//! closes: the issue's security invariant is
//!
//! > A challenge cannot redirect payment to another URL, **body**, recipient,
//! > or network.
//!
//! Without an intent, a spend decision authorized for
//! `GET https://pay.example.com/weather` is indistinguishable from a `POST` of
//! an entirely different body to the same URL — same challenge, same policy,
//! same Allow. A [`PaymentIntent`] pins the method and a hash of the request
//! body alongside the payment terms, so a decision is attributable to exactly
//! one request and a replay against a different one is detectable.
//!
//! # Immutability
//!
//! Every field is private. The only constructor is
//! [`PaymentIntent::new`], which validates, and the only deserialization path
//! goes through the same validation (`#[serde(try_from = …)]`). There are no
//! setters and no `&mut` accessors, so once an intent exists it cannot be
//! edited into describing a different payment — the guarantee "immutable" is
//! supposed to carry, rather than a docstring over `pub` fields.
//!
//! [`PaymentIntent::intent_hash_hex`] is a deterministic SHA-256 over the whole
//! record with a versioned domain tag. Two processes that hold the same intent
//! compute the same hash, so an audit sink can prove the intent it stored is
//! the intent policy evaluated even across a serialization boundary.
//!
//! # Money
//!
//! `atomic_amount` is the on-chain integer amount, carried verbatim from the
//! wire contract. There is no float anywhere in this module.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::{
    validate_solana_address, SelectedPayment, SolanaNetwork, MAX_TIMEOUT_SECONDS, SCHEME_EXACT,
    X402_VERSION,
};

/// Domain-separation tag mixed into [`PaymentIntent::intent_hash_hex`]. Bump the
/// version suffix if the hashed tuple ever changes shape.
pub const PAYMENT_INTENT_HASH_DOMAIN: &str = "ferrogate.x402.payment-intent.v1";

/// Longest accepted HTTP method token. RFC 9110 puts no hard cap on a method
/// name; this bounds an attacker-suppliable field without excluding any real
/// method (the longest registered one is 18 characters).
const MAX_METHOD_BYTES: usize = 32;

/// Longest accepted identity component (tenant/project/.../request id).
const MAX_IDENTITY_BYTES: usize = 256;

/// Longest accepted resource URL, matching the wire contract's own bound on the
/// resource it parses.
const MAX_RESOURCE_URL_BYTES: usize = 2_048;

// ---------------------------------------------------------------------------
// Request body hash
// ---------------------------------------------------------------------------

/// SHA-256 of the request body an authorized egress request carries.
///
/// A bodyless request hashes the empty byte string, so "no body" is a concrete,
/// checkable value rather than an absence that every consumer has to remember
/// to special-case.
///
/// Deliberately a PLAIN SHA-256 of the body with no domain tag: every other
/// place in the codebase that records a request-body hash (the worker's
/// `AuthorizedRequest`, the negotiation context's attempt evidence) computes
/// exactly that, and a second, tagged definition would mean the same body
/// hashed two different ways depending on which path built the intent. The type
/// provides the separation a tag would; the bytes stay interoperable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestBodyHash([u8; 32]);

impl RequestBodyHash {
    /// Hash a request body. An empty slice is the canonical "no body" value.
    pub fn of(body: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(body);
        Self(hasher.finalize().into())
    }

    /// The canonical hash of a bodyless request (`GET`, `HEAD`, …).
    pub fn empty() -> Self {
        Self::of(&[])
    }

    /// Lowercase hex form — the wire/audit representation.
    pub fn as_hex(&self) -> String {
        hex_lower(&self.0)
    }

    /// Parse a lowercase-hex body hash back. Rejects anything that is not
    /// exactly 32 bytes of hex, so a truncated or upper-cased value can never
    /// silently compare unequal to the same logical hash.
    pub fn from_hex(value: &str) -> Result<Self, PaymentIntentError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(PaymentIntentError::InvalidBodyHash {
                value: value.to_string(),
            });
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).expect("validated hex");
            let lo = (chunk[1] as char).to_digit(16).expect("validated hex");
            bytes[index] = (hi * 16 + lo) as u8;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for RequestBodyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for RequestBodyHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for RequestBodyHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Who the payment is being made on behalf of. `tenant_id` and `request_id` are
/// mandatory: without them a persisted decision cannot be attributed to anyone,
/// which is the exact gap that makes a spend ledger unauditable.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PaymentIntentIdentity {
    /// Owning tenant (organization). Mandatory.
    pub tenant_id: String,
    /// Project inside the tenant, when the request carried one.
    #[serde(default)]
    pub project_id: Option<String>,
    /// Workspace inside the project, when the request carried one.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// Virtual API key that made the request, when known.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Agent run that caused the payment, when the caller is an agent run.
    #[serde(default)]
    pub run_id: Option<String>,
    /// Worker that executed the run, when known.
    #[serde(default)]
    pub worker_id: Option<String>,
    /// The gateway request id. Mandatory — it is the join key back to the
    /// request log and the idempotency anchor for the settlement loop.
    pub request_id: String,
}

// ---------------------------------------------------------------------------
// Draft (the only way in)
// ---------------------------------------------------------------------------

/// The unvalidated shape of a [`PaymentIntent`]. Exists so construction and
/// deserialization share exactly one validation path; it is never itself
/// treated as an authorization input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentIntentDraft {
    /// x402 protocol version. Must be [`X402_VERSION`].
    pub x402_version: u64,
    /// Payment scheme. Must be [`SCHEME_EXACT`].
    pub scheme: String,
    /// CAIP-2 identifier of the Solana network the payment settles on. Carried
    /// as its canonical string rather than a Rust variant so a persisted intent
    /// is never coupled to an enum name.
    pub network_caip2: String,
    /// Canonical base58 SPL mint address.
    pub mint: String,
    /// On-chain atomic token amount. Integer; never a float.
    pub atomic_amount: u64,
    /// Canonical base58 recipient (`payTo`).
    pub recipient: String,
    /// The resource URL the gateway ALREADY authorized egress to. The
    /// challenge's own resource must equal this.
    pub authorized_resource_url: String,
    /// HTTP method of the already-authorized request, e.g. `GET`, `POST`.
    pub http_method: String,
    /// SHA-256 of the already-authorized request body.
    pub request_body_hash: RequestBodyHash,
    /// The wire contract's deterministic challenge hash, lowercase hex.
    pub challenge_hash_hex: String,
    /// Merchant-advertised payment validity window, in seconds.
    pub max_timeout_seconds: u64,
    /// Who is paying.
    pub identity: PaymentIntentIdentity,
}

// ---------------------------------------------------------------------------
// The sealed intent
// ---------------------------------------------------------------------------

/// The immutable payment-intent contract (issue #351).
///
/// Binds one already-authorized egress request to one merchant challenge at one
/// caller identity. Every field is private and there is no mutating API, so an
/// intent cannot be edited into describing a different payment between the
/// policy call and the audit sink.
///
/// Build with [`PaymentIntent::new`] or [`PaymentIntent::from_selected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PaymentIntentDraft", into = "PaymentIntentDraft")]
pub struct PaymentIntent {
    x402_version: u64,
    scheme: String,
    network: SolanaNetwork,
    mint: String,
    atomic_amount: u64,
    recipient: String,
    authorized_resource_url: String,
    http_method: String,
    request_body_hash: RequestBodyHash,
    challenge_hash_hex: String,
    max_timeout_seconds: u64,
    identity: PaymentIntentIdentity,
}

impl PaymentIntent {
    /// Validate a draft into an immutable intent.
    ///
    /// Fails closed on every field the decision later depends on: an unknown
    /// protocol version or scheme, a non-canonical mint/recipient, a zero
    /// amount, a blank or non-absolute resource URL, a method that is not an
    /// HTTP token, a malformed challenge hash, an out-of-range timeout, and a
    /// missing tenant or request id.
    pub fn new(draft: PaymentIntentDraft) -> Result<Self, PaymentIntentError> {
        if draft.x402_version != X402_VERSION {
            return Err(PaymentIntentError::UnsupportedVersion {
                value: draft.x402_version,
            });
        }
        if draft.scheme != SCHEME_EXACT {
            return Err(PaymentIntentError::UnsupportedScheme {
                value: draft.scheme,
            });
        }
        let network = SolanaNetwork::from_caip2(&draft.network_caip2).ok_or_else(|| {
            PaymentIntentError::UnknownNetwork {
                value: draft.network_caip2.clone(),
            }
        })?;
        validate_solana_address("mint", &draft.mint).map_err(|_| {
            PaymentIntentError::InvalidAddress {
                field: "mint",
                value: draft.mint.clone(),
            }
        })?;
        validate_solana_address("recipient", &draft.recipient).map_err(|_| {
            PaymentIntentError::InvalidAddress {
                field: "recipient",
                value: draft.recipient.clone(),
            }
        })?;
        // A zero-amount intent would authorize a payment that can never be
        // reconciled against a real transfer; the wire contract already rejects
        // it, and re-checking here keeps the intent valid on its own terms.
        if draft.atomic_amount == 0 {
            return Err(PaymentIntentError::ZeroAmount);
        }
        let authorized_resource_url = require_absolute_url(&draft.authorized_resource_url)?;
        let http_method = normalize_http_method(&draft.http_method)?;
        if draft.challenge_hash_hex.len() != 64
            || !draft
                .challenge_hash_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(PaymentIntentError::InvalidChallengeHash {
                value: draft.challenge_hash_hex,
            });
        }
        if draft.max_timeout_seconds == 0 || draft.max_timeout_seconds > MAX_TIMEOUT_SECONDS {
            return Err(PaymentIntentError::TimeoutOutOfRange {
                value: draft.max_timeout_seconds,
            });
        }
        let identity = validate_identity(draft.identity)?;

        Ok(Self {
            x402_version: draft.x402_version,
            scheme: draft.scheme,
            network,
            mint: draft.mint,
            atomic_amount: draft.atomic_amount,
            recipient: draft.recipient,
            authorized_resource_url,
            http_method,
            request_body_hash: draft.request_body_hash,
            challenge_hash_hex: draft.challenge_hash_hex,
            max_timeout_seconds: draft.max_timeout_seconds,
            identity,
        })
    }

    /// Build an intent from a wire-validated challenge plus the request the
    /// gateway already authorized. The convenience path every caller should
    /// use: it copies the payment terms straight off [`SelectedPayment`] so a
    /// transcription slip cannot silently change what is being paid.
    ///
    /// `body` is the authorized request body; pass `&[]` for a bodyless method.
    pub fn from_selected(
        selected: &SelectedPayment,
        http_method: &str,
        authorized_resource_url: &str,
        body: &[u8],
        identity: PaymentIntentIdentity,
    ) -> Result<Self, PaymentIntentError> {
        Self::new(PaymentIntentDraft {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network_caip2: selected.network.caip2().to_string(),
            mint: selected.mint.clone(),
            atomic_amount: selected.atomic_amount,
            recipient: selected.recipient.clone(),
            authorized_resource_url: authorized_resource_url.to_string(),
            http_method: http_method.to_string(),
            request_body_hash: RequestBodyHash::of(body),
            challenge_hash_hex: selected.challenge_hash_hex(),
            max_timeout_seconds: selected.max_timeout_seconds,
            identity,
        })
    }

    /// x402 protocol version this intent was formed under.
    pub fn x402_version(&self) -> u64 {
        self.x402_version
    }
    /// Payment scheme (always [`SCHEME_EXACT`] for this contract).
    pub fn scheme(&self) -> &str {
        &self.scheme
    }
    /// The settlement network.
    pub fn network(&self) -> SolanaNetwork {
        self.network
    }
    /// CAIP-2 identifier of [`Self::network`].
    pub fn network_caip2(&self) -> &'static str {
        self.network.caip2()
    }
    /// Canonical SPL mint address.
    pub fn mint(&self) -> &str {
        &self.mint
    }
    /// On-chain atomic amount, losslessly.
    pub fn atomic_amount(&self) -> u64 {
        self.atomic_amount
    }
    /// Canonical recipient (`payTo`) address.
    pub fn recipient(&self) -> &str {
        &self.recipient
    }
    /// The egress URL the gateway already authorized.
    pub fn authorized_resource_url(&self) -> &str {
        &self.authorized_resource_url
    }
    /// Uppercase HTTP method of the authorized request.
    pub fn http_method(&self) -> &str {
        &self.http_method
    }
    /// SHA-256 of the authorized request body.
    pub fn request_body_hash(&self) -> RequestBodyHash {
        self.request_body_hash
    }
    /// The wire contract's challenge hash, lowercase hex.
    pub fn challenge_hash_hex(&self) -> &str {
        &self.challenge_hash_hex
    }
    /// Merchant-advertised validity window in seconds.
    pub fn max_timeout_seconds(&self) -> u64 {
        self.max_timeout_seconds
    }
    /// Who is paying.
    pub fn identity(&self) -> &PaymentIntentIdentity {
        &self.identity
    }

    /// Deterministic SHA-256 over the whole intent, lowercase hex.
    ///
    /// Domain-tagged and NUL-separated so no two distinct intents can collide
    /// through field concatenation, and optional identity components encode
    /// their presence separately from their content so an absent `run_id` and
    /// an empty-string `run_id` never hash alike. Stable across processes: this
    /// is what lets an audit record prove it holds the same intent policy saw.
    pub fn intent_hash_hex(&self) -> String {
        let mut hasher = Sha256::new();
        let atomic = self.atomic_amount.to_string();
        let version = self.x402_version.to_string();
        let timeout = self.max_timeout_seconds.to_string();
        let body_hash = self.request_body_hash.as_hex();
        for part in [
            PAYMENT_INTENT_HASH_DOMAIN,
            version.as_str(),
            self.scheme.as_str(),
            self.network.caip2(),
            self.mint.as_str(),
            atomic.as_str(),
            self.recipient.as_str(),
            self.authorized_resource_url.as_str(),
            self.http_method.as_str(),
            body_hash.as_str(),
            self.challenge_hash_hex.as_str(),
            timeout.as_str(),
            self.identity.tenant_id.as_str(),
            self.identity.request_id.as_str(),
        ] {
            hasher.update(part.as_bytes());
            hasher.update([0u8]);
        }
        for optional in [
            &self.identity.project_id,
            &self.identity.workspace_id,
            &self.identity.key_id,
            &self.identity.run_id,
            &self.identity.worker_id,
        ] {
            match optional {
                Some(value) => {
                    hasher.update([1u8]);
                    hasher.update(value.as_bytes());
                }
                None => hasher.update([0u8]),
            }
            hasher.update([0u8]);
        }
        hex_lower(&hasher.finalize())
    }

    /// Does this intent describe exactly the payment `selected` demands?
    ///
    /// The check a policy layer runs before authorizing anything: an intent
    /// built for one challenge must never be presented alongside a different
    /// one. Returns the first field that disagrees, so the caller can emit a
    /// specific reason code instead of an opaque refusal.
    pub fn binding_mismatch(&self, selected: &SelectedPayment) -> Option<&'static str> {
        if self.challenge_hash_hex != selected.challenge_hash_hex() {
            return Some("challenge_hash");
        }
        if self.network != selected.network {
            return Some("network");
        }
        if self.mint != selected.mint {
            return Some("mint");
        }
        if self.recipient != selected.recipient {
            return Some("recipient");
        }
        if self.atomic_amount != selected.atomic_amount {
            return Some("atomic_amount");
        }
        if self.max_timeout_seconds != selected.max_timeout_seconds {
            return Some("max_timeout_seconds");
        }
        None
    }
}

impl From<PaymentIntent> for PaymentIntentDraft {
    fn from(intent: PaymentIntent) -> Self {
        Self {
            x402_version: intent.x402_version,
            scheme: intent.scheme,
            network_caip2: intent.network.caip2().to_string(),
            mint: intent.mint,
            atomic_amount: intent.atomic_amount,
            recipient: intent.recipient,
            authorized_resource_url: intent.authorized_resource_url,
            http_method: intent.http_method,
            request_body_hash: intent.request_body_hash,
            challenge_hash_hex: intent.challenge_hash_hex,
            max_timeout_seconds: intent.max_timeout_seconds,
            identity: intent.identity,
        }
    }
}

impl TryFrom<PaymentIntentDraft> for PaymentIntent {
    type Error = PaymentIntentError;

    fn try_from(draft: PaymentIntentDraft) -> Result<Self, Self::Error> {
        Self::new(draft)
    }
}

/// Uppercase and validate an HTTP method token.
///
/// Method names are case-sensitive per RFC 9110, but every method FerroGate
/// proxies is a registered uppercase one, and normalizing here means `get` and
/// `GET` cannot produce two different intent hashes for the same request.
fn normalize_http_method(value: &str) -> Result<String, PaymentIntentError> {
    let trimmed = value.trim();
    let invalid = || PaymentIntentError::InvalidHttpMethod {
        value: value.to_string(),
    };
    if trimmed.is_empty() || trimmed.len() > MAX_METHOD_BYTES {
        return Err(invalid());
    }
    // RFC 9110 tchar, restricted to the alphanumerics and `-`/`_` that every
    // real method uses. A method carrying a space, control character, or
    // separator is rejected rather than smuggled into an audit record.
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid());
    }
    Ok(trimmed.to_ascii_uppercase())
}

/// Require a non-blank absolute `http(s)` URL. The intent binds to a concrete
/// egress target; a relative or schemeless string cannot be compared against a
/// challenge resource and must not be accepted as one.
fn require_absolute_url(value: &str) -> Result<String, PaymentIntentError> {
    let trimmed = value.trim();
    let invalid = || PaymentIntentError::InvalidResourceUrl {
        value: value.to_string(),
    };
    if trimmed.is_empty() || trimmed.len() > MAX_RESOURCE_URL_BYTES {
        return Err(invalid());
    }
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err(invalid());
    };
    let scheme = scheme.to_ascii_lowercase();
    if (scheme != "https" && scheme != "http") || rest.is_empty() {
        return Err(invalid());
    }
    Ok(trimmed.to_string())
}

fn validate_identity(
    identity: PaymentIntentIdentity,
) -> Result<PaymentIntentIdentity, PaymentIntentError> {
    let required = |field: &'static str, value: &str| -> Result<String, PaymentIntentError> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_IDENTITY_BYTES {
            return Err(PaymentIntentError::InvalidIdentity {
                field,
                value: value.to_string(),
            });
        }
        Ok(trimmed.to_string())
    };
    let optional = |field: &'static str,
                    value: Option<String>|
     -> Result<Option<String>, PaymentIntentError> {
        match value {
            // An id present but blank is a caller bug, not "absent": accepting
            // it would put an empty string into the audit trail where a real id
            // was meant.
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() || trimmed.len() > MAX_IDENTITY_BYTES {
                    Err(PaymentIntentError::InvalidIdentity { field, value })
                } else {
                    Ok(Some(trimmed.to_string()))
                }
            }
            None => Ok(None),
        }
    };
    Ok(PaymentIntentIdentity {
        tenant_id: required("tenant_id", &identity.tenant_id)?,
        project_id: optional("project_id", identity.project_id)?,
        workspace_id: optional("workspace_id", identity.workspace_id)?,
        key_id: optional("key_id", identity.key_id)?,
        run_id: optional("run_id", identity.run_id)?,
        worker_id: optional("worker_id", identity.worker_id)?,
        request_id: required("request_id", &identity.request_id)?,
    })
}

/// Why a [`PaymentIntentDraft`] is not a valid intent. Every variant is a
/// distinct rejection class; there is no catch-all, so a caller can render or
/// branch on the cause without string matching.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaymentIntentError {
    /// The protocol version is not the one this contract implements.
    UnsupportedVersion { value: u64 },
    /// The scheme is not `exact`.
    UnsupportedScheme { value: String },
    /// The CAIP-2 network identifier is not a network this contract recognises.
    UnknownNetwork { value: String },
    /// A mint or recipient is not a canonical base58 32-byte address.
    InvalidAddress { field: &'static str, value: String },
    /// The atomic amount is zero.
    ZeroAmount,
    /// The authorized resource URL is blank, over-long, or not absolute http(s).
    InvalidResourceUrl { value: String },
    /// The HTTP method is blank, over-long, or not an HTTP token.
    InvalidHttpMethod { value: String },
    /// The request-body hash is not 32 bytes of lowercase hex.
    InvalidBodyHash { value: String },
    /// The challenge hash is not 32 bytes of lowercase hex.
    InvalidChallengeHash { value: String },
    /// The merchant timeout is zero or beyond the contract's ceiling.
    TimeoutOutOfRange { value: u64 },
    /// A mandatory identity component is blank, or any component is over-long.
    InvalidIdentity { field: &'static str, value: String },
}

impl fmt::Display for PaymentIntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { value } => {
                write!(
                    f,
                    "unsupported x402 version {value} (expected {X402_VERSION})"
                )
            }
            Self::UnsupportedScheme { value } => {
                write!(
                    f,
                    "unsupported payment scheme {value:?} (expected {SCHEME_EXACT:?})"
                )
            }
            Self::UnknownNetwork { value } => {
                write!(f, "unrecognised CAIP-2 network {value:?}")
            }
            Self::InvalidAddress { field, value } => {
                write!(f, "{field} {value:?} is not a valid base58 Solana address")
            }
            Self::ZeroAmount => write!(f, "payment intent atomic amount is zero"),
            Self::InvalidResourceUrl { value } => write!(
                f,
                "authorized resource url {value:?} is not an absolute http(s) URL"
            ),
            Self::InvalidHttpMethod { value } => {
                write!(f, "http method {value:?} is not a valid method token")
            }
            Self::InvalidBodyHash { value } => {
                write!(
                    f,
                    "request body hash {value:?} is not 32 bytes of lowercase hex"
                )
            }
            Self::InvalidChallengeHash { value } => {
                write!(
                    f,
                    "challenge hash {value:?} is not 32 bytes of lowercase hex"
                )
            }
            Self::TimeoutOutOfRange { value } => write!(
                f,
                "merchant timeout {value}s is outside 1..={MAX_TIMEOUT_SECONDS}"
            ),
            Self::InvalidIdentity { field, value } => {
                write!(f, "identity component {field} {value:?} is not usable")
            }
        }
    }
}

impl std::error::Error for PaymentIntentError {}

#[cfg(test)]
#[path = "intent_test.rs"]
mod intent_test;
