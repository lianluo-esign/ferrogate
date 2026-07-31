// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Frozen x402 V2 wire contract for the HTTP transport + Solana SVM `exact`
//! scheme (client role).
//!
//! Shapes follow the upstream specification
//! (`coinbase/x402` — `specs/x402-specification-v2.md`,
//! `specs/transports-v2/http.md`, `specs/schemes/exact/scheme_exact_svm.md`):
//!
//! - `PAYMENT-REQUIRED` (server → client): base64 of a `PaymentRequired`
//!   JSON object (`x402Version`, `resource`, `accepts[]`).
//! - `PAYMENT-SIGNATURE` (client → server): base64 of a `PaymentPayload`
//!   JSON object echoing the chosen requirement in `accepted` plus a
//!   scheme-specific `payload` — for SVM `exact`, a base64 partially-signed
//!   versioned transaction.
//! - `PAYMENT-RESPONSE` (server → client): base64 of a
//!   `SettlementResponse` JSON object.
//!
//! Parsing is strict: unknown top-level fields are tolerated (forward
//! compatibility) but every recognised field is validated, and nothing
//! invalid is ever coerced to a default.

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::PaymentError;

/// x402 protocol version this adapter speaks.
pub const X402_VERSION: u64 = 2;

/// HTTP header carrying the base64 `PaymentRequired` object (server→client).
pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
/// HTTP header carrying the base64 `PaymentPayload` object (client→server).
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
/// HTTP header carrying the base64 `SettlementResponse` object (server→client).
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Hard cap on the pre-decode (base64 text) size of any x402 header.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Hard cap on the number of entries in `accepts` before rejection.
pub const MAX_ACCEPTS_ENTRIES: usize = 16;
/// Safety cap on `maxTimeoutSeconds`; anything above is treated as unsafe.
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;
/// Maximum length of `extra.memo` in bytes, per the SVM `exact` scheme spec.
pub const MAX_MEMO_BYTES: usize = 256;
/// Domain-separation tag mixed into [`SelectedPayment::challenge_hash`].
///
/// The hash is a FerroGate-local idempotency/audit key, not part of the x402
/// wire format. Any change to the hashed tuple MUST bump this tag so that
/// persisted hashes from an older revision are distinguishable.
pub const CHALLENGE_HASH_DOMAIN: &str = "ferrogate-x402-challenge-v1";
/// Domain-separation tag mixed into [`SelectedPayment::payment_identity_hex`].
///
/// Separate from [`CHALLENGE_HASH_DOMAIN`] on purpose: the two hashes answer
/// different questions and MUST NOT be interchangeable. Any change to the
/// hashed tuple MUST bump this tag.
pub const PAYMENT_IDENTITY_DOMAIN: &str = "ferrogate-x402-payment-identity-v1";
/// Solana wire packet limit; a serialized proof transaction can never exceed
/// this, so larger signer output is rejected as a failed proof build.
pub const MAX_SVM_TRANSACTION_BYTES: usize = 1232;

/// CAIP-2 network identifier for Solana mainnet-beta.
pub const CAIP2_SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
/// CAIP-2 network identifier for Solana devnet.
pub const CAIP2_SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// The `exact` payment scheme identifier.
pub const SCHEME_EXACT: &str = "exact";

/// Recognised Solana networks, keyed by their CAIP-2 identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SolanaNetwork {
    /// `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
    Mainnet,
    /// `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1`
    Devnet,
}

impl SolanaNetwork {
    /// Recognise a CAIP-2 network identifier. Purely local — no RPC.
    pub fn from_caip2(id: &str) -> Option<Self> {
        match id {
            CAIP2_SOLANA_MAINNET => Some(Self::Mainnet),
            CAIP2_SOLANA_DEVNET => Some(Self::Devnet),
            _ => None,
        }
    }

    /// The CAIP-2 identifier for this network.
    pub fn caip2(self) -> &'static str {
        match self {
            Self::Mainnet => CAIP2_SOLANA_MAINNET,
            Self::Devnet => CAIP2_SOLANA_DEVNET,
        }
    }
}

/// Parsed, validated `PaymentRequired` object (the decoded
/// `PAYMENT-REQUIRED` header).
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentRequired {
    /// Optional human-readable reason supplied by the server.
    pub error: Option<String>,
    /// URL of the protected resource.
    pub resource_url: String,
    /// Optional resource description.
    pub resource_description: Option<String>,
    /// Optional resource MIME type.
    pub resource_mime_type: Option<String>,
    /// Raw, order-preserved `accepts` entries (validated lazily during
    /// selection so unsupported entries can be skipped without error).
    pub accepts: Vec<Value>,
    /// Server-advertised protocol `extensions` object, verbatim.
    ///
    /// Per x402 V2 §5.1.2/§5.2.2 the client MUST echo at least the info it
    /// received back in the outgoing `PaymentPayload`, so this is carried
    /// through selection into [`build_payment_signature`] unmodified.
    ///
    /// [`build_payment_signature`]: crate::build_payment_signature
    pub extensions: Option<Value>,
}

/// One fully validated, selected SVM `exact` requirement — the structured
/// adapter result handed to policy/billing and to the proof builder.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectedPayment {
    /// Recognised Solana network.
    pub network: SolanaNetwork,
    /// SPL token mint (base58, validated 32 bytes).
    pub mint: String,
    /// Atomic token amount. Parsed strictly; never coerced.
    pub atomic_amount: u64,
    /// Recipient wallet (base58, validated 32 bytes).
    pub recipient: String,
    /// Facilitator fee payer (base58, validated 32 bytes) from `extra.feePayer`.
    pub fee_payer: String,
    /// Optional seller memo from `extra.memo` (<= 256 bytes).
    pub memo: Option<String>,
    /// Optional server-supplied blockhash from `extra.recentBlockhash`
    /// (base58, validated 32 bytes). When present the signer SHOULD use it
    /// as the transaction lifetime instead of fetching its own; when absent
    /// the signer MUST fetch a recent blockhash itself.
    pub recent_blockhash: Option<String>,
    /// Optional `extra.lastValidBlockHeight` bound for
    /// [`Self::recent_blockhash`]. Per the SVM `exact` scheme this field is
    /// ignored when no blockhash was supplied, so it is only ever `Some`
    /// alongside `recent_blockhash`.
    pub last_valid_block_height: Option<u64>,
    /// URL of the protected resource this payment unlocks.
    pub resource_url: String,
    /// Relative payment validity window in seconds (1..=86400).
    pub max_timeout_seconds: u64,
    /// Server-advertised protocol `extensions`, echoed verbatim into the
    /// outgoing `PaymentPayload`.
    pub extensions: Option<Value>,
    /// Deterministic SHA-256 over the canonical *payment terms* tuple:
    /// domain tag, scheme, network, mint, recipient, fee payer, memo,
    /// atomic amount, timeout, resource URL. Stable across processes;
    /// suitable as an idempotency / audit key.
    ///
    /// Transient transport hints (`recentBlockhash`,
    /// `lastValidBlockHeight`) and `extensions` are deliberately EXCLUDED:
    /// a server may refresh them between retries of the same logical
    /// challenge, and including them would make the idempotency key unstable.
    pub challenge_hash: [u8; 32],
    /// The requirement entry exactly as received, echoed verbatim into the
    /// `accepted` field of the outgoing `PaymentPayload`.
    pub raw_requirement: Value,
}

impl SelectedPayment {
    /// Lowercase hex of the SHA-256 over the *economic identity* of this
    /// payment: scheme, network, mint, recipient, atomic amount, resource URL.
    ///
    /// This is NOT [`Self::challenge_hash`] and must not be confused with it.
    /// `challenge_hash` covers the full audit tuple, which includes
    /// `fee_payer`, `max_timeout_seconds` and `memo` — fields the MERCHANT
    /// controls and may legitimately refresh between retries of the same
    /// logical challenge. That makes `challenge_hash` right for the immutable
    /// audit record and WRONG as a payment idempotency key: a merchant that
    /// flips one `memo` byte on a retry would mint a different key, opening a
    /// second attempt and a second wallet hold for a payment the caller only
    /// ever authorized once — i.e. it could make the gateway pay twice.
    ///
    /// This tuple is exactly the set a merchant cannot vary without changing
    /// *what is being bought and for how much*: vary any of it and it genuinely
    /// is a different payment. Transport hints (`recentBlockhash`,
    /// `lastValidBlockHeight`) and `extensions` are excluded for the same
    /// refresh reason as in `challenge_hash`.
    ///
    /// Callers key durable payment attempts on this. The full `challenge_hash`
    /// is still stored on the attempt, so a retry that changes a merchant-
    /// controlled field lands on the SAME attempt id and fails closed against
    /// the attempt's immutable tuple rather than paying again.
    pub fn payment_identity_hex(&self) -> String {
        let mut h = Sha256::new();
        let amount = self.atomic_amount.to_string();
        for part in [
            PAYMENT_IDENTITY_DOMAIN,
            SCHEME_EXACT,
            self.network.caip2(),
            self.mint.as_str(),
            self.recipient.as_str(),
            amount.as_str(),
            self.resource_url.as_str(),
        ] {
            h.update(part.as_bytes());
            h.update([0u8]);
        }
        let digest: [u8; 32] = h.finalize().into();
        hex_lower(&digest)
    }

    /// Lowercase hex form of [`Self::challenge_hash`].
    pub fn challenge_hash_hex(&self) -> String {
        hex_lower(&self.challenge_hash)
    }
}

/// Lowercase hex of a 32-byte digest. One definition, so the two hash
/// accessors above cannot render the same bytes differently.
fn hex_lower(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Caller-supplied constraints for requirement selection. This is mechanical
/// input — actual payment *policy* (budgets, approvals) lives outside this
/// crate.
#[derive(Debug, Clone, Default)]
pub struct RequirementFilter<'a> {
    /// Networks the caller is willing to pay on. Empty ⇒ any recognised
    /// Solana network.
    pub networks: &'a [SolanaNetwork],
    /// Optional mint allowlist (base58 strings). `None` ⇒ any valid mint.
    pub allowed_mints: Option<&'a [&'a str]>,
}

/// Decoded settlement evidence from a `PAYMENT-RESPONSE` header.
#[derive(Debug, Clone, PartialEq)]
pub struct SettlementEvidence {
    /// Whether the facilitator reported successful settlement.
    pub success: bool,
    /// Base58 transaction signature (present and validated iff `success`).
    pub transaction_signature: Option<String>,
    /// Network the settlement occurred on.
    pub network: SolanaNetwork,
    /// Fee payer / payer address, if reported.
    pub payer: Option<String>,
    /// Machine-readable failure reason, if settlement failed.
    pub error_reason: Option<String>,
    /// Actual settled atomic amount, if reported.
    pub settled_amount: Option<u64>,
}

fn malformed(header: &'static str, reason: impl Into<String>) -> PaymentError {
    PaymentError::MalformedHeader {
        header,
        reason: reason.into(),
    }
}

/// Base64-decode an x402 header value (standard alphabet, padded), enforcing
/// the size cap BEFORE decoding.
fn decode_header(header: &'static str, value: &str) -> Result<Vec<u8>, PaymentError> {
    if value.len() > MAX_HEADER_BYTES {
        return Err(PaymentError::OversizedHeader {
            header,
            limit: MAX_HEADER_BYTES,
            actual: value.len(),
        });
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(malformed(header, "empty header value"));
    }
    BASE64_STD
        .decode(trimmed)
        .map_err(|e| malformed(header, format!("invalid base64: {e}")))
}

fn parse_json(header: &'static str, bytes: &[u8]) -> Result<Value, PaymentError> {
    serde_json::from_slice::<Value>(bytes)
        .map_err(|e| malformed(header, format!("invalid JSON: {e}")))
}

/// Validate the `x402Version` field: must exist and be the integer 2.
fn require_version(header: &'static str, obj: &Value) -> Result<(), PaymentError> {
    let v = obj
        .get("x402Version")
        .ok_or_else(|| malformed(header, "missing x402Version"))?;
    match v.as_u64() {
        Some(X402_VERSION) => Ok(()),
        _ => Err(PaymentError::UnsupportedVersion {
            found: v.to_string(),
        }),
    }
}

fn require_str<'v>(
    header: &'static str,
    obj: &'v Value,
    field: &str,
) -> Result<&'v str, PaymentError> {
    obj.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed(header, format!("missing or non-string {field}")))
}

/// Parse a `PAYMENT-REQUIRED` header value into a validated
/// [`PaymentRequired`].
pub fn parse_payment_required(header_value: &str) -> Result<PaymentRequired, PaymentError> {
    const H: &str = HEADER_PAYMENT_REQUIRED;
    let bytes = decode_header(H, header_value)?;
    let root = parse_json(H, &bytes)?;
    if !root.is_object() {
        return Err(malformed(H, "top-level value is not a JSON object"));
    }
    require_version(H, &root)?;

    let resource = root
        .get("resource")
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(H, "missing or non-object resource"))?;
    let resource_url = resource
        .get("url")
        .and_then(Value::as_str)
        .filter(|u| !u.is_empty() && u.len() <= 2048)
        .ok_or_else(|| malformed(H, "resource.url missing, empty, or oversized"))?
        .to_string();

    let accepts = root
        .get("accepts")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed(H, "missing or non-array accepts"))?;
    if accepts.is_empty() {
        return Err(malformed(H, "accepts is empty"));
    }
    if accepts.len() > MAX_ACCEPTS_ENTRIES {
        return Err(malformed(
            H,
            format!(
                "accepts has {} entries, cap is {MAX_ACCEPTS_ENTRIES}",
                accepts.len()
            ),
        ));
    }
    if !accepts.iter().all(Value::is_object) {
        return Err(malformed(H, "accepts contains a non-object entry"));
    }

    let extensions = match root.get("extensions") {
        None | Some(Value::Null) => None,
        Some(v) if v.is_object() => Some(v.clone()),
        Some(_) => return Err(malformed(H, "extensions is not a JSON object")),
    };

    Ok(PaymentRequired {
        error: root
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string),
        resource_url,
        resource_description: resource
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_string),
        resource_mime_type: resource
            .get("mimeType")
            .and_then(Value::as_str)
            .map(str::to_string),
        accepts: accepts.clone(),
        extensions,
    })
}

/// Strict atomic-amount parser: ASCII digits only, canonical (no leading
/// zeros), non-zero, fits `u64`. Invalid input is a hard error — NEVER zero.
pub fn parse_atomic_amount(raw: &str) -> Result<u64, PaymentError> {
    let err = |reason: &str| PaymentError::InvalidAmount {
        amount: truncate_for_error(raw),
        reason: reason.to_string(),
    };
    if raw.is_empty() {
        return Err(err("empty"));
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("must contain only ASCII digits"));
    }
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(err("non-canonical leading zero"));
    }
    let value: u64 = raw.parse().map_err(|_| err("overflows u64"))?;
    if value == 0 {
        return Err(err("zero amount"));
    }
    Ok(value)
}

fn truncate_for_error(s: &str) -> String {
    const CAP: usize = 64;
    if s.len() <= CAP {
        s.to_string()
    } else {
        let mut end = CAP;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Minimal base58 decoder (Bitcoin alphabet) — enough to validate Solana
/// addresses (32 bytes) and transaction signatures (64 bytes) without
/// pulling the Solana SDK stack.
pub fn base58_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() > 128 {
        return None;
    }
    let mut digits: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input.as_bytes() {
        let d = BASE58_ALPHABET.iter().position(|&a| a == b)?;
        digits.push(d as u8);
    }
    let zeros = input.bytes().take_while(|&b| b == b'1').count();
    let mut out: Vec<u8> = Vec::new();
    for &d in &digits {
        let mut carry = u32::from(d);
        for byte in out.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.reverse();
    Some(out)
}

/// Validate a base58 Solana address (must decode to exactly 32 bytes).
pub fn validate_solana_address(field: &'static str, value: &str) -> Result<(), PaymentError> {
    match base58_decode(value) {
        Some(bytes) if bytes.len() == 32 => Ok(()),
        _ => Err(PaymentError::InvalidRecipient {
            field,
            value: truncate_for_error(value),
        }),
    }
}

fn require_timeout(entry: &Value) -> Result<u64, PaymentError> {
    let v = entry
        .get("maxTimeoutSeconds")
        .ok_or_else(|| PaymentError::InvalidTimeout {
            reason: "missing".to_string(),
        })?;
    let secs = v.as_u64().ok_or_else(|| PaymentError::InvalidTimeout {
        reason: format!("not a non-negative integer: {v}"),
    })?;
    if secs == 0 {
        return Err(PaymentError::InvalidTimeout {
            reason: "zero (already expired)".to_string(),
        });
    }
    if secs > MAX_TIMEOUT_SECONDS {
        return Err(PaymentError::InvalidTimeout {
            reason: format!("{secs}s exceeds safety cap of {MAX_TIMEOUT_SECONDS}s"),
        });
    }
    Ok(secs)
}

/// Strict decimal parser for `extra.lastValidBlockHeight`, which the SVM
/// `exact` scheme defines as a decimal string. Unlike an atomic amount this
/// tolerates leading zeros (it is an advisory bound, not money), but it is
/// still never coerced: a non-numeric, zero, or overflowing value is an error.
fn parse_block_height(raw: &str) -> Result<u64, PaymentError> {
    let bad = || {
        malformed(
            HEADER_PAYMENT_REQUIRED,
            format!(
                "extra.lastValidBlockHeight {:?} is not a positive decimal u64",
                truncate_for_error(raw)
            ),
        )
    };
    if raw.is_empty() || raw.len() > 20 || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    match raw.parse::<u64>() {
        Ok(v) if v > 0 => Ok(v),
        _ => Err(bad()),
    }
}

/// Deterministic SHA-256 over the canonical payment-terms tuple.
/// FerroGate-local (not part of the wire contract); NUL-separated with a
/// versioned domain tag so field concatenation cannot collide.
///
/// Memo presence is encoded separately from memo content so that an absent
/// memo and an empty-string memo cannot hash to the same value.
fn challenge_hash(terms: &ChallengeTerms<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    let amount = terms.atomic_amount.to_string();
    let timeout = terms.max_timeout_seconds.to_string();
    for part in [
        CHALLENGE_HASH_DOMAIN,
        SCHEME_EXACT,
        terms.network.caip2(),
        terms.mint,
        terms.recipient,
        terms.fee_payer,
        amount.as_str(),
        timeout.as_str(),
        terms.resource_url,
    ] {
        h.update(part.as_bytes());
        h.update([0u8]);
    }
    match terms.memo {
        Some(m) => {
            h.update([1u8]);
            h.update(m.as_bytes());
        }
        None => h.update([0u8]),
    }
    h.update([0u8]);
    h.finalize().into()
}

/// The payment-terms tuple fed to [`challenge_hash`]. Deliberately excludes
/// the transient `recentBlockhash` / `lastValidBlockHeight` hints and
/// `extensions`, which a server may refresh between retries of the same
/// logical challenge.
struct ChallengeTerms<'a> {
    network: SolanaNetwork,
    mint: &'a str,
    recipient: &'a str,
    fee_payer: &'a str,
    memo: Option<&'a str>,
    atomic_amount: u64,
    max_timeout_seconds: u64,
    resource_url: &'a str,
}

/// Select exactly one supported requirement from a parsed
/// [`PaymentRequired`], validating every field of the chosen entry.
///
/// Entries whose scheme or network this adapter does not support are
/// skipped; if a supported entry is present but corrupt (bad amount,
/// invalid recipient, unsafe timeout, ...), that is a hard error rather
/// than a silent skip. Exact-duplicate or conflicting entries (same
/// scheme/network/mint/recipient with differing amounts) are rejected.
pub fn select_requirement(
    required: &PaymentRequired,
    filter: &RequirementFilter<'_>,
) -> Result<SelectedPayment, PaymentError> {
    const H: &str = HEADER_PAYMENT_REQUIRED;

    // Reject duplicate / conflicting accepts entries up front.
    let mut seen: Vec<(&str, &str, &str, &str)> = Vec::new();
    for entry in &required.accepts {
        let key = (
            entry.get("scheme").and_then(Value::as_str).unwrap_or(""),
            entry.get("network").and_then(Value::as_str).unwrap_or(""),
            entry.get("asset").and_then(Value::as_str).unwrap_or(""),
            entry.get("payTo").and_then(Value::as_str).unwrap_or(""),
        );
        if seen.contains(&key) {
            return Err(malformed(
                H,
                "duplicate or conflicting accepts entries for the same \
                 scheme/network/asset/payTo",
            ));
        }
        seen.push(key);
    }

    let mut last_unsupported: Option<PaymentError> = None;
    for entry in &required.accepts {
        let scheme = require_str(H, entry, "scheme")?;
        if scheme != SCHEME_EXACT {
            last_unsupported = Some(PaymentError::UnsupportedScheme {
                scheme: truncate_for_error(scheme),
            });
            continue;
        }
        let network_id = require_str(H, entry, "network")?;
        let Some(network) = SolanaNetwork::from_caip2(network_id) else {
            last_unsupported = Some(PaymentError::UnsupportedNetwork {
                network: truncate_for_error(network_id),
            });
            continue;
        };
        if !filter.networks.is_empty() && !filter.networks.contains(&network) {
            last_unsupported = Some(PaymentError::UnsupportedNetwork {
                network: network_id.to_string(),
            });
            continue;
        }

        // This entry claims a scheme+network we support: from here on any
        // invalid field is a hard error, never a silent skip.
        let mint = require_str(H, entry, "asset")?;
        validate_solana_address("asset", mint)?;
        if let Some(allow) = filter.allowed_mints {
            if !allow.contains(&mint) {
                last_unsupported = Some(PaymentError::UnsupportedMint {
                    mint: mint.to_string(),
                });
                continue;
            }
        }
        let amount_raw = require_str(H, entry, "amount")?;
        let atomic_amount = parse_atomic_amount(amount_raw)?;
        let recipient = require_str(H, entry, "payTo")?;
        validate_solana_address("payTo", recipient)?;
        let max_timeout_seconds = require_timeout(entry)?;

        let extra = entry
            .get("extra")
            .and_then(Value::as_object)
            .ok_or_else(|| malformed(H, "SVM exact requirement missing extra object"))?;
        let fee_payer = extra
            .get("feePayer")
            .and_then(Value::as_str)
            .ok_or_else(|| malformed(H, "extra.feePayer missing or non-string"))?;
        validate_solana_address("extra.feePayer", fee_payer)?;
        let memo = match extra.get("memo") {
            None => None,
            Some(Value::String(m)) if m.len() <= MAX_MEMO_BYTES => Some(m.clone()),
            Some(Value::String(_)) => {
                return Err(malformed(
                    H,
                    format!("extra.memo exceeds {MAX_MEMO_BYTES} bytes"),
                ))
            }
            Some(_) => return Err(malformed(H, "extra.memo is not a string")),
        };

        // `extra.recentBlockhash` / `extra.lastValidBlockHeight` are the
        // transaction-lifetime hints the SVM `exact` scheme lets the resource
        // server supply so the client can skip a `getLatestBlockhash` RPC.
        // They are signer input, so they must survive into the intent rather
        // than force the signer to re-parse the raw requirement.
        let recent_blockhash = match extra.get("recentBlockhash") {
            None | Some(Value::Null) => None,
            Some(Value::String(bh)) => match base58_decode(bh) {
                Some(bytes) if bytes.len() == 32 => Some(bh.clone()),
                _ => {
                    return Err(malformed(
                        H,
                        "extra.recentBlockhash is not a base58 32-byte blockhash",
                    ))
                }
            },
            Some(_) => return Err(malformed(H, "extra.recentBlockhash is not a string")),
        };
        // Spec: `lastValidBlockHeight` is "ignored when recentBlockhash is
        // absent", so it is only validated when a blockhash was supplied.
        let last_valid_block_height = match (&recent_blockhash, extra.get("lastValidBlockHeight")) {
            (None, _) | (Some(_), None) | (Some(_), Some(Value::Null)) => None,
            (Some(_), Some(Value::String(height))) => Some(parse_block_height(height)?),
            (Some(_), Some(_)) => {
                return Err(malformed(
                    H,
                    "extra.lastValidBlockHeight is not a decimal string",
                ))
            }
        };

        return Ok(SelectedPayment {
            network,
            mint: mint.to_string(),
            atomic_amount,
            recipient: recipient.to_string(),
            fee_payer: fee_payer.to_string(),
            memo: memo.clone(),
            recent_blockhash,
            last_valid_block_height,
            resource_url: required.resource_url.clone(),
            max_timeout_seconds,
            extensions: required.extensions.clone(),
            challenge_hash: challenge_hash(&ChallengeTerms {
                network,
                mint,
                recipient,
                fee_payer,
                memo: memo.as_deref(),
                atomic_amount,
                max_timeout_seconds,
                resource_url: &required.resource_url,
            }),
            raw_requirement: entry.clone(),
        });
    }

    match last_unsupported {
        Some(err @ PaymentError::UnsupportedMint { .. }) => Err(err),
        Some(err @ PaymentError::UnsupportedNetwork { .. }) if required.accepts.len() == 1 => {
            Err(err)
        }
        Some(err @ PaymentError::UnsupportedScheme { .. }) if required.accepts.len() == 1 => {
            Err(err)
        }
        _ => Err(PaymentError::NoAcceptableRequirement),
    }
}

/// Parse and validate a `PAYMENT-RESPONSE` settlement header.
///
/// `expected_network` pins the evidence to the network of the payment that
/// was actually proposed; a mismatch is malformed settlement evidence.
pub fn parse_payment_response(
    header_value: &str,
    expected_network: SolanaNetwork,
) -> Result<SettlementEvidence, PaymentError> {
    const H: &str = HEADER_PAYMENT_RESPONSE;
    let settle_err = |reason: String| PaymentError::MalformedSettlement { reason };

    let bytes = decode_header(H, header_value).map_err(|e| match e {
        PaymentError::OversizedHeader { .. } => e,
        other => settle_err(other.to_string()),
    })?;
    let root = serde_json::from_slice::<Value>(&bytes)
        .map_err(|e| settle_err(format!("invalid JSON: {e}")))?;
    if !root.is_object() {
        return Err(settle_err("top-level value is not a JSON object".into()));
    }

    let success = root
        .get("success")
        .and_then(Value::as_bool)
        .ok_or_else(|| settle_err("missing or non-boolean success".into()))?;

    let network_id = root
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| settle_err("missing or non-string network".into()))?;
    let network =
        SolanaNetwork::from_caip2(network_id).ok_or_else(|| PaymentError::UnsupportedNetwork {
            network: truncate_for_error(network_id),
        })?;
    if network != expected_network {
        return Err(settle_err(format!(
            "settlement network {} does not match expected {}",
            network.caip2(),
            expected_network.caip2()
        )));
    }

    let transaction = root
        .get("transaction")
        .and_then(Value::as_str)
        .ok_or_else(|| settle_err("missing or non-string transaction".into()))?;
    let transaction_signature = if success {
        match base58_decode(transaction) {
            Some(sig) if sig.len() == 64 => Some(transaction.to_string()),
            _ => {
                return Err(settle_err(
                    "successful settlement carries an invalid base58 \
                     transaction signature"
                        .into(),
                ))
            }
        }
    } else {
        None
    };

    let settled_amount = match root.get("amount") {
        None | Some(Value::Null) => None,
        Some(Value::String(a)) => Some(parse_atomic_amount(a)?),
        Some(_) => return Err(settle_err("amount is not a string".into())),
    };

    Ok(SettlementEvidence {
        success,
        transaction_signature,
        network,
        payer: root
            .get("payer")
            .and_then(Value::as_str)
            .map(str::to_string),
        error_reason: root
            .get("errorReason")
            .and_then(Value::as_str)
            .map(str::to_string),
        settled_amount,
    })
}

/// Encode arbitrary bytes as a base64 header value (standard alphabet,
/// padded) — the inverse of [`decode_header`] for outbound headers.
pub(crate) fn encode_header_bytes(bytes: &[u8]) -> String {
    BASE64_STD.encode(bytes)
}
