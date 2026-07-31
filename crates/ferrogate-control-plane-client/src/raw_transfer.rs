// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Resolution evidence and integrity verification for byte-faithful (raw)
//! transfers (issue #363).
//!
//! A raw export writes the server's bytes to stdout unchanged, which is the
//! whole point of the path — but it also meant every *out-of-band* fact the
//! contract attaches to those bytes was dropped on the floor. `getAsset`
//! resolves a channel (`stable`) or a semver range (`^1.2`) to a concrete
//! version and reports which one it picked in `x-ferrogate-asset-version` /
//! `-resolved` / `-variant`; it flags a withdrawn release with
//! `x-ferrogate-asset-yanked` plus an RFC 7234 `Warning`; and it publishes the
//! object's SHA-256 as a strong `ETag`. Discarding all of that left
//! `ctl assets get cli_tool ferrogate stable` unable to answer "which version
//! did I just download, is it yanked, and did it arrive intact" — the exact
//! questions the issue's channel-promotion and checksum acceptance criteria
//! are about.
//!
//! Everything here is pure and header-driven. There is no asset-specific name
//! in the selection rule: the evidence set is "the vendor namespace plus the
//! HTTP validators", so an operation that starts reporting a new
//! `x-ferrogate-*` fact surfaces it without a code change here.
//!
//! Diagnostics discipline: these values go to **stderr**, never stdout. stdout
//! on this path is the durable artifact and a single stray byte corrupts it.

use sha2::{Digest, Sha256};

/// Vendor namespace whose response headers are operator-facing evidence.
const EVIDENCE_PREFIX: &str = "x-ferrogate-";

/// The one `x-ferrogate-*` response header that is NOT evidence: the client
/// time token is replay-sensitive transport material the context store already
/// consumes, not something to echo into an operator's terminal or CI log.
const EVIDENCE_PREFIX_EXCEPTIONS: &[&str] = &["x-ferrogate-time-token"];

/// Standard HTTP headers that describe *which bytes these are*: the validator,
/// the range actually served, the freshness policy, and the warning a yanked
/// release carries.
const EVIDENCE_HEADERS: &[&str] = &[
    "etag",
    "warning",
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "last-modified",
];

/// Header naming the strong SHA-256 validator of the resolved object.
const ETAG_HEADER: &str = "etag";

/// Header present (with value `true`) only when the resolved version is yanked.
const YANKED_HEADER: &str = "x-ferrogate-asset-yanked";

/// Header carrying the concrete version a channel/semver reference resolved to.
const VERSION_HEADER: &str = "x-ferrogate-asset-version";

/// Header present when the response body is one byte range, not the whole
/// object. Its presence makes the `ETag` (which validates the *complete*
/// representation) inapplicable to the bytes in hand.
const CONTENT_RANGE_HEADER: &str = "content-range";

/// Case-insensitive header lookup over a transport header list.
fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The response headers a raw transfer must report to the operator, in the
/// order the server sent them.
///
/// Selection is by rule, not by list: every `x-ferrogate-*` header except the
/// replay-sensitive time token, plus the HTTP validators/descriptors in
/// [`EVIDENCE_HEADERS`]. Correlation ids (`x-request-id`, `x-trace-id`) are
/// deliberately absent — the caller already reports those under their own
/// labels, and duplicating them here would double every line.
pub fn transfer_evidence(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let lower = name.to_ascii_lowercase();
            if EVIDENCE_PREFIX_EXCEPTIONS.contains(&lower.as_str()) {
                return false;
            }
            lower.starts_with(EVIDENCE_PREFIX) || EVIDENCE_HEADERS.contains(&lower.as_str())
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect()
}

/// The operator-facing warning when the resolved version has been yanked, or
/// `None` when it has not.
///
/// A yanked version stays downloadable by contract (existing lockfiles must
/// keep resolving), so the bytes are not an error — but a pull that silently
/// hands over a withdrawn release is how a known-bad artifact gets redeployed.
/// The server's own `Warning` text is included verbatim when present rather
/// than paraphrased, so the reason travels with the notice.
pub fn yank_warning(headers: &[(String, String)]) -> Option<String> {
    let yanked = header(headers, YANKED_HEADER)?;
    if !yanked.eq_ignore_ascii_case("true") {
        return None;
    }
    let version = header(headers, VERSION_HEADER).unwrap_or("(version not reported)");
    let detail = match header(headers, "warning") {
        Some(warning) => format!(" — {warning}"),
        None => String::new(),
    };
    Some(format!(
        "warning: the resolved version {version} is YANKED and must not be used for new \
         deployments{detail}"
    ))
}

/// Outcome of checking the downloaded bytes against the server's strong
/// validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumVerdict {
    /// The body hashes to exactly what the `ETag` declared.
    Verified {
        /// Lowercase hex SHA-256 of the received bytes.
        sha256: String,
    },
    /// No check was possible. Carries the reason so the operator is never left
    /// believing an unverified download was verified.
    Unverifiable {
        /// Why verification did not apply (no validator, partial content, or a
        /// validator that is not a SHA-256 digest).
        reason: &'static str,
    },
    /// The bytes are not the object the server named. Fail closed.
    Mismatch {
        /// Digest the `ETag` declared.
        expected: String,
        /// Digest the received bytes actually hash to.
        actual: String,
    },
}

/// Verify the received bytes against the strong `ETag` validator.
///
/// `ETag` on this surface is `"<sha256hex>"` — the gateway derives it directly
/// from the stored `content_hash` — so the client can recompute it and refuse a
/// corrupted or truncated transfer instead of writing damaged bytes to stdout
/// with exit 0. A weak (`W/`) validator or any non-64-hex token is reported as
/// unverifiable rather than treated as a mismatch: a weak validator makes no
/// byte-equality claim, so failing on it would be a false alarm.
///
/// A `206` (or any response carrying `Content-Range`) is unverifiable by
/// design: the validator describes the *complete* representation, and hashing
/// one range against it would fail every time.
pub fn verify_checksum(status: u16, headers: &[(String, String)], body: &[u8]) -> ChecksumVerdict {
    if status == 206 || header(headers, CONTENT_RANGE_HEADER).is_some() {
        return ChecksumVerdict::Unverifiable {
            reason: "the response is a partial byte range; the ETag validates the whole object",
        };
    }
    let Some(etag) = header(headers, ETAG_HEADER) else {
        return ChecksumVerdict::Unverifiable {
            reason: "the server sent no ETag validator",
        };
    };
    let Some(expected) = sha256_from_etag(etag) else {
        return ChecksumVerdict::Unverifiable {
            reason: "the ETag is not a strong SHA-256 validator",
        };
    };
    let actual = sha256_hex(body);
    if actual == expected {
        ChecksumVerdict::Verified { sha256: actual }
    } else {
        ChecksumVerdict::Mismatch { expected, actual }
    }
}

/// Extract the lowercase hex SHA-256 from a strong `ETag`, or `None` when the
/// validator is weak or is not a 64-character hex digest.
fn sha256_from_etag(etag: &str) -> Option<String> {
    let trimmed = etag.trim();
    if trimmed.starts_with("W/") || trimmed.starts_with("w/") {
        return None;
    }
    let token = trimmed.trim_matches('"');
    if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(token.to_ascii_lowercase())
    } else {
        None
    }
}

/// Lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}
