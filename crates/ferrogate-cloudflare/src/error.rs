// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Typed error model for the shared Cloudflare API client.

//! Typed errors for the Cloudflare client (issue #405).
//!
//! Cloudflare's REST API always answers with a JSON envelope
//! (`{ success, errors[], result }`); a non-2xx HTTP status and a
//! `success: false` envelope both carry the same `errors[]` array of
//! `{ code, message }` pairs. [`CloudflareError`] flattens that plus the
//! transport/decoding failure modes into one exhaustive enum so every
//! downstream Cloudflare sub-issue maps failures the same way instead of
//! re-deriving the codes.

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

/// A single `{ code, message }` entry from a Cloudflare error envelope.
///
/// `code` is Cloudflare's stable numeric error code (e.g. `9109`
/// "Unauthorized to access requested resource"); `message` is the
/// human-readable text. Both are decoded verbatim from the wire.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CloudflareApiError {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

impl fmt::Display for CloudflareApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Cloudflare error codes that mean "the token is valid but is missing a
/// required permission group" — surfaced as [`CloudflareError::MissingScope`]
/// so `preflight()` can name the scopes an operator must add.
///
/// `9109` = "Unauthorized to access requested resource"; `9103` /
/// `9107` are the sibling authorization-denied codes Cloudflare returns
/// when a token authenticates but is not scoped for the resource.
///
/// Cross-namespace audit (issue #493): all three codes live in the
/// account/token-auth namespace (`9xxx`), which every product shares — they
/// are not re-used with a different meaning by R2 (whose codes are the
/// disjoint S3-flavoured `10001`-`10007x` range plus the outlier `100100`
/// `EntityTooLarge`/400, documented at
/// <https://developers.cloudflare.com/r2/api/error-codes/>, e.g. `10002`
/// Unauthorized/401, `10003` AccessDenied/403, `10035`
/// SignatureDoesNotMatch/403, `10042` NotEntitled/403 — none of which
/// overlap the `9xxx`/`1000`/`10000` account-auth codes) or by any other
/// Cloudflare product researched for that issue. No collision found, so the
/// bare numeric match is kept as-is.
pub const MISSING_SCOPE_CODES: &[i64] = &[9103, 9107, 9109];

/// Cloudflare error codes that mean the credential itself is bad
/// (unknown/expired/malformed token), as opposed to merely under-scoped.
///
/// Cross-namespace audit (issue #493): same conclusion as
/// [`MISSING_SCOPE_CODES`] — `1000`, `9106` and `10000` are general
/// `client/v4` account-auth codes and none of them appear in R2's disjoint
/// error-code range (`10001`-`10007x` plus `100100`; R2 defines neither
/// `1000` nor `10000`; its own auth codes are
/// `10002`/`10003`/`10035`/`10042`, none of which are listed here because
/// `status == 401`/`403` in [`CloudflareError::from_response`] already
/// classifies them as [`CloudflareError::Unauthorized`] without needing a
/// numeric-code match). No collision found.
pub const AUTHENTICATION_CODES: &[i64] = &[1000, 9106, 10000];

/// Every failure mode of the shared Cloudflare client.
#[derive(Debug)]
pub enum CloudflareError {
    /// Static configuration is unusable (empty account id / token, malformed
    /// base URL). Raised before any request is attempted.
    Config(String),
    /// The [`crate::TokenResolver`] could not turn a token reference into a
    /// secret (missing env var, unsupported `cf://` backend, etc.).
    TokenResolution(String),
    /// The HTTP request never produced a usable response (DNS, TLS, connect,
    /// timeout, body read). These are retried by the client's backoff loop.
    Transport(String),
    /// A 2xx response body could not be decoded as the expected envelope /
    /// result type.
    Decode(String),
    /// The credential is valid but lacks a required permission group.
    /// `preflight()` populates `required` with [`crate::scopes`] so the
    /// operator sees exactly which token permission groups to grant.
    MissingScope {
        errors: Vec<CloudflareApiError>,
        required: Vec<&'static str>,
    },
    /// The credential is unknown, expired, or malformed.
    Unauthorized { errors: Vec<CloudflareApiError> },
    /// Cloudflare's global API rate limit (~1,200 requests / 5 min / user)
    /// was hit and the client exhausted its retry budget. `retry_after`
    /// echoes the server's `Retry-After` header when present.
    RateLimited {
        retry_after: Option<Duration>,
        attempts: u32,
    },
    /// A non-2xx / `success:false` response that is not an auth/scope/rate
    /// case — carries the raw HTTP status and the decoded error array.
    Api {
        status: u16,
        errors: Vec<CloudflareApiError>,
    },
    /// The retry budget was exhausted on a retryable transport/5xx failure.
    ExhaustedRetries {
        attempts: u32,
        last: Box<CloudflareError>,
    },
}

impl CloudflareError {
    /// Map a fully-received (non-retryable at the HTTP layer) response into a
    /// typed error. `status` is the HTTP status; `errors` is the decoded
    /// envelope error array (may be empty for a bare non-2xx body).
    ///
    /// Precedence: rate-limit (429) → missing-scope codes → auth codes →
    /// generic API error.
    ///
    /// Rate-limit detection is `status == 429` alone (issue #493). An earlier
    /// version additionally treated any envelope carrying `errors[].code ==
    /// 10013` as a rate limit regardless of namespace. That numeral is not a
    /// rate-limit code in *any* Cloudflare product: in R2 it is
    /// `IncompleteBody` (HTTP 400 — "request body terminated before expected
    /// Content-Length", a client-side truncation that can never succeed by
    /// retrying), and in the general `client/v4` namespace it surfaces as
    /// `workers.api.error.unknown` (HTTP 500), also unrelated to rate
    /// limiting. Because R2 now routes through this mapper (`r2.rs`), the
    /// collision was live.
    ///
    /// What the collision actually broke was the **operator-facing
    /// classification**, not the retry behaviour. `from_response` runs
    /// *after* the backoff loop has already returned
    /// (`client.rs` `execute_with_retry` → `into_result` →
    /// `envelope.rs`), and that loop retries on HTTP status
    /// (`is_retryable_status` = `429|500|502|503|504`) plus transport
    /// failures — the latter gated by [`CloudflareError::is_retryable`],
    /// which on that arm only ever sees `Transport(_)`, since the
    /// `HttpTransport` contract restricts what `execute` may return. Mapped
    /// errors from `from_response` never re-enter the loop at all, because
    /// `from_response` runs after it has returned. So a
    /// `400 + code 10013` response was issued exactly once, before and after
    /// this change. The defect was that a truncated upload body was reported
    /// to the operator as `RateLimited` ("cloudflare rate limit hit") instead
    /// of a client-side `Api { status: 400 }`, and that any consumer matching
    /// on the variant — e.g. the guardrails adapter's
    /// `RateLimited → Overloaded` mapping — would decide from a false premise.
    ///
    /// R2's real rate-limit code, `10058` / `TooManyRequests`, always arrives
    /// with HTTP 429 per
    /// <https://developers.cloudflare.com/r2/api/error-codes/>, so
    /// `status == 429` alone already classifies it correctly — no
    /// additional numeric-code branch is added, since a bare `code == 10058`
    /// match would reintroduce the same collision class: in Cloudflare's
    /// Lists/Bulk-Redirect `10xxx` namespace, `10058` means "list items
    /// incompatible with list type" (HTTP 400), not a rate limit.
    pub(crate) fn from_response(
        status: u16,
        retry_after: Option<Duration>,
        errors: Vec<CloudflareApiError>,
    ) -> Self {
        if status == 429 {
            return CloudflareError::RateLimited {
                retry_after,
                attempts: 0,
            };
        }
        if errors.iter().any(|e| MISSING_SCOPE_CODES.contains(&e.code)) {
            return CloudflareError::MissingScope {
                errors,
                required: crate::scopes::required_group_names(),
            };
        }
        if status == 401
            || status == 403
            || errors
                .iter()
                .any(|e| AUTHENTICATION_CODES.contains(&e.code))
        {
            return CloudflareError::Unauthorized { errors };
        }
        CloudflareError::Api { status, errors }
    }

    /// Whether the client's backoff loop should retry this error.
    pub(crate) fn is_retryable(&self) -> bool {
        matches!(
            self,
            CloudflareError::Transport(_) | CloudflareError::RateLimited { .. }
        )
    }
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudflareError::Config(m) => write!(f, "cloudflare config error: {m}"),
            CloudflareError::TokenResolution(m) => {
                write!(f, "cloudflare token resolution error: {m}")
            }
            CloudflareError::Transport(m) => write!(f, "cloudflare transport error: {m}"),
            CloudflareError::Decode(m) => write!(f, "cloudflare response decode error: {m}"),
            CloudflareError::MissingScope { errors, required } => write!(
                f,
                "cloudflare token is missing a required permission group ({}); grant the token these permission groups: {}",
                join_errors(errors),
                required.join(", ")
            ),
            CloudflareError::Unauthorized { errors } => {
                write!(f, "cloudflare authentication failed ({})", join_errors(errors))
            }
            CloudflareError::RateLimited {
                retry_after,
                attempts,
            } => write!(
                f,
                "cloudflare rate limit hit after {attempts} attempt(s){}",
                match retry_after {
                    Some(d) => format!(" (retry-after {}s)", d.as_secs()),
                    None => String::new(),
                }
            ),
            CloudflareError::Api { status, errors } => {
                write!(f, "cloudflare API error (HTTP {status}): {}", join_errors(errors))
            }
            CloudflareError::ExhaustedRetries { attempts, last } => {
                write!(f, "cloudflare request failed after {attempts} attempt(s): {last}")
            }
        }
    }
}

impl std::error::Error for CloudflareError {}

fn join_errors(errors: &[CloudflareApiError]) -> String {
    if errors.is_empty() {
        return "no error detail".to_string();
    }
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}
