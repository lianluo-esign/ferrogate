// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Cloudflare JSON response envelope decoding.

//! The Cloudflare REST response envelope (issue #405).
//!
//! Every `client/v4` endpoint wraps its payload in
//! `{ success, errors[], messages[], result }`. [`CloudflareEnvelope`] decodes
//! that shape generically; [`CloudflareEnvelope::into_result`] collapses it to
//! either the typed `result` or a [`CloudflareError`].

use serde::Deserialize;

use crate::error::{CloudflareApiError, CloudflareError};

/// A decoded Cloudflare response envelope.
///
/// `result` is optional because error envelopes (and 204-style success
/// envelopes) omit it. Unknown fields (`result_info`, etc.) are ignored so a
/// caller only pays for the `result` shape it asks for.
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareEnvelope<T> {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errors: Vec<CloudflareApiError>,
    #[serde(default)]
    pub messages: Vec<CloudflareMessage>,
    #[serde(default = "none")]
    pub result: Option<T>,
}

/// A single `{ code, message }` entry from the envelope's `messages[]` array
/// (Cloudflare's non-fatal advisories). Decoded but not acted upon here.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CloudflareMessage {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

fn none<T>() -> Option<T> {
    None
}

impl<T> CloudflareEnvelope<T> {
    /// Collapse the envelope into the typed result or a [`CloudflareError`].
    ///
    /// `status` and `retry_after` come from the HTTP layer so error mapping
    /// can distinguish 429 rate-limits and 401/403 auth failures even when the
    /// body carries no structured code. A `success: true` envelope with a
    /// missing `result` is a decode error (the caller expected a body).
    pub fn into_result(
        self,
        status: u16,
        retry_after: Option<std::time::Duration>,
    ) -> Result<T, CloudflareError> {
        if self.success && (200..300).contains(&status) {
            return self.result.ok_or_else(|| {
                CloudflareError::Decode("expected a `result` body but it was absent".to_string())
            });
        }
        Err(CloudflareError::from_response(
            status,
            retry_after,
            self.errors,
        ))
    }

    /// Like [`into_result`](Self::into_result) but for endpoints whose success
    /// carries no meaningful `result` (verify/ping style). Returns `()` on a
    /// `success: true` envelope, a typed error otherwise.
    pub fn into_ack(
        self,
        status: u16,
        retry_after: Option<std::time::Duration>,
    ) -> Result<(), CloudflareError> {
        if self.success && (200..300).contains(&status) {
            return Ok(());
        }
        Err(CloudflareError::from_response(
            status,
            retry_after,
            self.errors,
        ))
    }
}
