// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Cloudflare JSON response envelope decoding.

//! The Cloudflare REST response envelope (issue #405).
//!
//! Every `client/v4` endpoint wraps its payload in
//! `{ success, errors[], messages[], result }`, and paginated endpoints add a
//! `result_info`. [`CloudflareEnvelope`] decodes that shape generically;
//! [`CloudflareEnvelope::into_result`] collapses it to either the typed
//! `result` or a [`CloudflareError`], and
//! [`CloudflareEnvelope::into_result_with_info`] keeps the pagination cursor
//! alongside it (issue #490).

use serde::Deserialize;

use crate::error::{CloudflareApiError, CloudflareError};

/// A decoded Cloudflare response envelope.
///
/// `result` is optional because error envelopes (and 204-style success
/// envelopes) omit it. `result_info` is present only on paginated endpoints;
/// any other unknown field is ignored so a caller only pays for the `result`
/// shape it asks for.
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
    /// Pagination metadata, present only on list endpoints.
    #[serde(default)]
    pub result_info: Option<CloudflareResultInfo>,
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

/// The `result_info` object on a paginated `client/v4` response (issue #490).
///
/// Cloudflare uses two pagination dialects and this covers both: page-numbered
/// endpoints (D1's database list) report `page`/`per_page`/`count`/
/// `total_count`, while cursor endpoints (R2's bucket list) report an opaque
/// `cursor` that must be echoed back to fetch the next page. Every field is
/// optional because no endpoint sends all of them.
///
/// Dropping this object is why a list call could silently answer with only its
/// first page — the caller had no way to learn more existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CloudflareResultInfo {
    /// Continuation token for the next page; absent or empty on the last page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Maximum number of rows this page could carry.
    #[serde(default)]
    pub per_page: Option<u64>,
    /// Rows actually returned on this page.
    #[serde(default)]
    pub count: Option<u64>,
    /// 1-based page number (page-numbered endpoints only).
    #[serde(default)]
    pub page: Option<u64>,
    /// Total rows across all pages (page-numbered endpoints only).
    #[serde(default)]
    pub total_count: Option<u64>,
}

impl CloudflareResultInfo {
    /// The continuation cursor, normalised: `None` when absent *or* empty.
    /// Cloudflare signals "last page" both ways, and treating `""` as a real
    /// cursor would loop forever.
    pub fn next_cursor(&self) -> Option<&str> {
        self.cursor.as_deref().filter(|cursor| !cursor.is_empty())
    }
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

    /// Like [`into_result`](Self::into_result) but also hands back the
    /// `result_info` pagination metadata, so a list caller can follow the
    /// cursor instead of silently returning page 1 (issue #490).
    pub fn into_result_with_info(
        self,
        status: u16,
        retry_after: Option<std::time::Duration>,
    ) -> Result<(T, Option<CloudflareResultInfo>), CloudflareError> {
        let result_info = self.result_info.clone();
        self.into_result(status, retry_after)
            .map(|result| (result, result_info))
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
