// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: Recorded request/response fixture transport for deterministic adapter tests (#201).

//! [`FixtureTransport`] replays RECORDED request/response JSON exchanges for
//! the native adapters, so conformance and evaluation runs are deterministic
//! and never touch the network. The recorded wire shapes live in
//! `tests/fixtures/*.json` and mirror real Presidio / LLM-Guard payloads;
//! matching is by exact JSON equality of the request body, so any drift
//! between the adapter's serializer and the recorded contract fails loudly.
//!
//! Compiled only under `cfg(test)` or the opt-in `conformance` feature.

use super::{DetectorTransport, TransportReply};
use crate::conformance::PROBE_SECRET;
use crate::{DetectorError, DetectorErrorKind};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

/// Recorded Presidio analyzer exchanges (see `tests/fixtures/`).
pub const PRESIDIO_FIXTURES: &str = include_str!("../../tests/fixtures/presidio_exchanges.json");
/// Recorded LLM-Guard API exchanges (see `tests/fixtures/`).
pub const LLM_GUARD_FIXTURES: &str = include_str!("../../tests/fixtures/llm_guard_exchanges.json");

#[derive(Debug, Clone, Deserialize)]
struct RecordedFile {
    #[allow(dead_code)]
    #[serde(default)]
    adapter: Option<String>,
    exchanges: Vec<RecordedExchange>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedExchange {
    /// Human-readable label for triage; unused at runtime.
    #[allow(dead_code)]
    #[serde(default)]
    name: Option<String>,
    /// Free-form provenance note; unused at runtime.
    #[allow(dead_code)]
    #[serde(default)]
    note: Option<String>,
    request: Value,
    #[serde(default)]
    response: Option<RecordedReply>,
    /// `"hang"` makes the transport never reply, so the adapter's own
    /// deadline enforcement is genuinely exercised.
    #[serde(default)]
    outcome: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RecordedReply {
    status: u16,
    #[serde(default)]
    body: Option<Value>,
    /// Raw (possibly non-JSON) body for malformed-response cases.
    #[serde(default)]
    body_raw: Option<String>,
}

/// A [`DetectorTransport`] that answers each request with the recorded reply
/// whose request JSON matches exactly. An unmatched request is a loud
/// `Internal` error so a drifted wire format can never silently pass.
#[derive(Debug)]
pub struct FixtureTransport {
    exchanges: Vec<RecordedExchange>,
}

impl FixtureTransport {
    /// Load recorded exchanges from fixture JSON. `${PROBE_SECRET}` in the
    /// fixture text is substituted with the runtime synthetic probe secret
    /// (the fixture files never carry a contiguous secret-shaped token).
    pub fn from_recorded(fixture_json: &str) -> Self {
        let substituted = fixture_json.replace("${PROBE_SECRET}", PROBE_SECRET);
        let file: RecordedFile =
            serde_json::from_str(&substituted).expect("recorded fixture file is valid JSON");
        Self {
            exchanges: file.exchanges,
        }
    }

    /// The recorded Presidio analyzer exchange set.
    pub fn presidio_recorded() -> Self {
        Self::from_recorded(PRESIDIO_FIXTURES)
    }

    /// The recorded LLM-Guard API exchange set.
    pub fn llm_guard_recorded() -> Self {
        Self::from_recorded(LLM_GUARD_FIXTURES)
    }
}

#[async_trait]
impl DetectorTransport for FixtureTransport {
    async fn post_json(&self, body: &[u8]) -> Result<TransportReply, DetectorError> {
        let request: Value = serde_json::from_slice(body).map_err(|_| {
            DetectorError::new(
                DetectorErrorKind::Internal,
                "fixture transport received a non-JSON request body",
            )
        })?;
        let Some(exchange) = self
            .exchanges
            .iter()
            .find(|exchange| exchange.request == request)
        else {
            return Err(DetectorError::new(
                DetectorErrorKind::Internal,
                "no recorded fixture exchange matches the adapter request (wire drift?)",
            ));
        };
        if exchange.outcome.as_deref() == Some("hang") {
            // Never resolves: the adapter's deadline wrap must fire.
            std::future::pending::<()>().await;
            unreachable!("pending future resolved");
        }
        let Some(reply) = &exchange.response else {
            return Err(DetectorError::new(
                DetectorErrorKind::Internal,
                "recorded fixture exchange has neither response nor outcome",
            ));
        };
        let body = match (&reply.body, &reply.body_raw) {
            (Some(value), _) => serde_json::to_vec(value).map_err(|_| {
                DetectorError::new(
                    DetectorErrorKind::Internal,
                    "recorded fixture body failed to serialize",
                )
            })?,
            (None, Some(raw)) => raw.clone().into_bytes(),
            (None, None) => Vec::new(),
        };
        Ok(TransportReply {
            status: reply.status,
            body,
        })
    }
}
