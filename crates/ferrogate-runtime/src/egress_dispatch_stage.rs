// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! How far an outbound egress request got on the wire, as a TYPED discriminant
//! that survives the worker → gateway process boundary (issue #353).
//!
//! # Why this lives here and not in `agent-worker`
//!
//! Only the worker can observe how far a dispatch got. Only the gateway owns the
//! durable payment attempt (`X402SettlementLoop`, `ferrogate-cli`), and the two
//! run in different processes. Before this module the observation existed solely
//! as an English suffix on an error message — `"(no request byte reached the
//! upstream)"` versus `"(the request may have reached the upstream)"` — so a
//! consumer wanting the RELEASE edge would have had to substring-match a
//! sentence to make a money decision, and any reword would silently flip every
//! hold to the wrong edge.
//!
//! `ferrogate-runtime` is the crate both sides already depend on, so putting the
//! vocabulary here is what makes it *consumable*: the gateway can now name the
//! type. The prose stays where it is, as human diagnostics, and stops being
//! load-bearing.
//!
//! # The fail-safe direction, and where it is enforced
//!
//! The two misclassifications are not symmetric:
//!
//! * Calling a SENT request "not sent" releases a wallet hold for a payment that
//!   may already have settled on-chain — FerroGate hands over stablecoin and
//!   charges nobody. Unrecoverable.
//! * Calling an UNSENT request "sent" merely parks a hold that the TTL sweeper
//!   (`state_x402_sweeper.rs`) reclaims on its next tick. Recoverable.
//!
//! So every path that can produce a [`RequestWireStage`] without proof must land
//! on [`RequestWireStage::SentOrUnknown`]. That is enforced in three places, all
//! of them defaults rather than conventions:
//!
//! 1. [`Default`] — the value an unclassified construction gets.
//! 2. [`RequestWireStage::from_wire_token`] — an absent, empty, differently-cased
//!    or unrecognised token reads as retain, never as release. A future
//!    producer that emits a token this build has never heard of therefore
//!    degrades to retain.
//! 3. [`Deserialize`] — implemented on top of `from_wire_token` rather than
//!    derived, so an unknown wire token deserializes to retain instead of
//!    erroring *or*, worse, being pattern-matched loosely by a caller.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Event-metadata key carrying the [`RequestWireStage`] wire token.
///
/// This is the key a #381 consumer reads off a worker event's `metadata` map.
pub const EGRESS_REQUEST_WIRE_STAGE_KEY: &str = "egress_request_wire_stage";

/// Event-metadata key carrying the [`HoldDisposition`] wire token.
///
/// Always derived from [`EGRESS_REQUEST_WIRE_STAGE_KEY`] at write time by
/// [`RequestWireStage::write_event_metadata`], so the two keys cannot disagree.
/// It exists for human/audit readability; the authoritative discriminant a
/// consumer branches on is the wire stage.
pub const EGRESS_HOLD_DISPOSITION_KEY: &str = "egress_hold_disposition";

/// How far an outgoing egress request got before the dispatch failed.
///
/// Only the worker can observe this, and it is the single fact the gateway's
/// durable attempt API needs in order to choose between releasing a hold and
/// retaining it. The variants are named for what can be **proven**, not for what
/// is likely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestWireStage {
    /// PROVEN that no request byte can have reached the peer: the failure
    /// happened during validation, address resolution, connection setup, or
    /// socket option setup — strictly before the first write was attempted.
    ProvenNotSent,
    /// Everything else, including every genuinely ambiguous case: a partial
    /// write, a connection reset mid-request, a read timeout after the request
    /// was fully written, or any failure the producer has not explicitly proven
    /// to be pre-send.
    SentOrUnknown,
}

/// The fail-safe default is [`RequestWireStage::SentOrUnknown`].
///
/// The two misclassifications are not symmetric. Calling a sent request
/// "not sent" releases a wallet hold for a payment that may already have
/// settled on-chain — FerroGate would have handed over stablecoin and charged
/// nobody. Calling an unsent request "sent" merely parks a hold that the TTL
/// sweeper (`state_x402_sweeper.rs`) reclaims on its next tick. So anything not
/// proven pre-send must land here.
impl Default for RequestWireStage {
    fn default() -> Self {
        Self::SentOrUnknown
    }
}

/// What the gateway's durable attempt API may do with the wallet hold, in that
/// API's own vocabulary (`state_x402_settlement.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoldDisposition {
    /// Safe to take the loop's RELEASE edge (`X402SettlementLoop::cancel`),
    /// which is valid only on a pre-submission attempt.
    ReleasableBeforeSubmission,
    /// The proof may be on the wire. The attempt must be parked
    /// `outcome_unknown` with the hold RETAINED, for the reconciler to resolve.
    RetainOutcomeUnknown,
}

/// Same asymmetry as [`RequestWireStage::default`]: an unspecified disposition
/// retains.
impl Default for HoldDisposition {
    fn default() -> Self {
        Self::RetainOutcomeUnknown
    }
}

impl RequestWireStage {
    /// Frozen wire token for [`Self::ProvenNotSent`]. This exact string is the
    /// ONLY input that can yield a release; see [`Self::from_wire_token`].
    pub const PROVEN_NOT_SENT_TOKEN: &'static str = "proven_not_sent";
    /// Frozen wire token for [`Self::SentOrUnknown`].
    pub const SENT_OR_UNKNOWN_TOKEN: &'static str = "sent_or_unknown";

    /// The stable token this stage is transmitted as.
    pub fn as_wire_token(self) -> &'static str {
        match self {
            Self::ProvenNotSent => Self::PROVEN_NOT_SENT_TOKEN,
            Self::SentOrUnknown => Self::SENT_OR_UNKNOWN_TOKEN,
        }
    }

    /// Read a stage back from its wire token, failing safe.
    ///
    /// Deliberately an exact match against [`Self::PROVEN_NOT_SENT_TOKEN`]: a
    /// missing token, an empty token, a differently-cased token, a whitespace-
    /// padded token, or a token from some future producer this build does not
    /// know all read as [`Self::SentOrUnknown`] — retain the hold. There is no
    /// lenient parsing on the release edge, because leniency there is how a
    /// typo or a version skew spends money for free.
    pub fn from_wire_token(token: Option<&str>) -> Self {
        match token {
            Some(Self::PROVEN_NOT_SENT_TOKEN) => Self::ProvenNotSent,
            _ => Self::SentOrUnknown,
        }
    }

    /// Map the observed wire stage onto the hold disposition.
    ///
    /// This function does NOT call the durable attempt API: that API lives
    /// behind the gateway's capability boundary. It converts an observation into
    /// the vocabulary the API is driven with; performing the call is the
    /// gateway-side transport binding's job (#381).
    pub fn hold_disposition(self) -> HoldDisposition {
        match self {
            Self::ProvenNotSent => HoldDisposition::ReleasableBeforeSubmission,
            Self::SentOrUnknown => HoldDisposition::RetainOutcomeUnknown,
        }
    }

    /// Write this stage — and the disposition DERIVED from it — into a worker
    /// event's metadata map, which is the map that crosses the process boundary.
    ///
    /// The disposition is never accepted as an independent input, so the two
    /// keys cannot drift apart.
    pub fn write_event_metadata(self, metadata: &mut BTreeMap<String, String>) {
        metadata.insert(
            EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(),
            self.as_wire_token().to_string(),
        );
        metadata.insert(
            EGRESS_HOLD_DISPOSITION_KEY.to_string(),
            self.hold_disposition().as_wire_token().to_string(),
        );
    }

    /// Read the stage a worker recorded on an event, failing safe.
    ///
    /// This is the single read point for a consumer driving the durable attempt
    /// API. It reads the discriminant only; the event's `message` and any
    /// `failure_reason` prose are diagnostics and are never consulted.
    pub fn from_event_metadata(metadata: &BTreeMap<String, String>) -> Self {
        Self::from_wire_token(
            metadata
                .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
                .map(String::as_str),
        )
    }
}

impl HoldDisposition {
    /// Frozen wire token for [`Self::ReleasableBeforeSubmission`].
    pub const RELEASABLE_BEFORE_SUBMISSION_TOKEN: &'static str = "releasable_before_submission";
    /// Frozen wire token for [`Self::RetainOutcomeUnknown`].
    pub const RETAIN_OUTCOME_UNKNOWN_TOKEN: &'static str = "retain_outcome_unknown";

    /// The stable token this disposition is transmitted as.
    pub fn as_wire_token(self) -> &'static str {
        match self {
            Self::ReleasableBeforeSubmission => Self::RELEASABLE_BEFORE_SUBMISSION_TOKEN,
            Self::RetainOutcomeUnknown => Self::RETAIN_OUTCOME_UNKNOWN_TOKEN,
        }
    }

    /// Read a disposition back from its wire token, failing safe: anything that
    /// is not exactly [`Self::RELEASABLE_BEFORE_SUBMISSION_TOKEN`] retains.
    pub fn from_wire_token(token: Option<&str>) -> Self {
        match token {
            Some(Self::RELEASABLE_BEFORE_SUBMISSION_TOKEN) => Self::ReleasableBeforeSubmission,
            _ => Self::RetainOutcomeUnknown,
        }
    }
}

impl fmt::Display for RequestWireStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_wire_token())
    }
}

impl fmt::Display for HoldDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_wire_token())
    }
}

impl Serialize for RequestWireStage {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire_token())
    }
}

/// Deserialization goes through [`RequestWireStage::from_wire_token`] rather
/// than a derived enum representation, so an unknown or null token becomes
/// `SentOrUnknown` (retain) instead of an error a caller might `unwrap_or`
/// into the wrong edge. Combined with `#[serde(default)]` on a containing
/// struct field, an ABSENT field retains too.
impl<'de> Deserialize<'de> for RequestWireStage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = Option::<String>::deserialize(deserializer)?;
        Ok(Self::from_wire_token(token.as_deref()))
    }
}

impl Serialize for HoldDisposition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire_token())
    }
}

/// Same fail-safe deserialization as [`RequestWireStage`].
impl<'de> Deserialize<'de> for HoldDisposition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = Option::<String>::deserialize(deserializer)?;
        Ok(Self::from_wire_token(token.as_deref()))
    }
}

#[cfg(test)]
#[path = "egress_dispatch_stage_test.rs"]
mod egress_dispatch_stage_test;
