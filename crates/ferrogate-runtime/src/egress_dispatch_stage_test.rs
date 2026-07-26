// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! The wire-stage carrier's money-safety contract (#353).
//!
//! Everything asserted here is about ONE direction being unreachable by
//! accident: a release. A hold may only be released when a producer explicitly
//! wrote the frozen `proven_not_sent` token. Absence, nulls, unknown tokens,
//! case differences, whitespace and version skew must all read as retain.

use super::*;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Tokens and round-tripping
// ---------------------------------------------------------------------------

/// The wire tokens are frozen: they are what a cross-process consumer matches
/// on, so renaming one is a breaking protocol change and must break a test.
#[test]
fn the_wire_tokens_are_frozen_and_round_trip() {
    assert_eq!(
        RequestWireStage::ProvenNotSent.as_wire_token(),
        "proven_not_sent"
    );
    assert_eq!(
        RequestWireStage::SentOrUnknown.as_wire_token(),
        "sent_or_unknown"
    );
    assert_eq!(
        HoldDisposition::ReleasableBeforeSubmission.as_wire_token(),
        "releasable_before_submission"
    );
    assert_eq!(
        HoldDisposition::RetainOutcomeUnknown.as_wire_token(),
        "retain_outcome_unknown"
    );

    for stage in [
        RequestWireStage::ProvenNotSent,
        RequestWireStage::SentOrUnknown,
    ] {
        assert_eq!(
            RequestWireStage::from_wire_token(Some(stage.as_wire_token())),
            stage
        );
    }
    for disposition in [
        HoldDisposition::ReleasableBeforeSubmission,
        HoldDisposition::RetainOutcomeUnknown,
    ] {
        assert_eq!(
            HoldDisposition::from_wire_token(Some(disposition.as_wire_token())),
            disposition
        );
    }
}

/// The defaults are the retain edge on BOTH types. This is the structural half
/// of the fail-safe: a value nobody classified cannot release.
#[test]
fn the_defaults_are_the_retain_edge() {
    assert_eq!(RequestWireStage::default(), RequestWireStage::SentOrUnknown);
    assert_eq!(
        RequestWireStage::default().hold_disposition(),
        HoldDisposition::RetainOutcomeUnknown
    );
    assert_eq!(
        HoldDisposition::default(),
        HoldDisposition::RetainOutcomeUnknown
    );
}

// ---------------------------------------------------------------------------
// The release edge is reachable ONLY by the exact frozen token
// ---------------------------------------------------------------------------

/// Every near-miss on the release token retains. A consumer running against a
/// producer that is newer, older, sloppier or actively hostile still parks the
/// hold rather than freeing money.
#[test]
fn only_the_exact_release_token_can_release_a_hold() {
    let near_misses = [
        None,
        Some(""),
        Some(" "),
        Some("proven_not_sent "),
        Some(" proven_not_sent"),
        Some("PROVEN_NOT_SENT"),
        Some("ProvenNotSent"),
        Some("proven-not-sent"),
        Some("provennotsent"),
        Some("not_sent"),
        Some("sent_or_unknown"),
        Some("releasable_before_submission"),
        Some("some_future_stage_this_build_never_heard_of"),
        Some("null"),
        Some("true"),
    ];
    for token in near_misses {
        let stage = RequestWireStage::from_wire_token(token);
        assert_eq!(
            stage,
            RequestWireStage::SentOrUnknown,
            "token {token:?} must not be readable as a release"
        );
        assert_eq!(
            stage.hold_disposition(),
            HoldDisposition::RetainOutcomeUnknown,
            "token {token:?}"
        );
    }
    // ...and the one token that does release.
    assert_eq!(
        RequestWireStage::from_wire_token(Some("proven_not_sent")).hold_disposition(),
        HoldDisposition::ReleasableBeforeSubmission
    );
}

/// The disposition token has the same one-way leniency rule.
#[test]
fn only_the_exact_release_disposition_token_can_release_a_hold() {
    for token in [
        None,
        Some(""),
        Some("RELEASABLE_BEFORE_SUBMISSION"),
        Some("releasable"),
        Some("retain_outcome_unknown"),
        Some("proven_not_sent"),
    ] {
        assert_eq!(
            HoldDisposition::from_wire_token(token),
            HoldDisposition::RetainOutcomeUnknown,
            "token {token:?} must not be readable as a release"
        );
    }
}

// ---------------------------------------------------------------------------
// Deserialization is part of the fail-safe, not an afterthought
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct DispatchReport {
    #[serde(default)]
    wire_stage: RequestWireStage,
}

/// A JSON payload that omits the field, nulls it, or carries a token this build
/// does not recognise deserializes to RETAIN — it does not error, and it
/// certainly does not release.
#[test]
fn unknown_absent_and_null_tokens_deserialize_to_retain() {
    for payload in [
        r#"{}"#,
        r#"{"wire_stage": null}"#,
        r#"{"wire_stage": ""}"#,
        r#"{"wire_stage": "sent_or_unknown"}"#,
        r#"{"wire_stage": "PROVEN_NOT_SENT"}"#,
        r#"{"wire_stage": "a_stage_added_in_a_later_release"}"#,
    ] {
        let report: DispatchReport = serde_json::from_str(payload).expect("payload deserializes");
        assert_eq!(
            report.wire_stage,
            RequestWireStage::SentOrUnknown,
            "payload {payload} must deserialize to retain"
        );
    }

    let released: DispatchReport =
        serde_json::from_str(r#"{"wire_stage": "proven_not_sent"}"#).unwrap();
    assert_eq!(released.wire_stage, RequestWireStage::ProvenNotSent);
}

/// Serialize → deserialize is lossless for both variants, so the discriminant
/// really does survive a process boundary rather than merely being emittable.
#[test]
fn both_stages_survive_a_json_round_trip() {
    for stage in [
        RequestWireStage::ProvenNotSent,
        RequestWireStage::SentOrUnknown,
    ] {
        let encoded = serde_json::to_string(&stage).unwrap();
        assert_eq!(encoded, format!("\"{}\"", stage.as_wire_token()));
        let decoded: RequestWireStage = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, stage);
    }
    for disposition in [
        HoldDisposition::ReleasableBeforeSubmission,
        HoldDisposition::RetainOutcomeUnknown,
    ] {
        let encoded = serde_json::to_string(&disposition).unwrap();
        let decoded: HoldDisposition = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, disposition);
    }
}

// ---------------------------------------------------------------------------
// Event metadata: the map that actually crosses the boundary
// ---------------------------------------------------------------------------

/// The disposition key is DERIVED at write time, never accepted as an
/// independent input, so the two keys cannot disagree about a money decision.
#[test]
fn the_disposition_metadata_key_is_derived_from_the_stage() {
    for (stage, expected_stage_token, expected_disposition_token) in [
        (
            RequestWireStage::ProvenNotSent,
            "proven_not_sent",
            "releasable_before_submission",
        ),
        (
            RequestWireStage::SentOrUnknown,
            "sent_or_unknown",
            "retain_outcome_unknown",
        ),
    ] {
        let mut metadata = BTreeMap::new();
        stage.write_event_metadata(&mut metadata);

        assert_eq!(
            metadata
                .get(EGRESS_REQUEST_WIRE_STAGE_KEY)
                .map(String::as_str),
            Some(expected_stage_token)
        );
        assert_eq!(
            metadata
                .get(EGRESS_HOLD_DISPOSITION_KEY)
                .map(String::as_str),
            Some(expected_disposition_token)
        );
        assert_eq!(RequestWireStage::from_event_metadata(&metadata), stage);
    }
}

/// A metadata map from a producer that never wrote the key — an older worker,
/// or a family that has no dispatch stage — reads as retain.
#[test]
fn metadata_without_the_stage_key_reads_as_retain() {
    let mut metadata = BTreeMap::from([
        ("external_action".to_string(), "rest".to_string()),
        (
            "failure_reason".to_string(),
            // Deliberately the old prose. It must NOT be able to drive the edge.
            "managed REST action transport failed (no request byte reached the upstream)"
                .to_string(),
        ),
    ]);
    assert_eq!(
        RequestWireStage::from_event_metadata(&metadata),
        RequestWireStage::SentOrUnknown
    );

    // Only the typed key moves the edge.
    RequestWireStage::ProvenNotSent.write_event_metadata(&mut metadata);
    assert_eq!(
        RequestWireStage::from_event_metadata(&metadata),
        RequestWireStage::ProvenNotSent
    );
}
