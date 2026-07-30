// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-30
// description: Focused tests for the agent-worker egress wire-stage E2E gate (#353).

//! These prove the scenario's ASSERTIONS bite. A gate whose checks silently
//! accept a damaged input is worse than no gate, so every check below is fed the
//! failure it exists to catch.

use super::*;

fn healthy_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(),
            RequestWireStage::SENT_OR_UNKNOWN_TOKEN.to_string(),
        ),
        (
            EGRESS_HOLD_DISPOSITION_KEY.to_string(),
            HoldDisposition::RETAIN_OUTCOME_UNKNOWN_TOKEN.to_string(),
        ),
        (
            "response_excerpt".to_string(),
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nferrogate governed rest smoke\n"
                .to_string(),
        ),
    ])
}

#[test]
fn a_healthy_dispatch_passes_every_check() {
    let metadata = healthy_metadata();
    verify_typed_discriminant(&metadata).unwrap();
    verify_consumer_side_is_fail_safe(&metadata).unwrap();
    verify_no_bearer_material(&metadata).unwrap();
}

#[test]
fn a_dropped_write_event_metadata_call_is_caught() {
    let mut metadata = healthy_metadata();
    metadata.remove(EGRESS_REQUEST_WIRE_STAGE_KEY);

    let error = verify_typed_discriminant(&metadata)
        .unwrap_err()
        .to_string();
    assert!(error.contains(EGRESS_REQUEST_WIRE_STAGE_KEY), "{error}");
}

/// The check that no in-crate test can make: the binary emitting a stage token
/// and a disposition token that disagree. `write_event_metadata` derives one
/// from the other, so disagreement can only appear if some future emit path
/// stops going through it — which is exactly the regression worth catching.
#[test]
fn a_disposition_that_disagrees_with_its_stage_is_caught() {
    let mut metadata = healthy_metadata();
    metadata.insert(
        EGRESS_HOLD_DISPOSITION_KEY.to_string(),
        HoldDisposition::RELEASABLE_BEFORE_SUBMISSION_TOKEN.to_string(),
    );

    let error = verify_typed_discriminant(&metadata)
        .unwrap_err()
        .to_string();
    assert!(error.contains("disagrees"), "{error}");
}

/// A completed dispatch really reached the upstream. Reporting the release edge
/// for it would let the gateway cancel a hold for a request the merchant already
/// answered, so it must fail even though the two tokens agree with each other.
#[test]
fn a_completed_dispatch_claiming_the_release_edge_is_caught() {
    let mut metadata = healthy_metadata();
    metadata.insert(
        EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(),
        RequestWireStage::PROVEN_NOT_SENT_TOKEN.to_string(),
    );
    metadata.insert(
        EGRESS_HOLD_DISPOSITION_KEY.to_string(),
        HoldDisposition::RELEASABLE_BEFORE_SUBMISSION_TOKEN.to_string(),
    );

    let error = verify_typed_discriminant(&metadata)
        .unwrap_err()
        .to_string();
    assert!(error.contains("must carry the retain edge"), "{error}");
}

#[test]
fn a_token_outside_the_frozen_vocabulary_is_caught() {
    let mut metadata = healthy_metadata();
    metadata.insert(
        EGRESS_REQUEST_WIRE_STAGE_KEY.to_string(),
        "sent".to_string(),
    );

    let error = verify_typed_discriminant(&metadata)
        .unwrap_err()
        .to_string();
    assert!(error.contains("outside the frozen vocabulary"), "{error}");
}

#[test]
fn leaked_credential_material_in_recorded_evidence_is_caught() {
    for leak in [
        "authorization: Bearer super-secret-token",
        "PAYMENT-SIGNATURE: PROOFDONOTLOG",
        "set-cookie: session=abc123",
    ] {
        let mut metadata = healthy_metadata();
        metadata.insert(
            "response_excerpt".to_string(),
            format!("HTTP/1.1 200 OK\r\n{leak}\r\n\r\nbody\n"),
        );

        let error = verify_no_bearer_material(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("credential marker"), "{leak}: {error}");
    }
}

#[test]
fn a_metadata_value_that_is_not_a_string_is_rejected() {
    let event = serde_json::json!({ "metadata": { "status_code": 200 } });

    let error = string_metadata(&event).unwrap_err().to_string();
    assert!(error.contains("not a string"), "{error}");
}

#[test]
fn a_missing_dispatch_event_is_named_rather_than_skipped() {
    let events = vec![serde_json::json!({ "kind": "capability.allowed" })];

    let error = find_event(&events, "rest.requested")
        .unwrap_err()
        .to_string();
    assert!(error.contains("rest.requested"), "{error}");
}

#[test]
fn a_missing_binary_is_an_actionable_error() {
    let error = ensure_binary(Path::new("target/debug/definitely-not-built"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("cargo build -p agent-worker"), "{error}");
}
