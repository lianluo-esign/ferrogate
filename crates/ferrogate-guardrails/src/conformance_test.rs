// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Conformance-harness tests for the mock adapter and the real deterministic detector.

use super::conformance::{
    assert_detector_conforms, conformance_probe_result, run_detector_conformance, MockAdapter,
    MockResponse, PROBE_SECRET,
};
use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn mock_input() -> DetectorInput<'static> {
    DetectorInput {
        protocol: GuardrailProtocol::ChatCompletions,
        stage: DetectorStage::Request,
        tenant: DetectorTenant {
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            api_key_id: None,
        },
        model: None,
        provider: None,
        text: "hello",
        segments: &[],
    }
}

/// A deterministic, in-repo detector wired so the harness probe (an AWS-style
/// key in user text) fails with a sanitized, redactable finding while benign
/// text passes. This proves a third adapter honours the contract without any
/// core policy semantics being touched.
fn deterministic_conformance_detector() -> DeterministicDetector {
    DeterministicDetector::new(DeterministicDetectorConfig {
        id: "conformance-local".to_string(),
        supported_sources: all_content_sources(),
        keywords: Vec::new(),
        regex: Vec::new(),
        max_input_bytes: None,
        json: None,
        request: None,
        secret_patterns: vec![SecretPattern::AwsAccessKeyId],
        fingerprint_key: Some(DetectorSecret::new(
            "conformance-fingerprint-key".to_string(),
        )),
    })
    .unwrap()
}

fn declared_modes() -> Vec<DetectorErrorKind> {
    vec![
        DetectorErrorKind::Timeout,
        DetectorErrorKind::Unavailable,
        DetectorErrorKind::Internal,
    ]
}

fn descriptor_with_modes(modes: Vec<DetectorErrorKind>) -> DetectorDescriptor {
    DetectorDescriptor {
        id: "mock-adapter".to_string(),
        version: "mock/1".to_string(),
        supports_request: true,
        supports_response: true,
        supports_transform: true,
        supported_sources: all_content_sources(),
        credential: DetectorCredentialType::None,
        data_residency: DataResidency::InRepo,
        max_payload_bytes: usize::MAX,
        declared_failure_modes: modes,
    }
}

#[test]
fn mock_adapter_exercises_every_conformance_behaviour() {
    let mock = MockAdapter::conforming();
    let report = runtime().block_on(run_detector_conformance(&mock));
    assert!(
        report.conforms(),
        "mock should conform: {:?}",
        report.failures
    );
    assert!(report.pass_verdict);
    assert!(report.sanitized_fail);
    assert!(report.transform_validated);
    assert!(report.error_classified);
    assert!(report.timeout_enforced);
    assert!(report.version_reported);
    assert!(report.all_behaviours_exercised());
}

#[test]
fn deterministic_detector_passes_the_contract_end_to_end() {
    let detector = deterministic_conformance_detector();
    // assert_detector_conforms panics unless all six behaviours hold.
    let report = runtime().block_on(assert_detector_conforms(&detector));
    assert!(report.all_behaviours_exercised());

    // The declared modes must be a superset of what it emits: the only runtime
    // error is the timeout, which is declared.
    let descriptor = detector.descriptor();
    assert_eq!(descriptor.data_residency, DataResidency::InRepo);
    assert_eq!(descriptor.credential, DetectorCredentialType::None);
    assert!(descriptor
        .declared_failure_modes
        .contains(&DetectorErrorKind::Timeout));
}

#[test]
fn deterministic_probe_fail_keeps_raw_value_out_of_evidence() {
    let detector = deterministic_conformance_detector();
    let envelope = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        format!("leaked credential {PROBE_SECRET} in transit"),
    );
    let input = DetectorInput {
        protocol: envelope.protocol,
        stage: envelope.stage,
        tenant: DetectorTenant {
            organization_id: None,
            team_id: None,
            project_id: None,
            user_id: None,
            api_key_id: None,
        },
        model: None,
        provider: None,
        text: envelope.segments[0].text.as_str(),
        segments: &envelope.segments,
    };
    let result = runtime()
        .block_on(detector.evaluate(&input, Instant::now() + Duration::from_secs(1)))
        .unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Fail);
    // Sanitized: a fingerprint is present, no raw text is retained, and the
    // serialized evidence never contains the secret.
    assert!(result.findings.iter().any(|f| f.fingerprint.is_some()));
    assert!(result.findings.iter().all(|f| f.matched_text.is_none()));
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains(PROBE_SECRET));
    // The emitted redaction patch validates against the evaluated segment.
    assert!(!result.patches.is_empty());
    validate_content_patches_for_segments(&envelope.segments, &result.patches).unwrap();
}

#[test]
fn mock_scripts_a_non_timeout_error_classified_as_declared() {
    let mock = MockAdapter::new(descriptor_with_modes(declared_modes()))
        .script([MockResponse::error(DetectorErrorKind::Unavailable)]);
    let error = runtime()
        .block_on(mock.evaluate(&mock_input(), Instant::now() + Duration::from_secs(1)))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::Unavailable);
    assert!(mock
        .descriptor()
        .declared_failure_modes
        .contains(&error.kind));
}

#[test]
fn harness_flags_a_runtime_error_that_is_not_a_declared_mode() {
    // A descriptor that omits Timeout: the expired-deadline drive still returns
    // Timeout, which the harness must flag as undeclared.
    let mock = MockAdapter::new(descriptor_with_modes(vec![DetectorErrorKind::Unavailable]))
        .script([
            MockResponse::pass("mock/1"),
            MockResponse::result(conformance_probe_result("mock/1")),
        ]);
    let report = runtime().block_on(run_detector_conformance(&mock));
    assert!(!report.conforms());
    assert!(!report.error_classified);
    assert!(report
        .failures
        .iter()
        .any(|failure| failure.contains("not a declared failure mode")));
    // The other five behaviours still held, proving the failure is isolated.
    assert!(report.pass_verdict);
    assert!(report.sanitized_fail);
    assert!(report.transform_validated);
    assert!(report.timeout_enforced);
    assert!(report.version_reported);
}

#[test]
fn mock_delay_past_deadline_reports_timeout() {
    let mock = MockAdapter::new(descriptor_with_modes(declared_modes()))
        .script([MockResponse::pass("mock/1").after(Duration::from_millis(80))]);
    let error = runtime()
        .block_on(mock.evaluate(&mock_input(), Instant::now() + Duration::from_millis(15)))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::Timeout);
}

#[test]
fn mock_drains_script_then_falls_back_to_default() {
    let mock = MockAdapter::new(descriptor_with_modes(declared_modes()))
        .with_default(MockResponse::error(DetectorErrorKind::Unavailable))
        .script([MockResponse::pass("mock/1")]);
    let runtime = runtime();
    let deadline = Instant::now() + Duration::from_secs(1);
    let first = runtime
        .block_on(mock.evaluate(&mock_input(), deadline))
        .unwrap();
    assert_eq!(first.verdict, DetectorVerdict::Pass);
    // Script drained: the default (a scripted Unavailable) now applies.
    let second = runtime
        .block_on(mock.evaluate(&mock_input(), deadline))
        .unwrap_err();
    assert_eq!(second.kind, DetectorErrorKind::Unavailable);
}
