// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Tests for the Guardrail detector evaluation corpus + accuracy/latency runner (#201).

use super::conformance::{MockAdapter, MockResponse};
use super::evaluation::{reference_corpus, run_detector_evaluation};
use super::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A deterministic secret detector that flags only AWS access key ids -- so on
/// the reference corpus it catches the leaked-secret case but misses the
/// prompt-injection case, giving a realistic recall < 1.
fn aws_secret_detector() -> DeterministicDetector {
    DeterministicDetector::new(DeterministicDetectorConfig {
        id: "evaluation-local".to_string(),
        supported_sources: all_content_sources(),
        keywords: Vec::new(),
        regex: Vec::new(),
        max_input_bytes: None,
        json: None,
        request: None,
        secret_patterns: vec![SecretPattern::AwsAccessKeyId],
        fingerprint_key: Some(DetectorSecret::new(
            "evaluation-fingerprint-key".to_string(),
        )),
    })
    .unwrap()
}

fn mock_descriptor() -> DetectorDescriptor {
    DetectorDescriptor {
        id: "mock-eval".to_string(),
        version: "mock/1".to_string(),
        supports_request: true,
        supports_response: true,
        supports_transform: false,
        supported_sources: all_content_sources(),
        credential: DetectorCredentialType::None,
        data_residency: DataResidency::InRepo,
        max_payload_bytes: usize::MAX,
        declared_failure_modes: vec![DetectorErrorKind::Unavailable],
    }
}

fn fail_result() -> DetectorResult {
    DetectorResult {
        verdict: DetectorVerdict::Fail,
        findings: Vec::new(),
        patches: Vec::new(),
        detector_version: "mock/1".to_string(),
    }
}

#[test]
fn secret_detector_scores_realistic_precision_and_recall_on_reference_corpus() {
    let corpus = reference_corpus();
    let detector = aws_secret_detector();
    let metrics = runtime().block_on(run_detector_evaluation(&detector, &corpus));

    assert_eq!(metrics.corpus_version, "reference/2");
    assert_eq!(metrics.total, 8);
    // Catches the secret (TP), misses every injection (FN), flags no benign.
    assert_eq!(metrics.true_positives, 1);
    assert_eq!(metrics.false_negatives, 3);
    assert_eq!(metrics.false_positives, 0);
    assert_eq!(metrics.true_negatives, 4);
    assert_eq!(metrics.errors, 0);
    assert!(
        (metrics.precision - 1.0).abs() < 1e-9,
        "{}",
        metrics.precision
    );
    assert!((metrics.recall - 0.25).abs() < 1e-9, "{}", metrics.recall);
    // F1 = 2*1*0.25/(1+0.25) = 0.4
    assert!((metrics.f1 - 0.4).abs() < 1e-9, "{}", metrics.f1);
    // The missed cases are named for triage; no benign case is a false alarm.
    assert_eq!(
        metrics.false_negative_cases,
        vec![
            "prompt-injection-override",
            "prompt-injection-exfiltration",
            "prompt-injection-roleplay"
        ]
    );
    assert!(metrics.false_positive_cases.is_empty());
    // The latency distribution is populated and ordered.
    assert!(metrics.latency_max_ms >= metrics.latency_p95_ms);
    assert!(metrics.latency_p95_ms >= metrics.latency_p50_ms);
}

#[test]
fn always_pass_detector_has_zero_recall_and_lists_every_missed_malicious_case() {
    let corpus = reference_corpus();
    // MockAdapter's default reply is Pass, and no script is added.
    let detector = MockAdapter::new(mock_descriptor());
    let metrics = runtime().block_on(run_detector_evaluation(&detector, &corpus));

    assert_eq!(metrics.true_positives, 0);
    assert_eq!(metrics.false_negatives, corpus.malicious_count());
    assert_eq!(metrics.false_positives, 0);
    assert_eq!(metrics.recall, 0.0);
    assert_eq!(metrics.precision, 0.0); // no positive predictions -> guarded to 0
    let mut missed = metrics.false_negative_cases.clone();
    missed.sort();
    assert_eq!(
        missed,
        vec![
            "prompt-injection-exfiltration",
            "prompt-injection-override",
            "prompt-injection-roleplay",
            "secret-aws-key"
        ]
    );
}

#[test]
fn always_fail_detector_has_full_recall_and_lists_every_benign_false_positive() {
    let corpus = reference_corpus();
    let detector =
        MockAdapter::new(mock_descriptor()).with_default(MockResponse::result(fail_result()));
    let metrics = runtime().block_on(run_detector_evaluation(&detector, &corpus));

    // Flags everything: catches all malicious (recall 1.0) but false-alarms on
    // all four benign cases.
    assert_eq!(metrics.true_positives, 4);
    assert_eq!(metrics.false_negatives, 0);
    assert_eq!(metrics.false_positives, 4);
    assert_eq!(metrics.true_negatives, 0);
    assert!((metrics.recall - 1.0).abs() < 1e-9);
    // precision = 4 / (4 + 4) = 0.5
    assert!(
        (metrics.precision - 0.5).abs() < 1e-9,
        "{}",
        metrics.precision
    );
    let mut false_alarms = metrics.false_positive_cases.clone();
    false_alarms.sort();
    assert_eq!(
        false_alarms,
        vec![
            "benign-code-question",
            "benign-greeting",
            "benign-mentions-ignore",
            "benign-mentions-key-word"
        ]
    );
}

#[test]
fn detector_errors_are_tallied_separately_from_accuracy() {
    let corpus = reference_corpus();
    let detector = MockAdapter::new(mock_descriptor())
        .with_default(MockResponse::error(DetectorErrorKind::Unavailable));
    let metrics = runtime().block_on(run_detector_evaluation(&detector, &corpus));

    assert_eq!(metrics.errors, corpus.cases.len());
    assert_eq!(metrics.error_cases.len(), corpus.cases.len());
    // No case was scored as a positive/negative when it errored.
    assert_eq!(metrics.true_positives, 0);
    assert_eq!(metrics.false_positives, 0);
    assert_eq!(metrics.true_negatives, 0);
    assert_eq!(metrics.false_negatives, 0);
}

#[test]
fn metrics_never_carry_raw_matched_content() {
    // The reference corpus embeds a synthetic secret; the metrics must reference
    // only case ids/descriptions, never the raw content.
    let corpus = reference_corpus();
    let metrics = runtime().block_on(run_detector_evaluation(&aws_secret_detector(), &corpus));
    let serialized = format!("{metrics:?}");
    assert!(
        !serialized.contains("AKIA"),
        "evaluation metrics must not carry the raw secret: {serialized}"
    );
}
