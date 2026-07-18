// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Tests for the Guardrail detector evaluation corpus + accuracy/latency runner (#201).

use super::conformance::{MockAdapter, MockResponse};
use super::evaluation::{
    record_shadow_observations, reference_corpus, run_detector_evaluation,
    score_shadow_observations, PromotionDecision, PromotionGate, PromotionThresholds,
    RollbackDecision, ShadowObservation, ShadowOutcome,
};
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

// --- shadow-verdict scoring + promotion gate (#201) -------------------------

#[test]
fn scoring_recorded_shadow_verdicts_matches_a_live_run() {
    // A shadow deployment records verdicts as evidence; scoring those recorded
    // verdicts against the labels must reproduce exactly what a live run yields.
    let corpus = reference_corpus();
    let detector = aws_secret_detector();
    let live = runtime().block_on(run_detector_evaluation(&detector, &corpus));

    let observations = runtime().block_on(record_shadow_observations(&detector, &corpus));
    let scored = score_shadow_observations(&corpus.version, &observations);

    assert_eq!(scored.true_positives, live.true_positives);
    assert_eq!(scored.false_positives, live.false_positives);
    assert_eq!(scored.true_negatives, live.true_negatives);
    assert_eq!(scored.false_negatives, live.false_negatives);
    assert_eq!(scored.errors, live.errors);
    assert_eq!(scored.false_negative_cases, live.false_negative_cases);
    assert_eq!(scored.false_positive_cases, live.false_positive_cases);
    assert!((scored.precision - live.precision).abs() < 1e-9);
    assert!((scored.recall - live.recall).abs() < 1e-9);
    assert!((scored.f1 - live.f1).abs() < 1e-9);
    // The shadow path records verdicts, not timings.
    assert_eq!(scored.latency_p50_ms, 0.0);
    assert_eq!(scored.latency_max_ms, 0.0);
}

#[test]
fn shadow_outcome_maps_verdicts_like_the_live_runner() {
    let flagged: Result<DetectorResult, DetectorError> = Ok(DetectorResult {
        verdict: DetectorVerdict::Fail,
        findings: Vec::new(),
        patches: Vec::new(),
        detector_version: "x/1".to_string(),
    });
    let cleared: Result<DetectorResult, DetectorError> = Ok(DetectorResult {
        verdict: DetectorVerdict::Pass,
        findings: Vec::new(),
        patches: Vec::new(),
        detector_version: "x/1".to_string(),
    });
    let errored: Result<DetectorResult, DetectorError> =
        Err(DetectorError::new(DetectorErrorKind::Unavailable, "down"));
    assert_eq!(ShadowOutcome::from_result(&flagged), ShadowOutcome::Flagged);
    assert_eq!(ShadowOutcome::from_result(&cleared), ShadowOutcome::Cleared);
    assert_eq!(ShadowOutcome::from_result(&errored), ShadowOutcome::Errored);
}

#[test]
fn promotion_gate_promotes_a_shadow_candidate_that_clears_the_bar() {
    // A perfect-precision, full-recall shadow run clears the conservative bar.
    let observations = vec![
        ShadowObservation::new("attack-1", true, ShadowOutcome::Flagged),
        ShadowObservation::new("attack-2", true, ShadowOutcome::Flagged),
        ShadowObservation::new("benign-1", false, ShadowOutcome::Cleared),
        ShadowObservation::new("benign-2", false, ShadowOutcome::Cleared),
    ];
    let metrics = score_shadow_observations("reference/2", &observations);
    let gate = PromotionGate::new(PromotionThresholds::conservative());
    assert_eq!(gate.assess_shadow(&metrics), PromotionDecision::Promote);
    assert!(gate.assess_shadow(&metrics).is_promote());
}

#[test]
fn promotion_gate_holds_a_shadow_candidate_that_false_alarms() {
    // One false positive drops precision below the 1.0 bar -> held, with a reason.
    let observations = vec![
        ShadowObservation::new("attack-1", true, ShadowOutcome::Flagged),
        ShadowObservation::new("attack-2", true, ShadowOutcome::Flagged),
        ShadowObservation::new("benign-1", false, ShadowOutcome::Flagged),
        ShadowObservation::new("benign-2", false, ShadowOutcome::Cleared),
    ];
    let metrics = score_shadow_observations("reference/2", &observations);
    let gate = PromotionGate::new(PromotionThresholds::conservative());
    match gate.assess_shadow(&metrics) {
        PromotionDecision::Hold { unmet } => {
            assert!(unmet.iter().any(|reason| reason.contains("precision")));
        }
        other => panic!("expected Hold, got {other:?}"),
    }
}

#[test]
fn promotion_gate_holds_when_the_detector_errors_too_much() {
    let observations = vec![
        ShadowObservation::new("attack-1", true, ShadowOutcome::Flagged),
        ShadowObservation::new("attack-2", true, ShadowOutcome::Errored),
        ShadowObservation::new("benign-1", false, ShadowOutcome::Cleared),
    ];
    let metrics = score_shadow_observations("reference/2", &observations);
    let gate = PromotionGate::new(PromotionThresholds::conservative());
    match gate.assess_shadow(&metrics) {
        PromotionDecision::Hold { unmet } => {
            assert!(unmet.iter().any(|reason| reason.contains("error rate")));
        }
        other => panic!("expected Hold on error rate, got {other:?}"),
    }
}

#[test]
fn rollback_is_triggered_only_on_a_genuine_regression_below_the_floor() {
    let gate = PromotionGate::new(PromotionThresholds::conservative());

    // A healthy enforced revision (precision 1.0, recall 1.0) is kept.
    let healthy = score_shadow_observations(
        "reference/2",
        &[
            ShadowObservation::new("attack-1", true, ShadowOutcome::Flagged),
            ShadowObservation::new("benign-1", false, ShadowOutcome::Cleared),
        ],
    );
    assert_eq!(gate.assess_enforced(&healthy), RollbackDecision::Keep);

    // A regression: the enforced revision now false-alarms on most benign
    // traffic, dropping precision below the 0.9 rollback floor -> roll back.
    let regressed = score_shadow_observations(
        "reference/2",
        &[
            ShadowObservation::new("attack-1", true, ShadowOutcome::Flagged),
            ShadowObservation::new("benign-1", false, ShadowOutcome::Flagged),
            ShadowObservation::new("benign-2", false, ShadowOutcome::Flagged),
        ],
    );
    match gate.assess_enforced(&regressed) {
        RollbackDecision::Rollback { regressions } => {
            assert!(regressions
                .iter()
                .any(|reason| reason.contains("precision")));
        }
        other => panic!("expected Rollback, got {other:?}"),
    }
    assert!(gate.assess_enforced(&regressed).is_rollback());
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
