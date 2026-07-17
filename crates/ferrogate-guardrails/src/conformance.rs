// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: Reusable Guardrail detector conformance harness plus an in-repo scriptable mock.

//! A backend-free way to prove a [`GuardrailDetector`] honours the adapter
//! contract. [`run_detector_conformance`] drives any detector through the six
//! required behaviours and reports which held; [`MockAdapter`] is a scriptable
//! trait implementation used both to exercise the harness and to let downstream
//! adapter authors stand in a detector without a real vendor.
//!
//! This module is never part of a production build: it is compiled only under
//! `cfg(test)` and behind the opt-in `conformance` feature.

use crate::{
    all_content_sources, validate_content_patches_for_segments, ContentPatch, ContentSource,
    DataResidency, DetectorCredentialType, DetectorDescriptor, DetectorError, DetectorErrorKind,
    DetectorHealth, DetectorInput, DetectorResult, DetectorStage, DetectorTenant, DetectorVerdict,
    Finding, FindingSeverity, GuardrailDetector, GuardrailEnvelope, GuardrailProtocol,
};
use async_trait::async_trait;
use serde_json::Map;
use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};

/// A synthetic AWS-style access key. It is not a real credential; it exists so a
/// deterministic secret detector fails on the probe input while the harness can
/// still assert the raw value never reaches serialized evidence.
pub const PROBE_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

/// Content the harness expects a conformant detector to pass.
fn benign_envelope() -> GuardrailEnvelope {
    GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "the quick brown fox jumps over the lazy dog",
    )
}

/// Content the harness expects a conformant detector to fail on, in a mutable
/// user-text segment so a transform-capable detector can emit a patch.
fn probe_envelope() -> GuardrailEnvelope {
    GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        format!("leaked credential {PROBE_SECRET} in transit"),
    )
}

fn detector_input(envelope: &GuardrailEnvelope) -> DetectorInput<'_> {
    DetectorInput {
        protocol: envelope.protocol,
        stage: envelope.stage,
        tenant: DetectorTenant {
            organization_id: Some("conformance-org"),
            team_id: None,
            project_id: None,
            user_id: None,
            api_key_id: None,
        },
        model: Some("conformance-model"),
        provider: Some("conformance-provider"),
        text: envelope
            .segments
            .first()
            .map(|segment| segment.text.as_str())
            .unwrap_or_default(),
        segments: &envelope.segments,
    }
}

/// The outcome of driving a detector through the conformance behaviours. Each
/// flag records that the behaviour was genuinely exercised (not merely absent);
/// `failures` carries a human-readable reason for anything that did not hold.
#[derive(Debug, Default, Clone)]
pub struct ConformanceReport {
    pub pass_verdict: bool,
    pub sanitized_fail: bool,
    pub transform_validated: bool,
    pub error_classified: bool,
    pub timeout_enforced: bool,
    pub version_reported: bool,
    pub failures: Vec<String>,
}

impl ConformanceReport {
    fn fail(&mut self, message: impl Into<String>) {
        self.failures.push(message.into());
    }

    /// True when every required behaviour held.
    pub fn conforms(&self) -> bool {
        self.failures.is_empty()
    }

    /// True when every required behaviour was both exercised and held.
    pub fn all_behaviours_exercised(&self) -> bool {
        self.conforms()
            && self.pass_verdict
            && self.sanitized_fail
            && self.transform_validated
            && self.error_classified
            && self.timeout_enforced
            && self.version_reported
    }
}

/// Drive `detector` through the six required adapter behaviours and report which
/// held: (1) a Pass verdict on benign content; (2) a Fail verdict whose findings
/// are sanitized (a fingerprint is present, the raw matched value never reaches
/// serialized evidence, and no finding carries `matched_text`); (3) a transform
/// whose emitted patches validate against the evaluated segments; (4) an error
/// whose kind is a member of `descriptor().declared_failure_modes`; (5) a
/// timeout when handed an already-expired deadline; and (6) non-empty version
/// reporting on both the descriptor and the result.
pub async fn run_detector_conformance(detector: &dyn GuardrailDetector) -> ConformanceReport {
    let mut report = ConformanceReport::default();
    let descriptor = detector.descriptor();
    if descriptor.version.trim().is_empty() {
        report.fail("descriptor().version is empty");
    }

    let far = Instant::now() + Duration::from_secs(5);

    // (1) Pass verdict + (6) version reporting.
    let benign = benign_envelope();
    let benign_input = detector_input(&benign);
    match detector.evaluate(&benign_input, far).await {
        Ok(result) => {
            report.pass_verdict = result.verdict == DetectorVerdict::Pass;
            if !report.pass_verdict {
                report.fail("benign content did not produce a Pass verdict");
            }
            if result.detector_version.trim().is_empty() {
                report.fail("DetectorResult.detector_version is empty");
            }
            report.version_reported =
                !descriptor.version.trim().is_empty() && !result.detector_version.trim().is_empty();
        }
        Err(error) => report.fail(format!(
            "benign evaluation errored: {}",
            error.kind.as_str()
        )),
    }

    // (2) Sanitized fail + (3) transform.
    let probe = probe_envelope();
    let probe_input = detector_input(&probe);
    match detector.evaluate(&probe_input, far).await {
        Ok(result) => {
            if result.verdict != DetectorVerdict::Fail {
                report.fail("probe content did not produce a Fail verdict");
            }
            let serialized = serde_json::to_string(&result).unwrap_or_default();
            let leaks_raw_value = serialized.contains(PROBE_SECRET);
            let carries_matched_text = result.findings.iter().any(|f| f.matched_text.is_some());
            let has_fingerprint = result.findings.iter().any(|f| f.fingerprint.is_some());
            if leaks_raw_value {
                report.fail("serialized DetectorResult leaked the raw matched value");
            }
            if carries_matched_text {
                report.fail("a finding carried raw matched_text in persisted evidence");
            }
            if result.findings.is_empty() {
                report.fail("fail verdict produced no findings");
            } else if !has_fingerprint {
                report.fail("no finding carried a sanitized fingerprint");
            }
            report.sanitized_fail = result.verdict == DetectorVerdict::Fail
                && !leaks_raw_value
                && !carries_matched_text
                && has_fingerprint;

            match validate_content_patches_for_segments(&probe.segments, &result.patches) {
                Ok(()) => {
                    if descriptor.supports_transform && result.patches.is_empty() {
                        report.fail(
                            "supports_transform detector emitted no patch for patch-eligible content",
                        );
                    } else {
                        report.transform_validated = true;
                    }
                }
                Err(error) => report.fail(format!(
                    "emitted patch failed validation: {}",
                    error.kind.as_str()
                )),
            }
        }
        Err(error) => report.fail(format!("probe evaluation errored: {}", error.kind.as_str())),
    }

    // (4) Error classification + (5) timeout, driven via an expired deadline.
    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    match detector.evaluate(&benign_input, expired).await {
        Ok(_) => report.fail("expired deadline did not produce an error"),
        Err(error) => {
            report.timeout_enforced = error.kind == DetectorErrorKind::Timeout;
            if !report.timeout_enforced {
                report.fail(format!(
                    "expired deadline produced {} instead of timeout",
                    error.kind.as_str()
                ));
            }
            report.error_classified = descriptor.declared_failure_modes.contains(&error.kind);
            if !report.error_classified {
                report.fail(format!(
                    "error kind {} is not a declared failure mode",
                    error.kind.as_str()
                ));
            }
        }
    }

    report
}

/// Run [`run_detector_conformance`] and panic unless every required behaviour
/// was exercised and held. Convenience for conformance tests.
pub async fn assert_detector_conforms(detector: &dyn GuardrailDetector) -> ConformanceReport {
    let report = run_detector_conformance(detector).await;
    assert!(
        report.conforms(),
        "detector failed guardrail conformance: {:?}",
        report.failures
    );
    assert!(report.pass_verdict, "pass-verdict behaviour not exercised");
    assert!(
        report.sanitized_fail,
        "sanitized-fail behaviour not exercised"
    );
    assert!(
        report.transform_validated,
        "transform behaviour not exercised"
    );
    assert!(
        report.error_classified,
        "error-classification behaviour not exercised"
    );
    assert!(report.timeout_enforced, "timeout behaviour not exercised");
    assert!(
        report.version_reported,
        "version-reporting behaviour not exercised"
    );
    report
}

/// A single scripted reply from a [`MockAdapter`]: either a full result or an
/// error kind, optionally preceded by a delay used to exercise deadline
/// enforcement.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub outcome: Result<DetectorResult, DetectorErrorKind>,
    pub delay: Option<Duration>,
}

impl MockResponse {
    /// A Pass verdict carrying the given detector version.
    pub fn pass(detector_version: impl Into<String>) -> Self {
        Self {
            outcome: Ok(DetectorResult {
                verdict: DetectorVerdict::Pass,
                findings: Vec::new(),
                patches: Vec::new(),
                detector_version: detector_version.into(),
            }),
            delay: None,
        }
    }

    /// A scripted error of the given kind.
    pub fn error(kind: DetectorErrorKind) -> Self {
        Self {
            outcome: Err(kind),
            delay: None,
        }
    }

    /// A result reply (e.g. a sanitized fail with patches).
    pub fn result(result: DetectorResult) -> Self {
        Self {
            outcome: Ok(result),
            delay: None,
        }
    }

    /// Sleep for `delay` before replying; if the deadline passes meanwhile the
    /// adapter reports a timeout instead.
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = Some(delay);
        self
    }
}

/// A programmable [`GuardrailDetector`]. Its descriptor is fixed at construction;
/// its per-call replies are a FIFO script (falling back to a default reply once
/// the script is drained). An expired deadline always yields a timeout before a
/// scripted reply is consumed, mirroring the production detectors.
#[derive(Debug)]
pub struct MockAdapter {
    descriptor: DetectorDescriptor,
    responses: Mutex<VecDeque<MockResponse>>,
    default: MockResponse,
}

impl MockAdapter {
    /// A mock with the given descriptor and a default Pass reply.
    pub fn new(descriptor: DetectorDescriptor) -> Self {
        let default = MockResponse::pass(descriptor.version.clone());
        Self {
            descriptor,
            responses: Mutex::new(VecDeque::new()),
            default,
        }
    }

    /// Append scripted replies, consumed in order (builder form).
    #[must_use]
    pub fn script(self, responses: impl IntoIterator<Item = MockResponse>) -> Self {
        self.responses
            .lock()
            .expect("mock adapter mutex poisoned")
            .extend(responses);
        self
    }

    /// Append a scripted reply after construction.
    pub fn push(&self, response: MockResponse) {
        self.responses
            .lock()
            .expect("mock adapter mutex poisoned")
            .push_back(response);
    }

    /// Replace the default reply used once the script is drained (builder form).
    #[must_use]
    pub fn with_default(mut self, response: MockResponse) -> Self {
        self.default = response;
        self
    }

    /// A mock pre-scripted to satisfy [`run_detector_conformance`]: a Pass, then
    /// a sanitized Fail carrying a redaction patch that validates against the
    /// harness probe segment. The timeout drive consumes no script.
    pub fn conforming() -> Self {
        let descriptor = DetectorDescriptor {
            id: "mock-adapter".to_string(),
            version: "mock/1".to_string(),
            supports_request: true,
            supports_response: true,
            supports_transform: true,
            supported_sources: all_content_sources(),
            credential: DetectorCredentialType::None,
            data_residency: DataResidency::InRepo,
            max_payload_bytes: usize::MAX,
            declared_failure_modes: vec![
                DetectorErrorKind::Timeout,
                DetectorErrorKind::Unavailable,
                DetectorErrorKind::Internal,
            ],
        };
        Self::new(descriptor).script([
            MockResponse::pass("mock/1"),
            MockResponse::result(conformance_probe_result("mock/1")),
        ])
    }

    fn next_response(&self) -> MockResponse {
        self.responses
            .lock()
            .expect("mock adapter mutex poisoned")
            .pop_front()
            .unwrap_or_else(|| self.default.clone())
    }
}

/// Build a sanitized Fail result whose finding and redaction patch line up with
/// the harness probe segment (matched by segment id, fingerprint, protocol path,
/// and byte range). Carries a fingerprint but never the raw matched value. Public
/// so adapter authors can script a conforming [`MockAdapter`] with their own
/// descriptor.
pub fn conformance_probe_result(detector_version: &str) -> DetectorResult {
    let probe = probe_envelope();
    let segment = probe
        .segments
        .first()
        .expect("probe envelope has one segment");
    let start = segment
        .text
        .find(PROBE_SECRET)
        .expect("probe text contains the secret");
    let end = start + PROBE_SECRET.len();
    DetectorResult {
        verdict: DetectorVerdict::Fail,
        findings: vec![Finding {
            category: "secret.mock".to_string(),
            severity: FindingSeverity::Critical,
            confidence: Some(0.99),
            byte_start: Some(start),
            byte_end: Some(end),
            segment_id: Some(segment.segment_id.clone()),
            fingerprint: Some("hmac-sha256:mock".to_string()),
            matched_text: None,
            attributes: Map::new(),
        }],
        patches: vec![ContentPatch {
            segment_id: segment.segment_id.clone(),
            expected_fingerprint: segment.fingerprint.clone(),
            protocol_location: segment.protocol_location.clone(),
            byte_start: start,
            byte_end: end,
            replacement: "[REDACTED]".to_string(),
        }],
        detector_version: detector_version.to_string(),
    }
}

#[async_trait]
impl GuardrailDetector for MockAdapter {
    fn descriptor(&self) -> DetectorDescriptor {
        self.descriptor.clone()
    }

    fn health(&self) -> DetectorHealth {
        DetectorHealth {
            circuit_open: false,
            consecutive_failures: 0,
            in_flight: 0,
            request_total: 0,
            success_total: 0,
            failure_total: 0,
        }
    }

    async fn evaluate(
        &self,
        _input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        if Instant::now() >= deadline {
            return Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "mock adapter deadline expired before execution",
            ));
        }
        let response = self.next_response();
        if let Some(delay) = response.delay {
            tokio::time::sleep(delay).await;
            if Instant::now() >= deadline {
                return Err(DetectorError::new(
                    DetectorErrorKind::Timeout,
                    "mock adapter deadline expired during scripted delay",
                ));
            }
        }
        response
            .outcome
            .map_err(|kind| DetectorError::new(kind, "mock adapter scripted error"))
    }
}
