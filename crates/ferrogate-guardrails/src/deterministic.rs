// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Deterministic structured Guardrail detectors with sanitized findings.

use crate::{
    ContentPatch, ContentSegment, ContentSource, DataResidency, DetectorCredentialType,
    DetectorDescriptor, DetectorError, DetectorErrorKind, DetectorHealth, DetectorInput,
    DetectorResult, DetectorSecret, DetectorVerdict, Finding, FindingSeverity, GuardrailDetector,
    GuardrailProtocol, SegmentContentType,
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use jsonschema::Validator;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::Instant,
};

const DETERMINISTIC_VERSION: &str = "deterministic/1";
const REDACTION: &str = "[REDACTED]";

/// Hard cap on the findings a single `evaluate` call will enumerate. An
/// absurdly repetitive input (e.g. a 1 MB body that is one repeated 1-char
/// keyword) produces ~N matches; even with O(1) dedup that is N `Finding` + N
/// `ContentPatch` structs, an O(N) MEMORY amplifier that concurrent requests
/// could turn into an OOM. Once this many findings exist the content is already
/// conclusively flagged, so enumeration stops and a single truncation marker is
/// emitted (see `add_text_match`). The bound is deliberately generous: real
/// inputs never approach it, so normal detection is byte-for-byte unchanged and
/// only pathological floods are capped.
pub(crate) const MAX_FINDINGS_PER_EVALUATION: usize = 10_000;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JsonConstraints {
    #[serde(default)]
    pub schema: Option<Value>,
    /// RFC 6901 JSON pointers. The empty pointer denotes the document root.
    #[serde(default)]
    pub required_keys: Vec<String>,
    /// RFC 6901 JSON pointers. A present value causes a finding.
    #[serde(default)]
    pub forbidden_keys: Vec<String>,
}

impl JsonConstraints {
    pub fn is_empty(&self) -> bool {
        self.schema.is_none() && self.required_keys.is_empty() && self.forbidden_keys.is_empty()
    }

    pub(crate) fn validate(&self, name: &str) -> Result<(), DetectorError> {
        validate_json_pointers(&self.required_keys, name)?;
        validate_json_pointers(&self.forbidden_keys, name)?;
        if self.required_keys.iter().collect::<HashSet<_>>().len() != self.required_keys.len()
            || self.forbidden_keys.iter().collect::<HashSet<_>>().len() != self.forbidden_keys.len()
        {
            return Err(invalid_config(
                "structured Guardrail key constraints must be unique",
            ));
        }
        if let Some(schema) = &self.schema {
            jsonschema::validator_for(schema).map_err(|_| {
                invalid_config("structured Guardrail contains an invalid JSON Schema")
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestConstraints {
    #[serde(default)]
    pub allowed_endpoints: Vec<GuardrailProtocol>,
    #[serde(default)]
    pub allowed_models: Vec<String>,
    #[serde(default)]
    pub forbidden_models: Vec<String>,
    #[serde(default)]
    pub allowed_providers: Vec<String>,
    #[serde(default)]
    pub forbidden_providers: Vec<String>,
    #[serde(default)]
    pub metadata: Option<JsonConstraints>,
    #[serde(default)]
    pub tool_parameters: Option<JsonConstraints>,
}

impl RequestConstraints {
    pub fn is_empty(&self) -> bool {
        self.allowed_endpoints.is_empty()
            && self.allowed_models.is_empty()
            && self.forbidden_models.is_empty()
            && self.allowed_providers.is_empty()
            && self.forbidden_providers.is_empty()
            && self.metadata.as_ref().is_none_or(JsonConstraints::is_empty)
            && self
                .tool_parameters
                .as_ref()
                .is_none_or(JsonConstraints::is_empty)
    }

    pub(crate) fn validate(&self) -> Result<(), DetectorError> {
        for values in [
            &self.allowed_models,
            &self.forbidden_models,
            &self.allowed_providers,
            &self.forbidden_providers,
        ] {
            if values.iter().any(|value| value.trim().is_empty())
                || values.iter().collect::<HashSet<_>>().len() != values.len()
            {
                return Err(invalid_config(
                    "request Guardrail constraints must be non-empty and unique",
                ));
            }
        }
        if self.allowed_endpoints.iter().collect::<HashSet<_>>().len()
            != self.allowed_endpoints.len()
        {
            return Err(invalid_config(
                "request Guardrail endpoint constraints must be unique",
            ));
        }
        if let Some(metadata) = &self.metadata {
            metadata.validate("metadata")?;
        }
        if let Some(tool_parameters) = &self.tool_parameters {
            tool_parameters.validate("tool_parameters")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecretPattern {
    OpenAiApiKey,
    GithubToken,
    AwsAccessKeyId,
}

impl SecretPattern {
    fn category(self) -> &'static str {
        match self {
            Self::OpenAiApiKey => "secret.openai_api_key",
            Self::GithubToken => "secret.github_token",
            Self::AwsAccessKeyId => "secret.aws_access_key_id",
        }
    }

    fn expression(self) -> &'static str {
        match self {
            // Version 1 intentionally favors precision over recall. Broad
            // `sk-*` matching is not called high confidence.
            Self::OpenAiApiKey => r"\bsk-(?:proj-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{32,})\b",
            Self::GithubToken => {
                r"\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b"
            }
            Self::AwsAccessKeyId => r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        }
    }
}

#[derive(Clone)]
pub struct DeterministicDetectorConfig {
    pub id: String,
    pub supported_sources: Vec<ContentSource>,
    pub keywords: Vec<String>,
    pub regex: Vec<String>,
    pub max_input_bytes: Option<usize>,
    pub json: Option<JsonConstraints>,
    pub request: Option<RequestConstraints>,
    pub secret_patterns: Vec<SecretPattern>,
    pub fingerprint_key: Option<DetectorSecret>,
}

impl std::fmt::Debug for DeterministicDetectorConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeterministicDetectorConfig")
            .field("id", &self.id)
            .field("supported_sources", &self.supported_sources)
            .field("keywords", &self.keywords)
            .field("regex", &self.regex)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("json", &self.json)
            .field("request", &self.request)
            .field("secret_patterns", &self.secret_patterns)
            .field("fingerprint_key", &self.fingerprint_key)
            .finish()
    }
}

#[derive(Clone, Debug)]
struct CompiledJsonConstraints {
    validator: Option<Validator>,
    required_keys: Vec<String>,
    forbidden_keys: Vec<String>,
}

impl CompiledJsonConstraints {
    fn compile(constraints: &JsonConstraints) -> Result<Self, DetectorError> {
        constraints.validate("json")?;
        let validator = constraints
            .schema
            .as_ref()
            .map(jsonschema::validator_for)
            .transpose()
            .map_err(|_| invalid_config("structured Guardrail contains an invalid JSON Schema"))?;
        Ok(Self {
            validator,
            required_keys: constraints.required_keys.clone(),
            forbidden_keys: constraints.forbidden_keys.clone(),
        })
    }

    fn evaluate(&self, value: &Value) -> Vec<&'static str> {
        let mut failures = Vec::new();
        if self
            .validator
            .as_ref()
            .is_some_and(|validator| !validator.is_valid(value))
        {
            failures.push("json_schema");
        }
        if self
            .required_keys
            .iter()
            .any(|pointer| value.pointer(pointer).is_none())
        {
            failures.push("required_key");
        }
        if self
            .forbidden_keys
            .iter()
            .any(|pointer| value.pointer(pointer).is_some())
        {
            failures.push("forbidden_key");
        }
        failures
    }
}

#[derive(Clone, Debug)]
struct CompiledRequestConstraints {
    definition: RequestConstraints,
    metadata: Option<CompiledJsonConstraints>,
    tool_parameters: Option<CompiledJsonConstraints>,
}

#[derive(Debug)]
pub struct DeterministicDetector {
    config: DeterministicDetectorConfig,
    regex: Vec<Regex>,
    json: Option<CompiledJsonConstraints>,
    request: Option<CompiledRequestConstraints>,
    secrets: Vec<(SecretPattern, Regex)>,
}

#[derive(Debug, Clone, Copy)]
struct TextMatch<'a> {
    category: &'a str,
    severity: FindingSeverity,
    confidence: Option<f32>,
    start: usize,
    end: usize,
}

/// Mutable accumulator for text-scan results plus the indexes that keep both the
/// finding and patch de-duplication sub-linear per match. Every keyword/regex/
/// secret match from both the coalesced-group scan and the per-segment scan
/// funnels through [`DeterministicDetector::add_text_match`], so the dedup cost
/// is paid once per match: with linear `Vec::iter().any(...)` rescans that was
/// O(matches^2) (a single long keyword run is a request-level DoS), whereas the
/// `seen_findings` set and per-segment interval maps below make it O(log n) per
/// match — O(n log n) overall.
#[derive(Default)]
struct TextMatchSink {
    findings: Vec<Finding>,
    patches: Vec<ContentPatch>,
    /// Exact `(category, segment_id, byte_start, byte_end)` keys already emitted
    /// as findings. A match wholly inside one segment is offered by both scans,
    /// so this set collapses the duplicate to one finding at O(1) amortized while
    /// still letting the per-segment scan surface a boundary-anchored match the
    /// coalesced scan missed. This is exactly the key the old linear guard used.
    seen_findings: HashSet<(String, String, usize, usize)>,
    /// Accepted patch intervals per segment (`byte_start -> byte_end`), kept
    /// non-overlapping. A candidate patch overlapping an accepted one is dropped
    /// — the exact semantics of the old linear overlap guard. Overlap avoidance
    /// is REQUIRED, not cosmetic: `validate_content_patches_for_segments` rejects
    /// any overlapping patch set downstream, which collapses surgical redaction
    /// into a whole-field `[REDACTED]`; and distinct matches can genuinely
    /// overlap (e.g. keywords `abc` and `bcd` over `abcd`), so an exact-duplicate
    /// set would not suffice. Sorted-interval neighbour probes make the overlap
    /// test O(log n) instead of an O(n) rescan.
    patched_intervals: HashMap<String, BTreeMap<usize, usize>>,
    /// Set once `MAX_FINDINGS_PER_EVALUATION` findings have been enumerated. When
    /// set, every further match is dropped in O(1) and a single truncation marker
    /// stands in for the un-enumerated remainder, bounding the evidence (and thus
    /// per-request memory) no matter how many matches the input contains.
    truncated: bool,
}

impl DeterministicDetector {
    pub fn new(config: DeterministicDetectorConfig) -> Result<Self, DetectorError> {
        validate_config(&config)?;
        let regex = config
            .regex
            .iter()
            .map(|expression| {
                Regex::new(expression)
                    .map_err(|_| invalid_config("local Guardrail contains an invalid regex"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let json = config
            .json
            .as_ref()
            .map(CompiledJsonConstraints::compile)
            .transpose()?;
        let request = config
            .request
            .as_ref()
            .map(|definition| {
                definition.validate()?;
                Ok(CompiledRequestConstraints {
                    metadata: definition
                        .metadata
                        .as_ref()
                        .map(CompiledJsonConstraints::compile)
                        .transpose()?,
                    tool_parameters: definition
                        .tool_parameters
                        .as_ref()
                        .map(CompiledJsonConstraints::compile)
                        .transpose()?,
                    definition: definition.clone(),
                })
            })
            .transpose()?;
        let secrets = config
            .secret_patterns
            .iter()
            .copied()
            .map(|pattern| {
                Regex::new(pattern.expression())
                    .map(|expression| (pattern, expression))
                    .map_err(|_| invalid_config("built-in secret pattern failed to compile"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            config,
            regex,
            json,
            request,
            secrets,
        })
    }

    fn finding(
        &self,
        category: impl Into<String>,
        severity: FindingSeverity,
        confidence: Option<f32>,
        segment: Option<&ContentSegment>,
        range: Option<(usize, usize)>,
        sensitive_value: Option<&str>,
    ) -> Finding {
        Finding {
            category: category.into(),
            severity,
            confidence,
            byte_start: range.map(|range| range.0),
            byte_end: range.map(|range| range.1),
            segment_id: segment.map(|segment| segment.segment_id.clone()),
            fingerprint: sensitive_value.and_then(|value| self.hmac_fingerprint(value)),
            matched_text: None,
            attributes: Map::new(),
        }
    }

    fn hmac_fingerprint(&self, value: &str) -> Option<String> {
        let key = self.config.fingerprint_key.as_ref()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).ok()?;
        mac.update(value.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut output = String::with_capacity("hmac-sha256:".len() + bytes.len() * 2);
        output.push_str("hmac-sha256:");
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        Some(output)
    }

    fn add_text_match(
        &self,
        sink: &mut TextMatchSink,
        segment: &ContentSegment,
        detected: TextMatch<'_>,
    ) {
        // Bounded evidence (belt-and-suspenders on top of the O(1) dedup): once
        // MAX_FINDINGS_PER_EVALUATION findings exist the content is already
        // conclusively flagged, so stop enumerating and drop every further match
        // in O(1). This caps per-request memory (Finding + ContentPatch structs)
        // to a constant regardless of input size, closing the O(N) memory
        // amplifier a repetitive flood would otherwise open. Detection is not
        // weakened: the verdict is still Fail. The single truncation marker below
        // is a *located* finding with no covering patch, so downstream
        // has_unredactable_findings forces a Redact action to fail closed (Deny)
        // — a truncated result can never be fully scrubbed.
        if sink.truncated {
            return;
        }
        if sink.findings.len() >= MAX_FINDINGS_PER_EVALUATION {
            sink.truncated = true;
            // Zero-width marker at offset 0: no positive-width patch can ever
            // cover [0, 0) (a patch needs byte_start < 0), so this finding is
            // guaranteed unredactable, which is exactly the fail-closed signal.
            sink.findings.push(self.finding(
                "detector.truncated",
                FindingSeverity::Critical,
                Some(1.0),
                Some(segment),
                Some((0, 0)),
                None,
            ));
            return;
        }
        let TextMatch {
            category,
            severity,
            confidence,
            start,
            end,
        } = detected;
        let matched = &segment.text[start..end];
        // Both the coalesced-group scan and the per-segment scan funnel through
        // here, so a match wholly inside one segment is offered twice. Dedupe
        // findings by the exact (category, segment_id, byte range) key via a
        // seen-set — the same key the old linear guard used — so such a match is
        // reported exactly once at O(1) amortized (the old `findings.iter()
        // .any(...)` rescan was O(current findings) per match -> O(n^2) over n
        // matches). The per-segment scan can still surface an anchored match the
        // coalesced scan missed at a segment boundary.
        if sink
            .seen_findings
            .insert((category.to_string(), segment.segment_id.clone(), start, end))
        {
            sink.findings.push(self.finding(
                category,
                severity,
                confidence,
                Some(segment),
                Some((start, end)),
                Some(matched),
            ));
        }
        // Emit a redaction patch for mutable segments, skipping any candidate
        // that overlaps an already-accepted patch on the same segment. Overlap
        // avoidance preserves the old guard's semantics and is REQUIRED, not
        // cosmetic (see TextMatchSink::patched_intervals). Accepted intervals are
        // kept in a per-segment sorted map, so overlap is decided by two O(log n)
        // neighbour probes instead of the old O(current patches) rescan per match
        // — the other half of the former O(n^2) blowup.
        if is_mutable_text_segment(segment) {
            let intervals = sink
                .patched_intervals
                .entry(segment.segment_id.clone())
                .or_default();
            let overlaps = intervals
                .range(..=start)
                .next_back()
                .is_some_and(|(_, &existing_end)| start < existing_end)
                || intervals
                    .range(start..)
                    .next()
                    .is_some_and(|(&existing_start, _)| existing_start < end);
            if !overlaps {
                intervals.insert(start, end);
                sink.patches.push(ContentPatch {
                    segment_id: segment.segment_id.clone(),
                    expected_fingerprint: segment.fingerprint.clone(),
                    protocol_location: segment.protocol_location.clone(),
                    byte_start: start,
                    byte_end: end,
                    replacement: REDACTION.to_string(),
                });
            }
        }
    }

    /// Map a match found in a coalesced group's contiguous text back to the
    /// individual segments it covers, emitting a finding (and, for mutable
    /// segments, a patch) for each per-segment sub-range. A match wholly inside
    /// one segment resolves to exactly one sub-range identical to matching that
    /// segment directly; a match that straddles a segment boundary resolves to
    /// one sub-range per segment it overlaps so every mutable part is patched
    /// and every immutable part still yields a finding.
    fn add_group_match(
        &self,
        sink: &mut TextMatchSink,
        group: &CoalescedGroup<'_>,
        detected: TextMatch<'_>,
    ) {
        for (index, segment) in group.segments.iter().enumerate() {
            let segment_start = group.starts[index];
            let segment_end = segment_start + segment.text.len();
            let overlap_start = detected.start.max(segment_start);
            let overlap_end = detected.end.min(segment_end);
            if overlap_start < overlap_end {
                self.add_text_match(
                    sink,
                    segment,
                    TextMatch {
                        start: overlap_start - segment_start,
                        end: overlap_end - segment_start,
                        ..detected
                    },
                );
            }
        }
    }
}

/// A maximal run of consecutive selected segments that share one
/// [`ContentSource`]. Keyword/regex/secret matchers run against the
/// concatenation of the run (no separator) so a token an attacker split across
/// adjacent same-source text parts or same-source messages is still detected;
/// `starts` records where each segment begins in `text` so match offsets map
/// back to the individual segments for patching and evidence.
struct CoalescedGroup<'a> {
    text: String,
    segments: Vec<&'a ContentSegment>,
    starts: Vec<usize>,
}

/// Coalesce consecutive same-source selected segments into contiguous groups.
///
/// The run boundary is [`ContentSource`]: a source change (or the first
/// segment) starts a new group, so content from a different speaker or a
/// different tool is never concatenated into a single match. Segments are
/// joined with no separator (unlike `GuardrailEnvelope::flattened_text`, whose
/// `"\n"` joins would re-break a straddling token).
fn coalesce_selected_segments<'a>(selected: &[&'a ContentSegment]) -> Vec<CoalescedGroup<'a>> {
    let mut groups: Vec<CoalescedGroup<'a>> = Vec::new();
    for &segment in selected {
        let extend = groups.last().is_some_and(|group| {
            group
                .segments
                .last()
                .is_some_and(|last| last.source == segment.source)
        });
        if !extend {
            groups.push(CoalescedGroup {
                text: String::new(),
                segments: Vec::new(),
                starts: Vec::new(),
            });
        }
        let group = groups
            .last_mut()
            .expect("a group was just pushed when not extending");
        group.starts.push(group.text.len());
        group.text.push_str(&segment.text);
        group.segments.push(segment);
    }
    groups
}

#[async_trait]
impl GuardrailDetector for DeterministicDetector {
    fn descriptor(&self) -> DetectorDescriptor {
        DetectorDescriptor {
            id: self.config.id.clone(),
            version: DETERMINISTIC_VERSION.to_string(),
            supports_request: true,
            supports_response: true,
            supports_transform: true,
            supported_sources: self.config.supported_sources.clone(),
            // In-repo, deterministic evaluation: no backend, no credential.
            credential: DetectorCredentialType::None,
            data_residency: DataResidency::InRepo,
            // The input cap is advisory (an oversized input yields a finding, not
            // a rejection); an unset cap means no declared upper bound.
            max_payload_bytes: self.config.max_input_bytes.unwrap_or(usize::MAX),
            // At runtime this detector only surfaces Timeout (expired deadline);
            // InvalidConfiguration is emitted at construction, and Internal is
            // declared conservatively for defensive HMAC/lock failures.
            declared_failure_modes: vec![
                DetectorErrorKind::Timeout,
                DetectorErrorKind::Internal,
                DetectorErrorKind::InvalidConfiguration,
            ],
        }
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
        input: &DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError> {
        if Instant::now() >= deadline {
            return Err(DetectorError::new(
                DetectorErrorKind::Timeout,
                "deterministic Guardrail deadline expired before execution",
            ));
        }
        let selected = input
            .segments
            .iter()
            .filter(|segment| self.config.supported_sources.contains(&segment.source))
            .collect::<Vec<_>>();
        let mut sink = TextMatchSink::default();

        if self.config.max_input_bytes.is_some_and(|limit| {
            selected
                .iter()
                .map(|segment| segment.text.len())
                .sum::<usize>()
                > limit
        }) {
            sink.findings.push(self.finding(
                "size.input_bytes",
                FindingSeverity::High,
                Some(1.0),
                None,
                None,
                None,
            ));
        }

        // Run keyword/regex/secret matchers over the contiguous concatenation
        // of each same-source run so a token split across adjacent segments is
        // detected; offsets are mapped back to the individual segments for
        // patching. A token wholly inside one segment resolves to exactly the
        // same per-segment sub-range as before, preserving prior behaviour.
        for group in &coalesce_selected_segments(&selected) {
            for keyword in &self.config.keywords {
                for (start, matched) in group.text.match_indices(keyword) {
                    self.add_group_match(
                        &mut sink,
                        group,
                        TextMatch {
                            category: "contains",
                            severity: FindingSeverity::High,
                            confidence: Some(1.0),
                            start,
                            end: start + matched.len(),
                        },
                    );
                }
            }
            for expression in &self.regex {
                for matched in expression.find_iter(&group.text) {
                    self.add_group_match(
                        &mut sink,
                        group,
                        TextMatch {
                            category: "regex",
                            severity: FindingSeverity::High,
                            confidence: Some(1.0),
                            start: matched.start(),
                            end: matched.end(),
                        },
                    );
                }
            }
            for (pattern, expression) in &self.secrets {
                for matched in expression.find_iter(&group.text) {
                    self.add_group_match(
                        &mut sink,
                        group,
                        TextMatch {
                            category: pattern.category(),
                            severity: FindingSeverity::Critical,
                            confidence: Some(0.99),
                            start: matched.start(),
                            end: matched.end(),
                        },
                    );
                }
            }
        }

        // Also scan each selected segment in isolation. The coalesced scan above
        // concatenates same-source neighbours with no separator, which catches a
        // token an attacker split across parts but destroys the word boundary in
        // front of a `\b`/`^`-anchored pattern when the preceding segment ends in
        // a word char (e.g. "mykey" + "AKIA…" hides the AWS key from the
        // `\b`-anchored secret regex). Rerunning the same matchers over each
        // segment restores that per-segment anchor context; add_text_match
        // dedupes findings and patches, so a match wholly inside one segment that
        // the coalesced scan already reported is not double-counted.
        for segment in &selected {
            for keyword in &self.config.keywords {
                for (start, matched) in segment.text.match_indices(keyword) {
                    self.add_text_match(
                        &mut sink,
                        segment,
                        TextMatch {
                            category: "contains",
                            severity: FindingSeverity::High,
                            confidence: Some(1.0),
                            start,
                            end: start + matched.len(),
                        },
                    );
                }
            }
            for expression in &self.regex {
                for matched in expression.find_iter(&segment.text) {
                    self.add_text_match(
                        &mut sink,
                        segment,
                        TextMatch {
                            category: "regex",
                            severity: FindingSeverity::High,
                            confidence: Some(1.0),
                            start: matched.start(),
                            end: matched.end(),
                        },
                    );
                }
            }
            for (pattern, expression) in &self.secrets {
                for matched in expression.find_iter(&segment.text) {
                    self.add_text_match(
                        &mut sink,
                        segment,
                        TextMatch {
                            category: pattern.category(),
                            severity: FindingSeverity::Critical,
                            confidence: Some(0.99),
                            start: matched.start(),
                            end: matched.end(),
                        },
                    );
                }
            }
        }

        // JSON constraints are evaluated per segment: each JSON-valued segment
        // is a self-contained document and must never be concatenated with a
        // neighbour before parsing.
        if let Some(json) = &self.json {
            for segment in &selected {
                evaluate_json_segment(self, json, segment, "json", &mut sink.findings);
            }
        }

        if let Some(request) = &self.request {
            evaluate_request_constraints(self, request, input, &selected, &mut sink.findings);
        }
        let TextMatchSink {
            findings, patches, ..
        } = sink;
        Ok(DetectorResult {
            verdict: if findings.is_empty() {
                DetectorVerdict::Pass
            } else {
                DetectorVerdict::Fail
            },
            findings,
            patches,
            detector_version: DETERMINISTIC_VERSION.to_string(),
        })
    }
}

fn evaluate_json_segment(
    detector: &DeterministicDetector,
    constraints: &CompiledJsonConstraints,
    segment: &ContentSegment,
    prefix: &str,
    findings: &mut Vec<Finding>,
) {
    let value = match serde_json::from_str::<Value>(&segment.text) {
        Ok(value) => value,
        Err(_) => {
            findings.push(detector.finding(
                format!("{prefix}.invalid"),
                FindingSeverity::High,
                Some(1.0),
                Some(segment),
                None,
                None,
            ));
            return;
        }
    };
    for failure in constraints.evaluate(&value) {
        findings.push(detector.finding(
            format!("{prefix}.{failure}"),
            FindingSeverity::High,
            Some(1.0),
            Some(segment),
            None,
            None,
        ));
    }
}

fn evaluate_request_constraints(
    detector: &DeterministicDetector,
    constraints: &CompiledRequestConstraints,
    input: &DetectorInput<'_>,
    selected: &[&ContentSegment],
    findings: &mut Vec<Finding>,
) {
    let definition = &constraints.definition;
    let endpoint_denied = !definition.allowed_endpoints.is_empty()
        && !definition.allowed_endpoints.contains(&input.protocol);
    add_context_finding(detector, findings, endpoint_denied, "request.endpoint");
    let model_denied = input.model.is_some_and(|model| {
        (!definition.allowed_models.is_empty()
            && !definition.allowed_models.iter().any(|v| v == model))
            || definition.forbidden_models.iter().any(|v| v == model)
    });
    add_context_finding(detector, findings, model_denied, "request.model");
    let provider_denied = input.provider.is_some_and(|provider| {
        (!definition.allowed_providers.is_empty()
            && !definition.allowed_providers.iter().any(|v| v == provider))
            || definition.forbidden_providers.iter().any(|v| v == provider)
    });
    add_context_finding(detector, findings, provider_denied, "request.provider");

    if let Some(metadata) = &constraints.metadata {
        for segment in selected
            .iter()
            .copied()
            .filter(|segment| segment.source == ContentSource::Metadata)
        {
            evaluate_json_segment(detector, metadata, segment, "metadata", findings);
        }
    }
    if let Some(tool_parameters) = &constraints.tool_parameters {
        for segment in selected
            .iter()
            .copied()
            .filter(|segment| segment.source == ContentSource::ToolArguments)
        {
            evaluate_json_segment(
                detector,
                tool_parameters,
                segment,
                "tool_parameters",
                findings,
            );
        }
    }
}

fn add_context_finding(
    detector: &DeterministicDetector,
    findings: &mut Vec<Finding>,
    denied: bool,
    category: &str,
) {
    if denied {
        findings.push(detector.finding(
            category,
            FindingSeverity::High,
            Some(1.0),
            None,
            None,
            None,
        ));
    }
}

fn is_mutable_text_segment(segment: &ContentSegment) -> bool {
    matches!(
        segment.source,
        ContentSource::System
            | ContentSource::Developer
            | ContentSource::User
            | ContentSource::Assistant
            | ContentSource::ToolResult
            | ContentSource::TextAttachment
    ) && matches!(
        segment.content_type,
        SegmentContentType::Text | SegmentContentType::TextAttachment
    )
}

fn validate_config(config: &DeterministicDetectorConfig) -> Result<(), DetectorError> {
    if config.id.trim().is_empty()
        || config.supported_sources.is_empty()
        || config.keywords.iter().any(String::is_empty)
        || config.max_input_bytes == Some(0)
        || config
            .supported_sources
            .iter()
            .collect::<HashSet<_>>()
            .len()
            != config.supported_sources.len()
        || config.secret_patterns.iter().collect::<HashSet<_>>().len()
            != config.secret_patterns.len()
    {
        return Err(invalid_config(
            "deterministic Guardrail id, limits, patterns, or sources are invalid",
        ));
    }
    if config.keywords.is_empty()
        && config.regex.is_empty()
        && config.max_input_bytes.is_none()
        && config.json.as_ref().is_none_or(JsonConstraints::is_empty)
        && config
            .request
            .as_ref()
            .is_none_or(RequestConstraints::is_empty)
        && config.secret_patterns.is_empty()
    {
        return Err(invalid_config(
            "deterministic Guardrail requires at least one constraint",
        ));
    }
    if !config.secret_patterns.is_empty() && config.fingerprint_key.is_none() {
        return Err(invalid_config(
            "secret detection requires fingerprint_secret_ref for keyed evidence",
        ));
    }
    if let Some(json) = &config.json {
        json.validate("json")?;
    }
    if let Some(request) = &config.request {
        request.validate()?;
    }
    Ok(())
}

fn validate_json_pointers(pointers: &[String], name: &str) -> Result<(), DetectorError> {
    if pointers
        .iter()
        .any(|pointer| !pointer.is_empty() && !pointer.starts_with('/'))
    {
        return Err(invalid_config(match name {
            "metadata" => "metadata key constraints must use RFC 6901 JSON pointers",
            "tool_parameters" => "tool parameter key constraints must use RFC 6901 JSON pointers",
            _ => "JSON key constraints must use RFC 6901 JSON pointers",
        }));
    }
    Ok(())
}

fn invalid_config(message: &'static str) -> DetectorError {
    DetectorError::new(DetectorErrorKind::InvalidConfiguration, message)
}
