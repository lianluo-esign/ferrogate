// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Boundary and adversarial coverage for deterministic Guardrail checks.

use super::*;
use std::time::{Duration, Instant};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn config(sources: Vec<ContentSource>) -> DeterministicDetectorConfig {
    DeterministicDetectorConfig {
        id: "deterministic-test".to_string(),
        supported_sources: sources,
        keywords: Vec::new(),
        regex: Vec::new(),
        max_input_bytes: None,
        json: None,
        request: None,
        secret_patterns: Vec::new(),
        fingerprint_key: Some(DetectorSecret::new("test-hmac-key".to_string())),
    }
}

fn evaluate(
    detector: &DeterministicDetector,
    envelope: &GuardrailEnvelope,
    model: Option<&str>,
    provider: Option<&str>,
) -> Result<DetectorResult, DetectorError> {
    let text = envelope.flattened_text();
    runtime().block_on(detector.evaluate(
        &DetectorInput {
            protocol: envelope.protocol,
            stage: envelope.stage,
            tenant: DetectorTenant {
                organization_id: Some("org-test"),
                team_id: None,
                project_id: None,
                user_id: None,
                api_key_id: None,
            },
            model,
            provider,
            text: &text,
            segments: &envelope.segments,
        },
        Instant::now() + Duration::from_secs(1),
    ))
}

#[test]
fn legacy_contains_regex_and_size_are_compatible_and_boundary_exact() {
    let mut detector_config = config(vec![ContentSource::User]);
    detector_config.keywords = vec!["blocked".to_string()];
    detector_config.regex = vec![r"token-[0-9]+".to_string()];
    detector_config.max_input_bytes = Some(32);
    let detector = DeterministicDetector::new(detector_config).unwrap();

    let pass = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "safe",
    );
    assert_eq!(
        evaluate(&detector, &pass, Some("model"), Some("provider"))
            .unwrap()
            .verdict,
        DetectorVerdict::Pass
    );

    let boundary = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "x".repeat(32),
    );
    assert_eq!(
        evaluate(&detector, &boundary, None, None).unwrap().verdict,
        DetectorVerdict::Pass
    );

    let failed = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "blocked token-42 and blocked",
    );
    let result = evaluate(&detector, &failed, None, None).unwrap();
    assert_eq!(result.verdict, DetectorVerdict::Fail);
    assert_eq!(result.findings.len(), 3);
    assert!(result.findings.iter().all(|finding| {
        finding.matched_text.is_none()
            && finding
                .fingerprint
                .as_deref()
                .is_some_and(|value| value.starts_with("hmac-sha256:"))
    }));
}

#[test]
fn json_schema_required_forbidden_metadata_and_tool_parameters_are_structured() {
    let constraints = JsonConstraints {
        schema: Some(serde_json::json!({
            "type": "object",
            "properties": {"safe": {"type": "boolean"}},
            "required": ["safe"]
        })),
        required_keys: vec!["/safe".to_string()],
        forbidden_keys: vec!["/credential".to_string()],
    };
    let mut detector_config = config(vec![ContentSource::Metadata, ContentSource::ToolArguments]);
    detector_config.request = Some(RequestConstraints {
        metadata: Some(constraints.clone()),
        tool_parameters: Some(constraints),
        ..RequestConstraints::default()
    });
    let detector = DeterministicDetector::new(detector_config).unwrap();
    let envelope = normalize_request(
        GuardrailProtocol::ChatCompletions,
        &serde_json::json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{"function": {"arguments": "{\"credential\":\"not-a-substring-check\"}"}}]
            }],
            "metadata": {"safe": "not-a-boolean", "credential": "present"}
        }),
    );
    let result = evaluate(&detector, &envelope, None, None).unwrap();
    let categories = result
        .findings
        .iter()
        .map(|finding| finding.category.as_str())
        .collect::<Vec<_>>();
    assert!(categories.contains(&"metadata.json_schema"));
    assert!(categories.contains(&"metadata.forbidden_key"));
    assert!(categories.contains(&"tool_parameters.json_schema"));
    assert!(categories.contains(&"tool_parameters.required_key"));
    assert!(categories.contains(&"tool_parameters.forbidden_key"));

    let invalid = GuardrailEnvelope::from_text(
        GuardrailProtocol::Responses,
        DetectorStage::Request,
        ContentSource::ToolArguments,
        "input[0].arguments",
        "not json",
    );
    let result = evaluate(&detector, &invalid, None, None).unwrap();
    assert_eq!(result.findings[0].category, "tool_parameters.invalid");
}

#[test]
fn structured_constraints_pass_valid_endpoint_metadata_and_tool_boundaries() {
    let constraints = JsonConstraints {
        schema: Some(serde_json::json!({
            "type": "object",
            "properties": {"safe": {"type": "boolean"}},
            "required": ["safe"],
            "additionalProperties": false
        })),
        required_keys: vec!["/safe".to_string()],
        forbidden_keys: vec!["/credential".to_string()],
    };
    let mut detector_config = config(vec![ContentSource::Metadata, ContentSource::ToolArguments]);
    detector_config.request = Some(RequestConstraints {
        allowed_endpoints: vec![GuardrailProtocol::ChatCompletions],
        allowed_models: vec!["approved".to_string()],
        allowed_providers: vec!["approved-provider".to_string()],
        metadata: Some(constraints.clone()),
        tool_parameters: Some(constraints),
        ..RequestConstraints::default()
    });
    let detector = DeterministicDetector::new(detector_config).unwrap();
    let envelope = normalize_request(
        GuardrailProtocol::ChatCompletions,
        &serde_json::json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{"function": {"arguments": "{\"safe\":true}"}}]
            }],
            "metadata": {"safe": true}
        }),
    );
    assert_eq!(
        evaluate(
            &detector,
            &envelope,
            Some("approved"),
            Some("approved-provider")
        )
        .unwrap()
        .verdict,
        DetectorVerdict::Pass
    );
}

#[test]
fn endpoint_model_and_provider_constraints_use_typed_context() {
    let mut detector_config = config(vec![ContentSource::User]);
    detector_config.request = Some(RequestConstraints {
        allowed_endpoints: vec![GuardrailProtocol::Responses],
        allowed_models: vec!["approved".to_string()],
        forbidden_models: vec!["forbidden".to_string()],
        allowed_providers: vec!["approved-provider".to_string()],
        forbidden_providers: vec!["forbidden-provider".to_string()],
        ..RequestConstraints::default()
    });
    let detector = DeterministicDetector::new(detector_config).unwrap();
    let envelope = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "safe",
    );
    let result = evaluate(
        &detector,
        &envelope,
        Some("forbidden"),
        Some("forbidden-provider"),
    )
    .unwrap();
    let categories = result
        .findings
        .iter()
        .map(|finding| finding.category.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        categories,
        vec!["request.endpoint", "request.model", "request.provider"]
    );
}

#[test]
fn versioned_secret_patterns_return_only_hmac_evidence_and_safe_patches() {
    let openai = format!("sk-proj-{}", "A".repeat(40));
    let github = format!("ghp_{}", "B".repeat(36));
    let aws = format!("AKIA{}", "C".repeat(16));
    let text = format!("keys: {openai} and {github} and {aws}");
    let envelope = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Response,
        ContentSource::Assistant,
        "choices[0].message.content",
        &text,
    );
    let mut detector_config = config(vec![ContentSource::Assistant]);
    detector_config.secret_patterns = vec![
        SecretPattern::OpenAiApiKey,
        SecretPattern::GithubToken,
        SecretPattern::AwsAccessKeyId,
    ];
    let detector = DeterministicDetector::new(detector_config).unwrap();
    let result = evaluate(&detector, &envelope, None, None).unwrap();
    assert_eq!(result.detector_version, "deterministic/1");
    assert_eq!(result.findings.len(), 3);
    assert_eq!(result.patches.len(), 3);
    let serialized = serde_json::to_string(&result).unwrap();
    assert!(!serialized.contains(&openai));
    assert!(!serialized.contains(&github));
    assert!(!serialized.contains(&aws));
    assert!(serialized.contains("hmac-sha256:"));

    let below_boundary = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Response,
        ContentSource::Assistant,
        "choices[0].message.content",
        format!(
            "sk-proj-{} ghp_{} AKIA{}",
            "A".repeat(31),
            "B".repeat(35),
            "C".repeat(15)
        ),
    );
    assert_eq!(
        evaluate(&detector, &below_boundary, None, None)
            .unwrap()
            .verdict,
        DetectorVerdict::Pass
    );
}

#[test]
fn responses_patch_mutates_only_the_exact_output_text_field() {
    let document = serde_json::json!({
        "id": "resp-protected",
        "model": "model-protected",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "secret value"}]
        }],
        "usage": {"total_tokens": 7}
    });
    let bytes = serde_json::to_vec(&document).unwrap();
    let envelope = normalize_response(GuardrailProtocol::Responses, &bytes, false);
    let mut detector_config = config(vec![ContentSource::Assistant]);
    detector_config.keywords = vec!["secret".to_string()];
    let detector = DeterministicDetector::new(detector_config).unwrap();
    let result = evaluate(&detector, &envelope, None, None).unwrap();
    let transformed = apply_content_patches_to_document(
        &document,
        &envelope,
        &[ContentSource::Assistant],
        &result.patches,
    )
    .unwrap();
    assert_eq!(
        transformed["output"][0]["content"][0]["text"],
        "[REDACTED] value"
    );
    assert_eq!(transformed["id"], "resp-protected");
    assert_eq!(transformed["model"], "model-protected");
    assert_eq!(transformed["usage"]["total_tokens"], 7);
}

#[test]
fn patches_preserve_model_and_reject_protected_or_escaped_paths() {
    let response = serde_json::json!({
        "model": "protected-model",
        "choices": [{"message": {"role": "assistant", "content": "secret value"}}],
        "usage": {"total_tokens": 9}
    });
    let bytes = serde_json::to_vec(&response).unwrap();
    let envelope = normalize_response(GuardrailProtocol::ChatCompletions, &bytes, false);
    let segment = &envelope.segments[0];
    let patch = ContentPatch {
        segment_id: segment.segment_id.clone(),
        expected_fingerprint: segment.fingerprint.clone(),
        protocol_location: segment.protocol_location.clone(),
        byte_start: 0,
        byte_end: 6,
        replacement: "[REDACTED]".to_string(),
    };
    let transformed = apply_content_patches_to_document(
        &response,
        &envelope,
        &[ContentSource::Assistant],
        &[patch.clone()],
    )
    .unwrap();
    assert_eq!(transformed["model"], "protected-model");
    assert_eq!(transformed["usage"]["total_tokens"], 9);
    assert_eq!(
        transformed["choices"][0]["message"]["content"],
        "[REDACTED] value"
    );

    let mut escaped = patch;
    escaped.protocol_location = "model".to_string();
    assert_eq!(
        validate_content_patches_for_segments(&envelope.segments, &[escaped])
            .unwrap_err()
            .kind,
        DetectorErrorKind::InvalidPatch
    );

    let request = serde_json::json!({
        "model": "protected-model",
        "messages": [{
            "role": "assistant",
            "tool_calls": [{"function": {"arguments": "{\"credential\":\"secret\"}"}}]
        }],
        "tools": [{"type": "function", "function": {"name": "protected", "parameters": {}}}],
        "metadata": {"credential": "secret"}
    });
    let envelope = normalize_request(GuardrailProtocol::ChatCompletions, &request);
    for segment in &envelope.segments {
        let protected_patch = ContentPatch {
            segment_id: segment.segment_id.clone(),
            expected_fingerprint: segment.fingerprint.clone(),
            protocol_location: segment.protocol_location.clone(),
            byte_start: 0,
            byte_end: segment.text.len(),
            replacement: "changed".to_string(),
        };
        assert_eq!(
            validate_content_patch_permissions(&envelope, &[segment.source], &[protected_patch])
                .unwrap_err()
                .kind,
            DetectorErrorKind::ProtectedPath
        );
    }
}

#[test]
fn invalid_config_and_expired_deadline_are_explicit_errors() {
    let mut missing_key = config(vec![ContentSource::User]);
    missing_key.secret_patterns = vec![SecretPattern::AwsAccessKeyId];
    missing_key.fingerprint_key = None;
    assert_eq!(
        DeterministicDetector::new(missing_key).unwrap_err().kind,
        DetectorErrorKind::InvalidConfiguration
    );

    let mut valid = config(vec![ContentSource::User]);
    valid.keywords = vec!["x".to_string()];
    let detector = DeterministicDetector::new(valid).unwrap();
    let envelope = GuardrailEnvelope::from_text(
        GuardrailProtocol::ChatCompletions,
        DetectorStage::Request,
        ContentSource::User,
        "messages[0].content",
        "x",
    );
    let text = envelope.flattened_text();
    let error = runtime()
        .block_on(detector.evaluate(
            &DetectorInput {
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
                text: &text,
                segments: &envelope.segments,
            },
            Instant::now(),
        ))
        .unwrap_err();
    assert_eq!(error.kind, DetectorErrorKind::Timeout);
}
