// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for guardrail envelopes, kept outside business logic.

use super::*;
use serde_json::json;

#[test]
fn chat_request_extracts_all_roles_tools_and_utf8_ranges_stably() {
    let body = json!({
        "messages": [
            {"role": "system", "content": "保密 system"},
            {"role": "developer", "content": "developer"},
            {"role": "user", "content": [
                {"type": "text", "text": "user"},
                {"type": "input_file", "media_type": "text/plain", "text": "attachment"}
            ]},
            {"role": "assistant", "tool_calls": [{"function": {"arguments": "{\"secret\":true}"}}]},
            {"role": "tool", "content": "tool result"}
        ],
        "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}],
        "metadata": {"case": "42"}
    });
    let envelope = normalize_request(GuardrailProtocol::ChatCompletions, &body);
    let sources = envelope
        .segments
        .iter()
        .map(|segment| segment.source)
        .collect::<Vec<_>>();
    for source in [
        ContentSource::System,
        ContentSource::Developer,
        ContentSource::User,
        ContentSource::TextAttachment,
        ContentSource::ToolArguments,
        ContentSource::ToolResult,
        ContentSource::ToolSchema,
        ContentSource::Metadata,
    ] {
        assert!(sources.contains(&source), "missing {source:?}");
    }
    assert!(envelope
        .segments
        .iter()
        .all(|segment| segment.fingerprint.starts_with("sha256:")));
    let system = &envelope.segments[0];
    assert_eq!(&system.text[0..6], "保密");
}

#[test]
fn responses_request_extracts_instructions_input_and_tool_items() {
    let envelope = normalize_request(
        GuardrailProtocol::Responses,
        &json!({
            "instructions": "developer instruction",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hello"}]},
                {"type": "function_call", "arguments": "{\"city\":\"Paris\"}"},
                {"type": "function_call_output", "output": "sunny"}
            ],
            "tools": [{"type": "function", "name": "weather"}]
        }),
    );
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.source == ContentSource::Developer));
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.source == ContentSource::ToolArguments));
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.source == ContentSource::ToolResult));
}

#[test]
fn embeddings_request_extracts_string_input_and_metadata() {
    let envelope = normalize_request(
        GuardrailProtocol::Embeddings,
        &json!({
            "model": "text-embedding-3-small",
            "input": "embed this",
            "metadata": {"case": "42"}
        }),
    );
    assert_eq!(envelope.segments.len(), 2);
    assert_eq!(envelope.segments[0].source, ContentSource::User);
    assert_eq!(envelope.segments[0].text, "embed this");
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.source == ContentSource::Metadata));
}

#[test]
fn embeddings_request_extracts_each_batch_item_as_its_own_segment() {
    let envelope = normalize_request(
        GuardrailProtocol::Embeddings,
        &json!({
            "model": "text-embedding-3-small",
            "input": ["first", "second", "third"]
        }),
    );
    let texts = envelope
        .segments
        .iter()
        .map(|segment| segment.text.as_str())
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["first", "second", "third"]);
    assert!(envelope
        .segments
        .iter()
        .all(|segment| segment.source == ContentSource::User));
}

#[test]
fn embeddings_response_is_never_normalized_into_content_segments() {
    // Embeddings have no model-generated text; normalize_response's raw-body
    // fallback would otherwise mistake the numeric embedding vector for
    // assistant text (issue #207) -- callers must never invoke this for
    // GuardrailProtocol::Embeddings, but the match itself stays a no-op for
    // safety if one ever did.
    let envelope = normalize_response(
        GuardrailProtocol::Embeddings,
        br#"{"data":[{"embedding":[0.1,0.2,0.3]}]}"#,
        false,
    );
    assert!(envelope.segments.is_empty());
}

#[test]
fn sse_deltas_are_assembled_before_fingerprinting() {
    let body = br#"data: {"choices":[{"delta":{"content":"split-sec"}}]}

data: {"choices":[{"delta":{"content":"ret"}}]}

data: [DONE]

"#;
    let envelope = normalize_response(GuardrailProtocol::ChatCompletions, body, true);
    assert_eq!(envelope.segments.len(), 1);
    assert_eq!(envelope.segments[0].text, "split-secret");
}

#[test]
fn responses_sse_assembles_text_and_function_arguments() {
    let body = br#"event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"hello "}

event: response.output_text.delta
data: {"type":"response.output_text.delta","delta":"world"}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","index":0,"delta":"{\"a\":"}

event: response.function_call_arguments.delta
data: {"type":"response.function_call_arguments.delta","index":0,"delta":"1}"}

"#;
    let envelope = normalize_response(GuardrailProtocol::Responses, body, true);
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.text == "hello world"));
    assert!(envelope
        .segments
        .iter()
        .any(|segment| segment.text == "{\"a\":1}"));
}

#[test]
fn managed_action_input_envelope_is_tool_arguments() {
    // #200: an action's input arguments become a ToolArguments segment under
    // the ManagedAction protocol at the Request stage.
    let envelope = GuardrailEnvelope::managed_action(
        DetectorStage::Request,
        "mcp:github/create_issue/arguments",
        r#"{"title":"leak","body":"sk-secret"}"#,
    );
    assert_eq!(envelope.protocol, GuardrailProtocol::ManagedAction);
    assert_eq!(envelope.stage, DetectorStage::Request);
    assert_eq!(envelope.segments.len(), 1);
    let segment = &envelope.segments[0];
    assert_eq!(segment.source, ContentSource::ToolArguments);
    assert_eq!(
        segment.protocol_location,
        "mcp:github/create_issue/arguments"
    );
    assert!(envelope.flattened_text().contains("sk-secret"));
}

#[test]
fn managed_action_output_envelope_is_tool_result() {
    // #200: an action's result becomes a ToolResult segment at the Response
    // stage (output guardrail — quarantine/redact before it reaches the model).
    let envelope = GuardrailEnvelope::managed_action(
        DetectorStage::Response,
        "cli:bash/result",
        "total 4\n-rw------- 1 root root /etc/shadow",
    );
    assert_eq!(envelope.protocol, GuardrailProtocol::ManagedAction);
    assert_eq!(envelope.stage, DetectorStage::Response);
    assert_eq!(envelope.segments[0].source, ContentSource::ToolResult);
    assert!(envelope.flattened_text().contains("/etc/shadow"));
}

#[test]
fn managed_action_envelope_is_never_produced_by_http_extractors() {
    // Managed actions are built directly; the HTTP normalizers yield an empty
    // envelope for the ManagedAction protocol (they are never called for it).
    let req = normalize_request(
        GuardrailProtocol::ManagedAction,
        &serde_json::json!({"a":1}),
    );
    assert!(req.segments.is_empty());
    let resp = normalize_response(GuardrailProtocol::ManagedAction, b"{\"a\":1}", false);
    assert!(resp.segments.is_empty());
}
