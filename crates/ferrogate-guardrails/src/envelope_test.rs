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
