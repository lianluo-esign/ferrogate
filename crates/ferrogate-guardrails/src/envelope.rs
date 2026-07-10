// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-10
// description: Protocol-normalized Guardrail content envelopes for Chat Completions and Responses.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::DetectorStage;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailProtocol {
    ChatCompletions,
    Responses,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContentSource {
    System,
    Developer,
    User,
    Assistant,
    ToolSchema,
    ToolArguments,
    ToolResult,
    Metadata,
    TextAttachment,
    Unknown,
}

pub const ALL_CONTENT_SOURCES: [ContentSource; 10] = [
    ContentSource::System,
    ContentSource::Developer,
    ContentSource::User,
    ContentSource::Assistant,
    ContentSource::ToolSchema,
    ContentSource::ToolArguments,
    ContentSource::ToolResult,
    ContentSource::Metadata,
    ContentSource::TextAttachment,
    ContentSource::Unknown,
];

pub fn all_content_sources() -> Vec<ContentSource> {
    ALL_CONTENT_SOURCES.to_vec()
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SegmentContentType {
    Text,
    Json,
    TextAttachment,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContentSegment {
    pub segment_id: String,
    pub source: ContentSource,
    pub protocol_location: String,
    pub content_type: SegmentContentType,
    pub text: String,
    pub fingerprint: String,
}

impl ContentSegment {
    fn new(
        segment_id: impl Into<String>,
        source: ContentSource,
        protocol_location: impl Into<String>,
        content_type: SegmentContentType,
        text: impl Into<String>,
    ) -> Self {
        let text = text.into();
        Self {
            segment_id: segment_id.into(),
            source,
            protocol_location: protocol_location.into(),
            content_type,
            fingerprint: fingerprint(&text),
            text,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GuardrailEnvelope {
    pub protocol: GuardrailProtocol,
    pub stage: DetectorStage,
    pub segments: Vec<ContentSegment>,
}

impl GuardrailEnvelope {
    pub fn from_text(
        protocol: GuardrailProtocol,
        stage: DetectorStage,
        source: ContentSource,
        protocol_location: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        let protocol_location = protocol_location.into();
        Self {
            protocol,
            stage,
            segments: vec![ContentSegment::new(
                format!("{}:0", protocol_name(protocol)),
                source,
                protocol_location,
                SegmentContentType::Text,
                text,
            )],
        }
    }

    pub fn flattened_text(&self) -> String {
        self.segments
            .iter()
            .map(|segment| segment.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn total_text_bytes(&self) -> usize {
        self.segments.iter().map(|segment| segment.text.len()).sum()
    }
}

pub fn normalize_request(protocol: GuardrailProtocol, body: &Value) -> GuardrailEnvelope {
    let mut builder = EnvelopeBuilder::new(protocol, DetectorStage::Request);
    match protocol {
        GuardrailProtocol::ChatCompletions => extract_chat_request(body, &mut builder),
        GuardrailProtocol::Responses => extract_responses_request(body, &mut builder),
    }
    builder.finish()
}

pub fn normalize_response(
    protocol: GuardrailProtocol,
    body: &[u8],
    streaming: bool,
) -> GuardrailEnvelope {
    let mut builder = EnvelopeBuilder::new(protocol, DetectorStage::Response);
    if streaming {
        extract_sse(protocol, body, &mut builder);
    } else if let Ok(value) = serde_json::from_slice::<Value>(body) {
        match protocol {
            GuardrailProtocol::ChatCompletions => extract_chat_response(&value, &mut builder),
            GuardrailProtocol::Responses => extract_responses_response(&value, &mut builder),
        }
    }
    if builder.is_empty() && !body.is_empty() {
        builder.push(
            ContentSource::Assistant,
            "response.raw",
            SegmentContentType::Text,
            String::from_utf8_lossy(body),
        );
    }
    builder.finish()
}

struct EnvelopeBuilder {
    protocol: GuardrailProtocol,
    stage: DetectorStage,
    segments: Vec<ContentSegment>,
}

impl EnvelopeBuilder {
    fn new(protocol: GuardrailProtocol, stage: DetectorStage) -> Self {
        Self {
            protocol,
            stage,
            segments: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    fn push(
        &mut self,
        source: ContentSource,
        location: impl Into<String>,
        content_type: SegmentContentType,
        text: impl Into<String>,
    ) {
        let text = text.into();
        if text.is_empty() {
            return;
        }
        let index = self.segments.len();
        let location = location.into();
        self.segments.push(ContentSegment::new(
            format!("{}:{index}", protocol_name(self.protocol)),
            source,
            location,
            content_type,
            text,
        ));
    }

    fn finish(self) -> GuardrailEnvelope {
        GuardrailEnvelope {
            protocol: self.protocol,
            stage: self.stage,
            segments: self.segments,
        }
    }
}

fn extract_chat_request(body: &Value, builder: &mut EnvelopeBuilder) {
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for (message_index, message) in messages.iter().enumerate() {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let source = source_for_role(role);
            extract_content(
                message.get("content"),
                source,
                &format!("messages[{message_index}].content"),
                builder,
            );
            extract_tool_calls(
                message.get("tool_calls"),
                &format!("messages[{message_index}].tool_calls"),
                builder,
            );
        }
    }
    extract_tools(body.get("tools"), "tools", builder);
    extract_metadata(body.get("metadata"), builder);
}

fn extract_responses_request(body: &Value, builder: &mut EnvelopeBuilder) {
    if let Some(instructions) = body.get("instructions").and_then(Value::as_str) {
        builder.push(
            ContentSource::Developer,
            "instructions",
            SegmentContentType::Text,
            instructions,
        );
    }
    match body.get("input") {
        Some(Value::String(text)) => {
            builder.push(ContentSource::User, "input", SegmentContentType::Text, text)
        }
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                extract_responses_item(item, &format!("input[{index}]"), builder);
            }
        }
        _ => {}
    }
    extract_tools(body.get("tools"), "tools", builder);
    extract_metadata(body.get("metadata"), builder);
}

fn extract_chat_response(body: &Value, builder: &mut EnvelopeBuilder) {
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        for (choice_index, choice) in choices.iter().enumerate() {
            let message = choice.get("message").or_else(|| choice.get("delta"));
            let source = message
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
                .map(source_for_role)
                .unwrap_or(ContentSource::Assistant);
            extract_content(
                message.and_then(|message| message.get("content")),
                source,
                &format!("choices[{choice_index}].message.content"),
                builder,
            );
            extract_tool_calls(
                message.and_then(|message| message.get("tool_calls")),
                &format!("choices[{choice_index}].message.tool_calls"),
                builder,
            );
        }
    }
}

fn extract_responses_response(body: &Value, builder: &mut EnvelopeBuilder) {
    if let Some(output) = body.get("output").and_then(Value::as_array) {
        for (index, item) in output.iter().enumerate() {
            extract_responses_item(item, &format!("output[{index}]"), builder);
        }
    } else if let Some(text) = body.get("output_text").and_then(Value::as_str) {
        builder.push(
            ContentSource::Assistant,
            "output_text",
            SegmentContentType::Text,
            text,
        );
    }
}

fn extract_responses_item(item: &Value, location: &str, builder: &mut EnvelopeBuilder) {
    let item_type = item
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("message");
    match item_type {
        "function_call" => {
            if let Some(arguments) = item.get("arguments").and_then(Value::as_str) {
                builder.push(
                    ContentSource::ToolArguments,
                    format!("{location}.arguments"),
                    SegmentContentType::Json,
                    arguments,
                );
            }
        }
        "function_call_output" => {
            extract_content(
                item.get("output"),
                ContentSource::ToolResult,
                &format!("{location}.output"),
                builder,
            );
        }
        _ => {
            let source = item
                .get("role")
                .and_then(Value::as_str)
                .map(source_for_role)
                .unwrap_or(ContentSource::User);
            extract_content(
                item.get("content"),
                source,
                &format!("{location}.content"),
                builder,
            );
        }
    }
}

fn extract_content(
    content: Option<&Value>,
    source: ContentSource,
    location: &str,
    builder: &mut EnvelopeBuilder,
) {
    match content {
        Some(Value::String(text)) => {
            let source = if source == ContentSource::ToolResult {
                ContentSource::ToolResult
            } else {
                source
            };
            builder.push(source, location, SegmentContentType::Text, text);
        }
        Some(Value::Array(parts)) => {
            for (part_index, part) in parts.iter().enumerate() {
                let part_type = part.get("type").and_then(Value::as_str).unwrap_or("text");
                let part_location = format!("{location}[{part_index}]");
                match part_type {
                    "text" | "input_text" | "output_text" => {
                        if let Some(text) = part.get("text").and_then(Value::as_str) {
                            builder.push(source, part_location, SegmentContentType::Text, text);
                        }
                    }
                    "input_file" | "file" => {
                        let media_type = part
                            .get("media_type")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if media_type.starts_with("text/") {
                            if let Some(text) = part
                                .get("text")
                                .or_else(|| part.get("file_data"))
                                .and_then(Value::as_str)
                            {
                                builder.push(
                                    ContentSource::TextAttachment,
                                    part_location,
                                    SegmentContentType::TextAttachment,
                                    text,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Some(value) if source == ContentSource::ToolResult => {
            if let Ok(text) = serde_json::to_string(value) {
                builder.push(source, location, SegmentContentType::Json, text);
            }
        }
        _ => {}
    }
}

fn extract_tool_calls(calls: Option<&Value>, location: &str, builder: &mut EnvelopeBuilder) {
    let Some(calls) = calls.and_then(Value::as_array) else {
        return;
    };
    for (index, call) in calls.iter().enumerate() {
        if let Some(arguments) = call
            .get("function")
            .and_then(|function| function.get("arguments"))
            .and_then(Value::as_str)
        {
            builder.push(
                ContentSource::ToolArguments,
                format!("{location}[{index}].function.arguments"),
                SegmentContentType::Json,
                arguments,
            );
        }
    }
}

fn extract_tools(tools: Option<&Value>, location: &str, builder: &mut EnvelopeBuilder) {
    let Some(tools) = tools.and_then(Value::as_array) else {
        return;
    };
    for (index, tool) in tools.iter().enumerate() {
        if let Ok(text) = serde_json::to_string(tool) {
            builder.push(
                ContentSource::ToolSchema,
                format!("{location}[{index}]"),
                SegmentContentType::Json,
                text,
            );
        }
    }
}

fn extract_metadata(metadata: Option<&Value>, builder: &mut EnvelopeBuilder) {
    let Some(metadata) = metadata.filter(|metadata| !metadata.is_null()) else {
        return;
    };
    if let Ok(text) = serde_json::to_string(metadata) {
        builder.push(
            ContentSource::Metadata,
            "metadata",
            SegmentContentType::Json,
            text,
        );
    }
}

fn extract_sse(protocol: GuardrailProtocol, body: &[u8], builder: &mut EnvelopeBuilder) {
    let normalized = String::from_utf8_lossy(body).replace("\r\n", "\n");
    let mut accumulated: BTreeMap<(ContentSource, String), String> = BTreeMap::new();
    for frame in normalized.split("\n\n") {
        let mut event = None;
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event = Some(value.trim());
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.trim_start());
            }
        }
        let data = data.join("\n");
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        match protocol {
            GuardrailProtocol::ChatCompletions => accumulate_chat_sse(&value, &mut accumulated),
            GuardrailProtocol::Responses => {
                accumulate_responses_sse(event, &value, &mut accumulated)
            }
        }
    }
    for ((source, location), text) in accumulated {
        let content_type = if source == ContentSource::ToolArguments {
            SegmentContentType::Json
        } else {
            SegmentContentType::Text
        };
        builder.push(source, location, content_type, text);
    }
}

fn accumulate_chat_sse(value: &Value, accumulated: &mut BTreeMap<(ContentSource, String), String>) {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return;
    };
    for (choice_index, choice) in choices.iter().enumerate() {
        let Some(delta) = choice.get("delta") else {
            continue;
        };
        if let Some(content) = delta.get("content").and_then(Value::as_str) {
            accumulated
                .entry((
                    ContentSource::Assistant,
                    format!("choices[{choice_index}].delta.content"),
                ))
                .or_default()
                .push_str(content);
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for (call_offset, call) in calls.iter().enumerate() {
                let call_index = call
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(call_offset as u64);
                if let Some(arguments) = call
                    .get("function")
                    .and_then(|function| function.get("arguments"))
                    .and_then(Value::as_str)
                {
                    accumulated
                        .entry((
                            ContentSource::ToolArguments,
                            format!(
                                "choices[{choice_index}].delta.tool_calls[{call_index}].function.arguments"
                            ),
                        ))
                        .or_default()
                        .push_str(arguments);
                }
            }
        }
    }
}

fn accumulate_responses_sse(
    event: Option<&str>,
    value: &Value,
    accumulated: &mut BTreeMap<(ContentSource, String), String>,
) {
    let event_type = value.get("type").and_then(Value::as_str).or(event);
    match event_type {
        Some("response.output_text.delta") => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                let output = value
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let content = value
                    .get("content_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                accumulated
                    .entry((
                        ContentSource::Assistant,
                        format!("output[{output}].content[{content}].text"),
                    ))
                    .or_default()
                    .push_str(delta);
            }
        }
        Some("response.function_call_arguments.delta") => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
                accumulated
                    .entry((
                        ContentSource::ToolArguments,
                        format!("output[{index}].arguments"),
                    ))
                    .or_default()
                    .push_str(delta);
            }
        }
        _ => {}
    }
}

fn source_for_role(role: &str) -> ContentSource {
    match role {
        "system" => ContentSource::System,
        "developer" => ContentSource::Developer,
        "user" => ContentSource::User,
        "assistant" => ContentSource::Assistant,
        "tool" | "function" => ContentSource::ToolResult,
        _ => ContentSource::Unknown,
    }
}

fn protocol_name(protocol: GuardrailProtocol) -> &'static str {
    match protocol {
        GuardrailProtocol::ChatCompletions => "chat",
        GuardrailProtocol::Responses => "responses",
    }
}

fn fingerprint(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    format!("sha256:{encoded}")
}

#[cfg(test)]
mod tests {
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
}
