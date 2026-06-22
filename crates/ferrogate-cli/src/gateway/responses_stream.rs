// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Error as IoError, Read},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponsesStreamProviderKind {
    OpenAiCompatible,
    Anthropic,
    Gemini,
    Other,
}

#[derive(Debug)]
pub(super) struct ResponsesStreamNormalizer<R> {
    reader: R,
    provider_kind: ResponsesStreamProviderKind,
    request_id: String,
    content_type: String,
    buffer: String,
    output: Vec<u8>,
    output_offset: usize,
    eof: bool,
    completed: bool,
    saw_text_delta: bool,
    saw_function_call_delta: bool,
    function_calls: BTreeMap<u64, FunctionCallState>,
    usage: ProviderUsageState,
}

#[derive(Debug, Default, Clone, Copy)]
struct ProviderUsageState {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

#[derive(Debug, Default, Clone)]
struct FunctionCallState {
    call_id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ProviderUsageState {
    fn update_from_value(&mut self, value: &Value, provider_kind: ResponsesStreamProviderKind) {
        match provider_kind {
            ResponsesStreamProviderKind::Anthropic => {
                if let Some(usage) = value.get("usage") {
                    self.prompt_tokens = usage.get("input_tokens").and_then(Value::as_u64);
                    self.completion_tokens = usage.get("output_tokens").and_then(Value::as_u64);
                    self.total_tokens = self
                        .prompt_tokens
                        .zip(self.completion_tokens)
                        .map(|(left, right)| left + right);
                }
            }
            ResponsesStreamProviderKind::Gemini => {
                if let Some(usage) = value.get("usageMetadata") {
                    self.prompt_tokens = usage.get("promptTokenCount").and_then(Value::as_u64);
                    self.completion_tokens =
                        usage.get("candidatesTokenCount").and_then(Value::as_u64);
                    self.total_tokens = usage.get("totalTokenCount").and_then(Value::as_u64);
                }
            }
            ResponsesStreamProviderKind::OpenAiCompatible | ResponsesStreamProviderKind::Other => {
                if let Some(usage) = value.get("usage") {
                    self.prompt_tokens = usage.get("prompt_tokens").and_then(Value::as_u64);
                    self.completion_tokens = usage.get("completion_tokens").and_then(Value::as_u64);
                    self.total_tokens = usage.get("total_tokens").and_then(Value::as_u64);
                }
            }
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        })
    }
}

impl<R: Read> ResponsesStreamNormalizer<R> {
    pub(super) fn new(
        reader: R,
        provider_kind: ResponsesStreamProviderKind,
        request_id: impl Into<String>,
        content_type: impl Into<String>,
    ) -> Self {
        Self {
            reader,
            provider_kind,
            request_id: request_id.into(),
            content_type: content_type.into(),
            buffer: String::new(),
            output: Vec::new(),
            output_offset: 0,
            eof: false,
            completed: false,
            saw_text_delta: false,
            saw_function_call_delta: false,
            function_calls: BTreeMap::new(),
            usage: ProviderUsageState::default(),
        }
    }

    fn queue_event(&mut self, event: Option<&str>, data: &str) {
        if let Some(event) = event {
            self.output.extend_from_slice(b"event: ");
            self.output.extend_from_slice(event.as_bytes());
            self.output.push(b'\n');
        }
        for line in data.split('\n') {
            self.output.extend_from_slice(b"data: ");
            self.output.extend_from_slice(line.as_bytes());
            self.output.push(b'\n');
        }
        self.output.push(b'\n');
    }

    fn queue_json_event(&mut self, event: &str, value: Value) {
        let data = serde_json::to_string(&value).expect("JSON serialization should not fail");
        self.queue_event(Some(event), &data);
    }

    fn queue_data_event(&mut self, data: &str) {
        self.queue_event(None, data);
    }

    fn finish_stream(&mut self) {
        if self.completed {
            return;
        }
        if self.saw_text_delta {
            self.queue_event(Some("response.output_text.done"), "{}");
        }
        if self.saw_function_call_delta {
            let function_calls = self
                .function_calls
                .iter()
                .map(|(index, call)| (*index, call.clone()))
                .collect::<Vec<_>>();
            for (index, call) in function_calls {
                self.queue_json_event(
                    "response.function_call_arguments.done",
                    json!({
                        "request_id": self.request_id,
                        "index": index,
                        "call_id": call.call_id,
                        "name": call.name,
                        "arguments": call.arguments,
                    }),
                );
            }
        }
        self.queue_json_event(
            "response.completed",
            json!({
                "request_id": self.request_id,
                "content_type": self.content_type,
                "usage": self.usage.as_json(),
            }),
        );
        self.queue_data_event("[DONE]");
        self.completed = true;
    }

    fn drain_frame(&mut self, frame: &str) {
        let mut event_name = None;
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event_name = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.trim_start().to_string());
            }
        }
        let data = data.join("\n");
        if data.is_empty() && event_name.is_none() {
            return;
        }
        if data.trim() == "[DONE]" {
            self.eof = true;
            return;
        }

        let parsed = serde_json::from_str::<Value>(&data).ok();
        if let Some(value) = parsed.as_ref() {
            self.usage.update_from_value(value, self.provider_kind);
        }

        if self.emit_error(event_name.as_deref(), parsed.as_ref()) {
            self.completed = true;
            return;
        }

        for delta in extract_text_deltas(self.provider_kind, event_name.as_deref(), parsed.as_ref())
        {
            self.saw_text_delta = true;
            self.queue_json_event(
                "response.output_text.delta",
                json!({
                    "request_id": self.request_id,
                    "delta": delta,
                }),
            );
        }

        for delta in extract_function_call_deltas(
            self.provider_kind,
            event_name.as_deref(),
            parsed.as_ref(),
            &mut self.function_calls,
        ) {
            self.saw_function_call_delta = true;
            self.queue_json_event(
                "response.function_call_arguments.delta",
                json!({
                    "request_id": self.request_id,
                    "index": delta.index,
                    "call_id": delta.call_id,
                    "name": delta.name,
                    "delta": delta.delta,
                }),
            );
        }

        if is_done_frame(self.provider_kind, event_name.as_deref(), parsed.as_ref()) {
            self.eof = true;
        }
    }

    fn emit_error(&mut self, event_name: Option<&str>, parsed: Option<&Value>) -> bool {
        if event_name != Some("error") && parsed.and_then(|value| value.get("error")).is_none() {
            return false;
        }
        let error = parsed.and_then(|value| value.get("error"));
        let message = error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .or_else(|| parsed.and_then(|value| value.as_str()))
            .unwrap_or("provider returned a streaming error")
            .to_string();
        let code = error
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .or_else(|| {
                error
                    .and_then(|error| error.get("type"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("provider_stream_error")
            .to_string();
        self.queue_json_event(
            "response.failed",
            json!({
                "request_id": self.request_id,
                "error": {
                    "message": message,
                    "type": "ferrogate_error",
                    "code": code,
                }
            }),
        );
        self.queue_data_event("[DONE]");
        true
    }
}

impl<R: Read> Read for ResponsesStreamNormalizer<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let available = self.output.len().saturating_sub(self.output_offset);
            if available > 0 {
                let read = available.min(buf.len());
                buf[..read]
                    .copy_from_slice(&self.output[self.output_offset..self.output_offset + read]);
                self.output_offset += read;
                if self.output_offset >= self.output.len() {
                    self.output.clear();
                    self.output_offset = 0;
                }
                return Ok(read);
            }

            if self.completed {
                return Ok(0);
            }

            if self.eof {
                self.finish_stream();
                continue;
            }

            let mut buffer = [0_u8; 8192];
            let read = self.reader.read(&mut buffer).map_err(|error| {
                IoError::other(format!("reading provider streaming response: {error}"))
            })?;
            if read == 0 {
                self.eof = true;
                if !self.buffer.is_empty() {
                    let frame = std::mem::take(&mut self.buffer);
                    self.drain_frame(&frame);
                }
                continue;
            }

            let chunk = String::from_utf8_lossy(&buffer[..read]);
            self.buffer.push_str(&chunk);
            if self.buffer.contains('\r') {
                self.buffer = self.buffer.replace("\r\n", "\n");
                self.buffer.retain(|ch| ch != '\r');
            }
            while let Some(frame_end) = self.buffer.find("\n\n") {
                let frame = self.buffer[..frame_end].to_string();
                self.buffer.drain(..frame_end + 2);
                self.drain_frame(&frame);
                if self.completed {
                    break;
                }
            }
        }
    }
}

fn is_done_frame(
    provider_kind: ResponsesStreamProviderKind,
    event_name: Option<&str>,
    parsed: Option<&Value>,
) -> bool {
    if event_name == Some("response.completed") || event_name == Some("message_stop") {
        return true;
    }
    if parsed.is_some_and(|value| {
        value.get("type").and_then(Value::as_str) == Some("response.completed")
    }) {
        return true;
    }
    if parsed.is_some_and(|value| value.get("finish_reason").is_some()) {
        return true;
    }
    match provider_kind {
        ResponsesStreamProviderKind::OpenAiCompatible
        | ResponsesStreamProviderKind::Anthropic
        | ResponsesStreamProviderKind::Gemini
        | ResponsesStreamProviderKind::Other => false,
    }
}

fn extract_text_deltas(
    provider_kind: ResponsesStreamProviderKind,
    event_name: Option<&str>,
    parsed: Option<&Value>,
) -> Vec<String> {
    let Some(value) = parsed else {
        return Vec::new();
    };

    match provider_kind {
        ResponsesStreamProviderKind::Anthropic => {
            if matches!(
                event_name,
                Some("content_block_delta") | Some("response.output_text.delta")
            ) {
                value
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                    .map(|text| vec![text.to_string()])
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        ResponsesStreamProviderKind::Gemini => value
            .get("candidates")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|candidate| candidate.get("content"))
            .filter_map(|content| content.get("parts"))
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(|part| part.get("text"))
            .filter_map(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        ResponsesStreamProviderKind::OpenAiCompatible | ResponsesStreamProviderKind::Other => {
            if let Some(output_text) = value.get("output_text").and_then(Value::as_str) {
                return if output_text.is_empty() {
                    Vec::new()
                } else {
                    vec![output_text.to_string()]
                };
            }
            value
                .get("choices")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|choice| choice.get("delta"))
                .flat_map(|delta| {
                    delta
                        .get("content")
                        .and_then(Value::as_str)
                        .map(|text| vec![text.to_string()])
                        .or_else(|| {
                            delta
                                .get("text")
                                .and_then(Value::as_str)
                                .map(|text| vec![text.to_string()])
                        })
                        .or_else(|| {
                            delta
                                .get("output_text")
                                .and_then(Value::as_str)
                                .map(|text| vec![text.to_string()])
                        })
                        .unwrap_or_default()
                })
                .filter(|text| !text.is_empty())
                .collect()
        }
    }
}

#[derive(Debug, Clone)]
struct FunctionCallDelta {
    index: u64,
    call_id: Option<String>,
    name: Option<String>,
    delta: String,
}

fn extract_function_call_deltas(
    provider_kind: ResponsesStreamProviderKind,
    event_name: Option<&str>,
    parsed: Option<&Value>,
    function_calls: &mut BTreeMap<u64, FunctionCallState>,
) -> Vec<FunctionCallDelta> {
    let Some(value) = parsed else {
        return Vec::new();
    };

    match provider_kind {
        ResponsesStreamProviderKind::OpenAiCompatible | ResponsesStreamProviderKind::Other => value
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .flat_map(|(choice_index, choice)| {
                let Some(delta) = choice.get("delta") else {
                    return Vec::new();
                };

                let mut deltas = Vec::new();
                if let Some(function_call) = delta.get("function_call") {
                    let index = choice_index as u64;
                    let entry = function_calls.entry(index).or_default();
                    if let Some(call_id) = function_call.get("id").and_then(Value::as_str) {
                        entry.call_id = Some(call_id.to_string());
                    }
                    if let Some(name) = function_call.get("name").and_then(Value::as_str) {
                        entry.name = Some(name.to_string());
                    }
                    if let Some(arguments) = function_call.get("arguments").and_then(Value::as_str)
                    {
                        if !arguments.is_empty() {
                            entry.arguments.push_str(arguments);
                            deltas.push(FunctionCallDelta {
                                index,
                                call_id: entry.call_id.clone(),
                                name: entry.name.clone(),
                                delta: arguments.to_string(),
                            });
                        }
                    }
                }

                if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    for (tool_index, tool_call) in tool_calls.iter().enumerate() {
                        let index = tool_call
                            .get("index")
                            .and_then(Value::as_u64)
                            .unwrap_or(choice_index as u64 + tool_index as u64);
                        let entry = function_calls.entry(index).or_default();
                        if let Some(call_id) = tool_call.get("id").and_then(Value::as_str) {
                            entry.call_id = Some(call_id.to_string());
                        }
                        if let Some(function) = tool_call.get("function") {
                            if let Some(name) = function.get("name").and_then(Value::as_str) {
                                entry.name = Some(name.to_string());
                            }
                            if let Some(arguments) =
                                function.get("arguments").and_then(Value::as_str)
                            {
                                if !arguments.is_empty() {
                                    entry.arguments.push_str(arguments);
                                    deltas.push(FunctionCallDelta {
                                        index,
                                        call_id: entry.call_id.clone(),
                                        name: entry.name.clone(),
                                        delta: arguments.to_string(),
                                    });
                                }
                            }
                        }
                    }
                }

                deltas
            })
            .collect(),
        ResponsesStreamProviderKind::Anthropic => {
            if matches!(
                event_name,
                Some("content_block_delta") | Some("response.output_item.delta")
            ) {
                if let Some(delta) = value.get("delta") {
                    let index = value
                        .get("index")
                        .and_then(Value::as_u64)
                        .unwrap_or_default();
                    let entry = function_calls.entry(index).or_default();
                    if let Some(call_id) = value.get("id").and_then(Value::as_str) {
                        entry.call_id = Some(call_id.to_string());
                    }
                    if let Some(name) = delta
                        .get("name")
                        .or_else(|| value.get("name"))
                        .and_then(Value::as_str)
                    {
                        entry.name = Some(name.to_string());
                    }
                    if let Some(arguments) = delta
                        .get("text")
                        .or_else(|| delta.get("input"))
                        .and_then(Value::as_str)
                        .filter(|arguments| !arguments.is_empty())
                    {
                        entry.arguments.push_str(arguments);
                        return vec![FunctionCallDelta {
                            index,
                            call_id: entry.call_id.clone(),
                            name: entry.name.clone(),
                            delta: arguments.to_string(),
                        }];
                    }
                }
            }
            Vec::new()
        }
        ResponsesStreamProviderKind::Gemini => {
            if matches!(
                event_name,
                Some("data") | Some("message") | Some("response.output_item.delta")
            ) {
                let mut deltas = Vec::new();
                if let Some(candidates) = value.get("candidates").and_then(Value::as_array) {
                    for (candidate_index, candidate) in candidates.iter().enumerate() {
                        if let Some(content) = candidate.get("content") {
                            if let Some(parts) = content.get("parts").and_then(Value::as_array) {
                                for (part_index, part) in parts.iter().enumerate() {
                                    let index = candidate_index as u64 + part_index as u64;
                                    let entry = function_calls.entry(index).or_default();
                                    if let Some(call_id) =
                                        part.get("functionCall").and_then(|value| value.get("id"))
                                    {
                                        if let Some(call_id) = call_id.as_str() {
                                            entry.call_id = Some(call_id.to_string());
                                        }
                                    }
                                    if let Some(name) = part
                                        .get("functionCall")
                                        .and_then(|value| value.get("name"))
                                        .and_then(Value::as_str)
                                    {
                                        entry.name = Some(name.to_string());
                                    }
                                    if let Some(args) = part
                                        .get("functionCall")
                                        .and_then(|value| value.get("args"))
                                        .or_else(|| {
                                            part.get("functionCall")
                                                .and_then(|value| value.get("arguments"))
                                        })
                                        .and_then(Value::as_str)
                                    {
                                        if !args.is_empty() {
                                            entry.arguments.push_str(args);
                                            deltas.push(FunctionCallDelta {
                                                index,
                                                call_id: entry.call_id.clone(),
                                                name: entry.name.clone(),
                                                delta: args.to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                deltas
            } else {
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    fn read_all<R: Read>(mut reader: R) -> String {
        let mut body = String::new();
        reader.read_to_string(&mut body).unwrap();
        body
    }

    fn sse_json_events(body: &str, event_name: &str) -> Vec<Value> {
        body.split("\n\n")
            .filter_map(|frame| {
                let mut event = None;
                let mut data = Vec::new();
                for line in frame.lines() {
                    if let Some(value) = line.strip_prefix("event:") {
                        event = Some(value.trim());
                    } else if let Some(value) = line.strip_prefix("data:") {
                        data.push(value.trim_start());
                    }
                }
                if event != Some(event_name) {
                    return None;
                }
                serde_json::from_str::<Value>(&data.join("\n")).ok()
            })
            .collect()
    }

    #[test]
    fn normalizes_openai_sse_stream_into_responses_events() {
        let body = b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\ndata: [DONE]\n\n";
        let reader = Cursor::new(body.to_vec());
        let normalizer = ResponsesStreamNormalizer::new(
            reader,
            ResponsesStreamProviderKind::OpenAiCompatible,
            "fg-test",
            "text/event-stream",
        );

        let normalized = read_all(normalizer);
        assert!(normalized.contains("event: response.output_text.delta"));
        assert!(normalized.contains(r#""delta":"ok""#));
        assert!(normalized.contains(r#""request_id":"fg-test""#));
        assert!(normalized.contains("event: response.completed"));
        assert!(normalized.contains(r#""prompt_tokens":3"#));
        assert!(normalized.contains(r#""completion_tokens":5"#));
        assert!(normalized.contains(r#""total_tokens":8"#));
        assert!(normalized.contains("data: [DONE]"));
    }

    #[test]
    fn normalizes_anthropic_delta_and_stop_events() {
        let body = b"event: content_block_delta\ndata: {\"delta\":{\"text\":\"ok\"}}\n\nevent: message_stop\ndata: {}\n\n";
        let reader = Cursor::new(body.to_vec());
        let normalizer = ResponsesStreamNormalizer::new(
            reader,
            ResponsesStreamProviderKind::Anthropic,
            "fg-test",
            "text/event-stream",
        );

        let normalized = read_all(normalizer);
        assert!(normalized.contains("event: response.output_text.delta"));
        assert!(normalized.contains("event: response.completed"));
    }

    #[test]
    fn normalizes_gemini_usage_and_text() {
        let body = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ok\"}]}}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":5,\"totalTokenCount\":8}}\n\n";
        let reader = Cursor::new(body.to_vec());
        let normalizer = ResponsesStreamNormalizer::new(
            reader,
            ResponsesStreamProviderKind::Gemini,
            "fg-test",
            "text/event-stream",
        );

        let normalized = read_all(normalizer);
        assert!(normalized.contains("event: response.output_text.delta"));
        assert!(normalized.contains(r#""prompt_tokens":3"#));
        assert!(normalized.contains(r#""completion_tokens":5"#));
        assert!(normalized.contains(r#""total_tokens":8"#));
    }

    #[test]
    fn normalizes_openai_tool_call_arguments_into_responses_events() {
        let body = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"query\\\":\\\"\"}}]}}]}\n\ndata: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ferrogate\\\"}\"}}]}}]}\n\ndata: [DONE]\n\n";
        let reader = Cursor::new(body.to_vec());
        let normalizer = ResponsesStreamNormalizer::new(
            reader,
            ResponsesStreamProviderKind::OpenAiCompatible,
            "fg-test",
            "text/event-stream",
        );

        let normalized = read_all(normalizer);
        assert!(normalized.contains("event: response.function_call_arguments.delta"));
        let delta_events = sse_json_events(&normalized, "response.function_call_arguments.delta");
        assert_eq!(delta_events.len(), 2, "{normalized}");
        assert_eq!(delta_events[0]["name"], "lookup");
        assert_eq!(delta_events[0]["call_id"], "call_1");
        assert_eq!(delta_events[0]["delta"], r#"{"query":""#);
        assert_eq!(delta_events[1]["delta"], r#"ferrogate"}"#);
        assert!(normalized.contains("event: response.function_call_arguments.done"));
        let done_events = sse_json_events(&normalized, "response.function_call_arguments.done");
        assert_eq!(done_events.len(), 1, "{normalized}");
        assert_eq!(done_events[0]["name"], "lookup");
        assert_eq!(done_events[0]["call_id"], "call_1");
        assert_eq!(done_events[0]["arguments"], r#"{"query":"ferrogate"}"#);
        assert!(normalized.contains("data: [DONE]"));
    }

    #[test]
    fn normalizes_provider_stream_errors_into_failed_responses_events() {
        let body = b"event: error\ndata: {\"error\":{\"message\":\"stream exploded\",\"type\":\"rate_limit_exceeded\",\"code\":\"rate_limit_exceeded\"}}\n\n";
        let reader = Cursor::new(body.to_vec());
        let normalizer = ResponsesStreamNormalizer::new(
            reader,
            ResponsesStreamProviderKind::OpenAiCompatible,
            "fg-test",
            "text/event-stream",
        );

        let normalized = read_all(normalizer);
        assert!(normalized.contains("event: response.failed"));
        assert!(normalized.contains(r#""message":"stream exploded""#));
        assert!(normalized.contains(r#""code":"rate_limit_exceeded""#));
        assert!(normalized.contains("data: [DONE]"));
    }
}
