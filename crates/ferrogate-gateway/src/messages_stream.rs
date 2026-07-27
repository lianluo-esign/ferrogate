// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Reverse SSE normalization for the Anthropic `POST /v1/messages`
// ingress (issue #272). The gateway dispatches every `/v1/messages` request
// through the shared chat-completions pipeline, so an upstream returns either an
// OpenAI-compatible chat-completion (streamed as OpenAI SSE) or a native
// Anthropic response. This module (a) accumulates a buffered OpenAI chat SSE
// stream into a single chat-completion object so it can be governed +
// translated exactly like the non-streaming path, and (b) serializes a
// translated Anthropic Messages object into the Anthropic event-frame sequence
// (`message_start` / `content_block_start` / `content_block_delta` /
// `content_block_stop` / `message_delta` / `message_stop`) that Claude-native
// clients expect. Modeled on `responses_stream.rs`.
//
// Issue #310 adds (c) [`MessagesStreamNormalizer`]: an incremental `Read`
// adapter that translates a live OpenAI chat-completions SSE stream into the
// same Anthropic event-frame sequence chunk by chunk, so a streaming
// `/v1/messages` request delivers tokens as the provider produces them instead
// of one buffered body. The buffered helpers above remain the governed path
// when a BufferAndEnforce response guardrail must inspect the whole stream
// before first-byte release, and the non-streaming path is untouched.

use std::{
    collections::BTreeMap,
    io::{Error as IoError, Read},
};

use ferrogate_providers::anthropic_messages::finish_reason_to_stop_reason;
use serde_json::{json, Value};

/// Accumulate a buffered OpenAI chat-completions SSE stream into a single
/// chat-completion object. The gateway buffers the provider stream so streaming
/// requests get identical governance (guardrail block/redact, metering) to
/// non-streaming ones before the response is re-emitted as Anthropic frames.
pub fn chat_sse_to_completion(sse: &[u8]) -> Value {
    let mut id = None;
    let mut model = None;
    let mut content = String::new();
    let mut saw_content = false;
    let mut finish_reason = None;
    let mut usage = None;
    let mut tool_calls: BTreeMap<u64, ToolCallAccumulator> = BTreeMap::new();

    for data in sse_data_payloads(sse) {
        if data.trim() == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        if id.is_none() {
            id = value.get("id").and_then(Value::as_str).map(str::to_string);
        }
        if model.is_none() {
            model = value
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if let Some(reported) = value.get("usage").filter(|usage| !usage.is_null()) {
            usage = Some(reported.clone());
        }
        let Some(choice) = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            continue;
        };
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            finish_reason = Some(reason.to_string());
        }
        let Some(delta) = choice.get("delta") else {
            continue;
        };
        if let Some(text) = delta.get("content").and_then(Value::as_str) {
            content.push_str(text);
            saw_content = true;
        }
        if let Some(deltas) = delta.get("tool_calls").and_then(Value::as_array) {
            for (position, tool_call) in deltas.iter().enumerate() {
                let index = tool_call
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(position as u64);
                let entry = tool_calls.entry(index).or_default();
                if let Some(call_id) = tool_call.get("id").and_then(Value::as_str) {
                    entry.id = call_id.to_string();
                }
                if let Some(function) = tool_call.get("function") {
                    if let Some(name) = function.get("name").and_then(Value::as_str) {
                        entry.name = name.to_string();
                    }
                    if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                        entry.arguments.push_str(arguments);
                    }
                }
            }
        }
    }

    let mut message = json!({ "role": "assistant" });
    message["content"] = if saw_content {
        Value::String(content)
    } else {
        Value::Null
    };
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(
            tool_calls
                .into_values()
                .map(|call| {
                    json!({
                        "id": call.id,
                        "type": "function",
                        "function": { "name": call.name, "arguments": call.arguments },
                    })
                })
                .collect(),
        );
    }

    let mut completion = json!({
        "id": id.unwrap_or_else(|| "chatcmpl-ferrogate".to_string()),
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason,
        }],
    });
    if let Some(model) = model {
        completion["model"] = Value::String(model);
    }
    if let Some(usage) = usage {
        completion["usage"] = usage;
    }
    completion
}

#[derive(Debug, Default)]
struct ToolCallAccumulator {
    id: String,
    name: String,
    arguments: String,
}

fn sse_data_payloads(sse: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(sse);
    let mut payloads = Vec::new();
    for frame in text.replace("\r\n", "\n").split("\n\n") {
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("data:") {
                data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
            }
        }
        if !data.is_empty() {
            payloads.push(data.join("\n"));
        }
    }
    payloads
}

/// Serialize an Anthropic Messages object (as produced by
/// `ferrogate_providers::anthropic_messages::chat_completion_to_message`) into
/// the Anthropic event-frame SSE sequence.
pub fn message_to_anthropic_sse(message: &Value) -> Vec<u8> {
    let mut out = Vec::new();

    let input_tokens = message
        .get("usage")
        .and_then(|usage| usage.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = message
        .get("usage")
        .and_then(|usage| usage.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    // message_start carries the shell of the message with empty content.
    let start_message = json!({
        "id": message.get("id").cloned().unwrap_or_else(|| json!("msg_ferrogate")),
        "type": "message",
        "role": "assistant",
        "model": message.get("model").cloned().unwrap_or(Value::Null),
        "content": [],
        "stop_reason": Value::Null,
        "stop_sequence": Value::Null,
        "usage": { "input_tokens": input_tokens, "output_tokens": 0 },
    });
    write_event(
        &mut out,
        "message_start",
        &json!({ "type": "message_start", "message": start_message }),
    );

    if let Some(blocks) = message.get("content").and_then(Value::as_array) {
        for (index, block) in blocks.iter().enumerate() {
            emit_content_block(&mut out, index, block);
        }
    }

    let stop_reason = message.get("stop_reason").cloned().unwrap_or(Value::Null);
    let stop_sequence = message.get("stop_sequence").cloned().unwrap_or(Value::Null);
    write_event(
        &mut out,
        "message_delta",
        &json!({
            "type": "message_delta",
            "delta": { "stop_reason": stop_reason, "stop_sequence": stop_sequence },
            "usage": { "output_tokens": output_tokens },
        }),
    );
    write_event(&mut out, "message_stop", &json!({ "type": "message_stop" }));
    out
}

fn emit_content_block(out: &mut Vec<u8>, index: usize, block: &Value) {
    match block.get("type").and_then(Value::as_str) {
        Some("tool_use") => {
            write_event(
                out,
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {
                        "type": "tool_use",
                        "id": block.get("id").cloned().unwrap_or(Value::Null),
                        "name": block.get("name").cloned().unwrap_or(Value::Null),
                        "input": {},
                    },
                }),
            );
            let partial = block
                .get("input")
                .map(|input| input.to_string())
                .unwrap_or_else(|| "{}".to_string());
            write_event(
                out,
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "input_json_delta", "partial_json": partial },
                }),
            );
        }
        _ => {
            write_event(
                out,
                "content_block_start",
                &json!({
                    "type": "content_block_start",
                    "index": index,
                    "content_block": { "type": "text", "text": "" },
                }),
            );
            let text = block
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            write_event(
                out,
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": index,
                    "delta": { "type": "text_delta", "text": text },
                }),
            );
        }
    }
    write_event(
        out,
        "content_block_stop",
        &json!({ "type": "content_block_stop", "index": index }),
    );
}

/// Serialize an Anthropic-shaped error into a single SSE `error` frame, used
/// when a guardrail blocks a streaming response or the upstream stream fails.
pub fn error_sse(code: &str, message: &str) -> Vec<u8> {
    let mut out = Vec::new();
    write_event(
        &mut out,
        "error",
        &json!({
            "type": "error",
            "error": { "type": code, "message": message },
        }),
    );
    out
}

/// Incrementally translate an OpenAI chat-completions SSE stream into the
/// Anthropic Messages event-frame sequence (issue #310). Each provider frame
/// is re-emitted as soon as it is read -- `message_start` on the first parsed
/// chunk, `content_block_start`/`content_block_delta` per token or tool-call
/// argument chunk, and the `message_delta`/`message_stop` tail once the
/// provider signals completion -- so token-by-token delivery survives the
/// translation. The terminal `stop_reason` and `usage` mirror what the
/// buffered `chat_sse_to_completion` -> `chat_completion_to_message` ->
/// `message_to_anthropic_sse` pipeline would produce for the same stream.
pub struct MessagesStreamNormalizer<R> {
    reader: R,
    fallback_model: String,
    buffer: String,
    output: Vec<u8>,
    output_offset: usize,
    eof: bool,
    completed: bool,
    started: bool,
    message_id: Option<String>,
    model: Option<String>,
    open_block: Option<OpenBlock>,
    current_block_index: u64,
    next_block_index: u64,
    tool_calls: BTreeMap<u64, ToolCallAccumulator>,
    finish_reason: Option<String>,
    saw_tool_use: bool,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenBlock {
    Text,
    ToolUse { tool_index: u64 },
}

impl<R: Read> MessagesStreamNormalizer<R> {
    pub fn new(reader: R, fallback_model: impl Into<String>) -> Self {
        Self {
            reader,
            fallback_model: fallback_model.into(),
            buffer: String::new(),
            output: Vec::new(),
            output_offset: 0,
            eof: false,
            completed: false,
            started: false,
            message_id: None,
            model: None,
            open_block: None,
            current_block_index: 0,
            next_block_index: 0,
            tool_calls: BTreeMap::new(),
            finish_reason: None,
            saw_tool_use: false,
            prompt_tokens: None,
            completion_tokens: None,
        }
    }

    fn ensure_started(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        let start_message = json!({
            "id": self
                .message_id
                .clone()
                .unwrap_or_else(|| "msg_ferrogate".to_string()),
            "type": "message",
            "role": "assistant",
            "model": self
                .model
                .clone()
                .unwrap_or_else(|| self.fallback_model.clone()),
            "content": [],
            "stop_reason": Value::Null,
            "stop_sequence": Value::Null,
            "usage": { "input_tokens": 0, "output_tokens": 0 },
        });
        write_event(
            &mut self.output,
            "message_start",
            &json!({ "type": "message_start", "message": start_message }),
        );
    }

    fn close_open_block(&mut self) {
        if self.open_block.take().is_some() {
            write_event(
                &mut self.output,
                "content_block_stop",
                &json!({ "type": "content_block_stop", "index": self.current_block_index }),
            );
        }
    }

    fn ensure_text_block(&mut self) -> u64 {
        if self.open_block == Some(OpenBlock::Text) {
            return self.current_block_index;
        }
        self.close_open_block();
        let index = self.next_block_index;
        self.next_block_index += 1;
        self.current_block_index = index;
        self.open_block = Some(OpenBlock::Text);
        write_event(
            &mut self.output,
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "text", "text": "" },
            }),
        );
        index
    }

    fn ensure_tool_block(&mut self, tool_index: u64) -> u64 {
        if self.open_block == Some(OpenBlock::ToolUse { tool_index }) {
            return self.current_block_index;
        }
        self.close_open_block();
        let (id, name) = self
            .tool_calls
            .get(&tool_index)
            .map(|call| (call.id.clone(), call.name.clone()))
            .unwrap_or_default();
        let index = self.next_block_index;
        self.next_block_index += 1;
        self.current_block_index = index;
        self.open_block = Some(OpenBlock::ToolUse { tool_index });
        write_event(
            &mut self.output,
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "tool_use", "id": id, "name": name, "input": {} },
            }),
        );
        index
    }

    fn finish_stream(&mut self) {
        if self.completed {
            return;
        }
        self.ensure_started();
        self.close_open_block();
        let stop_reason =
            finish_reason_to_stop_reason(self.finish_reason.as_deref(), self.saw_tool_use);
        let mut usage = json!({ "output_tokens": self.completion_tokens.unwrap_or(0) });
        if let Some(input_tokens) = self.prompt_tokens {
            usage["input_tokens"] = json!(input_tokens);
        }
        write_event(
            &mut self.output,
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": { "stop_reason": stop_reason, "stop_sequence": Value::Null },
                "usage": usage,
            }),
        );
        write_event(
            &mut self.output,
            "message_stop",
            &json!({ "type": "message_stop" }),
        );
        self.completed = true;
    }

    fn emit_error(&mut self, value: &Value) {
        let error = value.get("error");
        let message = error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("provider returned a streaming error");
        let code = error
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .or_else(|| {
                error
                    .and_then(|error| error.get("type"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("provider_stream_error");
        self.output.extend_from_slice(&error_sse(code, message));
        self.completed = true;
    }

    fn drain_frame(&mut self, frame: &str) {
        let mut event_name = None;
        let mut data = Vec::new();
        for line in frame.lines() {
            if let Some(value) = line.strip_prefix("event:") {
                event_name = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
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
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            return;
        };

        if self.message_id.is_none() {
            self.message_id = value
                .get("id")
                .and_then(Value::as_str)
                .map(|id| id.replace("chatcmpl", "msg"));
        }
        if self.model.is_none() {
            self.model = value
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
        if let Some(usage) = value.get("usage").filter(|usage| !usage.is_null()) {
            if let Some(prompt) = usage.get("prompt_tokens").and_then(Value::as_u64) {
                self.prompt_tokens = Some(prompt);
            }
            if let Some(completion) = usage.get("completion_tokens").and_then(Value::as_u64) {
                self.completion_tokens = Some(completion);
            }
        }
        if event_name.as_deref() == Some("error") || value.get("error").is_some() {
            self.emit_error(&value);
            return;
        }
        let Some(choice) = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        else {
            return;
        };
        // A chat chunk is flowing: open the Anthropic message immediately so
        // the client sees `message_start` on the provider's first frame.
        self.ensure_started();
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            self.finish_reason = Some(reason.to_string());
        }
        let Some(delta) = choice.get("delta").cloned() else {
            return;
        };
        if let Some(text) = delta.get("content").and_then(Value::as_str) {
            if !text.is_empty() {
                let index = self.ensure_text_block();
                write_event(
                    &mut self.output,
                    "content_block_delta",
                    &json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": { "type": "text_delta", "text": text },
                    }),
                );
            }
        }
        if let Some(tool_deltas) = delta.get("tool_calls").and_then(Value::as_array) {
            for (position, tool_call) in tool_deltas.iter().enumerate() {
                let tool_index = tool_call
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(position as u64);
                {
                    let entry = self.tool_calls.entry(tool_index).or_default();
                    if let Some(call_id) = tool_call.get("id").and_then(Value::as_str) {
                        entry.id = call_id.to_string();
                    }
                    if let Some(name) = tool_call
                        .get("function")
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                    {
                        entry.name = name.to_string();
                    }
                }
                self.saw_tool_use = true;
                let index = self.ensure_tool_block(tool_index);
                if let Some(arguments) = tool_call
                    .get("function")
                    .and_then(|function| function.get("arguments"))
                    .and_then(Value::as_str)
                    .filter(|arguments| !arguments.is_empty())
                {
                    write_event(
                        &mut self.output,
                        "content_block_delta",
                        &json!({
                            "type": "content_block_delta",
                            "index": index,
                            "delta": { "type": "input_json_delta", "partial_json": arguments },
                        }),
                    );
                }
            }
        }
    }
}

impl<R: Read> Read for MessagesStreamNormalizer<R> {
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
            let read = match self.reader.read(&mut buffer) {
                Ok(read) => read,
                // Issue #311: `WouldBlock` is the async pump's "no upstream
                // chunk fed yet" signal from the streaming body feed; surface
                // it untouched (no state has been mutated) so the pump can
                // await the next chunk and retry this read.
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => {
                    return Err(IoError::other(format!(
                        "reading provider streaming response: {error}"
                    )))
                }
            };
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

fn write_event(out: &mut Vec<u8>, event: &str, value: &Value) {
    let data = serde_json::to_string(value).expect("JSON serialization should not fail");
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(event.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(data.as_bytes());
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_openai_chat_sse_into_a_completion() {
        let sse = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();

        let completion = chat_sse_to_completion(sse);
        assert_eq!(completion["id"], "chatcmpl-1");
        assert_eq!(completion["model"], "gpt-4o");
        assert_eq!(completion["choices"][0]["message"]["content"], "Hello");
        assert_eq!(completion["choices"][0]["finish_reason"], "stop");
        assert_eq!(completion["usage"]["completion_tokens"], 2);
    }

    #[test]
    fn accumulates_streamed_tool_calls() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"x\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        )
        .as_bytes();

        let completion = chat_sse_to_completion(sse);
        let tool_call = &completion["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(tool_call["id"], "call_1");
        assert_eq!(tool_call["function"]["name"], "lookup");
        assert_eq!(tool_call["function"]["arguments"], r#"{"q":"x"}"#);
        assert_eq!(completion["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn serializes_anthropic_frame_sequence() {
        let message = json!({
            "id": "msg-1",
            "type": "message",
            "role": "assistant",
            "model": "claude-logical",
            "content": [
                { "type": "text", "text": "hi" },
                { "type": "tool_use", "id": "call_1", "name": "lookup", "input": { "q": "x" } }
            ],
            "stop_reason": "tool_use",
            "stop_sequence": Value::Null,
            "usage": { "input_tokens": 5, "output_tokens": 3 }
        });

        let sse = String::from_utf8(message_to_anthropic_sse(&message)).unwrap();
        // Ordered frame sequence.
        let start = sse.find("event: message_start").unwrap();
        let block_start = sse.find("event: content_block_start").unwrap();
        let block_delta = sse.find("event: content_block_delta").unwrap();
        let block_stop = sse.find("event: content_block_stop").unwrap();
        let message_delta = sse.find("event: message_delta").unwrap();
        let message_stop = sse.find("event: message_stop").unwrap();
        assert!(start < block_start);
        assert!(block_start < block_delta);
        assert!(block_delta < block_stop);
        assert!(block_stop < message_delta);
        assert!(message_delta < message_stop);

        assert!(sse.contains(r#""type":"text_delta""#));
        assert!(sse.contains(r#""text":"hi""#));
        assert!(sse.contains(r#""type":"input_json_delta""#));
        assert!(sse.contains(r#""partial_json":"{\"q\":\"x\"}""#));
        assert!(sse.contains(r#""stop_reason":"tool_use""#));
        assert!(sse.contains(r#""output_tokens":3"#));
    }

    /// One provider SSE frame per `read()` call, so tests can observe exactly
    /// how much input the normalizer consumed before producing output.
    struct StepReader {
        frames: Vec<&'static [u8]>,
        position: usize,
    }

    impl std::io::Read for StepReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let Some(frame) = self.frames.get(self.position) else {
                return Ok(0);
            };
            self.position += 1;
            buffer[..frame.len()].copy_from_slice(frame);
            Ok(frame.len())
        }
    }

    fn sse_event_names(sse: &str) -> Vec<String> {
        sse.lines()
            .filter_map(|line| line.strip_prefix("event: "))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn normalizer_translates_chat_sse_into_the_anthropic_frame_sequence() {
        let sse: &[u8] = concat!(
            "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2,\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();

        let mut normalized = String::new();
        std::io::Read::read_to_string(
            &mut MessagesStreamNormalizer::new(std::io::Cursor::new(sse), "claude-logical"),
            &mut normalized,
        )
        .unwrap();

        assert_eq!(
            sse_event_names(&normalized),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ],
            "{normalized}"
        );
        // Two separate text deltas -- the stream is NOT coalesced.
        assert!(normalized.contains(r#""text":"Hel""#));
        assert!(normalized.contains(r#""text":"lo""#));
        assert!(normalized.contains(r#""id":"msg-1""#));
        assert!(normalized.contains(r#""model":"gpt-4o""#));
        assert!(normalized.contains(r#""stop_reason":"end_turn""#));
        assert!(normalized.contains(r#""output_tokens":2"#));
        assert!(normalized.contains(r#""input_tokens":5"#));
        assert!(!normalized.contains("[DONE]"));

        // Terminal semantics match the buffered pipeline for the same stream.
        let buffered = message_to_anthropic_sse(
            &ferrogate_providers::anthropic_messages::chat_completion_to_message(
                &chat_sse_to_completion(sse),
                "claude-logical",
            ),
        );
        let buffered = String::from_utf8(buffered).unwrap();
        assert!(buffered.contains(r#""stop_reason":"end_turn""#));
        assert!(buffered.contains(r#""output_tokens":2"#));
    }

    #[test]
    fn normalizer_emits_frames_incrementally_not_after_the_stream_ends() {
        let reader = StepReader {
            frames: vec![
                b"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"}}]}\n\n",
                b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                b"data: [DONE]\n\n",
            ],
            position: 0,
        };
        let mut normalizer = MessagesStreamNormalizer::new(reader, "claude-logical");

        // Drain everything the normalizer will emit for the FIRST provider
        // frame only: read until the first frame's translation is complete.
        let mut early = Vec::new();
        let mut buffer = [0_u8; 256];
        loop {
            let read = std::io::Read::read(&mut normalizer, &mut buffer).unwrap();
            assert!(read > 0, "normalizer ended before emitting first frames");
            early.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&early);
            if text.contains(r#""text":"first""#) {
                break;
            }
        }
        // The first token was delivered while ONLY the first provider frame
        // had been consumed -- no buffering until stream completion.
        assert_eq!(normalizer.reader.position, 1);
        let early_text = String::from_utf8_lossy(&early).into_owned();
        assert!(early_text.contains("event: message_start"));
        assert!(early_text.contains("event: content_block_delta"));
        assert!(!early_text.contains("event: message_stop"));

        let mut rest = String::new();
        std::io::Read::read_to_string(&mut normalizer, &mut rest).unwrap();
        assert!(rest.contains("event: message_delta"));
        assert!(rest.contains("event: message_stop"));
        assert_eq!(normalizer.reader.position, 3);
    }

    #[test]
    fn normalizer_translates_streamed_tool_calls_into_tool_use_blocks() {
        let sse: &[u8] = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"calling\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"q\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"x\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: [DONE]\n\n",
        )
        .as_bytes();

        let mut normalized = String::new();
        std::io::Read::read_to_string(
            &mut MessagesStreamNormalizer::new(std::io::Cursor::new(sse), "claude-logical"),
            &mut normalized,
        )
        .unwrap();

        assert_eq!(
            sse_event_names(&normalized),
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ],
            "{normalized}"
        );
        assert!(normalized.contains(r#""type":"tool_use""#));
        assert!(normalized.contains(r#""id":"call_1""#));
        assert!(normalized.contains(r#""name":"lookup""#));
        assert!(normalized.contains(r#""partial_json":"{\"q\":""#));
        assert!(normalized.contains(r#""partial_json":"\"x\"}""#));
        assert!(normalized.contains(r#""stop_reason":"tool_use""#));
    }

    #[test]
    fn normalizer_translates_provider_stream_errors_into_anthropic_error_frames() {
        let sse: &[u8] =
            b"data: {\"error\":{\"message\":\"stream exploded\",\"code\":\"rate_limit_exceeded\"}}\n\n";

        let mut normalized = String::new();
        std::io::Read::read_to_string(
            &mut MessagesStreamNormalizer::new(std::io::Cursor::new(sse), "claude-logical"),
            &mut normalized,
        )
        .unwrap();

        assert!(normalized.contains("event: error"));
        assert!(normalized.contains(r#""type":"rate_limit_exceeded""#));
        assert!(normalized.contains(r#""message":"stream exploded""#));
    }
}
