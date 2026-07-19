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

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Accumulate a buffered OpenAI chat-completions SSE stream into a single
/// chat-completion object. The gateway buffers the provider stream so streaming
/// requests get identical governance (guardrail block/redact, metering) to
/// non-streaming ones before the response is re-emitted as Anthropic frames.
pub(super) fn chat_sse_to_completion(sse: &[u8]) -> Value {
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
pub(super) fn message_to_anthropic_sse(message: &Value) -> Vec<u8> {
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
pub(super) fn error_sse(code: &str, message: &str) -> Vec<u8> {
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
}
