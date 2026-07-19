// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Anthropic-native Messages <-> OpenAI chat-completions translation
// (issue #272). The gateway exposes a `POST /v1/messages` ingress for
// Claude-protocol-native clients (Claude Code and the wider coding-agent
// ecosystem). To reuse ALL existing adapter families as upstreams and route
// through the SAME governed chokepoint the OpenAI ingress uses, the Anthropic
// request is translated into an OpenAI chat-completions request here, dispatched
// through the ordinary chat-completions path, and the provider's chat-completion
// response is translated back into an Anthropic Messages object on the way out.
// Pure JSON <-> JSON transforms only; no I/O, no governance -- those stay in the
// gateway handler so this stays unit-testable in isolation.

use serde_json::{json, Map, Value};

use crate::AdapterError;

/// Translate an Anthropic Messages request body into an OpenAI
/// chat-completions request body so it can flow through the existing
/// chat-completions governance + dispatch pipeline (and therefore every
/// adapter family). Text content is preserved verbatim so request-stage
/// guardrails see identical text under either ingress protocol.
pub fn to_chat_completions(body: Value) -> Result<Value, AdapterError> {
    let object = body
        .as_object()
        .ok_or_else(|| AdapterError::InvalidRequest {
            message: "Anthropic messages request body must be a JSON object".into(),
        })?;

    let mut out = Map::new();

    // Scalar passthroughs. `model` and `stream` are required by the gateway's
    // shared request planner; `max_tokens`/sampling params map 1:1.
    for key in ["model", "max_tokens", "temperature", "top_p", "stream"] {
        if let Some(value) = object.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    // Anthropic `stop_sequences` -> OpenAI `stop`.
    if let Some(stop) = object.get("stop_sequences") {
        out.insert("stop".to_string(), stop.clone());
    }

    let mut messages = Vec::new();
    // Anthropic carries the system prompt as a top-level field (string or an
    // array of text blocks). OpenAI carries it as the first `system` message.
    if let Some(system) = object.get("system") {
        if let Some(text) = anthropic_system_to_text(system) {
            messages.push(json!({ "role": "system", "content": text }));
        }
    }

    if let Some(items) = object.get("messages").and_then(Value::as_array) {
        for message in items {
            anthropic_message_to_chat(message, &mut messages)?;
        }
    }
    out.insert("messages".to_string(), Value::Array(messages));

    if let Some(tools) = object.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools.iter().map(anthropic_tool_to_openai).collect();
        if !converted.is_empty() {
            out.insert("tools".to_string(), Value::Array(converted));
        }
    }
    if let Some(tool_choice) = object.get("tool_choice") {
        if let Some(converted) = anthropic_tool_choice_to_openai(tool_choice) {
            out.insert("tool_choice".to_string(), converted);
        }
    }

    Ok(Value::Object(out))
}

fn anthropic_system_to_text(system: &Value) -> Option<String> {
    match system {
        Value::String(text) => (!text.is_empty()).then(|| text.clone()),
        Value::Array(blocks) => {
            let text = blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n");
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn anthropic_message_to_chat(message: &Value, out: &mut Vec<Value>) -> Result<(), AdapterError> {
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user");
    let content = message.get("content").unwrap_or(&Value::Null);

    // Simple string content maps straight across for both roles.
    if let Some(text) = content.as_str() {
        out.push(json!({ "role": role, "content": text }));
        return Ok(());
    }

    let Some(blocks) = content.as_array() else {
        // Null / absent content -> empty assistant/user turn.
        out.push(json!({ "role": role, "content": "" }));
        return Ok(());
    };

    // Partition the Anthropic content blocks. `tool_result` blocks (only valid
    // on a user turn) become standalone OpenAI `tool` messages; `tool_use`
    // blocks (assistant) become `tool_calls`; everything else is ordinary
    // multimodal content.
    let mut content_parts: Vec<Value> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut tool_messages: Vec<Value> = Vec::new();

    for block in blocks {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                content_parts.push(json!({
                    "type": "text",
                    "text": block.get("text").and_then(Value::as_str).unwrap_or(""),
                }));
            }
            Some("image") => {
                if let Some(url) = anthropic_image_to_data_url(block) {
                    content_parts.push(json!({
                        "type": "image_url",
                        "image_url": { "url": url },
                    }));
                }
            }
            Some("tool_use") => {
                tool_calls.push(json!({
                    "id": block.get("id").and_then(Value::as_str).unwrap_or_default(),
                    "type": "function",
                    "function": {
                        "name": block.get("name").and_then(Value::as_str).unwrap_or_default(),
                        "arguments": stringify_arguments(block.get("input")),
                    },
                }));
            }
            Some("tool_result") => {
                tool_messages.push(json!({
                    "role": "tool",
                    "tool_call_id": block
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    "content": tool_result_to_text(block.get("content")),
                }));
            }
            _ => {}
        }
    }

    // OpenAI requires tool result messages to appear before the next user text
    // in the same logical turn.
    out.append(&mut tool_messages);

    if !tool_calls.is_empty() {
        let mut assistant = Map::new();
        assistant.insert("role".to_string(), json!("assistant"));
        assistant.insert("content".to_string(), collapse_content(&content_parts));
        assistant.insert("tool_calls".to_string(), Value::Array(tool_calls));
        out.push(Value::Object(assistant));
    } else if !content_parts.is_empty() {
        out.push(json!({ "role": role, "content": collapse_content(&content_parts) }));
    }

    Ok(())
}

/// A single text block collapses to a plain string (the shape most upstreams
/// prefer); anything richer stays an OpenAI content-part array.
fn collapse_content(parts: &[Value]) -> Value {
    match parts {
        [] => Value::Null,
        [single] if single.get("type").and_then(Value::as_str) == Some("text") => single
            .get("text")
            .cloned()
            .unwrap_or_else(|| Value::String(String::new())),
        _ => Value::Array(parts.to_vec()),
    }
}

fn anthropic_image_to_data_url(block: &Value) -> Option<String> {
    let source = block.get("source")?;
    match source.get("type").and_then(Value::as_str) {
        Some("base64") => {
            let media_type = source
                .get("media_type")
                .and_then(Value::as_str)
                .unwrap_or("image/png");
            let data = source.get("data").and_then(Value::as_str)?;
            Some(format!("data:{media_type};base64,{data}"))
        }
        Some("url") => source
            .get("url")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

fn tool_result_to_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .map(|block| match block.get("text").and_then(Value::as_str) {
                Some(text) => text.to_string(),
                None => block.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn stringify_arguments(input: Option<&Value>) -> String {
    match input {
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
        None => "{}".to_string(),
    }
}

fn anthropic_tool_to_openai(tool: &Value) -> Value {
    let mut function = Map::new();
    function.insert(
        "name".to_string(),
        tool.get("name").cloned().unwrap_or(Value::Null),
    );
    if let Some(description) = tool.get("description") {
        function.insert("description".to_string(), description.clone());
    }
    function.insert(
        "parameters".to_string(),
        tool.get("input_schema")
            .cloned()
            .unwrap_or_else(|| json!({ "type": "object" })),
    );
    json!({ "type": "function", "function": Value::Object(function) })
}

fn anthropic_tool_choice_to_openai(choice: &Value) -> Option<Value> {
    match choice.get("type").and_then(Value::as_str) {
        Some("auto") => Some(json!("auto")),
        Some("none") => Some(json!("none")),
        Some("any") => Some(json!("required")),
        Some("tool") => choice
            .get("name")
            .and_then(Value::as_str)
            .map(|name| json!({ "type": "function", "function": { "name": name } })),
        _ => None,
    }
}

/// Translate an upstream chat-completion response into an Anthropic Messages
/// object. If the body is already Anthropic-shaped (an Anthropic upstream
/// answered), it is passed through unchanged so a Claude client sees a native
/// response either way.
pub fn chat_completion_to_message(chat: &Value, fallback_model: &str) -> Value {
    if is_anthropic_message(chat) {
        return chat.clone();
    }

    let id = chat
        .get("id")
        .and_then(Value::as_str)
        .map(|id| id.replace("chatcmpl", "msg"))
        .unwrap_or_else(|| "msg_ferrogate".to_string());
    let model = chat
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model)
        .to_string();

    let choice = chat
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first());
    let message = choice.and_then(|choice| choice.get("message"));
    let finish_reason = choice
        .and_then(|choice| choice.get("finish_reason"))
        .and_then(Value::as_str);

    let mut content = Vec::new();
    if let Some(text) = message
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
    {
        if !text.is_empty() {
            content.push(json!({ "type": "text", "text": text }));
        }
    }
    let mut saw_tool_use = false;
    if let Some(tool_calls) = message
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for tool_call in tool_calls {
            saw_tool_use = true;
            let function = tool_call.get("function");
            content.push(json!({
                "type": "tool_use",
                "id": tool_call.get("id").and_then(Value::as_str).unwrap_or_default(),
                "name": function
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                "input": parse_arguments(
                    function.and_then(|function| function.get("arguments")),
                ),
            }));
        }
    }

    let usage = chat.get("usage");
    let input_tokens = usage
        .and_then(|usage| usage.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .and_then(|usage| usage.get("completion_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content,
        "stop_reason": finish_reason_to_stop_reason(finish_reason, saw_tool_use),
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    })
}

pub(crate) fn is_anthropic_message(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("message")
        && value.get("content").is_some_and(Value::is_array)
}

pub(crate) fn finish_reason_to_stop_reason(
    finish_reason: Option<&str>,
    saw_tool_use: bool,
) -> &'static str {
    if saw_tool_use {
        return "tool_use";
    }
    match finish_reason {
        Some("length") => "max_tokens",
        Some("tool_calls") => "tool_use",
        Some("stop") => "end_turn",
        _ => "end_turn",
    }
}

pub(crate) fn parse_arguments(arguments: Option<&Value>) -> Value {
    match arguments {
        Some(Value::String(text)) => {
            serde_json::from_str::<Value>(text).unwrap_or_else(|_| json!({}))
        }
        Some(value) => value.clone(),
        None => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_system_messages_and_sampling_params() {
        let chat = to_chat_completions(json!({
            "model": "claude-logical",
            "max_tokens": 256,
            "temperature": 0.5,
            "stop_sequences": ["STOP"],
            "stream": true,
            "system": "be concise",
            "messages": [{ "role": "user", "content": "hello" }]
        }))
        .unwrap();

        assert_eq!(chat["model"], "claude-logical");
        assert_eq!(chat["max_tokens"], 256);
        assert_eq!(chat["temperature"], 0.5);
        assert_eq!(chat["stop"][0], "STOP");
        assert_eq!(chat["stream"], true);
        assert_eq!(chat["messages"][0]["role"], "system");
        assert_eq!(chat["messages"][0]["content"], "be concise");
        assert_eq!(chat["messages"][1]["role"], "user");
        assert_eq!(chat["messages"][1]["content"], "hello");
    }

    #[test]
    fn translates_tools_tool_use_and_tool_result() {
        let chat = to_chat_completions(json!({
            "model": "claude-logical",
            "max_tokens": 512,
            "tools": [{
                "name": "lookup_weather",
                "description": "Look up weather",
                "input_schema": { "type": "object", "properties": { "city": { "type": "string" } } }
            }],
            "tool_choice": { "type": "tool", "name": "lookup_weather" },
            "messages": [
                { "role": "user", "content": "weather in SH?" },
                { "role": "assistant", "content": [
                    { "type": "text", "text": "checking" },
                    { "type": "tool_use", "id": "toolu_1", "name": "lookup_weather", "input": { "city": "Shanghai" } }
                ]},
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_1", "content": "21C" }
                ]}
            ]
        }))
        .unwrap();

        assert_eq!(chat["tools"][0]["type"], "function");
        assert_eq!(chat["tools"][0]["function"]["name"], "lookup_weather");
        assert_eq!(
            chat["tools"][0]["function"]["parameters"]["properties"]["city"]["type"],
            "string"
        );
        assert_eq!(chat["tool_choice"]["type"], "function");
        assert_eq!(chat["tool_choice"]["function"]["name"], "lookup_weather");

        // assistant tool_use -> tool_calls with stringified arguments.
        let assistant = &chat["messages"][1];
        assert_eq!(assistant["role"], "assistant");
        assert_eq!(assistant["content"], "checking");
        assert_eq!(assistant["tool_calls"][0]["id"], "toolu_1");
        assert_eq!(
            assistant["tool_calls"][0]["function"]["name"],
            "lookup_weather"
        );
        assert_eq!(
            assistant["tool_calls"][0]["function"]["arguments"],
            r#"{"city":"Shanghai"}"#
        );

        // user tool_result -> standalone tool message.
        let tool_message = &chat["messages"][2];
        assert_eq!(tool_message["role"], "tool");
        assert_eq!(tool_message["tool_call_id"], "toolu_1");
        assert_eq!(tool_message["content"], "21C");
    }

    #[test]
    fn translates_base64_image_blocks_to_data_urls() {
        let chat = to_chat_completions(json!({
            "model": "claude-logical",
            "max_tokens": 64,
            "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "what is this" },
                { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "Zm9v" } }
            ]}]
        }))
        .unwrap();

        let parts = &chat["messages"][0]["content"];
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[1]["type"], "image_url");
        assert_eq!(parts[1]["image_url"]["url"], "data:image/png;base64,Zm9v");
    }

    #[test]
    fn translates_chat_completion_response_to_anthropic_message() {
        let message = chat_completion_to_message(
            &json!({
                "id": "chatcmpl-abc",
                "model": "gpt-4o",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "hello there",
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": { "name": "lookup", "arguments": "{\"q\":\"x\"}" }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": { "prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19 }
            }),
            "claude-logical",
        );

        assert_eq!(message["type"], "message");
        assert_eq!(message["role"], "assistant");
        assert_eq!(message["id"], "msg-abc");
        assert_eq!(message["content"][0]["type"], "text");
        assert_eq!(message["content"][0]["text"], "hello there");
        assert_eq!(message["content"][1]["type"], "tool_use");
        assert_eq!(message["content"][1]["id"], "call_1");
        assert_eq!(message["content"][1]["name"], "lookup");
        assert_eq!(message["content"][1]["input"]["q"], "x");
        assert_eq!(message["stop_reason"], "tool_use");
        assert_eq!(message["usage"]["input_tokens"], 12);
        assert_eq!(message["usage"]["output_tokens"], 7);
    }

    #[test]
    fn passes_through_anthropic_shaped_responses() {
        let native = json!({
            "id": "msg_native",
            "type": "message",
            "role": "assistant",
            "content": [{ "type": "text", "text": "native" }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 1, "output_tokens": 2 }
        });
        let passed = chat_completion_to_message(&native, "claude-logical");
        assert_eq!(passed, native);
    }
}
