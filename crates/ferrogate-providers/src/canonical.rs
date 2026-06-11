// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};

use crate::AdapterError;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalAiRequest {
    source_body: Value,
    messages: Vec<CanonicalMessage>,
    instructions: Option<Value>,
    max_output_tokens: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalMessage {
    role: String,
    content: CanonicalContent,
}

#[derive(Debug, Clone, PartialEq)]
enum CanonicalContent {
    Text(String),
    TextBlocks(Vec<String>),
}

impl CanonicalAiRequest {
    pub(crate) fn from_responses_body(body: Value) -> Result<Self, AdapterError> {
        let body = ensure_object_body(body)?;
        let input = body.get("input");
        Ok(Self {
            messages: responses_input_to_messages(input)?,
            instructions: body.get("instructions").cloned(),
            max_output_tokens: body.get("max_output_tokens").cloned(),
            source_body: body,
        })
    }

    pub(crate) fn into_chat_body_with_system_field(self) -> Value {
        let mut body = self.source_body;
        body["messages"] = canonical_messages_to_json(&self.messages);
        if let Some(instructions) = self.instructions {
            body["system"] = instructions;
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            body["max_tokens"] = max_output_tokens;
        }
        body
    }

    pub(crate) fn into_chat_body_with_system_message(self) -> Value {
        let mut body = self.source_body;
        let mut messages = canonical_messages_to_json(&self.messages);
        if let Some(instructions) = self.instructions {
            messages
                .as_array_mut()
                .expect("canonical messages are represented as an array")
                .insert(
                    0,
                    json!({
                        "role": "system",
                        "content": instructions,
                    }),
                );
        }
        body["messages"] = messages;
        if let Some(max_output_tokens) = self.max_output_tokens {
            body["max_tokens"] = max_output_tokens;
        }
        body
    }
}

fn ensure_object_body(body: Value) -> Result<Value, AdapterError> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(AdapterError::InvalidRequest {
            message: "responses request body must be a JSON object".into(),
        })
    }
}

fn responses_input_to_messages(
    input: Option<&Value>,
) -> Result<Vec<CanonicalMessage>, AdapterError> {
    match input {
        Some(Value::String(text)) => Ok(vec![CanonicalMessage::user(CanonicalContent::Text(
            text.clone(),
        ))]),
        Some(Value::Array(items)) if items.iter().any(has_message_role) => items
            .iter()
            .filter(|value| has_message_role(value))
            .map(responses_message_to_canonical_message)
            .collect(),
        Some(Value::Array(items)) => Ok(vec![CanonicalMessage::user(
            responses_content_to_canonical(&Value::Array(items.clone()))?,
        )]),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(other) => Ok(vec![CanonicalMessage::user(
            responses_content_to_canonical(other)?,
        )]),
    }
}

impl CanonicalMessage {
    fn user(content: CanonicalContent) -> Self {
        Self {
            role: "user".into(),
            content,
        }
    }
}

fn has_message_role(value: &Value) -> bool {
    value.get("role").and_then(Value::as_str).is_some()
}

fn responses_message_to_canonical_message(value: &Value) -> Result<CanonicalMessage, AdapterError> {
    let role = value.get("role").and_then(Value::as_str).unwrap_or("user");
    let content = responses_content_to_canonical(value.get("content").unwrap_or(&Value::Null))?;
    Ok(CanonicalMessage {
        role: role.into(),
        content,
    })
}

fn responses_content_to_canonical(value: &Value) -> Result<CanonicalContent, AdapterError> {
    match value {
        Value::String(text) => Ok(CanonicalContent::Text(text.clone())),
        Value::Array(items) => items
            .iter()
            .map(responses_content_block_to_text)
            .collect::<Result<Vec<_>, _>>()
            .map(CanonicalContent::TextBlocks),
        Value::Object(_) => responses_content_block_to_text(value)
            .map(|text| CanonicalContent::TextBlocks(vec![text])),
        Value::Null => Ok(CanonicalContent::Text(String::new())),
        _ => Err(text_only_error()),
    }
}

fn responses_content_block_to_text(value: &Value) -> Result<String, AdapterError> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Object(object) => {
            let block_type = object.get("type").and_then(Value::as_str);
            if matches!(block_type, Some("input_text" | "output_text" | "text")) {
                return Ok(object
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string());
            }
            Err(text_only_error())
        }
        _ => Err(text_only_error()),
    }
}

fn text_only_error() -> AdapterError {
    AdapterError::InvalidRequest {
        message: "Responses adapter supports text input content only".into(),
    }
}

fn canonical_messages_to_json(messages: &[CanonicalMessage]) -> Value {
    Value::Array(
        messages
            .iter()
            .map(|message| {
                json!({
                    "role": message.role,
                    "content": canonical_content_to_json(&message.content),
                })
            })
            .collect(),
    )
}

fn canonical_content_to_json(content: &CanonicalContent) -> Value {
    match content {
        CanonicalContent::Text(text) => Value::String(text.clone()),
        CanonicalContent::TextBlocks(blocks) => Value::Array(
            blocks
                .iter()
                .map(|text| json!({ "type": "text", "text": text }))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_simple_responses_input() {
        let body = CanonicalAiRequest::from_responses_body(json!({
            "model": "logical",
            "instructions": "be concise",
            "input": "hello",
            "max_output_tokens": 64
        }))
        .unwrap()
        .into_chat_body_with_system_field();

        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "hello");
        assert_eq!(body["system"], "be concise");
        assert_eq!(body["max_tokens"], 64);
    }

    #[test]
    fn preserves_responses_message_roles_and_text_blocks() {
        let body = CanonicalAiRequest::from_responses_body(json!({
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hello"}]
                },
                {
                    "role": "assistant",
                    "content": "hi"
                }
            ]
        }))
        .unwrap()
        .into_chat_body_with_system_message();

        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"][0]["text"], "hello");
        assert_eq!(body["messages"][1]["role"], "assistant");
        assert_eq!(body["messages"][1]["content"], "hi");
    }

    #[test]
    fn rejects_non_text_responses_content() {
        let error = CanonicalAiRequest::from_responses_body(json!({
            "input": [{"type": "input_image", "image_url": "https://example.com/a.png"}]
        }))
        .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "Responses adapter supports text input content only".into()
            }
        );
    }
}
