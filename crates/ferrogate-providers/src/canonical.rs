// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};

use crate::AdapterError;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalAiRequest {
    source_body: Value,
    messages: Vec<CanonicalMessage>,
    tools: Vec<CanonicalToolDefinition>,
    tool_choice: Option<CanonicalToolChoice>,
    instructions: Option<Value>,
    max_output_tokens: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalToolDefinition {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum CanonicalToolChoice {
    Auto,
    None,
    Required,
    Tool(String),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CanonicalMessage {
    role: String,
    content: CanonicalContent,
}

#[derive(Debug, Clone, PartialEq)]
enum CanonicalContent {
    Text(String),
    TextBlocks(Vec<CanonicalContentBlock>),
    ToolCalls(Vec<CanonicalToolCall>),
}

#[derive(Debug, Clone, PartialEq)]
enum CanonicalContentBlock {
    Text(String),
    ImageUrl(String),
    ImageBase64(String),
}

impl CanonicalAiRequest {
    pub(crate) fn from_responses_body(body: Value) -> Result<Self, AdapterError> {
        let body = ensure_object_body(body)?;
        let input = body.get("input");
        Ok(Self {
            messages: responses_input_to_messages(input)?,
            tools: responses_tools_to_canonical(body.get("tools"))?,
            tool_choice: responses_tool_choice_to_canonical(body.get("tool_choice"))?,
            instructions: body.get("instructions").cloned(),
            max_output_tokens: body.get("max_output_tokens").cloned(),
            source_body: body,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_chat_body_with_system_field(self) -> Value {
        let mut body = self.source_body;
        body["messages"] = canonical_messages_to_json(&self.messages);
        if !self.tools.is_empty() {
            body["tools"] = canonical_tools_to_json(&self.tools);
        }
        if let Some(tool_choice) = &self.tool_choice {
            body["tool_choice"] = canonical_tool_choice_to_json(tool_choice);
        }
        if let Some(instructions) = self.instructions {
            body["system"] = instructions;
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            body["max_tokens"] = max_output_tokens;
        }
        body
    }

    #[cfg(test)]
    pub(crate) fn into_chat_body_with_system_message(self) -> Value {
        let mut body = self.source_body;
        let mut messages = canonical_messages_to_json(&self.messages);
        if !self.tools.is_empty() {
            body["tools"] = canonical_tools_to_json(&self.tools);
        }
        if let Some(tool_choice) = &self.tool_choice {
            body["tool_choice"] = canonical_tool_choice_to_json(tool_choice);
        }
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

    pub(crate) fn into_anthropic_body(self) -> Value {
        let mut body = self.source_body;
        body["messages"] = canonical_messages_to_anthropic_json(&self.messages);
        if !self.tools.is_empty() {
            body["tools"] = canonical_tools_to_anthropic_json(&self.tools);
        }
        if let Some(tool_choice) = &self.tool_choice {
            body["tool_choice"] = canonical_tool_choice_to_anthropic_json(tool_choice);
        }
        if let Some(instructions) = self.instructions {
            body["system"] = instructions;
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            body["max_tokens"] = max_output_tokens;
        }
        body
    }

    pub(crate) fn into_gemini_body(self) -> Value {
        let mut body = self.source_body;
        body["contents"] = canonical_messages_to_gemini_json(&self.messages);
        if let Some(instructions) = self.instructions {
            body["systemInstruction"] = canonical_instruction_to_gemini_json(&instructions);
        }
        if !self.tools.is_empty() {
            body["tools"] = canonical_tools_to_gemini_json(&self.tools);
        }
        if let Some(tool_choice) = &self.tool_choice {
            body["toolConfig"] = canonical_tool_choice_to_gemini_json(tool_choice);
        }
        if let Some(max_output_tokens) = self.max_output_tokens {
            body["generationConfig"] = json!({ "maxOutputTokens": max_output_tokens });
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
        Some(Value::Array(items)) if items.iter().any(has_message_role) => {
            if items.iter().any(|value| !has_message_role(value)) {
                return Err(content_not_supported_error());
            }
            items
                .iter()
                .map(responses_message_to_canonical_message)
                .collect()
        }
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
    let content = if let Some(tool_calls) = value.get("tool_calls") {
        if !tool_calls_is_empty(tool_calls) && !content_is_empty(value.get("content")) {
            return Err(content_not_supported_error());
        }
        CanonicalContent::ToolCalls(responses_tool_calls_to_canonical(tool_calls)?)
    } else {
        responses_content_to_canonical(value.get("content").unwrap_or(&Value::Null))?
    };
    Ok(CanonicalMessage {
        role: role.into(),
        content,
    })
}

fn responses_content_to_canonical(value: &Value) -> Result<CanonicalContent, AdapterError> {
    match value {
        Value::String(text) => Ok(CanonicalContent::Text(text.clone())),
        Value::Array(items) => {
            let mut blocks = Vec::new();
            let mut tool_calls = Vec::new();
            for item in items {
                match responses_content_item_to_canonical(item)? {
                    ResponsesContentItem::Block(block) => blocks.push(block),
                    ResponsesContentItem::ToolCall(tool_call) => tool_calls.push(tool_call),
                }
            }
            if !tool_calls.is_empty() {
                if !blocks.is_empty() {
                    return Err(content_not_supported_error());
                }
                Ok(CanonicalContent::ToolCalls(tool_calls))
            } else {
                Ok(CanonicalContent::TextBlocks(blocks))
            }
        }
        Value::Object(_) => match responses_content_item_to_canonical(value)? {
            ResponsesContentItem::Block(block) => Ok(CanonicalContent::TextBlocks(vec![block])),
            ResponsesContentItem::ToolCall(tool_call) => {
                Ok(CanonicalContent::ToolCalls(vec![tool_call]))
            }
        },
        Value::Null => Ok(CanonicalContent::Text(String::new())),
        _ => Err(content_not_supported_error()),
    }
}

enum ResponsesContentItem {
    Block(CanonicalContentBlock),
    ToolCall(CanonicalToolCall),
}

fn responses_content_item_to_canonical(
    value: &Value,
) -> Result<ResponsesContentItem, AdapterError> {
    match value {
        Value::String(text) => Ok(ResponsesContentItem::Block(CanonicalContentBlock::Text(
            text.clone(),
        ))),
        Value::Object(object) => {
            let block_type = object.get("type").and_then(Value::as_str);
            if matches!(block_type, Some("input_text" | "output_text" | "text")) {
                return Ok(ResponsesContentItem::Block(CanonicalContentBlock::Text(
                    object
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                )));
            }
            if matches!(block_type, Some("input_image" | "image_url" | "image")) {
                let image =
                    extract_image_reference(object).ok_or_else(content_not_supported_error)?;
                if image.starts_with("data:") {
                    return Ok(ResponsesContentItem::Block(
                        CanonicalContentBlock::ImageBase64(image),
                    ));
                }
                return Ok(ResponsesContentItem::Block(
                    CanonicalContentBlock::ImageUrl(image),
                ));
            }
            if matches!(block_type, Some("tool_call" | "function_call" | "tool_use")) {
                return Ok(ResponsesContentItem::ToolCall(
                    responses_tool_call_to_canonical(value)?,
                ));
            }
            Err(content_not_supported_error())
        }
        _ => Err(content_not_supported_error()),
    }
}

fn responses_tool_calls_to_canonical(
    value: &Value,
) -> Result<Vec<CanonicalToolCall>, AdapterError> {
    match value {
        Value::Array(items) => items.iter().map(responses_tool_call_to_canonical).collect(),
        Value::Object(_) => Ok(vec![responses_tool_call_to_canonical(value)?]),
        Value::Null => Ok(Vec::new()),
        _ => Err(content_not_supported_error()),
    }
}

fn responses_tool_call_to_canonical(value: &Value) -> Result<CanonicalToolCall, AdapterError> {
    let function = value.get("function");
    let id = value
        .get("id")
        .or_else(|| value.get("call_id"))
        .and_then(Value::as_str)
        .ok_or_else(content_not_supported_error)?
        .to_string();
    let name = function
        .and_then(|function| function.get("name"))
        .or_else(|| value.get("name"))
        .and_then(Value::as_str)
        .ok_or_else(content_not_supported_error)?
        .to_string();
    let arguments = function
        .and_then(|function| function.get("arguments"))
        .or_else(|| value.get("arguments"))
        .or_else(|| value.get("input"))
        .or_else(|| value.get("args"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(CanonicalToolCall {
        id,
        name,
        arguments: parse_json_string_or_clone(&arguments),
    })
}

fn content_is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        Some(Value::Array(items)) => items.is_empty(),
        Some(Value::Object(object)) => object.is_empty(),
        _ => false,
    }
}

fn tool_calls_is_empty(value: &Value) -> bool {
    matches!(value, Value::Null) || value.as_array().is_some_and(Vec::is_empty)
}

fn extract_image_reference(object: &serde_json::Map<String, Value>) -> Option<String> {
    object
        .get("image_url")
        .or_else(|| object.get("url"))
        .or_else(|| object.get("source").and_then(|source| source.get("url")))
        .or_else(|| object.get("source").and_then(|source| source.get("data")))
        .and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Object(image) => image
                .get("url")
                .or_else(|| image.get("data"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        })
        .or_else(|| {
            object
                .get("image_url")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
}

fn content_not_supported_error() -> AdapterError {
    AdapterError::InvalidRequest {
        message: "Responses adapter supports text, image, and tool-call input content only".into(),
    }
}

#[cfg(test)]
fn canonical_messages_to_json(messages: &[CanonicalMessage]) -> Value {
    Value::Array(messages.iter().map(canonical_message_to_json).collect())
}

fn canonical_messages_to_anthropic_json(messages: &[CanonicalMessage]) -> Value {
    Value::Array(
        messages
            .iter()
            .map(|message| {
                let content = canonical_content_to_anthropic_json(&message.content);
                json!({
                    "role": message.role,
                    "content": content,
                })
            })
            .collect(),
    )
}

fn canonical_messages_to_gemini_json(messages: &[CanonicalMessage]) -> Value {
    Value::Array(
        messages
            .iter()
            .filter(|message| message.role != "system")
            .map(|message| {
                json!({
                    "role": canonical_role_to_gemini_role(&message.role),
                    "parts": canonical_content_to_gemini_parts(&message.content),
                })
            })
            .collect(),
    )
}

#[cfg(test)]
fn canonical_message_to_json(message: &CanonicalMessage) -> Value {
    match &message.content {
        CanonicalContent::ToolCalls(tool_calls) => json!({
            "role": message.role,
            "content": Value::Null,
            "tool_calls": canonical_tool_calls_to_json(tool_calls),
        }),
        _ => json!({
            "role": message.role,
            "content": canonical_content_to_json(&message.content),
        }),
    }
}

#[cfg(test)]
fn canonical_content_to_json(content: &CanonicalContent) -> Value {
    match content {
        CanonicalContent::Text(text) => Value::String(text.clone()),
        CanonicalContent::TextBlocks(blocks) => {
            Value::Array(blocks.iter().map(canonical_content_block_to_json).collect())
        }
        CanonicalContent::ToolCalls(_) => Value::Null,
    }
}

fn canonical_content_to_anthropic_json(content: &CanonicalContent) -> Value {
    match content {
        CanonicalContent::Text(text) => Value::String(text.clone()),
        CanonicalContent::TextBlocks(blocks) => Value::Array(
            blocks
                .iter()
                .map(canonical_content_block_to_anthropic_json)
                .collect(),
        ),
        CanonicalContent::ToolCalls(tool_calls) => Value::Array(
            tool_calls
                .iter()
                .map(|tool_call| {
                    json!({
                        "type": "tool_use",
                        "id": tool_call.id,
                        "name": tool_call.name,
                        "input": tool_call.arguments,
                    })
                })
                .collect(),
        ),
    }
}

fn canonical_content_to_gemini_parts(content: &CanonicalContent) -> Value {
    match content {
        CanonicalContent::Text(text) => Value::Array(vec![json!({ "text": text })]),
        CanonicalContent::TextBlocks(blocks) => Value::Array(
            blocks
                .iter()
                .map(canonical_content_block_to_gemini_part)
                .collect(),
        ),
        CanonicalContent::ToolCalls(tool_calls) => Value::Array(
            tool_calls
                .iter()
                .map(|tool_call| {
                    json!({
                        "functionCall": {
                            "name": tool_call.name,
                            "args": tool_call.arguments,
                            "id": tool_call.id,
                        }
                    })
                })
                .collect(),
        ),
    }
}

#[cfg(test)]
fn canonical_content_block_to_json(block: &CanonicalContentBlock) -> Value {
    match block {
        CanonicalContentBlock::Text(text) => json!({ "type": "text", "text": text }),
        CanonicalContentBlock::ImageUrl(url) => {
            json!({ "type": "image_url", "image_url": { "url": url } })
        }
        CanonicalContentBlock::ImageBase64(data_url) => {
            json!({ "type": "image_url", "image_url": { "url": data_url } })
        }
    }
}

fn canonical_content_block_to_anthropic_json(block: &CanonicalContentBlock) -> Value {
    match block {
        CanonicalContentBlock::Text(text) => json!({ "type": "text", "text": text }),
        CanonicalContentBlock::ImageUrl(url) => json!({
            "type": "image",
            "source": {
                "type": "url",
                "url": url,
            }
        }),
        CanonicalContentBlock::ImageBase64(data_url) => {
            let (media_type, data) = decode_data_url(data_url)
                .unwrap_or_else(|| ("image/png".to_string(), data_url.clone()));
            json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": media_type,
                    "data": data,
                }
            })
        }
    }
}

fn canonical_content_block_to_gemini_part(block: &CanonicalContentBlock) -> Value {
    match block {
        CanonicalContentBlock::Text(text) => json!({ "text": text }),
        CanonicalContentBlock::ImageUrl(url) => json!({
            "fileData": {
                "fileUri": url,
            }
        }),
        CanonicalContentBlock::ImageBase64(data_url) => {
            let (mime_type, data) = decode_data_url(data_url)
                .unwrap_or_else(|| ("image/png".to_string(), data_url.clone()));
            json!({
                "inlineData": {
                    "mimeType": mime_type,
                    "data": data,
                }
            })
        }
    }
}

fn canonical_instruction_to_gemini_json(instructions: &Value) -> Value {
    json!({
        "role": "system",
        "parts": canonical_instruction_parts(instructions),
    })
}

fn canonical_instruction_parts(instructions: &Value) -> Value {
    match instructions {
        Value::String(text) => Value::Array(vec![json!({ "text": text })]),
        Value::Array(blocks) => Value::Array(
            blocks
                .iter()
                .filter_map(|block| match block {
                    Value::String(text) => Some(json!({ "text": text })),
                    Value::Object(object) if object.get("type").and_then(Value::as_str) == Some("text") => {
                        Some(json!({ "text": object.get("text").and_then(Value::as_str).unwrap_or("") }))
                    }
                    _ => None,
                })
                .collect(),
        ),
        _ => Value::Array(Vec::new()),
    }
}

fn canonical_tools_to_anthropic_json(tools: &[CanonicalToolDefinition]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|tool| {
                let mut value = json!({
                    "name": tool.name,
                    "input_schema": tool.input_schema,
                });
                if let Some(description) = &tool.description {
                    value["description"] = Value::String(description.clone());
                }
                value
            })
            .collect(),
    )
}

fn canonical_tools_to_gemini_json(tools: &[CanonicalToolDefinition]) -> Value {
    Value::Array(vec![json!({
        "functionDeclarations": tools
            .iter()
            .map(|tool| {
                let mut value = json!({
                    "name": tool.name,
                    "parameters": tool.input_schema,
                });
                if let Some(description) = &tool.description {
                    value["description"] = Value::String(description.clone());
                }
                value
            })
            .collect::<Vec<_>>(),
    })])
}

fn canonical_tool_choice_to_anthropic_json(choice: &CanonicalToolChoice) -> Value {
    match choice {
        CanonicalToolChoice::Auto => json!({ "type": "auto" }),
        CanonicalToolChoice::None => json!({ "type": "none" }),
        CanonicalToolChoice::Required => json!({ "type": "any" }),
        CanonicalToolChoice::Tool(name) => json!({ "type": "tool", "name": name }),
    }
}

fn canonical_tool_choice_to_gemini_json(choice: &CanonicalToolChoice) -> Value {
    match choice {
        CanonicalToolChoice::Auto => json!({
            "functionCallingConfig": { "mode": "AUTO" }
        }),
        CanonicalToolChoice::None => json!({
            "functionCallingConfig": { "mode": "NONE" }
        }),
        CanonicalToolChoice::Required => json!({
            "functionCallingConfig": { "mode": "ANY" }
        }),
        CanonicalToolChoice::Tool(name) => json!({
            "functionCallingConfig": {
                "mode": "ANY",
                "allowedFunctionNames": [name],
            }
        }),
    }
}

fn canonical_role_to_gemini_role(role: &str) -> &'static str {
    match role {
        "assistant" | "model" => "model",
        "system" => "user",
        "tool" => "user",
        _ => "user",
    }
}

fn decode_data_url(value: &str) -> Option<(String, String)> {
    let rest = value.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let media_type = meta.split(';').next().unwrap_or("image/png").to_string();
    Some((media_type, data.to_string()))
}

#[cfg(test)]
fn canonical_tool_calls_to_json(tool_calls: &[CanonicalToolCall]) -> Value {
    Value::Array(
        tool_calls
            .iter()
            .map(|tool_call| {
                json!({
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.name,
                        "arguments": tool_arguments_to_string(&tool_call.arguments),
                    }
                })
            })
            .collect(),
    )
}

#[cfg(test)]
fn canonical_tools_to_json(tools: &[CanonicalToolDefinition]) -> Value {
    Value::Array(
        tools
            .iter()
            .map(|tool| {
                let mut function = json!({
                    "name": tool.name,
                    "parameters": tool.input_schema,
                });
                if let Some(description) = &tool.description {
                    function["description"] = Value::String(description.clone());
                }
                json!({
                    "type": "function",
                    "function": function,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
fn canonical_tool_choice_to_json(choice: &CanonicalToolChoice) -> Value {
    match choice {
        CanonicalToolChoice::Auto => Value::String("auto".into()),
        CanonicalToolChoice::None => Value::String("none".into()),
        CanonicalToolChoice::Required => Value::String("required".into()),
        CanonicalToolChoice::Tool(name) => json!({
            "type": "function",
            "function": {
                "name": name,
            },
        }),
    }
}

fn responses_tools_to_canonical(
    value: Option<&Value>,
) -> Result<Vec<CanonicalToolDefinition>, AdapterError> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .map(responses_tool_definition_to_canonical)
            .collect(),
        Some(Value::Null) | None => Ok(Vec::new()),
        Some(_) => Err(content_not_supported_error()),
    }
}

fn responses_tool_definition_to_canonical(
    value: &Value,
) -> Result<CanonicalToolDefinition, AdapterError> {
    let object = value.as_object().ok_or_else(content_not_supported_error)?;
    let function = object.get("function").and_then(Value::as_object);
    let name = object
        .get("name")
        .or_else(|| function.and_then(|function| function.get("name")))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(content_not_supported_error)?
        .to_string();
    let description = object
        .get("description")
        .or_else(|| function.and_then(|function| function.get("description")))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let input_schema = object
        .get("input_schema")
        .or_else(|| object.get("parameters"))
        .or_else(|| function.and_then(|function| function.get("parameters")))
        .cloned()
        .ok_or_else(content_not_supported_error)?;
    Ok(CanonicalToolDefinition {
        name,
        description,
        input_schema,
    })
}

fn responses_tool_choice_to_canonical(
    value: Option<&Value>,
) -> Result<Option<CanonicalToolChoice>, AdapterError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(choice)) => match choice.as_str() {
            "auto" => Ok(Some(CanonicalToolChoice::Auto)),
            "none" => Ok(Some(CanonicalToolChoice::None)),
            "required" | "any" => Ok(Some(CanonicalToolChoice::Required)),
            _ => Err(content_not_supported_error()),
        },
        Some(Value::Object(object)) => {
            let kind = object.get("type").and_then(Value::as_str);
            match kind {
                Some("auto") => Ok(Some(CanonicalToolChoice::Auto)),
                Some("none") => Ok(Some(CanonicalToolChoice::None)),
                Some("required" | "any") => Ok(Some(CanonicalToolChoice::Required)),
                Some("function") | Some("tool") => {
                    let name = object
                        .get("name")
                        .or_else(|| {
                            object
                                .get("function")
                                .and_then(Value::as_object)
                                .and_then(|function| function.get("name"))
                        })
                        .and_then(Value::as_str)
                        .filter(|name| !name.trim().is_empty())
                        .ok_or_else(content_not_supported_error)?;
                    Ok(Some(CanonicalToolChoice::Tool(name.to_string())))
                }
                _ => Err(content_not_supported_error()),
            }
        }
        _ => Err(content_not_supported_error()),
    }
}

fn parse_json_string_or_clone(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| value.clone())
}

#[cfg(test)]
fn tool_arguments_to_string(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
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
    fn parses_tool_definitions_tool_choice_and_multimodal_input() {
        let body = CanonicalAiRequest::from_responses_body(json!({
            "instructions": "be concise",
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup_weather",
                    "description": "Lookup weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}}
                    }
                }
            }],
            "tool_choice": {"type": "tool", "name": "lookup_weather"},
            "input": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_text", "text": "hello"},
                        {"type": "input_image", "image_url": "https://example.com/a.png"},
                        {"type": "input_image", "image_url": "data:image/png;base64,Zm9v"}
                    ]
                },
                {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "lookup_weather",
                            "arguments": "{\"city\":\"Shanghai\"}"
                        }
                    }]
                }
            ]
        }))
        .unwrap()
        .into_chat_body_with_system_field();

        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "lookup_weather");
        assert_eq!(body["tool_choice"]["type"], "function");
        assert_eq!(body["messages"][0]["content"][0]["type"], "text");
        assert_eq!(body["messages"][0]["content"][1]["type"], "image_url");
        assert_eq!(
            body["messages"][0]["content"][1]["image_url"]["url"],
            "https://example.com/a.png"
        );
        assert_eq!(
            body["messages"][0]["content"][2]["image_url"]["url"],
            "data:image/png;base64,Zm9v"
        );
        assert_eq!(body["messages"][1]["tool_calls"][0]["id"], "call_1");
        assert_eq!(
            body["messages"][1]["tool_calls"][0]["function"]["name"],
            "lookup_weather"
        );
        assert_eq!(body["system"], "be concise");
    }

    #[test]
    fn rejects_unsupported_mixed_tool_call_content() {
        let error = CanonicalAiRequest::from_responses_body(json!({
            "input": [{
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "hello"},
                    {"type": "tool_call", "id": "call_1", "name": "lookup_weather", "arguments": {}}
                ]
            }]
        }))
        .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "Responses adapter supports text, image, and tool-call input content only"
                    .into()
            }
        );
    }
}
