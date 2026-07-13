// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};

use ferrogate_core::{ToolCall, ToolDef, ToolResult};

use crate::{
    canonical::CanonicalAiRequest, AdapterError, ChatCompletionPlan, ProviderAdapter,
    ProviderConfig, ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage,
    ResponsesPlan, SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct AnthropicAdapter;

impl ProviderAdapter for AnthropicAdapter {
    fn kind(&self) -> &'static str {
        "anthropic"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let body = ensure_object_body(request.body)?;
        let messages = body.get("messages").cloned().unwrap_or_else(|| json!([]));
        let max_tokens = body
            .get("max_tokens")
            .cloned()
            .unwrap_or_else(|| json!(1024));

        let mut anthropic_body = json!({
            "model": request.provider_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": request.stream,
        });
        if let Some(system) = body.get("system") {
            anthropic_body["system"] = system.clone();
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: messages_endpoint(&provider.base_url),
            body: anthropic_body,
            stream: request.stream,
            headers: anthropic_headers(provider.api_key),
        })
    }

    fn prepare_responses(
        &self,
        provider: ProviderConfig,
        request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let body = CanonicalAiRequest::from_responses_body(request.body)?.into_anthropic_body();
        let messages = body.get("messages").cloned().unwrap_or_else(|| json!([]));
        let max_tokens = body
            .get("max_tokens")
            .cloned()
            .unwrap_or_else(|| json!(1024));

        let mut anthropic_body = json!({
            "model": request.provider_model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": request.stream,
        });
        if let Some(system) = body.get("system") {
            anthropic_body["system"] = system.clone();
        }
        if let Some(tools) = body.get("tools") {
            anthropic_body["tools"] = tools.clone();
        }
        if let Some(tool_choice) = body.get("tool_choice") {
            anthropic_body["tool_choice"] = tool_choice.clone();
        }

        Ok(ProviderHttpRequest {
            provider: provider.name.clone(),
            endpoint: messages_endpoint(&provider.base_url),
            body: anthropic_body,
            stream: request.stream,
            headers: anthropic_headers(provider.api_key),
        })
    }

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse {
        let parsed = serde_json::from_slice::<Value>(body).ok();
        let provider_error = parsed.as_ref().and_then(|value| value.get("error"));
        let message = provider_error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| fallback_error_message(parsed.as_ref(), body))
            .unwrap_or_else(|| format!("provider returned HTTP {status}"));
        let provider_type = provider_error
            .and_then(|error| error.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("provider_error");

        ProviderErrorResponse {
            status,
            body: json!({
                "error": {
                    "message": message,
                    "type": "provider_error",
                    "provider_type": provider_type,
                    "code": provider_type,
                    "provider_status": status,
                    "provider_content_type": content_type,
                    "request_id": request_id,
                }
            }),
        }
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        let value = serde_json::from_slice::<Value>(body).ok()?;
        let usage = value.get("usage").or_else(|| {
            value
                .get("message")
                .and_then(|message| message.get("usage"))
        })?;
        let prompt_tokens = usage.get("input_tokens").and_then(Value::as_u64);
        let completion_tokens = usage.get("output_tokens").and_then(Value::as_u64);
        let total_tokens = prompt_tokens
            .zip(completion_tokens)
            .map(|(left, right)| left + right);
        let extracted = ProviderUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        };
        (extracted.prompt_tokens.is_some()
            || extracted.completion_tokens.is_some()
            || extracted.total_tokens.is_some())
        .then_some(extracted)
    }

    fn inject_tools(&self, body: Value, tools: &[ToolDef]) -> Result<Value, AdapterError> {
        let mut body = ensure_object_body(body)?;
        if tools.is_empty() {
            return Ok(body);
        }
        body["tools"] = Value::Array(
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
        );
        Ok(body)
    }

    fn extract_tool_calls(&self, body: &[u8]) -> Result<Vec<ToolCall>, AdapterError> {
        let value = serde_json::from_slice::<Value>(body).map_err(|error| {
            AdapterError::InvalidRequest {
                message: format!("provider response body must be JSON: {error}"),
            }
        })?;
        Ok(value
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|block| {
                block
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind == "tool_use")
            })
            .filter_map(anthropic_tool_use_to_canonical)
            .collect())
    }

    fn append_tool_results(
        &self,
        body: Value,
        results: &[ToolResult],
    ) -> Result<Value, AdapterError> {
        let mut body = ensure_object_body(body)?;
        if results.is_empty() {
            return Ok(body);
        }
        if !body.get("messages").is_some_and(Value::is_array) {
            body["messages"] = json!([]);
        }
        let messages = body["messages"]
            .as_array_mut()
            .expect("messages initialized as array");
        messages.push(json!({
            "role": "user",
            "content": results.iter().map(|result| {
                json!({
                    "type": "tool_result",
                    "tool_use_id": result.tool_call_id,
                    "content": tool_result_content_to_string(&result.content),
                    "is_error": result.is_error,
                })
            }).collect::<Vec<_>>(),
        }));
        Ok(body)
    }
}

fn anthropic_headers(api_key: Option<String>) -> Vec<ProviderHeader> {
    let mut headers = vec![
        ProviderHeader {
            name: "content-type".into(),
            value: SecretValue::new("application/json"),
        },
        ProviderHeader {
            name: "anthropic-version".into(),
            value: SecretValue::new("2023-06-01"),
        },
    ];
    if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
        headers.push(ProviderHeader {
            name: "x-api-key".into(),
            value: SecretValue::new(api_key),
        });
    }
    headers
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    match kind {
        "anthropic" => Ok(()),
        other => Err(AdapterError::UnsupportedProviderKind {
            kind: other.to_string(),
        }),
    }
}

fn ensure_object_body(body: Value) -> Result<Value, AdapterError> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(AdapterError::InvalidRequest {
            message: "chat completion request body must be a JSON object".into(),
        })
    }
}

fn messages_endpoint(base_url: &str) -> String {
    format!("{}/messages", base_url.trim_end_matches('/'))
}

fn fallback_error_message(parsed: Option<&Value>, body: &[u8]) -> Option<String> {
    parsed
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .or_else(|| {
            let text = std::str::from_utf8(body).ok()?.trim();
            (!text.is_empty()).then(|| text.chars().take(512).collect())
        })
}

fn anthropic_tool_use_to_canonical(value: &Value) -> Option<ToolCall> {
    Some(ToolCall {
        id: value.get("id")?.as_str()?.to_string(),
        name: value.get("name")?.as_str()?.to_string(),
        arguments: value.get("input").cloned().unwrap_or(Value::Null),
    })
}

fn tool_result_content_to_string(value: &Value) -> String {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "anthropic".into(),
            kind: "anthropic".into(),
            base_url: "https://api.anthropic.example/v1/".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: None,
            gcp_credentials: None,
        }
    }

    #[test]
    fn converts_openai_chat_plan_to_anthropic_messages_request() {
        let adapter = AnthropicAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "claude-chat".into(),
                    provider_model: "claude-3-5-sonnet-latest".into(),
                    stream: true,
                    body: json!({
                        "model": "claude-chat",
                        "messages": [{"role": "user", "content": "hello"}],
                        "max_tokens": 256,
                        "system": "be concise"
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://api.anthropic.example/v1/messages"
        );
        assert_eq!(prepared.body["model"], "claude-3-5-sonnet-latest");
        assert_eq!(prepared.body["messages"][0]["content"], "hello");
        assert_eq!(prepared.body["max_tokens"], 256);
        assert_eq!(prepared.body["system"], "be concise");
        assert_eq!(prepared.body["stream"], true);
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.name == "x-api-key"
                && header.value.expose_secret() == "provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn rejects_non_object_chat_body() {
        let adapter = AnthropicAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider(None),
                ChatCompletionPlan {
                    logical_model: "claude-chat".into(),
                    provider_model: "claude".into(),
                    stream: false,
                    body: json!("bad"),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "chat completion request body must be a JSON object".into()
            }
        );
    }

    #[test]
    fn converts_responses_plan_to_anthropic_messages_request() {
        let adapter = AnthropicAdapter;
        let prepared = adapter
            .prepare_responses(
                provider(Some("provider-secret")),
                ResponsesPlan {
                    logical_model: "claude-chat".into(),
                    provider_model: "claude-3-5-sonnet-latest".into(),
                    stream: false,
                    body: json!({
                        "model": "claude-chat",
                        "instructions": "be concise",
                        "input": "hello",
                        "max_output_tokens": 256
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://api.anthropic.example/v1/messages"
        );
        assert_eq!(prepared.body["model"], "claude-3-5-sonnet-latest");
        assert_eq!(prepared.body["messages"][0]["role"], "user");
        assert_eq!(prepared.body["messages"][0]["content"], "hello");
        assert_eq!(prepared.body["system"], "be concise");
        assert_eq!(prepared.body["max_tokens"], 256);
        assert_eq!(prepared.body["stream"], false);
    }

    #[test]
    fn converts_responses_plan_with_tool_choice_and_image_inputs_to_anthropic_messages_request() {
        let adapter = AnthropicAdapter;
        let prepared = adapter
            .prepare_responses(
                provider(None),
                ResponsesPlan {
                    logical_model: "claude-chat".into(),
                    provider_model: "claude-3-5-sonnet-latest".into(),
                    stream: false,
                    body: json!({
                        "tools": [{
                            "type": "function",
                            "function": {
                                "name": "lookup_weather",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"city": {"type": "string"}}
                                }
                            }
                        }],
                        "tool_choice": {"type": "tool", "name": "lookup_weather"},
                        "input": [{
                            "role": "user",
                            "content": [
                                {"type": "input_text", "text": "look"},
                                {"type": "input_image", "image_url": "https://example.com/a.png"}
                            ]
                        }]
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.body["tools"][0]["name"], "lookup_weather");
        assert_eq!(prepared.body["tool_choice"]["type"], "tool");
        assert_eq!(prepared.body["messages"][0]["content"][0]["type"], "text");
        assert_eq!(prepared.body["messages"][0]["content"][1]["type"], "image");
        assert_eq!(
            prepared.body["messages"][0]["content"][1]["source"]["type"],
            "url"
        );
    }

    #[test]
    fn normalizes_anthropic_error_response() {
        let adapter = AnthropicAdapter;
        let normalized = adapter.normalize_error_response(
            400,
            "application/json",
            br#"{"type":"error","error":{"type":"invalid_request_error","message":"bad request"}}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 400);
        assert_eq!(normalized.body["error"]["message"], "bad request");
        assert_eq!(
            normalized.body["error"]["provider_type"],
            "invalid_request_error"
        );
        assert_eq!(normalized.body["error"]["code"], "invalid_request_error");
    }

    #[test]
    fn extracts_anthropic_usage_metadata() {
        let adapter = AnthropicAdapter;
        let usage = adapter
            .extract_usage(br#"{"usage":{"input_tokens":13,"output_tokens":8}}"#)
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(13));
        assert_eq!(usage.completion_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(21));
    }

    #[test]
    fn injects_anthropic_tools_and_round_trips_tool_calls() {
        let adapter = AnthropicAdapter;
        let body = adapter
            .inject_tools(
                json!({"model": "claude", "messages": []}),
                &[ToolDef {
                    name: "lookup_weather".into(),
                    description: Some("Lookup weather".into()),
                    input_schema: json!({
                        "type": "object",
                        "properties": {"city": {"type": "string"}}
                    }),
                }],
            )
            .unwrap();

        assert_eq!(body["tools"][0]["name"], "lookup_weather");
        assert_eq!(
            body["tools"][0]["input_schema"]["properties"]["city"]["type"],
            "string"
        );

        let calls = adapter
            .extract_tool_calls(
                br#"{"stop_reason":"tool_use","content":[{"type":"text","text":"checking"},{"type":"tool_use","id":"toolu_1","name":"lookup_weather","input":{"city":"Shanghai"}}]}"#,
            )
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "toolu_1");
        assert_eq!(calls[0].name, "lookup_weather");
        assert_eq!(calls[0].arguments["city"], "Shanghai");
    }

    #[test]
    fn appends_anthropic_tool_results_as_content_blocks() {
        let adapter = AnthropicAdapter;
        let body = adapter
            .append_tool_results(
                json!({"messages": [{"role": "user", "content": "weather?"}]}),
                &[ToolResult {
                    tool_call_id: "toolu_1".into(),
                    content: json!({"temp_c": 21}),
                    is_error: false,
                }],
            )
            .unwrap();

        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["messages"][1]["content"][0]["type"], "tool_result");
        assert_eq!(body["messages"][1]["content"][0]["tool_use_id"], "toolu_1");
        assert_eq!(
            body["messages"][1]["content"][0]["content"],
            r#"{"temp_c":21}"#
        );
    }
}
