// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};

use ferrogate_core::{ToolCall, ToolDef, ToolResult};

use crate::types::is_openai_compatible_provider_kind;
use crate::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderCatalogModel,
    ProviderCatalogRequest, ProviderConfig, ProviderErrorResponse, ProviderHeader,
    ProviderHttpRequest, ProviderUsage, ResponsesPlan, SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenAiCompatibleAdapter;

impl ProviderAdapter for OpenAiCompatibleAdapter {
    fn kind(&self) -> &'static str {
        "openai-compatible"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let mut body = ensure_chat_object_body(request.body)?;
        body["model"] = Value::String(request.provider_model);
        body["stream"] = Value::Bool(request.stream);

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: chat_completions_endpoint(&provider.base_url),
            body,
            stream: request.stream,
            headers: provider_headers(provider.api_key),
        })
    }

    fn prepare_responses(
        &self,
        provider: ProviderConfig,
        request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let mut body = ensure_labeled_object_body(request.body, "responses request body")?;
        body["model"] = Value::String(request.provider_model);
        body["stream"] = Value::Bool(request.stream);

        Ok(ProviderHttpRequest {
            provider: provider.name.clone(),
            endpoint: responses_endpoint(&provider.base_url),
            body,
            stream: request.stream,
            headers: provider_headers(provider.api_key),
        })
    }

    fn prepare_model_catalog(
        &self,
        provider: ProviderConfig,
    ) -> Result<ProviderCatalogRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        Ok(ProviderCatalogRequest {
            provider: provider.name,
            endpoint: models_endpoint(&provider.base_url),
            headers: provider_headers(provider.api_key),
        })
    }

    fn parse_model_catalog(&self, body: &[u8]) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
        parse_openai_model_catalog(body)
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
        let kind = provider_error
            .and_then(|error| error.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("provider_error");
        let code = provider_error
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .filter(|code| !code.trim().is_empty())
            .unwrap_or("provider_error");

        ProviderErrorResponse {
            status,
            body: json!({
                "error": {
                    "message": message,
                    "type": "provider_error",
                    "provider_type": kind,
                    "code": code,
                    "provider_status": status,
                    "provider_content_type": content_type,
                    "request_id": request_id,
                }
            }),
        }
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        let value = serde_json::from_slice::<Value>(body).ok()?;
        let usage = value.get("usage")?;
        let extracted = ProviderUsage {
            prompt_tokens: usage.get("prompt_tokens").and_then(Value::as_u64),
            completion_tokens: usage.get("completion_tokens").and_then(Value::as_u64),
            total_tokens: usage.get("total_tokens").and_then(Value::as_u64),
        };
        (extracted.prompt_tokens.is_some()
            || extracted.completion_tokens.is_some()
            || extracted.total_tokens.is_some())
        .then_some(extracted)
    }

    fn inject_tools(&self, body: Value, tools: &[ToolDef]) -> Result<Value, AdapterError> {
        let mut body = ensure_labeled_object_body(body, "tool-enabled request body")?;
        if tools.is_empty() {
            return Ok(body);
        }
        body["tools"] = Value::Array(
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
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|choice| choice.get("message"))
            .filter_map(|message| message.get("tool_calls"))
            .filter_map(Value::as_array)
            .flatten()
            .filter_map(openai_tool_call_to_canonical)
            .collect())
    }

    fn append_tool_results(
        &self,
        body: Value,
        results: &[ToolResult],
    ) -> Result<Value, AdapterError> {
        let mut body = ensure_labeled_object_body(body, "tool-result request body")?;
        if results.is_empty() {
            return Ok(body);
        }
        if !body.get("messages").is_some_and(Value::is_array) {
            body["messages"] = json!([]);
        }
        let messages = body["messages"]
            .as_array_mut()
            .expect("messages initialized as array");
        messages.extend(results.iter().map(|result| {
            json!({
                "role": "tool",
                "tool_call_id": result.tool_call_id,
                "content": tool_result_content_to_string(&result.content),
            })
        }));
        Ok(body)
    }
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    if is_openai_compatible_provider_kind(kind) {
        Ok(())
    } else {
        Err(AdapterError::UnsupportedProviderKind {
            kind: kind.trim().to_ascii_lowercase(),
        })
    }
}

fn ensure_chat_object_body(body: Value) -> Result<Value, AdapterError> {
    ensure_labeled_object_body(body, "chat completion request body")
}

fn ensure_labeled_object_body(body: Value, label: &str) -> Result<Value, AdapterError> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(AdapterError::InvalidRequest {
            message: format!("{label} must be a JSON object"),
        })
    }
}

fn provider_headers(api_key: Option<String>) -> Vec<ProviderHeader> {
    let mut headers = vec![ProviderHeader {
        name: "content-type".into(),
        value: SecretValue::new("application/json"),
    }];
    if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
        headers.push(ProviderHeader {
            name: "authorization".into(),
            value: SecretValue::new(format!("Bearer {api_key}")),
        });
    }
    headers
}

fn chat_completions_endpoint(base_url: &str) -> String {
    format!("{}/chat/completions", base_url.trim_end_matches('/'))
}

fn responses_endpoint(base_url: &str) -> String {
    format!("{}/responses", base_url.trim_end_matches('/'))
}

fn models_endpoint(base_url: &str) -> String {
    format!("{}/models", base_url.trim_end_matches('/'))
}

fn parse_openai_model_catalog(body: &[u8]) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
    let value =
        serde_json::from_slice::<Value>(body).map_err(|error| AdapterError::InvalidRequest {
            message: format!("provider model catalog must be JSON: {error}"),
        })?;
    let data = value.get("data").and_then(Value::as_array).ok_or_else(|| {
        AdapterError::InvalidRequest {
            message: "provider model catalog must include a data array".into(),
        }
    })?;

    data.iter()
        .map(|model| {
            let id = model
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .ok_or_else(|| AdapterError::InvalidRequest {
                    message: "provider model catalog entry missing id".into(),
                })?
                .to_string();
            Ok(ProviderCatalogModel {
                id,
                owned_by: model
                    .get("owned_by")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                created: model.get("created").and_then(Value::as_u64),
                context_window: model
                    .get("context_length")
                    .or_else(|| model.get("context_window"))
                    .and_then(Value::as_u64),
                capabilities: catalog_capabilities(model),
            })
        })
        .collect()
}

fn catalog_capabilities(model: &Value) -> Vec<String> {
    let mut capabilities = Vec::new();
    for key in [
        "capabilities",
        "supported_modalities",
        "input_modalities",
        "output_modalities",
    ] {
        if let Some(values) = model.get(key).and_then(Value::as_array) {
            capabilities.extend(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(ToOwned::to_owned),
            );
        }
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn fallback_error_message(parsed: Option<&Value>, body: &[u8]) -> Option<String> {
    parsed
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .or_else(|| {
            let text = std::str::from_utf8(body).ok()?.trim();
            (!text.is_empty()).then(|| text.chars().take(512).collect())
        })
}

fn openai_tool_call_to_canonical(value: &Value) -> Option<ToolCall> {
    let function = value.get("function")?;
    Some(ToolCall {
        id: value.get("id")?.as_str()?.to_string(),
        name: function.get("name")?.as_str()?.to_string(),
        arguments: parse_json_string_or_clone(function.get("arguments")?),
    })
}

fn parse_json_string_or_clone(value: &Value) -> Value {
    value
        .as_str()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .unwrap_or_else(|| value.clone())
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
    use serde_json::json;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "https://api.openai.example/v1/".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: None,
            gcp_credentials: None,
        }
    }

    #[test]
    fn rewrites_logical_model_to_provider_model() {
        let adapter = OpenAiCompatibleAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(None),
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4o-mini".into(),
                    stream: false,
                    body: json!({
                        "model": "fast-chat",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://api.openai.example/v1/chat/completions"
        );
        assert_eq!(prepared.body["model"], "gpt-4o-mini");
        assert_eq!(prepared.body["stream"], false);
        assert_eq!(prepared.body["messages"][0]["content"], "hello");
    }

    #[test]
    fn preserves_streaming_flag_and_redacts_secret_debug_output() {
        let adapter = OpenAiCompatibleAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "provider-chat".into(),
                    stream: true,
                    body: json!({"model": "fast-chat", "stream": false}),
                },
            )
            .unwrap();

        assert!(prepared.stream);
        assert_eq!(prepared.body["stream"], true);
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.value.expose_secret() == "Bearer provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn prepares_model_catalog_request_without_leaking_secret_debug_output() {
        let adapter = OpenAiCompatibleAdapter;
        let prepared = adapter
            .prepare_model_catalog(provider(Some("provider-secret")))
            .unwrap();

        assert_eq!(prepared.provider, "openai");
        assert_eq!(prepared.endpoint, "https://api.openai.example/v1/models");
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.value.expose_secret() == "Bearer provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn parses_openai_model_catalog_candidates() {
        let adapter = OpenAiCompatibleAdapter;
        let models = adapter
            .parse_model_catalog(
                br#"{"object":"list","data":[{"id":"gpt-4o-mini","owned_by":"openai","created":1715367049,"context_window":128000,"capabilities":["chat","tools"]}]}"#,
            )
            .unwrap();

        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "gpt-4o-mini");
        assert_eq!(models[0].owned_by.as_deref(), Some("openai"));
        assert_eq!(models[0].created, Some(1715367049));
        assert_eq!(models[0].context_window, Some(128000));
        assert_eq!(models[0].capabilities, vec!["chat", "tools"]);
    }

    #[test]
    fn rejects_non_object_chat_body() {
        let adapter = OpenAiCompatibleAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider(None),
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "provider-chat".into(),
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
    fn rejects_unsupported_provider_kind() {
        let adapter = OpenAiCompatibleAdapter;
        let mut provider = provider(None);
        provider.kind = "anthropic".into();

        let error = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "provider-chat".into(),
                    stream: false,
                    body: json!({"model": "fast-chat"}),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::UnsupportedProviderKind {
                kind: "anthropic".into()
            }
        );
    }

    #[test]
    fn accepts_shared_openai_compatible_provider_kinds() {
        let adapter = OpenAiCompatibleAdapter;
        for kind in [
            "openai",
            "openai-compatible",
            "deepseek",
            "newapi",
            "sub2api",
            "cliproxyapi",
            "vllm",
            "llama.cpp",
            "tgi",
            "ollama-compatible",
        ] {
            let mut provider = provider(None);
            provider.kind = kind.into();
            let prepared = adapter
                .prepare_chat_completions(
                    provider,
                    ChatCompletionPlan {
                        logical_model: "fast-chat".into(),
                        provider_model: "provider-chat".into(),
                        stream: false,
                        body: json!({"model": "fast-chat"}),
                    },
                )
                .unwrap();
            assert_eq!(prepared.body["model"], "provider-chat");
        }
    }

    #[test]
    fn normalizes_openai_error_response() {
        let adapter = OpenAiCompatibleAdapter;
        let normalized = adapter.normalize_error_response(
            429,
            "application/json",
            br#"{"error":{"message":"rate limited","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 429);
        assert_eq!(normalized.body["error"]["message"], "rate limited");
        assert_eq!(normalized.body["error"]["type"], "provider_error");
        assert_eq!(
            normalized.body["error"]["provider_type"],
            "rate_limit_error"
        );
        assert_eq!(normalized.body["error"]["code"], "rate_limit_exceeded");
        assert_eq!(normalized.body["error"]["request_id"], "fg-test");
    }

    #[test]
    fn normalizes_non_json_error_response() {
        let adapter = OpenAiCompatibleAdapter;
        let normalized =
            adapter.normalize_error_response(503, "text/plain", b"upstream unavailable", "fg-test");

        assert_eq!(normalized.status, 503);
        assert_eq!(normalized.body["error"]["message"], "upstream unavailable");
        assert_eq!(normalized.body["error"]["code"], "provider_error");
    }

    #[test]
    fn extracts_openai_usage_metadata() {
        let adapter = OpenAiCompatibleAdapter;
        let usage = adapter
            .extract_usage(
                br#"{"id":"chatcmpl","usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#,
            )
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(11));
        assert_eq!(usage.completion_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(18));
        assert_eq!(adapter.extract_usage(br#"{"id":"chatcmpl"}"#), None);
    }

    #[test]
    fn prepares_responses_request() {
        let adapter = OpenAiCompatibleAdapter;
        let prepared = adapter
            .prepare_responses(
                provider(Some("provider-secret")),
                ResponsesPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    stream: true,
                    body: json!({
                        "model": "fast-chat",
                        "input": "hello",
                        "stream": false
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.endpoint, "https://api.openai.example/v1/responses");
        assert_eq!(prepared.body["model"], "gpt-4.1-mini");
        assert_eq!(prepared.body["input"], "hello");
        assert_eq!(prepared.body["stream"], true);
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.value.expose_secret() == "Bearer provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn preserves_responses_tools_tool_choice_and_images_for_openai_compatible_providers() {
        let adapter = OpenAiCompatibleAdapter;
        let prepared = adapter
            .prepare_responses(
                provider(None),
                ResponsesPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    stream: false,
                    body: json!({
                        "model": "fast-chat",
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
                        "tool_choice": {"type": "function", "function": {"name": "lookup_weather"}},
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

        assert_eq!(prepared.body["model"], "gpt-4.1-mini");
        assert_eq!(
            prepared.body["tools"][0]["function"]["name"],
            "lookup_weather"
        );
        assert_eq!(
            prepared.body["tool_choice"]["function"]["name"],
            "lookup_weather"
        );
        assert_eq!(
            prepared.body["input"][0]["content"][1]["image_url"],
            "https://example.com/a.png"
        );
    }

    #[test]
    fn injects_openai_tools_and_round_trips_tool_calls() {
        let adapter = OpenAiCompatibleAdapter;
        let body = adapter
            .inject_tools(
                json!({"model": "gpt", "messages": []}),
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

        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "lookup_weather");
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["properties"]["city"]["type"],
            "string"
        );

        let calls = adapter
            .extract_tool_calls(
                br#"{"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_weather","arguments":"{\"city\":\"Shanghai\"}"}}]}}]}"#,
            )
            .unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "lookup_weather");
        assert_eq!(calls[0].arguments["city"], "Shanghai");
    }

    #[test]
    fn appends_openai_tool_results_as_tool_messages() {
        let adapter = OpenAiCompatibleAdapter;
        let body = adapter
            .append_tool_results(
                json!({"messages": [{"role": "user", "content": "weather?"}]}),
                &[ToolResult {
                    tool_call_id: "call_1".into(),
                    content: json!({"temp_c": 21}),
                    is_error: false,
                }],
            )
            .unwrap();

        assert_eq!(body["messages"][1]["role"], "tool");
        assert_eq!(body["messages"][1]["tool_call_id"], "call_1");
        assert_eq!(body["messages"][1]["content"], r#"{"temp_c":21}"#);
    }
}
