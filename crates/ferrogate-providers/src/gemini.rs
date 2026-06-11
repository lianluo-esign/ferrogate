// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Map, Value};

use crate::{
    canonical::CanonicalAiRequest, AdapterError, ChatCompletionPlan, ProviderAdapter,
    ProviderConfig, ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage,
    ResponsesPlan, SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct GeminiAdapter;

impl ProviderAdapter for GeminiAdapter {
    fn kind(&self) -> &'static str {
        "gemini"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let body = ensure_object_body(request.body)?;

        let mut gemini_body = json!({
            "contents": openai_messages_to_gemini_contents(&body)?,
        });
        if let Some(system_instruction) = system_instruction(&body)? {
            gemini_body["systemInstruction"] = system_instruction;
        }
        if let Some(generation_config) = generation_config(&body) {
            gemini_body["generationConfig"] = generation_config;
        }

        let mut headers = vec![ProviderHeader {
            name: "content-type".into(),
            value: SecretValue::new("application/json"),
        }];
        if let Some(api_key) = provider.api_key.filter(|value| !value.trim().is_empty()) {
            headers.push(ProviderHeader {
                name: "x-goog-api-key".into(),
                value: SecretValue::new(api_key),
            });
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: generate_content_endpoint(
                &provider.base_url,
                &request.provider_model,
                request.stream,
            ),
            body: gemini_body,
            stream: request.stream,
            headers,
        })
    }

    fn prepare_responses(
        &self,
        provider: ProviderConfig,
        request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.prepare_chat_completions(
            provider,
            ChatCompletionPlan {
                logical_model: request.logical_model,
                provider_model: request.provider_model,
                stream: request.stream,
                body: CanonicalAiRequest::from_responses_body(request.body)?
                    .into_chat_body_with_system_message(),
            },
        )
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
            .and_then(|error| error.get("status"))
            .and_then(Value::as_str)
            .or_else(|| {
                provider_error
                    .and_then(|error| error.get("code"))
                    .and_then(Value::as_i64)
                    .map(|_| "google_rpc_error")
            })
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
        let usage = value.get("usageMetadata")?;
        let prompt_tokens = usage.get("promptTokenCount").and_then(Value::as_u64);
        let completion_tokens = usage.get("candidatesTokenCount").and_then(Value::as_u64);
        let total_tokens = usage.get("totalTokenCount").and_then(Value::as_u64);
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
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    match kind {
        "gemini" => Ok(()),
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

fn openai_messages_to_gemini_contents(body: &Value) -> Result<Value, AdapterError> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(json!([]));
    };

    let mut contents = Vec::new();
    for message in messages {
        if message.get("role").and_then(Value::as_str) == Some("system") {
            continue;
        }
        let role = match message.get("role").and_then(Value::as_str) {
            Some("assistant") => "model",
            Some("user") | None => "user",
            Some("tool") => "user",
            Some(other) => {
                return Err(AdapterError::InvalidRequest {
                    message: format!("unsupported Gemini message role {other}"),
                });
            }
        };
        contents.push(json!({
            "role": role,
            "parts": content_parts(message.get("content"))?,
        }));
    }
    Ok(Value::Array(contents))
}

fn system_instruction(body: &Value) -> Result<Option<Value>, AdapterError> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut parts = Vec::new();
    for message in messages {
        if message.get("role").and_then(Value::as_str) != Some("system") {
            continue;
        }
        parts.extend(content_parts(message.get("content"))?);
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(json!({
            "role": "system",
            "parts": parts,
        })))
    }
}

fn content_parts(content: Option<&Value>) -> Result<Vec<Value>, AdapterError> {
    match content {
        Some(Value::String(text)) => Ok(vec![json!({ "text": text })]),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .map(|block| match block {
                Value::Object(object)
                    if object.get("type").and_then(Value::as_str) == Some("text") =>
                {
                    let text = object.get("text").and_then(Value::as_str).unwrap_or("");
                    Ok(json!({ "text": text }))
                }
                Value::String(text) => Ok(json!({ "text": text })),
                _ => Err(AdapterError::InvalidRequest {
                    message: "Gemini adapter supports text message content only".into(),
                }),
            })
            .collect(),
        Some(Value::Null) | None => Ok(vec![json!({ "text": "" })]),
        _ => Err(AdapterError::InvalidRequest {
            message: "Gemini adapter supports text message content only".into(),
        }),
    }
}

fn generation_config(body: &Value) -> Option<Value> {
    let mut config = Map::new();
    copy_config(body, &mut config, "temperature", "temperature");
    copy_config(body, &mut config, "top_p", "topP");
    copy_config(body, &mut config, "top_k", "topK");
    copy_config(body, &mut config, "max_tokens", "maxOutputTokens");
    if let Some(stop) = body.get("stop") {
        match stop {
            Value::String(value) => {
                config.insert("stopSequences".into(), Value::Array(vec![json!(value)]));
            }
            Value::Array(values) => {
                config.insert("stopSequences".into(), Value::Array(values.clone()));
            }
            _ => {}
        }
    }
    (!config.is_empty()).then_some(Value::Object(config))
}

fn copy_config(body: &Value, config: &mut Map<String, Value>, source: &str, target: &str) {
    if let Some(value) = body.get(source) {
        config.insert(target.into(), value.clone());
    }
}

fn generate_content_endpoint(base_url: &str, provider_model: &str, stream: bool) -> String {
    let action = if stream {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };
    format!(
        "{}/models/{}:{}",
        base_url.trim_end_matches('/'),
        provider_model.trim_start_matches("models/"),
        action
    )
}

fn fallback_error_message(parsed: Option<&Value>, body: &[u8]) -> Option<String> {
    parsed
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .or_else(|| {
            let text = std::str::from_utf8(body).ok()?.trim();
            (!text.is_empty()).then(|| text.chars().take(512).collect())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "gemini".into(),
            kind: "gemini".into(),
            base_url: "https://generativelanguage.googleapis.com/v1beta/".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: None,
            openrouter_x_title: None,
        }
    }

    #[test]
    fn converts_openai_chat_plan_to_gemini_generate_content_request() {
        let adapter = GeminiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "flash-chat".into(),
                    provider_model: "gemini-2.5-flash".into(),
                    stream: false,
                    body: json!({
                        "model": "flash-chat",
                        "messages": [
                            {"role": "system", "content": "be concise"},
                            {"role": "user", "content": "hello"},
                            {"role": "assistant", "content": "hi"},
                            {"role": "user", "content": [{"type": "text", "text": "again"}]}
                        ],
                        "max_tokens": 256,
                        "temperature": 0.2,
                        "top_p": 0.8,
                        "stop": ["END"]
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(prepared.body["contents"][0]["role"], "user");
        assert_eq!(prepared.body["contents"][0]["parts"][0]["text"], "hello");
        assert_eq!(prepared.body["contents"][1]["role"], "model");
        assert_eq!(
            prepared.body["systemInstruction"]["parts"][0]["text"],
            "be concise"
        );
        assert_eq!(prepared.body["generationConfig"]["maxOutputTokens"], 256);
        assert_eq!(prepared.body["generationConfig"]["topP"], 0.8);
        assert_eq!(prepared.body["generationConfig"]["stopSequences"][0], "END");
        assert!(prepared.headers.iter().any(|header| {
            header.name == "x-goog-api-key" && header.value.expose_secret() == "provider-secret"
        }));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn uses_stream_generate_content_endpoint_for_streaming() {
        let adapter = GeminiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(None),
                ChatCompletionPlan {
                    logical_model: "flash-chat".into(),
                    provider_model: "models/gemini-2.5-flash".into(),
                    stream: true,
                    body: json!({"messages": [{"role": "user", "content": "hello"}]}),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn converts_responses_plan_to_gemini_generate_content_request() {
        let adapter = GeminiAdapter;
        let prepared = adapter
            .prepare_responses(
                provider(Some("provider-secret")),
                ResponsesPlan {
                    logical_model: "flash-chat".into(),
                    provider_model: "gemini-2.5-flash".into(),
                    stream: false,
                    body: json!({
                        "model": "flash-chat",
                        "instructions": "be concise",
                        "input": [{"type": "input_text", "text": "hello"}],
                        "max_output_tokens": 64
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(
            prepared.body["systemInstruction"]["parts"][0]["text"],
            "be concise"
        );
        assert_eq!(prepared.body["contents"][0]["role"], "user");
        assert_eq!(prepared.body["contents"][0]["parts"][0]["text"], "hello");
        assert_eq!(prepared.body["generationConfig"]["maxOutputTokens"], 64);
    }

    #[test]
    fn rejects_non_text_content_blocks() {
        let adapter = GeminiAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider(None),
                ChatCompletionPlan {
                    logical_model: "flash-chat".into(),
                    provider_model: "gemini-2.5-flash".into(),
                    stream: false,
                    body: json!({
                        "messages": [{"role": "user", "content": [{"type": "image_url"}]}]
                    }),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "Gemini adapter supports text message content only".into()
            }
        );
    }

    #[test]
    fn normalizes_gemini_error_response() {
        let adapter = GeminiAdapter;
        let normalized = adapter.normalize_error_response(
            400,
            "application/json",
            br#"{"error":{"code":400,"message":"bad request","status":"INVALID_ARGUMENT"}}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 400);
        assert_eq!(normalized.body["error"]["message"], "bad request");
        assert_eq!(
            normalized.body["error"]["provider_type"],
            "INVALID_ARGUMENT"
        );
        assert_eq!(normalized.body["error"]["code"], "INVALID_ARGUMENT");
    }

    #[test]
    fn extracts_gemini_usage_metadata() {
        let adapter = GeminiAdapter;
        let usage = adapter
            .extract_usage(
                br#"{"usageMetadata":{"promptTokenCount":13,"candidatesTokenCount":8,"totalTokenCount":21}}"#,
            )
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(13));
        assert_eq!(usage.completion_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(21));
    }
}
