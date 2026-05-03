use serde_json::{json, Value};

use crate::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
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
        if let Some(api_key) = provider.api_key.filter(|value| !value.trim().is_empty()) {
            headers.push(ProviderHeader {
                name: "x-api-key".into(),
                value: SecretValue::new(api_key),
            });
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: messages_endpoint(&provider.base_url),
            body: anthropic_body,
            stream: request.stream,
            headers,
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
        let usage = value.get("usage")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "anthropic".into(),
            kind: "anthropic".into(),
            base_url: "https://api.anthropic.example/v1/".into(),
            api_key: api_key.map(str::to_string),
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
}
