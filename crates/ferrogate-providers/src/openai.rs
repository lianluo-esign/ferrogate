use serde_json::{json, Value};

use crate::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, ResponsesPlan, SecretValue,
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
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    match kind {
        "openai" | "openai-compatible" => Ok(()),
        other => Err(AdapterError::UnsupportedProviderKind {
            kind: other.to_string(),
        }),
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
    use serde_json::json;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "openai".into(),
            kind: "openai".into(),
            base_url: "https://api.openai.example/v1/".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: None,
            openrouter_x_title: None,
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
}
