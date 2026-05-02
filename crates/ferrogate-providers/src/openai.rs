use serde_json::Value;

use crate::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderHeader,
    ProviderHttpRequest, SecretValue,
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
        let mut body = ensure_object_body(request.body)?;
        body["model"] = Value::String(request.provider_model);
        body["stream"] = Value::Bool(request.stream);

        let mut headers = vec![ProviderHeader {
            name: "content-type".into(),
            value: SecretValue::new("application/json"),
        }];
        if let Some(api_key) = provider.api_key.filter(|value| !value.trim().is_empty()) {
            headers.push(ProviderHeader {
                name: "authorization".into(),
                value: SecretValue::new(format!("Bearer {api_key}")),
            });
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: chat_completions_endpoint(&provider.base_url),
            body,
            stream: request.stream,
            headers,
        })
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

fn ensure_object_body(body: Value) -> Result<Value, AdapterError> {
    if body.is_object() {
        Ok(body)
    } else {
        Err(AdapterError::InvalidRequest {
            message: "chat completion request body must be a JSON object".into(),
        })
    }
}

fn chat_completions_endpoint(base_url: &str) -> String {
    format!("{}/chat/completions", base_url.trim_end_matches('/'))
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
}
