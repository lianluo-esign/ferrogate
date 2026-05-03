use crate::{
    AdapterError, ChatCompletionPlan, OpenAiCompatibleAdapter, ProviderAdapter, ProviderConfig,
    ProviderErrorResponse, ProviderHttpRequest, ProviderUsage,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct GrokAdapter {
    openai_compatible: OpenAiCompatibleAdapter,
}

impl ProviderAdapter for GrokAdapter {
    fn kind(&self) -> &'static str {
        "grok"
    }

    fn prepare_chat_completions(
        &self,
        mut provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        provider.kind = "openai-compatible".into();
        self.openai_compatible
            .prepare_chat_completions(provider, request)
    }

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse {
        self.openai_compatible
            .normalize_error_response(status, content_type, body, request_id)
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        self.openai_compatible.extract_usage(body)
    }
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    match kind {
        "grok" | "xai" => Ok(()),
        other => Err(AdapterError::UnsupportedProviderKind {
            kind: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn provider(kind: &str, api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "xai".into(),
            kind: kind.into(),
            base_url: "https://api.x.ai/v1/".into(),
            api_key: api_key.map(str::to_string),
        }
    }

    #[test]
    fn prepares_grok_chat_completions_as_openai_compatible_request() {
        let adapter = GrokAdapter::default();
        let prepared = adapter
            .prepare_chat_completions(
                provider("grok", Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "grok-chat".into(),
                    provider_model: "grok-4.20-fast".into(),
                    stream: true,
                    body: json!({
                        "model": "grok-chat",
                        "messages": [{"role": "user", "content": "hello"}],
                        "stream": false
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.provider, "xai");
        assert_eq!(prepared.endpoint, "https://api.x.ai/v1/chat/completions");
        assert_eq!(prepared.body["model"], "grok-4.20-fast");
        assert_eq!(prepared.body["stream"], true);
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.value.expose_secret() == "Bearer provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn accepts_xai_provider_kind_alias() {
        let adapter = GrokAdapter::default();
        let prepared = adapter
            .prepare_chat_completions(
                provider("xai", None),
                ChatCompletionPlan {
                    logical_model: "grok-chat".into(),
                    provider_model: "grok-4.20-fast".into(),
                    stream: false,
                    body: json!({"messages": []}),
                },
            )
            .unwrap();

        assert_eq!(prepared.body["model"], "grok-4.20-fast");
    }

    #[test]
    fn delegates_usage_extraction_to_openai_compatible_shape() {
        let adapter = GrokAdapter::default();
        let usage = adapter
            .extract_usage(
                br#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
            )
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(3));
        assert_eq!(usage.completion_tokens, Some(5));
        assert_eq!(usage.total_tokens, Some(8));
    }
}
