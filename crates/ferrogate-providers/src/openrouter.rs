// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::{
    AdapterError, ChatCompletionPlan, OpenAiCompatibleAdapter, ProviderAdapter,
    ProviderCatalogModel, ProviderCatalogRequest, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, ResponsesPlan, SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct OpenRouterAdapter {
    openai_compatible: OpenAiCompatibleAdapter,
}

impl ProviderAdapter for OpenRouterAdapter {
    fn kind(&self) -> &'static str {
        "openrouter"
    }

    fn prepare_chat_completions(
        &self,
        mut provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let headers = openrouter_headers(&provider);
        let stream = request.stream;
        provider.kind = "openai-compatible".into();
        let mut prepared = self
            .openai_compatible
            .prepare_chat_completions(provider, request)?;
        if stream {
            // OpenRouter includes usage automatically and has deprecated both
            // OpenAI's stream_options opt-in and its older usage.include flag.
            let body = prepared
                .body
                .as_object_mut()
                .expect("OpenAI-compatible adapter returned an object body");
            body.remove("stream_options");
        }
        prepared.headers.extend(headers);
        Ok(prepared)
    }

    fn prepare_responses(
        &self,
        mut provider: ProviderConfig,
        request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let headers = openrouter_headers(&provider);
        provider.kind = "openai-compatible".into();
        let mut prepared = self
            .openai_compatible
            .prepare_responses(provider, request)?;
        prepared.headers.extend(headers);
        Ok(prepared)
    }

    fn prepare_model_catalog(
        &self,
        mut provider: ProviderConfig,
    ) -> Result<ProviderCatalogRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let headers = openrouter_headers(&provider);
        provider.kind = "openai-compatible".into();
        let mut prepared = self.openai_compatible.prepare_model_catalog(provider)?;
        prepared.headers.extend(headers);
        Ok(prepared)
    }

    fn parse_model_catalog(&self, body: &[u8]) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
        self.openai_compatible.parse_model_catalog(body)
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
        "openrouter" => Ok(()),
        other => Err(AdapterError::UnsupportedProviderKind {
            kind: other.to_string(),
        }),
    }
}

fn openrouter_headers(provider: &ProviderConfig) -> Vec<ProviderHeader> {
    let mut headers = Vec::new();
    if let Some(value) = non_empty_header_value(provider.openrouter_http_referer.as_deref()) {
        headers.push(ProviderHeader {
            name: "http-referer".into(),
            value: SecretValue::new(value),
        });
    }
    if let Some(value) = non_empty_header_value(provider.openrouter_x_title.as_deref()) {
        headers.push(ProviderHeader {
            name: "x-title".into(),
            value: SecretValue::new(value),
        });
    }
    headers
}

fn non_empty_header_value(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn provider(api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "openrouter".into(),
            kind: "openrouter".into(),
            base_url: "https://openrouter.ai/api/v1/".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: Some("https://ferrogate.example".into()),
            openrouter_x_title: Some("FerroGate".into()),
            aws_credentials: None,
            gcp_credentials: None,
            cloudflare_ai_gateway: None,
        }
    }

    #[test]
    fn prepares_openrouter_chat_completions_as_openai_compatible_request() {
        let adapter = OpenRouterAdapter::default();
        let prepared = adapter
            .prepare_chat_completions(
                provider(Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "router-chat".into(),
                    provider_model: "openai/gpt-4o-mini".into(),
                    stream: true,
                    body: json!({
                        "model": "router-chat",
                        "messages": [{"role": "user", "content": "hello"}],
                        "stream": false
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.provider, "openrouter");
        assert_eq!(
            prepared.endpoint,
            "https://openrouter.ai/api/v1/chat/completions"
        );
        assert_eq!(prepared.body["model"], "openai/gpt-4o-mini");
        assert_eq!(prepared.body["stream"], true);
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.value.expose_secret() == "Bearer provider-secret"));
        assert!(prepared.headers.iter().any(|header| {
            header.name == "http-referer"
                && header.value.expose_secret() == "https://ferrogate.example"
        }));
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.name == "x-title" && header.value.expose_secret() == "FerroGate"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn prepares_openrouter_responses_as_openai_compatible_request() {
        let adapter = OpenRouterAdapter::default();
        let prepared = adapter
            .prepare_responses(
                provider(None),
                ResponsesPlan {
                    logical_model: "router-chat".into(),
                    provider_model: "anthropic/claude-sonnet-4".into(),
                    stream: false,
                    body: json!({"model": "router-chat", "input": "hello"}),
                },
            )
            .unwrap();

        assert_eq!(prepared.endpoint, "https://openrouter.ai/api/v1/responses");
        assert_eq!(prepared.body["model"], "anthropic/claude-sonnet-4");
        assert_eq!(prepared.body["input"], "hello");
        assert_eq!(prepared.body["stream"], false);
    }

    #[test]
    fn delegates_usage_extraction_to_openai_compatible_shape() {
        let adapter = OpenRouterAdapter::default();
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
