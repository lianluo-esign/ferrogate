// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use ferrogate_core::{ToolCall, ToolDef, ToolResult};
use serde_json::Value;

use crate::{
    canonical_provider_adapter_family, AdapterError, AnthropicAdapter, AzureOpenAiAdapter,
    BedrockAdapter, ChatCompletionPlan, EmbeddingsPlan, GeminiAdapter, GrokAdapter,
    OpenAiCompatibleAdapter, OpenRouterAdapter, ProviderAdapter, ProviderAdapterFamily,
    ProviderCatalogModel, ProviderCatalogRequest, ProviderConfig, ProviderErrorResponse,
    ProviderHttpRequest, ProviderUsage, ResponsesPlan, VertexAiAdapter,
};

#[derive(Debug, Default, Clone)]
pub struct ProviderAdapterRegistry {
    openai_compatible: OpenAiCompatibleAdapter,
    anthropic: AnthropicAdapter,
    gemini: GeminiAdapter,
    grok: GrokAdapter,
    openrouter: OpenRouterAdapter,
    azure_openai: AzureOpenAiAdapter,
    bedrock: BedrockAdapter,
    vertex: VertexAiAdapter,
}

impl ProviderAdapterRegistry {
    pub fn adapter_for(&self, kind: &str) -> Result<&dyn ProviderAdapter, AdapterError> {
        match canonical_provider_adapter_family(kind) {
            Some(ProviderAdapterFamily::OpenAiCompatible) => Ok(&self.openai_compatible),
            Some(ProviderAdapterFamily::Anthropic) => Ok(&self.anthropic),
            Some(ProviderAdapterFamily::Gemini) => Ok(&self.gemini),
            Some(ProviderAdapterFamily::Grok) => Ok(&self.grok),
            Some(ProviderAdapterFamily::OpenRouter) => Ok(&self.openrouter),
            Some(ProviderAdapterFamily::AzureOpenAi) => Ok(&self.azure_openai),
            Some(ProviderAdapterFamily::Bedrock) => Ok(&self.bedrock),
            Some(ProviderAdapterFamily::Vertex) => Ok(&self.vertex),
            None => Err(AdapterError::UnsupportedProviderKind {
                kind: kind.trim().to_ascii_lowercase(),
            }),
        }
    }

    pub fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.adapter_for(&provider.kind)?
            .prepare_chat_completions(provider, request)
    }

    pub fn prepare_responses(
        &self,
        provider: ProviderConfig,
        request: ResponsesPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.adapter_for(&provider.kind)?
            .prepare_responses(provider, request)
    }

    pub fn prepare_embeddings(
        &self,
        provider: ProviderConfig,
        request: EmbeddingsPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        self.adapter_for(&provider.kind)?
            .prepare_embeddings(provider, request)
    }

    pub fn translate_embeddings_response(
        &self,
        provider_kind: &str,
        body: &[u8],
        model: &str,
    ) -> Result<Option<Value>, AdapterError> {
        self.adapter_for(provider_kind)?
            .translate_embeddings_response(body, model)
    }

    pub fn prepare_model_catalog(
        &self,
        provider: ProviderConfig,
    ) -> Result<ProviderCatalogRequest, AdapterError> {
        self.adapter_for(&provider.kind)?
            .prepare_model_catalog(provider)
    }

    pub fn parse_model_catalog(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Vec<ProviderCatalogModel>, AdapterError> {
        self.adapter_for(provider_kind)?.parse_model_catalog(body)
    }

    pub fn normalize_error_response(
        &self,
        provider_kind: &str,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> Result<ProviderErrorResponse, AdapterError> {
        Ok(self.adapter_for(provider_kind)?.normalize_error_response(
            status,
            content_type,
            body,
            request_id,
        ))
    }

    pub fn extract_usage(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Option<ProviderUsage>, AdapterError> {
        Ok(self.adapter_for(provider_kind)?.extract_usage(body))
    }

    pub fn inject_tools(
        &self,
        provider_kind: &str,
        body: Value,
        tools: &[ToolDef],
    ) -> Result<Value, AdapterError> {
        self.adapter_for(provider_kind)?.inject_tools(body, tools)
    }

    pub fn extract_tool_calls(
        &self,
        provider_kind: &str,
        body: &[u8],
    ) -> Result<Vec<ToolCall>, AdapterError> {
        self.adapter_for(provider_kind)?.extract_tool_calls(body)
    }

    pub fn append_tool_results(
        &self,
        provider_kind: &str,
        body: Value,
        results: &[ToolResult],
    ) -> Result<Value, AdapterError> {
        self.adapter_for(provider_kind)?
            .append_tool_results(body, results)
    }

    pub fn is_retryable_status(
        &self,
        provider_kind: &str,
        status: u16,
    ) -> Result<bool, AdapterError> {
        Ok(self.adapter_for(provider_kind)?.is_retryable_status(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{sync::Arc, thread, time::Instant};

    #[test]
    fn resolves_openai_compatible_adapter_aliases() {
        let registry = ProviderAdapterRegistry::default();

        assert_eq!(
            registry.adapter_for("openai").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for("deepseek").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for("vllm").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for("ollama-compatible").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for("openai-compatible").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for(" OpenAI-Compatible ").unwrap().kind(),
            "openai-compatible"
        );
    }

    #[test]
    fn resolves_openrouter_adapter() {
        let registry = ProviderAdapterRegistry::default();

        assert_eq!(
            registry.adapter_for("openrouter").unwrap().kind(),
            "openrouter"
        );
    }

    #[test]
    fn resolves_bedrock_adapter() {
        // Issue #172: "bedrock" was intentionally unsupported until this
        // adapter landed -- this replaces the old
        // rejects_unknown_provider_kind_before_runtime_dispatch test, which
        // pinned that as expected behavior.
        let registry = ProviderAdapterRegistry::default();
        assert_eq!(registry.adapter_for("bedrock").unwrap().kind(), "bedrock");
        assert_eq!(
            registry.adapter_for("aws-bedrock").unwrap().kind(),
            "bedrock"
        );
    }

    #[test]
    fn resolves_vertex_adapter() {
        // Issue #172: "vertex" was intentionally unsupported until this
        // adapter landed -- replaces the old
        // rejects_unknown_provider_kind_before_runtime_dispatch test,
        // which pinned that as expected behavior.
        let registry = ProviderAdapterRegistry::default();
        assert_eq!(registry.adapter_for("vertex").unwrap().kind(), "vertex");
        assert_eq!(registry.adapter_for("vertex-ai").unwrap().kind(), "vertex");
    }

    #[test]
    fn rejects_unknown_provider_kind_before_runtime_dispatch() {
        let registry = ProviderAdapterRegistry::default();
        let error = match registry.adapter_for("cohere") {
            Ok(adapter) => panic!("unexpected provider adapter {}", adapter.kind()),
            Err(error) => error,
        };

        assert_eq!(
            error,
            AdapterError::UnsupportedProviderKind {
                kind: "cohere".into()
            }
        );
    }

    #[test]
    fn prepares_chat_completions_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let prepared = registry
            .prepare_chat_completions(
                provider("openai"),
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4o-mini".into(),
                    stream: true,
                    body: json!({
                        "model": "fast-chat",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.provider, "openai");
        assert_eq!(
            prepared.endpoint,
            "https://api.openai.example/v1/chat/completions"
        );
        assert_eq!(prepared.body["model"], "gpt-4o-mini");
        assert_eq!(prepared.body["stream"], true);
    }

    #[test]
    fn prepares_anthropic_chat_completions_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let prepared = registry
            .prepare_chat_completions(
                provider("anthropic"),
                ChatCompletionPlan {
                    logical_model: "claude-chat".into(),
                    provider_model: "claude-3-5-sonnet-latest".into(),
                    stream: false,
                    body: json!({
                        "model": "claude-chat",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.endpoint, "https://api.openai.example/v1/messages");
        assert_eq!(prepared.body["model"], "claude-3-5-sonnet-latest");
    }

    #[test]
    fn prepares_gemini_chat_completions_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let prepared = registry
            .prepare_chat_completions(
                provider("gemini"),
                ChatCompletionPlan {
                    logical_model: "flash-chat".into(),
                    provider_model: "gemini-2.5-flash".into(),
                    stream: false,
                    body: json!({
                        "model": "flash-chat",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://api.openai.example/v1/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(prepared.body["contents"][0]["parts"][0]["text"], "hello");
    }

    #[test]
    fn prepares_grok_chat_completions_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let prepared = registry
            .prepare_chat_completions(
                provider("grok"),
                ChatCompletionPlan {
                    logical_model: "grok-chat".into(),
                    provider_model: "grok-4.20-fast".into(),
                    stream: false,
                    body: json!({
                        "model": "grok-chat",
                        "messages": [{"role": "user", "content": "hello"}]
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://api.openai.example/v1/chat/completions"
        );
        assert_eq!(prepared.body["model"], "grok-4.20-fast");
    }

    #[test]
    fn prepares_openai_responses_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let prepared = registry
            .prepare_responses(
                provider("openai"),
                ResponsesPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4.1-mini".into(),
                    stream: false,
                    body: json!({
                        "model": "fast-chat",
                        "input": "hello"
                    }),
                },
            )
            .unwrap();

        assert_eq!(prepared.provider, "openai");
        assert_eq!(prepared.endpoint, "https://api.openai.example/v1/responses");
        assert_eq!(prepared.body["model"], "gpt-4.1-mini");
        assert_eq!(prepared.body["input"], "hello");
        assert_eq!(prepared.body["stream"], false);
    }

    #[test]
    fn prepares_azure_openai_chat_completions_through_registry() {
        let registry = ProviderAdapterRegistry::default();
        let mut provider = provider("azure-openai");
        provider.base_url = "https://example.openai.azure.com".into();
        let prepared = registry
            .prepare_chat_completions(
                provider,
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
            "https://example.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21"
        );
        assert!(prepared.body.get("model").is_none());
    }

    #[test]
    fn normalizes_errors_and_extracts_usage_through_registry() {
        let registry = ProviderAdapterRegistry::default();

        let normalized = registry
            .normalize_error_response(
                "openai",
                429,
                "application/json",
                br#"{"error":{"message":"rate limited","type":"rate_limit_error","code":"rate_limit_exceeded"}}"#,
                "fg-test",
            )
            .unwrap();
        assert_eq!(normalized.body["error"]["message"], "rate limited");
        assert_eq!(
            normalized.body["error"]["provider_type"],
            "rate_limit_error"
        );

        let usage = registry
            .extract_usage(
                "openai-compatible",
                br#"{"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
            )
            .unwrap()
            .unwrap();
        assert_eq!(usage.prompt_tokens, Some(3));
        assert_eq!(usage.completion_tokens, Some(5));
        assert_eq!(usage.total_tokens, Some(8));
    }

    #[test]
    fn classifies_retryable_provider_status_through_registry() {
        let registry = ProviderAdapterRegistry::default();

        assert!(registry.is_retryable_status("openai", 429).unwrap());
        assert!(registry.is_retryable_status("gemini", 503).unwrap());
        assert!(!registry.is_retryable_status("anthropic", 400).unwrap());
    }

    #[test]
    fn prepares_chat_completions_concurrently() {
        let registry = Arc::new(ProviderAdapterRegistry::default());
        let handles = (0..16)
            .map(|_| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..64 {
                        registry
                            .prepare_chat_completions(
                                provider("openai"),
                                ChatCompletionPlan {
                                    logical_model: "fast-chat".into(),
                                    provider_model: "gpt-4o-mini".into(),
                                    stream: false,
                                    body: json!({"model": "fast-chat"}),
                                },
                            )
                            .unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn registry_prepare_chat_completions_latency_smoke() {
        let registry = ProviderAdapterRegistry::default();
        let started = Instant::now();

        for _ in 0..1_000 {
            registry
                .prepare_chat_completions(
                    provider("openai"),
                    ChatCompletionPlan {
                        logical_model: "fast-chat".into(),
                        provider_model: "gpt-4o-mini".into(),
                        stream: false,
                        body: json!({"model": "fast-chat"}),
                    },
                )
                .unwrap();
        }

        assert!(
            started.elapsed().as_millis() < 250,
            "registry planning should stay below 250ms for 1000 requests"
        );
    }

    fn provider(kind: &str) -> ProviderConfig {
        ProviderConfig {
            name: "openai".into(),
            kind: kind.into(),
            base_url: "https://api.openai.example/v1".into(),
            api_key: Some("provider-secret".into()),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: None,
            gcp_credentials: None,
        }
    }
}
