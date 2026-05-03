use crate::{
    AdapterError, ChatCompletionPlan, OpenAiCompatibleAdapter, ProviderAdapter, ProviderConfig,
    ProviderErrorResponse, ProviderHttpRequest, ProviderUsage,
};

#[derive(Debug, Default, Clone)]
pub struct ProviderAdapterRegistry {
    openai_compatible: OpenAiCompatibleAdapter,
}

impl ProviderAdapterRegistry {
    pub fn adapter_for(&self, kind: &str) -> Result<&dyn ProviderAdapter, AdapterError> {
        match normalize_kind(kind).as_str() {
            "openai" | "openai-compatible" => Ok(&self.openai_compatible),
            other => Err(AdapterError::UnsupportedProviderKind {
                kind: other.to_string(),
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
}

fn normalize_kind(kind: &str) -> String {
    kind.trim().to_ascii_lowercase()
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
            registry.adapter_for("openai-compatible").unwrap().kind(),
            "openai-compatible"
        );
        assert_eq!(
            registry.adapter_for(" OpenAI-Compatible ").unwrap().kind(),
            "openai-compatible"
        );
    }

    #[test]
    fn rejects_unknown_provider_kind_before_runtime_dispatch() {
        let registry = ProviderAdapterRegistry::default();
        let error = match registry.adapter_for("anthropic") {
            Ok(adapter) => panic!("unexpected provider adapter {}", adapter.kind()),
            Err(error) => error,
        };

        assert_eq!(
            error,
            AdapterError::UnsupportedProviderKind {
                kind: "anthropic".into()
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
        }
    }
}
