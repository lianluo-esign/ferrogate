// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-13
// description: Provider-specific streaming reported-usage request contracts (#214).

use ferrogate_providers::{ChatCompletionPlan, ProviderAdapterRegistry, ProviderConfig};
use serde_json::{json, Value};

#[test]
fn openai_grok_and_azure_request_stream_usage_in_the_openai_shape() {
    let registry = ProviderAdapterRegistry::default();
    for (kind, name, base_url, provider_model) in [
        (
            "openai",
            "openai",
            "https://api.openai.test/v1",
            "gpt-4o-mini",
        ),
        ("xai", "xai", "https://api.x.ai/v1", "grok-4.20-fast"),
        (
            "azure-openai",
            "azure-openai",
            "https://example.openai.azure.com",
            "azure-gpt-4o",
        ),
    ] {
        let request = registry
            .prepare_chat_completions(
                provider(kind, name, base_url),
                streaming_plan(provider_model),
            )
            .unwrap();

        assert_eq!(
            request.body["stream_options"]["include_usage"],
            Value::Bool(true),
            "{kind} must explicitly request the terminal usage chunk"
        );
    }
}

#[test]
fn openrouter_relies_on_automatic_stream_usage_without_deprecated_opt_ins() {
    let registry = ProviderAdapterRegistry::default();
    let request = registry
        .prepare_chat_completions(
            provider("openrouter", "openrouter", "https://openrouter.ai/api/v1"),
            streaming_plan("openai/gpt-4o-mini"),
        )
        .unwrap();

    assert!(request.body.get("usage").is_none());
    assert!(request.body.get("stream_options").is_none());
}

fn provider(kind: &str, name: &str, base_url: &str) -> ProviderConfig {
    ProviderConfig {
        name: name.to_string(),
        kind: kind.to_string(),
        base_url: base_url.to_string(),
        api_key: Some("provider-secret".into()),
        openrouter_http_referer: None,
        openrouter_x_title: None,
        aws_credentials: None,
        gcp_credentials: None,
        cloudflare_ai_gateway: None,
    }
}

fn streaming_plan(provider_model: &str) -> ChatCompletionPlan {
    ChatCompletionPlan {
        logical_model: "logical-chat".into(),
        provider_model: provider_model.to_string(),
        stream: true,
        body: json!({
            "model": "logical-chat",
            "messages": [{"role": "user", "content": "hello"}],
        }),
    }
}
