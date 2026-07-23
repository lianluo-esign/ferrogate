// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Stub-level tests for Cloudflare AI Gateway upstream routing
// (issue #406): all four surfaces through both compat and unified modes, BYOK
// preservation, cf-aig-* injection, and the absent-config no-op.

use serde_json::json;

use crate::{
    ChatCompletionPlan, CloudflareAiGatewayMode, CloudflareAiGatewayRouting, EmbeddingsPlan,
    ProviderAdapterRegistry, ProviderConfig, ProviderHttpRequest, ResponsesPlan, SecretValue,
};

const ACCOUNT: &str = "acct-123";
const GATEWAY: &str = "gw-1";
const GATEWAY_HOST: &str = "https://gateway.ai.cloudflare.com";
const API_HOST: &str = "https://api.cloudflare.com/client/v4";

fn routing(mode: CloudflareAiGatewayMode, aig_token: Option<&str>) -> CloudflareAiGatewayRouting {
    CloudflareAiGatewayRouting {
        account_id: ACCOUNT.into(),
        gateway_id: GATEWAY.into(),
        gateway_base_url: GATEWAY_HOST.into(),
        api_base_url: API_HOST.into(),
        aig_token: aig_token.map(SecretValue::new),
        mode,
        provider_slug: None,
    }
}

fn provider(kind: &str, routing: Option<CloudflareAiGatewayRouting>) -> ProviderConfig {
    let base_url = match kind {
        "anthropic" => "https://api.anthropic.com/v1",
        _ => "https://api.openai.com/v1",
    };
    ProviderConfig {
        name: kind.into(),
        kind: kind.into(),
        base_url: base_url.into(),
        api_key: Some("tenant-provider-key".into()),
        openrouter_http_referer: None,
        openrouter_x_title: None,
        aws_credentials: None,
        gcp_credentials: None,
        cloudflare_ai_gateway: routing,
    }
}

fn header<'a>(request: &'a ProviderHttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.expose_secret())
}

fn chat_plan() -> ChatCompletionPlan {
    ChatCompletionPlan {
        logical_model: "fast-chat".into(),
        provider_model: "gpt-4o-mini".into(),
        stream: false,
        body: json!({"model": "fast-chat", "messages": [{"role": "user", "content": "hi"}]}),
    }
}

// --- compat mode: per-provider passthrough, body/BYOK untouched ---------------

#[test]
fn compat_routes_openai_chat_completions_through_gateway() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_chat_completions(
            provider(
                "openai",
                Some(routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"))),
            ),
            chat_plan(),
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/openai/chat/completions"
    );
    // Pass-through: model + body shape unchanged (Cloudflare forwards verbatim).
    assert_eq!(prepared.body["model"], "gpt-4o-mini");
    // BYOK provider key preserved so per-tenant keys still authenticate upstream.
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
    // Authenticated gateway token injected.
    assert_eq!(
        header(&prepared, "cf-aig-authorization"),
        Some("Bearer aig-secret")
    );
    // Secrets never leak through Debug.
    assert!(!format!("{prepared:?}").contains("aig-secret"));
    assert!(!format!("{prepared:?}").contains("tenant-provider-key"));
}

#[test]
fn compat_routes_openai_responses_through_gateway() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_responses(
            provider(
                "openai",
                Some(routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"))),
            ),
            ResponsesPlan {
                logical_model: "fast-chat".into(),
                provider_model: "gpt-4.1-mini".into(),
                stream: false,
                body: json!({"model": "fast-chat", "input": "hi"}),
            },
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/openai/responses"
    );
    assert_eq!(prepared.body["model"], "gpt-4.1-mini");
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
    assert_eq!(
        header(&prepared, "cf-aig-authorization"),
        Some("Bearer aig-secret")
    );
}

#[test]
fn compat_routes_openai_embeddings_through_gateway() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_embeddings(
            provider(
                "openai",
                Some(routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"))),
            ),
            EmbeddingsPlan {
                logical_model: "fast-embed".into(),
                provider_model: "text-embedding-3-small".into(),
                body: json!({"model": "fast-embed", "input": "hi"}),
            },
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/openai/embeddings"
    );
    assert_eq!(prepared.body["model"], "text-embedding-3-small");
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
}

#[test]
fn compat_routes_anthropic_messages_through_gateway() {
    let registry = ProviderAdapterRegistry::default();
    // Anthropic dispatches chat completions as `/v1/messages`.
    let prepared = registry
        .prepare_chat_completions(
            provider(
                "anthropic",
                Some(routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"))),
            ),
            ChatCompletionPlan {
                logical_model: "claude-chat".into(),
                provider_model: "claude-3-5-sonnet-latest".into(),
                stream: false,
                body: json!({"messages": [{"role": "user", "content": "hi"}]}),
            },
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/anthropic/v1/messages"
    );
    assert_eq!(prepared.body["model"], "claude-3-5-sonnet-latest");
    // Anthropic BYOK header preserved (x-api-key, not Authorization).
    assert_eq!(header(&prepared, "x-api-key"), Some("tenant-provider-key"));
    assert_eq!(header(&prepared, "anthropic-version"), Some("2023-06-01"));
    assert_eq!(
        header(&prepared, "cf-aig-authorization"),
        Some("Bearer aig-secret")
    );
}

#[test]
fn compat_unauthenticated_gateway_omits_cf_aig_authorization() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_chat_completions(
            provider(
                "openai",
                Some(routing(CloudflareAiGatewayMode::Compat, None)),
            ),
            chat_plan(),
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/openai/chat/completions"
    );
    assert!(header(&prepared, "cf-aig-authorization").is_none());
    // BYOK still forwarded so the request authenticates at the real provider.
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
}

// --- unified mode: REST API + cf-aig-gateway-id + author/model ----------------

#[test]
fn unified_routes_openai_chat_completions_through_rest_api() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_chat_completions(
            provider(
                "openai",
                Some(routing(
                    CloudflareAiGatewayMode::Unified,
                    Some("aig-secret"),
                )),
            ),
            chat_plan(),
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://api.cloudflare.com/client/v4/accounts/acct-123/ai/v1/chat/completions"
    );
    // Unified REST expects author/model form.
    assert_eq!(prepared.body["model"], "openai/gpt-4o-mini");
    // Gateway selected via header (not a path segment) in unified mode.
    assert_eq!(header(&prepared, "cf-aig-gateway-id"), Some("gw-1"));
    assert_eq!(
        header(&prepared, "cf-aig-authorization"),
        Some("Bearer aig-secret")
    );
    // BYOK preserved.
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
}

#[test]
fn unified_routes_openai_embeddings_through_rest_api() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_embeddings(
            provider(
                "openai",
                Some(routing(
                    CloudflareAiGatewayMode::Unified,
                    Some("aig-secret"),
                )),
            ),
            EmbeddingsPlan {
                logical_model: "fast-embed".into(),
                provider_model: "text-embedding-3-small".into(),
                body: json!({"model": "fast-embed", "input": "hi"}),
            },
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://api.cloudflare.com/client/v4/accounts/acct-123/ai/v1/embeddings"
    );
    assert_eq!(prepared.body["model"], "openai/text-embedding-3-small");
    assert_eq!(header(&prepared, "cf-aig-gateway-id"), Some("gw-1"));
}

#[test]
fn unified_routes_anthropic_messages_through_rest_api() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_responses(
            provider(
                "anthropic",
                Some(routing(
                    CloudflareAiGatewayMode::Unified,
                    Some("aig-secret"),
                )),
            ),
            ResponsesPlan {
                logical_model: "claude-chat".into(),
                provider_model: "claude-3-5-sonnet-latest".into(),
                stream: false,
                body: json!({"input": "hi", "instructions": "be brief"}),
            },
        )
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://api.cloudflare.com/client/v4/accounts/acct-123/ai/v1/messages"
    );
    assert_eq!(prepared.body["model"], "anthropic/claude-3-5-sonnet-latest");
    assert_eq!(header(&prepared, "cf-aig-gateway-id"), Some("gw-1"));
    assert_eq!(header(&prepared, "x-api-key"), Some("tenant-provider-key"));
}

// --- opt-out / overrides / fail-closed ---------------------------------------

#[test]
fn absent_config_leaves_request_unchanged() {
    let registry = ProviderAdapterRegistry::default();
    let prepared = registry
        .prepare_chat_completions(provider("openai", None), chat_plan())
        .unwrap();

    // Direct dispatch: no rewrite, no cf-aig-* headers.
    assert_eq!(
        prepared.endpoint,
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(prepared.body["model"], "gpt-4o-mini");
    assert!(header(&prepared, "cf-aig-authorization").is_none());
    assert!(header(&prepared, "cf-aig-gateway-id").is_none());
    assert_eq!(
        header(&prepared, "authorization"),
        Some("Bearer tenant-provider-key")
    );
}

#[test]
fn explicit_provider_slug_overrides_family_default() {
    let registry = ProviderAdapterRegistry::default();
    let mut cf = routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"));
    cf.provider_slug = Some("openai-custom".into());
    let prepared = registry
        .prepare_chat_completions(provider("openai", Some(cf)), chat_plan())
        .unwrap();

    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/openai-custom/chat/completions"
    );
}

#[test]
fn family_without_default_slug_fails_closed_when_enabled() {
    let registry = ProviderAdapterRegistry::default();
    // Gemini has no OpenAI/Anthropic-shaped Cloudflare passthrough default; an
    // operator that opted into routing without an explicit slug must fail
    // closed rather than dispatch to a wrong host.
    let error = registry
        .prepare_chat_completions(
            provider(
                "gemini",
                Some(routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"))),
            ),
            ChatCompletionPlan {
                logical_model: "flash".into(),
                provider_model: "gemini-2.5-flash".into(),
                stream: false,
                body: json!({"messages": [{"role": "user", "content": "hi"}]}),
            },
        )
        .unwrap_err();

    assert!(
        matches!(error, crate::AdapterError::InvalidRequest { .. }),
        "expected InvalidRequest, got {error:?}"
    );
}

#[test]
fn gemini_with_explicit_slug_routes_through_gateway() {
    let registry = ProviderAdapterRegistry::default();
    let mut cf = routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"));
    cf.provider_slug = Some("google-ai-studio".into());
    let prepared = registry
        .prepare_chat_completions(
            provider("gemini", Some(cf)),
            ChatCompletionPlan {
                logical_model: "flash".into(),
                provider_model: "gemini-2.5-flash".into(),
                stream: false,
                body: json!({"messages": [{"role": "user", "content": "hi"}]}),
            },
        )
        .unwrap();

    // Gemini uses the OpenAI-shaped chat surface suffix under the given slug.
    assert_eq!(
        prepared.endpoint,
        "https://gateway.ai.cloudflare.com/v1/acct-123/gw-1/google-ai-studio/chat/completions"
    );
}

#[test]
fn empty_account_id_fails_closed() {
    let registry = ProviderAdapterRegistry::default();
    let mut cf = routing(CloudflareAiGatewayMode::Compat, Some("aig-secret"));
    cf.account_id = "  ".into();
    let error = registry
        .prepare_chat_completions(provider("openai", Some(cf)), chat_plan())
        .unwrap_err();
    assert!(matches!(error, crate::AdapterError::InvalidRequest { .. }));
}
