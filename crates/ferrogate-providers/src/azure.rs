// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use serde_json::{json, Value};

use crate::{
    openai::request_openai_stream_usage, AdapterError, ChatCompletionPlan, ProviderAdapter,
    ProviderConfig, ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage,
    SecretValue,
};

const DEFAULT_API_VERSION: &str = "2024-10-21";

#[derive(Debug, Default, Clone, Copy)]
pub struct AzureOpenAiAdapter;

impl ProviderAdapter for AzureOpenAiAdapter {
    fn kind(&self) -> &'static str {
        "azure-openai"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let mut body = ensure_object_body(request.body)?;
        body.as_object_mut()
            .expect("object checked above")
            .remove("model");
        body["stream"] = Value::Bool(request.stream);
        if request.stream {
            request_openai_stream_usage(&mut body);
        }

        let mut headers = vec![ProviderHeader {
            name: "content-type".into(),
            value: SecretValue::new("application/json"),
        }];
        if let Some(api_key) = provider.api_key.filter(|value| !value.trim().is_empty()) {
            headers.push(ProviderHeader {
                name: "api-key".into(),
                value: SecretValue::new(api_key),
            });
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint: chat_completions_endpoint(&provider.base_url, &request.provider_model),
            body,
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
                    "provider_type": code,
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
        "azure-openai" | "azure" => Ok(()),
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

fn chat_completions_endpoint(base_url: &str, deployment: &str) -> String {
    let (base_url, api_version) = split_base_url_api_version(base_url);
    format!(
        "{}/openai/deployments/{}/chat/completions?api-version={}",
        base_url.trim_end_matches('/'),
        encode_path_segment(deployment),
        api_version
    )
}

fn split_base_url_api_version(base_url: &str) -> (&str, &str) {
    let Some((endpoint, query)) = base_url.split_once('?') else {
        return (base_url, DEFAULT_API_VERSION);
    };
    let api_version = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(name, value)| (name == "api-version").then_some(value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(DEFAULT_API_VERSION);
    (endpoint, api_version)
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
        if keep {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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

    fn provider(kind: &str, api_key: Option<&str>) -> ProviderConfig {
        ProviderConfig {
            name: "azure-eastus".into(),
            kind: kind.into(),
            base_url: "https://example.openai.azure.com/?api-version=2024-02-15-preview".into(),
            api_key: api_key.map(str::to_string),
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: None,
            gcp_credentials: None,
        }
    }

    #[test]
    fn prepares_azure_chat_completions_deployment_request() {
        let adapter = AzureOpenAiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider("azure-openai", Some("provider-secret")),
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4o mini".into(),
                    stream: true,
                    body: json!({
                        "model": "fast-chat",
                        "messages": [{"role": "user", "content": "hello"}],
                        "temperature": 0.2
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://example.openai.azure.com/openai/deployments/gpt-4o%20mini/chat/completions?api-version=2024-02-15-preview"
        );
        assert!(prepared.body.get("model").is_none());
        assert_eq!(prepared.body["stream"], true);
        assert_eq!(prepared.body["messages"][0]["content"], "hello");
        assert!(prepared
            .headers
            .iter()
            .any(|header| header.name == "api-key"
                && header.value.expose_secret() == "provider-secret"));
        assert!(!format!("{prepared:?}").contains("provider-secret"));
    }

    #[test]
    fn defaults_api_version_when_base_url_does_not_provide_one() {
        let adapter = AzureOpenAiAdapter;
        let mut provider = provider("azure", None);
        provider.base_url = "https://example.openai.azure.com/".into();
        let prepared = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "fast-chat".into(),
                    provider_model: "gpt-4o-mini".into(),
                    stream: false,
                    body: json!({"messages": []}),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://example.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21"
        );
    }

    #[test]
    fn normalizes_azure_error_response() {
        let adapter = AzureOpenAiAdapter;
        let normalized = adapter.normalize_error_response(
            401,
            "application/json",
            br#"{"error":{"code":"401","message":"invalid api key"}}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 401);
        assert_eq!(normalized.body["error"]["message"], "invalid api key");
        assert_eq!(normalized.body["error"]["provider_type"], "401");
    }

    #[test]
    fn extracts_azure_openai_usage_metadata() {
        let adapter = AzureOpenAiAdapter;
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
