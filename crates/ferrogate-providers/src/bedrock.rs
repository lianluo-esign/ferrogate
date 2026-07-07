// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: AWS Bedrock provider adapter (issue #172), targeting the
// Bedrock Runtime `Converse` API
// (<https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_Converse.html>).
// Authenticates via AWS SigV4 (see `sigv4.rs`) rather than a static bearer
// token, since Bedrock has no API-key auth mode. `prepare_responses`/tool
// calling are intentionally not implemented in this first cut (the trait's
// default impl returns `UnsupportedProviderKind` for them) -- chat
// completions is the scope this issue's acceptance criteria asks for;
// widening to the Responses API and tool-call round-tripping is a
// reasonable, self-contained follow-up once this lands.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::sigv4::{sign, AwsCredentials, SigningRequest};
use crate::{
    AdapterError, ChatCompletionPlan, ProviderAdapter, ProviderConfig, ProviderErrorResponse,
    ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct BedrockAdapter;

impl ProviderAdapter for BedrockAdapter {
    fn kind(&self) -> &'static str {
        "bedrock"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let credentials =
            provider
                .aws_credentials
                .as_ref()
                .ok_or_else(|| AdapterError::InvalidRequest {
                    message: "bedrock provider is missing AWS credentials".into(),
                })?;
        let body = ensure_object_body(request.body)?;

        let mut bedrock_body = json!({
            "messages": openai_messages_to_bedrock_messages(&body)?,
        });
        if let Some(system) = system_blocks(&body)? {
            bedrock_body["system"] = system;
        }
        if let Some(inference_config) = inference_config(&body) {
            bedrock_body["inferenceConfig"] = inference_config;
        }

        let host = extract_host(&provider.base_url)?;
        let path = format!(
            "/model/{}/converse",
            percent_encode_path_segment(&request.provider_model)
        );
        // Real Bedrock is https-only; `http://` is accepted too so tests
        // (and any local/VPC-endpoint mock) can exercise this adapter
        // against a plain-HTTP mock server the same way every other
        // adapter in this crate is tested, rather than requiring a real
        // TLS-terminated stand-in.
        let scheme = if provider.base_url.trim_start().starts_with("http://") {
            "http"
        } else {
            "https"
        };
        let endpoint = format!("{scheme}://{host}{path}");
        let body_bytes =
            serde_json::to_vec(&bedrock_body).map_err(|error| AdapterError::InvalidRequest {
                message: format!("failed to serialize Bedrock request body: {error}"),
            })?;

        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let signed = sign(
            &SigningRequest {
                method: "POST",
                path: &path,
                host: &host,
                region: &credentials.region,
                service: "bedrock",
                body: &body_bytes,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: credentials.access_key_id.clone(),
                secret_access_key: credentials.secret_access_key.expose_secret().to_string(),
                session_token: credentials
                    .session_token
                    .as_ref()
                    .map(|token| token.expose_secret().to_string()),
            },
        );

        let mut headers = vec![
            ProviderHeader {
                name: "content-type".into(),
                value: SecretValue::new("application/json"),
            },
            ProviderHeader {
                name: "host".into(),
                value: SecretValue::new(host),
            },
            ProviderHeader {
                name: "x-amz-date".into(),
                value: SecretValue::new(signed.x_amz_date),
            },
            ProviderHeader {
                name: "authorization".into(),
                value: SecretValue::new(signed.authorization),
            },
        ];
        if let Some(session_token) = signed.x_amz_security_token {
            headers.push(ProviderHeader {
                name: "x-amz-security-token".into(),
                value: SecretValue::new(session_token),
            });
        }

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint,
            body: bedrock_body,
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
        // Bedrock error bodies are flat: {"message": "..."}. The specific
        // exception name (ValidationException, ThrottlingException, ...)
        // is only available via the x-amzn-errortype response header,
        // which this trait method doesn't receive -- status-code
        // classification (see is_retryable_status) covers the cases that
        // matter for retry/fallback decisions without it.
        let message = parsed
            .as_ref()
            .and_then(|value| value.get("message"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| fallback_error_message(body))
            .unwrap_or_else(|| format!("provider returned HTTP {status}"));

        ProviderErrorResponse {
            status,
            body: json!({
                "error": {
                    "message": message,
                    "type": "provider_error",
                    "provider_type": "bedrock_error",
                    "code": "bedrock_error",
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
        let prompt_tokens = usage.get("inputTokens").and_then(Value::as_u64);
        let completion_tokens = usage.get("outputTokens").and_then(Value::as_u64);
        let total_tokens = usage
            .get("totalTokens")
            .and_then(Value::as_u64)
            .or_else(|| prompt_tokens.zip(completion_tokens).map(|(a, b)| a + b));
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
        "bedrock" => Ok(()),
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

/// OpenAI-shaped `messages` -> Bedrock Converse `messages`
/// (`[{"role": "user"|"assistant", "content": [{"text": "..."}]}]`).
/// `system` messages are extracted separately by [`system_blocks`], same
/// split Bedrock's own wire format requires (`system` is a top-level
/// field, not a message role).
fn openai_messages_to_bedrock_messages(body: &Value) -> Result<Value, AdapterError> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(json!([]));
    };
    let mut converted = Vec::new();
    for message in messages {
        let role = match message.get("role").and_then(Value::as_str) {
            Some("system") => continue,
            Some("assistant") => "assistant",
            Some("user") | None => "user",
            Some("tool") => "user",
            Some(other) => {
                return Err(AdapterError::InvalidRequest {
                    message: format!("unsupported Bedrock message role {other}"),
                });
            }
        };
        converted.push(json!({
            "role": role,
            "content": content_blocks(message.get("content"))?,
        }));
    }
    Ok(Value::Array(converted))
}

fn system_blocks(body: &Value) -> Result<Option<Value>, AdapterError> {
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut blocks = Vec::new();
    for message in messages {
        if message.get("role").and_then(Value::as_str) != Some("system") {
            continue;
        }
        blocks.extend(content_blocks(message.get("content"))?);
    }
    if blocks.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Value::Array(blocks)))
    }
}

fn content_blocks(content: Option<&Value>) -> Result<Vec<Value>, AdapterError> {
    match content {
        Some(Value::String(text)) => Ok(vec![json!({ "text": text })]),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .map(|block| match block {
                Value::Object(object)
                    if object.get("type").and_then(Value::as_str) == Some("text") =>
                {
                    let text = object.get("text").and_then(Value::as_str).unwrap_or("");
                    Ok(json!({ "text": text }))
                }
                Value::Object(object) => Err(AdapterError::InvalidRequest {
                    message: format!(
                        "unsupported Bedrock content block type {:?}",
                        object.get("type")
                    ),
                }),
                _ => Err(AdapterError::InvalidRequest {
                    message: "Bedrock content blocks must be objects".into(),
                }),
            })
            .collect(),
        None => Ok(vec![json!({ "text": "" })]),
        Some(_) => Err(AdapterError::InvalidRequest {
            message: "unsupported Bedrock message content shape".into(),
        }),
    }
}

fn inference_config(body: &Value) -> Option<Value> {
    let mut config = Map::new();
    copy_config(body, &mut config, "max_tokens", "maxTokens");
    copy_config(body, &mut config, "temperature", "temperature");
    copy_config(body, &mut config, "top_p", "topP");
    if let Some(stop) = body.get("stop") {
        match stop {
            Value::String(value) => {
                config.insert("stopSequences".into(), Value::Array(vec![json!(value)]));
            }
            Value::Array(values) => {
                config.insert("stopSequences".into(), Value::Array(values.clone()));
            }
            _ => {}
        }
    }
    (!config.is_empty()).then_some(Value::Object(config))
}

fn copy_config(body: &Value, config: &mut Map<String, Value>, source: &str, target: &str) {
    if let Some(value) = body.get(source) {
        config.insert(target.into(), value.clone());
    }
}

/// Extracts `host[:port]` from a configured Bedrock `base_url` (e.g.
/// `https://bedrock-runtime.us-east-1.amazonaws.com`) -- SigV4 signs
/// against the bare host, and the same value becomes the literal `Host`
/// header, so both need it in exactly this form. `pub(crate)` so the
/// `vertex` adapter can reuse the same scheme/host extraction for
/// building its endpoint URL from `base_url`.
pub(crate) fn extract_host(base_url: &str) -> Result<String, AdapterError> {
    let trimmed = base_url.trim_end_matches('/');
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host.is_empty() {
        return Err(AdapterError::InvalidRequest {
            message: format!("bedrock provider base_url {base_url} has no host"),
        });
    }
    Ok(host.to_string())
}

fn percent_encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn fallback_error_message(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?.trim();
    (!text.is_empty()).then(|| text.chars().take(512).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::AwsProviderCredentials;

    fn provider() -> ProviderConfig {
        ProviderConfig {
            name: "bedrock".into(),
            kind: "bedrock".into(),
            base_url: "https://bedrock-runtime.us-east-1.amazonaws.com".into(),
            api_key: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: Some(AwsProviderCredentials {
                access_key_id: "AKIDEXAMPLE".into(),
                secret_access_key: SecretValue::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                session_token: None,
                region: "us-east-1".into(),
            }),
            gcp_credentials: None,
        }
    }

    #[test]
    fn converts_openai_chat_plan_to_signed_bedrock_converse_request() {
        let adapter = BedrockAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(),
                ChatCompletionPlan {
                    logical_model: "bedrock-chat".into(),
                    provider_model: "anthropic.claude-3-5-sonnet-20241022-v2:0".into(),
                    stream: false,
                    body: json!({
                        "model": "bedrock-chat",
                        "messages": [
                            {"role": "system", "content": "be concise"},
                            {"role": "user", "content": "hello"}
                        ],
                        "max_tokens": 256,
                        "temperature": 0.5
                    }),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/\
             anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"
        );
        assert_eq!(prepared.body["messages"][0]["role"], "user");
        assert_eq!(prepared.body["messages"][0]["content"][0]["text"], "hello");
        assert_eq!(prepared.body["system"][0]["text"], "be concise");
        assert_eq!(prepared.body["inferenceConfig"]["maxTokens"], 256);
        assert_eq!(prepared.body["inferenceConfig"]["temperature"], 0.5);

        let header = |name: &str| {
            prepared
                .headers
                .iter()
                .find(|header| header.name == name)
                .map(|header| header.value.expose_secret())
        };
        assert_eq!(
            header("host"),
            Some("bedrock-runtime.us-east-1.amazonaws.com")
        );
        assert!(header("x-amz-date").is_some());
        assert!(header("authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
        assert!(header("x-amz-security-token").is_none());
        assert!(!format!("{prepared:?}").contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn includes_security_token_header_for_temporary_credentials() {
        let mut provider = provider();
        provider.aws_credentials = Some(AwsProviderCredentials {
            access_key_id: "ASIAEXAMPLE".into(),
            secret_access_key: SecretValue::new("secret"),
            session_token: Some(SecretValue::new("temporary-session-token")),
            region: "us-east-1".into(),
        });
        let adapter = BedrockAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "bedrock-chat".into(),
                    provider_model: "test-model".into(),
                    stream: false,
                    body: json!({"messages": [{"role": "user", "content": "hi"}]}),
                },
            )
            .unwrap();

        assert!(prepared
            .headers
            .iter()
            .any(|header| header.name == "x-amz-security-token"
                && header.value.expose_secret() == "temporary-session-token"));
    }

    #[test]
    fn rejects_missing_aws_credentials() {
        let mut provider = provider();
        provider.aws_credentials = None;
        let adapter = BedrockAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "bedrock-chat".into(),
                    provider_model: "test-model".into(),
                    stream: false,
                    body: json!({"messages": []}),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "bedrock provider is missing AWS credentials".into()
            }
        );
    }

    #[test]
    fn rejects_non_object_chat_body() {
        let adapter = BedrockAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider(),
                ChatCompletionPlan {
                    logical_model: "bedrock-chat".into(),
                    provider_model: "test-model".into(),
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
    fn normalizes_bedrock_error_response() {
        let adapter = BedrockAdapter;
        let normalized = adapter.normalize_error_response(
            400,
            "application/json",
            br#"{"message":"The model is not supported"}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 400);
        assert_eq!(
            normalized.body["error"]["message"],
            "The model is not supported"
        );
        assert_eq!(normalized.body["error"]["code"], "bedrock_error");
    }

    #[test]
    fn extracts_bedrock_usage_metadata() {
        let adapter = BedrockAdapter;
        let usage = adapter
            .extract_usage(br#"{"usage":{"inputTokens":13,"outputTokens":8,"totalTokens":21}}"#)
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(13));
        assert_eq!(usage.completion_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(21));
    }

    #[test]
    fn extract_host_strips_scheme_and_trailing_slash() {
        assert_eq!(
            extract_host("https://bedrock-runtime.us-east-1.amazonaws.com/").unwrap(),
            "bedrock-runtime.us-east-1.amazonaws.com"
        );
        assert_eq!(
            extract_host("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap(),
            "bedrock-runtime.us-east-1.amazonaws.com"
        );
    }
}
