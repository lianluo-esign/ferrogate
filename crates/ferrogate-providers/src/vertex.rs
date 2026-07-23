// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: Google Vertex AI provider adapter (issue #172), targeting
// the Gemini-on-Vertex `generateContent`/`streamGenerateContent` REST
// endpoints
// (<https://cloud.google.com/vertex-ai/generative-ai/docs/model-reference/inference>).
// Authenticates via a static OAuth2 Bearer access token rather than
// minting one from a service-account key in-crate -- see
// `GcpProviderCredentials` in `types.rs` for why. Reuses `gemini.rs`'s
// OpenAI-to-Gemini request-body conversion and response normalization,
// since Vertex's Gemini-model wire format is documented as the same
// `contents`/`systemInstruction`/`generationConfig`/`usageMetadata` shape
// the public Generative Language API uses -- only the endpoint URL and
// auth scheme differ. `prepare_responses`/tool calling are intentionally
// not implemented in this first cut, matching the scope `bedrock.rs`
// already established for the same issue.

use serde_json::{json, Value};

use crate::bedrock::extract_host;
use crate::gemini::{
    embeddings_text_inputs, ensure_object_body, generation_config, openai_embeddings_response,
    openai_messages_to_gemini_contents, parse_embeddings_response_body, system_instruction,
};
use crate::{
    AdapterError, ChatCompletionPlan, EmbeddingsPlan, GeminiAdapter, ProviderAdapter,
    ProviderConfig, ProviderErrorResponse, ProviderHeader, ProviderHttpRequest, ProviderUsage,
    SecretValue,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct VertexAiAdapter;

impl ProviderAdapter for VertexAiAdapter {
    fn kind(&self) -> &'static str {
        "vertex"
    }

    fn prepare_chat_completions(
        &self,
        provider: ProviderConfig,
        request: ChatCompletionPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let credentials =
            provider
                .gcp_credentials
                .as_ref()
                .ok_or_else(|| AdapterError::InvalidRequest {
                    message: "vertex provider is missing GCP credentials".into(),
                })?;
        let body = ensure_object_body(request.body)?;

        let mut vertex_body = json!({
            "contents": openai_messages_to_gemini_contents(&body)?,
        });
        if let Some(system_instruction) = system_instruction(&body)? {
            vertex_body["systemInstruction"] = system_instruction;
        }
        if let Some(config) = generation_config(&body) {
            vertex_body["generationConfig"] = config;
        }

        let endpoint = generate_content_endpoint(
            &provider.base_url,
            credentials,
            &request.provider_model,
            request.stream,
        )?;

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint,
            body: vertex_body,
            stream: request.stream,
            headers: vertex_headers(&credentials.access_token),
        })
    }

    fn prepare_embeddings(
        &self,
        provider: ProviderConfig,
        request: EmbeddingsPlan,
    ) -> Result<ProviderHttpRequest, AdapterError> {
        validate_kind(&provider.kind)?;
        let credentials =
            provider
                .gcp_credentials
                .as_ref()
                .ok_or_else(|| AdapterError::InvalidRequest {
                    message: "vertex provider is missing GCP credentials".into(),
                })?;
        let body = ensure_object_body(request.body)?;
        let inputs = embeddings_text_inputs(&body)?;
        // Vertex text-embedding models use the `:predict` endpoint with an
        // `instances` array (one `{"content": text}` per input), distinct
        // from the public Generative Language API's `:batchEmbedContents`.
        let instances: Vec<Value> = inputs
            .iter()
            .map(|text| json!({ "content": text }))
            .collect();
        let endpoint = predict_endpoint(&provider.base_url, credentials, &request.provider_model)?;

        Ok(ProviderHttpRequest {
            provider: provider.name,
            endpoint,
            body: json!({ "instances": instances }),
            stream: false,
            headers: vertex_headers(&credentials.access_token),
        })
    }

    fn translate_embeddings_response(
        &self,
        body: &[u8],
        model: &str,
    ) -> Result<Option<Value>, AdapterError> {
        let value = parse_embeddings_response_body(body)?;
        let predictions = value
            .get("predictions")
            .and_then(Value::as_array)
            .ok_or_else(|| AdapterError::InvalidRequest {
                message: "Vertex embeddings response is missing a predictions array".into(),
            })?;
        let mut vectors = Vec::with_capacity(predictions.len());
        let (mut token_total, mut saw_tokens) = (0_u64, false);
        for prediction in predictions {
            let embeddings = prediction.get("embeddings");
            vectors.push(
                embeddings
                    .and_then(|embeddings| embeddings.get("values"))
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            );
            if let Some(tokens) = embeddings
                .and_then(|embeddings| embeddings.get("statistics"))
                .and_then(|statistics| statistics.get("token_count"))
                .and_then(Value::as_u64)
            {
                token_total += tokens;
                saw_tokens = true;
            }
        }
        Ok(Some(openai_embeddings_response(
            vectors,
            model,
            saw_tokens.then_some(token_total),
        )))
    }

    fn normalize_error_response(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
        request_id: &str,
    ) -> ProviderErrorResponse {
        // Vertex's error envelope for Gemini-model calls is documented as
        // the same {"error": {code, message, status}} shape the public
        // Generative Language API uses, so this delegates rather than
        // duplicating `gemini.rs`'s parsing.
        GeminiAdapter.normalize_error_response(status, content_type, body, request_id)
    }

    fn extract_usage(&self, body: &[u8]) -> Option<ProviderUsage> {
        // Chat/`generateContent` responses carry a Gemini-shaped
        // `usageMetadata`; embeddings `:predict` responses instead report
        // per-instance `statistics.token_count`, so fall back to summing
        // those for provider-reported embeddings metering (issue #274).
        GeminiAdapter
            .extract_usage(body)
            .or_else(|| vertex_embeddings_usage(body))
    }
}

fn vertex_embeddings_usage(body: &[u8]) -> Option<ProviderUsage> {
    let value = serde_json::from_slice::<Value>(body).ok()?;
    let predictions = value.get("predictions").and_then(Value::as_array)?;
    let mut total = 0_u64;
    let mut saw_tokens = false;
    for prediction in predictions {
        if let Some(tokens) = prediction
            .get("embeddings")
            .and_then(|embeddings| embeddings.get("statistics"))
            .and_then(|statistics| statistics.get("token_count"))
            .and_then(Value::as_u64)
        {
            total += tokens;
            saw_tokens = true;
        }
    }
    saw_tokens.then_some(ProviderUsage {
        prompt_tokens: Some(total),
        completion_tokens: None,
        total_tokens: Some(total),
    })
}

fn validate_kind(kind: &str) -> Result<(), AdapterError> {
    match kind {
        "vertex" | "vertex-ai" => Ok(()),
        other => Err(AdapterError::UnsupportedProviderKind {
            kind: other.to_string(),
        }),
    }
}

fn vertex_headers(access_token: &SecretValue) -> Vec<ProviderHeader> {
    vec![
        ProviderHeader {
            name: "content-type".into(),
            value: SecretValue::new("application/json"),
        },
        ProviderHeader {
            name: "authorization".into(),
            value: SecretValue::new(format!("Bearer {}", access_token.expose_secret())),
        },
    ]
}

fn generate_content_endpoint(
    base_url: &str,
    credentials: &crate::types::GcpProviderCredentials,
    provider_model: &str,
    stream: bool,
) -> Result<String, AdapterError> {
    let host = extract_host(base_url)?;
    let scheme = if base_url.trim_start().starts_with("http://") {
        "http"
    } else {
        "https"
    };
    let action = if stream {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };
    let model = provider_model
        .trim_start_matches("publishers/google/models/")
        .trim_start_matches("models/");
    Ok(format!(
        "{scheme}://{host}/v1/projects/{}/locations/{}/publishers/google/models/{model}:{action}",
        credentials.project_id, credentials.location,
    ))
}

fn predict_endpoint(
    base_url: &str,
    credentials: &crate::types::GcpProviderCredentials,
    provider_model: &str,
) -> Result<String, AdapterError> {
    let host = extract_host(base_url)?;
    let scheme = if base_url.trim_start().starts_with("http://") {
        "http"
    } else {
        "https"
    };
    let model = provider_model
        .trim_start_matches("publishers/google/models/")
        .trim_start_matches("models/");
    Ok(format!(
        "{scheme}://{host}/v1/projects/{}/locations/{}/publishers/google/models/{model}:predict",
        credentials.project_id, credentials.location,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::GcpProviderCredentials;

    fn provider() -> ProviderConfig {
        ProviderConfig {
            name: "vertex".into(),
            kind: "vertex".into(),
            base_url: "https://us-central1-aiplatform.googleapis.com".into(),
            api_key: None,
            openrouter_http_referer: None,
            openrouter_x_title: None,
            aws_credentials: None,
            gcp_credentials: Some(GcpProviderCredentials {
                access_token: SecretValue::new("ya29.EXAMPLE_ACCESS_TOKEN"),
                project_id: "my-gcp-project".into(),
                location: "us-central1".into(),
            }),
            cloudflare_ai_gateway: None,
        }
    }

    #[test]
    fn converts_openai_chat_plan_to_vertex_generate_content_request() {
        let adapter = VertexAiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(),
                ChatCompletionPlan {
                    logical_model: "vertex-chat".into(),
                    provider_model: "gemini-1.5-pro".into(),
                    stream: false,
                    body: json!({
                        "model": "vertex-chat",
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
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:generateContent"
        );
        assert_eq!(prepared.body["contents"][0]["role"], "user");
        assert_eq!(prepared.body["contents"][0]["parts"][0]["text"], "hello");
        assert_eq!(
            prepared.body["systemInstruction"]["parts"][0]["text"],
            "be concise"
        );
        assert_eq!(prepared.body["generationConfig"]["maxOutputTokens"], 256);

        let header = |name: &str| {
            prepared
                .headers
                .iter()
                .find(|header| header.name == name)
                .map(|header| header.value.expose_secret())
        };
        assert_eq!(
            header("authorization"),
            Some("Bearer ya29.EXAMPLE_ACCESS_TOKEN")
        );
        assert!(!format!("{prepared:?}").contains("ya29.EXAMPLE_ACCESS_TOKEN"));
    }

    #[test]
    fn uses_stream_generate_content_endpoint_for_streaming() {
        let adapter = VertexAiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider(),
                ChatCompletionPlan {
                    logical_model: "vertex-chat".into(),
                    provider_model: "gemini-1.5-pro".into(),
                    stream: true,
                    body: json!({"messages": [{"role": "user", "content": "hello"}]}),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/gemini-1.5-pro:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn preserves_http_scheme_for_local_mock_servers() {
        let mut provider = provider();
        provider.base_url = "http://127.0.0.1:9999".into();
        let adapter = VertexAiAdapter;
        let prepared = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "vertex-chat".into(),
                    provider_model: "gemini-1.5-pro".into(),
                    stream: false,
                    body: json!({"messages": [{"role": "user", "content": "hi"}]}),
                },
            )
            .unwrap();

        assert!(prepared.endpoint.starts_with("http://127.0.0.1:9999/v1/"));
    }

    #[test]
    fn rejects_missing_gcp_credentials() {
        let mut provider = provider();
        provider.gcp_credentials = None;
        let adapter = VertexAiAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider,
                ChatCompletionPlan {
                    logical_model: "vertex-chat".into(),
                    provider_model: "gemini-1.5-pro".into(),
                    stream: false,
                    body: json!({"messages": []}),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "vertex provider is missing GCP credentials".into()
            }
        );
    }

    #[test]
    fn rejects_non_object_chat_body() {
        let adapter = VertexAiAdapter;
        let error = adapter
            .prepare_chat_completions(
                provider(),
                ChatCompletionPlan {
                    logical_model: "vertex-chat".into(),
                    provider_model: "gemini-1.5-pro".into(),
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
    fn normalizes_vertex_error_response_via_gemini_shape() {
        let adapter = VertexAiAdapter;
        let normalized = adapter.normalize_error_response(
            403,
            "application/json",
            br#"{"error":{"code":403,"message":"permission denied","status":"PERMISSION_DENIED"}}"#,
            "fg-test",
        );

        assert_eq!(normalized.status, 403);
        assert_eq!(normalized.body["error"]["message"], "permission denied");
        assert_eq!(
            normalized.body["error"]["provider_type"],
            "PERMISSION_DENIED"
        );
    }

    #[test]
    fn extracts_vertex_usage_metadata_via_gemini_shape() {
        let adapter = VertexAiAdapter;
        let usage = adapter
            .extract_usage(
                br#"{"usageMetadata":{"promptTokenCount":13,"candidatesTokenCount":8,"totalTokenCount":21}}"#,
            )
            .unwrap();

        assert_eq!(usage.prompt_tokens, Some(13));
        assert_eq!(usage.completion_tokens, Some(8));
        assert_eq!(usage.total_tokens, Some(21));
    }

    #[test]
    fn converts_embeddings_plan_to_vertex_predict_request() {
        let adapter = VertexAiAdapter;
        let prepared = adapter
            .prepare_embeddings(
                provider(),
                EmbeddingsPlan {
                    logical_model: "vertex-embed".into(),
                    provider_model: "text-embedding-004".into(),
                    body: json!({"input": ["alpha", "beta"]}),
                },
            )
            .unwrap();

        assert_eq!(
            prepared.endpoint,
            "https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1/publishers/google/models/text-embedding-004:predict"
        );
        assert_eq!(prepared.body["instances"][0]["content"], "alpha");
        assert_eq!(prepared.body["instances"][1]["content"], "beta");
        assert!(!prepared.stream);
        assert_eq!(
            prepared
                .headers
                .iter()
                .find(|header| header.name == "authorization")
                .map(|header| header.value.expose_secret()),
            Some("Bearer ya29.EXAMPLE_ACCESS_TOKEN")
        );
    }

    #[test]
    fn rejects_embeddings_without_gcp_credentials() {
        let mut provider = provider();
        provider.gcp_credentials = None;
        let adapter = VertexAiAdapter;
        let error = adapter
            .prepare_embeddings(
                provider,
                EmbeddingsPlan {
                    logical_model: "vertex-embed".into(),
                    provider_model: "text-embedding-004".into(),
                    body: json!({"input": "hello"}),
                },
            )
            .unwrap_err();

        assert_eq!(
            error,
            AdapterError::InvalidRequest {
                message: "vertex provider is missing GCP credentials".into()
            }
        );
    }

    #[test]
    fn normalizes_vertex_predict_response_and_meters_reported_tokens() {
        let adapter = VertexAiAdapter;
        let raw = br#"{"predictions":[
            {"embeddings":{"values":[0.1,0.2],"statistics":{"token_count":3}}},
            {"embeddings":{"values":[0.3,0.4],"statistics":{"token_count":4}}}
        ]}"#;

        let normalized = adapter
            .translate_embeddings_response(raw, "vertex-embed")
            .unwrap()
            .unwrap();
        assert_eq!(normalized["object"], "list");
        assert_eq!(normalized["model"], "vertex-embed");
        assert_eq!(normalized["data"][0]["embedding"][1], 0.2);
        assert_eq!(normalized["data"][1]["index"], 1);
        assert_eq!(normalized["usage"]["prompt_tokens"], 7);
        assert_eq!(normalized["usage"]["total_tokens"], 7);

        let usage = adapter.extract_usage(raw).unwrap();
        assert_eq!(usage.prompt_tokens, Some(7));
        assert_eq!(usage.total_tokens, Some(7));
    }
}
