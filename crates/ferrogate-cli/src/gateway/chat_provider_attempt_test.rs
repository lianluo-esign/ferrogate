// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Dedicated provider-attempt identity coverage for billing issue #213.

use super::{
    extract_last_provider_stream_usage, provider_request_for_attempt, ProviderAttemptSequence,
    StreamingUsageCapture, STREAMING_USAGE_CAPTURE_MAX_BYTES,
};
use ferrogate_billing::ProviderAttempt;
use ferrogate_providers::{ProviderHeader, ProviderHttpRequest, ProviderUsage, SecretValue};

#[test]
fn provider_attempt_sequence_is_stable_across_retry_and_fallback_dispatches() {
    let mut sequence = ProviderAttemptSequence::default();

    let primary = sequence.next("request-a");
    let primary_retry = sequence.next("request-a");
    let fallback = sequence.next("request-a");

    assert_eq!(primary.provider_attempt_index, 0);
    assert_eq!(primary_retry.provider_attempt_index, 1);
    assert_eq!(fallback.provider_attempt_index, 2);
    assert_eq!(primary.provider_attempt_id, "request-a:provider-attempt:0");
    assert_eq!(fallback.provider_attempt_id, "request-a:provider-attempt:2");
}

#[test]
fn provider_attempt_sequence_is_scoped_by_logical_request_id() {
    let mut first_request = ProviderAttemptSequence::default();
    let mut second_request = ProviderAttemptSequence::default();

    let first = first_request.next("request-a");
    let second = second_request.next("request-b");

    assert_eq!(first.provider_attempt_index, second.provider_attempt_index);
    assert_ne!(first.provider_attempt_id, second.provider_attempt_id);
}

#[test]
fn runtime_attempt_headers_replace_spoofed_provider_configuration() {
    let prepared = ProviderHttpRequest {
        provider: "openai".into(),
        endpoint: "http://127.0.0.1/v1/chat/completions".into(),
        body: serde_json::json!({}),
        stream: false,
        headers: vec![
            ProviderHeader {
                name: "X-FerroGate-Provider-Attempt-ID".into(),
                value: SecretValue::new("spoofed-id"),
            },
            ProviderHeader {
                name: "x-ferrogate-provider-attempt-index".into(),
                value: SecretValue::new("999"),
            },
        ],
    };

    let request =
        provider_request_for_attempt(&prepared, &ProviderAttempt::for_request("request-truth", 2));

    let attempt_headers = request
        .headers
        .iter()
        .filter(|header| {
            header
                .name
                .to_ascii_lowercase()
                .starts_with("x-ferrogate-provider-attempt-")
        })
        .map(|header| {
            (
                header.name.to_ascii_lowercase(),
                header.value.expose_secret().to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attempt_headers.len(), 2);
    assert_eq!(
        attempt_headers["x-ferrogate-provider-attempt-id"],
        "request-truth:provider-attempt:2"
    );
    assert_eq!(attempt_headers["x-ferrogate-provider-attempt-index"], "2");
}

#[test]
fn streaming_usage_uses_the_last_reported_sse_payload() {
    let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n\
data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10}}\r\n\r\n\
data: [DONE]\n\n";

    let usage = extract_last_provider_stream_usage(stream, |payload| {
        let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
        let usage = value.get("usage")?;
        Some(ProviderUsage {
            prompt_tokens: usage
                .get("prompt_tokens")
                .and_then(serde_json::Value::as_u64),
            completion_tokens: usage
                .get("completion_tokens")
                .and_then(serde_json::Value::as_u64),
            total_tokens: usage
                .get("total_tokens")
                .and_then(serde_json::Value::as_u64),
        })
    })
    .expect("the final provider usage payload must be extracted");

    assert_eq!(usage.prompt_tokens, Some(4));
    assert_eq!(usage.completion_tokens, Some(6));
    assert_eq!(usage.total_tokens, Some(10));
}

#[test]
fn streaming_usage_capture_retains_usage_at_the_tail_of_long_responses() {
    let mut capture = StreamingUsageCapture::default();
    capture.append(&vec![b'x'; STREAMING_USAGE_CAPTURE_MAX_BYTES]);
    capture.append(
        b"\n\ndata: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10}}\n\n",
    );

    let usage = extract_last_provider_stream_usage(&capture.body(), |payload| {
        let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
        let usage = value.get("usage")?;
        Some(ProviderUsage {
            prompt_tokens: usage
                .get("prompt_tokens")
                .and_then(serde_json::Value::as_u64),
            completion_tokens: usage
                .get("completion_tokens")
                .and_then(serde_json::Value::as_u64),
            total_tokens: usage
                .get("total_tokens")
                .and_then(serde_json::Value::as_u64),
        })
    })
    .expect("tail capture must retain the provider usage event");

    assert_eq!(usage.total_tokens, Some(10));
}
