// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Gateway-side TLS egress executor for brokered edge-function calls (#120).
//!
//! Given an already-built, already-governed [`EdgeFunctionHttpRequest`] (target
//! validated https + allowlisted upstream, credential injected by the runtime
//! builder), this performs the real `reqwest` (rustls) request and returns a
//! bounded [`FunctionInvocationOutcome`]. It is transport-agnostic on purpose —
//! the https/allowlist policy lives upstream, so this stays unit-testable against
//! a local server. Credentials are never logged.
//!
//! The `/v1/functions/execute` route (#119) is the production caller; until it
//! lands these are exercised only by tests, so dead-code is allowed here.
#![allow(dead_code)]

use std::{sync::OnceLock, time::Duration};

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_runtime::{EdgeFunctionHttpRequest, FunctionInvocationOutcome};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method,
};

const BODY_EXCERPT_MAX_BYTES: usize = 2048;

/// Execute a brokered edge-function request and return a bounded outcome.
pub(super) async fn execute_edge_function_request(
    request: &EdgeFunctionHttpRequest,
    function_slug: &str,
    timeout: Duration,
    max_body_bytes: usize,
) -> AnyResult<FunctionInvocationOutcome> {
    let method = Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("invalid function method: {}", request.method))?;
    let url = reqwest::Url::parse(&request.url)
        .with_context(|| format!("invalid function url: {}", request.url))?;
    match url.scheme() {
        "https" | "http" => {}
        other => bail!("unsupported function url scheme: {other}"),
    }

    let headers = build_headers(request)?;
    let response = function_http_client()?
        .request(method, url)
        .headers(headers)
        .timeout(timeout)
        .body(request.body.clone())
        .send()
        .await
        .context("edge-function request failed")?;

    let status_code = response.status().as_u16();
    if let Some(content_length) = response.content_length() {
        if content_length > max_body_bytes as u64 {
            bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
        }
    }
    let body = response
        .bytes()
        .await
        .context("failed to read edge-function response body")?;
    if body.len() > max_body_bytes {
        bail!("edge_function_response_body_too_large: exceeds {max_body_bytes} bytes");
    }

    let body_excerpt = String::from_utf8_lossy(&body)
        .chars()
        .take(BODY_EXCERPT_MAX_BYTES)
        .collect();

    Ok(FunctionInvocationOutcome {
        function_slug: function_slug.to_string(),
        status_code,
        body_excerpt,
    })
}

fn build_headers(request: &EdgeFunctionHttpRequest) -> AnyResult<HeaderMap> {
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid function header name: {name}"))?;
        let header_value = HeaderValue::from_str(value).context("invalid function header value")?;
        headers.insert(header_name, header_value);
    }
    Ok(headers)
}

fn function_http_client() -> AnyResult<Client> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    let result = CLIENT.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Client::builder()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()
            .map_err(|error| error.to_string())
    });
    match result {
        Ok(client) => Ok(client.clone()),
        Err(error) => bail!("failed to initialize function HTTP client: {error}"),
    }
}

#[cfg(test)]
#[path = "function_egress_test.rs"]
mod function_egress_test;
