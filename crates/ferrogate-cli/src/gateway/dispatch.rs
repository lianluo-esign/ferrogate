// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{bail, Context, Result as AnyResult};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use reqwest::Client;
use std::{
    io::{Error as IoError, Read},
    sync::OnceLock,
    time::Duration,
};

use ferrogate_providers::ProviderHttpRequest;

#[derive(Debug, Clone)]
pub(super) struct ProviderHttpResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: String,
    pub(super) body: Vec<u8>,
}

pub(super) struct ProviderStreamingResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: String,
    pub(super) initial_body: Vec<u8>,
    pub(super) body: ProviderBodyReader,
}

pub(super) struct ProviderBodyReader {
    runtime: tokio::runtime::Handle,
    response: reqwest::Response,
    pending: Option<Bytes>,
}

impl Read for ProviderBodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        loop {
            if let Some(mut pending) = self.pending.take() {
                let read = pending.len().min(buffer.len());
                buffer[..read].copy_from_slice(&pending[..read]);
                if read < pending.len() {
                    let _ = pending.split_to(read);
                    self.pending = Some(pending);
                }
                return Ok(read);
            }

            let chunk = self
                .runtime
                .block_on(self.response.chunk())
                .map_err(IoError::other)?;
            match chunk {
                Some(chunk) if chunk.is_empty() => continue,
                Some(chunk) => self.pending = Some(chunk),
                None => return Ok(0),
            }
        }
    }
}

pub(super) async fn dispatch_provider_request(
    request: ProviderHttpRequest,
    timeout: Duration,
    max_body_bytes: usize,
) -> AnyResult<ProviderHttpResponse> {
    let body = serde_json::to_vec(&request.body).context("failed to serialize provider body")?;
    let response = build_provider_request(&request, timeout, body)?
        .send()
        .await
        .context("provider request failed")?;
    let status = response.status();
    let content_type = provider_response_content_type(response.headers());
    if let Some(content_length) = response.content_length() {
        if content_length > max_body_bytes as u64 {
            bail!(
                "provider_response_body_too_large: provider response body exceeds {max_body_bytes} bytes"
            );
        }
    }
    let body = response
        .bytes()
        .await
        .context("failed to read provider response body")?;
    if body.len() > max_body_bytes {
        bail!(
            "provider_response_body_too_large: provider response body exceeds {max_body_bytes} bytes"
        );
    }
    Ok(ProviderHttpResponse {
        status,
        content_type,
        body: body.to_vec(),
    })
}

pub(super) async fn dispatch_provider_streaming_request(
    request: ProviderHttpRequest,
    timeout: Duration,
) -> AnyResult<ProviderStreamingResponse> {
    let body = serde_json::to_vec(&request.body).context("failed to serialize provider body")?;
    let response = build_provider_request(&request, timeout, body)?
        .send()
        .await
        .context("provider streaming request failed")?;
    let status = response.status();
    let content_type = provider_response_content_type(response.headers());
    Ok(ProviderStreamingResponse {
        status,
        content_type,
        initial_body: Vec::new(),
        body: ProviderBodyReader {
            runtime: tokio::runtime::Handle::current(),
            response,
            pending: None,
        },
    })
}

fn provider_http_client() -> AnyResult<Client> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    let result = CLIENT.get_or_init(|| {
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
        Err(error) => bail!("failed to initialize provider HTTP client: {error}"),
    }
}

fn build_provider_request(
    request: &ProviderHttpRequest,
    timeout: Duration,
    body: Vec<u8>,
) -> AnyResult<reqwest::RequestBuilder> {
    let endpoint = reqwest::Url::parse(&request.endpoint)
        .with_context(|| format!("invalid provider endpoint {}", request.endpoint))?;
    match endpoint.scheme() {
        "http" | "https" => {}
        other => bail!("provider dispatch supports http and https endpoints only, got {other}"),
    }
    let mut headers = HeaderMap::new();
    for header in &request.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .with_context(|| format!("invalid provider header name {}", header.name))?;
        let value = HeaderValue::from_str(header.value.expose_secret())
            .with_context(|| format!("invalid provider header value for {}", header.name))?;
        headers.insert(name, value);
    }

    Ok(provider_http_client()?
        .post(endpoint)
        .headers(headers)
        .timeout(timeout)
        .body(body))
}

fn provider_response_content_type(headers: &HeaderMap) -> String {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "application/json".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_providers::ProviderHttpRequest;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    #[tokio::test]
    async fn rejects_unsupported_provider_target_scheme() {
        let request = ProviderHttpRequest {
            provider: "openai".into(),
            endpoint: "ftp://api.example.test/v1".into(),
            body: json!({"model": "gpt-test", "messages": []}),
            stream: false,
            headers: vec![],
        };

        let error = dispatch_provider_request(request, Duration::from_millis(50), 16 * 1024)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("supports http and https endpoints only"));
    }

    #[tokio::test]
    async fn provider_dispatch_respects_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        let request = ProviderHttpRequest {
            provider: "openai".into(),
            endpoint: format!("http://{addr}/v1/chat/completions"),
            body: json!({"model": "gpt-test", "messages": []}),
            stream: false,
            headers: vec![],
        };

        let started = Instant::now();
        let error = dispatch_provider_request(request, Duration::from_millis(50), 16 * 1024)
            .await
            .unwrap_err();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!error.to_string().is_empty());
        handle.join().unwrap();
    }

    #[tokio::test]
    async fn provider_dispatch_reads_chunked_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
                )
                .unwrap();
        });
        let request = ProviderHttpRequest {
            provider: "openai".into(),
            endpoint: format!("http://{addr}/v1/chat/completions"),
            body: json!({"model": "gpt-test", "messages": []}),
            stream: false,
            headers: vec![],
        };

        let response = dispatch_provider_request(request, Duration::from_secs(1), 16 * 1024)
            .await
            .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body, b"{}");
        handle.join().unwrap();
    }
}
