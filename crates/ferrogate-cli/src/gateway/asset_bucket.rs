// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: S3-compatible object-storage bucket client for `/v1/assets/*`
// content (issue #176) -- Supabase Storage exposes an S3-compatible API
// (same SigV4 auth AWS S3 uses), so this reuses the SigV4 signer already
// built and verified for the Bedrock adapter (`ferrogate-providers::sigv4`)
// rather than a second hand-rolled implementation. Content stays inline in
// `stored_assets.content` (the original #176 design) unless a bucket is
// configured via `[asset_bucket]`; when it is, `push`/`pull`/`delete`
// switch to this client and `stored_assets.storage_uri` records the
// object key instead of duplicating bytes in Postgres.
//
// Honest scope note: tested against a local mock S3-compatible HTTP
// server (asserting request shape: path-style URL, SigV4 headers,
// signed x-amz-content-sha256), the same testing philosophy as every
// other externally-facing adapter in this codebase (Bedrock, Vertex,
// Stripe) -- no live Supabase Storage bucket credentials were available
// to verify end-to-end against the real service, including its
// Row-Level Security tenant-isolation policies. That remains open on
// issue #176.

use std::time::{SystemTime, UNIX_EPOCH};

use ferrogate_providers::{sign_sigv4_with_content_hash_header, AwsCredentials, SigningRequest};

use super::dispatch::provider_http_client;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssetBucketConfig {
    /// `scheme://host[:port]`, no trailing slash and no bucket/key suffix
    /// -- e.g. `https://<project>.supabase.co/storage/v1/s3` for Supabase
    /// Storage's S3-compatible endpoint, or `http://127.0.0.1:PORT` for a
    /// local mock in tests.
    pub(crate) endpoint: String,
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) access_key_id: String,
    pub(crate) secret_access_key: String,
}

pub(crate) struct AssetBucketClient {
    config: AssetBucketConfig,
}

impl AssetBucketClient {
    pub(crate) fn new(config: AssetBucketConfig) -> Self {
        Self { config }
    }

    pub(crate) async fn put_object(
        &self,
        key: &str,
        body: &[u8],
        content_type: &str,
    ) -> anyhow::Result<()> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("PUT", &path, &host, body);
        let client = provider_http_client()?;
        let mut request = client
            .put(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone())
            .header("content-type", content_type)
            .body(body.to_vec());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket PUT failed (HTTP {status}): {text}");
        }
        Ok(())
    }

    pub(crate) async fn get_object(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("GET", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .get(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket GET failed (HTTP {status}): {text}");
        }
        Ok(response.bytes().await?.to_vec())
    }

    pub(crate) async fn delete_object(&self, key: &str) -> anyhow::Result<()> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("DELETE", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .delete(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        // A 404 on delete is not an error here: the caller already knows
        // the `stored_assets` row existed (it's deleting the DB row in
        // the same operation), so a missing bucket object is at worst a
        // prior inconsistency, not something to fail the whole delete on.
        if !status.is_success() && status.as_u16() != 404 {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket DELETE failed (HTTP {status}): {text}");
        }
        Ok(())
    }

    fn object_path(&self, key: &str) -> String {
        format!("/{}/{key}", self.config.bucket)
    }

    fn sign(
        &self,
        method: &'static str,
        path: &str,
        host: &str,
        body: &[u8],
    ) -> ferrogate_providers::SignedHeaders {
        let timestamp_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        sign_sigv4_with_content_hash_header(
            &SigningRequest {
                method,
                path,
                host,
                region: &self.config.region,
                service: "s3",
                body,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
        )
    }

    /// Extracts `(scheme, host[:port])` from `config.endpoint` -- mirrors
    /// `bedrock.rs::extract_host`'s http-preserved-for-tests /
    /// https-otherwise convention, duplicated here rather than shared
    /// since it's a trivial ~10-line helper and the two crates don't
    /// otherwise need a shared utilities module for it.
    fn scheme_and_host(&self) -> anyhow::Result<(&'static str, String)> {
        let trimmed = self.config.endpoint.trim_end_matches('/');
        let scheme = if trimmed.starts_with("http://") {
            "http"
        } else {
            "https"
        };
        let host = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);
        if host.is_empty() {
            anyhow::bail!("asset_bucket.endpoint {} has no host", self.config.endpoint);
        }
        Ok((scheme, host.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        body: Vec<u8>,
        has_authorization: bool,
        content_sha256_header: Option<String>,
    }

    /// A one-shot mock S3-compatible endpoint: accepts exactly one
    /// request, records its shape, and replies with a fixed status/body.
    /// Mirrors `payments.rs`'s `spawn_stripe_mock` pattern.
    fn spawn_bucket_mock(
        response_status: &'static str,
        response_body: &'static [u8],
    ) -> (String, Arc<Mutex<Option<CapturedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let captured = Arc::new(Mutex::new(None));
        let server_captured = Arc::clone(&captured);

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
            let content_length: usize = head
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            while raw.len() < header_end + content_length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                raw.extend_from_slice(&buffer[..read]);
            }
            let body = raw[header_end..header_end + content_length].to_vec();
            let request_line = head.lines().next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            let has_authorization = head
                .to_lowercase()
                .contains("authorization: aws4-hmac-sha256");
            let content_sha256_header = head.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("x-amz-content-sha256")
                        .then(|| value.trim().to_string())
                })
            });
            *server_captured.lock().unwrap() = Some(CapturedRequest {
                method,
                path,
                body,
                has_authorization,
                content_sha256_header,
            });

            let response = format!(
                "HTTP/1.1 {response_status}\r\nContent-Length: {}\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(response_body).unwrap();
        });

        (endpoint, captured)
    }

    fn client(endpoint: String) -> AssetBucketClient {
        AssetBucketClient::new(AssetBucketConfig {
            endpoint,
            bucket: "ferrogate-assets".into(),
            region: "us-east-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        })
    }

    #[tokio::test]
    async fn put_object_sends_a_signed_path_style_request_with_the_body() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let bucket = client(endpoint);

        bucket
            .put_object(
                "tenant-a:cli_tool:hello:1.0.0",
                b"asset bytes",
                "text/plain",
            )
            .await
            .unwrap();

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "PUT");
        assert_eq!(
            request.path,
            "/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0"
        );
        assert_eq!(request.body, b"asset bytes");
        assert!(request.has_authorization);
        assert!(request.content_sha256_header.is_some());
        assert!(!format!("{request:?}").contains("wJalrXUtnFEMI"));
    }

    #[tokio::test]
    async fn get_object_returns_the_response_body() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"fetched bytes");
        let bucket = client(endpoint);

        let bytes = bucket
            .get_object("tenant-a:cli_tool:hello:1.0.0")
            .await
            .unwrap();
        assert_eq!(bytes, b"fetched bytes");

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.has_authorization);
    }

    #[tokio::test]
    async fn get_object_errors_on_a_non_success_status() {
        let (endpoint, _captured) = spawn_bucket_mock("404 Not Found", b"no such key");
        let bucket = client(endpoint);

        let error = bucket
            .get_object("tenant-a:cli_tool:missing:1.0.0")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("404"));
    }

    #[tokio::test]
    async fn delete_object_treats_404_as_success() {
        let (endpoint, captured) = spawn_bucket_mock("404 Not Found", b"");
        let bucket = client(endpoint);

        bucket
            .delete_object("tenant-a:cli_tool:already-gone:1.0.0")
            .await
            .unwrap();

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "DELETE");
    }

    #[test]
    fn scheme_and_host_preserves_http_for_local_mocks_and_defaults_to_https() {
        let http_bucket = client("http://127.0.0.1:9999".into());
        assert_eq!(
            http_bucket.scheme_and_host().unwrap(),
            ("http", "127.0.0.1:9999".to_string())
        );

        let https_bucket = client("https://project.supabase.co/storage/v1/s3".into());
        assert_eq!(
            https_bucket.scheme_and_host().unwrap(),
            ("https", "project.supabase.co/storage/v1/s3".to_string())
        );
    }
}
