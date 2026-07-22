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

use ferrogate_providers::{
    presign_sigv4_query, sign_sigv4_with_content_hash_header, AwsCredentials, PresignRequest,
    SigningRequest,
};

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
        self.put_object_owned(key, body.to_vec(), content_type)
            .await
    }

    /// PUTs an owned object buffer without cloning it for the HTTP request.
    /// The presigned commit path already owns the verified bytes and may hold
    /// up to the configured multi-gigabyte ceiling, so a second full copy is
    /// not acceptable there.
    pub(crate) async fn put_object_owned(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("PUT", &path, &host, &body);
        let client = provider_http_client()?;
        let mut request = client
            .put(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone())
            .header("content-type", content_type)
            .body(body);
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
        self.get_object_if_present(key).await?.ok_or_else(|| {
            anyhow::anyhow!("asset bucket GET failed (HTTP 404 Not Found): object does not exist")
        })
    }

    /// GETs an object while preserving a missing-key result for commit-race
    /// reconciliation. Other bucket failures remain explicit errors.
    pub(crate) async fn get_object_if_present(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
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
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket GET failed (HTTP {status}): {text}");
        }
        Ok(Some(response.bytes().await?.to_vec()))
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

    /// HEAD the object, returning its size (`Content-Length`) or `None`
    /// when it does not exist (404). The large-file commit path (issue
    /// #259) uses this to gate the object's size against the registered
    /// intent *before* downloading it for the sha256 + supply-chain checks.
    pub(crate) async fn head_object(&self, key: &str) -> anyhow::Result<Option<u64>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let signed = self.sign("HEAD", &path, &host, b"");
        let client = provider_http_client()?;
        let mut request = client
            .head(format!("{scheme}://{host}{path}"))
            .header("host", host.clone())
            .header("x-amz-date", signed.x_amz_date.clone())
            .header("authorization", signed.authorization.clone());
        if let Some(content_sha256) = &signed.x_amz_content_sha256 {
            request = request.header("x-amz-content-sha256", content_sha256.clone());
        }
        let response = request.send().await?;
        let status = response.status();
        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("asset bucket HEAD failed (HTTP {status}): {text}");
        }
        let size = response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| anyhow::anyhow!("asset bucket HEAD returned no valid Content-Length"))?;
        Ok(Some(size))
    }

    /// Lists every object in the bucket (following continuation tokens) as
    /// `(key, last_modified_unix)` pairs -- the #263 unreferenced-blob GC
    /// reconcile pass compares these against the registry's `storage_uri`s.
    /// Signs a `ListObjectsV2` (`GET /{bucket}?list-type=2&...`) with the query
    /// folded into the SigV4 signature (unlike object PUT/GET/DELETE, whose
    /// query is empty). The `LastModified` timestamp is parsed to unix seconds;
    /// an unparseable one yields `0`, which the GC planner treats as
    /// too-new-to-delete (fail-safe KEEP).
    pub(crate) async fn list_objects(
        &self,
    ) -> anyhow::Result<Vec<ferrogate_storage::BucketObject>> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = format!("/{}", self.config.bucket);
        let client = provider_http_client()?;
        let mut objects = Vec::new();
        let mut continuation_token: Option<String> = None;
        // Bound the pagination loop so a pathological bucket can never spin
        // forever; 1000 keys/page * 1000 pages is 1M objects per pass.
        for _ in 0..1_000 {
            let mut params: Vec<(&str, &str)> = vec![("list-type", "2")];
            if let Some(token) = continuation_token.as_deref() {
                params.push(("continuation-token", token));
            }
            let canonical_query = ferrogate_providers::sigv4_canonical_query_string(&params);
            let timestamp_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            let signed = ferrogate_providers::sign_sigv4_with_content_hash_header_and_query(
                &SigningRequest {
                    method: "GET",
                    path: &path,
                    host: &host,
                    region: &self.config.region,
                    service: "s3",
                    body: b"",
                    timestamp_unix,
                },
                &AwsCredentials {
                    access_key_id: self.config.access_key_id.clone(),
                    secret_access_key: self.config.secret_access_key.clone(),
                    session_token: None,
                },
                &canonical_query,
            );
            let mut request = client
                .get(format!("{scheme}://{host}{path}?{canonical_query}"))
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
                anyhow::bail!("asset bucket LIST failed (HTTP {status}): {text}");
            }
            let body = response.text().await?;
            objects.extend(parse_list_objects_v2(&body));
            match next_continuation_token(&body) {
                Some(token) => continuation_token = Some(token),
                None => break,
            }
        }
        Ok(objects)
    }

    /// Issues a short-TTL SigV4 query-string presigned upload URL (issue
    /// #259). The holder streams the object bytes straight to the bucket
    /// with a plain `PUT` (no auth headers), bypassing the gateway hot
    /// path; the gateway later verifies the committed object.
    pub(crate) fn presign_put(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        self.presign_url("PUT", key, expires_secs, timestamp_unix)
    }

    /// Issues a short-TTL SigV4 query-string presigned download URL (issue
    /// #259) so reads never require the bucket to be public.
    pub(crate) fn presign_get(
        &self,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        self.presign_url("GET", key, expires_secs, timestamp_unix)
    }

    fn presign_url(
        &self,
        method: &'static str,
        key: &str,
        expires_secs: u64,
        timestamp_unix: u64,
    ) -> anyhow::Result<String> {
        let (scheme, host) = self.scheme_and_host()?;
        let path = self.object_path(key);
        let query = presign_sigv4_query(
            &PresignRequest {
                method,
                path: &path,
                host: &host,
                region: &self.config.region,
                service: "s3",
                expires_secs,
                timestamp_unix,
            },
            &AwsCredentials {
                access_key_id: self.config.access_key_id.clone(),
                secret_access_key: self.config.secret_access_key.clone(),
                session_token: None,
            },
        );
        Ok(format!("{scheme}://{host}{path}?{query}"))
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

/// Extracts `<Contents>` entries from a `ListObjectsV2` XML body as
/// `(Key, last_modified_unix)`. Deliberately a tiny, dependency-free tag
/// scanner rather than a full XML parser: the S3 `ListObjectsV2` shape is
/// fixed and shallow, and every other externally-facing adapter here parses
/// only the fields it needs. An entry missing/holding an unparseable
/// `LastModified` gets `0`, which the GC planner treats as unknown-age =>
/// KEEP (fail-safe).
fn parse_list_objects_v2(xml: &str) -> Vec<ferrogate_storage::BucketObject> {
    let mut objects = Vec::new();
    for contents in extract_tags(xml, "Contents") {
        let Some(key) = extract_tag(&contents, "Key") else {
            continue;
        };
        let last_modified_unix = extract_tag(&contents, "LastModified")
            .and_then(|value| parse_rfc3339_unix(&value))
            .unwrap_or(0);
        objects.push(ferrogate_storage::BucketObject {
            key,
            last_modified_unix,
        });
    }
    objects
}

/// The truncation continuation token, present only when the listing is paged.
fn next_continuation_token(xml: &str) -> Option<String> {
    let truncated = extract_tag(xml, "IsTruncated")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !truncated {
        return None;
    }
    extract_tag(xml, "NextContinuationToken").filter(|token| !token.is_empty())
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml_unescape(&xml[start..end]))
}

fn extract_tags(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(rel_start) = xml[cursor..].find(&open) {
        let start = cursor + rel_start + open.len();
        let Some(rel_end) = xml[start..].find(&close) else {
            break;
        };
        let end = start + rel_end;
        out.push(xml[start..end].to_string());
        cursor = end + close.len();
    }
    out
}

fn xml_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

/// Parses an S3 `LastModified` RFC3339/ISO-8601 timestamp to unix seconds.
fn parse_rfc3339_unix(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value.trim())
        .ok()
        .map(|datetime| datetime.timestamp())
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
    fn presign_put_builds_a_path_style_sigv4_query_string_url_with_a_bounded_ttl() {
        let bucket = client("https://project.supabase.co/storage/v1/s3".into());
        let url = bucket
            .presign_put("tenant-a:cli_tool:hello:1.0.0", 900, 1_440_938_160)
            .unwrap();

        // Path-style URL against the configured endpoint host + bucket/key.
        assert!(url.starts_with(
            "https://project.supabase.co/storage/v1/s3/ferrogate-assets/tenant-a:cli_tool:hello:1.0.0?"
        ));
        // SigV4 query-string presign markers, bounded TTL, and a signature.
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains("X-Amz-SignedHeaders=host"));
        assert!(url.contains("X-Amz-Signature="));
        // The secret key never leaks into the URL.
        assert!(!url.contains("wJalrXUtnFEMI"));
    }

    #[test]
    fn presign_get_and_presign_put_sign_the_same_key_differently() {
        let bucket = client("http://127.0.0.1:9999".into());
        let put = bucket.presign_put("k", 300, 1_440_938_160).unwrap();
        let get = bucket.presign_get("k", 300, 1_440_938_160).unwrap();
        assert!(put.starts_with("http://127.0.0.1:9999/ferrogate-assets/k?"));
        let put_sig = put.rsplit("X-Amz-Signature=").next().unwrap();
        let get_sig = get.rsplit("X-Amz-Signature=").next().unwrap();
        assert_ne!(
            put_sig, get_sig,
            "PUT and GET presigns of the same key must differ (method is signed)"
        );
    }

    #[tokio::test]
    async fn head_object_returns_the_content_length() {
        let (endpoint, captured) = spawn_bucket_mock("200 OK", b"");
        let bucket = client(endpoint);

        let size = bucket
            .head_object("tenant-a:cli_tool:hello:1.0.0")
            .await
            .unwrap();
        // The mock echoes the request body length as Content-Length (0 here).
        assert_eq!(size, Some(0));
        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "HEAD");
        assert!(request.has_authorization);
    }

    #[tokio::test]
    async fn head_object_returns_none_on_404() {
        let (endpoint, _captured) = spawn_bucket_mock("404 Not Found", b"");
        let bucket = client(endpoint);
        let size = bucket
            .head_object("tenant-a:cli_tool:missing:1.0.0")
            .await
            .unwrap();
        assert_eq!(size, None);
    }

    #[tokio::test]
    async fn list_objects_parses_signed_list_v2_contents() {
        // #263: a ListObjectsV2 XML body maps to (key, last_modified_unix)
        // pairs; the request is a signed GET carrying the list-type=2 query.
        let xml = "<?xml version=\"1.0\"?><ListBucketResult>\
            <IsTruncated>false</IsTruncated>\
            <Contents><Key>t1:cli_tool:rg:1.0.0</Key>\
            <LastModified>2026-07-19T12:00:00.000Z</LastModified></Contents>\
            <Contents><Key>t1:cli_tool:orphan:9.9.9</Key>\
            <LastModified>2020-01-01T00:00:00Z</LastModified></Contents>\
            </ListBucketResult>";
        let (endpoint, captured) = spawn_bucket_mock("200 OK", xml.as_bytes());
        let bucket = client(endpoint);

        let objects = bucket.list_objects().await.unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].key, "t1:cli_tool:rg:1.0.0");
        assert_eq!(objects[0].last_modified_unix, 1_784_462_400);
        assert_eq!(objects[1].key, "t1:cli_tool:orphan:9.9.9");
        assert_eq!(objects[1].last_modified_unix, 1_577_836_800);

        let request = captured.lock().unwrap().clone().unwrap();
        assert_eq!(request.method, "GET");
        assert!(request.path.starts_with("/ferrogate-assets?"));
        assert!(request.path.contains("list-type=2"));
        assert!(request.has_authorization);
    }

    #[test]
    fn parse_list_objects_v2_defaults_unparseable_timestamps_to_zero() {
        let xml = "<Contents><Key>k</Key><LastModified>not-a-date</LastModified></Contents>";
        let objects = parse_list_objects_v2(xml);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].key, "k");
        assert_eq!(objects[0].last_modified_unix, 0);
    }

    #[test]
    fn next_continuation_token_only_when_truncated() {
        let truncated =
            "<IsTruncated>true</IsTruncated><NextContinuationToken>abc</NextContinuationToken>";
        assert_eq!(next_continuation_token(truncated), Some("abc".to_string()));
        let done =
            "<IsTruncated>false</IsTruncated><NextContinuationToken>abc</NextContinuationToken>";
        assert_eq!(next_continuation_token(done), None);
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
