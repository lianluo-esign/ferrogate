// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: End-to-end proof for the presigned asset lifecycle (#338):
// issue an upload intent through a real gateway, upload directly to a local
// SigV4-validating S3-compatible mock, commit, inspect list/manifest metadata,
// then issue a download URL and fetch the original bytes directly.

mod support;

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::Child,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::NaiveDateTime;
use ferrogate_providers::{
    presign_sigv4_query, sign_sigv4_with_content_hash_header, AwsCredentials, PresignRequest,
    SigningRequest,
};
use ferrogate_storage::sha256_hex;
use support::{http_request, start_ready_gateway};

const BUCKET: &str = "ferrogate-assets-presign-e2e";
const REGION: &str = "us-east-1";
const ACCESS_KEY_ID: &str = "AKIDPRESIGNE2E";
const SECRET_ACCESS_KEY: &str = "presign-e2e-secret-access-key";
const SECRET_ENV: &str = "FERROGATE_TEST_PRESIGN_BUCKET_SECRET";
const PRESIGN_TTL_SECS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
enum SignatureKind {
    Query,
    Header,
}

#[derive(Debug, Clone)]
struct CapturedBucketRequest {
    method: String,
    path: String,
    signature_kind: SignatureKind,
    signature_valid: bool,
}

#[derive(Debug, Default)]
struct BucketState {
    objects: HashMap<String, Vec<u8>>,
    requests: Vec<CapturedBucketRequest>,
}

struct GatewayGuard(Child);

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_sigv4_bucket_mock() -> (String, Arc<Mutex<BucketState>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(BucketState::default()));
    let server_state = Arc::clone(&state);

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            let (path, query) = request
                .target
                .split_once('?')
                .map_or((request.target.as_str(), None), |(path, query)| {
                    (path, Some(query))
                });
            let signature_kind = if query.is_some() {
                SignatureKind::Query
            } else {
                SignatureKind::Header
            };
            let signature_valid = verify_sigv4(&request, path, query).is_ok();

            let mut state = server_state.lock().unwrap();
            state.requests.push(CapturedBucketRequest {
                method: request.method.clone(),
                path: path.to_string(),
                signature_kind,
                signature_valid,
            });

            if !signature_valid {
                write_http_response(&mut stream, "403 Forbidden", b"invalid SigV4", None);
                continue;
            }

            match request.method.as_str() {
                "PUT" => {
                    state.objects.insert(path.to_string(), request.body);
                    write_http_response(&mut stream, "200 OK", b"", None);
                }
                "HEAD" => match state.objects.get(path) {
                    Some(bytes) => {
                        write_http_response(&mut stream, "200 OK", b"", Some(bytes.len()))
                    }
                    None => write_http_response(&mut stream, "404 Not Found", b"", None),
                },
                "GET" => match state.objects.get(path) {
                    Some(bytes) => write_http_response(&mut stream, "200 OK", bytes, None),
                    None => write_http_response(&mut stream, "404 Not Found", b"", None),
                },
                "DELETE" => {
                    state.objects.remove(path);
                    write_http_response(&mut stream, "204 No Content", b"", None);
                }
                _ => write_http_response(&mut stream, "405 Method Not Allowed", b"", None),
            }
        }
    });

    (endpoint, state)
}

struct RawHttpRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Option<RawHttpRequest> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(read) => read,
            Err(_) => return None,
        };
        raw.extend_from_slice(&buffer[..read]);
        if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let target = request_line.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect();
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while raw.len() < header_end + content_length {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(read) => read,
            Err(_) => return None,
        };
        raw.extend_from_slice(&buffer[..read]);
    }

    Some(RawHttpRequest {
        method,
        target,
        headers,
        body: raw[header_end..header_end + content_length].to_vec(),
    })
}

fn verify_sigv4(request: &RawHttpRequest, path: &str, query: Option<&str>) -> Result<(), String> {
    let host = request
        .headers
        .get("host")
        .ok_or_else(|| "missing Host header".to_string())?;
    let credentials = AwsCredentials {
        access_key_id: ACCESS_KEY_ID.to_string(),
        secret_access_key: SECRET_ACCESS_KEY.to_string(),
        session_token: None,
    };

    if let Some(query) = query {
        if request.headers.contains_key("authorization") {
            return Err("presigned requests must not carry Authorization".to_string());
        }
        let timestamp = raw_query_value(query, "X-Amz-Date")
            .and_then(parse_amz_timestamp)
            .ok_or_else(|| "missing or invalid X-Amz-Date".to_string())?;
        let expires_secs = raw_query_value(query, "X-Amz-Expires")
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "missing or invalid X-Amz-Expires".to_string())?;
        let expected = presign_sigv4_query(
            &PresignRequest {
                method: &request.method,
                path,
                host,
                region: REGION,
                service: "s3",
                expires_secs,
                timestamp_unix: timestamp,
            },
            &credentials,
        );
        return (query == expected)
            .then_some(())
            .ok_or_else(|| "query signature mismatch".to_string());
    }

    let timestamp = request
        .headers
        .get("x-amz-date")
        .and_then(|value| parse_amz_timestamp(value))
        .ok_or_else(|| "missing or invalid x-amz-date".to_string())?;
    let expected = sign_sigv4_with_content_hash_header(
        &SigningRequest {
            method: &request.method,
            path,
            host,
            region: REGION,
            service: "s3",
            body: &request.body,
            timestamp_unix: timestamp,
        },
        &credentials,
    );
    let authorization_matches =
        request.headers.get("authorization") == Some(&expected.authorization);
    let hash_matches =
        request.headers.get("x-amz-content-sha256") == expected.x_amz_content_sha256.as_ref();
    (authorization_matches && hash_matches)
        .then_some(())
        .ok_or_else(|| "header signature mismatch".to_string())
}

fn raw_query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

fn parse_amz_timestamp(value: &str) -> Option<u64> {
    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
        .ok()?
        .and_utc()
        .timestamp()
        .try_into()
        .ok()
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    content_length_override: Option<usize>,
) {
    let content_length = content_length_override.unwrap_or(body.len());
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn direct_bucket_request(method: &str, url: &str, body: &[u8]) -> Vec<u8> {
    let authority_and_target = url
        .strip_prefix("http://")
        .expect("the local bucket URL must use http");
    let (authority, target) = authority_and_target
        .split_once('/')
        .expect("presigned URL must have an object path");
    let target = format!("/{target}");
    let mut stream = TcpStream::connect(authority).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn raw_response_body(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(&[], |position| &response[position + 4..])
}

fn write_config(path: &std::path::Path, gateway_addr: &str, bucket_endpoint: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[asset_bucket]
enabled = true
endpoint = "{bucket_endpoint}"
bucket = "{BUCKET}"
region = "{REGION}"
access_key_id = "{ACCESS_KEY_ID}"
secret_access_key_env = "{SECRET_ENV}"
presign_ttl_secs = {PRESIGN_TTL_SECS}
presign_max_object_bytes = 1048576

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "tenant-presign-e2e"

[[api_keys]]
id = "asset-reader"
name = "Asset reader"
key = "asset-reader-secret"
scopes = ["assets.read"]
organization_id = "tenant-presign-e2e"

[[api_keys]]
id = "asset-writer"
name = "Asset writer"
key = "asset-writer-secret"
scopes = ["assets.write"]
organization_id = "tenant-presign-e2e"
"#
        ),
    )
    .unwrap();
}

fn response_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("invalid JSON body: {error}\n{response}"))
}

fn assert_status(response: &str, status: u16) {
    let status_line = response.lines().next().unwrap_or_default();
    assert!(
        status_line.contains(&status.to_string()),
        "expected HTTP {status}, got: {response}"
    );
}

fn assert_json_error(response: &str, status: u16, code: &str) {
    assert_status(response, status);
    let body = response_json(response);
    assert_eq!(body["error"]["code"], code, "unexpected error: {body}");
    assert!(
        body["error"]["message"].is_string(),
        "typed errors must carry a message: {body}"
    );
    assert!(
        body["error"]["request_id"].is_string(),
        "typed errors must carry request_id: {body}"
    );
}

fn assert_no_bucket_location_fields(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for forbidden in ["storage_uri", "bucket", "key", "upload_url", "download_url"] {
                assert!(
                    !object.contains_key(forbidden),
                    "registry response leaked bucket-only field {forbidden}: {value}"
                );
            }
            for child in object.values() {
                assert_no_bucket_location_fields(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                assert_no_bucket_location_fields(child);
            }
        }
        _ => {}
    }
}

fn bucket_mutation_count(state: &Arc<Mutex<BucketState>>) -> usize {
    state
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|request| matches!(request.method.as_str(), "PUT" | "DELETE"))
        .count()
}

#[test]
fn presigned_asset_lifecycle_closes_through_typed_registry_and_direct_download() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, bucket_state) = spawn_sigv4_bucket_mock();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (gateway, gateway_addr) = start_ready_gateway(&config_path, |gateway_addr| {
        write_config(&config_path, gateway_addr, &bucket_endpoint);
    });
    let _gateway = GatewayGuard(gateway);
    support::wait_for_gateway(&gateway_addr);

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"tenant-presign-e2e","name":"Presign E2E","slug":"presign-e2e"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    let invalid_intent = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        r#"{"size_bytes":0,"sha256":"not-a-sha256"}"#,
    );
    assert_json_error(&invalid_intent, 400, "invalid_upload_intent");

    let content = b"#!/bin/sh\necho presigned asset lifecycle\n";
    let sha256 = sha256_hex(content);
    let intent_body = format!(r#"{{"size_bytes":{},"sha256":"{sha256}"}}"#, content.len());
    let read_only_intent = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-reader-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    );
    assert_json_error(&read_only_intent, 403, "scope_denied");

    let intent_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    );
    assert_status(&intent_response, 200);
    let intent = response_json(&intent_response);
    assert_eq!(intent["object"], "asset_upload_intent");
    assert_eq!(intent["method"], "PUT");
    assert_eq!(intent["expires_in_seconds"], PRESIGN_TTL_SECS);
    assert_eq!(intent["size_bytes"], content.len() as u64);
    assert_eq!(intent["sha256"], sha256);
    let object_key = intent["key"]
        .as_str()
        .expect("upload intent must identify its opaque asset key")
        .to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload intent must include upload_url");
    assert!(upload_url.starts_with(&bucket_endpoint));

    let upload = direct_bucket_request("PUT", upload_url, content);
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct upload failed: {}",
        String::from_utf8_lossy(&upload)
    );

    let commit_body = format!(
        r#"{{"size_bytes":{},"sha256":"{sha256}","content_type":"application/x-shellscript"}}"#,
        content.len()
    );
    let commit_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_status(&commit_response, 200);
    let committed = response_json(&commit_response);
    assert_eq!(committed["object"], "asset");
    let asset = &committed["asset"];
    assert_eq!(asset["asset_type"], "cli_tool");
    assert_eq!(asset["name"], "large-tool");
    assert_eq!(asset["version"], "1.2.3");
    assert_eq!(asset["content_type"], "application/x-shellscript");
    assert_eq!(asset["content_hash"], sha256);
    assert_eq!(asset["size_bytes"], content.len() as u64);
    assert_eq!(asset["storage_backed"], true);
    assert!(asset["created_at_unix"].is_i64());
    assert!(asset["updated_at_unix"].is_i64());

    let mutations_before_retry = bucket_mutation_count(&bucket_state);
    let repeated_commit_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_status(&repeated_commit_response, 200);
    let repeated_commit = response_json(&repeated_commit_response);
    assert_eq!(
        repeated_commit, committed,
        "an idempotent commit retry must return identical metadata, including updated_at_unix"
    );
    assert_eq!(
        bucket_mutation_count(&bucket_state),
        mutations_before_retry,
        "an idempotent commit retry must not mutate the bucket"
    );

    let list_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&list_response, 200);
    let list = response_json(&list_response);
    assert_eq!(list["object"], "list");
    let listed = list["data"]
        .as_array()
        .expect("asset list data must be an array");
    assert_eq!(listed.len(), 1, "unexpected asset list: {list}");
    assert_eq!(listed[0]["id"], object_key);
    assert_eq!(listed[0]["storage_backed"], true);
    assert_eq!(listed[0]["content_hash"], sha256);
    assert_no_bucket_location_fields(&list);

    let manifest_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/large-tool/manifest",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&manifest_response, 200);
    let manifest = response_json(&manifest_response);
    assert_eq!(manifest["object"], "asset_manifest");
    assert_eq!(manifest["asset_type"], "cli_tool");
    assert_eq!(manifest["name"], "large-tool");
    assert_eq!(manifest["channels"].as_array().unwrap().len(), 0);
    let versions = manifest["versions"]
        .as_array()
        .expect("manifest versions must be an array");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["version"], "1.2.3");
    assert_eq!(versions[0]["yanked"], false);
    let variants = versions[0]["variants"]
        .as_array()
        .expect("manifest variants must be an array");
    assert_eq!(variants.len(), 1);
    assert_eq!(variants[0]["variant"], "");
    assert_eq!(variants[0]["content_type"], "application/x-shellscript");
    assert_eq!(variants[0]["content_hash"], sha256);
    assert_eq!(variants[0]["size_bytes"], content.len() as u64);
    assert_eq!(variants[0]["storage_backed"], true);
    assert_no_bucket_location_fields(&manifest);

    let write_only_download = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/presign/download/cli_tool/large-tool/1.2.3",
        &["Authorization: Bearer asset-writer-secret"],
        "",
    );
    assert_json_error(&write_only_download, 403, "scope_denied");

    let download_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/presign/download/cli_tool/large-tool/1.2.3",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&download_response, 200);
    let download = response_json(&download_response);
    assert_eq!(download["object"], "asset_download_url");
    assert_eq!(download["method"], "GET");
    assert_eq!(download["expires_in_seconds"], PRESIGN_TTL_SECS);
    assert_eq!(download["sha256"], sha256);
    assert_eq!(download["size_bytes"], content.len() as u64);
    assert_eq!(download["content_type"], "application/x-shellscript");
    let download_url = download["download_url"]
        .as_str()
        .expect("download response must include download_url");
    let direct_download = direct_bucket_request("GET", download_url, b"");
    assert!(
        String::from_utf8_lossy(&direct_download).contains("HTTP/1.1 200"),
        "direct download failed: {}",
        String::from_utf8_lossy(&direct_download)
    );
    assert_eq!(raw_response_body(&direct_download), content);

    let yank_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/large-tool/1.2.3/yank",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&yank_response, 200);
    let yanked_list_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    let yanked_list = response_json(&yanked_list_response);
    assert_eq!(yanked_list["data"][0]["id"], object_key);
    assert_eq!(yanked_list["data"][0]["storage_backed"], true);
    assert_no_bucket_location_fields(&yanked_list);

    let yanked_manifest_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/large-tool/manifest",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    let yanked_manifest = response_json(&yanked_manifest_response);
    assert_eq!(yanked_manifest["versions"][0]["yanked"], true);
    assert_eq!(yanked_manifest["versions"][0]["variants"][0]["variant"], "");
    assert_no_bucket_location_fields(&yanked_manifest);

    let immutable_intent = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    );
    assert_json_error(&immutable_intent, 409, "asset_version_immutable");

    let bucket = bucket_state.lock().unwrap();
    assert!(
        bucket
            .requests
            .iter()
            .all(|request| request.signature_valid),
        "every direct and gateway bucket operation must carry a valid SigV4 signature: {:?}",
        bucket.requests
    );
    assert!(
        bucket.requests.iter().any(|request| {
            request.method == "PUT" && request.signature_kind == SignatureKind::Query
        }),
        "the object must be uploaded via a query-presigned PUT: {:?}",
        bucket.requests
    );
    assert!(
        bucket.requests.iter().any(|request| {
            request.method == "HEAD" && request.signature_kind == SignatureKind::Header
        }) && bucket.requests.iter().any(|request| {
            request.method == "GET" && request.signature_kind == SignatureKind::Header
        }),
        "commit must verify the object with header-signed HEAD + GET: {:?}",
        bucket.requests
    );
    assert!(
        bucket.requests.iter().any(|request| {
            request.method == "GET" && request.signature_kind == SignatureKind::Query
        }),
        "the object must be downloaded via a query-presigned GET: {:?}",
        bucket.requests
    );
    assert!(
        bucket
            .requests
            .iter()
            .all(|request| request.path.starts_with(&format!("/{BUCKET}/"))),
        "all bucket requests must stay inside the configured bucket: {:?}",
        bucket.requests
    );
    assert_eq!(
        bucket
            .requests
            .iter()
            .filter(|request| matches!(request.method.as_str(), "PUT" | "DELETE"))
            .count(),
        1,
        "the successful lifecycle performs one direct upload and no bucket deletes"
    );
    drop(bucket);
}
