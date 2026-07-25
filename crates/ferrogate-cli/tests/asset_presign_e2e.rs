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
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

use chrono::NaiveDateTime;
use ferrogate_providers::{
    presign_sigv4_query, presign_sigv4_query_bound, sign_sigv4_with_content_hash_header,
    AwsCredentials, PresignBoundPayload, PresignRequest, SigningRequest,
};
use ferrogate_storage::sha256_hex;
use support::{http_request, start_ready_gateway};

const BUCKET: &str = "ferrogate-assets-presign-e2e";
const REGION: &str = "us-east-1";
const ACCESS_KEY_ID: &str = "AKIDPRESIGNE2E";
const SECRET_ACCESS_KEY: &str = "presign-e2e-secret-access-key";
const SECRET_ENV: &str = "FERROGATE_TEST_PRESIGN_BUCKET_SECRET";
const PRESIGN_TTL_SECS: u64 = 120;
/// The canonical EICAR anti-malware test signature. `screen_asset_push`
/// fast-rejects any content embedding it (`asset_scan::contains_eicar`),
/// independent of the pluggable scanner backend, so it is the deterministic
/// "malware is detected and rejected" payload for a docker-free E2E.
const EICAR_PAYLOAD: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

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
    race_gate: Option<Arc<CommitRaceGate>>,
}

#[derive(Debug)]
struct CommitRaceGate {
    block_next_head: AtomicBool,
    signal_next_delete: AtomicBool,
    first_head_arrived: Mutex<Option<mpsc::Sender<()>>>,
    release_first_head: Mutex<mpsc::Receiver<()>>,
    staging_deleted: Mutex<Option<mpsc::Sender<()>>>,
}

impl CommitRaceGate {
    fn new() -> (
        Arc<Self>,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
        mpsc::Receiver<()>,
    ) {
        let (first_head_arrived_tx, first_head_arrived_rx) = mpsc::channel();
        let (release_first_head_tx, release_first_head_rx) = mpsc::channel();
        let (staging_deleted_tx, staging_deleted_rx) = mpsc::channel();
        (
            Arc::new(Self {
                block_next_head: AtomicBool::new(true),
                signal_next_delete: AtomicBool::new(true),
                first_head_arrived: Mutex::new(Some(first_head_arrived_tx)),
                release_first_head: Mutex::new(release_first_head_rx),
                staging_deleted: Mutex::new(Some(staging_deleted_tx)),
            }),
            first_head_arrived_rx,
            release_first_head_tx,
            staging_deleted_rx,
        )
    }
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
            let Ok(stream) = stream else { break };
            let connection_state = Arc::clone(&server_state);
            std::thread::spawn(move || handle_bucket_connection(stream, connection_state));
        }
    });

    (endpoint, state)
}

fn handle_bucket_connection(mut stream: TcpStream, server_state: Arc<Mutex<BucketState>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let Some(request) = read_http_request(&mut stream) else {
        return;
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

    let race_gate = server_state.lock().unwrap().race_gate.clone();
    if signature_valid && request.method == "HEAD" {
        if let Some(gate) = race_gate
            .as_ref()
            .filter(|gate| gate.block_next_head.swap(false, Ordering::AcqRel))
        {
            gate.first_head_arrived
                .lock()
                .unwrap()
                .take()
                .expect("first HEAD signal")
                .send(())
                .expect("report blocked first HEAD");
            gate.release_first_head
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .expect("release blocked first HEAD");
        }
    }

    let mut state = server_state.lock().unwrap();
    state.requests.push(CapturedBucketRequest {
        method: request.method.clone(),
        path: path.to_string(),
        signature_kind,
        signature_valid,
    });

    if !signature_valid {
        write_http_response(&mut stream, "403 Forbidden", b"invalid SigV4", None);
        return;
    }

    match request.method.as_str() {
        "PUT" => {
            state.objects.insert(path.to_string(), request.body);
            write_http_response(&mut stream, "200 OK", b"", None);
        }
        "HEAD" => match state.objects.get(path) {
            Some(bytes) => write_http_response(&mut stream, "200 OK", b"", Some(bytes.len())),
            None => write_http_response(&mut stream, "404 Not Found", b"", None),
        },
        "GET" => match state.objects.get(path) {
            Some(bytes) => write_http_response(&mut stream, "200 OK", bytes, None),
            None => write_http_response(&mut stream, "404 Not Found", b"", None),
        },
        "DELETE" => {
            state.objects.remove(path);
            let delete_gate = state.race_gate.as_ref().and_then(|gate| {
                gate.signal_next_delete
                    .swap(false, Ordering::AcqRel)
                    .then(|| Arc::clone(gate))
            });
            write_http_response(&mut stream, "204 No Content", b"", None);
            drop(state);
            if let Some(gate) = delete_gate {
                gate.staging_deleted
                    .lock()
                    .unwrap()
                    .take()
                    .expect("staging delete signal")
                    .send(())
                    .expect("report staging deletion");
            }
        }
        _ => write_http_response(&mut stream, "405 Method Not Allowed", b"", None),
    }
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
        let presign_request = PresignRequest {
            method: &request.method,
            path,
            host,
            region: REGION,
            service: "s3",
            expires_secs,
            timestamp_unix: timestamp,
        };
        let signed_headers = raw_query_value(query, "X-Amz-SignedHeaders")
            .ok_or_else(|| "missing X-Amz-SignedHeaders".to_string())?;
        let expected = match signed_headers {
            // #368: a bound upload URL. The bucket recomputes the signature
            // over the headers the client ACTUALLY sent, and (like AWS S3
            // for a concrete x-amz-content-sha256) verifies the received
            // bytes against the declared hash + length. A request that
            // omits a signed header, lies about size/checksum, or carries
            // different bytes therefore never verifies.
            "content-length%3Bhost%3Bx-amz-content-sha256" => {
                let declared_length = request
                    .headers
                    .get("content-length")
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| "bound upload missing content-length".to_string())?;
                let declared_sha256 = request
                    .headers
                    .get("x-amz-content-sha256")
                    .ok_or_else(|| "bound upload missing x-amz-content-sha256".to_string())?;
                if request.body.len() as u64 != declared_length {
                    return Err("bound upload body length mismatch".to_string());
                }
                if sha256_hex(&request.body) != *declared_sha256 {
                    return Err("bound upload payload hash mismatch".to_string());
                }
                presign_sigv4_query_bound(
                    &presign_request,
                    &credentials,
                    &PresignBoundPayload {
                        content_length: declared_length,
                        content_sha256_hex: declared_sha256,
                    },
                )
                .query
            }
            "host" => presign_sigv4_query(&presign_request, &credentials),
            other => return Err(format!("unexpected X-Amz-SignedHeaders: {other}")),
        };
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

/// Issues a raw direct-to-bucket request. `extra_headers` carries the
/// intent's `required_headers` (#368) minus `content-length`, which this
/// helper always derives from the actual body -- exactly like a real HTTP
/// client, so a tampered body automatically declares its own length.
fn direct_bucket_request(
    method: &str,
    url: &str,
    body: &[u8],
    extra_headers: &[(&str, &str)],
) -> Vec<u8> {
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
    let extra = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",
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

fn object_path_from_url(url: &str) -> String {
    let authority_and_target = url
        .strip_prefix("http://")
        .expect("the local bucket URL must use http");
    let (_, target) = authority_and_target
        .split_once('/')
        .expect("presigned URL must have an object path");
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    format!("/{path}")
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

fn status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn error_code(response: &str) -> String {
    response_json(response)["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
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
        .expect("upload intent must identify its logical asset key")
        .to_string();
    let upload_id = intent["upload_id"]
        .as_str()
        .expect("upload intent must include upload_id")
        .to_string();
    assert_eq!(upload_id.len(), 36);
    assert!(upload_id.starts_with("upl_"));
    assert!(upload_id[4..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload intent must include upload_url")
        .to_string();
    assert!(upload_url.starts_with(&bucket_endpoint));
    // #368: the intent returns the exact signed headers the direct PUT must
    // send, and echoes the per-object ceiling it was checked against.
    assert_eq!(
        intent["required_headers"]["content-length"],
        content.len().to_string()
    );
    assert_eq!(intent["required_headers"]["x-amz-content-sha256"], sha256);
    assert_eq!(
        intent["required_headers"]
            .as_object()
            .expect("required_headers must be a map")
            .len(),
        2
    );
    assert_eq!(intent["max_object_bytes"], 1_048_576);
    assert!(upload_url.contains("X-Amz-SignedHeaders=content-length%3Bhost%3Bx-amz-content-sha256"));
    let staging_path = object_path_from_url(&upload_url);

    let second_intent_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    );
    assert_status(&second_intent_response, 200);
    let second_intent = response_json(&second_intent_response);
    let second_upload_id = second_intent["upload_id"]
        .as_str()
        .expect("second intent must include upload_id")
        .to_string();
    let second_upload_url = second_intent["upload_url"]
        .as_str()
        .expect("second intent must include upload_url")
        .to_string();
    assert_eq!(second_intent["key"], object_key);
    assert_ne!(second_upload_id, upload_id);
    assert_ne!(second_upload_url, upload_url);
    let second_staging_path = object_path_from_url(&second_upload_url);
    assert_ne!(second_staging_path, staging_path);

    // #368: a direct PUT that omits the signed checksum header is rejected
    // at the bucket boundary -- the SigV4 signature covers it.
    let required_put_headers = [("x-amz-content-sha256", sha256.as_str())];
    let missing_header_upload = direct_bucket_request("PUT", &upload_url, content, &[]);
    assert!(
        String::from_utf8_lossy(&missing_header_upload).contains("HTTP/1.1 403"),
        "an upload omitting the signed checksum header must be rejected: {}",
        String::from_utf8_lossy(&missing_header_upload)
    );

    let upload = direct_bucket_request("PUT", &upload_url, content, &required_put_headers);
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    let second_upload =
        direct_bucket_request("PUT", &second_upload_url, content, &required_put_headers);
    assert!(
        String::from_utf8_lossy(&second_upload).contains("HTTP/1.1 200"),
        "second direct upload failed: {}",
        String::from_utf8_lossy(&second_upload)
    );

    let commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"application/x-shellscript"}}"#,
        content.len()
    );
    let (race_gate, first_head_arrived, release_first_head, staging_deleted) =
        CommitRaceGate::new();
    bucket_state.lock().unwrap().race_gate = Some(Arc::clone(&race_gate));

    // The first request reads no metadata and then blocks at bucket HEAD. The
    // second identical request publishes and deletes staging; only then does
    // the first resume and observe 404. Its post-failure metadata reconcile
    // must return the durable winner instead of a stale 404/503.
    let late_gateway_addr = gateway_addr.clone();
    let late_commit_body = commit_body.clone();
    let late_commit = std::thread::spawn(move || {
        http_request(
            &late_gateway_addr,
            "POST",
            "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
            &[
                "Authorization: Bearer asset-secret",
                "Content-Type: application/json",
            ],
            &late_commit_body,
        )
    });
    first_head_arrived
        .recv_timeout(Duration::from_secs(5))
        .expect("first commit did not block at HEAD");

    let winner_gateway_addr = gateway_addr.clone();
    let winner_commit_body = commit_body.clone();
    let winner_commit = std::thread::spawn(move || {
        http_request(
            &winner_gateway_addr,
            "POST",
            "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
            &[
                "Authorization: Bearer asset-secret",
                "Content-Type: application/json",
            ],
            &winner_commit_body,
        )
    });
    staging_deleted
        .recv_timeout(Duration::from_secs(5))
        .expect("winning commit did not delete staging");
    release_first_head
        .send(())
        .expect("release late commit HEAD");

    let winner_commit_response = winner_commit.join().expect("winning commit request");
    let late_commit_response = late_commit.join().expect("late commit request");
    bucket_state.lock().unwrap().race_gate = None;
    assert_status(&winner_commit_response, 200);
    assert_status(&late_commit_response, 200);
    let committed = response_json(&winner_commit_response);
    assert_eq!(
        response_json(&late_commit_response),
        committed,
        "the late identical commit must reconcile to the exact durable winner"
    );
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

    let final_path = {
        let bucket = bucket_state.lock().unwrap();
        let final_path = bucket
            .requests
            .iter()
            .find(|request| {
                request.method == "PUT" && request.signature_kind == SignatureKind::Header
            })
            .expect("commit must copy verified bytes with a header-signed PUT")
            .path
            .clone();
        assert_ne!(final_path, staging_path);
        assert!(!upload_url.contains(&final_path));
        assert!(!second_upload_url.contains(&final_path));
        assert_eq!(
            bucket.objects.get(&final_path).map(Vec::as_slice),
            Some(content.as_slice())
        );
        final_path
    };

    // #368: replaying the still-unexpired PUT URL with different bytes is
    // now rejected AT THE BUCKET -- the signature binds the declared
    // checksum and length, so the old capability cannot even recreate its
    // staging object with new content, let alone burn bucket capacity.
    let tampered = b"tampered after commit through the still-valid old PUT URL";
    let replay = direct_bucket_request("PUT", &upload_url, tampered, &required_put_headers);
    assert!(
        String::from_utf8_lossy(&replay).contains("HTTP/1.1 403"),
        "a replayed PUT with different bytes must be rejected by the bucket: {}",
        String::from_utf8_lossy(&replay)
    );
    {
        let bucket = bucket_state.lock().unwrap();
        assert!(
            !bucket.objects.contains_key(&staging_path),
            "a rejected replay must not recreate the staging object"
        );
        assert_eq!(
            bucket.objects.get(&final_path).map(Vec::as_slice),
            Some(content.as_slice()),
            "a replayed upload must not replace the immutable final object"
        );
    }

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

    let other_intent_commit_body = format!(
        r#"{{"upload_id":"{second_upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"application/x-shellscript"}}"#,
        content.len()
    );
    let other_intent_commit = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &other_intent_commit_body,
    );
    assert_json_error(&other_intent_commit, 409, "asset_version_immutable");
    let mutations_after_loser_cleanup = bucket_mutation_count(&bucket_state);
    assert_eq!(
        mutations_after_loser_cleanup,
        mutations_before_retry + 1,
        "a definitive different-upload conflict must delete only its staging object"
    );
    {
        let bucket = bucket_state.lock().unwrap();
        assert!(!bucket.objects.contains_key(&second_staging_path));
        assert!(bucket
            .requests
            .iter()
            .any(|request| { request.method == "DELETE" && request.path == second_staging_path }));
        assert_eq!(
            bucket.objects.get(&final_path).map(Vec::as_slice),
            Some(content.as_slice()),
            "loser cleanup must not touch the winner's immutable final object"
        );
    }

    let mismatched_sha256 = sha256_hex(tampered);
    let mismatched_commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{mismatched_sha256}","content_type":"application/x-shellscript"}}"#,
        tampered.len()
    );
    let mismatched_commit = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/large-tool/1.2.3",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &mismatched_commit_body,
    );
    assert_json_error(&mismatched_commit, 409, "asset_version_immutable");
    assert_eq!(
        bucket_mutation_count(&bucket_state),
        mutations_after_loser_cleanup,
        "same-upload metadata mismatches must not mutate staging or final objects"
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
    assert_eq!(object_path_from_url(download_url), final_path);
    assert_ne!(object_path_from_url(download_url), staging_path);
    let direct_download = direct_bucket_request("GET", download_url, b"", &[]);
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
    // #368: the ONLY signature-invalid requests are the two deliberately
    // out-of-contract direct PUTs (omitted signed header, tampered bytes);
    // both were rejected at the bucket boundary against the staging key.
    let invalid: Vec<_> = bucket
        .requests
        .iter()
        .filter(|request| !request.signature_valid)
        .collect();
    assert_eq!(
        invalid.len(),
        2,
        "exactly the two out-of-contract PUTs must fail verification: {:?}",
        bucket.requests
    );
    assert!(
        invalid.iter().all(|request| {
            request.method == "PUT"
                && request.path == staging_path
                && request.signature_kind == SignatureKind::Query
        }),
        "both rejected requests must be query-presigned staging PUTs: {invalid:?}"
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
            request.method == "PUT"
                && request.signature_kind == SignatureKind::Header
                && request.path == final_path
        }),
        "commit must copy verified bytes to a private header-signed final PUT: {:?}",
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
        7,
        "lifecycle mutation attempts: rejected header-less PUT, two staging uploads, final PUT, winner cleanup, rejected tampered replay, and loser cleanup"
    );
    assert_eq!(
        bucket.objects.get(&final_path).map(Vec::as_slice),
        Some(content.as_slice())
    );
    // #368: the rejected replay left no staging bytes behind -- the bucket
    // ends the lifecycle holding exactly the immutable final object.
    assert!(!bucket.objects.contains_key(&staging_path));
    assert!(!bucket.objects.contains_key(&second_staging_path));
    assert_eq!(bucket.objects.len(), 1);
    drop(bucket);
}

/// #366 content-rule parity: inline and presigned publication reach the SAME
/// typed decision for malicious content. The built-in EICAR check lives in
/// `validate_asset_content`, which both the inline push and the presigned
/// commit run, so this pins that the two transports never diverge on a
/// content-policy rejection -- the SAME EICAR payload is refused with the
/// byte-for-byte SAME 422 `asset_rejected` on BOTH paths, the presigned
/// rejection fails closed (staging deleted, no durable row), and it is audited
/// as `rejected_commit`.
///
/// NOTE: the content check pre-dates #366 on the presigned path (#368 commit
/// verification also runs `validate_asset_content`); the control-plane gates
/// that #366 specifically added to the presigned path -- signature requirement,
/// cross-tenant publish approval, pluggable scanner -- are isolated separately
/// in `inline_and_presigned_publication_apply_identical_cross_tenant_gate`.
#[test]
fn inline_and_presigned_publication_apply_identical_eicar_screening() {
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

    let sha256 = sha256_hex(EICAR_PAYLOAD.as_bytes());

    // (A) The inline PUT path refuses EICAR before anything is durably written.
    // `text/plain` is an allowed cli_tool content-type, so the rejection is the
    // malware gate, not the content-type allowlist.
    let inline = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/eicar-inline/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        EICAR_PAYLOAD,
    );
    assert_json_error(&inline, 422, "asset_rejected");
    let inline_decision = (status_code(&inline), error_code(&inline));

    // (B) The presigned path stages the identical bytes directly at the bucket
    // (which performs NO content screening) and then commits. The commit is the
    // only place trust screening can run for this path -- it must run there and
    // reach the same decision the inline push did.
    let intent_body = format!(
        r#"{{"size_bytes":{},"sha256":"{sha256}"}}"#,
        EICAR_PAYLOAD.len()
    );
    let intent = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/eicar-presign/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    ));
    let upload_id = intent["upload_id"]
        .as_str()
        .expect("upload intent must include upload_id")
        .to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload intent must include upload_url")
        .to_string();
    let staging_path = object_path_from_url(&upload_url);

    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        EICAR_PAYLOAD.as_bytes(),
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    assert_eq!(
        bucket_state
            .lock()
            .unwrap()
            .objects
            .get(&staging_path)
            .map(Vec::as_slice),
        Some(EICAR_PAYLOAD.as_bytes()),
        "the EICAR bytes must be staged at the bucket before commit screening runs"
    );

    let commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"text/plain"}}"#,
        EICAR_PAYLOAD.len()
    );
    let presigned = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/eicar-presign/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_json_error(&presigned, 422, "asset_rejected");

    // The core parity proof: both publication paths produced the identical
    // typed decision for identical malicious bytes.
    assert_eq!(
        (status_code(&presigned), error_code(&presigned)),
        inline_decision,
        "the presigned commit must reach the SAME screening decision as the inline push"
    );

    // Fail-closed at the bucket: the rejected commit deleted its staging object
    // and never wrote a final object -- staging was the only object, now gone.
    {
        let bucket = bucket_state.lock().unwrap();
        assert!(
            !bucket.objects.contains_key(&staging_path),
            "a rejected commit must delete the staging object: {:?}",
            bucket.requests
        );
        assert!(
            bucket
                .requests
                .iter()
                .any(|request| { request.method == "DELETE" && request.path == staging_path }),
            "a rejected commit must issue a staging DELETE: {:?}",
            bucket.requests
        );
        assert!(
            bucket.objects.is_empty(),
            "a rejected commit must leave no durable object behind: {:?}",
            bucket.objects.keys().collect::<Vec<_>>()
        );
    }

    // Fail-closed in the registry: neither the inline nor the presigned EICAR
    // push created an asset row.
    let list = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(
        list["data"].as_array().map(Vec::len),
        Some(0),
        "a screened-out EICAR push on either path must create no asset row: {list}"
    );

    // The presigned rejection is audited as `rejected_commit` on `asset.push`
    // (the inline path fails before the durable step, so only the presigned
    // path records this specific outcome).
    let audit = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit["data"]
        .as_array()
        .expect("audit-events must return a data array");
    assert!(
        events.iter().any(|event| {
            event["action"] == "asset.push" && event["outcome"] == "rejected_commit"
        }),
        "a rejected presigned commit must record a rejected_commit audit event: {audit}"
    );
}

/// #366 control-plane parity (the bypass #366 actually closes): the presigned
/// commit must apply the cross-tenant publish approval gate that the inline
/// `PUT /v1/assets` path applies. This gate is a #366 addition to the presigned
/// path -- before #366 the commit re-checked only size/SHA-256 + built-in
/// content validation, so a cross-tenant (`public`/`shared`) publish with NO
/// durable approval that the inline path refuses with 403
/// `cross_tenant_publish_denied` could be laundered in through presign+commit
/// and published tenant-wide. Unlike the EICAR content rule (also enforced by
/// #368 commit verification), this gate is reachable ONLY through
/// `screen_asset_push`, so it isolates the #366 fix. The content here is benign
/// -- the rejection is purely the approval gate -- and it is request-scoped
/// (visibility header / commit field), so it needs no process-global env and is
/// safe under parallel test execution.
#[test]
fn inline_and_presigned_publication_apply_identical_cross_tenant_gate() {
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

    let content = b"#!/bin/sh\necho cross-tenant publish parity\n";
    let sha256 = sha256_hex(content);

    // (A) The inline path refuses a cross-tenant publish that carries no durable
    // approval, before anything is written. The content is well-formed, so the
    // rejection is purely the cross-tenant approval gate.
    let inline = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/cross-inline/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
            "x-asset-visibility: public",
        ],
        std::str::from_utf8(content).unwrap(),
    );
    assert_json_error(&inline, 403, "cross_tenant_publish_denied");
    let inline_decision = (status_code(&inline), error_code(&inline));

    // (B) The presigned path stages the well-formed bytes (which pass #368
    // commit verification) and then commits requesting the SAME cross-tenant
    // visibility with NO approval. Only #366 screening applies this gate on the
    // presigned path; it must reach the identical decision.
    let intent_body = format!(r#"{{"size_bytes":{},"sha256":"{sha256}"}}"#, content.len());
    let intent = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/cross-presign/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &intent_body,
    ));
    let upload_id = intent["upload_id"]
        .as_str()
        .expect("upload intent must include upload_id")
        .to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload intent must include upload_url")
        .to_string();
    let staging_path = object_path_from_url(&upload_url);

    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );

    let commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"text/plain","visibility":"public"}}"#,
        content.len()
    );
    let presigned = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/cross-presign/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_json_error(&presigned, 403, "cross_tenant_publish_denied");

    // The core #366 proof: identical control-plane decision for identical
    // publish intent across both transports.
    assert_eq!(
        (status_code(&presigned), error_code(&presigned)),
        inline_decision,
        "the presigned commit must apply the SAME cross-tenant approval gate as the inline push"
    );

    // Fail-closed at the bucket: staging deleted, no final object written.
    {
        let bucket = bucket_state.lock().unwrap();
        assert!(
            !bucket.objects.contains_key(&staging_path),
            "a gated commit must delete the staging object: {:?}",
            bucket.requests
        );
        assert!(
            bucket
                .requests
                .iter()
                .any(|request| { request.method == "DELETE" && request.path == staging_path }),
            "a gated commit must issue a staging DELETE: {:?}",
            bucket.requests
        );
        assert!(
            bucket.objects.is_empty(),
            "a gated commit must leave no durable object behind: {:?}",
            bucket.objects.keys().collect::<Vec<_>>()
        );
    }

    // Fail-closed in the registry: neither path created an asset row.
    let list = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(
        list["data"].as_array().map(Vec::len),
        Some(0),
        "a cross-tenant publish denied on either path must create no asset row: {list}"
    );

    // The presigned rejection is audited as `rejected_commit` on `asset.push`.
    let audit = response_json(&http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit["data"]
        .as_array()
        .expect("audit-events must return a data array");
    assert!(
        events.iter().any(|event| {
            event["action"] == "asset.push" && event["outcome"] == "rejected_commit"
        }),
        "a gated presigned commit must record a rejected_commit audit event: {audit}"
    );
}
