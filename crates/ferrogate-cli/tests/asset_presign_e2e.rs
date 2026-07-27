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
    /// #368: object paths whose DELETE the bucket refuses with a 503, keeping
    /// the bytes. A real bucket does this under throttling, an expired role,
    /// or an object-lock policy -- and the abort surface must report the
    /// reclamation it actually achieved, not the one it attempted.
    refuse_delete_paths: std::collections::HashSet<String>,
    /// #529: how long a GET stalls before its body is written. A real bucket's
    /// reads take time; without that, concurrent gateway reads never actually
    /// overlap and an admission-control test would be measuring nothing.
    get_delay: Option<Duration>,
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
        "GET" => {
            // Copy out and RELEASE the state lock before writing the body.
            // Streaming a large object makes the gateway's verification GET and
            // its copy PUT concurrent by construction, and writing a
            // multi-megabyte body blocks until the reader drains it -- holding
            // the lock across that write deadlocks the PUT connection's handler
            // against the GET connection's, which is the bucket-side analogue of
            // the bug this whole change is about.
            let object = state.objects.get(path).cloned();
            let delay = state.get_delay;
            drop(state);
            // #529: stall AFTER releasing the lock, so concurrent GETs overlap
            // in the gateway rather than serializing on the mock.
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
            match object {
                Some(bytes) => write_http_response(&mut stream, "200 OK", &bytes, None),
                None => write_http_response(&mut stream, "404 Not Found", b"", None),
            }
        }
        "DELETE" if state.refuse_delete_paths.contains(path) => {
            // The object survives: this is the "the bucket said no" case, not
            // a no-op. `delete_object` errors on any non-2xx/404.
            write_http_response(&mut stream, "503 Service Unavailable", b"SlowDown", None);
        }
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
platform_operator = true

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

/// #368 abort/cancel surface + rejection-class evidence.
///
/// Before this, an intent that was never committed had no release path at all
/// (its staging bytes waited for the lifecycle GC), and the only "bucket
/// rejection" signal was an *inference* at commit time: "nothing is staged,
/// therefore the bucket refused it". That inference is unsound — absence also
/// means never-attempted and expired-URL — and it never fires at all in the
/// realistic case, where a client gets a 403 from the bucket and abandons the
/// flow without ever calling commit.
///
/// This pins the replacement end to end:
///
/// 1. An intent whose PUT really was refused (no staged object) can be aborted
///    with `reason=bucket_rejected`, and the gateway records the bucket class
///    only after corroborating the claim against the staging key.
/// 2. The same claim for an intent whose bytes ARE staged is contradicted by
///    that lookup, so it is downgraded to a plain abort — a client cannot
///    inflate the bucket-rejection evidence — and the staging object is
///    reclaimed immediately rather than left to the GC.
/// 3. A commit that finds nothing staged is audited as `staging_missing`, not
///    as a bucket rejection.
/// 4. Abort is not a deletion back door: an already-committed upload is 409.
#[test]
fn aborting_an_intent_reclaims_staging_and_records_a_corroborated_rejection_class() {
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

    let content = b"#!/bin/sh\necho abort surface\n";
    let sha256 = sha256_hex(content);
    let intent_body = format!(r#"{{"size_bytes":{},"sha256":"{sha256}"}}"#, content.len());
    let json_headers: [&str; 2] = [
        "Authorization: Bearer asset-secret",
        "Content-Type: application/json",
    ];

    // (1) An intent whose direct PUT was refused: nothing is ever staged.
    let refused = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/abort-refused/1.0.0",
        &json_headers,
        &intent_body,
    ));
    let refused_upload_id = refused["upload_id"].as_str().unwrap().to_string();
    let refused_staging_path = object_path_from_url(refused["upload_url"].as_str().unwrap());
    let abort_body = format!(
        r#"{{"upload_id":"{refused_upload_id}","size_bytes":{},"sha256":"{sha256}","reason":"bucket_rejected"}}"#,
        content.len()
    );
    let aborted_refused = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/abort/cli_tool/abort-refused/1.0.0",
        &json_headers,
        &abort_body,
    );
    assert_status(&aborted_refused, 200);
    let aborted_refused = response_json(&aborted_refused);
    assert_eq!(aborted_refused["object"], "asset_upload_abort");
    assert_eq!(
        aborted_refused["outcome"], "rejected_bucket",
        "a bucket-rejection report corroborated by an absent staging object must be recorded as one"
    );
    assert_eq!(aborted_refused["staging_object_removed"], false);
    // Nothing was staged, which is a different fact from a delete that failed;
    // both report `staging_object_removed: false` and only this field tells
    // them apart.
    assert_eq!(aborted_refused["staging_reclamation"], "not_staged");

    // (2) An intent whose bytes DID reach the bucket. The same claim is now
    // contradicted by the gateway's own lookup, so it must be downgraded.
    let staged = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/abort-staged/1.0.0",
        &json_headers,
        &intent_body,
    ));
    let staged_upload_id = staged["upload_id"].as_str().unwrap().to_string();
    let staged_upload_url = staged["upload_url"].as_str().unwrap().to_string();
    let staged_path = object_path_from_url(&staged_upload_url);
    let upload = direct_bucket_request(
        "PUT",
        &staged_upload_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    assert!(bucket_state
        .lock()
        .unwrap()
        .objects
        .contains_key(&staged_path));

    let lying_abort = format!(
        r#"{{"upload_id":"{staged_upload_id}","size_bytes":{},"sha256":"{sha256}","reason":"bucket_rejected"}}"#,
        content.len()
    );
    let aborted_staged = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/abort/cli_tool/abort-staged/1.0.0",
        &json_headers,
        &lying_abort,
    ));
    assert_eq!(
        aborted_staged["outcome"], "aborted",
        "a bucket-rejection claim the gateway contradicts must not be recorded as a bucket rejection"
    );
    assert_eq!(
        aborted_staged["staging_object_removed"], true,
        "abort must reclaim the staging object immediately, not defer it to the lifecycle GC"
    );
    assert_eq!(aborted_staged["staging_reclamation"], "removed");
    assert!(
        !bucket_state
            .lock()
            .unwrap()
            .objects
            .contains_key(&staged_path),
        "the aborted intent's staging bytes must be gone from the bucket"
    );

    // (2b) The same abort against a bucket that REFUSES the delete. Every
    // observable signal must say the bytes are still there: the delete error
    // is swallowed so the abort can still answer, and the previous shape of
    // this handler reported `staging_object_removed: true` from the HEAD that
    // preceded the delete -- a 200 telling the tenant its quota had been freed
    // while the object sat in the bucket until the lifecycle sweep.
    let undeletable = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/abort-undeletable/1.0.0",
        &json_headers,
        &intent_body,
    ));
    let undeletable_upload_id = undeletable["upload_id"].as_str().unwrap().to_string();
    let undeletable_url = undeletable["upload_url"].as_str().unwrap().to_string();
    let undeletable_path = object_path_from_url(&undeletable_url);
    let upload = direct_bucket_request(
        "PUT",
        &undeletable_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    bucket_state
        .lock()
        .unwrap()
        .refuse_delete_paths
        .insert(undeletable_path.clone());

    let undeletable_abort = format!(
        r#"{{"upload_id":"{undeletable_upload_id}","size_bytes":{},"sha256":"{sha256}"}}"#,
        content.len()
    );
    let aborted_undeletable = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/abort/cli_tool/abort-undeletable/1.0.0",
        &json_headers,
        &undeletable_abort,
    );
    // The abort itself partly succeeded (the intent IS released), so it stays
    // a 200 rather than becoming a 500 -- but it must not claim the removal.
    assert_status(&aborted_undeletable, 200);
    let aborted_undeletable = response_json(&aborted_undeletable);
    assert_eq!(
        aborted_undeletable["staging_object_removed"], false,
        "a delete the bucket refused must NOT be reported as a reclamation"
    );
    assert_eq!(
        aborted_undeletable["staging_reclamation"], "removal_failed",
        "the client must be able to tell a failed reclamation from nothing-staged"
    );
    assert_eq!(
        aborted_undeletable["outcome"], "aborted_reclaim_failed",
        "the failure must be filterable in the audit trail, not buried in prose"
    );
    assert!(
        bucket_state
            .lock()
            .unwrap()
            .objects
            .contains_key(&undeletable_path),
        "the mock must still hold the bytes -- otherwise this case proves nothing"
    );
    assert!(
        bucket_state
            .lock()
            .unwrap()
            .requests
            .iter()
            .any(|request| { request.method == "DELETE" && request.path == undeletable_path }),
        "the abort must have actually attempted the delete"
    );

    // A malformed abort is a typed 400, never a silent no-op.
    assert_json_error(
        &http_request(
            &gateway_addr,
            "POST",
            "/v1/assets/presign/abort/cli_tool/abort-staged/1.0.0",
            &json_headers,
            r#"{"upload_id":"not-an-upload-id","size_bytes":1,"sha256":"00"}"#,
        ),
        400,
        "invalid_abort",
    );

    // (3) Committing an intent with nothing staged is `staging_missing`, and
    // (4) abort refuses to touch an upload that is already committed.
    let commit_body = format!(
        r#"{{"upload_id":"{refused_upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"text/plain"}}"#,
        content.len()
    );
    assert_json_error(
        &http_request(
            &gateway_addr,
            "POST",
            "/v1/assets/presign/commit/cli_tool/abort-refused/1.0.0",
            &json_headers,
            &commit_body,
        ),
        404,
        "asset_not_uploaded",
    );
    assert!(!bucket_state
        .lock()
        .unwrap()
        .objects
        .contains_key(&refused_staging_path));

    let committed_intent = response_json(&http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/abort-committed/1.0.0",
        &json_headers,
        &intent_body,
    ));
    let committed_upload_id = committed_intent["upload_id"].as_str().unwrap().to_string();
    let committed_url = committed_intent["upload_url"].as_str().unwrap().to_string();
    let upload = direct_bucket_request(
        "PUT",
        &committed_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"));
    let commit_body = format!(
        r#"{{"upload_id":"{committed_upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"text/plain"}}"#,
        content.len()
    );
    assert_status(
        &http_request(
            &gateway_addr,
            "POST",
            "/v1/assets/presign/commit/cli_tool/abort-committed/1.0.0",
            &json_headers,
            &commit_body,
        ),
        200,
    );
    let abort_committed = format!(
        r#"{{"upload_id":"{committed_upload_id}","size_bytes":{},"sha256":"{sha256}"}}"#,
        content.len()
    );
    assert_json_error(
        &http_request(
            &gateway_addr,
            "POST",
            "/v1/assets/presign/abort/cli_tool/abort-committed/1.0.0",
            &json_headers,
            &abort_committed,
        ),
        409,
        "asset_upload_already_committed",
    );

    // The audit trail keeps the four classes apart, which is the whole point:
    // an operator must be able to tell a corroborated bucket refusal from an
    // ambiguous absence from an ordinary abandonment.
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
    for (action, outcome) in [
        ("asset.presign_upload_abort", "rejected_bucket"),
        ("asset.presign_upload_abort", "aborted"),
        ("asset.presign_upload_abort", "aborted_reclaim_failed"),
        ("asset.push", "staging_missing"),
    ] {
        assert!(
            events
                .iter()
                .any(|event| event["action"] == action && event["outcome"] == outcome),
            "missing {action}/{outcome} audit evidence: {audit}"
        );
    }
    assert!(
        !events
            .iter()
            .any(|event| event["action"] == "asset.push" && event["outcome"] == "rejected_bucket"),
        "commit-time absence must NOT be audited as a bucket rejection: {audit}"
    );
}

// ---- 100 MB lifecycle with a measured RSS ceiling (issue #259) ---------------

/// Bytes in the large-object lifecycle proof: the acceptance criterion's
/// "100MB binary", spelled exactly.
const LARGE_OBJECT_BYTES: usize = 100 * 1024 * 1024;

/// The gateway's in-memory budget for the run below. Two orders of magnitude
/// under the object, so the commit is forced onto the streaming path.
const LARGE_RUN_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// How much resident memory the gateway is allowed to gain across the whole
/// 100 MB commit.
///
/// This is the assertion the acceptance criterion turns on, so its value is
/// argued rather than tuned. The pre-#259 commit did
/// `response.bytes().await?.to_vec()` (one full copy, plus reqwest's own
/// `Bytes` buffer before the `to_vec`) and then re-PUT that buffer, so its
/// floor was ~100 MB and its realistic peak ~200 MB. The streaming commit's
/// resident cost is one HTTP chunk plus a 67-byte carry window. 32 MiB sits
/// far above the streaming path's real cost (allocator slack, connection
/// buffers, the tokio runtime's own growth under load) and far below the
/// buffering path's floor -- there is no value of "chunk size" that lets the
/// old code pass this, and no plausible allocator behavior that makes the new
/// code fail it.
const LARGE_RUN_RSS_CEILING_BYTES: u64 = 32 * 1024 * 1024;

fn write_large_object_config(path: &std::path::Path, gateway_addr: &str, bucket_endpoint: &str) {
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
presign_max_object_bytes = {}
max_gateway_buffer_bytes = {LARGE_RUN_BUFFER_BYTES}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write", "tools.read", "tools.execute"]
organization_id = "tenant-presign-e2e"
"#,
            LARGE_OBJECT_BYTES * 2
        ),
    )
    .unwrap();
}

/// Resident set size of `pid`, read straight from `/proc/<pid>/statm`.
///
/// Read in-process rather than shelled out to `ps`: no subprocess per sample
/// (which would itself perturb the measurement and cap the sampling rate), no
/// dependence on `ps` output formatting, and no PATH assumptions. Field 2 of
/// `statm` is resident pages.
#[cfg(target_os = "linux")]
fn resident_bytes(pid: u32) -> u64 {
    let Ok(statm) = std::fs::read_to_string(format!("/proc/{pid}/statm")) else {
        return 0;
    };
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|field| field.parse().ok())
        .unwrap_or(0);
    pages * 4096
}

/// Samples `pid`'s RSS until told to stop, returning the maximum observed.
///
/// Sampling (rather than a before/after difference) is the only honest way to
/// measure this: a 100 MB `Vec` is `mmap`ed by glibc and returned to the OS the
/// moment it is dropped, so a buffering implementation's peak is completely
/// invisible to a post-hoc reading. The 2 ms interval is far finer than the
/// hundreds of milliseconds a 100 MB buffer would have to stay resident for
/// (it lives across the whole GET, the hash, the screen and the re-PUT).
#[cfg(target_os = "linux")]
struct RssSampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<u64>,
}

#[cfg(target_os = "linux")]
impl RssSampler {
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut peak = 0;
            while !thread_stop.load(Ordering::Relaxed) {
                peak = peak.max(resident_bytes(pid));
                std::thread::sleep(Duration::from_millis(2));
            }
            peak.max(resident_bytes(pid))
        });
        Self { stop, handle }
    }

    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().expect("rss sampler thread")
    }
}

/// Streams a direct bucket `GET` and returns `(status, sha256, byte count)`
/// without ever holding the body -- the client half of the same discipline the
/// gateway now follows, so a 100 MB download does not need 100 MB in the test.
fn direct_bucket_get_streaming_sha256(url: &str) -> (u16, String, u64) {
    use sha2::{Digest, Sha256};

    let authority_and_target = url
        .strip_prefix("http://")
        .expect("the local bucket URL must use http");
    let (authority, target) = authority_and_target
        .split_once('/')
        .expect("presigned URL must have an object path");
    let mut stream = TcpStream::connect(authority).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        stream,
        "GET /{target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();

    let mut head = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let body_start = loop {
        let read = stream.read(&mut buffer).expect("read bucket response");
        assert!(read > 0, "bucket closed before sending response headers");
        head.extend_from_slice(&buffer[..read]);
        if let Some(position) = head.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let status = String::from_utf8_lossy(&head[..body_start])
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    hasher.update(&head[body_start..]);
    length += (head.len() - body_start) as u64;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                hasher.update(&buffer[..read]);
                length += read as u64;
            }
        }
    }
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(64);
    for byte in digest {
        sha256.push_str(&format!("{byte:02x}"));
    }
    (status, sha256, length)
}

/// The #259 acceptance criterion that was reopened twice: a 100 MB object goes
/// through the presigned lifecycle end-to-end while the gateway's resident
/// memory stays flat.
///
/// What this actually measures, stated plainly so it cannot be over-read:
///
/// - The *upload* leg never touched the gateway before this change either --
///   the client PUTs to the bucket directly. It is exercised here so the run is
///   a real lifecycle, not to prove anything new.
/// - The *commit* leg is what the reopen was about. The gateway must read the
///   staged object back to verify its SHA-256 and screen it, and it used to do
///   that by materializing the whole object. The sampled RSS ceiling around the
///   commit request is the proof that it no longer does.
/// - The *pull* half is driven at EVERY bucket-backed read surface, not just
///   the REST route. Round 1 of #259 bounded `GET /v1/assets/...` alone and
///   this test stayed green while the `fetch_asset` built-in tool, MCP
///   `resources/read` and the static-site serve still buffered whole objects --
///   the test could not see them because it never called them. It now asserts
///   that the same key with the same `assets.read` scope is refused on all
///   three request-driven surfaces, each under its own sampled RSS ceiling, and
///   that the presigned download returns bytes whose SHA-256 matches what was
///   pushed. (The static-site serve reaches the identical helper,
///   `FerroGateway::load_asset_content`; it is pinned by
///   `gateway::assets_test::the_shared_gateway_read_refuses_an_object_above_the_buffer_budget`
///   rather than by publishing a 100 MB site bundle here.)
#[cfg(target_os = "linux")]
#[test]
fn a_100mb_object_completes_the_presigned_lifecycle_with_flat_gateway_rss() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, bucket_state) = spawn_sigv4_bucket_mock();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (gateway, gateway_addr) = start_ready_gateway(&config_path, |gateway_addr| {
        write_large_object_config(&config_path, gateway_addr, &bucket_endpoint);
    });
    let gateway_pid = gateway.id();
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

    // The `free` plan's 10 MiB cumulative asset quota would reject a 100 MB
    // object at the intent preflight (`effective_max_object_bytes` is the min
    // of the global ceiling, the per-object ceiling and the cumulative quota),
    // so give this tenant room. This is deliberately a QUOTA change, not a
    // ceiling change: the point of the run is the memory bound, and the size
    // bounds must stay exactly as shipped.
    let quota = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-presign-e2e",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"asset_storage_quota_bytes":{},"enabled":true}}"#,
            LARGE_OBJECT_BYTES * 4
        ),
    );
    assert_status(&quota, 200);

    // A deterministic, incompressible-enough 100 MB "binary".
    let mut content = vec![0_u8; LARGE_OBJECT_BYTES];
    let mut lcg = 0x2545_f491_4f6c_dd1d_u64;
    for byte in content.iter_mut() {
        lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        *byte = (lcg >> 33) as u8;
    }
    let sha256 = sha256_hex(&content);

    let intent_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/big-binary/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"size_bytes":{LARGE_OBJECT_BYTES},"sha256":"{sha256}"}}"#),
    );
    assert_status(&intent_response, 200);
    let intent = response_json(&intent_response);
    let upload_id = intent["upload_id"].as_str().expect("upload_id").to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload_url")
        .to_string();

    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        &content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct 100MB upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    drop(content);

    // Baseline the gateway at rest, then sample it continuously across the
    // commit -- the one request where the gateway itself handles the object.
    let baseline_rss = resident_bytes(gateway_pid);
    assert!(
        baseline_rss > 8 * 1024 * 1024,
        "refusing to trust an RSS reading of {baseline_rss} bytes for pid {gateway_pid}: \
         that is not a running gateway, so the ceiling below would pass vacuously"
    );
    let sampler = RssSampler::start(gateway_pid);
    let commit_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/big-binary/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"upload_id":"{upload_id}","size_bytes":{LARGE_OBJECT_BYTES},"sha256":"{sha256}","content_type":"application/octet-stream"}}"#
        ),
    );
    let peak_rss = sampler.finish();

    assert_status(&commit_response, 200);
    let committed = response_json(&commit_response);
    assert_eq!(committed["asset"]["size_bytes"], LARGE_OBJECT_BYTES as u64);
    assert_eq!(committed["asset"]["content_hash"], sha256);
    assert_eq!(committed["asset"]["storage_backed"], true);
    assert_no_bucket_location_fields(&committed);

    let growth = peak_rss.saturating_sub(baseline_rss);
    assert!(
        growth < LARGE_RUN_RSS_CEILING_BYTES,
        "committing a {LARGE_OBJECT_BYTES}-byte object grew gateway RSS by {growth} bytes \
         (baseline {baseline_rss}, peak {peak_rss}); the ceiling is \
         {LARGE_RUN_RSS_CEILING_BYTES}. A growth at or above the object size means the \
         commit path is buffering the whole object again."
    );

    // The registry pull must REFUSE to buffer an object this size rather than
    // quietly reintroducing the same unbounded read on the read path.
    let inline_pull = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/big-binary/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_json_error(&inline_pull, 413, "asset_too_large_for_inline_pull");
    assert!(
        response_json(&inline_pull)["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("/v1/assets/presign/download/"),
        "the refusal must name the endpoint that does work: {inline_pull}"
    );

    // The two AGENT-FACING read surfaces -- the reason this pillar exists --
    // must refuse identically. Same key, same `assets.read` scope, same object.
    // Before this change both returned the full 100 MB `Vec`, re-hashed it, and
    // (for `fetch_asset`) base64-encoded it into a ~133 MB `String` plus the
    // serde_json copy: ~350-400 MB resident for one request. The RSS sampler is
    // what makes that visible; the response assertion alone would also catch it,
    // but only the sampler proves nothing was buffered on the way to refusing.
    let mcp_sampler = RssSampler::start(gateway_pid);
    let resources_read = http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"asset://cli_tool/big-binary/1.0.0"}}"#,
    );
    let fetch_asset = http_request(
        &gateway_addr,
        "POST",
        "/v1/mcp",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"builtin.fetch_asset","arguments":{"uri":"asset://cli_tool/big-binary/1.0.0"}}}"#,
    );
    let mcp_peak = mcp_sampler.finish();

    let read_body = response_json(&resources_read);
    assert!(
        read_body["result"].is_null(),
        "MCP resources/read must not inline a 100 MB object: {resources_read}"
    );
    let read_message = read_body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        read_message.contains("/v1/assets/presign/download/"),
        "resources/read must refuse with the endpoint that works: {resources_read}"
    );

    // `fetch_asset` runs through the governed tool chokepoint, which reports a
    // backend failure as a tool error rather than a JSON-RPC error, so accept
    // either shape -- what must not happen is the bytes coming back.
    let fetched_body = response_json(&fetch_asset);
    let fetched_text = fetch_asset.clone();
    assert!(
        fetched_body["result"]["content"][0]["resource"]["blob"].is_null()
            && fetched_body["result"]["content"][0]["resource"]["text"].is_null(),
        "fetch_asset must not inline a 100 MB object: {}",
        &fetched_text[..fetched_text.len().min(2000)]
    );
    assert!(
        fetched_text.contains("/v1/assets/presign/download/"),
        "fetch_asset must refuse with the endpoint that works: {}",
        &fetched_text[..fetched_text.len().min(2000)]
    );

    let mcp_growth = mcp_peak.saturating_sub(baseline_rss);
    assert!(
        mcp_growth < LARGE_RUN_RSS_CEILING_BYTES,
        "the agent-facing reads (MCP resources/read + fetch_asset) grew gateway RSS by \
         {mcp_growth} bytes for a {LARGE_OBJECT_BYTES}-byte object (baseline {baseline_rss}, \
         peak {mcp_peak}); the ceiling is {LARGE_RUN_RSS_CEILING_BYTES}. These are the surfaces \
         the pull bound missed in round 1."
    );

    // ...and the presigned download returns the exact bytes that were pushed,
    // straight from the bucket, with the gateway again staying flat (it only
    // signs a URL -- it is not in the data path at all).
    let download_sampler = RssSampler::start(gateway_pid);
    let download_response = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/presign/download/cli_tool/big-binary/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&download_response, 200);
    let download = response_json(&download_response);
    assert_eq!(download["sha256"], sha256);
    assert_eq!(download["size_bytes"], LARGE_OBJECT_BYTES as u64);
    let download_url = download["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();

    let (status, fetched_sha256, fetched_len) = direct_bucket_get_streaming_sha256(&download_url);
    let download_peak = download_sampler.finish();
    assert_eq!(status, 200, "the presigned download must serve the object");
    assert_eq!(fetched_len, LARGE_OBJECT_BYTES as u64);
    assert_eq!(
        fetched_sha256, sha256,
        "the bytes fetched directly from the bucket must be the bytes that were pushed"
    );
    let download_growth = download_peak.saturating_sub(baseline_rss);
    assert!(
        download_growth < LARGE_RUN_RSS_CEILING_BYTES,
        "issuing a presigned download for a {LARGE_OBJECT_BYTES}-byte object grew gateway RSS \
         by {download_growth} bytes; the gateway must not be in the data path"
    );

    // The bucket saw exactly the traffic the design claims: the client's direct
    // PUT to staging, the gateway's verification GET, the gateway's copy PUT to
    // the private final key, the staging reclamation, and the client's direct
    // GET of the final object. No second full-size PUT, i.e. no second copy.
    let requests = bucket_state.lock().unwrap();
    let puts = requests
        .requests
        .iter()
        .filter(|request| request.method == "PUT")
        .count();
    assert_eq!(
        puts, 2,
        "expected exactly the client's staging PUT and the gateway's single copy PUT"
    );
    assert_eq!(
        requests
            .requests
            .iter()
            .filter(|request| request.method == "GET")
            .count(),
        2,
        "expected exactly the gateway's verification GET and the client's download GET"
    );
}

// ---- Aggregate admission control with a measured RSS ceiling (issue #529) ----

/// The object every concurrent reader in the burst below pulls. Exactly the
/// per-operation budget, so each read is individually legal -- the point of
/// #529 is that a pile of individually-legal reads was collectively unbounded.
const BURST_OBJECT_BYTES: usize = 4 * 1024 * 1024;

/// The per-operation bound for the burst run.
const BURST_BUFFER_BYTES: usize = BURST_OBJECT_BYTES;

/// The AGGREGATE bound: two concurrent full-size reads. Everything past that
/// must be shed, not buffered.
const BURST_TOTAL_BUFFER_BYTES: usize = 2 * BURST_OBJECT_BYTES;

/// How long a shed read is willing to wait for capacity. Short enough that 24
/// readers resolve quickly, long enough to prove the queue-then-shed shape
/// rather than shed-immediately.
const BURST_ADMISSION_WAIT_MS: u64 = 150;

/// Concurrent readers driven at the gateway. Six times the aggregate budget's
/// capacity, so the ceiling has to do real work.
const BURST_READERS: usize = 24;

/// How much resident memory the gateway may gain across the whole burst.
///
/// Argued, not tuned. Without admission control the burst's floor is
/// `BURST_READERS x BURST_OBJECT_BYTES` = 96 MiB of asset buffers alone (each
/// read holds its object through the hash re-verification and the response
/// write), and in practice more, since the response path holds the bytes while
/// they drain to a client that is reading 24 sockets. With it, the resident
/// asset bytes are capped at `BURST_TOTAL_BUFFER_BYTES` = 8 MiB. 40 MiB sits
/// far above the enforced ceiling plus the runtime's own growth under 24
/// concurrent connections, and far below the unbounded floor: there is no
/// scheduling order that lets the unbounded code pass, and no plausible
/// allocator behavior that makes the bounded code fail.
const BURST_RSS_CEILING_BYTES: u64 = 40 * 1024 * 1024;

fn write_admission_config(path: &std::path::Path, gateway_addr: &str, bucket_endpoint: &str) {
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
presign_max_object_bytes = {}
max_gateway_buffer_bytes = {BURST_BUFFER_BYTES}
max_total_gateway_buffer_bytes = {BURST_TOTAL_BUFFER_BYTES}
buffer_admission_wait_ms = {BURST_ADMISSION_WAIT_MS}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write", "tools.read", "tools.execute"]
organization_id = "tenant-presign-e2e"
"#,
            BURST_OBJECT_BYTES * 4
        ),
    )
    .unwrap();
}

/// Publishes the 4 MiB `text/plain` object both admission tests read, through
/// the real presigned upload + commit lifecycle, and returns its sha256.
///
/// Deliberately printable ASCII: the same bytes have to survive a raw HTTP body
/// comparison on the registry-pull run AND a JSON `text` inlining on the MCP
/// run, so the object must be valid UTF-8 that takes the `text` branch rather
/// than the base64 one.
#[cfg(target_os = "linux")]
fn publish_burst_object(gateway_addr: &str) -> (Vec<u8>, String) {
    let register = http_request(
        gateway_addr,
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
    let quota = http_request(
        gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-presign-e2e",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"asset_storage_quota_bytes":{},"enabled":true}}"#,
            BURST_OBJECT_BYTES * 8
        ),
    );
    assert_status(&quota, 200);

    // Printable ASCII so the response body survives a text-shaped comparison,
    // and deterministic so the hash is stable.
    let content: Vec<u8> = (0..BURST_OBJECT_BYTES)
        .map(|index| b'!' + (index % 90) as u8)
        .collect();
    let sha256 = sha256_hex(&content);

    let intent_response = http_request(
        gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/burst-object/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"size_bytes":{BURST_OBJECT_BYTES},"sha256":"{sha256}"}}"#),
    );
    assert_status(&intent_response, 200);
    let intent = response_json(&intent_response);
    let upload_id = intent["upload_id"].as_str().expect("upload_id").to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload_url")
        .to_string();
    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        &content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct upload failed: {}",
        String::from_utf8_lossy(&upload)
    );

    let commit_response = http_request(
        gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/burst-object/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"upload_id":"{upload_id}","size_bytes":{BURST_OBJECT_BYTES},"sha256":"{sha256}","content_type":"text/plain"}}"#
        ),
    );
    assert_status(&commit_response, 200);

    (content, sha256)
}

/// #529 acceptance: more concurrent over-budget readers than the ceiling
/// allows, and the enforced behavior asserted with a measured memory ceiling.
///
/// What "over-budget" means here is deliberately NOT "too large an object" --
/// that is #259's 413, already proven. Every read below is individually inside
/// `max_gateway_buffer_bytes`. What they exceed, collectively, is
/// `max_total_gateway_buffer_bytes`. Before this change nothing looked at that
/// sum, so 24 legal reads held 24 buffers and the documented "peak memory =
/// per-op bound x concurrency" was a sizing hint with no enforcement behind it.
///
/// Three things are asserted, and each one is a separate way the feature could
/// be fake:
///
/// 1. **No truncation.** Every `200` carries the whole object, hash-verified.
///    A ceiling implemented by cutting bodies short would pass a status-code
///    assertion and fail this one.
/// 2. **A typed, named refusal.** Every non-`200` is
///    `503 gateway_buffer_budget_exhausted` -- not a generic 500, not a
///    `asset_bucket_unavailable` that blames a healthy bucket, and not a
///    timeout the caller experiences as a hang.
/// 3. **A measured ceiling.** Sampled RSS across the burst stays under a bound
///    the unbounded implementation cannot meet.
///
/// Progress is asserted too (at least one `200`): a "ceiling" that admits
/// nothing would satisfy 1-3 vacuously, and that is the exact dangerous
/// default this knob had to avoid.
#[cfg(target_os = "linux")]
#[test]
fn concurrent_over_budget_reads_are_shed_with_a_typed_refusal_and_a_flat_rss() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, bucket_state) = spawn_sigv4_bucket_mock();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (gateway, gateway_addr) = start_ready_gateway(&config_path, |gateway_addr| {
        write_admission_config(&config_path, gateway_addr, &bucket_endpoint);
    });
    let gateway_pid = gateway.id();
    let _gateway = GatewayGuard(gateway);
    support::wait_for_gateway(&gateway_addr);

    let (_content, sha256) = publish_burst_object(&gateway_addr);

    // Slow the bucket down so the concurrent reads genuinely overlap inside the
    // gateway. Without this the reads complete faster than they arrive and the
    // budget is never contended -- the test would pass with no admission
    // control at all.
    bucket_state.lock().unwrap().get_delay = Some(Duration::from_millis(400));

    let baseline_rss = resident_bytes(gateway_pid);
    assert!(
        baseline_rss > 8 * 1024 * 1024,
        "refusing to trust an RSS reading of {baseline_rss} bytes for pid {gateway_pid}: \
         that is not a running gateway, so the ceiling below would pass vacuously"
    );
    let sampler = RssSampler::start(gateway_pid);
    let readers: Vec<_> = (0..BURST_READERS)
        .map(|_| {
            let addr = gateway_addr.clone();
            std::thread::spawn(move || {
                support::http_request_bytes(
                    &addr,
                    "GET",
                    "/v1/assets/cli_tool/burst-object/1.0.0",
                    &["Authorization: Bearer asset-secret"],
                    b"",
                )
            })
        })
        .collect();
    let responses: Vec<Vec<u8>> = readers
        .into_iter()
        .map(|reader| reader.join().expect("reader thread"))
        .collect();
    let peak_rss = sampler.finish();

    let mut served = 0_usize;
    let mut shed = 0_usize;
    for response in &responses {
        let head = String::from_utf8_lossy(&response[..response.len().min(4096)]).to_string();
        let status = status_code(&head);
        let body = raw_response_body(response);
        if status == 200 {
            served += 1;
            // No truncation: an admitted read serves the WHOLE object.
            assert_eq!(
                body.len(),
                BURST_OBJECT_BYTES,
                "an admitted read must serve the whole object, not a truncated body"
            );
            assert_eq!(
                sha256_hex(body),
                sha256,
                "an admitted read must serve the exact bytes that were pushed"
            );
            continue;
        }
        shed += 1;
        assert_eq!(
            status, 503,
            "an over-budget read must be shed with a 503, not {status}: {head}"
        );
        let error = String::from_utf8_lossy(body).to_string();
        assert!(
            error.contains("gateway_buffer_budget_exhausted"),
            "the shed must be typed and named, not a generic failure: {error}"
        );
        assert!(
            error.contains("max_total_gateway_buffer_bytes"),
            "the shed must name the knob that caused it: {error}"
        );
        assert!(
            error.contains("/v1/assets/presign/download/"),
            "the shed must name the endpoint that does not use this budget: {error}"
        );
    }

    assert!(
        shed > 0,
        "{BURST_READERS} concurrent {BURST_OBJECT_BYTES}-byte reads against a \
         {BURST_TOTAL_BUFFER_BYTES}-byte aggregate budget must shed at least one; none were, so \
         the ceiling is not enforced"
    );
    assert!(
        served > 0,
        "the ceiling must SHED excess load, not close the door: every one of \
         {BURST_READERS} reads was refused"
    );

    let growth = peak_rss.saturating_sub(baseline_rss);
    assert!(
        growth < BURST_RSS_CEILING_BYTES,
        "{BURST_READERS} concurrent {BURST_OBJECT_BYTES}-byte reads grew gateway RSS by {growth} \
         bytes (baseline {baseline_rss}, peak {peak_rss}); the ceiling is \
         {BURST_RSS_CEILING_BYTES}, and the aggregate budget is {BURST_TOTAL_BUFFER_BYTES}. A \
         growth near {BURST_READERS} x {BURST_OBJECT_BYTES} means the reads are being admitted \
         without regard to the aggregate budget."
    );

    // The shed reads never touched the bucket: admission happens before the
    // GET, so an overloaded gateway does not also hammer the object store.
    let bucket_gets = bucket_state
        .lock()
        .unwrap()
        .requests
        .iter()
        .filter(|request| request.method == "GET")
        .count();
    assert!(
        bucket_gets <= served + 1,
        "shed reads must not issue a bucket GET: {bucket_gets} GETs for {served} served reads"
    );
}

// ---- Presigned quota accounting: counted ONCE, at commit (issue #259) --------

/// Reads the tenant's authoritative asset-storage summary.
fn storage_summary(gateway_addr: &str) -> serde_json::Value {
    let response = http_request(
        gateway_addr,
        "GET",
        "/v1/assets/storage/summary",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&response, 200);
    response_json(&response)
}

fn used_bytes(gateway_addr: &str) -> u64 {
    storage_summary(gateway_addr)["used_bytes"]
        .as_u64()
        .expect("used_bytes must be a number")
}

/// Acceptance box 5 of #259: "storage quota accounting remains correct for
/// presigned uploads (counted at commit)".
///
/// The three ways this can be wrong are each asserted separately, because they
/// fail in opposite directions and a single before/after check catches only
/// one of them:
///
/// 1. **Counted at intent.** Registering an intent reserves nothing durable --
///    the staged bytes are not a registry row and an intent that is never
///    committed must not consume the tenant's quota. Asserted after the intent
///    AND after the direct PUT actually puts bytes in the bucket, so this is
///    not merely "the gateway didn't write a row it had no reason to write".
/// 2. **Counted twice.** One commit must move `used_bytes` by exactly the
///    object's size -- not by twice it (staging + final are two bucket objects
///    for one logical asset, and an accounting that counted bucket objects
///    rather than registry rows would double it).
/// 3. **Counted again on replay.** Re-committing the same `upload_id` is
///    idempotent and returns the same asset; it must not add the bytes a
///    second time. This is the assertion a naive "increment a counter at
///    commit" implementation fails.
///
/// A rejected commit is checked too: bytes that never became an asset never
/// count.
#[test]
fn a_presigned_upload_is_counted_once_at_commit_never_at_intent_or_on_replay() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, _bucket_state) = spawn_sigv4_bucket_mock();
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

    const QUOTA_BYTES: u64 = 1_000_000;
    let quota = http_request(
        &gateway_addr,
        "PUT",
        "/admin/v1/quota-policies/tenant/tenant-presign-e2e",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"asset_storage_quota_bytes":{QUOTA_BYTES},"enabled":true}}"#),
    );
    assert_status(&quota, 200);

    // Baseline: nothing published yet, and the summary is the surface the whole
    // assertion rests on, so pin its shape before trusting its arithmetic.
    let baseline = storage_summary(&gateway_addr);
    assert_eq!(baseline["object"], "asset_storage_summary");
    assert_eq!(baseline["used_bytes"], 0);
    assert_eq!(baseline["quota_bytes"], QUOTA_BYTES);
    assert_eq!(baseline["remaining_bytes"], QUOTA_BYTES);
    assert_eq!(baseline["presigned_upload"]["enabled"], true);

    // A payload whose length is a distinctive, non-round number, so an
    // off-by-a-multiple accounting bug cannot coincide with the right answer.
    let content = vec![b'q'; 4_099];
    let size = content.len() as u64;
    let sha256 = sha256_hex(&content);

    let intent_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/quota-once/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"size_bytes":{size},"sha256":"{sha256}"}}"#),
    );
    assert_status(&intent_response, 200);
    let intent = response_json(&intent_response);
    let upload_id = intent["upload_id"].as_str().expect("upload_id").to_string();
    let upload_url = intent["upload_url"]
        .as_str()
        .expect("upload_url")
        .to_string();

    // (1) NOT counted at intent.
    assert_eq!(
        used_bytes(&gateway_addr),
        0,
        "registering an upload intent must not consume quota; only a committed \
         asset does"
    );

    // Bytes now genuinely exist in the bucket under the staging key...
    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        &content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );

    // ...and they still must not count: staged bytes are not a published asset.
    assert_eq!(
        used_bytes(&gateway_addr),
        0,
        "bytes staged against a presigned URL must not consume quota before commit"
    );

    let commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{size},"sha256":"{sha256}","content_type":"application/octet-stream"}}"#
    );
    let commit_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/quota-once/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_status(&commit_response, 200);
    assert_eq!(response_json(&commit_response)["asset"]["size_bytes"], size);

    // (2) Counted exactly ONCE, at commit -- not twice for staging + final.
    let after_commit = storage_summary(&gateway_addr);
    assert_eq!(
        after_commit["used_bytes"], size,
        "one committed presigned upload must move used_bytes by exactly the \
         object size (a doubled value means bucket objects are being counted \
         instead of registry rows): {after_commit}"
    );
    assert_eq!(
        after_commit["remaining_bytes"],
        QUOTA_BYTES - size,
        "remaining_bytes must stay consistent with used_bytes: {after_commit}"
    );

    // (3) Idempotent replay must not count the bytes again.
    let replay = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/quota-once/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &commit_body,
    );
    assert_status(&replay, 200);
    assert_eq!(
        used_bytes(&gateway_addr),
        size,
        "replaying the same commit is idempotent and must not double-count the \
         object against the tenant quota"
    );

    // And a commit the gateway REJECTS never counts: stage bytes that
    // contradict the intent they were registered under, and prove the tenant's
    // usage is untouched by the failed attempt.
    let bad_content = vec![b'z'; 512];
    let bad_sha256 = sha256_hex(&bad_content);
    let bad_intent = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/quota-once/2.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"size_bytes":{},"sha256":"{bad_sha256}"}}"#,
            bad_content.len()
        ),
    );
    assert_status(&bad_intent, 200);
    let bad_upload_id = response_json(&bad_intent)["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();
    // Never uploaded: the commit finds nothing staged and must refuse.
    let rejected = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/quota-once/2.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"upload_id":"{bad_upload_id}","size_bytes":{},"sha256":"{bad_sha256}","content_type":"application/octet-stream"}}"#,
            bad_content.len()
        ),
    );
    assert_json_error(&rejected, 404, "asset_not_uploaded");
    assert_eq!(
        used_bytes(&gateway_addr),
        size,
        "a refused commit must leave the tenant's asset-storage usage exactly \
         where the one successful commit left it"
    );
}

/// Acceptance box 4 of #259, second half: "issuing [a presigned URL] emits an
/// audit event with key/tenant/asset identity".
///
/// The existing coverage asserted only `action`/`outcome` string pairs, which
/// is what an audit trail looks like when it has been reduced to a log line:
/// it proves an event happened, not that the event can answer *who did what to
/// which asset*. All three identities are asserted here on the SUCCESSFUL
/// issue path (the one that hands out a capability), and the download issue is
/// checked too because it mints a read capability against a private bucket.
#[test]
fn issuing_a_presigned_url_audits_the_key_tenant_and_asset_identity() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, _bucket_state) = spawn_sigv4_bucket_mock();
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

    let content = b"#!/bin/sh\necho audited presign identity\n";
    let sha256 = sha256_hex(content);
    let intent_response = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/upload/cli_tool/audited-tool/3.1.4",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"size_bytes":{},"sha256":"{sha256}"}}"#, content.len()),
    );
    assert_status(&intent_response, 200);
    let upload_id = response_json(&intent_response)["upload_id"]
        .as_str()
        .expect("upload_id")
        .to_string();

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

    let issued = events
        .iter()
        .find(|event| {
            event["action"] == "asset.presign_upload_intent" && event["outcome"] == "issued"
        })
        .unwrap_or_else(|| {
            panic!("issuing an upload URL must emit an `issued` audit event: {audit}")
        });

    // KEY identity: the virtual/api key that authorized the capability.
    assert_eq!(
        issued["actor_api_key_id"], "asset-client",
        "the audit event must name the key that was handed the upload URL: {issued}"
    );
    // TENANT identity: the tenant the capability was scoped to.
    assert_eq!(
        issued["tenant"]["organization_id"], "tenant-presign-e2e",
        "the audit event must name the tenant the URL was scoped to: {issued}"
    );
    // ASSET identity: the logical asset the capability addresses. The target is
    // the tenant-qualified stored asset id, so every coordinate is recoverable.
    let target = issued["target"].as_str().unwrap_or_default();
    for coordinate in ["tenant-presign-e2e", "cli_tool", "audited-tool", "3.1.4"] {
        assert!(
            target.contains(coordinate),
            "the audit target must identify the asset by {coordinate}: {issued}"
        );
    }
    // The event must be correlatable and say what capability was minted.
    assert!(
        issued["request_id"].is_string(),
        "the audit event must carry the request id: {issued}"
    );
    let message = issued["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&upload_id),
        "the audit event must name the upload it authorized: {issued}"
    );

    // The download side mints a READ capability against a private bucket, so it
    // must be audited with the same three identities. Commit first so there is
    // an asset to download.
    let upload_url = response_json(&intent_response)["upload_url"]
        .as_str()
        .expect("upload_url")
        .to_string();
    let upload = direct_bucket_request(
        "PUT",
        &upload_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    );
    assert!(
        String::from_utf8_lossy(&upload).contains("HTTP/1.1 200"),
        "direct staging upload failed: {}",
        String::from_utf8_lossy(&upload)
    );
    let commit = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/audited-tool/3.1.4",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        &format!(
            r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha256}","content_type":"application/octet-stream"}}"#,
            content.len()
        ),
    );
    assert_status(&commit, 200);

    let download = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/presign/download/cli_tool/audited-tool/3.1.4",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert_status(&download, 200);

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
    let download_event = events
        .iter()
        .find(|event| {
            event["action"]
                .as_str()
                .is_some_and(|action| action.contains("presign") && action.contains("download"))
        })
        .unwrap_or_else(|| panic!("issuing a presigned DOWNLOAD url must be audited too: {audit}"));
    assert_eq!(
        download_event["actor_api_key_id"], "asset-client",
        "the download audit event must name the key: {download_event}"
    );
    assert_eq!(
        download_event["tenant"]["organization_id"], "tenant-presign-e2e",
        "the download audit event must name the tenant: {download_event}"
    );
    let download_target = download_event["target"].as_str().unwrap_or_default();
    for coordinate in ["cli_tool", "audited-tool", "3.1.4"] {
        assert!(
            download_target.contains(coordinate),
            "the download audit target must identify the asset by {coordinate}: {download_event}"
        );
    }
}

// ---- The ceiling holds while the CLIENT is the slow part (issue #529 rework) ----

/// How long each reader refuses to drain its socket after reading the response
/// head. The whole contended window has to sit in the RESPONSE WRITE, which is
/// the leg the first round of #529 left uncharged on the two MCP/tool surfaces.
#[cfg(target_os = "linux")]
const STALL: Duration = Duration::from_millis(1500);

/// Reads the response head, then stops reading for `stall`, then drains.
///
/// This is the client the review's repro describes. A 4 MiB response does not
/// fit a socket buffer, so the gateway is left holding whatever it allocated
/// for this response -- the buffer, the inlined JSON copy, and the serialized
/// body -- for the whole stall. A client that reads straight through never
/// exercises that, which is why the existing burst fixture (a deliberately slow
/// BUCKET, a fast client) cannot see an early permit release: its contended
/// window is entirely inside the bucket GET.
#[cfg(target_os = "linux")]
fn stalled_request(addr: &str, method: &str, path: &str, body: &str, stall: Duration) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer asset-secret\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(body.as_bytes()).unwrap();

    let mut head = [0_u8; 512];
    let read = stream.read(&mut head).unwrap_or(0);
    std::thread::sleep(stall);
    let mut response = head[..read].to_vec();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest);
    response.extend_from_slice(&rest);
    response
}

/// #529 rework acceptance: the aggregate ceiling holds on MCP `resources/read`
/// when the bucket is FAST and the clients are slow.
///
/// This is the run that separates a real ceiling from a bucket-GET rate
/// limiter. `concurrent_over_budget_reads_are_shed_...` slows the bucket by
/// 400 ms, so every read's contended window sits inside `get_object`, and a
/// permit released the moment that call returned would still look like a
/// ceiling. Here the bucket returns immediately and the readers stall for 1.5 s
/// after the response head, so the ONLY way resident asset bytes can exceed the
/// ceiling is by releasing the charge before the response is written -- which
/// is precisely what `resources/read` did before this rework, while a full
/// `text` copy of the object and its serialized form travelled on inside the
/// JSON value.
///
/// The surface is deliberately MCP rather than the registry pull: the pull
/// binds its permit across `write_cacheable_response` and always passed this.
#[cfg(target_os = "linux")]
#[test]
fn a_stalled_mcp_reader_cannot_hold_asset_bytes_outside_the_ceiling() {
    std::env::set_var(SECRET_ENV, SECRET_ACCESS_KEY);
    let (bucket_endpoint, _bucket_state) = spawn_sigv4_bucket_mock();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (gateway, gateway_addr) = start_ready_gateway(&config_path, |gateway_addr| {
        write_admission_config(&config_path, gateway_addr, &bucket_endpoint);
    });
    let gateway_pid = gateway.id();
    let _gateway = GatewayGuard(gateway);
    support::wait_for_gateway(&gateway_addr);

    let (content, _sha256) = publish_burst_object(&gateway_addr);

    // NO bucket delay: every read completes its GET instantly, so the whole
    // contended window is in the response write.
    let baseline_rss = resident_bytes(gateway_pid);
    assert!(
        baseline_rss > 8 * 1024 * 1024,
        "refusing to trust an RSS reading of {baseline_rss} bytes for pid {gateway_pid}: \
         that is not a running gateway, so the ceiling below would pass vacuously"
    );
    let sampler = RssSampler::start(gateway_pid);
    let readers: Vec<_> = (0..BURST_READERS)
        .map(|_| {
            let addr = gateway_addr.clone();
            std::thread::spawn(move || {
                stalled_request(
                    &addr,
                    "POST",
                    "/v1/mcp",
                    r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"asset://cli_tool/burst-object/1.0.0"}}"#,
                    STALL,
                )
            })
        })
        .collect();
    let responses: Vec<Vec<u8>> = readers
        .into_iter()
        .map(|reader| reader.join().expect("reader thread"))
        .collect();
    let peak_rss = sampler.finish();

    let mut served = 0_usize;
    let mut shed = 0_usize;
    for response in &responses {
        let head = String::from_utf8_lossy(&response[..response.len().min(4096)]).to_string();
        assert_eq!(
            status_code(&head),
            200,
            "JSON-RPC reports application errors in the body, not the status line: {head}"
        );
        let body = String::from_utf8_lossy(raw_response_body(response)).to_string();
        if body.contains("\"result\"") {
            served += 1;
            // No truncation: an admitted read inlines the WHOLE object.
            assert!(
                body.len() >= content.len(),
                "an admitted read must inline the whole {}-byte object, but the response body \
                 was {} bytes",
                content.len(),
                body.len()
            );
            assert!(
                body.contains("\"text\""),
                "the object is text/plain, so it must be inlined as text rather than base64: {}",
                &body[..body.len().min(512)]
            );
            continue;
        }
        shed += 1;
        assert!(
            body.contains("-32005"),
            "a shed MCP read must carry the typed aggregate-budget code, not a generic error: {}",
            &body[..body.len().min(512)]
        );
        assert!(
            body.contains("max_total_gateway_buffer_bytes"),
            "the shed must name the knob that caused it: {}",
            &body[..body.len().min(512)]
        );
    }

    assert!(
        shed > 0,
        "{BURST_READERS} concurrent stalled MCP reads of a {BURST_OBJECT_BYTES}-byte object \
         against a {BURST_TOTAL_BUFFER_BYTES}-byte aggregate budget must shed at least one"
    );
    assert!(
        served > 0,
        "the ceiling must SHED excess load, not close the door: every one of {BURST_READERS} \
         MCP reads was refused"
    );

    let growth = peak_rss.saturating_sub(baseline_rss);
    assert!(
        growth < BURST_RSS_CEILING_BYTES,
        "{BURST_READERS} stalled MCP readers grew gateway RSS by {growth} bytes (baseline \
         {baseline_rss}, peak {peak_rss}); the ceiling is {BURST_RSS_CEILING_BYTES} and the \
         aggregate budget is {BURST_TOTAL_BUFFER_BYTES}. Growth on this scale means the \
         admission charge is being released before the response is written, so resident asset \
         bytes track the number of slow clients instead of the ceiling."
    );
}
