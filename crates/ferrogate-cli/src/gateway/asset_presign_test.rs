// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Tests for the large-file presigned asset path (issue #259):
// commit-time size/sha256 verification against the committed object,
// fail-closed delete-on-violation, per-object ceiling enforcement, and the
// supply-chain check running against the committed bytes. Driven against a
// scripted local mock S3-compatible endpoint (the same testing philosophy
// as asset_bucket.rs), so no live bucket is required.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrogate_storage::sha256_hex;

use super::{verify_and_fetch_committed_object, CommitVerification};
use crate::gateway::asset_bucket::{AssetBucketClient, AssetBucketConfig};

/// The EICAR antivirus test signature -- the same fixed byte string
/// `asset_security` scans for, reproduced here to prove the supply-chain
/// check runs against the *committed* object (not just the inline path).
const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

#[derive(Clone)]
struct ScriptedResponse {
    status: &'static str,
    content_length: usize,
    body: Vec<u8>,
}

fn head_ok(size: usize) -> ScriptedResponse {
    ScriptedResponse {
        status: "200 OK",
        content_length: size,
        body: Vec::new(),
    }
}

fn head_404() -> ScriptedResponse {
    ScriptedResponse {
        status: "404 Not Found",
        content_length: 0,
        body: Vec::new(),
    }
}

fn get_ok(bytes: &[u8]) -> ScriptedResponse {
    ScriptedResponse {
        status: "200 OK",
        content_length: bytes.len(),
        body: bytes.to_vec(),
    }
}

fn delete_ok() -> ScriptedResponse {
    ScriptedResponse {
        status: "204 No Content",
        content_length: 0,
        body: Vec::new(),
    }
}

/// Serves a fixed script of responses (in order), recording each request's
/// method + path. Handles both keep-alive (multiple requests per
/// connection, which the pooled client uses) and fresh connections.
fn spawn_scripted_mock(responses: Vec<ScriptedResponse>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let methods = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorder = Arc::clone(&methods);
    let total = responses.len();

    std::thread::spawn(move || {
        let mut idx = 0;
        while idx < total {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            loop {
                let Some(method) = read_one_request(&mut stream) else {
                    break;
                };
                recorder.lock().unwrap().push(method);
                let response = &responses[idx];
                let head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\n\r\n",
                    response.status, response.content_length
                );
                stream.write_all(head.as_bytes()).unwrap();
                stream.write_all(&response.body).unwrap();
                idx += 1;
                if idx >= total {
                    return;
                }
            }
        }
    });

    (endpoint, methods)
}

/// Reads a single HTTP request from `stream`, returning its method, or
/// `None` on EOF / read timeout.
fn read_one_request(stream: &mut TcpStream) -> Option<String> {
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
        let read = match stream.read(&mut buffer) {
            Ok(0) => return None,
            Ok(read) => read,
            Err(_) => return None,
        };
        raw.extend_from_slice(&buffer[..read]);
    }
    let request_line = head.lines().next().unwrap_or_default();
    Some(
        request_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string(),
    )
}

fn test_bucket(endpoint: String) -> AssetBucketClient {
    AssetBucketClient::new(AssetBucketConfig {
        endpoint,
        bucket: "ferrogate-assets".into(),
        region: "us-east-1".into(),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
    })
}

#[tokio::test]
async fn commit_verify_accepts_a_matching_object_without_deleting_it() {
    let content = b"a reasonably sized committed object payload";
    let sha = sha256_hex(content);
    let (endpoint, methods) = spawn_scripted_mock(vec![head_ok(content.len()), get_ok(content)]);
    let bucket = test_bucket(endpoint);

    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:hello:1.0.0",
        content.len() as u64,
        &sha,
        "cli_tool",
        "text/plain",
        10 * 1024 * 1024,
    )
    .await
    .unwrap();

    match verification {
        CommitVerification::Verified { size_bytes, sha256 } => {
            assert_eq!(size_bytes, content.len() as u64);
            assert_eq!(sha256, sha);
        }
        _ => panic!("expected a verified commit"),
    }
    // Only HEAD + GET; a valid object is never deleted.
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD", "GET"]);
}

#[tokio::test]
async fn commit_verify_rejects_and_deletes_on_sha256_mismatch() {
    let content = b"the actual uploaded bytes";
    let registered_but_wrong = sha256_hex(b"what the client claimed it uploaded");
    let (endpoint, methods) =
        spawn_scripted_mock(vec![head_ok(content.len()), get_ok(content), delete_ok()]);
    let bucket = test_bucket(endpoint);

    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:hello:1.0.0",
        content.len() as u64,
        &registered_but_wrong,
        "cli_tool",
        "text/plain",
        10 * 1024 * 1024,
    )
    .await
    .unwrap();

    match verification {
        CommitVerification::Rejected(rejection) => {
            assert_eq!(rejection.code, "asset_commit_hash_mismatch");
        }
        _ => panic!("expected a sha256 rejection"),
    }
    // Fail closed: the orphaned object is deleted.
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD", "GET", "DELETE"]);
}

#[tokio::test]
async fn commit_verify_rejects_and_deletes_on_size_mismatch_without_downloading() {
    let (endpoint, methods) = spawn_scripted_mock(vec![head_ok(9_999), delete_ok()]);
    let bucket = test_bucket(endpoint);

    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:hello:1.0.0",
        100, // registered intent size differs from the HEAD size
        &sha256_hex(b"irrelevant"),
        "cli_tool",
        "text/plain",
        10 * 1024 * 1024,
    )
    .await
    .unwrap();

    match verification {
        CommitVerification::Rejected(rejection) => {
            assert_eq!(rejection.code, "asset_commit_size_mismatch");
        }
        _ => panic!("expected a size rejection"),
    }
    // Rejected on HEAD alone -- the oversized/wrong object is never fetched.
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD", "DELETE"]);
}

#[tokio::test]
async fn commit_verify_enforces_the_per_object_ceiling() {
    let (endpoint, methods) = spawn_scripted_mock(vec![head_ok(2_000), delete_ok()]);
    let bucket = test_bucket(endpoint);

    // Size matches the registered intent (2000) but exceeds the per-object
    // ceiling (1000), so it is rejected and deleted.
    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:big:1.0.0",
        2_000,
        &sha256_hex(b"irrelevant"),
        "cli_tool",
        "text/plain",
        1_000,
    )
    .await
    .unwrap();

    assert!(matches!(
        verification,
        CommitVerification::Rejected(rejection) if rejection.code == "asset_commit_size_mismatch"
    ));
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD", "DELETE"]);
}

#[tokio::test]
async fn commit_verify_runs_the_supply_chain_scan_on_the_committed_object() {
    let sha = sha256_hex(EICAR);
    let (endpoint, methods) =
        spawn_scripted_mock(vec![head_ok(EICAR.len()), get_ok(EICAR), delete_ok()]);
    let bucket = test_bucket(endpoint);

    // Size + sha256 match, but the committed bytes carry the EICAR malware
    // test signature: the supply-chain check must fail closed and delete it.
    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:hello:1.0.0",
        EICAR.len() as u64,
        &sha,
        "cli_tool",
        "text/plain",
        10 * 1024 * 1024,
    )
    .await
    .unwrap();

    match verification {
        CommitVerification::Rejected(rejection) => {
            assert_eq!(rejection.code, "asset_rejected");
        }
        _ => panic!("expected a supply-chain rejection"),
    }
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD", "GET", "DELETE"]);
}

#[tokio::test]
async fn commit_verify_reports_not_uploaded_when_the_object_is_absent() {
    let (endpoint, methods) = spawn_scripted_mock(vec![head_404()]);
    let bucket = test_bucket(endpoint);

    let verification = verify_and_fetch_committed_object(
        &bucket,
        "tenant-a:cli_tool:missing:1.0.0",
        100,
        &sha256_hex(b"whatever"),
        "cli_tool",
        "text/plain",
        10 * 1024 * 1024,
    )
    .await
    .unwrap();

    assert!(matches!(verification, CommitVerification::NotUploaded));
    // A never-uploaded object has nothing to delete.
    assert_eq!(*methods.lock().unwrap(), vec!["HEAD"]);
}

#[test]
fn is_hex_sha256_accepts_only_64_char_hex() {
    assert!(super::is_hex_sha256(&"a".repeat(64)));
    assert!(super::is_hex_sha256(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ));
    assert!(!super::is_hex_sha256(&"a".repeat(63)));
    assert!(!super::is_hex_sha256(&"a".repeat(65)));
    assert!(!super::is_hex_sha256(&"g".repeat(64)));
    assert!(!super::is_hex_sha256(""));
}
