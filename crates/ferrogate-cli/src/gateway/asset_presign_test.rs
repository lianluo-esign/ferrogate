// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Tests for the large-file presigned asset path (issue #259):
// commit-time size/sha256 verification against the committed object,
// fail-closed delete-on-violation, per-object ceiling enforcement, and the
// built-in content checks running against the committed bytes. Driven against a
// scripted local mock S3-compatible endpoint (the same testing philosophy
// as asset_bucket.rs), so no live bucket is required.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ferrogate_storage::{sha256_hex, StorageError, StoredAsset};

use super::{
    asset_create_failure_disposition, existing_asset_matches_commit, final_object_prefix,
    is_upload_id, new_upload_id, staging_object_key, verify_and_fetch_committed_object,
    AssetCreateFailureDisposition, CommitVerification, PresignCommitRequest,
    PresignUploadIntentRequest,
};
use crate::gateway::asset_bucket::{AssetBucketClient, AssetBucketConfig};

/// The EICAR antivirus test signature -- the same fixed byte string
/// `asset_security` scans for, reproduced here to prove the built-in content
/// check runs against the uploaded bytes (not just the inline path).
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
        CommitVerification::Verified { bytes, sha256 } => {
            assert_eq!(bytes, content);
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
async fn commit_verify_runs_built_in_content_checks_on_the_committed_object() {
    let sha = sha256_hex(EICAR);
    let (endpoint, methods) =
        spawn_scripted_mock(vec![head_ok(EICAR.len()), get_ok(EICAR), delete_ok()]);
    let bucket = test_bucket(endpoint);

    // Size + sha256 match, but the committed bytes carry the EICAR malware
    // test signature: the built-in content check must reject and delete it.
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
        _ => panic!("expected a built-in content rejection"),
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

#[test]
fn upload_ids_are_random_lowercase_128_bit_capabilities() {
    let first = new_upload_id().expect("first upload id");
    let second = new_upload_id().expect("second upload id");
    assert!(is_upload_id(&first));
    assert!(is_upload_id(&second));
    assert_ne!(first, second);
    assert!(!is_upload_id("upl_ABCDEF0123456789abcdef0123456789"));
    assert!(!is_upload_id("upl_0123456789abcdef"));
    assert!(!is_upload_id("obj_0123456789abcdef0123456789abcdef"));
}

#[test]
fn staging_keys_bind_upload_to_asset_size_and_hash_without_exposing_the_asset_id() {
    let asset_id = "tenant-a:cli_tool:hello:1.0.0";
    let upload_id = "upl_0123456789abcdef0123456789abcdef";
    let sha = "a".repeat(64);
    let key = staging_object_key(asset_id, upload_id, 42, &sha);
    assert!(key.starts_with(".ferrogate/staging/"));
    assert!(!key.contains(asset_id));
    assert_ne!(key, staging_object_key(asset_id, upload_id, 43, &sha));
    assert_ne!(
        key,
        staging_object_key("tenant-a:cli_tool:other:1.0.0", upload_id, 42, &sha,)
    );
    assert_ne!(
        key,
        staging_object_key(asset_id, "upl_fedcba9876543210fedcba9876543210", 42, &sha,)
    );
}

#[test]
fn presign_control_requests_reject_unknown_json_fields() {
    assert!(serde_json::from_str::<PresignUploadIntentRequest>(&format!(
        r#"{{"size_bytes":42,"sha256":"{}","extra":true}}"#,
        "a".repeat(64)
    ))
    .is_err());
    assert!(serde_json::from_str::<PresignCommitRequest>(
        &format!(
            r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42,"sha256":"{}","extra":true}}"#,
            "a".repeat(64)
        )
    )
    .is_err());
}

#[test]
fn create_failure_cleanup_preserves_only_genuinely_unknown_outcomes() {
    let unknown = StorageError::OperationCommitOutcomeUnknown {
        operation: "create asset if absent",
        stage: "transaction commit",
    };
    assert_eq!(
        asset_create_failure_disposition(&unknown),
        AssetCreateFailureDisposition::OutcomeUnknown
    );
    assert_eq!(
        asset_create_failure_disposition(&StorageError::Postgres("statement failed".into())),
        AssetCreateFailureDisposition::DefinitelyNotPublished
    );
    assert_eq!(
        asset_create_failure_disposition(&StorageError::OperationDeadlineExceeded {
            operation: "create asset if absent",
            stage: "asset insert",
            commit_started: false,
        }),
        AssetCreateFailureDisposition::DefinitelyNotPublished
    );
}

fn committed_asset(storage_uri: Option<&str>) -> StoredAsset {
    StoredAsset {
        id: "tenant-a:cli_tool:hello:1.0.0".into(),
        tenant_id: "tenant-a".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "hello".into(),
        version: "1.0.0".into(),
        content_type: "text/plain".into(),
        content_hash: "a".repeat(64),
        size_bytes: 42,
        content: Vec::new(),
        storage_uri: storage_uri.map(str::to_string),
        variant: String::new(),
        yanked: false,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn repeated_commit_is_idempotent_only_for_matching_bucket_metadata() {
    let asset_id = "tenant-a:cli_tool:hello:1.0.0";
    let upload_id = "upl_0123456789abcdef0123456789abcdef";
    let storage_uri = format!(
        "{}obj_{}",
        final_object_prefix(asset_id, upload_id),
        "c".repeat(32)
    );
    let bucket_asset = committed_asset(Some(&storage_uri));
    assert!(existing_asset_matches_commit(
        &bucket_asset,
        asset_id,
        upload_id,
        42,
        &"a".repeat(64),
        "text/plain",
    ));
    assert!(!existing_asset_matches_commit(
        &bucket_asset,
        asset_id,
        upload_id,
        43,
        &"a".repeat(64),
        "text/plain",
    ));
    assert!(!existing_asset_matches_commit(
        &bucket_asset,
        asset_id,
        upload_id,
        42,
        &"b".repeat(64),
        "text/plain",
    ));
    assert!(!existing_asset_matches_commit(
        &bucket_asset,
        asset_id,
        upload_id,
        42,
        &"a".repeat(64),
        "application/octet-stream",
    ));
    assert!(!existing_asset_matches_commit(
        &bucket_asset,
        asset_id,
        "upl_fedcba9876543210fedcba9876543210",
        42,
        &"a".repeat(64),
        "text/plain",
    ));

    let inline_asset = committed_asset(None);
    assert!(!existing_asset_matches_commit(
        &inline_asset,
        asset_id,
        upload_id,
        42,
        &"a".repeat(64),
        "text/plain",
    ));
}
