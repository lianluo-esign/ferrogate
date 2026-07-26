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

use ferrogate_storage::{sha256_hex, stored_asset_id, StorageError, StoredAsset};

use super::{
    asset_create_failure_disposition, classify_abort, effective_max_object_bytes,
    existing_asset_matches_commit, final_object_prefix, is_upload_id, new_upload_id,
    staging_object_key, verify_and_fetch_committed_object, AbortReason, AbortRecord,
    AssetCreateFailureDisposition, CommitVerification, PresignAbortRequest, PresignCommitRequest,
    PresignUploadIntentRequest, StagingReclamation,
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
            while let Some(method) = read_one_request(&mut stream) {
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
fn effective_per_object_ceiling_is_plan_quota_driven_with_a_global_default() {
    // #259: the per-object ceiling replaces a fixed constant with a
    // plan/quota-driven limit. A tenant with no dedicated per-object ceiling and
    // no cumulative quota (unlimited storage) keeps the operator's global
    // ceiling as the sane default.
    assert_eq!(
        effective_max_object_bytes(5 * 1024 * 1024 * 1024, None, None),
        5 * 1024 * 1024 * 1024
    );
    // A tenant whose cumulative quota is SMALLER than the global ceiling is
    // capped to its quota: a single object can never exceed the whole tenant
    // quota. (The dedicated per-object ceiling is unset here.)
    assert_eq!(
        effective_max_object_bytes(5 * 1024 * 1024 * 1024, None, Some(50 * 1024 * 1024)),
        50 * 1024 * 1024
    );
    // A tenant whose cumulative quota is LARGER than the global ceiling stays
    // bounded by the operator ceiling (the tighter always wins).
    assert_eq!(
        effective_max_object_bytes(1024 * 1024, None, Some(10 * 1024 * 1024 * 1024)),
        1024 * 1024
    );
    // Equal bounds resolve to that shared value.
    assert_eq!(effective_max_object_bytes(4096, None, Some(4096)), 4096);
    // A zero cumulative quota admits nothing -- degenerate but well-defined.
    assert_eq!(effective_max_object_bytes(4096, None, Some(0)), 0);
}

#[test]
fn dedicated_per_object_ceiling_binds_independently_of_the_cumulative_quota() {
    // #259: the dedicated per-object ceiling can be TIGHTER than the cumulative
    // quota and wins, even though the tenant's whole-store budget is far larger.
    assert_eq!(
        effective_max_object_bytes(
            5 * 1024 * 1024 * 1024,        // global operator ceiling (loose)
            Some(1024 * 1024),             // dedicated per-object ceiling (1 MiB)
            Some(10 * 1024 * 1024 * 1024), // cumulative quota (10 GiB, loose)
        ),
        1024 * 1024
    );
    // The cumulative quota can still bind tighter than the per-object ceiling --
    // the min of all three always wins.
    assert_eq!(
        effective_max_object_bytes(5000, Some(4096), Some(1024)),
        1024
    );
    // A None per-object ceiling is a NO-OP: behavior is exactly the old
    // min(global, cumulative).
    assert_eq!(effective_max_object_bytes(5000, None, Some(2048)), 2048);
    assert_eq!(effective_max_object_bytes(5000, None, None), 5000);
    // A per-object ceiling looser than both global and cumulative doesn't
    // loosen anything -- the tighter of the other two still wins.
    assert_eq!(
        effective_max_object_bytes(4096, Some(1024 * 1024), Some(8192)),
        4096
    );
    // A zero per-object ceiling admits nothing -- degenerate but well-defined.
    assert_eq!(effective_max_object_bytes(4096, Some(0), None), 0);
}

#[test]
fn presigned_read_path_issues_a_short_ttl_signed_url_never_a_public_object_url() {
    // #259 private-bucket read path: an authorized tenant's download resolves to
    // a gateway-issued presigned GET, so reads never require the bucket to be
    // public. Prove the URL is a short-TTL SigV4-signed URL, not a bare public
    // object URL, and that it never embeds the secret access key.
    let bucket = test_bucket("http://127.0.0.1:9".to_string());
    let ttl = 900_u64;
    let url = bucket
        .presign_get(".ferrogate/objects/abc/obj_deadbeef", ttl, 1_700_000_000)
        .expect("presign_get builds a signed URL");
    // Signed: carries the SigV4 query parameters and a bounded expiry.
    assert!(
        url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"),
        "url must be SigV4-signed: {url}"
    );
    assert!(
        url.contains("X-Amz-Signature="),
        "url must carry a signature: {url}"
    );
    assert!(
        url.contains(&format!("X-Amz-Expires={ttl}")),
        "url must carry the short TTL: {url}"
    );
    // Not a bare public object URL: a public URL would be the object path with
    // no signing query string at all.
    assert!(
        url.contains('?'),
        "a presigned URL must carry a query string: {url}"
    );
    // The signing secret must never appear in a URL handed to a client.
    assert!(
        !url.contains("wJalrXUtnFEMI"),
        "the secret access key must never be embedded in a presigned URL: {url}"
    );
}

#[test]
fn download_authorization_is_tenant_scoped_so_cross_tenant_reads_cannot_resolve() {
    // #259: the presigned download handler derives the asset id from the
    // AUTHENTICATED tenant (`stored_asset_id(tenant, ...)`), so a caller
    // authenticated as another tenant resolves a different id and misses -- the
    // storage-layer tenant-isolation bypass the public bucket allowed is closed
    // because the read path never trusts a caller-supplied object path.
    let owner = stored_asset_id("tenant-a", "cli_tool", "hello", "1.0.0");
    let cross_tenant = stored_asset_id("tenant-b", "cli_tool", "hello", "1.0.0");
    assert_ne!(
        owner, cross_tenant,
        "a cross-tenant caller must resolve a different asset id than the owner"
    );
    // The owning tenant's own request is stable and self-consistent.
    assert_eq!(
        owner,
        stored_asset_id("tenant-a", "cli_tool", "hello", "1.0.0")
    );
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
fn abort_request_requires_the_declarations_that_name_the_staging_object() {
    // #368: the staging key is H(asset_id|upload_id|size|sha256). A caller that
    // cannot restate all three cannot name -- and therefore cannot release --
    // an upload it did not register.
    let sha = "a".repeat(64);
    let abort: PresignAbortRequest = serde_json::from_str(&format!(
        r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42,"sha256":"{sha}","reason":"bucket_rejected"}}"#
    ))
    .expect("full abort body parses");
    assert_eq!(abort.size_bytes, 42);
    assert_eq!(
        AbortReason::parse(abort.reason.as_deref()),
        AbortReason::BucketRejected
    );

    // Missing declarations and unknown fields are typed failures, not defaults.
    for body in [
        format!(r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","sha256":"{sha}"}}"#),
        r#"{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42}"#.to_string(),
        format!(
            r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42,"sha256":"{sha}","extra":true}}"#
        ),
    ] {
        assert!(
            serde_json::from_str::<PresignAbortRequest>(&body).is_err(),
            "malformed abort body must be rejected: {body}"
        );
    }
}

#[test]
fn an_unrecognized_abort_reason_never_becomes_a_bucket_rejection_claim() {
    // #368: the reason decides which rejection class the evidence trail
    // records, so an absent/garbage value must degrade to the claim that costs
    // the least evidence -- never silently upgrade to `bucket_rejected`.
    assert_eq!(AbortReason::parse(None), AbortReason::Abandoned);
    assert_eq!(AbortReason::parse(Some("")), AbortReason::Abandoned);
    assert_eq!(
        AbortReason::parse(Some("abandoned")),
        AbortReason::Abandoned
    );
    assert_eq!(
        AbortReason::parse(Some("BUCKET_REJECTED")),
        AbortReason::Abandoned,
        "the enum is exact-match; a near-miss must not be honored"
    );
    assert_eq!(
        AbortReason::parse(Some("rejected_bucket")),
        AbortReason::Abandoned
    );
}

#[test]
fn a_bucket_rejection_is_recorded_only_when_the_gateway_corroborates_it() {
    use crate::state::AssetPresignOutcome;

    // The client says the bucket refused the PUT and the gateway does not
    // contradict it: no object exists under the staging key only the gateway
    // can derive. This is the ONLY input pair that produces bucket-rejection
    // evidence -- and even it is caller-asserted, not independently observed.
    assert_eq!(
        classify_abort(AbortReason::BucketRejected, StagingReclamation::NotStaged),
        AbortRecord {
            outcome: "rejected_bucket",
            metrics: &[AssetPresignOutcome::BucketRejected],
        }
    );
    // Contradicted: bytes ARE staged, so the bucket accepted the PUT. The
    // client's claim is downgraded rather than trusted -- without this, any
    // caller could inflate the bucket-rejection counter at will.
    assert_eq!(
        classify_abort(AbortReason::BucketRejected, StagingReclamation::Removed),
        AbortRecord {
            outcome: "aborted",
            metrics: &[AssetPresignOutcome::Aborted],
        }
    );
    // A plain abandonment makes no claim about the bucket either way.
    assert_eq!(
        classify_abort(AbortReason::Abandoned, StagingReclamation::NotStaged),
        AbortRecord {
            outcome: "aborted",
            metrics: &[AssetPresignOutcome::Aborted],
        }
    );
    assert_eq!(
        classify_abort(AbortReason::Abandoned, StagingReclamation::Removed),
        AbortRecord {
            outcome: "aborted",
            metrics: &[AssetPresignOutcome::Aborted],
        }
    );
}

#[test]
fn a_failed_reclamation_is_never_reported_as_a_successful_one() {
    use crate::state::AssetPresignOutcome;

    // #368: the abort surface exists to make reclamation *evidence*. The HEAD
    // says bytes were there; only the DELETE says they are gone. Rendering the
    // HEAD result as `staging_object_removed` told the client -- and the audit
    // trail, and the counter -- that a bucket 503/403 had freed the tenant's
    // quota. These three assertions are the whole invariant.
    assert!(!StagingReclamation::RemovalFailed.removed());
    assert!(StagingReclamation::Removed.removed());
    assert!(!StagingReclamation::NotStaged.removed());

    // The tri-state is typed on the wire, so a client can tell "nothing to
    // reclaim" from "reclaimed" from "still in the bucket".
    assert_eq!(StagingReclamation::NotStaged.as_str(), "not_staged");
    assert_eq!(StagingReclamation::Removed.as_str(), "removed");
    assert_eq!(StagingReclamation::RemovalFailed.as_str(), "removal_failed");

    // A failed reclaim gets its own audit outcome (filterable, not buried in
    // the detail prose) and a second counter mirroring the GC path's
    // `asset_lifecycle_failed_total`. It still counts as an abort: the intent
    // WAS released, it is the bytes that were not.
    for reason in [AbortReason::Abandoned, AbortReason::BucketRejected] {
        assert_eq!(
            classify_abort(reason, StagingReclamation::RemovalFailed),
            AbortRecord {
                outcome: "aborted_reclaim_failed",
                metrics: &[
                    AssetPresignOutcome::Aborted,
                    AssetPresignOutcome::AbortReclaimFailed,
                ],
            },
            "a refused delete must not be recorded as a clean abort"
        );
    }
}

#[test]
fn presign_outcomes_land_in_separate_operator_counters() {
    // #368 acceptance: operator metrics must distinguish intent rejection,
    // bucket rejection, and commit rejection (orphan GC has its own
    // `asset_lifecycle_*` counters). Record one of each plus the ambiguous
    // `staging_missing` class and assert nothing bleeds across.
    use crate::state::{AppState, AssetPresignOutcome};

    let state = AppState::new(crate::config::Config::default());
    state.record_asset_presign_outcome(AssetPresignOutcome::IntentIssued);
    state.record_asset_presign_outcome(AssetPresignOutcome::IntentIssued);
    state.record_asset_presign_outcome(AssetPresignOutcome::IntentRejected);
    state.record_asset_presign_outcome(AssetPresignOutcome::BucketRejected);
    state.record_asset_presign_outcome(AssetPresignOutcome::StagingMissing);
    state.record_asset_presign_outcome(AssetPresignOutcome::CommitRejected);
    state.record_asset_presign_outcome(AssetPresignOutcome::Aborted);
    state.record_asset_presign_outcome(AssetPresignOutcome::AbortReclaimFailed);

    let snapshot = state.prometheus_metrics_snapshot();
    assert_eq!(snapshot.asset_presign_intent_issued_total, 2);
    assert_eq!(snapshot.asset_presign_intent_rejected_total, 1);
    assert_eq!(snapshot.asset_presign_bucket_rejected_total, 1);
    assert_eq!(snapshot.asset_presign_staging_missing_total, 1);
    assert_eq!(snapshot.asset_presign_commit_rejected_total, 1);
    assert_eq!(snapshot.asset_presign_aborted_total, 1);
    // A failed reclamation is its own series, so a stuck bucket cannot hide
    // inside a healthy-looking abort rate.
    assert_eq!(snapshot.asset_presign_abort_reclaim_failed_total, 1);
}

#[test]
fn commit_request_carries_typed_trust_inputs_for_the_shared_screening_service() {
    // #366: the presigned commit body carries the same signature/visibility/
    // approval inputs the inline push carries via headers, so the SAME
    // screening service runs over the final verified bytes.
    let commit: PresignCommitRequest = serde_json::from_str(&format!(
        r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42,"sha256":"{}",
             "content_type":"application/octet-stream","signature":"c2ln","signature_format":"ed25519",
             "signature_key_id":"pub-1","visibility":"public","approval_id":"appr-9"}}"#,
        "a".repeat(64)
    ))
    .expect("commit with trust inputs parses");

    let signature = commit.signature_input().expect("signature input built");
    assert!(matches!(
        signature.format,
        crate::gateway::asset_signature::SignatureFormat::Ed25519
    ));
    assert_eq!(signature.material, "c2ln");
    assert_eq!(signature.key_id.as_deref(), Some("pub-1"));
    assert_eq!(
        commit.publish_visibility(),
        crate::gateway::asset_publish_gate::PublishVisibility::Public
    );
    assert_eq!(commit.approval_id.as_deref(), Some("appr-9"));
}

#[test]
fn commit_request_defaults_trust_inputs_when_omitted() {
    // An unsigned tenant-private publish sends no trust fields: unsigned, and
    // tenant-private visibility (the same defaults as the inline path).
    let commit: PresignCommitRequest = serde_json::from_str(&format!(
        r#"{{"upload_id":"upl_0123456789abcdef0123456789abcdef","size_bytes":42,"sha256":"{}"}}"#,
        "a".repeat(64)
    ))
    .expect("minimal commit parses");
    assert!(commit.signature_input().is_none());
    assert_eq!(
        commit.publish_visibility(),
        crate::gateway::asset_publish_gate::PublishVisibility::TenantPrivate
    );
    assert!(commit.approval_id.is_none());
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
        visibility: Default::default(),
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
