// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Docker-free E2E coverage for the #368 size+checksum-bound
// presigned staging upload path (gate-owned harness growth).

//! End-to-end proof, over a REAL gateway process and a checksum-enforcing
//! local SigV4 bucket double, of the two #368 acceptance boxes that had no
//! runnable harness scenario:
//!
//! * **The intent's contract is enforced, not advisory.** The upload intent
//!   returns `required_headers` / `max_object_bytes` / `upload_protocol` /
//!   `expires_in_seconds`, a client that follows them uploads successfully, and
//!   four separate deviations (omitted signed header, wrong declared checksum,
//!   a larger payload with an honestly-updated length + checksum, and a replay
//!   of the same URL with different bytes) are each refused **at the bucket**,
//!   before the gateway's commit-time verification ever runs.
//!
//! * **The four rejection classes are separately observable.** Intent
//!   rejection, bucket rejection, commit rejection and orphan GC each land in
//!   their own `/metrics` series AND their own audit `action`/`outcome` pair,
//!   driven here by really provoking each one rather than by poking counters.
//!
//! The bucket mock verifies every request's SigV4 independently of the gateway
//! (it holds only the shared secret) and refuses anything that does not verify
//! with a 403. It also re-hashes the body against `x-amz-content-sha256`, which
//! is the behavior this harness needs for bucket-boundary byte-substitution
//! coverage. Live Supabase Storage parity remains the separate env-gated probe
//! in `supabase_storage_s3_live.rs`.
//!
//! No load, stress or sustained-throughput traffic: the scenario issues a few
//! dozen small requests against a local mock, and never touches Supabase.

use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{free_addr, http_request_addr, HttpResponse},
};
use anyhow::{bail, Context, Result};
use ferrogate_providers::{
    presign_sigv4_query, presign_sigv4_query_bound, sign_sigv4_with_content_hash_header,
    AwsCredentials, PresignBoundPayload, PresignRequest, SigningRequest,
};
use ferrogate_storage::sha256_hex;
use serde_json::Value;
use std::{
    collections::HashMap,
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

#[path = "asset_buffer_admission.rs"]
mod asset_buffer_admission;

pub(crate) use asset_buffer_admission::run_asset_buffer_admission;

const ADMIN_AUTH: &str = "Authorization: Bearer presign-e2e-admin-secret";
const CLIENT_AUTH: &str = "Authorization: Bearer presign-e2e-client-secret";
const TENANT: &str = "org_presign_e2e";
const BUCKET: &str = "ferrogate-presign-harness";
const REGION: &str = "us-east-1";
const ACCESS_KEY_ID: &str = "AKIDPRESIGNHARNESS";
const SECRET_ACCESS_KEY: &str = "presign-harness-secret-access-key";
const SECRET_ENV: &str = "FERROGATE_HARNESS_PRESIGN_BUCKET_SECRET";
const PRESIGN_TTL_SECS: u64 = 120;
/// Deliberately small so an over-ceiling intent is a one-line request rather
/// than a large upload -- the ceiling rejection is a preflight, no bytes move.
const MAX_OBJECT_BYTES: u64 = 4096;
const ASSET_SCANNER_ENV_KEYS: &[&str] = &[
    "FERROGATE_ASSET_SCANNER",
    "FERROGATE_ASSET_SCANNER_ADDR",
    "FERROGATE_ASSET_SCANNER_ENDPOINT",
    "FERROGATE_ASSET_SCANNER_UNAVAILABLE",
    "FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES",
    "FERROGATE_ASSET_SCANNER_TIMEOUT_SECS",
];

pub(crate) fn run_asset_presign_api(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let content = b"#!/bin/sh\necho ferrogate presign harness\n".to_vec();
    let (bucket_endpoint, bucket) = spawn_sigv4_bucket_mock()?;
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("asset-presign.yaml");
    fs::write(
        &config_path,
        scenario_config(&gateway_addr, &bucket_endpoint),
    )?;
    // The threshold is strict (`size > threshold`): this fixture remains the
    // clean 200 control, while the one-byte-larger fixture below is withheld.
    let _gateway = GatewayGuard::start(
        &args.ferrogate_bin,
        &config_path,
        &gateway_addr,
        content.len(),
    )?;

    // Asset hosting is plan-gated: the presign routes require it.
    expect_created(
        http_request_addr(
            &gateway_addr,
            "POST",
            "/admin/v1/plans",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"id":"presign-e2e-plan","name":"Presign E2E plan","slug":"presign-e2e-plan","asset_hosting_enabled":true}"#,
        )?,
        "create hosting plan",
    )?;
    expect_created(
        http_request_addr(
            &gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"{TENANT}","name":"Presign E2E","slug":"presign-e2e","plan_id":"presign-e2e-plan"}}"#
            ),
        )?,
        "create hosting tenant",
    )?;

    let sha = sha256_hex(&content);

    // ---- 1. The intent publishes the exact contract for the direct PUT. ----
    let intent = json(&register_intent(
        &gateway_addr,
        "harness-tool",
        "1.0.0",
        content.len() as u64,
        &sha,
    )?)?;
    check(intent["method"] == "PUT", "intent method must be PUT")?;
    check(
        intent["upload_protocol"] == "single_put",
        "multipart behaviour must be typed as an explicit upload_protocol",
    )?;
    check(
        intent["max_object_bytes"] == MAX_OBJECT_BYTES,
        "the per-object ceiling must be echoed on the intent",
    )?;
    check(
        intent["expires_in_seconds"] == PRESIGN_TTL_SECS,
        "the URL expiry must be explicit on the intent",
    )?;
    let required = intent["required_headers"]
        .as_object()
        .context("intent must return required_headers")?;
    check(
        required.len() == 2
            && required.get("content-length").and_then(Value::as_str)
                == Some(&content.len().to_string())
            && required.get("x-amz-content-sha256").and_then(Value::as_str) == Some(sha.as_str()),
        "required_headers must name exactly the signed content-length + payload checksum",
    )?;
    let upload_url = intent["upload_url"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let upload_id = intent["upload_id"].as_str().unwrap_or_default().to_string();
    let staging_path = object_path(&upload_url);

    // ---- 2. Every deviation from that contract is refused at the bucket. ----
    let honest = [("x-amz-content-sha256", sha.as_str())];

    let omitted = direct_put(&upload_url, &content, &[])?;
    check(
        omitted == 403,
        &format!(
            "omitting the signed checksum header must be refused by the bucket, got {omitted}"
        ),
    )?;

    let wrong_checksum_value = sha256_hex(b"a checksum the gateway never approved");
    let wrong_checksum = direct_put(
        &upload_url,
        &content,
        &[("x-amz-content-sha256", wrong_checksum_value.as_str())],
    )?;
    check(
        wrong_checksum == 403,
        &format!(
            "a declared checksum other than the signed one must be refused, got {wrong_checksum}"
        ),
    )?;

    // The quota-burn attack the issue exists to stop: a larger payload with an
    // honestly restated length AND checksum. Both are signed, so it cannot verify.
    let mut oversized = content.clone();
    oversized.extend_from_slice(&b"x".repeat(512));
    let oversized_sha = sha256_hex(&oversized);
    let bigger = direct_put(
        &upload_url,
        &oversized,
        &[("x-amz-content-sha256", oversized_sha.as_str())],
    )?;
    check(
        bigger == 403,
        &format!("an upload larger than the signed content-length must be refused, got {bigger}"),
    )?;

    // A replay presents the ORIGINAL signed headers with different bytes.
    let mut tampered = content.clone();
    tampered[0] = b'@';
    let replay = direct_put(&upload_url, &tampered, &honest)?;
    check(
        replay == 403,
        &format!("a replay with different bytes must be refused, got {replay}"),
    )?;

    check(
        !bucket.lock().unwrap().objects.contains_key(&staging_path),
        "no refused upload may leave staging bytes in the bucket",
    )?;

    // ---- 3. A client that follows the contract succeeds and commits. ----
    let accepted = direct_put(&upload_url, &content, &honest)?;
    check(
        accepted == 200,
        &format!("the contract-following upload must be accepted, got {accepted}"),
    )?;
    let committed = http_request_addr(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/harness-tool/1.0.0",
        &[CLIENT_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha}","content_type":"application/x-shellscript"}}"#,
            content.len()
        ),
    )?;
    check(
        committed.status == 200,
        &format!(
            "commit of the contract-following upload failed: {}",
            committed.raw
        ),
    )?;

    // ---- 3b. A valid presigned upload can still be withheld by screening. ----
    verify_withheld_presigned_commit(&gateway_addr, content.len())?;

    // ---- 4. Provoke each of the four rejection classes for real. ----

    // (a) intent rejection: over the per-object ceiling, before any URL exists.
    let over_ceiling = register_intent(
        &gateway_addr,
        "too-big",
        "1.0.0",
        MAX_OBJECT_BYTES + 1,
        &sha,
    )?;
    check(
        over_ceiling.status == 413,
        &format!(
            "an over-ceiling intent must be a typed 413: {}",
            over_ceiling.raw
        ),
    )?;

    // (b) commit rejection: staged bytes the gateway's own verification refuses,
    // which is a DIFFERENT boundary from the bucket's signature check above.
    let rejected = provoke_commit_rejection(&gateway_addr, &bucket)?;
    check(
        rejected.status == 422,
        &format!(
            "a staged object failing commit verification must be a typed 422: {}",
            rejected.raw
        ),
    )?;

    // (c) bucket rejection: a client whose direct PUT was refused reports it,
    // and the gateway corroborates the report against the staging key.
    let refused = json(&register_intent(
        &gateway_addr,
        "bucket-refused",
        "1.0.0",
        content.len() as u64,
        &sha,
    )?)?;
    let refused_upload_id = refused["upload_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let abort = http_request_addr(
        &gateway_addr,
        "POST",
        "/v1/assets/presign/abort/cli_tool/bucket-refused/1.0.0",
        &[CLIENT_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"upload_id":"{refused_upload_id}","size_bytes":{},"sha256":"{sha}","reason":"bucket_rejected"}}"#,
            content.len()
        ),
    )?;
    check(
        abort.status == 200,
        &format!("the abort surface must answer: {}", abort.raw),
    )?;
    let abort_body = json(&abort)?;
    check(
        abort_body["outcome"] == "rejected_bucket"
            && abort_body["staging_reclamation"] == "not_staged"
            && abort_body["staging_object_removed"] == false,
        &format!(
            "a corroborated bucket refusal must be typed as one: {}",
            abort.raw
        ),
    )?;

    // ---- 5. All four classes are separately observable in metrics. ----
    let metrics = http_request_addr(&gateway_addr, "GET", "/metrics", &[ADMIN_AUTH], "")?;
    check(
        metrics.status == 200,
        &format!("metrics scrape failed: {}", metrics.raw),
    )?;
    for series in [
        "ferrogate_asset_presign_rejected_total{stage=\"intent\"} 1",
        "ferrogate_asset_presign_rejected_total{stage=\"bucket\"} 1",
        "ferrogate_asset_presign_rejected_total{stage=\"commit\"} 1",
    ] {
        check(
            metrics.body.contains(series),
            &format!("metrics must carry `{series}` exactly once each, so the classes cannot be conflated"),
        )?;
    }
    check(
        metrics
            .body
            .contains("ferrogate_asset_lifecycle_pruned_total"),
        "orphan GC must stay its own series rather than folding into a rejection stage",
    )?;
    check(
        metrics
            .body
            .contains("ferrogate_asset_presign_intents_issued_total"),
        "issued intents must be countable as the denominator for every rejection stage",
    )?;

    // ---- 6. …and in the audit trail, as distinct action/outcome pairs. ----
    let audit = http_request_addr(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &[ADMIN_AUTH],
        "",
    )?;
    let events = json(&audit)?;
    let events = events["data"]
        .as_array()
        .context("audit-events must return a data array")?
        .clone();
    for (action, outcome) in [
        ("asset.presign_upload_intent", "rejected_intent"),
        ("asset.presign_upload_abort", "rejected_bucket"),
        ("asset.push", "rejected_commit"),
        ("asset.push", "committed"),
    ] {
        check(
            events
                .iter()
                .any(|event| event["action"] == action && event["outcome"] == outcome),
            &format!("missing distinct audit evidence for {action}/{outcome}"),
        )?;
    }
    check(
        !events
            .iter()
            .any(|event| event["action"] == "asset.push" && event["outcome"] == "rejected_bucket"),
        "commit-time absence must never be audited as a bucket rejection",
    )?;

    // ---- 7. The bucket only ever refused the deliberate deviations. ----
    let state = bucket.lock().unwrap();
    let refusals: Vec<_> = state
        .requests
        .iter()
        .filter(|request| !request.signature_valid)
        .collect();
    check(
        refusals.len() == 4 && refusals.iter().all(|request| request.method == "PUT"),
        &format!(
            "exactly the four deliberate deviations must fail SigV4 verification, saw {refusals:?}"
        ),
    )?;
    drop(state);

    println!("asset-presign-api scenario passed");
    Ok(())
}

/// #528 at the presigned terminal, including its idempotent replay. The upload
/// is valid at the bucket and commit verifier; only the async scan threshold
/// withholds it. Both the first commit and an identical retry must preserve the
/// exact 202 + pending_scan contract instead of flattening to a successful 200.
fn verify_withheld_presigned_commit(gateway_addr: &str, threshold_bytes: usize) -> Result<()> {
    let content = vec![b'p'; threshold_bytes + 1];
    let sha = sha256_hex(&content);
    let intent = json(&register_intent(
        gateway_addr,
        "presign-withheld",
        "1.0.0",
        content.len() as u64,
        &sha,
    )?)?;
    let upload_url = intent["upload_url"]
        .as_str()
        .context("withheld presign intent omitted upload_url")?;
    let upload_id = intent["upload_id"]
        .as_str()
        .context("withheld presign intent omitted upload_id")?;
    let uploaded = direct_put(
        upload_url,
        &content,
        &[("x-amz-content-sha256", sha.as_str())],
    )?;
    check(
        uploaded == 200,
        &format!("the withheld fixture must first reach the bucket, got {uploaded}"),
    )?;

    let commit_path = "/v1/assets/presign/commit/cli_tool/presign-withheld/1.0.0";
    let commit_body = format!(
        r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha}","content_type":"application/octet-stream"}}"#,
        content.len()
    );
    for attempt in ["initial commit", "idempotent re-commit"] {
        let committed = http_request_addr(
            gateway_addr,
            "POST",
            commit_path,
            &[CLIENT_AUTH, JSON_CONTENT],
            &commit_body,
        )?;
        check(
            committed.status == 202,
            &format!(
                "withheld presigned {attempt} must answer exactly 202 Accepted: {}",
                committed.raw
            ),
        )?;
        let body = json(&committed)?;
        check(
            body["asset"]["visibility"] == "pending_scan",
            &format!(
                "withheld presigned {attempt} must report pending_scan: {}",
                committed.body
            ),
        )?;
    }

    let get = http_request_addr(
        gateway_addr,
        "GET",
        "/v1/assets/cli_tool/presign-withheld/1.0.0",
        &[CLIENT_AUTH],
        "",
    )?;
    check(
        get.status == 404,
        &format!(
            "pending presigned bytes must not be downloadable: {}",
            get.raw
        ),
    )?;
    let listed = http_request_addr(gateway_addr, "GET", "/v1/assets", &[CLIENT_AUTH], "")?;
    let rows = json(&listed)?["data"]
        .as_array()
        .context("asset list must return a data array")?
        .clone();
    check(
        !rows.iter().any(|row| row["name"] == "presign-withheld"),
        "pending presigned asset must be absent from the normal registry list",
    )
}

/// Drives the commit-time verification failure: an intent is registered and its
/// bytes staged, then the staged object is replaced out-of-band with different
/// bytes of a different length, so the gateway's HEAD/GET verification refuses
/// the commit that the bucket itself accepted.
fn provoke_commit_rejection(
    gateway_addr: &str,
    bucket: &Arc<Mutex<BucketState>>,
) -> Result<HttpResponse> {
    let body = b"the declared commit payload".to_vec();
    let sha = sha256_hex(&body);
    let intent = json(&register_intent(
        gateway_addr,
        "commit-verify",
        "1.0.0",
        body.len() as u64,
        &sha,
    )?)?;
    let url = intent["upload_url"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let upload_id = intent["upload_id"].as_str().unwrap_or_default().to_string();
    let staging = object_path(&url);
    let uploaded = direct_put(&url, &body, &[("x-amz-content-sha256", sha.as_str())])?;
    check(
        uploaded == 200,
        "the commit-verification fixture must stage its bytes",
    )?;
    // Out-of-band substitution: models a bucket that accepted bytes the gateway
    // did not approve (a misconfigured policy, a second writer, an object-store
    // bug). The commit-time verification is the control that must still refuse.
    bucket
        .lock()
        .unwrap()
        .objects
        .insert(staging, b"different bytes of a different length".to_vec());
    http_request_addr(
        gateway_addr,
        "POST",
        "/v1/assets/presign/commit/cli_tool/commit-verify/1.0.0",
        &[CLIENT_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"upload_id":"{upload_id}","size_bytes":{},"sha256":"{sha}","content_type":"text/plain"}}"#,
            body.len()
        ),
    )
}

fn register_intent(
    gateway_addr: &str,
    name: &str,
    version: &str,
    size_bytes: u64,
    sha256: &str,
) -> Result<HttpResponse> {
    http_request_addr(
        gateway_addr,
        "POST",
        &format!("/v1/assets/presign/upload/cli_tool/{name}/{version}"),
        &[CLIENT_AUTH, JSON_CONTENT],
        &format!(r#"{{"size_bytes":{size_bytes},"sha256":"{sha256}"}}"#),
    )
}

fn json(response: &HttpResponse) -> Result<Value> {
    serde_json::from_str(&response.body)
        .with_context(|| format!("response body is not JSON: {}", response.raw))
}

fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        bail!("{message}")
    }
}

fn expect_created(response: HttpResponse, what: &str) -> Result<()> {
    if response.status == 200 || response.status == 201 {
        Ok(())
    } else {
        bail!("failed to {what}: {}", response.raw)
    }
}

fn object_path(url: &str) -> String {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (_, target) = rest.split_once('/').unwrap_or((rest, ""));
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    format!("/{path}")
}

/// One raw direct-to-bucket PUT. `Content-Length` is always derived from the
/// body, exactly as a real HTTP client does, so a tampered payload declares its
/// own real length; `extra` carries the intent's remaining required headers.
fn direct_put(url: &str, body: &[u8], extra: &[(&str, &str)]) -> Result<u16> {
    let rest = url
        .strip_prefix("http://")
        .context("bucket URL must be http")?;
    let (authority, target) = rest.split_once('/').context("presigned URL needs a path")?;
    let mut stream = TcpStream::connect(authority)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let headers = extra
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    write!(
        stream,
        "PUT /{target} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let text = String::from_utf8_lossy(&response);
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .with_context(|| format!("unparsable bucket response: {text}"))
}

#[derive(Debug, Clone)]
struct CapturedRequest {
    method: String,
    signature_valid: bool,
}

#[derive(Debug, Default)]
struct BucketState {
    objects: HashMap<String, Vec<u8>>,
    requests: Vec<CapturedRequest>,
    blocked_get_path: Option<String>,
    get_gate: Option<Arc<BucketGetGate>>,
}

#[derive(Debug, Default)]
struct BucketGetGate {
    state: Mutex<BucketGetGateState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct BucketGetGateState {
    started: usize,
    released: bool,
}

impl BucketGetGate {
    fn arrive_and_wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.started += 1;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_for_started(&self, expected: usize, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        while state.started < expected {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                bail!(
                    "timed out waiting for {expected} bucket GETs; only {} arrived",
                    state.started
                );
            };
            let (next, result) = self.changed.wait_timeout(state, remaining).unwrap();
            state = next;
            if result.timed_out() && state.started < expected {
                bail!(
                    "timed out waiting for {expected} bucket GETs; only {} arrived",
                    state.started
                );
            }
        }
        Ok(())
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }
}

/// A minimal S3-compatible endpoint that independently verifies the SigV4 of
/// every request it receives and 403s anything that does not verify. It holds
/// only the shared secret, so it can refuse exactly what a real bucket refuses.
fn spawn_sigv4_bucket_mock() -> Result<(String, Arc<Mutex<BucketState>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let state = Arc::new(Mutex::new(BucketState::default()));
    let server_state = Arc::clone(&state);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let connection_state = Arc::clone(&server_state);
            thread::spawn(move || {
                let _ = handle_bucket_connection(stream, connection_state);
            });
        }
    });
    Ok((endpoint, state))
}

struct RawRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn handle_bucket_connection(mut stream: TcpStream, state: Arc<Mutex<BucketState>>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let Some(request) = read_raw_request(&mut stream) else {
        return Ok(());
    };
    let (path, query) = request
        .target
        .split_once('?')
        .map_or((request.target.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    let signature_valid = verify_sigv4(&request, path, query).is_ok();

    let mut state = state.lock().unwrap();
    state.requests.push(CapturedRequest {
        method: request.method.clone(),
        signature_valid,
    });
    if !signature_valid {
        return write_response(&mut stream, "403 Forbidden", b"invalid SigV4", None);
    }
    match request.method.as_str() {
        "PUT" => {
            state.objects.insert(path.to_string(), request.body);
            write_response(&mut stream, "200 OK", b"", None)
        }
        "HEAD" => match state.objects.get(path) {
            Some(bytes) => write_response(&mut stream, "200 OK", b"", Some(bytes.len())),
            None => write_response(&mut stream, "404 Not Found", b"", None),
        },
        "GET" => {
            let bytes = state.objects.get(path).cloned();
            let get_gate = state
                .get_gate
                .as_ref()
                .filter(|_| state.blocked_get_path.as_deref() == Some(path))
                .cloned();
            drop(state);
            if let Some(gate) = get_gate {
                gate.arrive_and_wait();
            }
            match bytes {
                Some(bytes) => write_response(&mut stream, "200 OK", &bytes, None),
                None => write_response(&mut stream, "404 Not Found", b"", None),
            }
        }
        "DELETE" => {
            state.objects.remove(path);
            write_response(&mut stream, "204 No Content", b"", None)
        }
        _ => write_response(&mut stream, "405 Method Not Allowed", b"", None),
    }
}

/// Recomputes the presigned signature with the S3-compatible
/// UNSIGNED-PAYLOAD canonical line. For a bound presigned upload the
/// declared length and checksum are ALSO checked against the bytes actually
/// received, which is what makes "wrong size" and "wrong checksum"
/// bucket-boundary rejections in this local harness rather than gateway-side
/// ones.
fn verify_sigv4(request: &RawRequest, path: &str, query: Option<&str>) -> Result<()> {
    let host = request.headers.get("host").context("missing Host")?;
    let credentials = AwsCredentials {
        access_key_id: ACCESS_KEY_ID.to_string(),
        secret_access_key: SECRET_ACCESS_KEY.to_string(),
        session_token: None,
    };
    let Some(query) = query else {
        let timestamp = request
            .headers
            .get("x-amz-date")
            .and_then(|value| parse_amz_timestamp(value))
            .context("missing x-amz-date")?;
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
        return check(
            request.headers.get("authorization") == Some(&expected.authorization),
            "header signature mismatch",
        );
    };
    if request.headers.contains_key("authorization") {
        bail!("a presigned request must not also carry Authorization");
    }
    let timestamp = raw_query_value(query, "X-Amz-Date")
        .and_then(|value| parse_amz_timestamp(&value))
        .context("missing X-Amz-Date")?;
    let expires_secs = raw_query_value(query, "X-Amz-Expires")
        .and_then(|value| value.parse::<u64>().ok())
        .context("missing X-Amz-Expires")?;
    let presign = PresignRequest {
        method: &request.method,
        path,
        host,
        region: REGION,
        service: "s3",
        expires_secs,
        timestamp_unix: timestamp,
    };
    let signed_headers =
        raw_query_value(query, "X-Amz-SignedHeaders").context("missing X-Amz-SignedHeaders")?;
    let expected = match signed_headers.as_str() {
        "content-length%3Bhost%3Bx-amz-content-sha256" => {
            let declared_length = request
                .headers
                .get("content-length")
                .and_then(|value| value.parse::<u64>().ok())
                .context("bound upload without content-length")?;
            let declared_sha = request
                .headers
                .get("x-amz-content-sha256")
                .context("bound upload without x-amz-content-sha256")?;
            if request.body.len() as u64 != declared_length {
                bail!("declared length does not match the received bytes");
            }
            if &sha256_hex(&request.body) != declared_sha {
                bail!("declared checksum does not match the received bytes");
            }
            presign_sigv4_query_bound(
                &presign,
                &credentials,
                &PresignBoundPayload {
                    content_length: declared_length,
                    content_sha256_hex: declared_sha,
                },
            )
            .query
        }
        "host" => presign_sigv4_query(&presign, &credentials),
        other => bail!("unsupported X-Amz-SignedHeaders: {other}"),
    };
    check(query == expected, "query signature mismatch")
}

fn raw_query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(key, _)| *key == name)
            .map(|(_, value)| value.to_string())
    })
}

/// `YYYYMMDDTHHMMSSZ` back to Unix seconds, so the mock re-signs at the same
/// instant the presigner used.
fn parse_amz_timestamp(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
    let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
    let year_adjusted = if month <= 2 { year - 1 } else { year };
    let era = if year_adjusted >= 0 {
        year_adjusted
    } else {
        year_adjusted - 399
    } / 400;
    let yoe = year_adjusted - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3600 + minute * 60 + second).ok()
}

fn read_raw_request(stream: &mut TcpStream) -> Option<RawRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let target = request_line.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Some(RawRequest {
        method,
        target,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    body: &[u8],
    content_length_override: Option<usize>,
) -> Result<()> {
    let length = content_length_override.unwrap_or(body.len());
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )?;
    stream.write_all(body)?;
    Ok(())
}

fn scenario_config(gateway_addr: &str, bucket_endpoint: &str) -> String {
    format!(
        r#"listen: {gateway_addr:?}
asset_bucket:
  enabled: true
  endpoint: {bucket_endpoint:?}
  bucket: {BUCKET:?}
  region: {REGION:?}
  access_key_id: {ACCESS_KEY_ID:?}
  secret_access_key_env: {SECRET_ENV:?}
  presign_ttl_secs: {PRESIGN_TTL_SECS}
  presign_max_object_bytes: {MAX_OBJECT_BYTES}
api_keys:
  - id: "presign-e2e-admin"
    name: "Presign E2E operator"
    key: "presign-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
    # #540: platform root is stated, never inherited from an omitted field.
    platform_operator: true
  - id: "presign-e2e-client"
    name: "Presign E2E tenant client"
    key: "presign-e2e-client-secret"
    scopes: ["assets.read", "assets.write"]
    organization_id: {TENANT:?}
    project_id: "project_presign_e2e"
"#
    )
}

struct GatewayGuard {
    child: Child,
}

impl GatewayGuard {
    fn start(
        binary: &Path,
        config_path: &Path,
        gateway_addr: &str,
        async_scan_threshold_bytes: usize,
    ) -> Result<Self> {
        let mut command = Command::new(binary);
        for key in ASSET_SCANNER_ENV_KEYS {
            command.env_remove(key);
        }
        let child = command
            .args(["run", "--config"])
            .arg(config_path)
            .env(SECRET_ENV, SECRET_ACCESS_KEY)
            .env(
                "FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES",
                async_scan_threshold_bytes.to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(
                if env::var("FERROGATE_TEST_DEBUG_STDERR").is_ok_and(|value| value == "1") {
                    Stdio::inherit()
                } else {
                    Stdio::null()
                },
            )
            .spawn()
            .with_context(|| format!("failed to start {}", binary.display()))?;
        let mut guard = Self { child };
        guard.wait_for_readiness(gateway_addr)?;
        Ok(guard)
    }

    fn wait_for_readiness(&mut self, gateway_addr: &str) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(180) {
            if let Some(status) = self.child.try_wait()? {
                bail!("FerroGate exited before asset-presign E2E readiness: {status}");
            }
            match http_request_addr(gateway_addr, "GET", "/healthz", &[], "") {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => last = response.raw,
                Err(error) => last = error.to_string(),
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!("timed out waiting for the asset-presign E2E gateway: {last}")
    }
}

impl Drop for GatewayGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
