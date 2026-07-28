// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Docker-free process-boundary coverage for issue #529's
// aggregate gateway asset-buffer admission contract.

//! A bounded, deterministic run against a real `ferrogate` process and the
//! SigV4-validating bucket double owned by `asset_presign`.
//!
//! This is intentionally a named harness command rather than another crate
//! integration test. It proves the operator-facing contract at the process
//! boundary: aggregate overload is typed, admitted bytes remain complete, the
//! charge survives slow response writers, and the streaming commit leg stays
//! independent from the buffering pool.

use super::*;
use crate::{
    cli::LocalArgs,
    constants::JSON_CONTENT,
    http::{http_request_addr, http_request_addr_bytes, HttpResponse},
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Barrier, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const OBJECT_BYTES: usize = 4 * 1024 * 1024;
const TOTAL_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const BUFFER_WAIT_MS: u64 = 150;
const READERS: usize = 24;
const RSS_GROWTH_CEILING_BYTES: u64 = 40 * 1024 * 1024;
const STORAGE_QUOTA_BYTES: usize = 64 * 1024 * 1024;
const STATIC_SITE: &str = "buffer-budget-site";
const STATIC_BYTES: usize = OBJECT_BYTES;
const BUFFERED_COMMIT_BYTES: usize = 1024 * 1024;
const STREAMING_COMMIT_BYTES: usize = OBJECT_BYTES + 1024 * 1024;

pub(crate) fn run_asset_buffer_admission(args: &LocalArgs) -> Result<()> {
    if !args.ferrogate_bin.exists() {
        bail!(
            "ferrogate binary does not exist at {}; run `cargo build -p ferrogate-cli` first or pass --ferrogate-bin",
            args.ferrogate_bin.display()
        );
    }

    let (bucket_endpoint, bucket) = spawn_sigv4_bucket_mock()?;
    let gateway_addr = free_addr()?;
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("asset-buffer-admission.yaml");
    fs::write(
        &config_path,
        scenario_config(&gateway_addr, &bucket_endpoint),
    )?;
    // Effectively disable asynchronous screening for these deterministic
    // fixtures while still clearing every inherited scanner selector.
    let gateway =
        GatewayGuard::start(&args.ferrogate_bin, &config_path, &gateway_addr, usize::MAX)?;
    let gateway_pid = gateway.child.id();

    bootstrap_tenant(&gateway_addr)?;
    let content = deterministic_bytes(OBJECT_BYTES, b'a');
    let content_sha = sha256_hex(&content);
    publish_presigned(
        &gateway_addr,
        "burst-object",
        "1.0.0",
        &content,
        "text/plain",
    )?;
    let burst_object_key = only_bucket_object_key(&bucket)?;

    verify_rest_burst(
        &gateway_addr,
        gateway_pid,
        &bucket,
        &burst_object_key,
        &content,
        &content_sha,
    )?;
    verify_slow_http_responses(
        &gateway_addr,
        "/v1/assets/cli_tool/burst-object/1.0.0",
        &[CLIENT_AUTH],
        &content,
        "REST asset pull",
    )?;
    verify_slow_mcp_responses(&gateway_addr, &content, "resources/read")?;
    verify_slow_mcp_responses(&gateway_addr, &content, "tools/call")?;
    verify_cross_surface_admission(&gateway_addr, &bucket, &burst_object_key, &content)?;

    println!(
        "asset-buffer-admission scenario passed: REST burst, MCP response residency, static-site shedding, buffered retry, and streaming commit"
    );
    Ok(())
}

fn bootstrap_tenant(gateway_addr: &str) -> Result<()> {
    expect_created(
        http_request_addr(
            gateway_addr,
            "POST",
            "/admin/v1/plans",
            &[ADMIN_AUTH, JSON_CONTENT],
            r#"{"id":"buffer-budget-plan","name":"Buffer budget plan","slug":"buffer-budget-plan","asset_hosting_enabled":true}"#,
        )?,
        "create buffer-budget hosting plan",
    )?;
    expect_created(
        http_request_addr(
            gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &[ADMIN_AUTH, JSON_CONTENT],
            &format!(
                r#"{{"id":"{TENANT}","name":"Buffer budget tenant","slug":"buffer-budget-tenant","plan_id":"buffer-budget-plan"}}"#
            ),
        )?,
        "create buffer-budget tenant",
    )?;
    let quota = http_request_addr(
        gateway_addr,
        "PUT",
        &format!("/admin/v1/quota-policies/tenant/{TENANT}"),
        &[ADMIN_AUTH, JSON_CONTENT],
        &format!(r#"{{"asset_storage_quota_bytes":{STORAGE_QUOTA_BYTES},"enabled":true}}"#),
    )?;
    check_response_status(&quota, 200, "configure asset storage quota")
}

fn verify_rest_burst(
    gateway_addr: &str,
    gateway_pid: u32,
    bucket: &Arc<Mutex<BucketState>>,
    object_key: &str,
    content: &[u8],
    content_sha: &str,
) -> Result<()> {
    let gate = install_bucket_get_gate(bucket, object_key);
    let baseline_rss = match resident_bytes(gateway_pid) {
        Ok(bytes) => bytes,
        Err(error) => {
            clear_bucket_get_gate(bucket);
            return Err(error);
        }
    };
    check(
        baseline_rss > TOTAL_BUFFER_BYTES as u64,
        "gateway RSS baseline is too small to be a credible live-process reading",
    )?;
    let sampler = RssSampler::start(gateway_pid);
    let barrier = Arc::new(Barrier::new(READERS + 1));
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let addr = gateway_addr.to_string();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                http_request_addr(
                    &addr,
                    "GET",
                    "/v1/assets/cli_tool/burst-object/1.0.0",
                    &[CLIENT_AUTH],
                    "",
                )
            })
        })
        .collect();
    barrier.wait();
    if let Err(error) = gate.wait_for_started(2, Duration::from_secs(10)) {
        gate.release();
        let _ = join_readers(readers);
        clear_bucket_get_gate(bucket);
        let _ = sampler.finish();
        return Err(error);
    }
    // Keep both admitted 4 MiB reads resident beyond the bounded admission
    // wait. The other 22 callers must resolve as typed load shedding.
    thread::sleep(Duration::from_millis(BUFFER_WAIT_MS + 100));
    gate.release();
    let responses = join_readers(readers);
    clear_bucket_get_gate(bucket);
    let peak_rss = sampler.finish();
    let responses = responses?;
    let peak_rss = peak_rss?;

    let mut served = 0;
    let mut shed = 0;
    for response in responses {
        match response.status {
            200 => {
                served += 1;
                check(
                    response.body.len() == content.len(),
                    "an admitted REST read returned a truncated body",
                )?;
                check(
                    sha256_hex(response.body.as_bytes()) == content_sha,
                    "an admitted REST read returned bytes that differ from the published object",
                )?;
            }
            503 => {
                shed += 1;
                assert_budget_error(&response, "REST asset pull")?;
            }
            status => bail!(
                "REST burst returned unexpected status {status}: {}",
                response.raw
            ),
        }
    }
    check(served > 0, "the aggregate budget admitted no REST reads")?;
    check(
        shed > 0,
        "24 legal REST reads against 8 MiB shed no callers",
    )?;

    let growth = peak_rss.saturating_sub(baseline_rss);
    check(
        growth < RSS_GROWTH_CEILING_BYTES,
        &format!(
            "REST burst grew gateway RSS by {growth} bytes (baseline {baseline_rss}, peak {peak_rss}); ceiling is {RSS_GROWTH_CEILING_BYTES}"
        ),
    )?;
    println!(
        "asset-buffer REST burst: served={served}, shed={shed}, baseline_rss={baseline_rss}, peak_rss={peak_rss}, growth={growth}"
    );
    Ok(())
}

/// A fast bucket plus slow clients proves the permit is tied to response
/// residency, not merely to the object-store GET. Two 4 MiB responses fill the
/// 8 MiB pool; a third request must shed until those response owners drop.
fn verify_slow_http_responses(
    gateway_addr: &str,
    path: &str,
    headers: &[&str],
    expected: &[u8],
    surface: &str,
) -> Result<()> {
    let mut stalled = vec![
        StalledHttpRequest::start(gateway_addr, "GET", path, headers, b"")?,
        StalledHttpRequest::start(gateway_addr, "GET", path, headers, b"")?,
    ];
    for request in &stalled {
        request.wait_for_response_head()?;
    }

    let later = http_request_addr(gateway_addr, "GET", path, headers, "")?;
    check_response_status(&later, 503, &format!("{surface} with two slow writers"))?;
    assert_budget_error(&later, surface)?;

    for request in stalled.drain(..) {
        let response_head = request.release_and_join()?;
        check(
            response_head.starts_with(b"HTTP/1.1 200"),
            &format!("the budget-holding {surface} response did not start with 200"),
        )?;
        check(
            response_content_length(&response_head)? == expected.len(),
            &format!("the budget-holding {surface} response declared a truncated body"),
        )?;
    }

    wait_for_http_budget_release(gateway_addr, path, headers, expected, surface)
}

fn wait_for_http_budget_release(
    gateway_addr: &str,
    path: &str,
    headers: &[&str],
    expected: &[u8],
    surface: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = http_request_addr(gateway_addr, "GET", path, headers, "")?;
        match response.status {
            200 => {
                return check(
                    response.body.as_bytes() == expected,
                    &format!("post-stall {surface} returned incomplete bytes"),
                );
            }
            503 if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            503 => bail!("{surface} permits were not released after clients disconnected"),
            status => bail!(
                "post-stall {surface} returned unexpected status {status}: {}",
                response.raw
            ),
        }
    }
}

fn verify_slow_mcp_responses(gateway_addr: &str, content: &[u8], method: &str) -> Result<()> {
    let request = match method {
        "resources/read" => {
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"asset://cli_tool/burst-object/1.0.0"}}"#
        }
        "tools/call" => {
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"builtin.fetch_asset","arguments":{"uri":"asset://cli_tool/burst-object/1.0.0"}}}"#
        }
        _ => bail!("unsupported MCP admission method {method}"),
    };
    let stalled = StalledHttpRequest::start(
        gateway_addr,
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        request.as_bytes(),
    )?;
    stalled.wait_for_response_head()?;

    let later = http_request_addr(
        gateway_addr,
        "POST",
        "/v1/mcp",
        &[CLIENT_AUTH, JSON_CONTENT],
        request,
    )?;
    check_response_status(&later, 200, "MCP JSON-RPC overload response")?;
    let later_json: Value = serde_json::from_str(&later.body)
        .with_context(|| format!("MCP overload response is not JSON: {}", later.raw))?;
    check(
        later_json["result"].is_null(),
        "a later MCP call succeeded while the first response still held the whole budget",
    )?;
    if !later.body.contains("max_total_gateway_buffer_bytes")
        || !later.body.contains("aggregate in-memory budget")
        || !later.body.contains("was shed")
    {
        bail!(
            "a later {method} call was not shed with the aggregate-budget reason: {}",
            later.raw
        );
    }
    if method == "resources/read" {
        check(
            later_json["error"]["code"] == -32005,
            "resources/read must use the dedicated -32005 aggregate-budget code",
        )?;
    } else {
        check(
            later_json["error"]["code"] == -32000,
            "tools/call must map the named tool execution overload to -32000",
        )?;
    }

    let first = stalled.release_and_join()?;
    let first_head = String::from_utf8_lossy(&first);
    check(
        first_head.starts_with("HTTP/1.1 200"),
        "the budget-holding MCP response did not begin successfully",
    )?;
    check(
        response_content_length(&first)? >= content.len(),
        "the budget-holding MCP response did not declare the complete inlined object",
    )?;
    wait_for_budget_release(gateway_addr, content)?;
    println!("asset-buffer MCP response residency: {method} later call shed as expected");
    Ok(())
}

fn wait_for_budget_release(gateway_addr: &str, expected: &[u8]) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = http_request_addr(
            gateway_addr,
            "GET",
            "/v1/assets/cli_tool/burst-object/1.0.0",
            &[CLIENT_AUTH],
            "",
        )?;
        match response.status {
            200 => {
                return check(
                    response.body.as_bytes() == expected,
                    "budget-release probe returned incomplete asset bytes",
                );
            }
            503 if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            503 => bail!("MCP response permit was not released after its client disconnected"),
            status => bail!(
                "budget-release probe returned unexpected status {status}: {}",
                response.raw
            ),
        }
    }
}

fn verify_cross_surface_admission(
    gateway_addr: &str,
    bucket: &Arc<Mutex<BucketState>>,
    object_key: &str,
    burst_content: &[u8],
) -> Result<()> {
    let static_content = publish_static_site(gateway_addr)?;
    verify_slow_http_responses(
        gateway_addr,
        &format!("/sites/{TENANT}/{STATIC_SITE}/"),
        &[],
        &static_content,
        "bucket-backed static-site serve",
    )?;
    let buffered = stage_presigned(
        gateway_addr,
        "buffered-retry",
        "1.0.0",
        &deterministic_bytes(BUFFERED_COMMIT_BYTES, b'b'),
        "application/octet-stream",
    )?;
    let streaming = stage_presigned(
        gateway_addr,
        "streaming-while-full",
        "1.0.0",
        &deterministic_bytes(STREAMING_COMMIT_BYTES, b'c'),
        "application/octet-stream",
    )?;

    let occupied = BudgetOccupancy::start(gateway_addr, bucket, object_key)?;

    let site = http_request_addr(
        gateway_addr,
        "GET",
        &format!("/sites/{TENANT}/{STATIC_SITE}/"),
        &[],
        "",
    )?;
    check_response_status(&site, 503, "bucket-backed static-site serve under load")?;
    assert_budget_error(&site, "static-site serve")?;

    let buffered_refusal = commit_presigned(gateway_addr, &buffered)?;
    check_response_status(
        &buffered_refusal,
        503,
        "buffered presigned commit under load",
    )?;
    assert_budget_error(&buffered_refusal, "buffered presigned commit")?;

    let streamed = commit_presigned(gateway_addr, &streaming)?;
    check_response_status(
        &streamed,
        200,
        "larger-than-per-operation streaming commit while budget is occupied",
    )?;

    let held_reads = occupied.release_and_join()?;
    for response in held_reads {
        check_response_status(&response, 200, "budget-occupying REST read")?;
        check(
            response.body.as_bytes() == burst_content,
            "a budget-occupying REST read returned incomplete bytes",
        )?;
    }

    // A 503 must leave staging intact. Reusing the exact upload_id after the
    // pool drains is the only meaningful proof that the response is retryable.
    let retried = commit_presigned(gateway_addr, &buffered)?;
    check_response_status(&retried, 200, "retry buffered commit after budget drains")?;
    println!(
        "asset-buffer cross-surface admission: site and buffered commit shed; streaming commit and buffered retry succeeded"
    );
    Ok(())
}

fn publish_static_site(gateway_addr: &str) -> Result<Vec<u8>> {
    let index = deterministic_bytes(STATIC_BYTES, b'd');
    let bundle = build_stored_zip(&[("index.html", index.as_slice())]);
    let response = http_request_addr_bytes(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/static_site/{STATIC_SITE}/1.0.0"),
        &[
            CLIENT_AUTH,
            "Content-Type: application/zip",
            "X-Site-Public: true",
        ],
        &bundle,
    )?;
    if response.status == 200 || response.status == 201 {
        Ok(index)
    } else {
        bail!(
            "failed to publish bucket-backed static site: {}",
            response.raw
        )
    }
}

fn publish_presigned(
    gateway_addr: &str,
    name: &str,
    version: &str,
    content: &[u8],
    content_type: &str,
) -> Result<()> {
    let staged = stage_presigned(gateway_addr, name, version, content, content_type)?;
    let response = commit_presigned(gateway_addr, &staged)?;
    check_response_status(&response, 200, "publish presigned fixture")
}

struct StagedAsset {
    name: String,
    version: String,
    upload_id: String,
    size_bytes: usize,
    sha256: String,
    content_type: String,
}

fn stage_presigned(
    gateway_addr: &str,
    name: &str,
    version: &str,
    content: &[u8],
    content_type: &str,
) -> Result<StagedAsset> {
    let sha256 = sha256_hex(content);
    let intent = register_intent(gateway_addr, name, version, content.len() as u64, &sha256)?;
    check_response_status(&intent, 200, "register presigned upload intent")?;
    let intent_json = json(&intent)?;
    let upload_url = intent_json["upload_url"]
        .as_str()
        .context("presigned intent omitted upload_url")?;
    let upload_id = intent_json["upload_id"]
        .as_str()
        .context("presigned intent omitted upload_id")?
        .to_string();
    let status = direct_put(
        upload_url,
        content,
        &[("x-amz-content-sha256", sha256.as_str())],
    )?;
    check(status == 200, "direct staging PUT failed")?;
    Ok(StagedAsset {
        name: name.to_string(),
        version: version.to_string(),
        upload_id,
        size_bytes: content.len(),
        sha256,
        content_type: content_type.to_string(),
    })
}

fn commit_presigned(gateway_addr: &str, staged: &StagedAsset) -> Result<HttpResponse> {
    http_request_addr(
        gateway_addr,
        "POST",
        &format!(
            "/v1/assets/presign/commit/cli_tool/{}/{}",
            staged.name, staged.version
        ),
        &[CLIENT_AUTH, JSON_CONTENT],
        &format!(
            r#"{{"upload_id":"{}","size_bytes":{},"sha256":"{}","content_type":"{}"}}"#,
            staged.upload_id, staged.size_bytes, staged.sha256, staged.content_type
        ),
    )
}

fn only_bucket_object_key(bucket: &Arc<Mutex<BucketState>>) -> Result<String> {
    let state = bucket.lock().unwrap();
    if state.objects.len() != 1 {
        bail!(
            "expected exactly one final bucket object after publishing the burst fixture, found {}",
            state.objects.len()
        );
    }
    Ok(state.objects.keys().next().unwrap().clone())
}

fn install_bucket_get_gate(
    bucket: &Arc<Mutex<BucketState>>,
    object_key: &str,
) -> Arc<BucketGetGate> {
    let gate = Arc::new(BucketGetGate::default());
    let mut state = bucket.lock().unwrap();
    state.blocked_get_path = Some(object_key.to_string());
    state.get_gate = Some(Arc::clone(&gate));
    gate
}

fn clear_bucket_get_gate(bucket: &Arc<Mutex<BucketState>>) {
    let mut state = bucket.lock().unwrap();
    state.blocked_get_path = None;
    state.get_gate = None;
}

struct BudgetOccupancy {
    gate: Arc<BucketGetGate>,
    bucket: Arc<Mutex<BucketState>>,
    readers: Vec<JoinHandle<Result<HttpResponse>>>,
}

impl BudgetOccupancy {
    fn start(
        gateway_addr: &str,
        bucket: &Arc<Mutex<BucketState>>,
        object_key: &str,
    ) -> Result<Self> {
        let gate = install_bucket_get_gate(bucket, object_key);
        let readers = (0..2)
            .map(|_| {
                let addr = gateway_addr.to_string();
                thread::spawn(move || {
                    http_request_addr(
                        &addr,
                        "GET",
                        "/v1/assets/cli_tool/burst-object/1.0.0",
                        &[CLIENT_AUTH],
                        "",
                    )
                })
            })
            .collect();
        if let Err(error) = gate.wait_for_started(2, Duration::from_secs(10)) {
            gate.release();
            let _ = join_readers(readers);
            clear_bucket_get_gate(bucket);
            return Err(error);
        }
        Ok(Self {
            gate,
            bucket: Arc::clone(bucket),
            readers,
        })
    }

    fn release_and_join(mut self) -> Result<Vec<HttpResponse>> {
        self.gate.release();
        let responses = join_readers(std::mem::take(&mut self.readers));
        clear_bucket_get_gate(&self.bucket);
        responses
    }
}

impl Drop for BudgetOccupancy {
    fn drop(&mut self) {
        self.gate.release();
        clear_bucket_get_gate(&self.bucket);
        for reader in std::mem::take(&mut self.readers) {
            let _ = reader.join();
        }
    }
}

fn join_readers(readers: Vec<JoinHandle<Result<HttpResponse>>>) -> Result<Vec<HttpResponse>> {
    readers
        .into_iter()
        .map(|reader| {
            reader
                .join()
                .map_err(|_| anyhow::anyhow!("asset reader thread panicked"))?
        })
        .collect()
}

struct StalledHttpRequest {
    head_received: mpsc::Receiver<()>,
    release: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<Result<Vec<u8>>>>,
}

impl StalledHttpRequest {
    fn start(
        gateway_addr: &str,
        method: &str,
        path: &str,
        headers: &[&str],
        request_body: &[u8],
    ) -> Result<Self> {
        let addr = gateway_addr.to_string();
        let method = method.to_string();
        let path = path.to_string();
        let headers: Vec<_> = headers.iter().map(|header| header.to_string()).collect();
        let body = request_body.to_vec();
        let (head_tx, head_received) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let handle = thread::spawn(move || -> Result<Vec<u8>> {
            let mut stream = TcpStream::connect(&addr)?;
            configure_small_receive_buffer(&stream)?;
            stream.set_read_timeout(Some(Duration::from_secs(60)))?;
            write!(
                stream,
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
                body.len()
            )?;
            for header in headers {
                write!(stream, "{header}\r\n")?;
            }
            write!(stream, "\r\n")?;
            stream.write_all(&body)?;
            stream.flush()?;

            let mut response = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !response.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk)?;
                if read == 0 {
                    bail!("gateway closed the stalled response before its headers");
                }
                response.extend_from_slice(&chunk[..read]);
            }
            head_tx.send(()).context("report stalled response head")?;
            release_rx
                .recv_timeout(Duration::from_secs(30))
                .context("wait for stalled response release")?;
            // Closing here is deliberate: the test has already proved the
            // writer still owns the permit by observing the second call shed.
            // Draining a multi-megabyte response through the intentionally tiny
            // receive window adds tens of seconds without strengthening that
            // lifetime assertion.
            drop(stream);
            Ok(response)
        });
        Ok(Self {
            head_received,
            release: Some(release),
            handle: Some(handle),
        })
    }

    fn wait_for_response_head(&self) -> Result<()> {
        self.head_received
            .recv_timeout(Duration::from_secs(30))
            .context("timed out waiting for stalled response head")
    }

    fn release_and_join(mut self) -> Result<Vec<u8>> {
        self.release
            .take()
            .context("stalled request already released")?
            .send(())
            .context("release stalled response")?;
        self.handle
            .take()
            .context("stalled request has no reader")?
            .join()
            .map_err(|_| anyhow::anyhow!("stalled response reader thread panicked"))?
    }
}

impl Drop for StalledHttpRequest {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_small_receive_buffer(stream: &TcpStream) -> Result<()> {
    configure_receive_buffer(stream, 8 * 1024)
}

#[cfg(target_os = "linux")]
fn configure_receive_buffer(stream: &TcpStream, bytes: i32) -> Result<()> {
    use std::{ffi::c_void, mem, os::fd::AsRawFd};

    // Linux's stable socket ABI values from asm-generic/socket.h and
    // linux/tcp.h. Declaring the one libc call locally keeps this gate-owned
    // helper from changing the workspace lockfile merely to tune a test socket.
    const SOL_SOCKET: i32 = 1;
    const SO_RCVBUF: i32 = 8;
    const IPPROTO_TCP: i32 = 6;
    const TCP_WINDOW_CLAMP: i32 = 10;
    unsafe extern "C" {
        fn setsockopt(
            fd: i32,
            level: i32,
            option_name: i32,
            option_value: *const c_void,
            option_length: u32,
        ) -> i32;
    }

    // SAFETY: `stream` owns a live socket fd and `bytes` points to a correctly
    // sized integer for the duration of this Linux setsockopt call.
    let receive_buffer_result = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUF,
            std::ptr::from_ref(&bytes).cast(),
            mem::size_of_val(&bytes) as u32,
        )
    };
    if receive_buffer_result != 0 {
        return Err(std::io::Error::last_os_error()).context("set small receive buffer");
    }

    // SO_RCVBUF alone is advisory and TCP autotuning can still advertise a
    // multi-megabyte receive window. Clamp the advertised window as well so a
    // multi-megabyte gateway response is provably still in its writer while
    // the admission probe runs.
    let receive_window = bytes / 2;
    let window_clamp_result = unsafe {
        setsockopt(
            stream.as_raw_fd(),
            IPPROTO_TCP,
            TCP_WINDOW_CLAMP,
            std::ptr::from_ref(&receive_window).cast(),
            mem::size_of_val(&receive_window) as u32,
        )
    };
    if window_clamp_result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("clamp TCP receive window")
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_small_receive_buffer(_stream: &TcpStream) -> Result<()> {
    Ok(())
}

fn response_header_end(response: &[u8]) -> Result<usize> {
    Ok(response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("raw HTTP response has no header terminator")?
        + 4)
}

fn response_content_length(response: &[u8]) -> Result<usize> {
    let header_end = response_header_end(response)?;
    let headers = String::from_utf8_lossy(&response[..header_end]);
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .context("stalled MCP response omitted Content-Length")
}

fn assert_budget_error(response: &HttpResponse, surface: &str) -> Result<()> {
    let body: Value = serde_json::from_str(&response.body)
        .with_context(|| format!("{surface} refusal is not JSON: {}", response.raw))?;
    check(
        body["error"]["code"] == "gateway_buffer_budget_exhausted",
        &format!("{surface} refusal is not gateway_buffer_budget_exhausted"),
    )?;
    check(
        response.body.contains("max_total_gateway_buffer_bytes"),
        &format!("{surface} refusal does not name max_total_gateway_buffer_bytes"),
    )
}

fn check_response_status(response: &HttpResponse, expected: u16, what: &str) -> Result<()> {
    if response.status == expected {
        Ok(())
    } else {
        bail!(
            "{what} returned {}, expected {expected}: {}",
            response.status,
            bounded_response_diagnostic(response)
        )
    }
}

fn bounded_response_diagnostic(response: &HttpResponse) -> String {
    const MAX_INLINE_BODY_BYTES: usize = 1024;
    if response.body.len() <= MAX_INLINE_BODY_BYTES {
        return response.raw.clone();
    }
    let headers = response
        .raw
        .split_once("\r\n\r\n")
        .map_or(response.raw.as_str(), |(headers, _)| headers);
    format!(
        "{headers}\r\n\r\n[{}-byte response body omitted]",
        response.body.len()
    )
}

fn deterministic_bytes(length: usize, base: u8) -> Vec<u8> {
    (0..length).map(|index| base + (index % 20) as u8).collect()
}

fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = out.len() as u32;
        let name = name.as_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let central_offset = out.len() as u32;
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
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
  presign_max_object_bytes: {}
  max_gateway_buffer_bytes: {OBJECT_BYTES}
  max_total_gateway_buffer_bytes: {TOTAL_BUFFER_BYTES}
  buffer_admission_wait_ms: {BUFFER_WAIT_MS}
api_keys:
  - id: "presign-e2e-admin"
    name: "Buffer admission operator"
    key: "presign-e2e-admin-secret"
    scopes: ["admin.read", "admin.write"]
    platform_operator: true
  - id: "presign-e2e-client"
    name: "Buffer admission tenant client"
    key: "presign-e2e-client-secret"
    scopes: ["assets.read", "assets.write", "tools.read", "tools.execute"]
    organization_id: {TENANT:?}
    project_id: "project_buffer_admission"
"#,
        STREAMING_COMMIT_BYTES * 2
    )
}

fn resident_bytes(pid: u32) -> Result<u64> {
    let statm = fs::read_to_string(format!("/proc/{pid}/statm"))
        .with_context(|| format!("read RSS for gateway pid {pid}"))?;
    let pages = statm
        .split_whitespace()
        .nth(1)
        .context("/proc statm omitted resident pages")?
        .parse::<u64>()
        .context("parse resident pages")?;
    Ok(pages * 4096)
}

struct RssSampler {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Result<u64>>,
}

impl RssSampler {
    fn start(pid: u32) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut peak = 0;
            while !thread_stop.load(Ordering::Relaxed) {
                peak = peak.max(resident_bytes(pid)?);
                thread::sleep(Duration::from_millis(2));
            }
            Ok(peak.max(resident_bytes(pid)?))
        });
        Self { stop, handle }
    }

    fn finish(self) -> Result<u64> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| anyhow::anyhow!("RSS sampler thread panicked"))?
    }
}
