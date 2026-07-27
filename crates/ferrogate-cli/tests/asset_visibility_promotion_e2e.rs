// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: In-memory end-to-end coverage for the #378 out-of-band scan
// promotion endpoint (POST /v1/assets/{type}/{name}/{version}/visibility). A
// deferred-scan push admits an asset as `pending_scan` (withheld from every
// download surface); the promotion endpoint then flips it to visible/quarantined
// based on a completed-scan verdict, emitting a durable audit event. Proves the
// full handler loop through a real gateway process on the in-memory backend (no
// DB required): withheld-before/downloadable-after, fail-closed rejection of a
// non-pending or missing asset and of an unknown verdict / missing evidence, the
// quarantine branch, and the durable promotion audit evidence.

mod support;

use support::{free_addr, http_request, wait_for_gateway};

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn admin_headers() -> Vec<&'static str> {
    vec![
        "Authorization: Bearer admin-secret",
        "Content-Type: application/json",
    ]
}

fn asset_headers() -> Vec<&'static str> {
    vec![
        "Authorization: Bearer asset-secret",
        "Content-Type: application/json",
    ]
}

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn status_line(response: &str) -> String {
    response.lines().next().unwrap_or_default().to_string()
}

fn config_body(gateway_addr: &str) -> String {
    // No `storage` section -> the default in-memory control plane, which seeds
    // the default free plan (asset_hosting_enabled = true), so a tenant created
    // through the admin API can host assets without a database.
    format!(
        r#"
listen = "{gateway_addr}"

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
organization_id = "org_demo"
"#
    )
}

/// Spawn the gateway with the async-scan threshold set so any non-empty push
/// defers to `pending_scan` -- the state the promotion endpoint operates on.
/// Mirrors `support::start_ready_gateway`'s bind-race retry, but injects the
/// scanner env var directly onto the child process rather than the test
/// process, so it cannot leak into any other test binary.
fn start_deferred_scan_gateway(config_path: &std::path::Path) -> (Child, String) {
    for _ in 0..20 {
        let addr = free_addr();
        std::fs::write(config_path, config_body(&addr)).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
            .args(["run", "--config", config_path.to_str().unwrap()])
            .env("FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        if gateway_ready_or_exited(&addr, &mut child) {
            return (child, addr);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("gateway never bound a free port after 20 attempts");
}

fn gateway_ready_or_exited(addr: &str, child: &mut Child) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return false;
        }
        if let Ok(mut stream) = TcpStream::connect(addr) {
            if stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .is_ok()
            {
                let mut buffer = [0_u8; 512];
                if stream.read(&mut buffer).unwrap_or(0) > 0 {
                    return !matches!(child.try_wait(), Ok(Some(_)));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

// Keep `free_addr`/`wait_for_gateway`/`TcpListener` referenced so support's
// re-exports stay in use across refactors.
#[allow(dead_code)]
fn _unused() {
    let _ = TcpListener::bind("127.0.0.1:0");
    let _ = wait_for_gateway;
}

#[test]
fn pending_scan_asset_is_promoted_visible_and_quarantined_with_audit_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (mut gateway, gateway_addr) = start_deferred_scan_gateway(&config_path);

    // Create the tenant so it lands on the seeded free plan (asset hosting on).
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        r#"{"id":"org_demo","name":"Org Demo","slug":"org-demo"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    // 1. Push an asset. With the async-scan threshold at 1 byte, this content
    // defers to an out-of-band scan and is admitted as `pending_scan`.
    let content = "#!/bin/sh\necho promote-me\n";
    let push = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/hello/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        content,
    );
    // 202, not "any 2xx": #528 made the status the wire statement that this
    // publish is WITHHELD pending its scan. A clean publish answers 200/201, so
    // pinning the exact code is what makes a regression back to a flat 200 --
    // "Asset pushed" for an object no read surface will serve -- fail here.
    assert!(
        push.contains("HTTP/1.1 202"),
        "a deferred-scan push must answer 202 Accepted: {push}"
    );

    // 2. A pending_scan asset is withheld from every download surface (#366):
    // the pull returns 404, indistinguishable from absent.
    let pull_before = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        pull_before.contains("HTTP/1.1 404"),
        "a pending_scan asset must be withheld before promotion: {}",
        status_line(&pull_before)
    );

    // 3. An unknown verdict is rejected fail-closed and never promotes.
    let bad_verdict = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/hello/1.0.0/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"maybe","evidence":"n/a"}"#,
    );
    assert!(
        bad_verdict.contains("HTTP/1.1 400"),
        "an unknown scan_outcome must be rejected: {}",
        status_line(&bad_verdict)
    );

    // 4. Missing evidence is rejected: a durable promotion must carry evidence.
    let no_evidence = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/hello/1.0.0/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"clean","evidence":"   "}"#,
    );
    assert!(
        no_evidence.contains("HTTP/1.1 400"),
        "a promotion without evidence must be rejected: {}",
        status_line(&no_evidence)
    );

    // Still withheld -- neither rejected attempt promoted anything.
    let pull_still = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        pull_still.contains("HTTP/1.1 404"),
        "a rejected promotion must not publish the asset: {}",
        status_line(&pull_still)
    );

    // 5. Promote to visible on a clean out-of-band scan.
    let promote = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/hello/1.0.0/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"clean","evidence":"clamav clean; ticket SEC-101","scanner":"clamav"}"#,
    ));
    assert_eq!(promote["object"], "asset.visibility_promotion");
    assert_eq!(promote["visibility"], "visible");
    assert_eq!(promote["scan_outcome"], "visible");
    assert_eq!(promote["asset"]["name"], "hello");

    // 6. Now downloadable, and the bytes verify.
    let pull_after = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/hello/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        pull_after.contains("HTTP/1.1 200"),
        "a promoted asset must be downloadable: {}",
        status_line(&pull_after)
    );
    assert!(
        pull_after.contains("echo promote-me"),
        "the served bytes must match the pushed content: {pull_after}"
    );

    // 7. Re-promoting a now-terminal asset is a fail-closed conflict (409).
    let repromote = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/hello/1.0.0/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"quarantined","evidence":"late verdict"}"#,
    );
    assert!(
        repromote.contains("HTTP/1.1 409"),
        "an already-terminal asset must not be re-promoted: {}",
        status_line(&repromote)
    );

    // 8. Promoting a missing asset is 404.
    let missing = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/hello/9.9.9/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"clean","evidence":"ghost"}"#,
    );
    assert!(
        missing.contains("HTTP/1.1 404"),
        "promoting a missing asset must be 404: {}",
        status_line(&missing)
    );

    // 9. Quarantine branch: a flagged verdict withholds the asset permanently.
    let push2 = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/tainted/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: text/plain",
        ],
        "suspicious payload",
    );
    // Withheld for the same reason as the first push: this gateway's async-scan
    // threshold is 1 byte, so every push defers. 202 exactly (#528).
    assert!(
        push2.contains("HTTP/1.1 202"),
        "a deferred-scan push must answer 202 Accepted: {push2}"
    );
    let quarantine = response_json(http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/tainted/1.0.0/visibility",
        &asset_headers(),
        r#"{"scan_outcome":"quarantined","evidence":"clamav: Eicar-Test-Signature; ticket SEC-102"}"#,
    ));
    assert_eq!(quarantine["visibility"], "quarantined");
    let pull_tainted = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/tainted/1.0.0",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        pull_tainted.contains("HTTP/1.1 404"),
        "a quarantined asset must stay withheld: {}",
        status_line(&pull_tainted)
    );

    // 10. Durable audit evidence links each promotion to its scan outcome.
    let audit = response_json(http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events?limit=200",
        &["Authorization: Bearer admin-secret"],
        "",
    ));
    let events = audit["data"].as_array().expect("audit events array");
    let promote_rows: Vec<&serde_json::Value> = events
        .iter()
        .filter(|event| event["action"] == "asset.visibility.promote")
        .collect();
    assert!(
        !promote_rows.is_empty(),
        "no asset.visibility.promote audit rows were recorded: {audit}"
    );
    // The clean promotion committed with its evidence recorded verbatim.
    let committed_clean = promote_rows.iter().find(|event| {
        event["outcome"] == "committed"
            && event["message"].as_str().is_some_and(|message| {
                message.contains("SEC-101") && message.contains("scan_outcome=visible")
            })
    });
    assert!(
        committed_clean.is_some(),
        "missing committed clean-promotion audit evidence: {promote_rows:?}"
    );
    // The quarantine promotion committed with its evidence.
    let committed_quarantine = promote_rows.iter().find(|event| {
        event["outcome"] == "committed"
            && event["message"].as_str().is_some_and(|message| {
                message.contains("SEC-102") && message.contains("quarantined")
            })
    });
    assert!(
        committed_quarantine.is_some(),
        "missing committed quarantine-promotion audit evidence: {promote_rows:?}"
    );
    // The rejected re-promotion left durable evidence too (fail-closed 409).
    let rejected = promote_rows
        .iter()
        .find(|event| event["outcome"] == "rejected");
    assert!(
        rejected.is_some(),
        "missing rejected-promotion audit evidence: {promote_rows:?}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}
