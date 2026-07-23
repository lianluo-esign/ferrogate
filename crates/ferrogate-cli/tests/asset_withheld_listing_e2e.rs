// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: In-memory end-to-end coverage for the #379 operator-only WITHHELD
// asset listing (GET /v1/assets/withheld). The ordinary list path hides
// pending_scan/quarantined rows (#366); this is the inverse operator view.
// Proves through a real gateway process (no DB): the listing returns exactly the
// withheld rows (pending_scan + quarantined) and never the visible one, each row
// carries its visibility state and the screening evidence recorded at push time,
// the view is tenant-scoped, and it paginates (offset/limit).

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

fn response_json(response: String) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(&response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

fn config_body(gateway_addr: &str) -> String {
    // No `storage` section -> the default in-memory control plane, which seeds
    // the default free plan (asset_hosting_enabled = true). Two asset tenants so
    // the tenant-scoping of the withheld view is provable.
    format!(
        r#"
listen = "{gateway_addr}"

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
organization_id = "org_demo"

[[api_keys]]
id = "asset-client-other"
name = "Other asset client"
key = "other-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_other"
"#
    )
}

/// Spawn the gateway with the async-scan threshold at 10 bytes: a push of <= 10
/// bytes scans inline and lands `visible`; a larger push defers to `pending_scan`
/// (withheld). Mirrors the promotion e2e's bind-race retry and per-child env.
fn start_threshold_gateway(config_path: &std::path::Path) -> (Child, String) {
    for _ in 0..20 {
        let addr = free_addr();
        std::fs::write(config_path, config_body(&addr)).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
            .args(["run", "--config", config_path.to_str().unwrap()])
            .env("FERROGATE_ASSET_SCANNER_ASYNC_THRESHOLD_BYTES", "10")
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

#[allow(dead_code)]
fn _unused() {
    let _ = TcpListener::bind("127.0.0.1:0");
    let _ = wait_for_gateway;
}

fn register_tenant(gateway_addr: &str, id: &str, name: &str, slug: &str) {
    let register = http_request(
        gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &admin_headers(),
        &format!(r#"{{"id":"{id}","name":"{name}","slug":"{slug}"}}"#),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed for {id}: {register}"
    );
}

fn push_asset(gateway_addr: &str, key: &str, name: &str, content: &str) {
    let push = http_request(
        gateway_addr,
        "PUT",
        &format!("/v1/assets/cli_tool/{name}/1.0.0"),
        &[
            &format!("Authorization: Bearer {key}"),
            "Content-Type: text/plain",
        ],
        content,
    );
    assert!(
        push.contains("HTTP/1.1 200") || push.contains("HTTP/1.1 201"),
        "push of {name} failed: {push}"
    );
}

#[test]
fn withheld_listing_surfaces_pending_and_quarantined_with_evidence_scoped_and_paginated() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    let (mut gateway, gateway_addr) = start_threshold_gateway(&config_path);

    register_tenant(&gateway_addr, "org_demo", "Org Demo", "org-demo");
    register_tenant(&gateway_addr, "org_other", "Org Other", "org-other");

    // org_demo assets:
    //  - "visible-tool": 5 bytes (<= threshold) -> scanned inline -> visible.
    //  - "aaa-pending":  large   (> threshold)  -> deferred        -> pending_scan.
    //  - "zzz-quar":     large   (> threshold)  -> deferred; then promoted to
    //                    quarantined via the #378 endpoint.
    push_asset(&gateway_addr, "asset-secret", "visible-tool", "hello");
    push_asset(
        &gateway_addr,
        "asset-secret",
        "aaa-pending",
        "a deferred pending payload well over ten bytes",
    );
    push_asset(
        &gateway_addr,
        "asset-secret",
        "zzz-quar",
        "another deferred payload to be quarantined",
    );
    // Flip zzz-quar pending_scan -> quarantined (the separate #378 action).
    let quarantine = http_request(
        &gateway_addr,
        "POST",
        "/v1/assets/cli_tool/zzz-quar/1.0.0/visibility",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/json",
        ],
        r#"{"scan_outcome":"quarantined","evidence":"clamav: flagged; ticket SEC-379"}"#,
    );
    assert_eq!(
        response_json(quarantine)["visibility"],
        "quarantined",
        "setup: zzz-quar must be quarantined"
    );

    // A different tenant's withheld asset -- must never appear in org_demo's view.
    push_asset(
        &gateway_addr,
        "other-secret",
        "not-mine",
        "other tenant deferred payload over ten bytes",
    );

    // 1. The operator withheld listing returns exactly the two withheld org_demo
    // rows (pending_scan + quarantined), never the visible one.
    let listing = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/withheld",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(listing["object"], "list");
    let rows = listing["data"].as_array().expect("withheld data array");
    let names: Vec<&str> = rows
        .iter()
        .map(|row| row["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        names,
        vec!["aaa-pending", "zzz-quar"],
        "exactly the withheld rows, deterministically ordered; visible-tool excluded: {listing}"
    );
    assert!(
        !names.contains(&"visible-tool"),
        "the visible asset must never appear in the withheld listing"
    );
    assert!(
        !names.contains(&"not-mine"),
        "another tenant's withheld asset must never leak into this listing"
    );

    // 2. Each row carries its visibility state + the screening evidence recorded
    // at push time (#366): the push audit detail (scan/signature/approval).
    let pending = &rows[0];
    assert_eq!(pending["visibility"], "pending_scan");
    let pending_evidence = pending["screening_evidence"]
        .as_str()
        .expect("pending row carries screening evidence");
    assert!(
        pending_evidence.contains("scan=pending_scan") && pending_evidence.contains("signature="),
        "pending evidence must be the push screening detail: {pending_evidence}"
    );
    let quarantined = &rows[1];
    assert_eq!(quarantined["visibility"], "quarantined");
    assert!(
        quarantined["screening_evidence"].as_str().is_some(),
        "quarantined row carries the screening evidence recorded at push time"
    );

    // 3. The other tenant sees only its own withheld asset (tenant scoping).
    let other = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/withheld",
        &["Authorization: Bearer other-secret"],
        "",
    ));
    let other_names: Vec<&str> = other["data"]
        .as_array()
        .expect("other data array")
        .iter()
        .map(|row| row["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        other_names,
        vec!["not-mine"],
        "org_other must see only its own withheld asset: {other}"
    );

    // 4. Pagination: limit=1 returns one row of the two, with total/offset/limit.
    let page = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/withheld?limit=1",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert_eq!(page["total"], 2, "total reflects the full withheld count");
    assert_eq!(page["limit"], 1);
    assert_eq!(page["offset"], 0);
    let page_rows = page["data"].as_array().expect("page data array");
    assert_eq!(page_rows.len(), 1, "limit=1 yields a single row");
    assert_eq!(page_rows[0]["name"], "aaa-pending");

    // The second page (offset=1) yields the other withheld row.
    let page2 = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/withheld?limit=1&offset=1",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    let page2_rows = page2["data"].as_array().expect("page2 data array");
    assert_eq!(page2_rows.len(), 1);
    assert_eq!(page2_rows[0]["name"], "zzz-quar");

    // 5. The asset_type filter narrows to the family (still only withheld rows).
    let filtered = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/withheld?asset_type=mcp_manifest",
        &["Authorization: Bearer asset-secret"],
        "",
    ));
    assert!(
        filtered["data"]
            .as_array()
            .expect("filtered array")
            .is_empty(),
        "no withheld mcp_manifest assets exist: {filtered}"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
}
