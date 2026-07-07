// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end proof of bucket-backed asset storage (issue
// #176) against a real running gateway: push an asset with [asset_bucket]
// configured, confirm the mock S3-compatible server received a correctly
// SigV4-signed PUT, confirm pull fetches the real bytes back from the
// bucket (not from `stored_assets.content`, which is independently
// verified to be empty via a real Postgres query), and confirm delete
// removes the bucket object too.
//
// No live Supabase Storage bucket credentials needed or used: this
// validates request shape and end-to-end byte round-tripping against a
// local mock S3-compatible server, the same testing philosophy as every
// other externally-facing adapter in this codebase (Bedrock, Vertex,
// Stripe). Opt-in via FERROGATE_SUPABASE_DSN like every other assets test,
// since this also independently verifies the `stored_assets` row shape
// against a real Postgres database.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[derive(Debug, Clone)]
struct CapturedBucketRequest {
    method: String,
    path: String,
}

/// A persistent (multi-request) mock S3-compatible object store: PUT
/// stores bytes keyed by path, GET returns exactly what was PUT for that
/// path (404 if never written or deleted), DELETE removes it. Unlike
/// `asset_bucket.rs`'s unit-test mock (a one-shot, fixed-response
/// server), this needs to actually round-trip real bytes so the pulled
/// asset's content_hash verification (done by the gateway itself)
/// succeeds against the exact bytes originally pushed.
fn spawn_stateful_bucket_mock() -> (String, Arc<Mutex<Vec<CapturedBucketRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let captured = Arc::new(Mutex::new(Vec::new()));
    let server_captured = Arc::clone(&captured);
    let objects: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    return;
                }
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
                let read = stream.read(&mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
            }
            let body = raw[header_end..header_end + content_length].to_vec();
            let request_line = head.lines().next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            server_captured.lock().unwrap().push(CapturedBucketRequest {
                method: method.clone(),
                path: path.clone(),
            });

            let mut store = objects.lock().unwrap();
            let (status, response_body): (&str, Vec<u8>) = match method.as_str() {
                "PUT" => {
                    store.insert(path.clone(), body);
                    ("200 OK", Vec::new())
                }
                "GET" => match store.get(&path) {
                    Some(bytes) => ("200 OK", bytes.clone()),
                    None => ("404 Not Found", b"no such key".to_vec()),
                },
                "DELETE" => {
                    store.remove(&path);
                    ("204 No Content", Vec::new())
                }
                _ => ("405 Method Not Allowed", Vec::new()),
            };
            drop(store);

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n",
                response_body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&response_body);
        }
    });

    (endpoint, captured)
}

fn write_config(path: &std::path::Path, gateway_addr: &str, dsn: &str, bucket_endpoint: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[asset_bucket]
enabled = true
endpoint = "{bucket_endpoint}"
bucket = "ferrogate-assets-test"
region = "us-east-1"
access_key_id = "AKIDEXAMPLE"
secret_access_key_env = "FERROGATE_TEST_ASSET_BUCKET_SECRET"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "asset-bucket-client"
name = "Asset bucket client"
key = "asset-bucket-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_asset_bucket"
"#
        ),
    )
    .unwrap();
}

fn response_json(response: String) -> serde_json::Value {
    let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
    serde_json::from_str(body)
        .unwrap_or_else(|error| panic!("invalid JSON body: {error}\n{response}"))
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn psql_query(dsn: &str, query: &str) -> String {
    let output = Command::new("psql")
        .arg(dsn)
        .arg("-t")
        .arg("-A")
        .arg("-c")
        .arg(query)
        .output()
        .expect("psql must be installed for this test's independent DB verification");
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        panic!("psql query failed: {query}");
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn asset_push_pull_delete_round_trips_through_a_real_bucket() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping asset_push_pull_delete_round_trips_through_a_real_bucket: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };
    std::env::set_var("FERROGATE_TEST_ASSET_BUCKET_SECRET", "test-secret-key");

    let (bucket_endpoint, captured) = spawn_stateful_bucket_mock();
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr, &dsn, &bucket_endpoint);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_asset_bucket","name":"Org Asset Bucket","slug":"org-asset-bucket"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    let content = "#!/bin/sh\necho hello from a real bucket-backed asset\n";
    let push = response_json(http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/bucket-hello/1.0.0",
        &[
            "Authorization: Bearer asset-bucket-secret",
            "Content-Type: text/plain",
        ],
        content,
    ));
    assert_eq!(push["asset"]["storage_backed"], true);
    let content_hash = push["asset"]["content_hash"]
        .as_str()
        .expect("content_hash must be present")
        .to_string();

    // The mock bucket must have received exactly one signed PUT.
    let requests = captured.lock().unwrap().clone();
    assert_eq!(
        requests.len(),
        1,
        "expected exactly one bucket request so far: {requests:?}"
    );
    assert_eq!(requests[0].method, "PUT");
    assert!(
        requests[0]
            .path
            .starts_with("/ferrogate-assets-test/org_asset_bucket:cli_tool:bucket-hello:1.0.0"),
        "unexpected bucket object path: {:?}",
        requests[0]
    );

    // The stored_assets row itself must NOT duplicate the bytes -- content
    // is empty and storage_uri is set, verified via a real, independent
    // SQL query (not just the gateway's own view of itself).
    let db_row = psql_query(
        &dsn,
        "SELECT length(content), storage_uri FROM ferrogate_control.stored_assets \
         WHERE tenant_id = 'org_asset_bucket' AND asset_type = 'cli_tool' AND name = 'bucket-hello'",
    );
    assert!(
        db_row.trim_start().starts_with('0'),
        "content column must be empty for a bucket-backed asset: {db_row}"
    );
    assert!(
        db_row.contains("org_asset_bucket:cli_tool:bucket-hello:1.0.0"),
        "storage_uri must be recorded: {db_row}"
    );

    // Pull must fetch the real bytes back from the bucket (not from the
    // empty content column) and pass content_hash verification.
    let pull = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/bucket-hello/1.0.0",
        &["Authorization: Bearer asset-bucket-secret"],
        "",
    );
    assert!(status_line(&pull).contains("200 OK"), "pull failed: {pull}");
    assert!(
        pull.ends_with(content),
        "pulled bytes must exactly match what was pushed: {pull}"
    );

    let requests_after_pull = captured.lock().unwrap().clone();
    assert_eq!(
        requests_after_pull.len(),
        2,
        "pull must issue a GET against the bucket: {requests_after_pull:?}"
    );
    assert_eq!(requests_after_pull[1].method, "GET");

    // Independently confirm via the list endpoint too.
    let list = response_json(http_request(
        &gateway_addr,
        "GET",
        "/v1/assets",
        &["Authorization: Bearer asset-bucket-secret"],
        "",
    ));
    let listed = list["data"]
        .as_array()
        .expect("list must have a data array");
    assert!(
        listed.iter().any(|asset| asset["name"] == "bucket-hello"
            && asset["content_hash"] == content_hash
            && asset["storage_backed"] == true),
        "pushed bucket-backed asset not present (or not flagged storage_backed) in list: {list}"
    );

    // Delete must remove the bucket object as well as the DB row.
    let delete = http_request(
        &gateway_addr,
        "DELETE",
        "/v1/assets/cli_tool/bucket-hello/1.0.0",
        &["Authorization: Bearer asset-bucket-secret"],
        "",
    );
    assert!(delete.contains("HTTP/1.1 200"), "delete failed: {delete}");

    let requests_after_delete = captured.lock().unwrap().clone();
    assert_eq!(
        requests_after_delete.len(),
        3,
        "delete must issue a DELETE against the bucket: {requests_after_delete:?}"
    );
    assert_eq!(requests_after_delete[2].method, "DELETE");

    let pull_after_delete = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/cli_tool/bucket-hello/1.0.0",
        &["Authorization: Bearer asset-bucket-secret"],
        "",
    );
    assert!(
        pull_after_delete.contains("HTTP/1.1 404"),
        "expected 404 after delete: {pull_after_delete}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
