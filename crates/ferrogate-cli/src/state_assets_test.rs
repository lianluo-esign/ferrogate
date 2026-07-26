// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Coverage for the gateway memory bound on the SHARED asset read
// chokepoint (`AppState::read_asset_content`, issue #259 round 2) -- the
// helper reached by the `fetch_asset` built-in tool and MCP `resources/read`,
// which round 1 left buffering objects of up to `presign_max_object_bytes`
// (5 GiB by default). No live bucket: the refusal is decided from the registry
// row's declared size, before a bucket client is ever resolved.

use super::*;

use ferrogate_storage::{stored_asset_id, StoredAsset};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// An `AppState` whose gateway buffer budget is `max_gateway_buffer_bytes`.
/// The bucket is left unconfigured on purpose: the bound must be decided
/// before the bucket client is resolved, so an over-budget object is refused
/// with a 413-equivalent rather than a "no bucket configured" 503 that would
/// mask it.
fn state_with_budget(max_gateway_buffer_bytes: u64) -> AppState {
    AppState::new(Config {
        asset_bucket: crate::config::AssetBucketConfig {
            max_gateway_buffer_bytes: Some(max_gateway_buffer_bytes),
            ..crate::config::AssetBucketConfig::default()
        },
        ..Config::default()
    })
}

fn bucket_backed_asset(tenant: &str, name: &str, size_bytes: u64) -> StoredAsset {
    StoredAsset {
        id: stored_asset_id(tenant, "cli_tool", name, "1.0.0"),
        tenant_id: tenant.into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: name.into(),
        version: "1.0.0".into(),
        content_type: "application/octet-stream".into(),
        content_hash: "0".repeat(64),
        size_bytes,
        content: Vec::new(),
        storage_uri: Some(format!(".ferrogate/objects/deadbeef/obj_{name}")),
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

/// The #259 round-2 failed box, at the surface that failed it.
///
/// `fetch_asset` and MCP `resources/read` both go through
/// `read_asset_content`. Before this change the helper called `get_object`
/// with no size gate, so the same API key that correctly got a 413 from
/// `GET /v1/assets/...` could pull the whole object -- plus a second full pass
/// to re-hash it and a ~1.33x base64 copy -- through either of them.
#[test]
fn the_shared_mcp_read_chokepoint_refuses_an_object_above_the_gateway_buffer_budget() {
    let state = state_with_budget(8 * 1024 * 1024);
    let asset = bucket_backed_asset("tenant-a", "big-binary", 100 * 1024 * 1024);
    let id = asset.id.clone();
    block_on(state.upsert_asset(asset)).unwrap();

    let error = block_on(state.read_asset_content(&id, "request-1"))
        .expect_err("an over-budget object must not be materialized");
    let AssetReadError::TooLarge(message) = error else {
        panic!("an over-budget object must be refused as TooLarge, not resolved or 503'd");
    };
    assert!(
        message.contains("104857600") && message.contains("8388608"),
        "the refusal must name both the object size and the budget: {message}"
    );
    assert!(
        message.contains("/v1/assets/presign/download/cli_tool/big-binary/1.0.0"),
        "the refusal must name the endpoint that does work: {message}"
    );
}

/// The bound must not be a size limit on assets in general: an object at or
/// below the budget still reads exactly as before. (It fails on the bucket
/// being unconfigured, which is the pre-existing behavior -- the point is that
/// it gets PAST the new gate.)
#[test]
fn an_object_at_the_budget_is_not_refused_by_the_memory_bound() {
    let state = state_with_budget(8 * 1024 * 1024);
    let asset = bucket_backed_asset("tenant-a", "small-binary", 8 * 1024 * 1024);
    let id = asset.id.clone();
    block_on(state.upsert_asset(asset)).unwrap();

    let error = block_on(state.read_asset_content(&id, "request-1"))
        .expect_err("no bucket is configured, so this cannot succeed");
    assert!(
        matches!(error, AssetReadError::BucketUnavailable(_)),
        "at-limit is inside the budget; only above-limit is refused"
    );
}

/// Issue #259 review finding 4, at the exits it was still open at:
/// `read_asset_content` returned the bucket error verbatim, and
/// `builtin_tools`/`mcp_rpc` forward that string to the caller unchanged.
/// `reqwest::Error`'s `Display` embeds the request URL, i.e. the internal
/// `.ferrogate/objects/<digest>/obj_<rand>` key and the bucket endpoint.
///
/// This drives a REAL `reqwest::Error` (a refused connection to a port nothing
/// is listening on) rather than a hand-written stand-in, so it stays honest
/// about what `Display` actually renders if the mapping is removed.
#[test]
fn a_bucket_read_failure_never_serializes_the_object_key_or_endpoint() {
    const SECRET_ENV: &str = "FERROGATE_TEST_ASSET_READ_LEAK_SECRET";
    std::env::set_var(SECRET_ENV, "test-secret-access-key");

    // A port that was free a moment ago and has no listener now: connecting
    // fails at the transport, which is exactly the error shape whose Display
    // carries the URL.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let endpoint = format!("http://127.0.0.1:{dead_port}");
    let state = AppState::new(Config {
        asset_bucket: crate::config::AssetBucketConfig {
            enabled: true,
            endpoint: Some(endpoint.clone()),
            bucket: Some("ferrogate-private".to_string()),
            region: Some("auto".to_string()),
            access_key_id: Some("AKIAEXAMPLE".to_string()),
            secret_access_key_env: Some(SECRET_ENV.to_string()),
            max_gateway_buffer_bytes: Some(8 * 1024 * 1024),
            ..crate::config::AssetBucketConfig::default()
        },
        ..Config::default()
    });
    let asset = bucket_backed_asset("tenant-a", "small-binary", 1024);
    let id = asset.id.clone();
    let storage_uri = asset.storage_uri.clone().unwrap();
    block_on(state.upsert_asset(asset)).unwrap();

    let error = block_on(state.read_asset_content(&id, "request-1"))
        .expect_err("nothing is listening on that port, so this cannot succeed");
    let AssetReadError::BucketUnavailable(message) = error else {
        panic!("an unreachable bucket must map to BucketUnavailable");
    };
    assert!(
        !message.contains(&storage_uri) && !message.contains("obj_"),
        "the internal object key must never reach the caller: {message}"
    );
    assert!(
        !message.contains(&endpoint)
            && !message.contains("127.0.0.1")
            && !message.contains("ferrogate-private"),
        "the bucket endpoint and bucket name must never reach the caller: {message}"
    );
    assert_eq!(
        message,
        crate::gateway::asset_bucket::BUCKET_READ_UNAVAILABLE_MESSAGE,
        "every read surface must see the one generic transport message"
    );
}
