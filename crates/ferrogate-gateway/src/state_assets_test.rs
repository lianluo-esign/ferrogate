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
        asset_bucket: ferrogate_config::AssetBucketConfig {
            max_gateway_buffer_bytes: Some(max_gateway_buffer_bytes),
            ..ferrogate_config::AssetBucketConfig::default()
        },
        ..Config::default()
    })
}

/// The runtime half of `AssetBucketConfig::builds_s3_client()` (#485).
///
/// Validation tests pin that disabled S3 sections skip S3-only rules. This
/// pins the converse at the actual runtime accessor: even when every
/// credential is present, disabling the section prevents construction of the
/// object-store client. Removing the runtime predicate makes the second
/// assertion fail instead of leaving only config-side coverage green.
#[test]
fn only_an_enabled_s3_section_builds_the_runtime_bucket_client() {
    const SECRET_ENV: &str = "FERROGATE_TEST_ASSET_BUCKET_SELECTION_SECRET";
    std::env::set_var(SECRET_ENV, "test-secret-access-key");

    let bucket_config = |enabled| ferrogate_config::AssetBucketConfig {
        enabled,
        endpoint: Some("http://127.0.0.1:9000".into()),
        bucket: Some("ferrogate-assets".into()),
        region: Some("us-east-1".into()),
        access_key_id: Some("AKIAEXAMPLE".into()),
        secret_access_key_env: Some(SECRET_ENV.into()),
        ..ferrogate_config::AssetBucketConfig::default()
    };

    let enabled = AppState::new(Config {
        asset_bucket: bucket_config(true),
        ..Config::default()
    });
    assert!(
        enabled.asset_bucket_client().is_some(),
        "an enabled, fully configured S3 section must build the runtime client"
    );

    let disabled = AppState::new(Config {
        asset_bucket: bucket_config(false),
        ..Config::default()
    });
    assert!(
        disabled.asset_bucket_client().is_none(),
        "a disabled S3 section must not build a runtime client even when every credential exists"
    );

    std::env::remove_var(SECRET_ENV);
}

/// #411: the Cloudflare publish target is NOT reachable through the object-store
/// seam. Cloudflare has no keyed GET/DELETE/LIST for published assets, so a
/// store handed out here would make every asset read fail, retention prune and
/// tenant purge unable to erase bytes, and blob GC permanently broken -- after
/// the write path had already dropped the inline copy. The bytes stay in
/// FerroGate; only the site publish target is exposed, and only for the one
/// `{tenant}/{site}` its Worker script belongs to.
#[test]
fn the_workers_static_assets_section_yields_a_publish_target_and_no_object_store() {
    let state = AppState::new(Config {
        asset_bucket: ferrogate_config::AssetBucketConfig {
            enabled: true,
            backend: ferrogate_config::AssetBucketBackend::WorkersStaticAssets,
            cf_account_id: Some("cf-account".into()),
            cf_api_token: Some("plaintext-token".into()),
            cf_script_name: Some("ferrogate-site".into()),
            cf_publish_tenant: Some("acme".into()),
            cf_publish_site: Some("docs".into()),
            ..ferrogate_config::AssetBucketConfig::default()
        },
        ..Config::default()
    });

    assert!(
        state.asset_bucket_client().is_none(),
        "the Cloudflare publish target must never stand behind the asset object-store seam"
    );
    let target = state
        .static_site_publish_target()
        .expect("a fully configured workers-static-assets section must build a publish target");
    assert!(target.publishes("acme", "docs"));
    assert!(!target.publishes("other-tenant", "docs"));

    // The default S3 section configures no publish target at all.
    assert!(AppState::new(Config::default())
        .static_site_publish_target()
        .is_none());
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
        asset_bucket: ferrogate_config::AssetBucketConfig {
            enabled: true,
            endpoint: Some(endpoint.clone()),
            bucket: Some("ferrogate-private".to_string()),
            region: Some("auto".to_string()),
            access_key_id: Some("AKIAEXAMPLE".to_string()),
            secret_access_key_env: Some(SECRET_ENV.to_string()),
            max_gateway_buffer_bytes: Some(8 * 1024 * 1024),
            ..ferrogate_config::AssetBucketConfig::default()
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
        crate::server::asset_bucket::BUCKET_READ_UNAVAILABLE_MESSAGE,
        "every read surface must see the one generic transport message"
    );
}

/// An `AppState` whose presigned-URL TTL is `presign_ttl_secs`, so the
/// configured value and the enforced bound can be probed independently.
fn state_with_presign_ttl(presign_ttl_secs: Option<u64>) -> AppState {
    AppState::new(Config {
        asset_bucket: ferrogate_config::AssetBucketConfig {
            presign_ttl_secs,
            ..ferrogate_config::AssetBucketConfig::default()
        },
        ..Config::default()
    })
}

/// Acceptance box 4 of #259: "presigned URL TTL is bounded and configurable".
///
/// Both halves are asserted here because they are separate claims and the
/// bound was previously only *documented*: nothing in the tree exercised
/// `asset_presign_ttl_secs`, so deleting the `.clamp(1, 604_800)` left every
/// test green while an operator-supplied `presign_ttl_secs = 31536000` would
/// have been signed into `X-Amz-Expires` verbatim -- a year-long upload
/// authorization from a config typo, which S3-compatible verifiers reject
/// outright (the 7-day maximum) so the URL is not merely over-long but
/// unusable.
#[test]
fn the_presigned_url_ttl_is_configurable_and_bounded_to_the_s3_maximum() {
    /// S3's presigned-URL maximum expiry: 7 days.
    const S3_MAX_EXPIRES_SECS: u64 = 604_800;

    // Configurable: an in-range value is used exactly as configured.
    assert_eq!(
        state_with_presign_ttl(Some(120)).asset_presign_ttl_secs(),
        120
    );
    assert_eq!(
        state_with_presign_ttl(Some(3_600)).asset_presign_ttl_secs(),
        3_600
    );
    // ...and the default is short-lived by design when unset.
    assert_eq!(state_with_presign_ttl(None).asset_presign_ttl_secs(), 900);

    // Bounded above: the S3 maximum is admitted, anything past it is clamped
    // to it rather than signed verbatim.
    assert_eq!(
        state_with_presign_ttl(Some(S3_MAX_EXPIRES_SECS)).asset_presign_ttl_secs(),
        S3_MAX_EXPIRES_SECS
    );
    for over_long in [S3_MAX_EXPIRES_SECS + 1, 31_536_000, u64::MAX] {
        assert_eq!(
            state_with_presign_ttl(Some(over_long)).asset_presign_ttl_secs(),
            S3_MAX_EXPIRES_SECS,
            "a {over_long}s configured TTL must be clamped to S3's {S3_MAX_EXPIRES_SECS}s \
             maximum, not signed into X-Amz-Expires verbatim"
        );
    }

    // Bounded below: a zero TTL would mint an already-expired URL, so it is
    // raised to the smallest usable window instead.
    assert_eq!(state_with_presign_ttl(Some(0)).asset_presign_ttl_secs(), 1);
}
