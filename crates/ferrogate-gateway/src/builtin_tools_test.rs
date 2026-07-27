// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for the built-in gateway tools (issue #257): the
// asset->resource URI mapping/metadata and the `fetch_asset` execution's
// asset-read authz (scope + tenant), kept outside business logic.

use super::*;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ferrogate_storage::{sha256_hex, StoredAsset};
use serde_json::json;

use crate::state::AppState;
use ferrogate_config::{ApiKey, Config};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn api_key(id: &str, secret: &str, scopes: &[&str], tenant: Option<&str>) -> ApiKey {
    ApiKey {
        region_allowlist: Vec::new(),
        id: id.into(),
        name: id.into(),
        key_env: None,
        key: Some(secret.into()),
        key_hash: None,
        enabled: true,
        scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
        allowed_models: vec![],
        denied_models: vec![],
        allowed_providers: vec![],
        denied_providers: vec![],
        organization_id: tenant.map(ToOwned::to_owned),
        // #540: root only where this fixture names no tenant -- exactly the
        // keys the pre-#540 default promoted, and nothing more.
        platform_operator: tenant.is_none().then_some(true),
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        monthly_token_budget: None,
        request_limit_per_minute: None,
        expires_at_unix: None,
        log_bodies: None,
        cache_enabled: None,
    }
}

fn bearer(secret: &str) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        format!("Bearer {secret}").parse().unwrap(),
    );
    headers
}

fn seed_asset(
    state: &AppState,
    tenant: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    content_type: &str,
    content: &[u8],
) -> StoredAsset {
    let asset = StoredAsset {
        id: stored_asset_id(tenant, asset_type, name, version),
        tenant_id: tenant.into(),
        project_id: None,
        asset_type: asset_type.into(),
        name: name.into(),
        version: version.into(),
        content_type: content_type.into(),
        content_hash: sha256_hex(content),
        size_bytes: content.len() as u64,
        content: content.to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    };
    block_on(state.upsert_asset(asset.clone())).unwrap();
    asset
}

#[test]
fn parse_asset_uri_round_trips_and_rejects_malformed() {
    assert_eq!(
        parse_asset_uri("asset://cli_tool/deploy/1.2.0"),
        Some((
            "cli_tool".to_string(),
            "deploy".to_string(),
            "1.2.0".to_string()
        ))
    );
    assert_eq!(
        parse_asset_uri(&asset_uri("cli_tool", "deploy", "1.2.0")),
        Some((
            "cli_tool".to_string(),
            "deploy".to_string(),
            "1.2.0".to_string()
        ))
    );
    // Wrong scheme, wrong arity, and empty segments all fail closed.
    assert_eq!(parse_asset_uri("https://cli_tool/deploy/1.2.0"), None);
    assert_eq!(parse_asset_uri("asset://cli_tool/deploy"), None);
    assert_eq!(parse_asset_uri("asset://cli_tool//1.2.0"), None);
    assert_eq!(parse_asset_uri("asset://a/b/c/d"), None);
}

#[test]
fn resource_descriptor_exposes_uri_and_fingerprint_metadata() {
    let content = b"echo hello";
    let asset = StoredAsset {
        id: stored_asset_id("tenant-1", "cli_tool", "deploy", "1.0.0"),
        tenant_id: "tenant-1".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "deploy".into(),
        version: "1.0.0".into(),
        content_type: "text/plain".into(),
        content_hash: sha256_hex(content),
        size_bytes: content.len() as u64,
        content: content.to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    };
    let descriptor = asset_resource_descriptor(&asset);
    assert_eq!(descriptor["uri"], "asset://cli_tool/deploy/1.0.0");
    assert_eq!(descriptor["mimeType"], "text/plain");
    assert_eq!(descriptor["size"], content.len() as u64);
    assert_eq!(descriptor["_meta"]["sha256"], sha256_hex(content));
    assert_eq!(descriptor["_meta"]["assetType"], "cli_tool");
    assert_eq!(descriptor["_meta"]["storageBacked"], false);
}

#[test]
fn content_entry_inlines_text_but_base64_encodes_binary() {
    let text = b"line one\nline two\n";
    let text_asset = StoredAsset {
        content_type: "text/markdown".into(),
        content_hash: sha256_hex(text),
        size_bytes: text.len() as u64,
        content: text.to_vec(),
        ..blank_asset()
    };
    let entry = asset_resource_content_entry(
        &text_asset,
        crate::server::asset_admission::BufferedObject::unbudgeted(text.to_vec()),
    )
    .value;
    assert_eq!(entry["text"], "line one\nline two\n");
    assert!(entry.get("blob").is_none());
    assert_eq!(entry["_meta"]["sha256"], sha256_hex(text));

    let binary = &[0u8, 159, 146, 150, 255];
    let binary_asset = StoredAsset {
        content_type: "application/octet-stream".into(),
        content_hash: sha256_hex(binary),
        size_bytes: binary.len() as u64,
        content: binary.to_vec(),
        ..blank_asset()
    };
    let entry = asset_resource_content_entry(
        &binary_asset,
        crate::server::asset_admission::BufferedObject::unbudgeted(binary.to_vec()),
    )
    .value;
    assert!(entry.get("text").is_none());
    assert_eq!(entry["blob"], BASE64_STANDARD.encode(binary));
}

/// The #529 rework's core property, at the function that builds the copy.
///
/// `asset_resource_content_entry` produces a full second copy of the object
/// inside a JSON value that outlives the buffer it was built from. If the
/// charge were released when that buffer dropped, the two MCP/tool surfaces
/// would be admission-controlled rate limiters rather than memory ceilings --
/// the exact asymmetry with the registry pull and the site serve that bounced
/// round 1. Asserted on BOTH branches, because the textual branch moves the
/// buffer and the base64 branch does not.
#[test]
fn inlining_an_asset_keeps_its_charge_until_the_entry_is_dropped() {
    use crate::server::asset_admission::{
        BufferedObject, GatewayBufferBudget, ReadResidency, ADMISSION_UNIT_BYTES,
    };

    for (content_type, body) in [
        ("text/plain", vec![b'x'; 4 * ADMISSION_UNIT_BYTES as usize]),
        (
            "application/octet-stream",
            vec![0xff_u8; 4 * ADMISSION_UNIT_BYTES as usize],
        ),
    ] {
        let budget = GatewayBufferBudget::new(
            64 * ADMISSION_UNIT_BYTES,
            4 * ADMISSION_UNIT_BYTES,
            std::time::Duration::ZERO,
        );
        let permit = block_on(budget.admit(ReadResidency::BufferOnly, body.len() as u64))
            .map_err(|_| ())
            .expect("the fixture read fits its budget");
        let free_before = budget.available_bytes();
        assert!(
            free_before < 64 * ADMISSION_UNIT_BYTES,
            "the fixture must actually be charged, or the assertions below prove nothing"
        );

        let asset = StoredAsset {
            content_type: content_type.into(),
            content_hash: sha256_hex(&body),
            size_bytes: body.len() as u64,
            ..blank_asset()
        };
        let entry = asset_resource_content_entry(&asset, BufferedObject::new(body, permit));

        assert!(
            entry.budget.is_charged(),
            "{content_type}: the entry must carry the charge for the copy it holds"
        );
        assert_eq!(
            budget.available_bytes(),
            free_before,
            "{content_type}: the charge must NOT come back when the buffer is consumed -- a full \
             copy of the object is still resident inside the entry"
        );

        drop(entry);
        assert_eq!(
            budget.available_bytes(),
            64 * ADMISSION_UNIT_BYTES,
            "{content_type}: dropping the entry must return the charge"
        );
    }
}

fn blank_asset() -> StoredAsset {
    StoredAsset {
        id: "id".into(),
        tenant_id: "tenant-1".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "deploy".into(),
        version: "1.0.0".into(),
        content_type: "text/plain".into(),
        content_hash: String::new(),
        size_bytes: 0,
        content: Vec::new(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

#[test]
fn fetch_asset_tool_is_the_only_builtin_and_never_requires_hard_approval() {
    assert!(is_builtin_tool(FETCH_ASSET_TOOL_NAME));
    assert!(!is_builtin_tool("local-echo"));
    // The `-`-free name keeps the chokepoint's MCP `serverName-toolName` split
    // from ever misclassifying it as an MCP tool.
    assert!(!FETCH_ASSET_TOOL_NAME.contains('-'));

    let tool = builtin_tool_by_name(FETCH_ASSET_TOOL_NAME).expect("builtin tool");
    assert_eq!(tool.approval_policy, ferrogate_core::ApprovalPolicy::Never);
    assert_eq!(tool.extension_id, "builtin");
    assert_eq!(builtin_tools().len(), 1);
}

#[test]
fn execute_fetch_asset_returns_content_matching_stored_fingerprint() {
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "reader",
            "reader-secret",
            &["assets.read"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    let asset = seed_asset(
        &state,
        "tenant-1",
        "cli_tool",
        "deploy",
        "1.0.0",
        "text/plain",
        b"echo hello",
    );
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("reader-secret"),
        "assets.read",
        "req-1",
    ))
    .expect("assets.read key authenticates");

    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "uri": "asset://cli_tool/deploy/1.0.0" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let response =
        block_on(execute_fetch_asset(&state, &auth, &request, "req-1")).expect("fetch succeeds");
    assert!(!response.is_error);
    let block = &response.content["content"][0];
    assert_eq!(block["type"], "resource");
    assert_eq!(block["resource"]["uri"], "asset://cli_tool/deploy/1.0.0");
    assert_eq!(block["resource"]["text"], "echo hello");
    assert_eq!(block["resource"]["_meta"]["sha256"], asset.content_hash);
    assert_eq!(response.content["_meta"]["sha256"], asset.content_hash);
}

#[test]
fn execute_fetch_asset_withholds_a_quarantined_asset() {
    // #366 write-path == read-path: a quarantined asset is persisted but must
    // be withheld from the built-in `fetch_asset` download surface too (which
    // routes through the shared read_asset_content chokepoint), reported as
    // not-found exactly like the REST pull and presigned download paths.
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "reader",
            "reader-secret",
            &["assets.read"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    let content = b"quarantined payload";
    let quarantined = StoredAsset {
        id: stored_asset_id("tenant-1", "cli_tool", "deploy", "9.9.9"),
        tenant_id: "tenant-1".into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: "deploy".into(),
        version: "9.9.9".into(),
        content_type: "text/plain".into(),
        content_hash: sha256_hex(content),
        size_bytes: content.len() as u64,
        content: content.to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: ferrogate_storage::AssetVisibility::Quarantined,
        created_at_unix: 1,
        updated_at_unix: 1,
    };
    block_on(state.upsert_asset(quarantined)).unwrap();
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("reader-secret"),
        "assets.read",
        "req-1",
    ))
    .expect("assets.read key authenticates");

    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "uri": "asset://cli_tool/deploy/9.9.9" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let error = block_on(execute_fetch_asset(&state, &auth, &request, "req-1"))
        .expect_err("quarantined asset must not be fetchable");
    assert!(
        matches!(error, ToolExecutionError::NotFound(_)),
        "withheld asset must report NotFound, got {error:?}"
    );
}

#[test]
fn execute_fetch_asset_accepts_explicit_coordinates() {
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "reader",
            "reader-secret",
            &["assets.read"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    seed_asset(
        &state,
        "tenant-1",
        "config",
        "app",
        "2",
        "application/json",
        br#"{"k":1}"#,
    );
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("reader-secret"),
        "assets.read",
        "req-1",
    ))
    .expect("authenticates");
    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "asset_type": "config", "name": "app", "version": "2" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let response =
        block_on(execute_fetch_asset(&state, &auth, &request, "req-1")).expect("fetch succeeds");
    assert_eq!(
        response.content["content"][0]["resource"]["text"],
        r#"{"k":1}"#
    );
}

#[test]
fn execute_fetch_asset_denies_missing_scope_and_missing_tenant() {
    // Key with a tenant but NOT assets.read: authenticates for tools.execute,
    // but fetch_asset must deny (visibility reuses the assets.read gate).
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "exec",
            "exec-secret",
            &["tools.execute"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    seed_asset(
        &state,
        "tenant-1",
        "cli_tool",
        "deploy",
        "1.0.0",
        "text/plain",
        b"x",
    );
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("exec-secret"),
        "tools.execute",
        "req-1",
    ))
    .expect("authenticates for tools.execute");
    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "uri": "asset://cli_tool/deploy/1.0.0" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let error = block_on(execute_fetch_asset(&state, &auth, &request, "req-1")).unwrap_err();
    assert_eq!(error.code(), "tool_denied");
    assert!(error.message().contains("assets.read"), "{error:?}");

    // Key with assets.read but NO tenant attribution: denied, mirroring
    // handle_asset_pull's tenant_required.
    let state = AppState::new(Config {
        api_keys: vec![api_key("root", "root-secret", &["assets.read"], None)],
        ..Config::default()
    });
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("root-secret"),
        "assets.read",
        "req-2",
    ))
    .expect("authenticates");
    let error = block_on(execute_fetch_asset(&state, &auth, &request, "req-2")).unwrap_err();
    assert_eq!(error.code(), "tool_denied");
    assert!(error.message().contains("tenant"), "{error:?}");
}

#[test]
fn execute_fetch_asset_reports_missing_asset_as_not_found() {
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "reader",
            "reader-secret",
            &["assets.read"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("reader-secret"),
        "assets.read",
        "req-1",
    ))
    .expect("authenticates");
    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "uri": "asset://cli_tool/absent/9.9.9" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let error = block_on(execute_fetch_asset(&state, &auth, &request, "req-1")).unwrap_err();
    assert_eq!(error.code(), "tool_not_found");
}

#[test]
fn execute_fetch_asset_rejects_invalid_arguments() {
    let state = AppState::new(Config {
        api_keys: vec![api_key(
            "reader",
            "reader-secret",
            &["assets.read"],
            Some("tenant-1"),
        )],
        ..Config::default()
    });
    let auth = block_on(crate::auth::authenticate(
        &state,
        &bearer("reader-secret"),
        "assets.read",
        "req-1",
    ))
    .expect("authenticates");
    let request = ToolExecutionRequest {
        name: FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "name": "deploy" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let error = block_on(execute_fetch_asset(&state, &auth, &request, "req-1")).unwrap_err();
    assert_eq!(error.code(), "tool_execution_failed");
}
