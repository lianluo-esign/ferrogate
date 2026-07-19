// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP RPC policy, kept outside business logic.

use super::*;

use ferrogate_storage::{sha256_hex, StoredAsset};

use crate::config::{ApiKey, Config};

#[test]
fn missing_method_scope_mapping_fails_closed() {
    let error = required_scope("unmapped/method").expect_err("missing mapping must fail");
    assert_eq!(error.method, "unmapped/method");
    assert!(error.to_string().contains("no MCP scope mapping"));
}

/// Acceptance (issue #257): the resources ingress reuses the asset-read scope,
/// so a key without `assets.read` is rejected at the ingress `authenticate`
/// step -- never reaching the handler to be masked as an empty list.
#[test]
fn resources_methods_require_assets_read_scope() {
    assert_eq!(required_scope("resources/list").unwrap(), "assets.read");
    assert_eq!(required_scope("resources/read").unwrap(), "assets.read");
}

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn reader_state(tenant: Option<&str>) -> AppState {
    AppState::new(Config {
        api_keys: vec![ApiKey {
            region_allowlist: Vec::new(),
            id: "reader".into(),
            name: "reader".into(),
            key_env: None,
            key: Some("reader-secret".into()),
            key_hash: None,
            enabled: true,
            scopes: vec!["assets.read".into()],
            allowed_models: vec![],
            denied_models: vec![],
            allowed_providers: vec![],
            denied_providers: vec![],
            organization_id: tenant.map(ToOwned::to_owned),
            team_id: None,
            project_id: None,
            workspace_id: None,
            user_id: None,
            monthly_token_budget: None,
            request_limit_per_minute: None,
            expires_at_unix: None,
            log_bodies: None,
            cache_enabled: None,
        }],
        ..Config::default()
    })
}

fn reader_auth(state: &AppState) -> AuthContext {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        "Bearer reader-secret".parse().unwrap(),
    );
    crate::auth::authenticate(state, &headers, "assets.read", "req").expect("authenticates")
}

fn test_ctx() -> ProxyContext {
    ProxyContext {
        request_id: "req".into(),
        ..ProxyContext::default()
    }
}

fn seed(state: &AppState, tenant: &str, asset_type: &str, name: &str, version: &str, body: &[u8]) {
    block_on(state.upsert_asset(StoredAsset {
        id: stored_asset_id(tenant, asset_type, name, version),
        tenant_id: tenant.into(),
        project_id: None,
        asset_type: asset_type.into(),
        name: name.into(),
        version: version.into(),
        content_type: "text/plain".into(),
        content_hash: sha256_hex(body),
        size_bytes: body.len() as u64,
        content: body.to_vec(),
        storage_uri: None,
        created_at_unix: 1,
        updated_at_unix: 1,
    }))
    .unwrap();
}

#[test]
fn resources_list_maps_tenant_assets_to_uris() {
    let state = reader_state(Some("tenant-1"));
    seed(&state, "tenant-1", "cli_tool", "deploy", "1.0.0", b"echo");
    // A different tenant's asset must not leak into this key's listing.
    seed(&state, "tenant-2", "cli_tool", "other", "1.0.0", b"nope");
    let auth = reader_auth(&state);

    let response = block_on(resources_list(&state, &test_ctx(), &auth, Some(json!(1))));
    let value = serde_json::to_value(&response).unwrap();
    let resources = value["result"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"], "asset://cli_tool/deploy/1.0.0");
    assert_eq!(resources[0]["_meta"]["sha256"], sha256_hex(b"echo"));
}

#[test]
fn resources_list_without_tenant_is_a_json_rpc_error() {
    let state = reader_state(None);
    let auth = reader_auth(&state);
    let response = block_on(resources_list(&state, &test_ctx(), &auth, Some(json!(1))));
    let value = serde_json::to_value(&response).unwrap();
    assert!(value["result"].is_null());
    assert_eq!(value["error"]["code"], ASSET_TENANT_REQUIRED_CODE);
}

#[test]
fn resources_read_returns_content_with_matching_fingerprint() {
    let state = reader_state(Some("tenant-1"));
    seed(
        &state,
        "tenant-1",
        "cli_tool",
        "deploy",
        "1.0.0",
        b"echo hello",
    );
    let auth = reader_auth(&state);

    let response = block_on(resources_read(
        &state,
        &test_ctx(),
        &auth,
        Some(json!(1)),
        &json!({ "uri": "asset://cli_tool/deploy/1.0.0" }),
    ));
    let value = serde_json::to_value(&response).unwrap();
    let contents = value["result"]["contents"].as_array().unwrap();
    assert_eq!(contents[0]["uri"], "asset://cli_tool/deploy/1.0.0");
    assert_eq!(contents[0]["text"], "echo hello");
    assert_eq!(contents[0]["_meta"]["sha256"], sha256_hex(b"echo hello"));
}

#[test]
fn resources_read_rejects_bad_uri_and_missing_asset() {
    let state = reader_state(Some("tenant-1"));
    let auth = reader_auth(&state);

    let bad = block_on(resources_read(
        &state,
        &test_ctx(),
        &auth,
        Some(json!(1)),
        &json!({ "uri": "https://example/x" }),
    ));
    assert_eq!(serde_json::to_value(&bad).unwrap()["error"]["code"], -32602);

    let missing = block_on(resources_read(
        &state,
        &test_ctx(),
        &auth,
        Some(json!(1)),
        &json!({ "uri": "asset://cli_tool/absent/9.9.9" }),
    ));
    let value = serde_json::to_value(&missing).unwrap();
    assert_eq!(value["error"]["code"], -32602);
    assert!(value["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no asset"));
}
