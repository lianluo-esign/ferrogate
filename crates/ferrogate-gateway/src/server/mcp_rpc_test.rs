// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP RPC policy, kept outside business logic.

use super::*;

use ferrogate_storage::{sha256_hex, StoredAsset};

use ferrogate_config::{ApiKey, Config};

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

#[test]
fn server_discovery_requires_tools_read_scope() {
    assert_eq!(required_scope("server/discover").unwrap(), "tools.read");
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
    block_on(crate::auth::authenticate(
        state,
        &headers,
        "assets.read",
        "req",
    ))
    .expect("authenticates")
}

fn test_ctx() -> ProxyContext {
    ProxyContext {
        request_id: "req".into(),
        ..ProxyContext::default()
    }
}

fn seeded_asset(
    tenant: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    body: &[u8],
) -> StoredAsset {
    StoredAsset {
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
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn seed(state: &AppState, tenant: &str, asset_type: &str, name: &str, version: &str, body: &[u8]) {
    block_on(state.upsert_asset(seeded_asset(tenant, asset_type, name, version, body))).unwrap();
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

/// Issue #529 rework: `resources/read` inlines a full second copy of the object
/// into a response value that somebody else serializes and writes. Round 1
/// released the admission charge at the end of the handler's match arm, so N
/// stalled clients each held a copy the ceiling had stopped counting -- the
/// registry pull and the site serve, which bind their permit across the
/// response write, did not have this hole.
///
/// This drives the production response builder with a genuinely charged buffer
/// and asserts the charge survives the call and dies with the response. The
/// enclosing handler is not reachable with one (it needs a live bucket), which
/// is why the builder is its own function.
#[test]
fn a_resources_read_response_holds_its_charge_until_the_response_is_dropped() {
    use crate::server::asset_admission::{BufferedObject, GatewayBufferBudget, ReadResidency};

    const OBJECT_BYTES: u64 = 64 * 1024;
    let budget = GatewayBufferBudget::new(
        4 * OBJECT_BYTES,
        OBJECT_BYTES,
        std::time::Duration::from_millis(0),
    );
    let body = vec![b'x'; OBJECT_BYTES as usize];
    let permit = block_on(budget.admit(ReadResidency::BufferOnly, OBJECT_BYTES))
        .map_err(|_| ())
        .expect("the fixture read fits its budget");
    let free_while_held = budget.available_bytes();
    assert_eq!(
        free_while_held,
        3 * OBJECT_BYTES,
        "the fixture must actually be charged, or nothing below proves anything"
    );

    let asset = StoredAsset {
        content_type: "text/plain".into(),
        content_hash: sha256_hex(&body),
        size_bytes: OBJECT_BYTES,
        ..seeded_asset("tenant-1", "cli_tool", "deploy", "1.0.0", b"")
    };
    let response =
        asset_resource_read_result(Some(json!(1)), &asset, BufferedObject::new(body, permit));

    assert!(
        response.holds_a_buffer_charge(),
        "the response must carry the charge for the copy of the object inside it"
    );
    assert_eq!(
        budget.available_bytes(),
        free_while_held,
        "building the response must NOT return the charge: the object is still resident, now as \
         JSON, and is about to be serialized and written"
    );
    let value = serde_json::to_value(&response).unwrap();
    assert_eq!(
        value["result"]["contents"][0]["text"]
            .as_str()
            .unwrap()
            .len(),
        OBJECT_BYTES as usize,
        "the copy being charged for must actually be in the response"
    );
    assert!(
        value.get("budget").is_none(),
        "the charge is gateway bookkeeping and must never be serialized to a client"
    );
    assert_eq!(
        budget.available_bytes(),
        free_while_held,
        "serializing it does not release it either -- that copy is resident too"
    );

    drop(response);
    assert_eq!(
        budget.available_bytes(),
        4 * OBJECT_BYTES,
        "dropping the response -- which the writer does after the socket write -- returns the \
         charge"
    );
}

/// The second #529 rework bounce was specifically the `builtin.fetch_asset`
/// path through MCP `tools/call`: content was copied into the JSON-RPC result,
/// but no behavioral test proved the real charge followed that copy. Drive the
/// two exact production builders so replacing either handoff with `none()`
/// releases the semaphore here and fails before the response is dropped.
#[test]
fn tools_call_keeps_fetch_asset_charge_through_result_holding_until_drop() {
    use crate::server::asset_admission::{
        BufferedObject, GatewayBufferBudget, ReadResidency, ADMISSION_UNIT_BYTES,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

    const OBJECT_BYTES: u64 = 4 * ADMISSION_UNIT_BYTES;
    const BUDGET_BYTES: u64 = 32 * ADMISSION_UNIT_BYTES;
    let budget = GatewayBufferBudget::new(BUDGET_BYTES, OBJECT_BYTES, std::time::Duration::ZERO);
    let body = vec![0xff; OBJECT_BYTES as usize];
    let expected_blob_len = BASE64_STANDARD.encode(&body).len();
    let permit = block_on(budget.admit(ReadResidency::InlinedInJsonResponse, OBJECT_BYTES))
        .map_err(|_| ())
        .expect("the fixture read fits its budget");
    let free_while_held = budget.available_bytes();
    assert!(
        free_while_held < BUDGET_BYTES,
        "the fixture must hold a real semaphore charge"
    );

    let asset = StoredAsset {
        content_type: "application/octet-stream".into(),
        content_hash: sha256_hex(&body),
        size_bytes: OBJECT_BYTES,
        ..seeded_asset("tenant-1", "cli_tool", "deploy", "1.0.0", b"")
    };
    let request = ToolExecutionRequest {
        name: crate::builtin_tools::FETCH_ASSET_TOOL_NAME.to_string(),
        arguments: json!({ "uri": "asset://cli_tool/deploy/1.0.0" }),
        route: Some("/v1/mcp".into()),
        session_id: None,
    };
    let tool_response = crate::builtin_tools::fetch_asset_response(
        &request,
        "req",
        3,
        &asset,
        BufferedObject::new(body, permit),
    );
    assert!(
        tool_response.budget.is_charged(),
        "fetch_asset_response must hand the real charge to the governed tool response"
    );
    assert_eq!(budget.available_bytes(), free_while_held);

    let response = tool_call_result(Some(json!(17)), tool_response);
    assert!(
        response.holds_a_buffer_charge(),
        "tools/call must forward fetch_asset's charge through result_holding"
    );
    assert_eq!(
        budget.available_bytes(),
        free_while_held,
        "the charge must remain committed while the JSON-RPC response owns the copied bytes"
    );
    let value = serde_json::to_value(&response).expect("response serializes");
    assert_eq!(value["id"], 17);
    assert_eq!(value["result"]["isError"], false);
    assert_eq!(
        value["result"]["content"][0]["resource"]["blob"]
            .as_str()
            .map(str::len),
        Some(expected_blob_len),
        "the JSON-RPC result must still contain the binary copy being charged"
    );
    assert!(
        value.get("budget").is_none(),
        "the charge is internal accounting, not protocol data"
    );
    assert_eq!(budget.available_bytes(), free_while_held);

    drop(response);
    assert_eq!(
        budget.available_bytes(),
        BUDGET_BYTES,
        "the final JSON-RPC response drop returns the charge"
    );
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

#[test]
fn initialize_downgrades_modern_version_to_the_direct_legacy_predecessor() {
    let value = initialize_result(&serde_json::json!({"protocolVersion": "2026-07-28"}));
    assert_eq!(value["protocolVersion"], "2025-11-25");
    assert_eq!(value["serverInfo"]["name"], "ferrogate");
}

#[test]
fn initialize_preserves_supported_legacy_protocol_versions() {
    let direct = initialize_result(&serde_json::json!({"protocolVersion": "2025-11-25"}));
    assert_eq!(direct["protocolVersion"], "2025-11-25");
    let value = initialize_result(&serde_json::json!({"protocolVersion": "2025-06-18"}));
    assert_eq!(value["protocolVersion"], "2025-06-18");
}

#[test]
fn initialize_defaults_to_the_direct_legacy_predecessor() {
    let value = initialize_result(&serde_json::json!({}));
    assert_eq!(value["protocolVersion"], "2025-11-25");
}

#[test]
fn discover_returns_the_pinned_candidate_contract_without_legacy_server_info() {
    let value = discover_result();
    assert_eq!(value["resultType"], "complete");
    assert_eq!(value["supportedVersions"][0], "2026-07-28");
    assert_eq!(value["supportedVersions"][1], "2025-11-25");
    assert_eq!(value["capabilities"]["tools"], json!({}));
    assert_eq!(value["capabilities"]["resources"], json!({}));
    assert_eq!(
        value["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "ferrogate"
    );
    assert!(value.get("serverInfo").is_none());
    assert_eq!(value["ttlMs"], 3_600_000);
    assert_eq!(value["cacheScope"], "public");
}

#[test]
fn unsupported_protocol_error_serializes_official_retry_data() {
    let response = error_with_data(
        Some(json!(7)),
        -32022,
        "Unsupported protocol version",
        Some(json!({
            "requested": "1900-01-01",
            "supported": ["2026-07-28", "2025-11-25", "2025-06-18"]
        })),
    );
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["error"]["code"], -32022);
    assert_eq!(value["error"]["data"]["requested"], "1900-01-01");
    assert_eq!(value["error"]["data"]["supported"][0], "2026-07-28");
}

#[test]
fn modern_successes_gain_the_required_result_type_without_changing_errors() {
    let mut success = result(Some(json!(1)), json!({"tools": []}));
    success.complete_modern_result();
    let value = serde_json::to_value(success).unwrap();
    assert_eq!(value["result"]["resultType"], "complete");

    let mut response = error(Some(json!(1)), -32601, "missing");
    response.complete_modern_result();
    let value = serde_json::to_value(response).unwrap();
    assert!(value.get("result").is_none());
    assert_eq!(value["error"]["code"], -32601);
}
