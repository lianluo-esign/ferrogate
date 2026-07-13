// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-13
// description: Unit tests for the live target-capability Supabase contract (#204).

use super::*;

#[test]
fn live_config_binds_target_grant_to_a_permission_key() {
    let config = target_capability_supabase_config(
        "127.0.0.1:8080",
        "ferrogate_test_tgt_contract",
        std::path::Path::new("/tmp/ferrogate-target.sock"),
        "verify_full",
        None,
    )
    .unwrap();

    assert!(config.contains("permission_key = \"managed_actions.mcp.customer_lookup\""));
    assert!(config.contains("class_only_policy_mode = \"deny\""));
    assert!(config.contains("postgres_schema = \"ferrogate_test_tgt_contract\""));
}

#[test]
fn runtime_request_carries_tenant_and_exact_mcp_target() {
    let request = target_authorization_request();

    assert_eq!(request.authorization.session.tenant_id, TARGET_TENANT_ID);
    assert_eq!(
        request.request_id,
        request.authorization.stable_request_id()
    );
    let ferrogate_runtime::ExternalActionSpec::McpTool {
        server_name,
        tool_name,
        arguments,
        ..
    } = request.authorization.action
    else {
        panic!("expected MCP target request");
    };
    assert_eq!(server_name, "customer-crm");
    assert_eq!(tool_name, "lookup");
    assert_eq!(arguments["customer_id"], "customer-204");
}
