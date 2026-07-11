// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP RPC policy, kept outside business logic.

use super::*;

#[test]
fn missing_method_scope_mapping_fails_closed() {
    let error = required_scope("unmapped/method").expect_err("missing mapping must fail");
    assert_eq!(error.method, "unmapped/method");
    assert!(error.to_string().contains("no MCP scope mapping"));
}
