// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for the gateway API contract, kept outside business logic.

use super::*;

#[test]
fn embedded_contract_builds_and_exposes_operation_metadata() {
    let operation = operation(&Method::GET, "/healthz").expect("health operation");
    assert_eq!(operation.operation_id, "getHealthz");
    assert_eq!(operation.visibility, "public");
    assert_eq!(operation.auth.kind, "anonymous");
    assert!(operation.rbac_action.is_none());
}

#[test]
fn mcp_contract_maps_supported_json_rpc_methods_to_scopes() {
    let operation = operation(&Method::POST, "/v1/mcp").expect("MCP operation");
    let discriminator = operation
        .auth
        .scope_discriminator
        .as_ref()
        .expect("method-dependent scope discriminator");
    assert_eq!(discriminator.field, "method");
    assert_eq!(
        discriminator.map.get("initialize").map(String::as_str),
        Some("tools.read")
    );
    assert_eq!(
        discriminator
            .map
            .get("notifications/initialized")
            .map(String::as_str),
        Some("tools.read")
    );
    assert_eq!(
        discriminator.map.get("ping").map(String::as_str),
        Some("tools.read")
    );
    assert_eq!(
        discriminator.map.get("tools/list").map(String::as_str),
        Some("tools.read")
    );
    assert_eq!(
        discriminator.map.get("tools/call").map(String::as_str),
        Some("tools.execute")
    );
}

#[test]
fn duplicate_operation_identity_is_rejected() {
    let error = parse_contract(
        r#"{
          "version": 1,
          "route_patterns": [{"pattern":"/a","group":"inference"}],
          "operations": [
            {"path":"/a","method":"get","operation_id":"same","visibility":"public","auth":{"kind":"anonymous","scope":null},"rbac_action":null},
            {"path":"/a","method":"post","operation_id":"same","visibility":"public","auth":{"kind":"anonymous","scope":null},"rbac_action":null}
          ]
        }"#,
    )
    .err()
    .expect("duplicate operation id must fail");
    assert!(error.contains("duplicate operation_id same"));
}

#[test]
fn bearer_operation_requires_an_explicit_scope() {
    let error = parse_contract(
        r#"{
          "version": 1,
          "route_patterns": [{"pattern":"/a","group":"inference"}],
          "operations": [
            {"path":"/a","method":"get","operation_id":"getA","visibility":"public","auth":{"kind":"bearer","scope":null},"rbac_action":null}
          ]
        }"#,
    )
    .err()
    .expect("missing bearer scope must fail");
    assert!(error.contains("without a scope"));
}

#[test]
fn method_dependent_operation_requires_a_scope_discriminator() {
    let error = parse_contract(
        r#"{
          "version": 1,
          "route_patterns": [{"pattern":"/a","group":"inference"}],
          "operations": [
            {"path":"/a","method":"post","operation_id":"postA","visibility":"public","auth":{"kind":"method_dependent","scope":null},"rbac_action":null}
          ]
        }"#,
    )
    .err()
    .expect("missing discriminator must fail");
    assert!(error.contains("without a scope discriminator"));
}
