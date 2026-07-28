// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-28
// description: Focused unit coverage for stateless modern MCP ingress validation.

use super::*;

fn rpc(method: &str, params: Value) -> McpJsonRpcRequest {
    McpJsonRpcRequest {
        jsonrpc: Some("2.0".to_string()),
        id: Some(json!(1)),
        method: method.to_string(),
        params,
    }
}

fn modern_params(extra: Value) -> Value {
    let mut params = extra.as_object().cloned().unwrap_or_default();
    let mut metadata = serde_json::Map::new();
    metadata.insert(PROTOCOL_VERSION_META.to_string(), json!("2026-07-28"));
    metadata.insert(CLIENT_CAPABILITIES_META.to_string(), json!({}));
    params.insert("_meta".to_string(), Value::Object(metadata));
    Value::Object(params)
}

fn modern_headers(method: &str, name: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        "2026-07-28".parse().unwrap(),
    );
    headers.insert(ferrogate_mcp::MCP_METHOD_HEADER, method.parse().unwrap());
    if let Some(name) = name {
        headers.insert(ferrogate_mcp::MCP_NAME_HEADER, name.parse().unwrap());
    }
    headers
}

#[test]
fn modern_requests_are_self_describing_and_never_depend_on_prior_requests() {
    let request = rpc("tools/list", modern_params(json!({})));
    let validated = validate_ingress(&modern_headers("tools/list", None), &request).unwrap();
    assert_eq!(validated.mode, McpIngressMode::Modern);
    assert_eq!(validated.metric_method, "tools/list");

    let legacy = rpc("tools/list", json!({}));
    let validated = validate_ingress(&HeaderMap::new(), &legacy).unwrap();
    assert_eq!(validated.mode, McpIngressMode::Legacy);

    // Re-validating the modern shape after an unrelated legacy request proves
    // the result is derived from this request, not remembered capabilities.
    let validated = validate_ingress(&modern_headers("tools/list", None), &request).unwrap();
    assert_eq!(validated.mode, McpIngressMode::Modern);
}

#[test]
fn initialize_is_modern_only_with_a_complete_current_request_envelope() {
    let modern = rpc("initialize", modern_params(json!({})));
    let validated = validate_ingress(&modern_headers("initialize", None), &modern).unwrap();
    assert_eq!(validated.mode, McpIngressMode::Modern);

    let plain_legacy = rpc(
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
    );
    assert_eq!(
        ingress_mode(&HeaderMap::new(), &plain_legacy),
        McpIngressMode::Legacy
    );

    let incomplete = rpc(
        "initialize",
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28"
            }
        }),
    );
    assert_eq!(
        ingress_mode(&modern_headers("initialize", None), &incomplete),
        McpIngressMode::Legacy,
        "an initialize request must not enter modern validation from partial metadata"
    );

    let malformed_client_info = rpc(
        "initialize",
        json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {"name": "missing-version"}
            }
        }),
    );
    assert_eq!(
        ingress_mode(&modern_headers("initialize", None), &malformed_client_info),
        McpIngressMode::Legacy,
        "malformed optional clientInfo must not classify initialize as modern"
    );
}

#[test]
fn missing_modern_headers_fail_with_header_mismatch() {
    let request = rpc(
        "tools/call",
        modern_params(json!({"name": "search", "arguments": {}})),
    );
    let complete = modern_headers("tools/call", Some("search"));

    for missing in [
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        ferrogate_mcp::MCP_METHOD_HEADER,
        ferrogate_mcp::MCP_NAME_HEADER,
    ] {
        let mut headers = complete.clone();
        headers.remove(missing);
        let error = validate_ingress(&headers, &request).unwrap_err();
        assert_eq!(error.code(), -32020, "removing {missing} must red");
    }
}

#[test]
fn malformed_or_missing_modern_body_metadata_fails_with_invalid_params() {
    let complete = modern_headers("tools/call", Some("search"));
    let request = || {
        rpc(
            "tools/call",
            modern_params(json!({"name": "search", "arguments": {}})),
        )
    };

    let mut missing_capabilities = request();
    missing_capabilities.params["_meta"]
        .as_object_mut()
        .unwrap()
        .remove(CLIENT_CAPABILITIES_META);
    assert_eq!(
        validate_ingress(&complete, &missing_capabilities)
            .unwrap_err()
            .code(),
        -32602
    );

    let mut missing_body_version = request();
    missing_body_version.params["_meta"]
        .as_object_mut()
        .unwrap()
        .remove(PROTOCOL_VERSION_META);
    assert_eq!(
        validate_ingress(&complete, &missing_body_version)
            .unwrap_err()
            .code(),
        -32602
    );

    for metadata in [
        Value::Null,
        json!({
            "io.modelcontextprotocol/protocolVersion": 20260728,
            "io.modelcontextprotocol/clientCapabilities": {}
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": [],
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": "not-an-object",
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {},
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": 570,
                "version": "1.0.0"
            },
        }),
        json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "ferrogate-test",
                "version": false
            },
        }),
    ] {
        let mut malformed = request();
        malformed.params["_meta"] = metadata;
        let error = validate_ingress(&complete, &malformed)
            .expect_err("malformed request metadata must fail");
        assert_eq!(error.code(), -32602, "error={error}");
        assert!(error.message().starts_with("Invalid params:"));
    }

    let mut unsupported_without_capabilities = request();
    unsupported_without_capabilities.params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2099-01-01"
    });
    let mut unsupported_headers = complete;
    unsupported_headers.insert(
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        "2099-01-01".parse().unwrap(),
    );
    assert_eq!(
        validate_ingress(&unsupported_headers, &unsupported_without_capabilities)
            .unwrap_err()
            .code(),
        -32602,
        "body schema validation must precede version support"
    );
}

#[test]
fn protocol_and_routing_mismatches_are_typed_and_base64_name_is_decoded() {
    let request = rpc(
        "tools/call",
        modern_params(json!({"name": "http-search", "arguments": {}})),
    );
    let encoded = modern_headers("tools/call", Some("=?base64?aHR0cC1zZWFyY2g=?="));
    let validated = validate_ingress(&encoded, &request).unwrap();
    assert_eq!(validated.metric_name, "http-search");

    let mismatch = modern_headers("tools/list", Some("http-search"));
    assert_eq!(
        validate_ingress(&mismatch, &request).unwrap_err().code(),
        -32020
    );

    let mut version_mismatch = modern_headers("tools/call", Some("http-search"));
    version_mismatch.insert(
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        "2025-11-25".parse().unwrap(),
    );
    assert_eq!(
        validate_ingress(&version_mismatch, &request)
            .unwrap_err()
            .code(),
        -32020
    );
}

#[test]
fn matching_unknown_version_reports_requested_and_supported_versions() {
    let mut request = rpc("tools/list", modern_params(json!({})));
    request.params["_meta"][PROTOCOL_VERSION_META] = json!("1900-01-01");
    let mut headers = modern_headers("tools/list", None);
    headers.insert(
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        "1900-01-01".parse().unwrap(),
    );

    let error = validate_ingress(&headers, &request).unwrap_err();
    assert_eq!(error.code(), -32022);
    assert!(error.to_string().contains("1900-01-01"));
    let data = error.data().expect("unsupported versions carry retry data");
    assert_eq!(data["requested"], "1900-01-01");
    assert_eq!(data["supported"][0], "2026-07-28");
}

#[test]
fn name_header_is_required_for_every_named_standard_method() {
    for (method, params) in [
        ("tools/call", modern_params(json!({"name": "tool"}))),
        (
            "resources/read",
            modern_params(json!({"uri": "asset://bundle/name/1"})),
        ),
        ("prompts/get", modern_params(json!({"name": "prompt"}))),
    ] {
        let error = validate_ingress(&modern_headers(method, None), &rpc(method, params))
            .expect_err("named methods require Mcp-Name");
        assert_eq!(error.code(), -32020, "method={method}");
    }
}

#[test]
fn duplicate_modern_routing_headers_are_rejected_as_ambiguous() {
    let request = rpc("tools/list", modern_params(json!({})));
    for name in [
        ferrogate_mcp::MCP_PROTOCOL_VERSION_HEADER,
        ferrogate_mcp::MCP_METHOD_HEADER,
    ] {
        let mut headers = modern_headers("tools/list", None);
        headers.append(name, "conflicting-value".parse().unwrap());
        let error = validate_ingress(&headers, &request)
            .expect_err("a repeated non-list header cannot be a routing authority");
        assert_eq!(error.code(), -32020, "header={name}");
        assert!(error.to_string().contains("more than once"));
    }
}
