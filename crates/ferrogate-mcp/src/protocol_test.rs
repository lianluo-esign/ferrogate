// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;

// -- issues #277/#570: dual-era negotiation + MCP routing headers ---

#[test]
fn initialize_negotiation_never_advertises_the_modern_revision() {
    assert_eq!(negotiate_protocol_version(Some("2026-07-28")), "2025-11-25");
    assert_eq!(negotiate_protocol_version(Some("2025-11-25")), "2025-11-25");
    assert_eq!(negotiate_protocol_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(negotiate_protocol_version(None), "2025-11-25");
    assert_eq!(negotiate_protocol_version(Some("2099-01-01")), "2025-11-25");
}

#[test]
fn legacy_initialize_adopts_only_supported_legacy_revisions() {
    assert_eq!(
        resolve_legacy_protocol_version(Some("2025-11-25")),
        Some("2025-11-25")
    );
    assert_eq!(
        resolve_legacy_protocol_version(Some("2025-06-18")),
        Some("2025-06-18")
    );
    assert_eq!(resolve_legacy_protocol_version(Some("2026-07-28")), None);
    assert_eq!(resolve_legacy_protocol_version(None), None);
    assert_eq!(resolve_legacy_protocol_version(Some("2099-01-01")), None);
    assert!(is_supported_protocol_version("2026-07-28"));
    assert!(is_supported_protocol_version("2025-11-25"));
    assert!(!is_supported_protocol_version("2099-01-01"));
    // This exported compatibility helper predates strict legacy initialize
    // negotiation and must retain its modern-version behavior.
    assert_eq!(resolve_negotiated_version(Some("2026-07-28")), "2026-07-28");
    assert_eq!(resolve_negotiated_version(Some("2025-11-25")), "2025-11-25");
    assert_eq!(resolve_negotiated_version(None), "2025-06-18");
}

#[test]
fn http_downgrade_requires_an_eligible_status_without_a_modern_error() {
    let unrecognized = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32000, "message": "extension error"}
    });
    for (status, expected) in [
        (400, McpProtocolDowngradeReason::Http400UnrecognizedResponse),
        (404, McpProtocolDowngradeReason::Http404UnrecognizedResponse),
        (405, McpProtocolDowngradeReason::Http405UnrecognizedResponse),
    ] {
        assert_eq!(
            http_legacy_downgrade_reason(status, Some(&unrecognized)),
            Some(expected)
        );
    }
    for code in [-32020, -32021, -32022, -32601] {
        let modern = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": code, "message": "recognized modern error"}
        });
        assert_eq!(http_legacy_downgrade_reason(400, Some(&modern)), None);
    }
    let malformed = serde_json::json!({"error": {"code": -32022}});
    assert_eq!(
        http_legacy_downgrade_reason(400, Some(&malformed)),
        Some(McpProtocolDowngradeReason::Http400UnrecognizedResponse)
    );
    assert_eq!(http_legacy_downgrade_reason(403, None), None);
    assert_eq!(http_legacy_downgrade_reason(500, None), None);
}

#[test]
fn discovery_success_requires_the_complete_modern_result_shape() {
    let valid = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "capabilities": {}
        }
    });
    assert!(discover_supports_current_version(&valid));

    for pointer in [
        "/jsonrpc",
        "/id",
        "/result/resultType",
        "/result/capabilities",
    ] {
        let mut malformed = valid.clone();
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        malformed
            .pointer_mut(if parent.is_empty() { "" } else { parent })
            .and_then(Value::as_object_mut)
            .unwrap()
            .remove(key);
        assert!(
            !discover_supports_current_version(&malformed),
            "missing {pointer} must not select modern mode"
        );
    }
}

#[test]
fn mirrored_header_encoding_handles_unsafe_and_ambiguous_values() {
    assert_eq!(encode_mcp_header_value("search"), "search");
    assert_eq!(
        encode_mcp_header_value("=?base64?literal?="),
        "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="
    );
    assert_eq!(
        encode_mcp_header_value(" padded "),
        "=?base64?IHBhZGRlZCA=?="
    );
    assert_eq!(
        encode_mcp_header_value("line\nname"),
        "=?base64?bGluZQpuYW1l?="
    );
}

#[test]
fn verify_routing_headers_accepts_matching_or_absent_and_rejects_mismatch() {
    // Absent headers (pre-2026-07-28 client) always pass.
    assert!(verify_routing_headers(None, None, "tools/call", Some("srv-search")).is_ok());
    // Matching headers pass.
    assert!(verify_routing_headers(
        Some("tools/call"),
        Some("srv-search"),
        "tools/call",
        Some("srv-search"),
    )
    .is_ok());
    // Method mismatch fails closed.
    let method_error = verify_routing_headers(Some("tools/list"), None, "tools/call", Some("x"))
        .expect_err("method mismatch must fail");
    assert_eq!(method_error.header, "Mcp-Method");
    // Name mismatch fails closed.
    let name_error = verify_routing_headers(
        Some("tools/call"),
        Some("srv-evil"),
        "tools/call",
        Some("srv-search"),
    )
    .expect_err("name mismatch must fail");
    assert_eq!(name_error.header, "Mcp-Name");
}
