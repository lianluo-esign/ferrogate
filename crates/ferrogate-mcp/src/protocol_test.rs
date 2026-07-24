// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;

// -- issue #277: 2026-07-28 negotiation + Mcp-Method/Mcp-Name routing ---

#[test]
fn negotiate_protocol_version_matrix_prefers_new_and_honours_legacy() {
    // Server-side ingress negotiation (old->new and new->new both resolve to a
    // mutually supported version; anything unknown negotiates down to newest).
    assert_eq!(negotiate_protocol_version(Some("2026-07-28")), "2026-07-28");
    assert_eq!(negotiate_protocol_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(negotiate_protocol_version(None), "2026-07-28");
    assert_eq!(negotiate_protocol_version(Some("2099-01-01")), "2026-07-28");
}

#[test]
fn resolve_negotiated_version_matrix_adopts_server_choice_or_falls_back() {
    // Client-side: adopt the server's echoed version when supported, else fall
    // back to the previous stable revision.
    assert_eq!(resolve_negotiated_version(Some("2026-07-28")), "2026-07-28");
    assert_eq!(resolve_negotiated_version(Some("2025-06-18")), "2025-06-18");
    assert_eq!(resolve_negotiated_version(None), "2025-06-18");
    assert_eq!(resolve_negotiated_version(Some("2099-01-01")), "2025-06-18");
    assert!(is_supported_protocol_version("2026-07-28"));
    assert!(!is_supported_protocol_version("2099-01-01"));
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
