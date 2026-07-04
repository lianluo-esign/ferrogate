// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Coverage for the HTTP hardening ported from the billing service (issue
//! #147, mirroring issue #138): bounding a declared `Content-Length` before
//! it is used as a slice index.

use super::*;

#[test]
fn bounded_body_end_rejects_content_length_over_the_limit() {
    let error = bounded_body_end(100, MAX_REQUEST_BYTES + 1, MAX_REQUEST_BYTES).unwrap_err();
    assert!(error.to_string().contains("exceeds"));
}

#[test]
fn bounded_body_end_rejects_overflowing_addition_instead_of_panicking() {
    // The historical bug: `body_start + content_length` with a malicious huge
    // Content-Length (e.g. usize::MAX) would overflow (debug builds panic) or
    // wrap (release builds produce start > end and panic on the slice).
    let error = bounded_body_end(100, usize::MAX, MAX_REQUEST_BYTES).unwrap_err();
    // usize::MAX is already caught by the max-bytes bound; assert it's
    // rejected as an error either way, never overflowing.
    assert!(error.to_string().contains("exceeds") || error.to_string().contains("overflow"));
}

#[test]
fn bounded_body_end_accepts_a_well_formed_content_length() {
    let body_end = bounded_body_end(100, 50, MAX_REQUEST_BYTES).unwrap();
    assert_eq!(body_end, 150);
}
