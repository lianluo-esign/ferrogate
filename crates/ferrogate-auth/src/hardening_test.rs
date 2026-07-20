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

// --- Body framing rejections (issue #328, finding 2) ---
//
// The parser frames a body solely from `Content-Length`. It must reject
// (not silently zero-length) a chunked/unlengthed body-bearing request so
// callers can answer 400/411 instead of forwarding a truncated request.

fn parse(raw: &str) -> anyhow::Result<HttpRequest> {
    // `&[u8]` implements `Read`; feed the whole request in one buffer.
    let mut reader = raw.as_bytes();
    read_http_request_bounded(&mut reader, MAX_REQUEST_BYTES)
}

#[test]
fn chunked_post_is_rejected_as_unsupported_transfer_encoding() {
    let error = parse(
        "POST /v1/auth/authorize HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
         5\r\nhello\r\n0\r\n\r\n",
    )
    .unwrap_err();
    let length_error = error
        .downcast_ref::<RequestLengthError>()
        .expect("chunked request must surface a RequestLengthError");
    assert_eq!(*length_error, RequestLengthError::ChunkedUnsupported);
    assert_eq!(length_error.http_status(), 400);
}

#[test]
fn post_without_content_length_is_rejected_as_length_required() {
    let error = parse("POST /v1/auth/authorize HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
    let length_error = error
        .downcast_ref::<RequestLengthError>()
        .expect("unlengthed POST must surface a RequestLengthError");
    assert_eq!(*length_error, RequestLengthError::LengthRequired);
    assert_eq!(length_error.http_status(), 411);
}

#[test]
fn post_with_explicit_content_length_still_parses() {
    let request =
        parse("POST /v1/auth/authorize HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
            .expect("a normal Content-Length body must still parse");
    assert_eq!(request.method, "POST");
    assert_eq!(request.body, b"hello");
}

#[test]
fn post_with_zero_content_length_still_parses() {
    let request = parse("POST /v1/auth/logout HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
        .expect("an explicit zero-length body is a valid intent");
    assert_eq!(request.method, "POST");
    assert!(request.body.is_empty());
}

#[test]
fn get_without_body_still_parses() {
    let request = parse("GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .expect("a bodyless GET must be unaffected by the length requirement");
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/healthz");
    assert!(request.body.is_empty());
}

#[test]
fn delete_without_body_or_length_still_parses() {
    // DELETE (like the admin project/workspace delete) carries no body and
    // must not be forced to send a Content-Length.
    let request = parse("DELETE /admin/v1/projects/p_1 HTTP/1.1\r\nHost: x\r\n\r\n")
        .expect("a bodyless DELETE must be unaffected by the length requirement");
    assert_eq!(request.method, "DELETE");
    assert!(request.body.is_empty());
}
