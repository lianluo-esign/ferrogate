// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Shared helpers for the sibling `*_test.rs` files: a canned server config
//! and disconnect-tolerant one-shot HTTP test-server plumbing.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use ferrogate_core::ApprovalPolicy;

use crate::config::{McpAuthType, McpServerConfig, McpTlsConfig, McpTransport};

pub(crate) fn test_config(name: &str) -> McpServerConfig {
    McpServerConfig {
        name: name.into(),
        transport: McpTransport::StreamableHttp,
        url: Some("http://127.0.0.1/mcp".into()),
        command: None,
        args: Vec::new(),
        auth_type: McpAuthType::None,
        headers: Vec::new(),
        oauth: None,
        signed_jwt_audience: None,
        tools_to_execute: vec!["search".into()],
        tools_to_auto_execute: Vec::new(),
        approval_policy: ApprovalPolicy::Never,
        tool_include: Vec::new(),
        tool_regex: Vec::new(),
        tls: McpTlsConfig::default(),
        timeout_ms: 1000,
        health_ping_interval_secs: 10,
        max_reconnect_attempts: 5,
        min_reconnect_backoff_secs: 1,
        max_reconnect_backoff_secs: 30,
    }
}

/// True for the I/O errors a one-shot test server legitimately sees when the
/// client already has what it needs (or gave up under CPU load) and dropped the
/// connection. These must never fail a test: the protocol behaviour under test
/// happened on the client side; a racing EPIPE/ECONNRESET on the server thread
/// is benign. See issue #327 (same family as #234/#235/#240/#324).
fn is_benign_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::{
        BrokenPipe, ConnectionAborted, ConnectionReset, TimedOut, UnexpectedEof, WouldBlock,
    };
    matches!(
        err.kind(),
        BrokenPipe | ConnectionReset | ConnectionAborted | WouldBlock | TimedOut | UnexpectedEof
    )
}

/// Reads one HTTP request from a test-server socket: the headers (through
/// CRLFCRLF) plus the body as advertised by `Content-Length`, so a request the
/// OS segments across multiple TCP reads is still captured whole (issue #438 —
/// stopping at the header terminator raced and dropped bodies that arrived in
/// a later segment). Requests with no `Content-Length` complete at the header
/// terminator, as before. The loop is bounded by a total-byte cap and a
/// wall-clock deadline so a broken test cannot hang the server thread.
/// Tolerates a client that reset the connection under load instead of
/// panicking, returning whatever was captured so far. Only a
/// genuinely-unexpected I/O error panics (that would be a real bug, not a
/// race). Name kept from the pre-#438 headers-only reader for call-site
/// stability.
pub(crate) fn read_until_headers_end(stream: &mut impl Read) -> Vec<u8> {
    /// Far above any request these tests send; a cap, not a target.
    const MAX_CAPTURE_BYTES: usize = 1 << 20;
    /// Generous versus the clients' own timeouts, so the bound never fires in
    /// a healthy run even under CPU-load stalls (issue #327).
    const CAPTURE_DEADLINE: Duration = Duration::from_secs(60);

    let deadline = Instant::now() + CAPTURE_DEADLINE;
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    while received.len() < MAX_CAPTURE_BYTES && Instant::now() < deadline {
        match Read::read(stream, &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&chunk[..n]);
                if request_capture_is_complete(&received) {
                    break;
                }
            }
            Err(err) if is_benign_disconnect(&err) => break,
            Err(err) => panic!("unexpected read error in one-shot test server: {err}"),
        }
    }
    received
}

/// True once `received` holds a full HTTP request: terminated headers plus a
/// body of at least `Content-Length` bytes (zero when the header is absent or
/// malformed, matching the header-terminated capture the tests relied on
/// before bodies were drained).
fn request_capture_is_complete(received: &[u8]) -> bool {
    let Some(headers_end) = received.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = headers_end + 4;
    let content_length = content_length_of(&received[..headers_end]);
    received.len() - body_start >= content_length
}

/// Parses `Content-Length` (case-insensitively, per RFC 9110) out of raw
/// header bytes, treating a missing or malformed header as zero.
fn content_length_of(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// Writes the canned response to a test-server socket and flushes it, tolerating
/// a client that already hung up (the client got what it needed, or timed out
/// under load and dropped the connection). Only a genuinely-unexpected I/O error
/// panics.
pub(crate) fn write_response_tolerant(stream: &mut impl Write, response: &[u8]) {
    if let Err(err) = stream.write_all(response) {
        assert!(
            is_benign_disconnect(&err),
            "unexpected write error in one-shot test server: {err}"
        );
        return;
    }
    if let Err(err) = stream.flush() {
        assert!(
            is_benign_disconnect(&err),
            "unexpected flush error in one-shot test server: {err}"
        );
    }
}

pub(crate) fn json_http_response(json_body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json_body.len(),
        json_body
    )
}
