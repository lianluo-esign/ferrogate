// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Unit tests for the sibling module; kept out of the business-logic file.

use super::*;
use crate::test_support::{
    json_http_response, read_until_headers_end, test_config, write_response_tolerant,
};
use crate::tls::ensure_rustls_crypto_provider;
use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::io::Cursor;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

#[test]
fn validate_http_endpoint_accepts_http_https_and_rejects_others() {
    assert!(validate_http_endpoint("http://127.0.0.1:8080/mcp").is_ok());
    assert!(validate_http_endpoint("https://example.com/mcp").is_ok());
    assert!(validate_http_endpoint("ftp://example.com").is_err());
    assert!(validate_http_endpoint("stdio://local").is_err());
    assert!(validate_http_endpoint("not a uri at all").is_err());
}

// -- issue #167: MCP TLS/HTTPS/SSE support -----------------------------

#[test]
fn parse_http_target_defaults_https_to_port_443_and_http_to_port_80() {
    // Uses a numeric IP literal (rather than a hostname) so the test doesn't
    // depend on DNS resolution being available in the test environment.
    let https = parse_http_target("https://127.0.0.1/mcp").unwrap();
    assert_eq!(https.scheme, HttpScheme::Https);
    assert_eq!(https.authority, "127.0.0.1");
    assert_eq!(https.address.port(), 443);

    let http = parse_http_target("http://127.0.0.1/mcp").unwrap();
    assert_eq!(http.scheme, HttpScheme::Http);
    assert_eq!(http.authority, "127.0.0.1");
    assert_eq!(http.address.port(), 80);

    let https_custom_port = parse_http_target("https://127.0.0.1:8443/mcp").unwrap();
    assert_eq!(https_custom_port.authority, "127.0.0.1:8443");
    assert_eq!(https_custom_port.address.port(), 8443);
}

#[test]
fn read_sse_json_response_extracts_first_complete_json_data_event() {
    let stream = ": keep-alive comment\n\nevent: ignored\ndata: not json at all\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
    let mut reader = Cursor::new(stream.as_bytes());
    let value = read_sse_json_response(&mut reader).unwrap();
    assert_eq!(value["result"]["ok"], true);
}

#[test]
fn read_sse_json_response_joins_multi_line_data_fields() {
    let stream = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
    let mut reader = Cursor::new(stream.as_bytes());
    let value = read_sse_json_response(&mut reader).unwrap();
    assert_eq!(value["id"], 1);
}

#[test]
fn read_sse_json_response_errors_on_closed_stream_without_data() {
    let mut reader = Cursor::new(b"event: nothing-useful\n".as_slice());
    assert!(read_sse_json_response(&mut reader).is_err());
}

#[test]
fn read_json_body_rejects_oversized_content_length_without_allocating() {
    // An attacker-controlled (lying) Content-Length larger than the cap must
    // bail BEFORE any allocation -- the prior `vec![0u8; len]` aborted the whole
    // gateway process on a huge len.
    let mut reader = Cursor::new(br#"{"ok":true}"#.as_slice());
    let result = read_json_body(&mut reader, Some(MAX_MCP_RESPONSE_BYTES + 1));
    assert!(result.is_err(), "oversized Content-Length must be rejected");
}

#[test]
fn read_json_body_parses_a_content_length_bounded_body() {
    let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
    let mut reader = Cursor::new(body.as_slice());
    let value = read_json_body(&mut reader, Some(body.len())).unwrap();
    assert_eq!(value["id"], 1);
}

#[test]
fn read_json_body_parses_a_body_without_content_length() {
    let mut reader = Cursor::new(br#"{"ok":true}"#.as_slice());
    let value = read_json_body(&mut reader, None).unwrap();
    assert_eq!(value["ok"], true);
}

fn spawn_https_test_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
    response: String,
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    // Must run before any rustls ClientConfig/ServerConfig builder in this
    // process — see `ensure_rustls_crypto_provider` in tls.rs.
    ensure_rustls_crypto_provider();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("valid self-signed test certificate");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let conn =
            ServerConnection::new(Arc::new(server_config)).expect("valid rustls server config");
        let mut tls_stream = StreamOwned::new(conn, tcp);
        let _received = read_until_headers_end(&mut tls_stream);
        write_response_tolerant(&mut tls_stream, response.as_bytes());
    });
    (addr, handle)
}

#[test]
fn post_http_json_preserves_upstream_401_as_identity_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let received = read_until_headers_end(&mut tcp);
        let request = String::from_utf8_lossy(&received);
        assert!(request.contains("Authorization: Bearer per-user-token\r\n"));
        write_response_tolerant(
            &mut tcp,
            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call"});
    let error = post_http_json(
        &format!("http://{addr}/mcp"),
        Duration::from_secs(2),
        &[("Authorization".into(), "Bearer per-user-token".into())],
        &McpTlsConfig::default(),
        &McpTransport::StreamableHttp,
        &body,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "mcp_upstream_unauthorized");
    handle.join().unwrap();
}

#[test]
fn post_http_json_establishes_real_tls_connection_over_https_with_insecure_skip_verify() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig {
        insecure_skip_verify: true,
        ca_cert_path: None,
    };
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    )
    .expect("https round trip must succeed");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}

#[test]
fn post_http_json_verifies_https_certificate_via_custom_ca_cert_path() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, cert.pem()).unwrap();

    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig {
        insecure_skip_verify: false,
        ca_cert_path: Some(ca_path.to_string_lossy().into_owned()),
    };
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    )
    .expect("https round trip trusting the custom CA must succeed");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}

#[test]
fn post_http_json_rejects_untrusted_https_certificate_by_default() {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let response = json_http_response(r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#);
    let (addr, handle) =
        spawn_https_test_server(cert.der().clone(), signing_key.serialize_der(), response);

    let endpoint = format!("https://{addr}/mcp");
    let tls = McpTlsConfig::default();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::StreamableHttp,
        &body,
    );

    assert!(result.is_err());
    // The server thread's write will fail/short-circuit once the client aborts
    // the handshake; only assert it doesn't hang.
    let _ = handle.join();
}

fn capture_http_exchange(responses: Vec<String>, client_call: impl FnOnce(String)) -> Vec<String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        responses
            .into_iter()
            .map(|response| {
                let deadline = std::time::Instant::now() + Duration::from_secs(60);
                let mut tcp = loop {
                    match listener.accept() {
                        Ok((tcp, _)) => break tcp,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("timed out accepting MCP test request: {error}"),
                    }
                };
                let received = read_until_headers_end(&mut tcp);
                write_response_tolerant(&mut tcp, response.as_bytes());
                String::from_utf8_lossy(&received).to_string()
            })
            .collect()
    });
    client_call(format!("http://{addr}/mcp"));
    handle.join().unwrap()
}

fn json_response_with_session(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: must-not-be-echoed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn error_json_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn request_json(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn header_value<'a>(request: &'a str, wanted: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(wanted).then_some(value.trim())
    })
}

#[test]
fn modern_http_wire_is_stateless_and_carries_headers_meta_and_identity() {
    let replies = vec![
        json_response_with_session(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
        ),
        json_response_with_session(
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","inputSchema":{"type":"object"}}]}}"#,
        ),
        json_response_with_session(
            r#"{"jsonrpc":"2.0","id":3,"result":{"content":[],"isError":false}}"#,
        ),
        json_response_with_session(
            r#"{"jsonrpc":"2.0","id":4,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
        ),
    ];
    let mut protocol = None;
    let requests = capture_http_exchange(replies, |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        config.timeout_ms = 30_000;
        let mut client = HttpMcpClient::new(&config).unwrap();
        client.negotiate().unwrap();
        client.list_tools().unwrap();
        let identity = McpDispatchHeaders::bearer("per-user-token".into()).unwrap();
        client
            .call_tool(
                "=?base64?literal?=",
                json!({"q": "x", "limit": 3}),
                &identity,
            )
            .unwrap();
        client.health_check().unwrap();
        protocol = client.negotiated_protocol();
    });

    assert_eq!(requests.len(), 4);
    assert!(!requests
        .iter()
        .any(|request| request.contains("initialize")));
    for (request, method) in requests.iter().zip([
        "server/discover",
        "tools/list",
        "tools/call",
        "server/discover",
    ]) {
        assert_eq!(
            header_value(request, "MCP-Protocol-Version"),
            Some("2026-07-28")
        );
        assert_eq!(header_value(request, "Mcp-Method"), Some(method));
        assert_eq!(header_value(request, "Mcp-Session-Id"), None);
        let body = request_json(request);
        assert_eq!(body["method"], method);
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
            "ferrogate"
        );
        assert!(body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object());
    }
    assert_eq!(
        header_value(&requests[2], "Mcp-Name"),
        Some("=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=")
    );
    assert_eq!(
        header_value(&requests[2], "Authorization"),
        Some("Bearer per-user-token")
    );
    let call = request_json(&requests[2]);
    assert_eq!(call["params"]["name"], "=?base64?literal?=");
    assert_eq!(call["params"]["arguments"], json!({"q": "x", "limit": 3}));
    assert_eq!(
        protocol.unwrap().mode,
        crate::protocol::McpProtocolMode::Modern
    );
    assert!(!requests
        .iter()
        .any(|request| { request_json(request)["method"] == "ping" }));
}

#[test]
fn http_unrecognized_404_falls_back_to_strict_legacy_wire() {
    let replies = vec![
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        json_http_response(r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18"}}"#),
        json_http_response(r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#),
    ];
    let mut protocol = None;
    let requests = capture_http_exchange(replies, |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        config.timeout_ms = 30_000;
        let mut client = HttpMcpClient::new(&config).unwrap();
        client.negotiate().unwrap();
        client.list_tools().unwrap();
        protocol = client.negotiated_protocol();
    });

    assert_eq!(requests.len(), 3);
    assert_eq!(request_json(&requests[0])["method"], "server/discover");
    let initialize = request_json(&requests[1]);
    assert_eq!(initialize["method"], "initialize");
    assert_eq!(initialize["params"]["protocolVersion"], "2025-11-25");
    let list = request_json(&requests[2]);
    assert_eq!(list["method"], "tools/list");
    assert!(list["params"].get("_meta").is_none());
    for request in &requests[1..] {
        assert_eq!(header_value(request, "MCP-Protocol-Version"), None);
        assert_eq!(header_value(request, "Mcp-Method"), None);
        assert_eq!(header_value(request, "Mcp-Name"), None);
    }
    let protocol = protocol.unwrap();
    assert_eq!(protocol.mode, crate::protocol::McpProtocolMode::Legacy);
    assert_eq!(protocol.version, "2025-06-18");
    assert_eq!(
        protocol.downgrade_reason,
        Some(crate::protocol::McpProtocolDowngradeReason::Http404UnrecognizedResponse)
    );
}

#[test]
fn http_empty_sse_error_body_still_takes_the_legacy_fallback() {
    let replies = vec![
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/event-stream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
        json_http_response(
            r#"{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-11-25"}}"#,
        ),
        json_http_response(r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[]}}"#),
    ];
    let requests = capture_http_exchange(replies, |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        config.timeout_ms = 30_000;
        let mut client = HttpMcpClient::new(&config).unwrap();
        client.negotiate().unwrap();
        client.list_tools().unwrap();
    });

    assert_eq!(requests.len(), 3);
    assert_eq!(request_json(&requests[0])["method"], "server/discover");
    assert_eq!(request_json(&requests[1])["method"], "initialize");
}

#[test]
fn malformed_discovery_success_fails_without_legacy_fallback() {
    let reply = json_http_response(
        r#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2026-07-28"],"capabilities":{}}}"#,
    );
    let mut error = String::new();
    let requests = capture_http_exchange(vec![reply], |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        config.timeout_ms = 30_000;
        let mut client = HttpMcpClient::new(&config).unwrap();
        error = client.negotiate().unwrap_err().to_string();
    });

    assert_eq!(requests.len(), 1);
    assert_eq!(request_json(&requests[0])["method"], "server/discover");
    assert!(error.contains("did not advertise"), "{error}");
}

#[test]
fn http_recognized_modern_error_never_falls_back_to_initialize() {
    let reply = error_json_response(
        "400 Bad Request",
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"unsupported","data":{"supported":[]}}}"#,
    );
    let mut error = String::new();
    let requests = capture_http_exchange(vec![reply], |endpoint| {
        let mut config = test_config("srv");
        config.url = Some(endpoint);
        config.timeout_ms = 30_000;
        let mut client = HttpMcpClient::new(&config).unwrap();
        error = client.negotiate().unwrap_err().to_string();
    });

    assert_eq!(requests.len(), 1);
    assert_eq!(request_json(&requests[0])["method"], "server/discover");
    assert!(error.contains("JSON-RPC error code -32022"), "{error}");
}

#[test]
fn post_http_json_parses_sse_formatted_response_over_plain_http() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        let _received = read_until_headers_end(&mut tcp);
        let sse_body =
            ": ping\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{sse_body}"
        );
        write_response_tolerant(&mut tcp, response.as_bytes());
    });

    let endpoint = format!("http://{addr}/mcp");
    let tls = McpTlsConfig::default();
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "ping", "params": {}});
    let result = post_http_json(
        &endpoint,
        Duration::from_secs(5),
        &[],
        &tls,
        &McpTransport::Sse,
        &body,
    )
    .expect("SSE-formatted response must parse");

    assert_eq!(result["result"]["ok"], true);
    handle.join().unwrap();
}
