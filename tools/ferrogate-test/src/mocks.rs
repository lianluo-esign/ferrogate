// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use crate::assertions::http_request_body;
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(crate) struct MockBillingServer {
    pub(crate) addr: String,
    pub(crate) received: mpsc::Receiver<String>,
    pub(crate) handle: Option<JoinHandle<()>>,
}

pub(crate) struct MockOtlpServer {
    pub(crate) addr: String,
    pub(crate) received: mpsc::Receiver<String>,
    pub(crate) handle: Option<JoinHandle<()>>,
}

pub(crate) struct MockThirdPartyAuthServer {
    pub(crate) addr: String,
    pub(crate) handle: Option<JoinHandle<Vec<String>>>,
}

impl MockThirdPartyAuthServer {
    pub(crate) fn join(mut self) -> Result<Vec<String>> {
        let handle = self
            .handle
            .take()
            .context("third-party auth mock join handle missing")?;
        handle
            .join()
            .map_err(|_| anyhow!("third-party auth mock thread panicked"))
    }
}

impl Drop for MockThirdPartyAuthServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(crate) fn spawn_local_provider_upstream(
    expected_requests: usize,
) -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while requests.len() < expected_requests && started.elapsed() < Duration::from_secs(3) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains("GET /v1/models ") {
                        r#"{"object":"list","data":[{"id":"provider-chat","owned_by":"ferrogate-test","created":1781417600,"context_window":8192,"capabilities":["chat","tools"]}]}"#
                    } else if request.contains("POST /v1/responses ") {
                        r#"{"id":"resp_ferrogate_test","object":"response","output_text":"ok","usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}"#
                    } else {
                        r#"{"id":"chatcmpl_ferrogate_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    requests.push(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        requests
    });
    Ok((addr, handle))
}

pub(crate) fn spawn_mock_mcp_server() -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains(r#""method":"initialize""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {
                                    "tools": {
                                        "listChanged": false
                                    }
                                },
                                "serverInfo": {
                                    "name": "mcp-harness",
                                    "version": "1.0.0"
                                },
                                "instructions": "Use the harness MCP server for compatibility checks."
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"tools/list""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "tools": [
                                    {
                                        "name": "search",
                                        "description": "Search the harness MCP upstream",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {
                                                "query": {
                                                    "type": "string"
                                                }
                                            },
                                            "required": ["query"]
                                        }
                                    }
                                ]
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"tools/call""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "ferrogate-result"
                                    }
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"ping""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {}
                        })
                        .to_string()
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "error": {
                                "code": -32601,
                                "message": "unsupported method"
                            }
                        })
                        .to_string()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    requests.push(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        requests
    });
    Ok((addr, handle))
}

pub(crate) fn spawn_mock_agent_server() -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(30) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = if request.contains(r#""method":"initialize""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {"tools": {"listChanged": false}},
                                "serverInfo": {"name": "agent-harness", "version": "1.0.0"}
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"message:send""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {"type": "text", "text": "agent-result"}
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"message:stream""#) {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {"type": "text", "text": "agent-stream"}
                                ],
                                "isError": false
                            }
                        })
                        .to_string()
                    } else {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "error": {"code": -32601, "message": "unsupported method"}
                        })
                        .to_string()
                    };
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    requests.push(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        requests
    });
    Ok((addr, handle))
}

pub(crate) fn spawn_mock_billing_server(expected_requests: usize) -> Result<MockBillingServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut received = 0;
        let started = Instant::now();
        while received < expected_requests && started.elapsed() < Duration::from_secs(10) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = r#"{"ok":true}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tx.send(request);
                    received += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Ok(MockBillingServer {
        addr,
        received: rx,
        handle: Some(handle),
    })
}

pub(crate) fn spawn_mock_otlp_server() -> Result<MockOtlpServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(15) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = r#"{"ok":true}"#;
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tx.send(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Ok(MockOtlpServer {
        addr,
        received: rx,
        handle: Some(handle),
    })
}

pub(crate) fn spawn_mock_third_party_auth_server(
    expected_requests: usize,
) -> Result<MockThirdPartyAuthServer> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        while requests.len() < expected_requests && started.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let body = third_party_auth_response_body(&request);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    requests.push(request);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        requests
    });
    Ok(MockThirdPartyAuthServer {
        addr,
        handle: Some(handle),
    })
}

fn third_party_auth_response_body(request: &str) -> String {
    if request.contains("POST /v1/auth/resolve-api-key ") {
        return r#"{"tenant":{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"client"},"subject":{"type":"api_key","api_key_id":"client"},"scopes":["models.read","chat.completions","responses.create"]}"#.to_string();
    }
    if request.contains("POST /v1/auth/authorize ") {
        let allowed = http_request_body(request)
            .ok()
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .and_then(|body| {
                body.get("resource")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .is_some_and(|resource| resource == "model:fast-chat");
        let reason = if allowed {
            "third_party_policy_allow"
        } else {
            "third_party_policy_deny"
        };
        return format!(
            r#"{{"allowed":{allowed},"tenant":{{"organization_id":"org_demo","team_id":null,"project_id":"project_gateway","user_id":null,"api_key_id":"client"}},"reason":"{reason}"}}"#
        );
    }
    r#"{"error":{"code":"not_found","message":"third-party auth mock endpoint not found"}}"#
        .to_string()
}

fn read_http_request(stream: &mut TcpStream) -> Result<String> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            let text = String::from_utf8_lossy(&request).to_string();
            let content_length = text
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length:")
                        .or_else(|| line.strip_prefix("content-length:"))
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let header_len = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .unwrap_or(request.len());
            while request.len().saturating_sub(header_len) < content_length {
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            break;
        }
    }
    Ok(String::from_utf8_lossy(&request).to_string())
}

fn extract_jsonrpc_id(request: &str) -> serde_json::Value {
    http_request_body(request)
        .ok()
        .and_then(|body| serde_json::from_str::<serde_json::Value>(body).ok())
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(serde_json::Value::Null)
}
