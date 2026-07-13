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
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
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
    stop: Arc<AtomicBool>,
) -> Result<(String, JoinHandle<Vec<String>>)> {
    spawn_local_provider_upstream_with_timeout(expected_requests, stop, Duration::from_secs(90))
}

pub(crate) fn spawn_local_provider_upstream_with_timeout(
    expected_requests: usize,
    stop: Arc<AtomicBool>,
    max_lifetime: Duration,
) -> Result<(String, JoinHandle<Vec<String>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?.to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let started = Instant::now();
        // Stop when the expected count is reached, on the safety cap, OR as soon
        // as the harness signals teardown — so a request-count mismatch no
        // longer stalls `Drop` for up to 90s before the real failure surfaces
        // (issue #142).
        while requests.len() < expected_requests
            && started.elapsed() < max_lifetime
            && !stop.load(Ordering::Relaxed)
        {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request = match read_http_request(&mut stream) {
                        Ok(request) => request,
                        Err(_) => continue,
                    };
                    let response = provider_response_for_request(&request);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.status,
                        response.content_type,
                        response.body.len(),
                        response.body
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

struct ProviderMockResponse {
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
}

fn provider_response_for_request(request: &str) -> ProviderMockResponse {
    if request.contains("GET /v1/models ") {
        return ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"object":"list","data":[{"id":"provider-chat","owned_by":"ferrogate-test","created":1781417600,"context_window":8192,"capabilities":["chat","tools"]}]}"#,
        };
    }
    if request.contains(r#""model":"gpt-4o-mini-failover-primary""#) {
        if request.contains("provider compliance multi attempt settlement") {
            return ProviderMockResponse {
                status: "503 Service Unavailable",
                content_type: "application/json",
                body: r#"{"error":{"message":"primary provider overloaded after consuming tokens","type":"server_error","code":"primary_overloaded"},"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}"#,
            };
        }
        return ProviderMockResponse {
            status: "503 Service Unavailable",
            content_type: "application/json",
            body: r#"{"error":{"message":"primary provider overloaded","type":"server_error","code":"primary_overloaded"}}"#,
        };
    }
    if request.contains(r#""model":"gpt-4o-mini-fallback""#) {
        if request.contains(r#""stream":true"#) {
            return ProviderMockResponse {
                status: "200 OK",
                content_type: "text/event-stream",
                body: "data: {\"id\":\"chatcmpl_ferrogate_fallback\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"fallback ok\"}}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10}}\n\ndata: [DONE]\n\n",
            };
        }
        return ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"chatcmpl_ferrogate_fallback","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"fallback ok"}}],"usage":{"prompt_tokens":4,"completion_tokens":6,"total_tokens":10}}"#,
        };
    }
    if let Some(response) = provider_matrix_response(request) {
        return response;
    }
    if request.contains("provider upstream error with usage") {
        return ProviderMockResponse {
            status: "400 Bad Request",
            content_type: "application/json",
            body: r#"{"error":{"message":"bad provider request","type":"invalid_request_error","code":"bad_provider_request"},"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#,
        };
    }
    if request.contains("provider upstream error") {
        return ProviderMockResponse {
            status: "400 Bad Request",
            content_type: "application/json",
            body: r#"{"error":{"message":"bad provider request","type":"invalid_request_error","code":"bad_provider_request"}}"#,
        };
    }
    if request.contains(r#""stream":true"#) {
        return ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"id\":\"chatcmpl_ferrogate_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"stream-ok\"}}]}\n\ndata: [DONE]\n\n",
        };
    }
    if request.contains("POST /v1/responses ") {
        return ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"resp_ferrogate_test","object":"response","output_text":"ok","usage":{"input_tokens":3,"output_tokens":5,"total_tokens":8}}"#,
        };
    }
    ProviderMockResponse {
        status: "200 OK",
        content_type: "application/json",
        body: r#"{"id":"chatcmpl_ferrogate_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
    }
}

fn provider_matrix_response(request: &str) -> Option<ProviderMockResponse> {
    let response = if request.contains("provider compliance openai-compatible streaming usage")
        && request.contains(r#""stream_options":{"include_usage":true}"#)
    {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"id\":\"chatcmpl_compliance_openai_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"id\":\"chatcmpl_compliance_openai_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\ndata: [DONE]\n\n",
        }
    } else if request.contains("provider compliance anthropic streaming usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_compliance_anthropic_stream\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3-5-sonnet-latest\",\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n",
        }
    } else if request.contains("provider compliance anthropic usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"msg_compliance_anthropic","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-3-5-sonnet-latest","stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":5}}"#,
        }
    } else if request.contains("provider compliance gemini streaming usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":5,\"totalTokenCount\":8},\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"resp_compliance_gemini_stream\"}\n\n",
        }
    } else if request.contains("provider compliance gemini usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8},"modelVersion":"gemini-2.5-flash","responseId":"resp_compliance_gemini"}"#,
        }
    } else if request.contains("provider compliance grok streaming usage")
        && request.contains(r#""stream_options":{"include_usage":true}"#)
    {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"id\":\"chatcmpl_compliance_grok_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"id\":\"chatcmpl_compliance_grok_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\ndata: [DONE]\n\n",
        }
    } else if request.contains("provider compliance grok usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"chatcmpl_compliance_grok","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
        }
    } else if request.contains("provider compliance openrouter streaming usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"id\":\"chatcmpl_compliance_openrouter_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"id\":\"chatcmpl_compliance_openrouter_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\ndata: [DONE]\n\n",
        }
    } else if request.contains("provider compliance openrouter usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"chatcmpl_compliance_openrouter","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
        }
    } else if request.contains("provider compliance azure-openai streaming usage")
        && request.contains(r#""stream_options":{"include_usage":true}"#)
    {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"id\":\"chatcmpl_compliance_azure_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: {\"id\":\"chatcmpl_compliance_azure_stream\",\"object\":\"chat.completion.chunk\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":5,\"total_tokens\":8}}\n\ndata: [DONE]\n\n",
        }
    } else if request.contains("provider compliance azure-openai usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"id":"chatcmpl_compliance_azure","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
        }
    } else if request.contains("provider compliance bedrock usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"stopReason":"end_turn","usage":{"inputTokens":3,"outputTokens":5,"totalTokens":8},"metrics":{"latencyMs":1}}"#,
        }
    } else if request.contains("provider compliance vertex streaming usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "text/event-stream",
            body: "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":5,\"totalTokenCount\":8},\"modelVersion\":\"gemini-2.5-flash\",\"responseId\":\"resp_compliance_vertex_stream\"}\n\n",
        }
    } else if request.contains("provider compliance vertex usage") {
        ProviderMockResponse {
            status: "200 OK",
            content_type: "application/json",
            body: r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8},"modelVersion":"gemini-2.5-flash","responseId":"resp_compliance_vertex"}"#,
        }
    } else {
        return None;
    };
    Some(response)
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
                    } else if request.contains(r#""method":"tools/call""#)
                        && request.contains("mcp-tool-error")
                    {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "tool rejected by harness"
                                    }
                                ],
                                "isError": true
                            }
                        })
                        .to_string()
                    } else if request.contains(r#""method":"tools/call""#)
                        && request.contains("mcp-malformed")
                    {
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": extract_jsonrpc_id(&request),
                            "result": {
                                "content": "not-a-valid-content-array",
                                "isError": false
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

pub(crate) fn read_http_request(stream: &mut TcpStream) -> Result<String> {
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
