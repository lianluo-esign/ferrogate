mod support;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use support::{free_addr, http_request, spawn_provider_upstream, start_gateway, wait_for_gateway};

#[test]
fn openai_models_and_chat_non_streaming_dispatch_work() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        2,
        r#"{"id":"chatcmpl_test","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"ok"}}]}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[models]]
name = "smart-chat"
provider = "openai"
provider_model = "gpt-4.1"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["models.read", "chat.completions"]
allowed_models = ["fast-chat", "smart-chat"]
organization_id = "org_demo"
team_id = "team_platform"
project_id = "project_gateway"
user_id = "user_demo"
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let models = http_request(
        &gateway_addr,
        "GET",
        "/v1/models",
        &["Authorization: Bearer client-secret"],
        "",
    );
    assert!(models.contains("200 OK"));
    assert!(models.contains("\"id\":\"fast-chat\""));
    assert!(models.contains("\"id\":\"smart-chat\""));

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"object\":\"chat.completion\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));
    assert!(!chat.contains("Bearer"));

    let smart_chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &["x-api-key: client-secret", "Content-Type: application/json"],
        r#"{"model":"smart-chat","messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(smart_chat.contains("200 OK"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0].contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_requests[0].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[0].contains(r#""model":"gpt-4o-mini""#));
    assert!(!provider_requests[0].contains("fast-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
    assert!(provider_requests[1].contains("authorization: Bearer provider-secret"));
    assert!(provider_requests[1].contains(r#""model":"gpt-4.1""#));
    assert!(!provider_requests[1].contains("smart-chat"));
    assert!(!provider_requests[1].contains("client-secret"));
}

#[test]
fn openai_chat_streaming_sse_dispatch_works() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_sse_provider_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(chat.contains("data: {\"choices\""));
    assert!(chat.contains("data: [DONE]"));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains("POST /v1/chat/completions HTTP/1.1"));
    assert!(provider_request.contains("authorization: Bearer provider-secret"));
    assert!(provider_request.contains(r#""model":"gpt-4o-mini""#));
    assert!(provider_request.contains(r#""stream":true"#));
    assert!(!provider_request.contains("fast-chat"));
    assert!(!provider_request.contains("client-secret"));
}

#[test]
fn openai_chat_streaming_sse_forwards_first_chunk_before_provider_finishes() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_slow_sse_provider_upstream();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "openai"
kind = "openai"
base_url = "http://{provider_addr}/v1"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let started = Instant::now();
    let mut stream = TcpStream::connect(&gateway_addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let body =
        r#"{"model":"fast-chat","stream":true,"messages":[{"role":"user","content":"hello"}]}"#;
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer client-secret\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .unwrap();

    let mut response = Vec::new();
    let mut buffer = [0_u8; 256];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0, "gateway closed before first SSE chunk");
        response.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&response);
        if text.contains("data: {\"choices\"") {
            assert!(
                started.elapsed() < Duration::from_millis(900),
                "first SSE chunk was buffered until provider completion"
            );
            assert!(!text.contains("data: [DONE]"));
            break;
        }
    }

    let mut rest = String::new();
    stream.read_to_string(&mut rest).unwrap();
    assert!(rest.contains("data: [DONE]"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_request = provider_handle.join().unwrap();
    assert!(provider_request.contains(r#""stream":true"#));
}

#[test]
fn gemini_chat_non_streaming_dispatch_converts_request_shape() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"candidates":[{"content":{"parts":[{"text":"ok"}]}}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":5,"totalTokenCount":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "gemini"
kind = "gemini"
base_url = "http://{provider_addr}/v1beta"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "flash-chat"
provider = "gemini"
provider_model = "gemini-2.5-flash"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["flash-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"flash-chat","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"max_tokens":64}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"usageMetadata\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0]
        .contains("POST /v1beta/models/gemini-2.5-flash:generateContent HTTP/1.1"));
    assert!(provider_requests[0].contains("x-goog-api-key: provider-secret"));
    assert!(provider_requests[0].contains(r#""role":"user""#));
    assert!(provider_requests[0].contains(r#""text":"hello""#));
    assert!(provider_requests[0].contains(r#""systemInstruction""#));
    assert!(provider_requests[0].contains(r#""maxOutputTokens":64"#));
    assert!(!provider_requests[0].contains("flash-chat"));
    assert!(!provider_requests[0].contains("client-secret"));
}

#[test]
fn azure_openai_chat_non_streaming_dispatch_uses_deployment_endpoint() {
    let gateway_addr = free_addr();
    let (provider_addr, provider_handle) = spawn_provider_upstream(
        1,
        r#"{"id":"chatcmpl_azure","choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":5,"total_tokens":8}}"#,
    );
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "azure-eastus"
kind = "azure-openai"
base_url = "http://{provider_addr}?api-version=2024-02-15-preview"
api_key_env = "FERROGATE_PROVIDER_SECRET"

[[models]]
name = "fast-chat"
provider = "azure-eastus"
provider_model = "gpt-4o-mini"
capabilities = ["chat"]

[[api_keys]]
id = "key_dev"
name = "Development key"
key = "client-secret"
scopes = ["chat.completions"]
allowed_models = ["fast-chat"]
"#
        ),
    )
    .unwrap();
    std::env::set_var("FERROGATE_PROVIDER_SECRET", "provider-secret");

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let chat = http_request(
        &gateway_addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Authorization: Bearer client-secret",
            "Content-Type: application/json",
        ],
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hello"}],"stream":false}"#,
    );
    assert!(chat.contains("200 OK"));
    assert!(chat.contains("\"id\":\"chatcmpl_azure\""));
    assert!(!chat.contains("provider-secret"));
    assert!(!chat.contains("client-secret"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    let provider_requests = provider_handle.join().unwrap();
    assert!(provider_requests[0].contains(
        "POST /openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview HTTP/1.1"
    ));
    assert!(provider_requests[0].contains("api-key: provider-secret"));
    assert!(provider_requests[0].contains(r#""messages""#));
    assert!(provider_requests[0].contains(r#""role":"user""#));
    assert!(provider_requests[0].contains(r#""content":"hello""#));
    assert!(!provider_requests[0].contains(r#""model":"fast-chat""#));
    assert!(!provider_requests[0].contains("client-secret"));
}

fn spawn_sse_provider_upstream() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        let body = "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        request
    });
    (addr, handle)
}

fn spawn_slow_sse_provider_upstream() -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_request(&mut stream);
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        stream
            .write_all(b"data: {\"choices\":[{\"delta\":{\"content\":\"first\"}}]}\n\n")
            .unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(1200));
        stream.write_all(b"data: [DONE]\n\n").unwrap();
        request
    });
    (addr, handle)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let content_length = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().ok())
                            .flatten()
                    })
                })
                .unwrap_or(0);
            if request.len().saturating_sub(header_end + 4) >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
