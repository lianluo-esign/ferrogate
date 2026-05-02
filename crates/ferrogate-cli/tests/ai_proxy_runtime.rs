mod support;

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
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
    assert!(chat.contains("content-type: text/event-stream"));
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
