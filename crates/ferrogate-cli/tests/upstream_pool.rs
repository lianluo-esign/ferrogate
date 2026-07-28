// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

mod support;

fn spawn_labeled_upstream(label: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = stream.read(&mut buffer).unwrap();
        let body = format!("upstream={label}");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
    });
    (addr, handle)
}

#[test]
fn upstream_pool_uses_round_robin_endpoint_selection() {
    let (first_addr, first_handle) = spawn_labeled_upstream("first");
    let (second_addr, second_handle) = spawn_labeled_upstream("second");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    let (mut gateway, gateway_addr) = support::start_ready_gateway(&config, |gateway_addr| {
        std::fs::write(
            &config,
            format!(
                r#"
listen = "{gateway_addr}"

# #542: no credential source of any kind, so the open posture is named
# rather than inherited from an empty [[api_keys]] section.
[auth]
disabled = true

[[upstreams]]
name = "pool"
url = "http://{first_addr}"
urls = ["http://{second_addr}"]

[[routes]]
name = "pool"
upstream = "pool"
path_prefixes = ["/pool"]
"#
            ),
        )
        .unwrap();
    });

    let first = support::http_request(&gateway_addr, "GET", "/pool", &[], "");
    let second = support::http_request(&gateway_addr, "GET", "/pool", &[], "");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    first_handle.join().unwrap();
    second_handle.join().unwrap();

    assert!(first.contains("upstream=first"));
    assert!(second.contains("upstream=second"));
}
