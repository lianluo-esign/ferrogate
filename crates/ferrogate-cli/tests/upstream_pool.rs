// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn ferrogate() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
}

fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

fn start_gateway(config: &std::path::Path) -> Child {
    ferrogate()
        .args(["run", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_for_gateway(addr: &str) {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut buffer = [0_u8; 512];
            if stream.read(&mut buffer).unwrap_or(0) > 0 {
                return;
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("gateway did not become ready at {addr}");
}

fn http_get(addr: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

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
    let gateway_addr = free_addr();
    let (first_addr, first_handle) = spawn_labeled_upstream("first");
    let (second_addr, second_handle) = spawn_labeled_upstream("second");
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

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

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let first = http_get(&gateway_addr, "/pool");
    let second = http_get(&gateway_addr, "/pool");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    first_handle.join().unwrap();
    second_handle.join().unwrap();

    assert!(first.contains("upstream=first"));
    assert!(second.contains("upstream=second"));
}
