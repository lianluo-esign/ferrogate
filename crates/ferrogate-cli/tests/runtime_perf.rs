use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const REQUESTS: usize = 100;

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
        if TcpStream::connect(addr).is_ok() {
            return;
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

fn spawn_loop_upstream(count: usize) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        }
    });
    (addr, handle)
}

#[test]
fn runtime_healthz_and_proxy_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let (upstream_addr, upstream_handle) = spawn_loop_upstream(REQUESTS);
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"

[[upstreams]]
name = "perf"
url = "http://{upstream_addr}"

[[routes]]
name = "perf"
upstream = "perf"
path_prefixes = ["/perf"]
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let health_started = Instant::now();
    for _ in 0..REQUESTS {
        assert!(http_get(&gateway_addr, "/healthz").contains("200 OK"));
    }
    assert!(
        health_started.elapsed() < Duration::from_secs(5),
        "healthz debug smoke exceeded 5s for {REQUESTS} requests"
    );

    let proxy_started = Instant::now();
    for _ in 0..REQUESTS {
        assert!(http_get(&gateway_addr, "/perf").contains("ok"));
    }
    assert!(
        proxy_started.elapsed() < Duration::from_secs(10),
        "proxy debug smoke exceeded 10s for {REQUESTS} requests"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
    upstream_handle.join().unwrap();
}
