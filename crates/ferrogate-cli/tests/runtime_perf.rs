use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const REQUESTS: usize = 100;
const CONCURRENT_REQUESTS: usize = 16;

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

fn read_rss_kb(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
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

#[test]
fn admin_dashboard_static_debug_perf_smoke() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);
    let pid = gateway.id();
    let start_rss = read_rss_kb(pid);

    let mut latencies = Vec::with_capacity(REQUESTS);
    let started = Instant::now();
    for _ in 0..REQUESTS {
        let request_started = Instant::now();
        let response = http_get(&gateway_addr, "/admin/");
        latencies.push(request_started.elapsed());
        assert!(response.contains("200 OK"));
        assert!(response.contains("FerroGate Admin"));
        assert!(response.contains("/admin/v1/status"));
    }
    latencies.sort();
    let p95 = latencies[REQUESTS * 95 / 100];

    let concurrent_started = Instant::now();
    let mut workers = Vec::with_capacity(CONCURRENT_REQUESTS);
    for _ in 0..CONCURRENT_REQUESTS {
        let gateway_addr = gateway_addr.clone();
        workers.push(thread::spawn(move || {
            http_get(&gateway_addr, "/admin/dashboard")
        }));
    }
    for worker in workers {
        let response = worker.join().unwrap();
        assert!(response.contains("200 OK"));
        assert!(response.contains("FerroGate Admin"));
    }
    let end_rss = read_rss_kb(pid);

    gateway.kill().unwrap();
    gateway.wait().unwrap();

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "dashboard smoke exceeded 5s for {REQUESTS} requests"
    );
    assert!(
        p95 < Duration::from_millis(100),
        "dashboard p95 exceeded 100ms: {p95:?}"
    );
    assert!(
        concurrent_started.elapsed() < Duration::from_secs(5),
        "dashboard concurrent smoke exceeded 5s for {CONCURRENT_REQUESTS} requests"
    );
    assert!(
        end_rss <= start_rss + 32 * 1024,
        "gateway RSS grew too much: start={start_rss}KB end={end_rss}KB"
    );
}

#[test]
fn homepage_static_debug_smoke() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config,
        format!(
            r#"
listen = "{gateway_addr}"
"#
        ),
    )
    .unwrap();

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = http_get(&gateway_addr, "/");
    assert!(response.contains("200 OK"));
    assert!(response.contains("FerroGate | AI Gateway Control Plane"));
    assert!(response.contains("Route every model through one control plane."));
    assert!(response.contains("https://github.com/lianluo-esign/ferrogate"));
    assert!(!response.contains("route_not_found"));

    let index_response = http_get(&gateway_addr, "/index.html");
    assert!(index_response.contains("200 OK"));
    assert!(index_response.contains("Self-hosted AI gateway"));

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
