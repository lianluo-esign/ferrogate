use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().to_string()
}

pub fn start_gateway(config: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args(["run", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

pub fn wait_for_gateway(addr: &str) {
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

pub fn http_request(addr: &str, method: &str, path: &str, headers: &[&str], body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for header in headers {
        write!(stream, "{header}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[allow(dead_code)]
pub fn spawn_provider_upstream(
    count: usize,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    spawn_provider_upstream_response(count, "200 OK", "application/json", response_body)
}

#[allow(dead_code)]
pub fn spawn_provider_upstream_response(
    count: usize,
    status: &'static str,
    content_type: &'static str,
    response_body: &'static str,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
        }
        requests
    });
    (addr, handle)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = find_header_end(&request) {
            let content_length = parse_content_length(&request[..header_end]);
            let body_read = request.len().saturating_sub(header_end + 4);
            if body_read >= content_length {
                break;
            }
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())
                    .flatten()
            })
        })
        .unwrap_or(0)
}
