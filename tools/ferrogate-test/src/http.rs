// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::{anyhow, bail, Context, Result};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: String,
    pub(crate) raw: String,
}

pub(crate) fn free_addr() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.to_string())
}

pub(crate) fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

pub(crate) fn http_request(
    host_port: u16,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<HttpResponse> {
    http_request_addr(
        &format!("127.0.0.1:{host_port}"),
        method,
        path,
        headers,
        body,
    )
}

pub(crate) fn http_request_addr(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Result<HttpResponse> {
    let mut stream = TcpStream::connect(addr)
        .with_context(|| format!("failed to connect to {addr} for {method} {path}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .with_context(|| format!("failed to write request line to {addr} for {method} {path}"))?;
    for header in headers {
        write!(stream, "{header}\r\n")
            .with_context(|| format!("failed to write header to {addr} for {method} {path}"))?;
    }
    write!(stream, "\r\n{body}")
        .with_context(|| format!("failed to write request body to {addr} for {method} {path}"))?;

    let raw = read_http_response(&mut stream, addr, method, path)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("HTTP response missing status: {raw}"))?;
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok(HttpResponse { status, body, raw })
}

fn read_http_response(
    stream: &mut TcpStream,
    addr: &str,
    method: &str,
    path: &str,
) -> Result<String> {
    let started = Instant::now();
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                raw.extend_from_slice(&buffer[..count]);
                if http_response_complete(&raw) {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if started.elapsed() > Duration::from_secs(60) {
                    bail!("timed out reading response from {addr} for {method} {path}");
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read response from {addr} for {method} {path}")
                });
            }
        }
    }
    String::from_utf8(raw)
        .with_context(|| format!("failed to decode response from {addr} for {method} {path}"))
}

fn http_response_complete(raw: &[u8]) -> bool {
    let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse::<usize>().ok()
        } else {
            None
        }
    });
    match content_length {
        Some(length) => raw.len() >= header_end + 4 + length,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_response_complete_uses_content_length_without_waiting_for_eof() {
        assert!(!http_response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe"
        ));
        assert!(http_response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        ));
    }
}
