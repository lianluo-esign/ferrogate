use anyhow::{bail, Context, Result as AnyResult};
use http::{StatusCode, Uri};
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, OnceLock},
    time::Duration,
};

use ferrogate_providers::ProviderHttpRequest;

#[derive(Debug, Clone)]
pub(super) struct ProviderHttpResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: String,
    pub(super) body: Vec<u8>,
}

pub(super) struct ProviderStreamingResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: String,
    pub(super) initial_body: Vec<u8>,
    pub(super) body: ProviderBodyReader,
}

pub(super) enum ProviderBodyReader {
    Http(TcpStream),
    Https(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for ProviderBodyReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Http(stream) => stream.read(buffer),
            Self::Https(stream) => stream.read(buffer),
        }
    }
}

pub(super) fn dispatch_provider_request(
    request: &ProviderHttpRequest,
    timeout: Duration,
) -> AnyResult<ProviderHttpResponse> {
    let target = parse_provider_target(&request.endpoint)?;
    let body = serde_json::to_vec(&request.body).context("failed to serialize provider body")?;
    let mut stream = connect_provider(&target, timeout)?;

    match target.scheme {
        ProviderScheme::Http => send_provider_http_request(&mut stream, &target, request, &body),
        ProviderScheme::Https => {
            let server_name = ServerName::try_from(target.host.clone())
                .with_context(|| format!("invalid provider TLS server name {}", target.host))?;
            let connection = ClientConnection::new(tls_client_config()?, server_name)
                .context("failed to initialize provider TLS client")?;
            let mut tls_stream = StreamOwned::new(connection, stream);
            send_provider_http_request(&mut tls_stream, &target, request, &body)
        }
    }
}

pub(super) fn dispatch_provider_streaming_request(
    request: &ProviderHttpRequest,
    timeout: Duration,
) -> AnyResult<ProviderStreamingResponse> {
    let target = parse_provider_target(&request.endpoint)?;
    let body = serde_json::to_vec(&request.body).context("failed to serialize provider body")?;
    let mut stream = connect_provider(&target, timeout)?;

    match target.scheme {
        ProviderScheme::Http => {
            write_provider_http_request(&mut stream, &target, request, &body)?;
            let (status, content_type, initial_body) = read_provider_response_head(&mut stream)?;
            Ok(ProviderStreamingResponse {
                status,
                content_type,
                initial_body,
                body: ProviderBodyReader::Http(stream),
            })
        }
        ProviderScheme::Https => {
            let server_name = ServerName::try_from(target.host.clone())
                .with_context(|| format!("invalid provider TLS server name {}", target.host))?;
            let connection = ClientConnection::new(tls_client_config()?, server_name)
                .context("failed to initialize provider TLS client")?;
            let mut tls_stream = StreamOwned::new(connection, stream);
            write_provider_http_request(&mut tls_stream, &target, request, &body)?;
            let (status, content_type, initial_body) =
                read_provider_response_head(&mut tls_stream)?;
            Ok(ProviderStreamingResponse {
                status,
                content_type,
                initial_body,
                body: ProviderBodyReader::Https(Box::new(tls_stream)),
            })
        }
    }
}

fn connect_provider(target: &ProviderTarget, timeout: Duration) -> AnyResult<TcpStream> {
    let address = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve provider {}", target.authority))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("provider {} resolved no addresses", target.authority))?;
    let stream = TcpStream::connect_timeout(&address, timeout)
        .with_context(|| format!("failed to connect provider {}", target.authority))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn send_provider_http_request<S: Read + Write>(
    stream: &mut S,
    target: &ProviderTarget,
    request: &ProviderHttpRequest,
    body: &[u8],
) -> AnyResult<ProviderHttpResponse> {
    write_provider_http_request(stream, target, request, body)?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_provider_response(&raw)
}

fn write_provider_http_request<S: Write>(
    stream: &mut S,
    target: &ProviderTarget,
    request: &ProviderHttpRequest,
    body: &[u8],
) -> AnyResult<()> {
    write!(
        stream,
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        target.path_query,
        target.authority,
        body.len()
    )?;
    for header in &request.headers {
        write!(
            stream,
            "{}: {}\r\n",
            header.name,
            header.value.expose_secret()
        )?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    static TLS_CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(config) = TLS_CLIENT_CONFIG.get() {
        return Ok(Arc::clone(config));
    }

    let config = build_tls_client_config()?;
    let _ = TLS_CLIENT_CONFIG.set(Arc::clone(&config));
    Ok(TLS_CLIENT_CONFIG.get().map(Arc::clone).unwrap_or(config))
}

fn build_tls_client_config() -> AnyResult<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    if !native_certs.errors.is_empty() {
        anyhow::bail!(
            "failed to load platform native certificates: {:?}",
            native_certs.errors
        );
    }
    for cert in native_certs.certs {
        roots
            .add(cert)
            .context("failed to add platform native certificate")?;
    }

    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderTarget {
    scheme: ProviderScheme,
    host: String,
    port: u16,
    authority: String,
    path_query: String,
}

fn parse_provider_target(raw: &str) -> AnyResult<ProviderTarget> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid provider endpoint {raw}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("provider endpoint must include scheme"))?;
    let scheme = match scheme {
        "http" => ProviderScheme::Http,
        "https" => ProviderScheme::Https,
        other => bail!("provider dispatch supports http and https endpoints only, got {other}"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("provider endpoint must include authority"))?;
    let host = authority.host().to_string();
    let default_port = match scheme {
        ProviderScheme::Http => 80,
        ProviderScheme::Https => 443,
    };
    let port = authority.port_u16().unwrap_or(default_port);
    let authority = if port == default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(ProviderTarget {
        scheme,
        host,
        port,
        authority,
        path_query,
    })
}

fn parse_provider_response(raw: &[u8]) -> AnyResult<ProviderHttpResponse> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("provider response missing header terminator"))?;
    let header_bytes = &raw[..split];
    let body = raw[split + 4..].to_vec();
    let (status, content_type) = parse_provider_response_head(header_bytes)?;
    Ok(ProviderHttpResponse {
        status,
        content_type,
        body,
    })
}

fn read_provider_response_head<S: Read>(
    stream: &mut S,
) -> AnyResult<(StatusCode, String, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut buffer = [0_u8; 1024];
    let split = loop {
        let read = stream
            .read(&mut buffer)
            .context("failed to read provider response head")?;
        if read == 0 {
            bail!("provider response missing header terminator");
        }
        raw.extend_from_slice(&buffer[..read]);
        if raw.len() > 64 * 1024 {
            bail!("provider response headers exceed 64KiB");
        }
        if let Some(split) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break split;
        }
    };

    let header_bytes = &raw[..split];
    let initial_body = raw[split + 4..].to_vec();
    let (status, content_type) = parse_provider_response_head(header_bytes)?;
    Ok((status, content_type, initial_body))
}

fn parse_provider_response_head(header_bytes: &[u8]) -> AnyResult<(StatusCode, String)> {
    let headers = String::from_utf8_lossy(header_bytes);
    let mut lines = headers.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("provider response missing status line"))?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("provider response missing status code"))?
        .parse::<u16>()
        .context("provider response has invalid status code")?;
    let content_type = lines
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-type")
                    .then(|| value.trim().to_string())
            })
        })
        .unwrap_or_else(|| "application/json".to_string());
    let status = StatusCode::from_u16(status_code).context("provider returned invalid status")?;
    Ok((status, content_type))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_providers::ProviderHttpRequest;
    use serde_json::json;
    use std::{
        net::TcpListener,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn parses_http_provider_target() {
        let target =
            parse_provider_target("http://127.0.0.1:9000/v1/chat/completions?trace=1").unwrap();

        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 9000);
        assert_eq!(target.authority, "127.0.0.1:9000");
        assert_eq!(target.path_query, "/v1/chat/completions?trace=1");
        assert_eq!(target.scheme, ProviderScheme::Http);
    }

    #[test]
    fn parses_default_port_and_root_provider_target() {
        let target = parse_provider_target("http://api.example.test").unwrap();

        assert_eq!(target.host, "api.example.test");
        assert_eq!(target.port, 80);
        assert_eq!(target.authority, "api.example.test");
        assert_eq!(target.path_query, "/");
        assert_eq!(target.scheme, ProviderScheme::Http);
    }

    #[test]
    fn parses_https_provider_target() {
        let target = parse_provider_target("https://api.example.test/v1/chat/completions").unwrap();

        assert_eq!(target.host, "api.example.test");
        assert_eq!(target.port, 443);
        assert_eq!(target.authority, "api.example.test");
        assert_eq!(target.path_query, "/v1/chat/completions");
        assert_eq!(target.scheme, ProviderScheme::Https);
    }

    #[test]
    fn parses_https_provider_target_with_custom_port() {
        let target =
            parse_provider_target("https://api.example.test:9443/v1/chat/completions").unwrap();

        assert_eq!(target.host, "api.example.test");
        assert_eq!(target.port, 9443);
        assert_eq!(target.authority, "api.example.test:9443");
        assert_eq!(target.path_query, "/v1/chat/completions");
        assert_eq!(target.scheme, ProviderScheme::Https);
    }

    #[test]
    fn rejects_unsupported_provider_target_scheme() {
        let error = parse_provider_target("ftp://api.example.test/v1")
            .unwrap_err()
            .to_string();

        assert!(error.contains("supports http and https endpoints only"));
    }

    #[test]
    fn parses_provider_response_status_content_type_and_body() {
        let response =
            parse_provider_response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}")
                .unwrap();

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body, b"{}");
    }

    #[test]
    fn defaults_provider_response_content_type() {
        let response =
            parse_provider_response(b"HTTP/1.1 429 Too Many Requests\r\n\r\nrate").unwrap();

        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.content_type, "application/json");
        assert_eq!(response.body, b"rate");
    }

    #[test]
    fn rejects_malformed_provider_responses() {
        let missing_header_end = parse_provider_response(b"HTTP/1.1 200 OK").unwrap_err();
        assert!(missing_header_end
            .to_string()
            .contains("missing header terminator"));

        let missing_status = parse_provider_response(b"HTTP/1.1\r\n\r\n{}").unwrap_err();
        assert!(missing_status.to_string().contains("missing status code"));

        let invalid_status = parse_provider_response(b"HTTP/1.1 nope OK\r\n\r\n{}").unwrap_err();
        assert!(invalid_status.to_string().contains("invalid status code"));

        let out_of_range = parse_provider_response(b"HTTP/1.1 1000 OK\r\n\r\n{}").unwrap_err();
        assert!(out_of_range.to_string().contains("invalid status"));
    }

    #[test]
    fn provider_dispatch_respects_read_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(250));
        });
        let request = ProviderHttpRequest {
            provider: "openai".into(),
            endpoint: format!("http://{addr}/v1/chat/completions"),
            body: json!({"model": "gpt-test", "messages": []}),
            stream: false,
            headers: vec![],
        };

        let started = Instant::now();
        let error = dispatch_provider_request(&request, Duration::from_millis(50)).unwrap_err();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!error.to_string().is_empty());
        handle.join().unwrap();
    }
}
