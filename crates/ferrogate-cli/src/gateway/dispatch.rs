use anyhow::{bail, Context, Result as AnyResult};
use http::{StatusCode, Uri};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use ferrogate_providers::ProviderHttpRequest;

#[derive(Debug, Clone)]
pub(super) struct ProviderHttpResponse {
    pub(super) status: StatusCode,
    pub(super) content_type: String,
    pub(super) body: Vec<u8>,
}

pub(super) fn dispatch_provider_request(
    request: &ProviderHttpRequest,
) -> AnyResult<ProviderHttpResponse> {
    let target = parse_provider_target(&request.endpoint)?;
    let body = serde_json::to_vec(&request.body).context("failed to serialize provider body")?;
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .with_context(|| format!("failed to connect provider {}", target.authority))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

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
    stream.write_all(&body)?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    parse_provider_response(&raw)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderTarget {
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
    if scheme != "http" {
        bail!("provider dispatch currently supports http endpoints only");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("provider endpoint must include authority"))?;
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(80);
    let authority = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let path_query = uri
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Ok(ProviderTarget {
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
    Ok(ProviderHttpResponse {
        status: StatusCode::from_u16(status_code).context("provider returned invalid status")?,
        content_type,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_provider_target() {
        let target =
            parse_provider_target("http://127.0.0.1:9000/v1/chat/completions?trace=1").unwrap();

        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 9000);
        assert_eq!(target.authority, "127.0.0.1:9000");
        assert_eq!(target.path_query, "/v1/chat/completions?trace=1");
    }

    #[test]
    fn parses_default_port_and_root_provider_target() {
        let target = parse_provider_target("http://api.example.test").unwrap();

        assert_eq!(target.host, "api.example.test");
        assert_eq!(target.port, 80);
        assert_eq!(target.authority, "api.example.test");
        assert_eq!(target.path_query, "/");
    }

    #[test]
    fn rejects_https_provider_target_until_tls_dispatch_exists() {
        let error = parse_provider_target("https://api.example.test/v1")
            .unwrap_err()
            .to_string();

        assert!(error.contains("http endpoints only"));
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
}
