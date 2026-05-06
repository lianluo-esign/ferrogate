use anyhow::{bail, Context, Result as AnyResult};
use http::Uri;
#[cfg(test)]
use http::{HeaderMap, HeaderName};

use crate::config::RouteRule;

#[derive(Debug, Clone)]
pub(crate) struct UpstreamEndpoint {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) authority: String,
    pub(crate) base_path: String,
}

impl RouteRule {
    #[cfg(test)]
    pub(crate) fn matches_request(
        &self,
        host: Option<&str>,
        path: &str,
        headers: &HeaderMap,
    ) -> bool {
        if !self.hosts.is_empty() {
            let Some(host) = host else {
                return false;
            };
            if !self
                .hosts
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(host))
            {
                return false;
            }
        }

        let path_matches = self.path_prefixes.is_empty()
            || self.path_prefixes.iter().any(|prefix| {
                path == prefix || path.starts_with(&format!("{}/", prefix.trim_end_matches('/')))
            });
        if !path_matches {
            return false;
        }

        self.match_headers.iter().all(|matcher| {
            HeaderName::from_bytes(matcher.name.as_bytes())
                .ok()
                .and_then(|name| headers.get(name))
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == matcher.value)
        })
    }

    pub(crate) fn rewrite_path(&self, original_path: &str) -> String {
        let mut path = original_path.to_string();
        if let Some(strip_prefix) = &self.strip_prefix {
            if path == *strip_prefix {
                path = "/".to_string();
            } else if path.starts_with(&format!("{}/", strip_prefix.trim_end_matches('/'))) {
                path = path[strip_prefix.len()..].to_string();
                path = ensure_leading_slash(&path);
            }
        }
        if let Some(add_prefix) = &self.add_prefix {
            path = join_url_path(add_prefix, &path);
        }
        ensure_leading_slash(&path)
    }
}

pub(crate) fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase()
}

pub(crate) fn parse_upstream_endpoint(raw: &str) -> AnyResult<UpstreamEndpoint> {
    let uri: Uri = raw
        .parse()
        .with_context(|| format!("invalid upstream URL {raw}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| anyhow::anyhow!("upstream URL must include scheme"))?
        .to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        bail!("upstream URL scheme must be http or https");
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("upstream URL must include authority"))?;
    let host = authority.host().to_string();
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let default_port = (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
    let authority = if default_port {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let base_path = uri.path().trim_end_matches('/').to_string();
    Ok(UpstreamEndpoint {
        scheme,
        host,
        port,
        authority,
        base_path,
    })
}

#[cfg(test)]
pub(crate) fn build_target_url(
    upstream_url: &str,
    route: &RouteRule,
    original_path: &str,
    query: Option<&str>,
) -> AnyResult<String> {
    let endpoint = parse_upstream_endpoint(upstream_url)?;
    let path_query = build_target_path_query(upstream_url, route, original_path, query)?;
    Ok(format!(
        "{}://{}{}",
        endpoint.scheme, endpoint.authority, path_query
    ))
}

#[cfg(test)]
pub(crate) fn build_target_path_query(
    upstream_url: &str,
    route: &RouteRule,
    original_path: &str,
    query: Option<&str>,
) -> AnyResult<String> {
    let endpoint = parse_upstream_endpoint(upstream_url)?;
    let rewritten = route.rewrite_path(original_path);
    Ok(build_target_uri(&endpoint, &rewritten, query)?.to_string())
}

pub(crate) fn build_target_uri(
    endpoint: &UpstreamEndpoint,
    rewritten_path: &str,
    query: Option<&str>,
) -> AnyResult<Uri> {
    let mut path = join_url_path(&endpoint.base_path, rewritten_path);
    if let Some(query) = query {
        if !query.is_empty() {
            path.push('?');
            path.push_str(query);
        }
    }
    path.parse()
        .with_context(|| format!("invalid target path {path}"))
}

fn ensure_leading_slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn join_url_path(left: &str, right: &str) -> String {
    let left = left.trim_end_matches('/');
    let right = right.trim_start_matches('/');
    match (left.is_empty(), right.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{right}"),
        (false, true) => left.to_string(),
        (false, false) => format!("{left}/{right}"),
    }
}
