// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use http::HeaderMap;

use super::{
    routing::{build_target_url, parse_upstream_endpoint},
    HeaderMatcher, RouteRule, Upstream,
};

#[test]
fn route_matches_host_and_path_prefix() {
    let route = route_with_prefix("/api");

    let headers = HeaderMap::new();
    assert!(route.matches_request(Some("api.example.com"), "/api/users", &headers));
    assert!(!route.matches_request(Some("www.example.com"), "/api/users", &headers));
    assert!(!route.matches_request(Some("api.example.com"), "/admin", &headers));
}

#[test]
fn route_matches_required_headers() {
    let mut route = route_with_prefix("/api");
    route.hosts.clear();
    route.match_headers = vec![HeaderMatcher {
        name: "x-ferrogate-target".into(),
        value: "primary".into(),
    }];
    let mut headers = HeaderMap::new();
    assert!(!route.matches_request(None, "/api/users", &headers));

    headers.insert("x-ferrogate-target", "primary".parse().unwrap());
    assert!(route.matches_request(None, "/api/users", &headers));

    headers.insert("x-ferrogate-target", "secondary".parse().unwrap());
    assert!(!route.matches_request(None, "/api/users", &headers));
}

#[test]
fn route_rewrites_path_with_strip_and_add_prefix() {
    let mut route = route_with_prefix("/proxy");
    route.hosts.clear();
    route.strip_prefix = Some("/proxy".into());
    route.add_prefix = Some("/v1".into());

    assert_eq!(route.rewrite_path("/proxy/users"), "/v1/users");
    assert_eq!(route.rewrite_path("/proxy"), "/v1");
}

#[test]
fn builds_target_url_with_query() {
    let upstream = Upstream {
        name: "backend".into(),
        url: Some("https://example.com/base".into()),
        urls: Vec::new(),
        enabled: true,
    };
    let mut route = route_with_prefix("/proxy");
    route.hosts.clear();
    route.strip_prefix = Some("/proxy".into());

    let url = build_target_url(
        upstream.url.as_deref().unwrap(),
        &route,
        "/proxy/users",
        Some("page=1"),
    )
    .unwrap();
    assert_eq!(url, "https://example.com/base/users?page=1");
}

#[test]
fn parses_upstream_endpoint_defaults_ports() {
    let https = parse_upstream_endpoint("https://example.com/base").unwrap();
    assert_eq!(https.scheme, "https");
    assert_eq!(https.host, "example.com");
    assert_eq!(https.port, 443);
    assert_eq!(https.authority, "example.com");
    assert_eq!(https.base_path, "/base");

    let http = parse_upstream_endpoint("http://127.0.0.1:18080").unwrap();
    assert_eq!(http.scheme, "http");
    assert_eq!(http.port, 18080);
    assert_eq!(http.authority, "127.0.0.1:18080");
}

fn route_with_prefix(prefix: &str) -> RouteRule {
    RouteRule {
        name: "api".into(),
        upstream: "backend".into(),
        hosts: vec!["api.example.com".into()],
        path_prefixes: vec![prefix.into()],
        match_headers: vec![],
        strip_prefix: None,
        add_prefix: None,
        request_headers: vec![],
        response_headers: vec![],
        enabled: true,
    }
}
