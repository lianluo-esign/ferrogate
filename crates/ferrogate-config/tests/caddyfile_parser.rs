use ferrogate_config::parse_caddyfile;

#[test]
fn parses_minimal_site_block_from_ferrogate_caddyfile() {
    let raw = include_str!("../../../Ferrogate/Caddyfile");

    let config = parse_caddyfile(raw, "Ferrogate/Caddyfile").unwrap();

    assert_eq!(config.listen, "127.0.0.1:8080");
    assert_eq!(config.admin.as_deref(), Some("localhost:2019"));
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(
        config
            .routes
            .iter()
            .filter(|route| route.upstream.is_some())
            .count(),
        1
    );
    assert!(config
        .routes
        .iter()
        .any(|route| route.static_response.is_some()));
}

#[test]
fn parses_route_handle_handle_path_reverse_proxy_and_header_blocks() {
    let config = parse_caddyfile(
        r#"
example.com {
    route /api/* {
        handle /v1/* {
            handle_path /chat/* {
                reverse_proxy https://upstream.example.com {
                    header_up x-provider openai
                    header_down x-gateway ferrogate
                }
            }
        }
    }
    header x-frame-options DENY
    rewrite * /index.html
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].url, "https://upstream.example.com");
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes[0].hosts, vec!["example.com"]);
    assert_eq!(config.routes[0].path_prefixes, vec!["/chat"]);
    assert_eq!(config.routes[0].request_headers[0].name, "x-provider");
    assert_eq!(config.routes[0].response_headers[0].name, "x-gateway");
}

#[test]
fn parses_multiple_reverse_proxy_upstreams_into_pool() {
    let config = parse_caddyfile(
        r#"
:8080 {
    reverse_proxy http://127.0.0.1:9001 http://127.0.0.1:9002
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].url, "http://127.0.0.1:9001");
    assert_eq!(config.upstreams[0].urls, vec!["http://127.0.0.1:9002"]);
}

#[test]
fn accepts_declared_p0_directives_as_typed_placeholders() {
    let config = parse_caddyfile(
        r#"
:8443 {
    encode gzip
    redir /old /new 308
    tls cert.pem key.pem
    log
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    assert_eq!(config.listen, "127.0.0.1:8443");
    assert_eq!(config.logs.len(), 1);
}

#[test]
fn accepts_named_matcher_declarations_for_p0_matcher_subset() {
    let config = parse_caddyfile(
        r#"
:8080 {
    @chat path /v1/chat/*
    @post method POST
    reverse_proxy @chat https://api.openai.com
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}

#[test]
fn returns_filename_line_column_for_unsupported_directive() {
    let error = parse_caddyfile(
        r#"
:8080 {
    file_server
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap_err();

    assert_eq!(error.file, "Ferrogate/Caddyfile");
    assert_eq!(error.line, 3);
    assert_eq!(error.column, 5);
    assert_eq!(error.directive, "file_server");
    assert!(error.suggestion.contains("supported MVP directives"));
}
