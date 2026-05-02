use super::parse_caddyfile;

#[test]
fn parses_initial_ferrogate_caddyfile_subset() {
    let config = parse_caddyfile(
        r#"
{
    admin localhost:2019
    debug
}

:8080 {
    log
    respond /healthz "ok" 200
    route /v1/* {
        reverse_proxy https://api.openai.com {
            header_up Authorization "Bearer {env.OPENAI_API_KEY}"
        }
    }
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap();

    assert_eq!(config.listen, "127.0.0.1:8080");
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.upstreams[0].url, "https://api.openai.com");
    let proxy_route = config
        .routes
        .iter()
        .find(|route| route.upstream.is_some())
        .unwrap();
    assert_eq!(proxy_route.path_prefixes, vec!["/v1"]);
    assert_eq!(proxy_route.request_headers[0].name, "Authorization");
    assert_eq!(
        proxy_route.request_headers[0].value,
        "Bearer {env.OPENAI_API_KEY}"
    );
    assert!(config
        .routes
        .iter()
        .any(|route| route.static_response.is_some()));
}

#[test]
fn unsupported_directive_reports_file_line_column_and_suggestion() {
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
    assert!(error.to_string().contains("unsupported directive"));
}
