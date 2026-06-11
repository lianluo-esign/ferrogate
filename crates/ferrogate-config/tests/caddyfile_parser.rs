// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use ferrogate_config::parse_caddyfile;

#[test]
fn parses_minimal_site_block_from_ferrogate_caddyfile() {
    let raw = include_str!("../../../Ferrogate/Caddyfile");

    let config = parse_caddyfile(raw, "Ferrogate/Caddyfile").unwrap();

    assert_eq!(config.listen, "0.0.0.0:8080");
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
    assert_eq!(config.tls.as_ref().unwrap().cert_path, "cert.pem");
    assert_eq!(config.tls.as_ref().unwrap().key_path, "key.pem");
    assert_eq!(config.logs.len(), 1);
}

#[test]
fn parses_tls_dns01_automation_block() {
    let config = parse_caddyfile(
        r#"
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
            ca https://acme-v02.api.letsencrypt.org/directory
        }
        storage ./acme
        challenge dns-01
        dns exec ./hooks/dns-set ./hooks/dns-cleanup {
            provider cloudflare
            api_token cf-token
            zone_id zone-123
        }
    }
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    let acme = config.tls_acme.as_ref().unwrap();
    assert_eq!(acme.domains, ["api.example.com"]);
    assert_eq!(acme.email.as_deref(), Some("ops@example.com"));
    assert_eq!(
        acme.directory_url.as_deref(),
        Some("https://acme-v02.api.letsencrypt.org/directory")
    );
    assert_eq!(acme.storage_dir.as_deref(), Some("./acme"));
    assert_eq!(acme.challenge.as_deref(), Some("dns-01"));
    assert_eq!(acme.dns_provider.as_deref(), Some("cloudflare"));
    assert_eq!(acme.dns_config.get("api_token").unwrap(), "cf-token");
    assert_eq!(acme.dns_config.get("zone_id").unwrap(), "zone-123");
    assert_eq!(acme.dns_hook_set.as_deref(), Some("./hooks/dns-set"));
    assert_eq!(
        acme.dns_hook_cleanup.as_deref(),
        Some("./hooks/dns-cleanup")
    );
}

#[test]
fn parses_tls_builtin_cloudflare_dns_provider_block() {
    let config = parse_caddyfile(
        r#"
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        dns cloudflare {
            api_token cf-token
            zone_id zone-123
        }
    }
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    let acme = config.tls_acme.as_ref().unwrap();
    assert_eq!(acme.dns_provider.as_deref(), Some("cloudflare"));
    assert_eq!(acme.dns_config.get("api_token").unwrap(), "cf-token");
    assert_eq!(acme.dns_config.get("zone_id").unwrap(), "zone-123");
    assert!(acme.dns_hook_set.is_none());
    assert!(acme.dns_hook_cleanup.is_none());
}

#[test]
fn parses_tls_http01_automation_block() {
    let config = parse_caddyfile(
        r#"
token4aicloud.com {
    tls {
        issuer acme {
            email ops@token4aicloud.com
        }
        challenge http-01
        http_challenge_listen 0.0.0.0:80
        storage ./acme
    }
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    let acme = config.tls_acme.as_ref().unwrap();
    assert_eq!(acme.domains, ["token4aicloud.com"]);
    assert_eq!(acme.challenge.as_deref(), Some("http-01"));
    assert_eq!(acme.http_challenge_listen.as_deref(), Some("0.0.0.0:80"));
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
fn parses_ai_gateway_typed_config_subset() {
    let config = parse_caddyfile(
        r#"
:8080 {
    ai_gateway {
        provider openai {
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
            openrouter_http_referer https://ferrogate.example
            openrouter_x_title FerroGate Local
        }
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
        }
        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions
            allowed_models fast-chat
            denied_models fast-chat
            denied_providers openai
        }
    }
}
"#,
        "test.Caddyfile",
    )
    .unwrap();

    assert_eq!(config.providers[0].base_url, "https://api.openai.com/v1");
    assert_eq!(
        config.providers[0].api_key_env.as_deref(),
        Some("OPENAI_API_KEY")
    );
    assert_eq!(
        config.providers[0].openrouter_http_referer.as_deref(),
        Some("https://ferrogate.example")
    );
    assert_eq!(
        config.providers[0].openrouter_x_title.as_deref(),
        Some("FerroGate Local")
    );
    assert_eq!(config.models[0].provider_model, "gpt-4o-mini");
    assert_eq!(config.api_keys[0].denied_models, ["fast-chat"]);
    assert_eq!(config.api_keys[0].denied_providers, ["openai"]);
    assert_eq!(
        config.api_keys[0].scopes,
        ["models.read", "chat.completions"]
    );
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
