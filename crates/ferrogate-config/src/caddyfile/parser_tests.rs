// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

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
fn parses_ai_gateway_provider_model_and_api_key_blocks() {
    let config = parse_caddyfile(
        r#"
:8080 {
    ai_gateway {
        provider openai {
            kind openai
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }

        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
            context_window 128000
            input_price_per_1m 0.15
            output_price_per_1m 0.60
        }

        api_key key_dev {
            name Development key
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions
            allowed_models fast-chat
            denied_models fast-chat
            denied_providers openai
            monthly_token_budget 1000000
            request_limit_per_minute 60
        }
    }
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap();

    assert_eq!(config.providers.len(), 1);
    assert_eq!(config.providers[0].name, "openai");
    assert_eq!(
        config.providers[0].api_key_env.as_deref(),
        Some("OPENAI_API_KEY")
    );
    assert_eq!(config.models.len(), 1);
    assert_eq!(config.models[0].name, "fast-chat");
    assert_eq!(config.models[0].provider, "openai");
    assert_eq!(config.models[0].provider_model, "gpt-4o-mini");
    assert_eq!(config.models[0].capabilities, ["chat", "streaming"]);
    assert_eq!(config.models[0].context_window, Some(128000));
    assert_eq!(config.api_keys.len(), 1);
    assert_eq!(config.api_keys[0].id, "key_dev");
    assert_eq!(
        config.api_keys[0].key_env.as_deref(),
        Some("FERROGATE_DEV_KEY")
    );
    assert_eq!(config.api_keys[0].allowed_models, ["fast-chat"]);
    assert_eq!(config.api_keys[0].denied_models, ["fast-chat"]);
    assert_eq!(config.api_keys[0].denied_providers, ["openai"]);
    assert_eq!(config.api_keys[0].monthly_token_budget, Some(1000000));
    assert_eq!(config.api_keys[0].request_limit_per_minute, Some(60));
}

/// #542 rework, finding 2: the Caddyfile grammar can state the authentication
/// posture, so a Caddy-migrated reverse proxy with no `ai_gateway` block has an
/// expressible remedy for the startup gate instead of being told to write a
/// TOML section its config format cannot hold.
///
/// Pins the `"auth"` arm of `Parser::parse_global_options`
/// (`caddyfile/parser.rs`). Delete the arm and the first two parses become
/// "unsupported directive" errors; make `off` a no-op and the first assertion
/// reds; make the default `true` and the third reds.
#[test]
fn global_auth_directive_states_the_posture_a_caddyfile_could_not_say() {
    let open = parse_caddyfile(
        r#"
{
    admin localhost:2019
    auth off
}

:8080 {
    reverse_proxy https://api.openai.com
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap();
    assert!(open.auth_disabled);

    let explicitly_required = parse_caddyfile(
        r#"
{
    auth on
}

:8080 {
    reverse_proxy https://api.openai.com
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap();
    assert!(!explicitly_required.auth_disabled);

    // The omitted directive is the safe answer, not an inherited one.
    let silent = parse_caddyfile(
        r#"
:8080 {
    reverse_proxy https://api.openai.com
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap();
    assert!(!silent.auth_disabled);
}

/// The posture directive is closed the same way the rest of the grammar is: a
/// misspelled argument is refused with a span, never read as "off".
#[test]
fn global_auth_directive_refuses_an_argument_it_does_not_understand() {
    for bad in ["auth disabled", "auth", "auth false"] {
        let error = parse_caddyfile(&format!("{{\n    {bad}\n}}\n"), "Ferrogate/Caddyfile")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("auth off") && error.contains("auth on"),
            "`{bad}` must be refused with the two spellings that work: {error}"
        );
    }
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
