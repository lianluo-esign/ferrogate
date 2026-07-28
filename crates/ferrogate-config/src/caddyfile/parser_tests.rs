// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use super::parse_caddyfile;
use ferrogate_providers::ModelCapability;

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
fn rejects_unknown_model_capability_in_caddyfile() {
    let error = parse_caddyfile(
        r#"
:8080 {
    ai_gateway {
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat telepathy
        }
    }
}
"#,
        "Ferrogate/Caddyfile",
    )
    .unwrap_err();

    assert_eq!(error.directive, "capabilities");
    let rendered = error.to_string();
    assert!(rendered.contains("unknown model capability \"telepathy\""));
    assert!(rendered.contains("structured_output"));
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
            # #540: this fixture mirrors the shipped `Ferrogate/Caddyfile`, so
            # it declares what that file declares -- a parser fixture that
            # would not load is a bad model of the file it copies.
            platform_operator on
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
    assert_eq!(
        config.models[0].capabilities,
        [ModelCapability::Chat, ModelCapability::Streaming]
    );
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

/// #540: the bridged config format can now state a key's tenant identity, which
/// is what makes the load-time refusal fixable in a Caddyfile at all.
///
/// Pins the `"organization_id"` and `"platform_operator"` arms of
/// `Parser::parse_ai_api_key` AND the two fields' journey through
/// `Config::from_gateway_config`. Reading the parsed `GatewayConfig` alone would
/// stay green if the bridge dropped them on the floor -- which is exactly the
/// half that decides whether a real deployment boots -- so assert on the
/// resolved `Config`, past both.
#[test]
fn api_key_tenancy_directives_reach_the_native_config() {
    let config = crate::Config::from_caddyfile_str(
        r#"
:8080 {
    ai_gateway {
        provider openai {
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat
        }
        api_key root {
            key root-secret
            scopes admin.read
            platform_operator on
        }
        api_key tenant {
            key tenant-secret
            scopes chat.completions
            organization_id acme-corp
        }
        api_key refuses {
            key refuses-secret
            scopes chat.completions
            organization_id acme-corp
            platform_operator off
        }
    }
}
"#,
        "Ferrogate/Caddyfile",
    )
    .expect("every key declares an identity, so this config loads under the #540 default");

    let key = |id: &str| {
        config
            .api_keys
            .iter()
            .find(|key| key.id == id)
            .unwrap_or_else(|| panic!("api key {id}"))
    };
    assert_eq!(key("root").platform_operator, Some(true));
    assert_eq!(key("root").organization_id, None);
    assert_eq!(key("tenant").platform_operator, None);
    assert_eq!(key("tenant").organization_id.as_deref(), Some("acme-corp"));
    assert_eq!(
        key("refuses").platform_operator,
        Some(false),
        "`off` must survive as an explicit refusal of root, not collapse into the absent state"
    );
}

/// The bridge must not invent an identity for a key that states none: doing so
/// would put #540's own bug -- an omitted field granting root -- back one layer
/// down, where neither the refusal nor the warning could ever see it again.
#[test]
fn a_caddyfile_key_that_declares_no_tenancy_is_refused_rather_than_defaulted() {
    let keyless = r#"
:8080 {
    ai_gateway {
        provider openai {
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }
        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat
        }
        # #540-undeclared-on-purpose: the key this refusal test is about
        api_key silent {
            key silent-secret
            scopes admin.read
        }
    }
}
"#;
    let parsed = parse_caddyfile(keyless, "Ferrogate/Caddyfile").unwrap();
    assert_eq!(
        parsed.api_keys[0].platform_operator, None,
        "the parser must carry the ABSENCE across; a synthesised Some(true) here is \
         indistinguishable from an operator who meant it"
    );

    let error = crate::Config::from_caddyfile_str(keyless, "Ferrogate/Caddyfile")
        .expect_err("#540: an undeclared key must not load")
        .to_string();
    assert!(
        error.contains("silent"),
        "the refusal names the key that has to change: {error}"
    );
}

/// The tenancy directives are closed the same way the rest of the grammar is: a
/// misspelled argument is refused with a span, never read as either answer.
///
/// #540-undeclared-on-purpose: key `k` below declares no identity in either
/// loop -- that is the input, since a directive that fails to parse is a
/// directive that declared nothing.
#[test]
fn platform_operator_directive_refuses_an_argument_it_does_not_understand() {
    for bad in [
        "platform_operator",
        "platform_operator yes",
        "platform_operator 1",
    ] {
        let error = parse_caddyfile(
            &format!(
                "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            {bad}\n        }}\n    }}\n}}\n"
            ),
            "Ferrogate/Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("platform_operator on") && error.contains("organization_id"),
            "`{bad}` must be refused with the spellings that work: {error}"
        );
    }
}

/// #540 rework, review minor 8: the sibling directive was asymmetric.
/// `platform_operator` with a bad or missing argument was refused with a span
/// (above); `organization_id` with no argument was `args.first().cloned()` ->
/// `None`, i.e. silently identical to writing nothing at all.
///
/// It fails closed either way -- the key ends up undeclared and the load
/// refusal catches it -- but the message the operator then reads says "declare
/// an organization_id", which is what they thought they had just done. A
/// directive whose entire job is to BE the declaration cannot be a no-op when
/// it is malformed.
///
/// Pins the `Some(value) if !value.trim().is_empty()` guard on the
/// `organization_id` arm in `parser.rs`. Restore `args.first().cloned()` and
/// both loop cases red -- `unwrap_err` panics, because the parse succeeds.
///
/// #540-undeclared-on-purpose: key `k` below declares no identity in either
/// loop case; a malformed declaration IS the input here.
#[test]
fn organization_id_directive_refuses_a_missing_argument_instead_of_ignoring_it() {
    for bad in ["organization_id", "organization_id \"\""] {
        let error = parse_caddyfile(
            &format!(
                "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            {bad}\n        }}\n    }}\n}}\n"
            ),
            "Ferrogate/Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("organization_id <tenants.id>") && error.contains("platform_operator"),
            "`{bad}` must be refused with the spellings that work: {error}"
        );
    }

    // Control: the well-formed directive still parses, so the guard above is
    // rejecting an empty argument and not the directive itself.
    let parsed = parse_caddyfile(
        "\n:8080 {\n    ai_gateway {\n        api_key k {\n            key s\n            organization_id tenant-a\n        }\n    }\n}\n",
        "Ferrogate/Caddyfile",
    )
    .expect("a well-formed organization_id must still parse");
    assert_eq!(
        parsed.api_keys[0].organization_id.as_deref(),
        Some("tenant-a")
    );
}

/// `organization_id` accepts the same `env.NAME`, `{env.NAME}` and `{$NAME}`
/// references as provider/API-key credentials, but resolves them to the tenant
/// id because the typed key has no separate `organization_id_env` field.
///
/// Pins the `env_reference(value)` branch in `parser.rs`: storing `value`
/// directly makes all three assertions read their placeholder literally.
#[test]
fn organization_id_expands_the_caddyfile_environment_reference_spellings() {
    const ENV_NAME: &str = "FERROGATE_CADDY_ORGANIZATION_ID_TEST";
    std::env::remove_var(ENV_NAME);
    std::env::set_var(ENV_NAME, "tenant-from-env");

    for reference in [
        format!("env.{ENV_NAME}"),
        format!("{{env.{ENV_NAME}}}"),
        format!("{{${ENV_NAME}}}"),
    ] {
        let parsed = parse_caddyfile(
            &format!(
                "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            \
                 organization_id {reference}\n        }}\n    }}\n}}\n"
            ),
            "Ferrogate/Caddyfile",
        )
        .expect("a set organization-id environment reference must parse");
        assert_eq!(
            parsed.api_keys[0].organization_id.as_deref(),
            Some("tenant-from-env"),
            "{reference} must resolve to the environment value, not become a literal tenant id"
        );
    }

    std::env::remove_var(ENV_NAME);

    let missing = parse_caddyfile(
        &format!(
            "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            \
             organization_id {{$${ENV_NAME}}}\n        }}\n    }}\n}}\n"
        ),
        "Ferrogate/Caddyfile",
    )
    .expect_err("a missing organization-id environment variable must fail closed")
    .to_string();
    assert!(
        missing.contains(ENV_NAME) && missing.contains("is not set"),
        "the refusal must name the missing environment variable: {missing}"
    );

    std::env::set_var(ENV_NAME, "");
    let empty = parse_caddyfile(
        &format!(
            "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            \
             organization_id {{$${ENV_NAME}}}\n        }}\n    }}\n}}\n"
        ),
        "Ferrogate/Caddyfile",
    )
    .expect_err("an empty organization-id environment variable must fail closed")
    .to_string();
    assert!(
        empty.contains(ENV_NAME) && empty.contains("empty tenant id"),
        "the refusal must distinguish an empty value from a missing one: {empty}"
    );
    std::env::remove_var(ENV_NAME);
}

/// The expected-token constructor must render what is missing. Before #540's
/// diagnostic rewrite, `directive` carried this value but `Display` dropped it,
/// so five distinct syntax errors collapsed to one opaque sentence.
#[test]
fn a_missing_required_token_is_present_in_structured_and_rendered_diagnostics() {
    let error = parse_caddyfile(
        "\n:8080 {\n    ai_gateway {\n        api_key\n    }\n}\n",
        "Ferrogate/Caddyfile",
    )
    .expect_err("api_key without an id must be refused");

    assert_eq!(error.directive, "api_key id");
    let rendered = error.to_string();
    assert!(
        rendered.contains("expected `api_key id`"),
        "the operator must be told which token is missing: {rendered}"
    );
}

/// #540 rework 2, review minor 14: a directive FerroGate supports, written with
/// an argument it does not, is no longer reported as unsupported.
///
/// `organization_id` with no value printed "unsupported directive
/// `organization_id`: not part of the FerroGate Caddyfile MVP subset" and then
/// suggested writing `organization_id <tenants.id>` -- the directive it had
/// just called unsupported. #540 ADDED that directive; the operator reading
/// that message cannot tell "delete this line" from "fix this argument", and
/// deleting it leaves the key undeclared, which is the state this whole issue
/// exists to stop.
///
/// Pins `Parser::invalid_argument` and both call sites. Route either arm back
/// to `self.unsupported(...)` and the corresponding assertion reds. The last
/// two assertions hold the other direction: a genuinely unknown directive still
/// says "unsupported", so this is not a build that simply deleted the word.
///
/// #540-undeclared-on-purpose: key `k` below declares no identity -- a
/// malformed declaration is the input.
#[test]
fn a_supported_directive_with_a_bad_argument_is_not_called_unsupported() {
    for bad in ["organization_id", "platform_operator yes"] {
        let error = parse_caddyfile(
            &format!(
                "\n:8080 {{\n    ai_gateway {{\n        api_key k {{\n            key s\n            {bad}\n        }}\n    }}\n}}\n"
            ),
            "Ferrogate/Caddyfile",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("invalid argument"),
            "`{bad}` names a directive FerroGate supports: {error}"
        );
        assert!(
            !error.contains("unsupported directive"),
            "...so telling the operator to delete it is the one answer that must not be given: \
             {error}"
        );
    }

    let unknown = parse_caddyfile(
        "\n:8080 {\n    ai_gateway {\n        api_key k {\n            key s\n            \
         organization_id tenant-a\n            nonsense yes\n        }\n    }\n}\n",
        "Ferrogate/Caddyfile",
    )
    .unwrap_err()
    .to_string();
    assert!(
        unknown.contains("unsupported directive") && unknown.contains("nonsense"),
        "a directive that really is outside the subset still says so: {unknown}"
    );
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
