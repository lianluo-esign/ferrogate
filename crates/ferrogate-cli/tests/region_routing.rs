// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for region-aware routing enforcement
// (issue #173): a tenant with a region_allowlist gets rejected with a
// clear, logged reason when no candidate route satisfies it, rather than
// silently falling back to an out-of-region provider -- exercised through
// the real /v1/chat/completions request path, not just the
// candidate_model_routes unit tests in state.rs.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[[providers]]
name = "eu-provider"
kind = "openai"
base_url = "http://127.0.0.1:65535/v1"
region = "eu-west-1"

[[providers]]
name = "us-provider"
kind = "openai"
base_url = "http://127.0.0.1:65534/v1"
region = "us-east-1"

[[models]]
name = "eu-only-chat"
provider = "eu-provider"
provider_model = "gpt-4o-mini"

[[models]]
name = "multi-region-chat"
provider = "eu-provider"
provider_model = "gpt-4o-mini"

[[models.fallbacks]]
provider = "us-provider"
provider_model = "gpt-4o-mini"
priority = 10
weight = 1

[[api_keys]]
id = "eu_only_client"
name = "EU-only client"
key = "eu-only-secret"
scopes = ["chat.completions"]
allowed_models = ["eu-only-chat", "multi-region-chat"]
region_allowlist = ["eu-west-1"]
platform_operator = true

[[api_keys]]
id = "us_only_client"
name = "US-only client"
key = "us-only-secret"
scopes = ["chat.completions"]
allowed_models = ["eu-only-chat", "multi-region-chat"]
region_allowlist = ["us-east-1"]
platform_operator = true

[[api_keys]]
id = "unrestricted_client"
name = "Unrestricted client"
key = "unrestricted-secret"
scopes = ["chat.completions"]
allowed_models = ["eu-only-chat", "multi-region-chat"]
platform_operator = true
"#
        ),
    )
    .unwrap();
}

fn chat(addr: &str, token: &str, model: &str) -> String {
    http_request(
        addr,
        "POST",
        "/v1/chat/completions",
        &[
            "Content-Type: application/json",
            &format!("Authorization: Bearer {token}"),
        ],
        &format!(r#"{{"model":"{model}","messages":[]}}"#),
    )
}

#[test]
fn region_restricted_key_is_rejected_when_no_candidate_route_is_in_region() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // eu-only-chat's only route is eu-provider (eu-west-1); a client whose
    // region_allowlist is us-east-1 has zero satisfying candidates.
    let response = chat(&gateway_addr, "us-only-secret", "eu-only-chat");
    assert!(
        response.contains("403 Forbidden"),
        "expected a 403 when no candidate route satisfies the region allowlist: {response}"
    );
    assert!(
        response.contains("region_not_allowed"),
        "expected the region_not_allowed error code: {response}"
    );
    assert!(
        !response.contains("us-only-secret"),
        "the API key secret must never leak into an error response: {response}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn region_restricted_key_succeeds_when_a_candidate_route_matches() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // eu-only-chat's only route (eu-provider, eu-west-1) does satisfy an
    // eu-west-1-restricted key -- the request proceeds past the region
    // gate (it still fails at actual provider dispatch, since
    // 127.0.0.1:65535 isn't a real upstream, but that's a *different*,
    // later failure than region_not_allowed, proving the gate didn't
    // block it).
    let response = chat(&gateway_addr, "eu-only-secret", "eu-only-chat");
    assert!(
        !response.contains("region_not_allowed"),
        "an in-region candidate exists, the region gate must not have blocked this: {response}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn multi_region_model_lets_each_region_restricted_key_reach_its_own_provider() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    // multi-region-chat has routes in both regions -- both a us-east-1-
    // restricted and an eu-west-1-restricted key must clear the region
    // gate (each via a different candidate route), and an unrestricted
    // key is unaffected either way.
    for token in ["eu-only-secret", "us-only-secret", "unrestricted-secret"] {
        let response = chat(&gateway_addr, token, "multi-region-chat");
        assert!(
            !response.contains("region_not_allowed"),
            "multi-region-chat has a route in every configured region, \
             {token} must not be blocked by the region gate: {response}"
        );
    }

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn unrestricted_key_is_never_blocked_by_the_region_gate() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("ferrogate.toml");
    write_config(&config, &gateway_addr);

    let mut gateway = start_gateway(&config);
    wait_for_gateway(&gateway_addr);

    let response = chat(&gateway_addr, "unrestricted-secret", "eu-only-chat");
    assert!(
        !response.contains("region_not_allowed"),
        "a key with no region_allowlist must be unaffected by region enforcement: {response}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
