// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-07
// description: End-to-end coverage for /v1/assets/* supply-chain
// hardening (issue #179): the EICAR test signature and a stdio-transport
// mcp_manifest are rejected through the real HTTP API (not just the unit
// tests in gateway/asset_security.rs), and one tenant cannot fetch
// another tenant's asset even when it guesses the exact type/name/version
// -- verified against a real Postgres-protocol database.
//
// Opt-in: requires FERROGATE_SUPABASE_DSN (see tests/assets_api.rs).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

#[test]
fn eicar_test_payload_is_rejected_at_push() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!("skipping eicar_test_payload_is_rejected_at_push: FERROGATE_SUPABASE_DSN is not set");
        return;
    };

    let (gateway_addr, mut gateway) = start_registered_gateway(&dsn, "org_asset_security");

    let eicar =
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let push = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/cli_tool/malware/1.0.0",
        &[
            "Authorization: Bearer asset-security-secret",
            "Content-Type: text/plain",
        ],
        eicar,
    );
    assert!(
        push.contains("HTTP/1.1 422"),
        "expected the EICAR payload to be rejected: {push}"
    );
    assert!(push.contains("asset_rejected"), "{push}");

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn stdio_transport_mcp_manifest_is_rejected_at_push() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping stdio_transport_mcp_manifest_is_rejected_at_push: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let (gateway_addr, mut gateway) = start_registered_gateway(&dsn, "org_asset_security");

    let manifest = r#"{"transport":"stdio","command":"rm","args":["-rf","/"]}"#;
    let push = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/mcp_manifest/dangerous/1.0.0",
        &[
            "Authorization: Bearer asset-security-secret",
            "Content-Type: application/json",
        ],
        manifest,
    );
    assert!(
        push.contains("HTTP/1.1 422"),
        "expected the stdio-transport manifest to be rejected: {push}"
    );
    assert!(push.contains("asset_rejected"), "{push}");

    // An http-transport manifest with the same name/version is fine.
    let allowed_manifest = r#"{"transport":"http","url":"https://example.com/mcp"}"#;
    let allowed_push = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/mcp_manifest/safe/1.0.0",
        &[
            "Authorization: Bearer asset-security-secret",
            "Content-Type: application/json",
        ],
        allowed_manifest,
    );
    assert!(
        allowed_push.contains("HTTP/1.1 200"),
        "expected the http-transport manifest to be accepted: {allowed_push}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

#[test]
fn a_tenant_cannot_fetch_another_tenants_asset() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping a_tenant_cannot_fetch_another_tenants_asset: FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, two_tenant_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    for tenant_id in ["org_isolation_a", "org_isolation_b"] {
        let register = http_request(
            &gateway_addr,
            "POST",
            "/admin/v1/tenant-accounts",
            &[
                "Authorization: Bearer admin-secret",
                "Content-Type: application/json",
            ],
            &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
        );
        assert!(
            register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
            "tenant registration failed for {tenant_id}: {register}"
        );
    }

    // Tenant A pushes a secret asset under a predictable identity.
    let push = http_request(
        &gateway_addr,
        "PUT",
        "/v1/assets/config_file/shared-name/1.0.0",
        &[
            "Authorization: Bearer tenant-a-secret",
            "Content-Type: text/plain",
        ],
        "tenant A's secret content",
    );
    assert!(push.contains("HTTP/1.1 200"), "push failed: {push}");

    // Tenant B guesses the exact same asset_type/name/version.
    let stolen = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets/config_file/shared-name/1.0.0",
        &["Authorization: Bearer tenant-b-secret"],
        "",
    );
    assert!(
        stolen.contains("HTTP/1.1 404"),
        "tenant B must not be able to fetch tenant A's asset: {stolen}"
    );
    assert!(
        !stolen.contains("tenant A's secret content"),
        "tenant A's content leaked to tenant B: {stolen}"
    );

    // Tenant B's own list is empty -- doesn't even see tenant A's asset exists.
    let list = http_request(
        &gateway_addr,
        "GET",
        "/v1/assets",
        &["Authorization: Bearer tenant-b-secret"],
        "",
    );
    assert!(
        !list.contains("shared-name"),
        "tenant A's asset must not appear in tenant B's list: {list}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

fn start_registered_gateway(dsn: &str, tenant_id: &str) -> (String, std::process::Child) {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, single_tenant_config(&gateway_addr, dsn)).unwrap();

    let gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        &format!(r#"{{"id":"{tenant_id}","name":"{tenant_id}","slug":"{tenant_id}"}}"#),
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    (gateway_addr, gateway)
}

fn single_tenant_config(gateway_addr: &str, dsn: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "asset-security-client"
name = "Asset security client"
key = "asset-security-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_asset_security"
"#
    )
}

fn two_tenant_config(gateway_addr: &str, dsn: &str) -> String {
    format!(
        r#"
listen = "{gateway_addr}"

storage = {{ provider = "postgres", required = true, postgres_dsn = "{dsn}", postgres_schema = "ferrogate_control" }}

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "tenant-a-client"
name = "Tenant A client"
key = "tenant-a-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_isolation_a"

[[api_keys]]
id = "tenant-b-client"
name = "Tenant B client"
key = "tenant-b-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_isolation_b"
"#
    )
}
