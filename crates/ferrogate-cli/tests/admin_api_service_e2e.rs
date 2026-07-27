// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: End-to-end coverage for the standalone admin-console API
// service (issue #315): `ferrogate admin-api serve` runs a dedicated
// listener that authenticates console callers (same virtual-key admin
// auth as the gateway) and reverse-proxies the path-compatible
// /admin/v1/* surface to the gateway -- while the AI data plane is NOT
// reachable through it, unauthenticated/wrong-scope callers are refused
// AT the admin-api layer (proven against a dead upstream), and tenant
// isolation (#185) holds identically through the proxy. In-memory
// storage, matching tests/tenant_isolation_admin_api.rs's convention.

mod support;

use std::process::{Child, Command, Stdio};

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str, admin_api_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[admin_api]
listen = "{admin_api_addr}"
gateway_url = "http://{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "chat-only"
name = "Data-plane only key"
key = "chat-secret"
scopes = ["chat.completions"]
platform_operator = true

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A admin-console session key"
key = "tenant-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "adminapi-tenant-a"
"#
        ),
    )
    .unwrap();
}

fn start_admin_api(config: &std::path::Path) -> Child {
    ferrogate()
        .args(["admin-api", "serve", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// The `ferrogate` binary, pre-armed so a service started here dies with the
/// test that started it (#568) rather than being reparented to init. These are
/// long-lived listeners like the gateway itself, and their cleanup is the same
/// easily-skipped `kill()` statement.
fn ferrogate() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ferrogate"));
    support::reap_with_test(&mut command);
    command
}

/// Same key roster as `write_config`, but wired through the CANONICAL
/// `[control_api]` section (#359) instead of the deprecated `[admin_api]`
/// alias -- so the full-parity CRUD flow can be exercised end to end
/// through the promoted Control Plane API.
fn write_control_api_config(path: &std::path::Path, gateway_addr: &str, control_api_addr: &str) {
    std::fs::write(
        path,
        format!(
            r#"
listen = "{gateway_addr}"

[control_api]
listen = "{control_api_addr}"
gateway_url = "http://{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true

[[api_keys]]
id = "chat-only"
name = "Data-plane only key"
key = "chat-secret"
scopes = ["chat.completions"]
platform_operator = true

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A admin-console session key"
key = "tenant-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "adminapi-tenant-a"
"#
        ),
    )
    .unwrap();
}

fn start_control_api(config: &std::path::Path) -> Child {
    ferrogate()
        .args(["control-api", "serve", "--config", config.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

const ADMIN: [&str; 2] = [
    "Authorization: Bearer admin-secret",
    "Content-Type: application/json",
];
const CHAT_ONLY: [&str; 2] = [
    "Authorization: Bearer chat-secret",
    "Content-Type: application/json",
];
const TENANT_A: [&str; 2] = [
    "Authorization: Bearer tenant-a-secret",
    "Content-Type: application/json",
];

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn response_json(response: &str) -> serde_json::Value {
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response);
    serde_json::from_str(body).unwrap_or_else(|error| panic!("invalid JSON: {error}; {response}"))
}

/// The console-shaped flow through the dedicated listener: create a
/// resource via the admin-api service, list it back through BOTH the
/// admin-api service and the gateway directly, and assert identical
/// behavior -- same statuses, same resource payloads, one shared control
/// plane. Also proves the data plane is not served and that tenant
/// isolation (#185) holds identically through the proxy.
#[test]
fn admin_api_service_serves_the_admin_surface_with_gateway_parity() {
    let gateway_addr = free_addr();
    let admin_api_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr, &admin_api_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let mut admin_api = start_admin_api(&config_path);
    wait_for_gateway(&admin_api_addr);

    // Create through the admin-api listener (console-shaped write).
    let created = http_request(
        &admin_api_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        r#"{"id":"adminapi-tenant-a","name":"Tenant A","slug":"adminapi-tenant-a"}"#,
    );
    assert!(
        created.contains("HTTP/1.1 200") || created.contains("HTTP/1.1 201"),
        "create through admin-api failed: {created}"
    );

    // Read back through both listeners: byte-identical resource payloads.
    let via_admin_api = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    let via_gateway = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    assert!(
        via_admin_api.contains("HTTP/1.1 200"),
        "list through admin-api failed: {via_admin_api}"
    );
    assert_eq!(
        status_line(&via_admin_api),
        status_line(&via_gateway),
        "status parity broke"
    );
    let listed_admin_api = response_json(&via_admin_api);
    let listed_gateway = response_json(&via_gateway);
    assert_eq!(
        listed_admin_api["data"], listed_gateway["data"],
        "the two listeners must expose the same control plane"
    );
    assert!(
        listed_admin_api["data"]
            .as_array()
            .expect("tenant list")
            .iter()
            .any(|tenant| tenant["id"] == "adminapi-tenant-a"),
        "created tenant missing from the admin-api listing: {listed_admin_api}"
    );

    // Error-status parity for an authenticated wrong-scope caller.
    let scoped_admin_api = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &CHAT_ONLY,
        "",
    );
    let scoped_gateway = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &CHAT_ONLY,
        "",
    );
    assert!(
        scoped_admin_api.contains("HTTP/1.1 403"),
        "wrong-scope caller must get 403 via admin-api: {scoped_admin_api}"
    );
    assert_eq!(status_line(&scoped_admin_api), status_line(&scoped_gateway));
    assert_eq!(
        response_json(&scoped_admin_api)["error"]["code"],
        response_json(&scoped_gateway)["error"]["code"]
    );

    // Tenant isolation (#185) holds identically through the proxy: tenant
    // A's console key cannot read another tenant's wallet.
    let foreign_wallet = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/wallets/some-other-tenant",
        &TENANT_A,
        "",
    );
    assert!(
        foreign_wallet.contains("HTTP/1.1 403"),
        "cross-tenant wallet read must be denied through the admin-api: {foreign_wallet}"
    );
    assert_eq!(
        response_json(&foreign_wallet)["error"]["code"],
        "tenant_scope_denied",
        "unexpected denial shape: {foreign_wallet}"
    );

    // The AI data plane is NOT served by the admin-api listener, even for
    // a fully privileged caller.
    let data_plane = http_request(
        &admin_api_addr,
        "POST",
        "/v1/chat/completions",
        &ADMIN,
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert!(
        data_plane.contains("HTTP/1.1 404"),
        "data-plane path must 404 on the admin-api listener: {data_plane}"
    );
    assert_eq!(response_json(&data_plane)["error"]["code"], "not_found");

    // The service's own health endpoint answers locally, reporting the
    // canonical FerroGate Control Plane API identity (#359) even when the
    // process was launched via the deprecated `admin-api serve` alias.
    let health = http_request(&admin_api_addr, "GET", "/healthz", &[], "");
    assert!(
        health.contains("HTTP/1.1 200") && health.contains("ferrogate-control-plane-api"),
        "unexpected health response: {health}"
    );

    let _ = admin_api.kill();
    let _ = gateway.kill();
    let _ = admin_api.wait();
    let _ = gateway.wait();
}

/// Fail-closed proof: with NO gateway running behind it (dead upstream),
/// the admin-api layer itself refuses unauthenticated (401) and
/// wrong-scope (403) callers -- so the auth gate demonstrably fires
/// BEFORE any forwarding -- while a fully authorized caller reaches the
/// forwarding stage and observes 502 for the dead upstream.
#[test]
fn admin_api_gate_refuses_before_forwarding() {
    let dead_gateway_addr = free_addr();
    let admin_api_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &dead_gateway_addr, &admin_api_addr);

    let mut admin_api = start_admin_api(&config_path);
    wait_for_gateway(&admin_api_addr);

    // Unauthenticated -> 401 at the admin-api layer.
    let unauthenticated = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &["Content-Type: application/json"],
        "",
    );
    assert!(
        unauthenticated.contains("HTTP/1.1 401"),
        "unauthenticated caller must be refused locally: {unauthenticated}"
    );
    assert_eq!(
        response_json(&unauthenticated)["error"]["code"],
        "missing_api_key"
    );

    // Unknown key -> 401 at the admin-api layer.
    let unknown = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer nope",
            "Content-Type: application/json",
        ],
        "",
    );
    assert!(
        unknown.contains("HTTP/1.1 401"),
        "unknown key must be refused locally: {unknown}"
    );
    assert_eq!(response_json(&unknown)["error"]["code"], "invalid_api_key");

    // Wrong scope -> 403 at the admin-api layer.
    let wrong_scope = http_request(
        &admin_api_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &CHAT_ONLY,
        r#"{"id":"x","name":"x","slug":"x"}"#,
    );
    assert!(
        wrong_scope.contains("HTTP/1.1 403"),
        "wrong-scope caller must be refused locally: {wrong_scope}"
    );
    assert_eq!(response_json(&wrong_scope)["error"]["code"], "scope_denied");

    // A fully authorized caller passes the gate and only then hits the
    // dead upstream: 502 from the admin-api layer, not a hang or a 401.
    let authorized = http_request(
        &admin_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    assert!(
        authorized.contains("HTTP/1.1 502"),
        "authorized caller must reach the forwarding stage: {authorized}"
    );
    assert_eq!(
        response_json(&authorized)["error"]["code"],
        "admin_upstream_unreachable"
    );

    // An admin-scoped payload above the #312 [limits] default (64 KiB for
    // standard admin mutations) is shed at the admin-api layer with the
    // gateway's payload_too_large shape -- again without any upstream.
    let oversized_body = format!(
        r#"{{"id":"big","name":"{}","slug":"big"}}"#,
        "x".repeat(70 * 1024)
    );
    let oversized = http_request(
        &admin_api_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        &oversized_body,
    );
    assert!(
        oversized.contains("HTTP/1.1 413"),
        "oversized admin body must be shed locally: {oversized}"
    );
    assert_eq!(
        response_json(&oversized)["error"]["code"],
        "payload_too_large"
    );

    // Body-framing rejections (issue #328, finding 2) are answered with a
    // clean HTTP error at the admin-api edge -- again with no upstream, so
    // the parser rejects before any forwarding, rather than dropping the
    // connection and stranding the console.
    //
    // A chunked POST -> 400 unsupported_transfer_encoding (this parser
    // frames bodies from Content-Length only and never decodes chunked).
    let chunked = raw_admin_api_request(
        &admin_api_addr,
        "POST /admin/v1/tenant-accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer admin-secret\r\nContent-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\n\r\n1e\r\n{\"id\":\"x\",\"name\":\"x\",\"slug\":\"x\"}\r\n0\r\n\r\n",
    );
    assert!(
        chunked.contains("HTTP/1.1 400"),
        "chunked request must be rejected with 400 at the admin-api edge: {chunked}"
    );
    assert_eq!(
        response_json(&chunked)["error"]["code"],
        "unsupported_transfer_encoding"
    );

    // A body-bearing POST with NO Content-Length -> 411 length_required.
    let unlengthed = raw_admin_api_request(
        &admin_api_addr,
        "POST /admin/v1/tenant-accounts HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Authorization: Bearer admin-secret\r\nContent-Type: application/json\r\n\r\n",
    );
    assert!(
        unlengthed.contains("HTTP/1.1 411"),
        "unlengthed body-bearing request must be rejected with 411: {unlengthed}"
    );
    assert_eq!(
        response_json(&unlengthed)["error"]["code"],
        "length_required"
    );

    let _ = admin_api.kill();
    let _ = admin_api.wait();
}

/// Write an exact raw HTTP request (bypassing the Content-Length-setting
/// `support::http_request` helper) and return the full response, so tests
/// can exercise malformed framing the normal helper would never produce.
fn raw_admin_api_request(addr: &str, raw: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    stream.write_all(raw.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

/// Startup fail-closed: with no credential source at all (no [[api_keys]],
/// no external auth service, no durable storage backend) the service
/// refuses to start rather than running an open control-plane proxy. Driven
/// through the DEPRECATED `admin-api serve` + `[admin_api]` alias to prove
/// the alias still reaches the identical fail-closed guard (#359).
#[test]
fn admin_api_refuses_to_start_without_a_credential_source() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config_path,
        format!(
            "listen = \"{}\"\n\n[admin_api]\nlisten = \"{}\"\ngateway_url = \"http://127.0.0.1:1\"\n",
            free_addr(),
            free_addr()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args([
            "admin-api",
            "serve",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "an open control-plane proxy must refuse to start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to start an open Control Plane API proxy"),
        "unexpected startup error: {stderr}"
    );
}

/// #359 canonical path: `ferrogate control-api serve` reading a `[control_api]`
/// config section starts the FerroGate Control Plane API service, reports the
/// canonical `/healthz` identity, and enforces the SAME fail-closed auth gate
/// as the deprecated alias -- unauthenticated callers are refused locally
/// (401) and a fully authorized caller passes the gate and only then reaches
/// the (deliberately dead) upstream (502). No gateway is spawned: this proves
/// the command dispatch, the `[control_api]` section wiring, and the canonical
/// naming without the heavier full-parity flow.
#[test]
fn control_api_command_and_config_section_start_and_gate() {
    let dead_gateway_addr = free_addr();
    let control_api_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
listen = "{dead_gateway_addr}"

[control_api]
listen = "{control_api_addr}"
gateway_url = "http://{dead_gateway_addr}"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true
"#
        ),
    )
    .unwrap();

    let mut control_api = ferrogate()
        .args([
            "control-api",
            "serve",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_gateway(&control_api_addr);

    // Canonical health identity.
    let health = http_request(&control_api_addr, "GET", "/healthz", &[], "");
    assert!(
        health.contains("HTTP/1.1 200") && health.contains("ferrogate-control-plane-api"),
        "unexpected health response: {health}"
    );

    // Unauthenticated -> 401 at the Control Plane API layer.
    let unauthenticated = http_request(
        &control_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &["Content-Type: application/json"],
        "",
    );
    assert!(
        unauthenticated.contains("HTTP/1.1 401"),
        "unauthenticated caller must be refused locally: {unauthenticated}"
    );

    // Authorized -> passes the gate, reaches the dead upstream -> 502.
    let authorized = http_request(
        &control_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    assert!(
        authorized.contains("HTTP/1.1 502"),
        "authorized caller must reach forwarding through [control_api]: {authorized}"
    );
    assert_eq!(
        response_json(&authorized)["error"]["code"],
        "admin_upstream_unreachable"
    );

    let _ = control_api.kill();
    let _ = control_api.wait();
}

/// #359 acceptance box 4, canonical: the full console-shaped CRUD flow --
/// create a resource, list it back through BOTH the Control Plane API
/// service and the gateway directly, assert byte-identical control-plane
/// parity, wrong-scope 403 parity, tenant isolation (#185), and that the
/// AI data plane is NOT served -- all END TO END through the promoted
/// `control-api serve` command and `[control_api]` section rather than the
/// deprecated `admin-api` alias. This is the canonical twin of
/// `admin_api_service_serves_the_admin_surface_with_gateway_parity`.
#[test]
fn control_api_service_serves_the_admin_surface_with_gateway_parity() {
    let gateway_addr = free_addr();
    let control_api_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_control_api_config(&config_path, &gateway_addr, &control_api_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);
    let mut control_api = start_control_api(&config_path);
    wait_for_gateway(&control_api_addr);

    // Create through the canonical Control Plane API listener.
    let created = http_request(
        &control_api_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        r#"{"id":"controlapi-tenant-a","name":"Tenant A","slug":"controlapi-tenant-a"}"#,
    );
    assert!(
        created.contains("HTTP/1.1 200") || created.contains("HTTP/1.1 201"),
        "create through control-api failed: {created}"
    );

    // Read back through both listeners: byte-identical resource payloads.
    let via_control_api = http_request(
        &control_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    let via_gateway = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &ADMIN,
        "",
    );
    assert!(
        via_control_api.contains("HTTP/1.1 200"),
        "list through control-api failed: {via_control_api}"
    );
    assert_eq!(
        status_line(&via_control_api),
        status_line(&via_gateway),
        "status parity broke"
    );
    let listed_control_api = response_json(&via_control_api);
    let listed_gateway = response_json(&via_gateway);
    assert_eq!(
        listed_control_api["data"], listed_gateway["data"],
        "the Control Plane API and gateway must expose the same control plane"
    );
    assert!(
        listed_control_api["data"]
            .as_array()
            .expect("tenant list")
            .iter()
            .any(|tenant| tenant["id"] == "controlapi-tenant-a"),
        "created tenant missing from the control-api listing: {listed_control_api}"
    );

    // Error-status parity for an authenticated wrong-scope caller.
    let scoped_control_api = http_request(
        &control_api_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &CHAT_ONLY,
        "",
    );
    let scoped_gateway = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/tenant-accounts",
        &CHAT_ONLY,
        "",
    );
    assert!(
        scoped_control_api.contains("HTTP/1.1 403"),
        "wrong-scope caller must get 403 via control-api: {scoped_control_api}"
    );
    assert_eq!(
        status_line(&scoped_control_api),
        status_line(&scoped_gateway)
    );
    assert_eq!(
        response_json(&scoped_control_api)["error"]["code"],
        response_json(&scoped_gateway)["error"]["code"]
    );

    // Tenant isolation (#185) holds identically through the canonical proxy.
    let foreign_wallet = http_request(
        &control_api_addr,
        "GET",
        "/admin/v1/wallets/some-other-tenant",
        &TENANT_A,
        "",
    );
    assert!(
        foreign_wallet.contains("HTTP/1.1 403"),
        "cross-tenant wallet read must be denied through control-api: {foreign_wallet}"
    );
    assert_eq!(
        response_json(&foreign_wallet)["error"]["code"],
        "tenant_scope_denied",
        "unexpected denial shape: {foreign_wallet}"
    );

    // The AI data plane is NOT served by the Control Plane API listener.
    let data_plane = http_request(
        &control_api_addr,
        "POST",
        "/v1/chat/completions",
        &ADMIN,
        r#"{"model":"fast-chat","messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert!(
        data_plane.contains("HTTP/1.1 404"),
        "data-plane path must 404 on the control-api listener: {data_plane}"
    );
    assert_eq!(response_json(&data_plane)["error"]["code"], "not_found");

    // Canonical health identity.
    let health = http_request(&control_api_addr, "GET", "/healthz", &[], "");
    assert!(
        health.contains("HTTP/1.1 200") && health.contains("ferrogate-control-plane-api"),
        "unexpected health response: {health}"
    );

    let _ = control_api.kill();
    let _ = gateway.kill();
    let _ = control_api.wait();
    let _ = gateway.wait();
}

/// #359 conflict guard: a config that sets BOTH the canonical `[control_api]`
/// section and the deprecated `[admin_api]` alias is rejected at startup with
/// a clear, actionable error rather than silently picking one.
#[test]
fn conflicting_control_api_and_admin_api_sections_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
listen = "{}"

[control_api]
listen = "{}"
gateway_url = "http://127.0.0.1:1"

[admin_api]
listen = "{}"
gateway_url = "http://127.0.0.1:1"

[[api_keys]]
id = "admin"
name = "Platform operator"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]
platform_operator = true
"#,
            free_addr(),
            free_addr(),
            free_addr()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args([
            "control-api",
            "serve",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "conflicting control-plane config must refuse to start"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conflicting control-plane API configuration"),
        "unexpected startup error: {stderr}"
    );
}
