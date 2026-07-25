// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: End-to-end dual-path parity for the /control/v1 URI alias
// (issue #453). The canonical /control/v1 prefix is normalized onto the stable
// /admin/v1 prefix at ingress, so both prefixes are served by one route
// contract with no duplicated handlers. These tests drive a real gateway
// process and assert byte-identical behavior across the two prefixes for
// missing auth, invalid keys, admin.read/admin.write scope enforcement,
// authorized reads, request IDs, error codes, pagination/query pass-through,
// CSRF, tenant isolation (cross-tenant wallet read denied identically), and
// not-found routing -- plus that the alias is transparent (an alias request
// echoes the canonical /admin/v1 path, never /control/v1).

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

const ADMIN_PREFIX: &str = "/admin/v1";
const CONTROL_PREFIX: &str = "/control/v1";

fn config_toml(gateway_addr: &str) -> String {
    // Memory-backed, auth-enforcing config: no external DB required, but
    // [[api_keys]] make auth_required() true so scope enforcement is exercised.
    format!(
        r#"
listen = "{gateway_addr}"

[[api_keys]]
id = "admin"
name = "Admin"
key = "admin-secret"
scopes = ["admin.read", "admin.write"]

[[api_keys]]
id = "reader"
name = "Reader"
key = "reader-secret"
scopes = ["admin.read"]

[[api_keys]]
id = "chat"
name = "Chat only"
key = "chat-secret"
scopes = ["chat.completions"]

[[api_keys]]
id = "tenant-a-console"
name = "Tenant A console session key"
key = "tenant-a-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "alias-tenant-a"
"#
    )
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn body_of(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or_default()
}

/// Replace the value of every `"request_id":"..."` with a fixed placeholder so
/// two responses that differ ONLY by their per-request id compare equal.
fn strip_request_id(body: &str) -> String {
    let needle = "\"request_id\":\"";
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(pos) = rest.find(needle) {
        out.push_str(&rest[..pos + needle.len()]);
        let after = &rest[pos + needle.len()..];
        match after.find('"') {
            Some(end) => {
                out.push_str("<redacted>");
                rest = &after[end..];
            }
            None => {
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn has_request_id_header(response: &str) -> bool {
    response
        .lines()
        .any(|line| line.to_ascii_lowercase().starts_with("x-request-id:"))
}

/// Issue one request under each prefix with identical method/headers/body and
/// assert full behavioral parity: identical status line, identical response
/// body (ignoring the volatile per-request id), and a request-id header on
/// both. Returns the `/control/v1` response for any alias-specific assertions.
fn assert_parity(
    addr: &str,
    method: &str,
    suffix: &str,
    headers: &[&str],
    body: &str,
    label: &str,
) -> String {
    let admin = http_request(
        addr,
        method,
        &format!("{ADMIN_PREFIX}{suffix}"),
        headers,
        body,
    );
    let control = http_request(
        addr,
        method,
        &format!("{CONTROL_PREFIX}{suffix}"),
        headers,
        body,
    );

    assert_eq!(
        status_line(&admin),
        status_line(&control),
        "{label}: status-line parity\nadmin: {admin}\ncontrol: {control}"
    );
    assert_eq!(
        strip_request_id(body_of(&admin)),
        strip_request_id(body_of(&control)),
        "{label}: response-body parity\nadmin: {admin}\ncontrol: {control}"
    );
    assert!(
        has_request_id_header(&admin),
        "{label}: admin response must carry x-request-id: {admin}"
    );
    assert!(
        has_request_id_header(&control),
        "{label}: control response must carry x-request-id: {control}"
    );
    control
}

#[test]
fn control_v1_alias_has_full_behavioral_parity_with_admin_v1() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, config_toml(&gateway_addr)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // 1. Missing credential -> 401 missing_api_key, identical envelope.
    let missing = assert_parity(&gateway_addr, "GET", "/providers", &[], "", "missing auth");
    assert!(
        status_line(&missing).contains("401"),
        "missing auth is 401: {missing}"
    );
    assert!(
        missing.contains("missing_api_key"),
        "missing auth code: {missing}"
    );

    // 2. Unknown key -> 401 invalid_api_key, identical envelope.
    let invalid = assert_parity(
        &gateway_addr,
        "GET",
        "/providers",
        &["Authorization: Bearer not-a-real-key"],
        "",
        "invalid key",
    );
    assert!(
        status_line(&invalid).contains("401"),
        "invalid key is 401: {invalid}"
    );
    assert!(
        invalid.contains("invalid_api_key"),
        "invalid key code: {invalid}"
    );

    // 3. Read scope enforcement: a chat-only key is denied admin.read (403).
    let wrong_scope = assert_parity(
        &gateway_addr,
        "GET",
        "/providers",
        &["Authorization: Bearer chat-secret"],
        "",
        "wrong scope read",
    );
    assert!(
        status_line(&wrong_scope).contains("403"),
        "wrong scope is 403: {wrong_scope}"
    );
    assert!(
        wrong_scope.contains("scope_denied"),
        "wrong scope code: {wrong_scope}"
    );

    // 4. Write scope enforcement: an admin.read-only key is denied a mutation
    // (admin.write). config/reload is a non-browser client here, so CSRF does
    // not fire and the request reaches the scope check identically.
    let read_only_write = assert_parity(
        &gateway_addr,
        "POST",
        "/config/reload",
        &[
            "Authorization: Bearer reader-secret",
            "Content-Type: application/json",
        ],
        "{}",
        "read-only key attempts write",
    );
    assert!(
        status_line(&read_only_write).contains("403"),
        "read-only write is 403: {read_only_write}"
    );
    assert!(
        read_only_write.contains("scope_denied"),
        "write scope code: {read_only_write}"
    );

    // 5. Authorized read of a deterministic resource -> 200, identical body.
    let providers = assert_parity(
        &gateway_addr,
        "GET",
        "/providers",
        &["Authorization: Bearer admin-secret"],
        "",
        "authorized providers read",
    );
    assert!(
        status_line(&providers).contains("200"),
        "authorized read is 200: {providers}"
    );

    // 6. Authorized status read -> 200; the AdminStatus body is config-derived
    // and therefore byte-identical across both prefixes.
    let status = assert_parity(
        &gateway_addr,
        "GET",
        "/status",
        &["Authorization: Bearer admin-secret"],
        "",
        "authorized status read",
    );
    assert!(
        status_line(&status).contains("200"),
        "status is 200: {status}"
    );

    // 7. Pagination / query-string pass-through parity.
    assert_parity(
        &gateway_addr,
        "GET",
        "/providers?limit=1&offset=0",
        &["Authorization: Bearer admin-secret"],
        "",
        "pagination query pass-through",
    );

    // 8. CSRF / confused-deputy parity: a cross-site browser mutation is
    // rejected identically under both prefixes (proves the CSRF guard sees the
    // normalized /admin/ path for /control/v1 too).
    let csrf = assert_parity(
        &gateway_addr,
        "POST",
        "/config/reload",
        &["Sec-Fetch-Site: cross-site", "Content-Type: text/plain"],
        "{}",
        "cross-site mutation",
    );
    assert!(
        status_line(&csrf).contains("403"),
        "cross-site mutation is 403: {csrf}"
    );
    assert!(
        csrf.contains("cross_site_admin_denied"),
        "CSRF code: {csrf}"
    );

    // 9. Not-found routing parity -- AND transparency: the alias request echoes
    // the canonical /admin/v1 path, never /control/v1.
    let not_found = assert_parity(
        &gateway_addr,
        "GET",
        "/no-such-endpoint-xyz",
        &[],
        "",
        "unknown endpoint",
    );
    assert!(
        status_line(&not_found).contains("404"),
        "unknown endpoint is 404: {not_found}"
    );
    assert!(
        not_found.contains("/admin/v1/no-such-endpoint-xyz"),
        "alias must transparently normalize to the canonical path: {not_found}"
    );
    assert!(
        !not_found.contains("/control/v1/no-such-endpoint-xyz"),
        "alias path must not leak into the normalized response: {not_found}"
    );

    // 10. Tenant-isolation parity (acceptance dimension, #185): a tenant-scoped
    // console key cannot read another tenant's wallet, and the denial is
    // byte-identical under both prefixes. This proves the tenant-scope guard --
    // like every other downstream consumer -- reads the normalized path for a
    // /control/v1 request too (a security-critical parity property that the
    // single-source normalization must not bypass).
    let cross_tenant = assert_parity(
        &gateway_addr,
        "GET",
        "/wallets/some-other-tenant",
        &["Authorization: Bearer tenant-a-secret"],
        "",
        "cross-tenant wallet read",
    );
    assert!(
        status_line(&cross_tenant).contains("403"),
        "cross-tenant read is 403: {cross_tenant}"
    );
    assert!(
        cross_tenant.contains("tenant_scope_denied"),
        "cross-tenant denial code: {cross_tenant}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
