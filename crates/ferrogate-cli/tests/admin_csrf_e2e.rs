// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-17
// description: End-to-end regression for the admin CSRF / confused-deputy
// defense. In zero-config mode (no api_keys, auth disabled) authenticate()
// admits every request, so without a cross-site guard a malicious web page
// could drive a state-changing /admin POST as a CORS "simple request",
// hijacking the gateway config via the victim's browser. A cross-site browser
// mutation must be rejected regardless of auth mode; a non-browser client
// (no Sec-Fetch-Site / Origin) must still be served.

mod support;

use support::{free_addr, http_request, start_gateway, wait_for_gateway};

fn write_config(path: &std::path::Path, gateway_addr: &str) {
    // Deliberately zero-config: no [[api_keys]] and no auth_service, so
    // auth_required() is false and authenticate() admits every request.
    std::fs::write(path, format!("listen = \"{gateway_addr}\"\n")).unwrap();
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn cross_site_admin_mutation_is_rejected_even_with_auth_disabled() {
    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    write_config(&config_path, &gateway_addr);

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // A malicious cross-site page's `fetch` carries an un-forgeable
    // `Sec-Fetch-Site: cross-site`. The admin mutation must be refused before
    // the (disabled) auth check ever admits it.
    let cross_site = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &["Sec-Fetch-Site: cross-site", "Content-Type: text/plain"],
        "{}",
    );
    assert!(
        status_line(&cross_site).contains("403"),
        "cross-site admin mutation must be rejected: {cross_site}"
    );
    assert!(
        cross_site.contains("cross_site_admin_denied"),
        "rejection must be the CSRF guard: {cross_site}"
    );

    // An old-browser cross-origin request (Origin present, no console origin
    // configured) is likewise refused.
    let cross_origin = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/config/reload",
        &["Origin: https://evil.example", "Content-Type: text/plain"],
        "{}",
    );
    assert!(
        status_line(&cross_origin).contains("403"),
        "cross-origin admin mutation must be rejected: {cross_origin}"
    );

    // A non-browser client (no Sec-Fetch-Site, no Origin -- curl/SDK/CLI) is NOT
    // blocked by the CSRF guard; it passes through to the handler (which may
    // reject the payload for other reasons, but never with the CSRF code).
    let non_browser = http_request(&gateway_addr, "GET", "/admin/v1/overview", &[], "");
    assert!(
        !non_browser.contains("cross_site_admin_denied"),
        "a non-browser client must not trip the CSRF guard: {non_browser}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}
