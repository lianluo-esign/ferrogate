// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: End-to-end coverage for the static-site serve mode + site
// bundles + HTTP caching (issue #258). Pushes a zip static_site through a real
// gateway process, then browses it via `GET /sites/{tenant}/{site}/...`,
// asserting index resolution, per-file Content-Type, conditional 304 and
// Range 206, the public/private visibility split (fail closed), and the
// publish audit event.
//
// Opt-in: requires FERROGATE_SUPABASE_DSN, like `assets_api.rs`.

mod support;

use support::{free_addr, http_request, http_request_bytes, start_gateway, wait_for_gateway};

#[test]
fn static_site_bundle_publish_serve_and_cache_round_trip() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping static_site_bundle_publish_serve_and_cache_round_trip: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, sites_config(&gateway_addr, &dsn)).unwrap();

    let mut gateway = start_gateway(&config_path);
    wait_for_gateway(&gateway_addr);

    // Tenant on the seeded free plan (asset_hosting_enabled = true).
    let register = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/tenant-accounts",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"id":"org_demo","name":"Org Demo","slug":"org-demo"}"#,
    );
    assert!(
        register.contains("HTTP/1.1 200") || register.contains("HTTP/1.1 201"),
        "tenant registration failed: {register}"
    );

    let index_html = b"<!doctype html><html><body><h1>Home</h1></body></html>".to_vec();
    let style_css = b"body { color: rebeccapurple; }".to_vec();
    let readme_md = b"# Docs\n\nHello from the bundle.".to_vec();
    let zip = build_stored_zip(&[
        ("index.html", &index_html),
        ("style.css", &style_css),
        ("docs/readme.md", &readme_md),
    ]);

    // 1. Publish a PUBLIC site bundle (explicit opt-in via X-Site-Public).
    let publish = String::from_utf8_lossy(&http_request_bytes(
        &gateway_addr,
        "PUT",
        "/v1/assets/static_site/marketing/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/zip",
            "X-Site-Public: true",
        ],
        &zip,
    ))
    .into_owned();
    assert!(
        publish.contains("HTTP/1.1 200"),
        "publish failed: {publish}"
    );
    assert!(
        publish.contains("\"file_count\":3"),
        "publish body: {publish}"
    );
    assert!(
        publish.contains("\"public\":true"),
        "publish body: {publish}"
    );

    // 2. Browse the index anonymously (public site) -> text/html.
    let index = http_request(&gateway_addr, "GET", "/sites/org_demo/marketing/", &[], "");
    assert!(
        index.contains("HTTP/1.1 200"),
        "index fetch failed: {index}"
    );
    assert!(
        index.to_lowercase().contains("content-type: text/html"),
        "index content-type: {index}"
    );
    assert!(index.contains("<h1>Home</h1>"), "index body: {index}");
    let etag = extract_header(&index, "etag").expect("index response must carry an ETag");

    // 3. style.css -> text/css.
    let css = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/marketing/style.css",
        &[],
        "",
    );
    assert!(css.contains("HTTP/1.1 200"), "css fetch failed: {css}");
    assert!(
        css.to_lowercase().contains("content-type: text/css"),
        "css content-type: {css}"
    );

    // 4. Nested path -> text/markdown.
    let md = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/marketing/docs/readme.md",
        &[],
        "",
    );
    assert!(md.contains("HTTP/1.1 200"), "markdown fetch failed: {md}");
    assert!(
        md.to_lowercase().contains("content-type: text/markdown"),
        "markdown content-type: {md}"
    );

    // 5. Conditional GET with the matching ETag -> 304 Not Modified.
    let not_modified = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/marketing/",
        &[&format!("If-None-Match: {etag}")],
        "",
    );
    assert!(
        not_modified.contains("HTTP/1.1 304"),
        "expected 304 for matching If-None-Match: {not_modified}"
    );

    // 6. Range request -> 206 Partial Content + Content-Range.
    let partial = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/marketing/",
        &["Range: bytes=0-9"],
        "",
    );
    assert!(
        partial.contains("HTTP/1.1 206"),
        "expected 206 for Range request: {partial}"
    );
    assert!(
        partial
            .to_lowercase()
            .contains(&format!("content-range: bytes 0-9/{}", index_html.len())),
        "expected Content-Range header: {partial}"
    );

    // 7. Publish a PRIVATE site (no X-Site-Public) and confirm it fails closed.
    let private_zip = build_stored_zip(&[("index.html", b"<h1>secret</h1>")]);
    let publish_private = String::from_utf8_lossy(&http_request_bytes(
        &gateway_addr,
        "PUT",
        "/v1/assets/static_site/internal/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/zip",
        ],
        &private_zip,
    ))
    .into_owned();
    assert!(
        publish_private.contains("HTTP/1.1 200"),
        "private publish failed: {publish_private}"
    );

    let anon_private = http_request(&gateway_addr, "GET", "/sites/org_demo/internal/", &[], "");
    assert!(
        anon_private.contains("HTTP/1.1 401"),
        "anonymous fetch of a private site must fail closed: {anon_private}"
    );

    let auth_private = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/internal/",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        auth_private.contains("HTTP/1.1 200"),
        "authenticated fetch of a private site should succeed: {auth_private}"
    );
    assert!(
        auth_private.contains("<h1>secret</h1>"),
        "private body: {auth_private}"
    );

    // 8. A key from a different tenant sees 404, not confirmation the site exists.
    let cross_tenant = http_request(
        &gateway_addr,
        "GET",
        "/sites/org_demo/internal/",
        &["Authorization: Bearer other-secret"],
        "",
    );
    assert!(
        cross_tenant.contains("HTTP/1.1 404"),
        "cross-tenant fetch must 404 (fail closed): {cross_tenant}"
    );

    // 9. Publishing (and enabling public mode) emits an audit event.
    let audit = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        audit.contains("site.publish"),
        "expected a site.publish audit event: {audit}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Extracts a response header value (case-insensitive name) from a raw HTTP
/// response string.
fn extract_header(response: &str, name: &str) -> Option<String> {
    let headers = response.split("\r\n\r\n").next()?;
    for line in headers.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Builds a minimal ZIP archive with stored (uncompressed) entries -- enough
/// for the gateway's zip reader without pulling in a zip dependency here.
fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for (name, data) in entries {
        let offset = out.len() as u32;
        let name_bytes = name.as_bytes();

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes()); // crc32
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn sites_config(gateway_addr: &str, dsn: &str) -> String {
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
id = "asset-client"
name = "Asset client"
key = "asset-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_demo"

[[api_keys]]
id = "other-client"
name = "Other tenant client"
key = "other-secret"
scopes = ["assets.read", "assets.write"]
organization_id = "org_other"
"#
    )
}
