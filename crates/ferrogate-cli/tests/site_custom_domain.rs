// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: End-to-end coverage for static-site custom domains (#265) and
// the #488 DNS ownership gate in front of them. Publishes site bundles through
// a real gateway process, binds a custom hostname via the audited admin API,
// proves the bound-but-UNVERIFIED hostname does not serve, completes the DNS
// TXT challenge through the zone-file resolver backend, browses the site by
// `Host:` header through the same serve/visibility path as
// `/sites/{tenant}/{site}/...`, then unbinds and confirms the hostname stops
// resolving. Also proves the tenant-scoping (cross-tenant conflict/challenge
// isolation), the resolver-unavailable-is-not-verified posture, the validation
// rejects, and the bind/verify/unbind audit events.
//
// Opt-in: requires FERROGATE_SUPABASE_DSN, like `static_site_serve.rs`.
// The gateway child runs with FERROGATE_SITE_DOMAIN_RESOLVER=zone-file so the
// ownership challenge resolves deterministically from a local file instead of
// the public DNS -- the seam, not a bypass: the file must carry the EXACT
// expected value under the EXACT challenge name.
// TLS/ACME is intentionally NOT exercised here (a real issuance needs a
// publicly resolvable hostname); the ACME merge + reload marking is covered
// by unit tests in `src/acme.rs`.

mod support;

use support::{
    free_addr, http_request, http_request_bytes, http_request_with_host, start_gateway_with_env,
    wait_for_gateway,
};

#[test]
fn custom_domain_bind_serve_and_unbind_round_trip() {
    let Ok(dsn) = std::env::var("FERROGATE_SUPABASE_DSN") else {
        eprintln!(
            "skipping custom_domain_bind_serve_and_unbind_round_trip: \
             FERROGATE_SUPABASE_DSN is not set"
        );
        return;
    };

    let gateway_addr = free_addr();
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("ferrogate.toml");
    std::fs::write(&config_path, sites_config(&gateway_addr, &dsn)).unwrap();

    // The #488 challenge resolver reads this file on every lookup; it does not
    // exist yet, which is exactly the "resolver unavailable" case asserted
    // below before any record is published.
    let zone_file = dir.path().join("challenge-zone.txt");
    let mut gateway = start_gateway_with_env(
        &config_path,
        &[
            ("FERROGATE_SITE_DOMAIN_RESOLVER", "zone-file"),
            (
                "FERROGATE_SITE_DOMAIN_RESOLVER_ZONE_FILE",
                zone_file.to_str().unwrap(),
            ),
        ],
    );
    wait_for_gateway(&gateway_addr);

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

    // The shared control-plane schema persists across runs: clear any binding
    // a previous (failed) run may have left behind so the unbound-hostname
    // assertions below start from a clean slate.
    for hostname in [
        "mysite.example.com",
        "secret.example.com",
        "stolen.example.com",
    ] {
        let _ = http_request(
            &gateway_addr,
            "DELETE",
            &format!("/admin/v1/site-domains/{hostname}"),
            &["Authorization: Bearer admin-secret"],
            "",
        );
    }

    // Publish a PUBLIC site and a PRIVATE site (visibility split, #258).
    let public_zip = build_stored_zip(&[
        ("index.html", b"<h1>bound home</h1>"),
        ("style.css", b"body{color:teal}"),
    ]);
    let publish = String::from_utf8_lossy(&http_request_bytes(
        &gateway_addr,
        "PUT",
        "/v1/assets/static_site/marketing/1.0.0",
        &[
            "Authorization: Bearer asset-secret",
            "Content-Type: application/zip",
            "X-Site-Public: true",
        ],
        &public_zip,
    ))
    .into_owned();
    assert!(
        publish.contains("HTTP/1.1 200"),
        "public publish failed: {publish}"
    );
    let private_zip = build_stored_zip(&[("index.html", b"<h1>bound secret</h1>")]);
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

    // 1. An unbound hostname does not serve anything (falls through to
    //    dynamic routing, which has no routes here).
    let unbound = http_request_with_host(&gateway_addr, "mysite.example.com", "GET", "/", &[], "");
    assert!(
        unbound.contains("HTTP/1.1 404"),
        "unbound hostname must not serve a site: {unbound}"
    );

    // 2. Binding requires a published site.
    let missing_site = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"hostname":"mysite.example.com","tenant_id":"org_demo","site":"nope"}"#,
    );
    assert!(
        missing_site.contains("HTTP/1.1 404") && missing_site.contains("site_not_found"),
        "binding to an unpublished site must 404: {missing_site}"
    );

    // 3. Invalid hostnames are rejected.
    let invalid = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"hostname":"*.example.com","tenant_id":"org_demo","site":"marketing"}"#,
    );
    assert!(
        invalid.contains("HTTP/1.1 400") && invalid.contains("invalid_site_domain"),
        "wildcard hostname must be rejected: {invalid}"
    );

    // 4. Bind the public site (hostname is normalized lowercase). Under #488 a
    //    bind only ISSUES a challenge: 202, pending_verification, not serving.
    let bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"hostname":"MySite.Example.COM","tenant_id":"org_demo","site":"marketing"}"#,
    );
    assert!(
        bind.contains("HTTP/1.1 202"),
        "bind must be accepted-but-pending until DNS ownership is proven: {bind}"
    );
    assert!(
        bind.contains("\"hostname\":\"mysite.example.com\""),
        "bound hostname must be normalized: {bind}"
    );
    assert!(
        bind.contains("\"serve_path\":\"/sites/org_demo/marketing/\""),
        "bind response body: {bind}"
    );
    assert!(
        bind.contains("\"state\":\"pending_verification\"") && bind.contains("\"serving\":false"),
        "bind response must report the pending ownership state: {bind}"
    );
    assert!(
        bind.contains("\"challenge_record_name\":\"_ferrogate-challenge.mysite.example.com\""),
        "bind response must tell the operator which TXT record to publish: {bind}"
    );

    // 4b. #488 REGRESSION: a bound but UNVERIFIED hostname must not serve.
    let unverified =
        http_request_with_host(&gateway_addr, "mysite.example.com", "GET", "/", &[], "");
    assert!(
        unverified.contains("HTTP/1.1 404"),
        "a bound hostname with no DNS ownership proof must not serve: {unverified}"
    );

    // 4c. The resolver cannot answer yet (no zone file): 503, NOT a pass, and
    //     the hostname still does not serve. Unavailable is not verified.
    let unresolvable = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains/mysite.example.com/verify",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        unresolvable.contains("HTTP/1.1 503") && unresolvable.contains("dns_resolver_unavailable"),
        "an unreachable resolver must fail closed, not verify: {unresolvable}"
    );
    let still_unverified =
        http_request_with_host(&gateway_addr, "mysite.example.com", "GET", "/", &[], "");
    assert!(
        still_unverified.contains("HTTP/1.1 404"),
        "a failed verification attempt must not make the hostname servable: {still_unverified}"
    );

    // 4d. A challenge is keyed on (tenant, hostname): another tenant cannot
    //     redeem the one org_demo started, it does not even exist for them.
    let foreign_verify = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains/mysite.example.com/verify",
        &["Authorization: Bearer scoped-admin-secret"],
        "",
    );
    assert!(
        foreign_verify.contains("HTTP/1.1 404")
            && foreign_verify.contains("site_domain_challenge_not_found"),
        "tenant B must not be able to redeem tenant A's challenge: {foreign_verify}"
    );

    // 4e. Publish the challenge TXT record and complete verification.
    let challenge_value = json_string_field(&bind, "challenge_record_value")
        .unwrap_or_else(|| panic!("bind response must carry the challenge value: {bind}"));
    std::fs::write(
        &zone_file,
        format!("_ferrogate-challenge.mysite.example.com {challenge_value}\n"),
    )
    .unwrap();
    let verify = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains/mysite.example.com/verify",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        verify.contains("HTTP/1.1 200") && verify.contains("\"state\":\"verified\""),
        "publishing the exact challenge TXT must verify the domain: {verify}"
    );
    assert!(
        verify.contains("\"serving\":true"),
        "a verified domain must report as serving: {verify}"
    );

    // 5. The verified hostname serves the site's index by Host header alone.
    let index = http_request_with_host(&gateway_addr, "mysite.example.com", "GET", "/", &[], "");
    assert!(
        index.contains("HTTP/1.1 200"),
        "bound hostname index fetch failed: {index}"
    );
    assert!(
        index.to_lowercase().contains("content-type: text/html"),
        "index content-type: {index}"
    );
    assert!(index.contains("<h1>bound home</h1>"), "index body: {index}");
    // Host headers carrying a port resolve identically.
    let with_port = http_request_with_host(
        &gateway_addr,
        "mysite.example.com:8443",
        "GET",
        "/style.css",
        &[],
        "",
    );
    assert!(
        with_port.contains("HTTP/1.1 200")
            && with_port.to_lowercase().contains("content-type: text/css"),
        "host-with-port fetch failed: {with_port}"
    );

    // 6. The admin surface lists and fetches the binding.
    let list = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/site-domains?tenant=org_demo",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        list.contains("HTTP/1.1 200") && list.contains("mysite.example.com"),
        "site-domain list: {list}"
    );
    let get = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/site-domains/mysite.example.com",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        get.contains("HTTP/1.1 200") && get.contains("\"site\":\"marketing\""),
        "site-domain get: {get}"
    );
    assert!(
        get.contains("\"verification_state\":\"verified\"") && get.contains("\"serving\":true"),
        "the ownership state must be visible on the single-domain read: {get}"
    );

    // 7. Visibility still honors the site's public/private setting: bind the
    //    PRIVATE site to another hostname and confirm it fails closed.
    let bind_private = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[
            "Authorization: Bearer admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"hostname":"secret.example.com","tenant_id":"org_demo","site":"internal"}"#,
    );
    assert!(
        bind_private.contains("HTTP/1.1 202"),
        "private bind failed: {bind_private}"
    );
    let private_challenge = json_string_field(&bind_private, "challenge_record_value")
        .unwrap_or_else(|| panic!("private bind must carry a challenge: {bind_private}"));
    std::fs::write(
        &zone_file,
        format!(
            "_ferrogate-challenge.mysite.example.com {challenge_value}\n\
             _ferrogate-challenge.secret.example.com {private_challenge}\n"
        ),
    )
    .unwrap();
    let verify_private = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains/secret.example.com/verify",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        verify_private.contains("HTTP/1.1 200")
            && verify_private.contains("\"state\":\"verified\""),
        "private domain verification failed: {verify_private}"
    );
    let anon_private =
        http_request_with_host(&gateway_addr, "secret.example.com", "GET", "/", &[], "");
    assert!(
        anon_private.contains("HTTP/1.1 401"),
        "anonymous fetch of a private site via custom domain must fail closed: {anon_private}"
    );
    let auth_private = http_request_with_host(
        &gateway_addr,
        "secret.example.com",
        "GET",
        "/",
        &["Authorization: Bearer asset-secret"],
        "",
    );
    assert!(
        auth_private.contains("HTTP/1.1 200") && auth_private.contains("<h1>bound secret</h1>"),
        "authenticated fetch of a private site via custom domain should succeed: {auth_private}"
    );
    let cross_tenant = http_request_with_host(
        &gateway_addr,
        "secret.example.com",
        "GET",
        "/",
        &["Authorization: Bearer other-secret"],
        "",
    );
    assert!(
        cross_tenant.contains("HTTP/1.1 404"),
        "cross-tenant key must see 404 via custom domain (fail closed): {cross_tenant}"
    );

    // 8. A tenant-scoped admin key cannot bind for another tenant.
    let foreign_bind = http_request(
        &gateway_addr,
        "POST",
        "/admin/v1/site-domains",
        &[
            "Authorization: Bearer scoped-admin-secret",
            "Content-Type: application/json",
        ],
        r#"{"hostname":"stolen.example.com","tenant_id":"org_demo","site":"marketing"}"#,
    );
    assert!(
        foreign_bind.contains("HTTP/1.1 403"),
        "cross-tenant bind must be denied: {foreign_bind}"
    );

    // 9. Unbind, audited, and the hostname stops serving.
    let unbind = http_request(
        &gateway_addr,
        "DELETE",
        "/admin/v1/site-domains/mysite.example.com",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        unbind.contains("HTTP/1.1 200") && unbind.contains("\"deleted\":true"),
        "unbind failed: {unbind}"
    );
    let after_unbind =
        http_request_with_host(&gateway_addr, "mysite.example.com", "GET", "/", &[], "");
    assert!(
        after_unbind.contains("HTTP/1.1 404"),
        "an unbound hostname must stop serving the site: {after_unbind}"
    );
    // The path-based route still serves the site after unbinding.
    let by_path = http_request(&gateway_addr, "GET", "/sites/org_demo/marketing/", &[], "");
    assert!(
        by_path.contains("HTTP/1.1 200"),
        "path-based serving must survive an unbind: {by_path}"
    );

    // 10. Bind + unbind are explicit audited admin actions.
    let audit = http_request(
        &gateway_addr,
        "GET",
        "/admin/v1/audit-events",
        &["Authorization: Bearer admin-secret"],
        "",
    );
    assert!(
        audit.contains("site_domain.bind"),
        "expected a site_domain.bind audit event: {audit}"
    );
    assert!(
        audit.contains("site_domain.unbind"),
        "expected a site_domain.unbind audit event: {audit}"
    );
    assert!(
        audit.contains("site_domain.verify"),
        "expected a site_domain.verify audit event: {audit}"
    );

    gateway.kill().unwrap();
    gateway.wait().unwrap();
}

/// Extracts `"<field>":"<value>"` from a raw HTTP response body. Enough for
/// the flat admin JSON these assertions read, without a JSON dependency here.
fn json_string_field(response: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = response.find(&needle)? + needle.len();
    let rest = &response[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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
platform_operator = true

[[api_keys]]
id = "scoped-admin"
name = "Scoped admin (other tenant)"
key = "scoped-admin-secret"
scopes = ["admin.read", "admin.write"]
organization_id = "org_other"

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
