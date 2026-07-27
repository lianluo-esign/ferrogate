// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-20
// description: Unit tests for the custom-domain binding pure logic (#265) --
// hostname normalization/validation -- kept out of the async gateway handler
// so they run without a live database.

use super::*;

#[test]
fn valid_hostnames_normalize_to_lowercase_without_port() {
    assert_eq!(
        validate_site_domain_hostname(Some("MySite.Example.COM")).unwrap(),
        "mysite.example.com"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("mysite.example.com:8443")).unwrap(),
        "mysite.example.com"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("  docs.internal.example  ")).unwrap(),
        "docs.internal.example"
    );
    assert_eq!(
        validate_site_domain_hostname(Some("a-1.b-2.example.io")).unwrap(),
        "a-1.b-2.example.io"
    );
}

#[test]
fn missing_or_empty_hostname_is_rejected() {
    assert!(validate_site_domain_hostname(None).is_err());
    assert!(validate_site_domain_hostname(Some("")).is_err());
    assert!(validate_site_domain_hostname(Some("   ")).is_err());
}

#[test]
fn single_label_hostnames_are_rejected() {
    let error = validate_site_domain_hostname(Some("localhost")).unwrap_err();
    assert!(error.contains("fully qualified"), "{error}");
    assert!(validate_site_domain_hostname(Some("intranet")).is_err());
}

#[test]
fn wildcards_and_ip_literals_are_rejected() {
    assert!(validate_site_domain_hostname(Some("*.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("192.168.1.10")).is_err());
    assert!(validate_site_domain_hostname(Some("[::1]:443")).is_err());
}

#[test]
fn malformed_dns_labels_are_rejected() {
    // Empty label (double dot / leading dot / trailing dot).
    assert!(validate_site_domain_hostname(Some("a..example.com")).is_err());
    assert!(validate_site_domain_hostname(Some(".example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("example.com.")).is_err());
    // Hyphen at a label edge.
    assert!(validate_site_domain_hostname(Some("-bad.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("bad-.example.com")).is_err());
    // Disallowed characters.
    assert!(validate_site_domain_hostname(Some("under_score.example.com")).is_err());
    assert!(validate_site_domain_hostname(Some("spa ce.example.com")).is_err());
    // Oversized label / hostname.
    let long_label = format!("{}.example.com", "a".repeat(64));
    assert!(validate_site_domain_hostname(Some(&long_label)).is_err());
    let long_hostname = format!("{}.example.com", "a.".repeat(130));
    assert!(validate_site_domain_hostname(Some(&long_hostname)).is_err());
}

/// #530: the handler answers 200/201/**202**, but the OpenAPI document declared
/// only 200/201. This couples the two so they cannot drift apart again: the
/// statuses the handler can actually produce, enumerated over every input, must
/// all be declared for `bindSiteDomain`.
///
/// The assertion is on the produced status set, not on the source text — adding
/// a fourth terminal to `site_domain_bind_status` without declaring it reds
/// this, and deleting the `202` declaration from the spec reds it too.
#[test]
fn every_bind_terminal_is_declared_in_the_openapi_document() {
    const SPEC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/admin-api.openapi.json"
    ));

    let produced: std::collections::BTreeSet<u16> = [true, false]
        .into_iter()
        .flat_map(|proven| {
            [true, false]
                .into_iter()
                .map(move |existing| site_domain_bind_status(proven, existing).status().as_u16())
        })
        .collect();
    // The three-way terminal the issue names. If this changes, the spec below
    // must change with it -- that coupling is the whole point of the test.
    assert_eq!(
        produced,
        [200u16, 201, 202].into_iter().collect(),
        "bind terminals changed"
    );

    let spec: serde_json::Value =
        serde_json::from_str(SPEC).expect("admin-api.openapi.json parses");
    let declared = spec["paths"]["/admin/v1/site-domains"]["post"]["responses"]
        .as_object()
        .expect("bindSiteDomain declares responses");
    for status in &produced {
        assert!(
            declared.contains_key(&status.to_string()),
            "handler can return {status} but bindSiteDomain does not declare it; \
             declared = {:?}",
            declared.keys().collect::<Vec<_>>()
        );
    }

    // Direction (b), added on review: a declared SUCCESS status the runtime can
    // never produce is drift too, and the first cut asserted only direction (a)
    // -- adding `"203": {...}` to the spec left it green. Only 2xx is compared,
    // because the error terminals come from shared `#/components/responses`
    // refs raised by helpers (`storage_error` -> 503, the validation arms ->
    // 400/404/409/413) rather than from `site_domain_bind_status`, so they are
    // not derivable here; item 2 of this review declares them explicitly
    // instead.
    let declared_success: std::collections::BTreeSet<u16> = declared
        .keys()
        .filter_map(|code| code.parse::<u16>().ok())
        .filter(|code| (200..300).contains(code))
        .collect();
    assert_eq!(
        declared_success, produced,
        "bindSiteDomain's declared 2xx set must equal what site_domain_bind_status \
         can produce -- a declared-but-unreachable success code is drift in the \
         other direction"
    );
}

/// Sibling audit: `verifySiteDomain` answers `400 invalid_site_domain` when
/// the `tenant_id` query parameter is absent (`site_domains.rs`, the `None =>`
/// arm of the tenant resolution), which the document did not declare.
///
/// NAMED FOR WHAT IT ACTUALLY PINS (#530 review): this asserts the
/// DECLARATION only. It derives nothing from the verify handler, so deleting
/// that `None =>` arm leaves it green and the runtime side of the gap can
/// reopen. The earlier name claimed it stopped exactly that. Closing the
/// runtime half needs the same newtype treatment the bind terminal got, or a
/// derivation from the runtime contract; neither is done here.
#[test]
fn verify_declares_a_400_for_the_missing_tenant_arm() {
    const SPEC: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/openapi/admin-api.openapi.json"
    ));
    let spec: serde_json::Value =
        serde_json::from_str(SPEC).expect("admin-api.openapi.json parses");
    let declared = spec["paths"]["/admin/v1/site-domains/{hostname}/verify"]["post"]["responses"]
        .as_object()
        .expect("verifySiteDomain declares responses");
    assert!(
        declared.contains_key("400"),
        "verifySiteDomain returns 400 when tenant_id is missing; declared = {:?}",
        declared.keys().collect::<Vec<_>>()
    );
}
