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
