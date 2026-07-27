// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Regression guards that a Vault token never reaches a rendered Debug string.

//! Issue #492: `VaultConfig` holds a **live Vault token**, and the
//! [`crate::SecretResolver`] trait requires `Debug`, so the type is reachable
//! from `{:?}` on the resolver and on the whole registry. These tests pin the
//! hand-written impl that keeps the token out of every one of those renderings.
//!
//! Both were verified to fail against the previous `#[derive(Debug)]` before
//! the fix landed — a redaction test nobody has watched fail is not a guard
//! (the lesson from #489, where a `Vec<u8>` field made a plaintext-only
//! assertion vacuous). `token` here is a `String`, so plaintext matching does
//! bite; the assertions below also pin the positive shape so a future impl
//! that simply drops the field is not silently accepted as "redacted".

use std::time::Duration;

use crate::{VaultConfig, VaultSecretResolver};

/// Shaped like a real Vault service token (`hvs.` prefix since Vault 1.10).
const VAULT_TOKEN: &str = "hvs.CAESIJsuper-secret-live-vault-token";

fn config() -> VaultConfig {
    VaultConfig {
        address: "https://vault.internal:8200".into(),
        token: VAULT_TOKEN.into(),
        ca_cert_path: Some("/etc/ferrogate/vault-ca.pem".into()),
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn vault_config_debug_redacts_the_token_and_keeps_the_rest() {
    let rendered = format!("{:?}", config());

    assert!(
        !rendered.contains(VAULT_TOKEN),
        "Vault token leaked into VaultConfig Debug: {rendered}"
    );
    // A partial leak is still a leak: the token body must not appear even
    // without its `hvs.` prefix.
    assert!(
        !rendered.contains("super-secret-live-vault-token"),
        "Vault token body leaked into VaultConfig Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");

    // The non-secret fields still have to be there, or the impl has traded a
    // leak for an undiagnosable config.
    assert!(rendered.contains("VaultConfig"), "{rendered}");
    assert!(
        rendered.contains("https://vault.internal:8200"),
        "{rendered}"
    );
    assert!(rendered.contains("vault-ca.pem"), "{rendered}");
}

/// The path that actually shows up in logs: `SecretResolver` requires `Debug`,
/// `VaultSecretResolver` derives it over the config, and
/// `SecretResolverRegistry` derives it over the resolver — so a single
/// `{:?}` three levels up used to print the token.
#[test]
fn vault_resolver_debug_redacts_the_nested_token() {
    let rendered = format!("{:?}", VaultSecretResolver::new(config()));

    assert!(
        !rendered.contains(VAULT_TOKEN),
        "Vault token leaked through VaultSecretResolver Debug: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert_no_token_prefix(&rendered, "VaultSecretResolver");
}

/// A partial leak is a leak: 16 characters of a live `hvs.` service token is a
/// disclosure, and the two full-secret assertions above do not see it.
/// `.field("token_prefix", &&self.token[..16])` on `VaultConfig::fmt` renders
/// `hvs.CAESIJsuper-` — which contains neither `VAULT_TOKEN` nor the
/// `super-secret-live-vault-token` body substring, and leaves `<redacted>` in
/// place — so without this guard both tests above stay green while the token
/// prints.
fn assert_no_token_prefix(rendered: &str, what: &str) {
    for prefix_len in [4usize, 8, 16] {
        let prefix = &VAULT_TOKEN[..prefix_len];
        assert!(
            !rendered.contains(prefix),
            "a {prefix_len}-char Vault token prefix leaked into {what} Debug: {rendered}"
        );
    }
}

#[test]
fn vault_config_debug_prints_no_prefix_of_the_token() {
    assert_no_token_prefix(&format!("{:?}", config()), "VaultConfig");
}
