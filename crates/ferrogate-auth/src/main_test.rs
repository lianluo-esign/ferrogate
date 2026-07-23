// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit coverage for the standalone ferrogate-auth Supabase connection config building (#386).

//! Proves the custom TLS CA path threads from the standalone `ferrogate-auth`
//! serve args into [`PostgresStorageConfig::tls_ca_cert_path`] (#386, twin of
//! #382): this binary previously hardcoded `None`, so `verify_ca`/`verify_full`
//! against Supabase's self-signed pooler chain could never complete the
//! handshake. These assertions exercise the pure config-building seam only; the
//! live Supabase handshake is verified by the harness/test agent.

use super::{build_supabase_storage_config, ServeArgs};

fn serve_args(tls_ca_cert_path: Option<&str>) -> ServeArgs {
    ServeArgs {
        listen: "127.0.0.1:8090".to_string(),
        data: None,
        supabase_dsn: Some("postgres://user:pass@db.example.supabase.co:6543/postgres".to_string()),
        supabase_tls_mode: "verify_full".to_string(),
        supabase_tls_ca_cert_path: tls_ca_cert_path.map(ToOwned::to_owned),
        supabase_schema: Some("auth".to_string()),
        supabase_search_path: Vec::new(),
        supabase_pool_size: 4,
        supabase_connect_timeout_secs: 10,
        supabase_statement_timeout_millis: 30_000,
        supabase_init_schema: false,
    }
}

#[test]
fn threads_ca_path_into_storage_config_when_provided() {
    let config =
        build_supabase_storage_config(&serve_args(Some("/etc/ferrogate/supabase-root-2021.pem")))
            .expect("config builds with a CA path");

    assert_eq!(
        config.tls_ca_cert_path.as_deref(),
        Some("/etc/ferrogate/supabase-root-2021.pem"),
        "the operator-supplied CA path must reach PostgresStorageConfig, not the old hardcoded None"
    );
}

#[test]
fn defaults_ca_path_to_none_when_absent() {
    let config =
        build_supabase_storage_config(&serve_args(None)).expect("config builds without a CA path");

    assert!(
        config.tls_ca_cert_path.is_none(),
        "absent CA path must stay None so the system trust store is used"
    );
}

#[test]
fn blank_ca_path_is_treated_as_absent() {
    // A blank flag/env value (e.g. `FERROGATE_AUTH_SUPABASE_TLS_CA_CERT_PATH=""`)
    // must be trimmed away rather than becoming a bogus zero-length path, matching
    // the gateway/migration threading in storage.rs and #382.
    for blank in ["", "   ", "\t\n"] {
        let config = build_supabase_storage_config(&serve_args(Some(blank)))
            .expect("config builds with a blank CA path");
        assert!(
            config.tls_ca_cert_path.is_none(),
            "blank CA path {blank:?} must be treated as absent"
        );
    }
}

#[test]
fn trims_surrounding_whitespace_from_ca_path() {
    let config = build_supabase_storage_config(&serve_args(Some("  /tmp/ca.pem \n")))
        .expect("config builds with a padded CA path");
    assert_eq!(
        config.tls_ca_cert_path.as_deref(),
        Some("/tmp/ca.pem"),
        "surrounding whitespace must be trimmed consistently with the mode/schema handling"
    );
}
