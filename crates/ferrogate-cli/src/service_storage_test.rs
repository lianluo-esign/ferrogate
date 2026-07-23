// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit coverage for side-service Supabase connection config building (#382).

//! Proves the custom TLS CA path threads from the auth/billing serve args
//! (via [`SupabaseConnection`]) into [`PostgresStorageConfig::tls_ca_cert_path`]
//! (#382): auth + billing previously hardcoded `None`, so `verify_ca`/
//! `verify_full` against Supabase's self-signed pooler chain could never
//! complete the handshake. These assertions exercise the pure config-building
//! seam only; the live Supabase handshake is verified by the harness/test agent.

use super::{build_supabase_storage_config, SupabaseConnection};

fn connection(tls_ca_cert_path: Option<&'static str>) -> SupabaseConnection<'static> {
    SupabaseConnection {
        dsn: "postgres://user:pass@db.example.supabase.co:6543/postgres",
        tls_mode: "verify_full",
        tls_ca_cert_path,
        schema: Some("billing"),
        init_schema: false,
    }
}

#[test]
fn threads_ca_path_into_storage_config_when_provided() {
    let config =
        build_supabase_storage_config(&connection(Some("/etc/ferrogate/supabase-root-2021.pem")))
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
        build_supabase_storage_config(&connection(None)).expect("config builds without a CA path");

    assert!(
        config.tls_ca_cert_path.is_none(),
        "absent CA path must stay None so the system trust store is used"
    );
}

#[test]
fn blank_ca_path_is_treated_as_absent() {
    // A blank flag/env value (e.g. `FERROGATE_BILLING_SUPABASE_TLS_CA_CERT_PATH=""`)
    // must be trimmed away rather than becoming a bogus zero-length path, matching
    // the gateway/migration threading in storage.rs.
    for blank in ["", "   ", "\t\n"] {
        let config = build_supabase_storage_config(&connection(Some(blank)))
            .expect("config builds with a blank CA path");
        assert!(
            config.tls_ca_cert_path.is_none(),
            "blank CA path {blank:?} must be treated as absent"
        );
    }
}

#[test]
fn trims_surrounding_whitespace_from_ca_path() {
    let config = build_supabase_storage_config(&connection(Some("  /tmp/ca.pem \n")))
        .expect("config builds with a padded CA path");
    assert_eq!(
        config.tls_ca_cert_path.as_deref(),
        Some("/tmp/ca.pem"),
        "surrounding whitespace must be trimmed consistently with the mode/schema handling"
    );
}
