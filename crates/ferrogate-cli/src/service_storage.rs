// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Shared Supabase repository construction for the side-service subcommands.
//!
//! Both `ferrogate auth serve` and `ferrogate billing serve` need to open a
//! durable Supabase/Postgres connection (for hashed virtual-key resolution and
//! for the billing ledger respectively). This module centralizes that wiring so
//! the two subcommands share identical DSN/TLS/schema handling.

use anyhow::Context;

use ferrogate_storage::{
    ControlPlaneDocuments, PostgresStorageConfig, PostgresTlsMode, RuntimeStorageOptions,
    RuntimeStorageRepositories, StorageProviderKind,
};

/// Options describing how a side service should connect to Supabase.
pub(crate) struct SupabaseConnection<'a> {
    pub(crate) dsn: &'a str,
    pub(crate) tls_mode: &'a str,
    pub(crate) schema: Option<&'a str>,
    pub(crate) init_schema: bool,
}

/// Build a durable, Supabase-backed [`RuntimeStorageRepositories`] for a side
/// service. Fails closed: the connection is `required` so a broken DSN aborts
/// startup rather than silently degrading to in-memory storage.
pub(crate) fn build_supabase_repositories(
    connection: SupabaseConnection<'_>,
) -> anyhow::Result<RuntimeStorageRepositories> {
    let dsn = connection.dsn.trim();
    if dsn.is_empty() {
        anyhow::bail!("supabase DSN must not be empty");
    }
    RuntimeStorageRepositories::supabase(
        PostgresStorageConfig {
            dsn: dsn.to_string(),
            pool_size: 4,
            tls_mode: parse_postgres_tls_mode(connection.tls_mode)?,
            tls_ca_cert_path: None,
            connect_timeout_secs: 10,
            statement_timeout_millis: 30_000,
            schema: connection
                .schema
                .map(str::trim)
                .filter(|schema| !schema.is_empty())
                .map(ToOwned::to_owned),
            search_path: Vec::new(),
        },
        RuntimeStorageOptions {
            provider_order: vec![StorageProviderKind::Supabase],
            required: true,
            initialize_schema: connection.init_schema,
            migration_mode: if connection.init_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records: 0,
            audit_event_retention_records: 0,
        },
    )
    .map_err(|error| anyhow::anyhow!("failed to open Supabase storage: {error}"))
    .context("supabase side-service storage")
}

fn parse_postgres_tls_mode(value: &str) -> anyhow::Result<PostgresTlsMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disable" => Ok(PostgresTlsMode::Disable),
        "prefer" => Ok(PostgresTlsMode::Prefer),
        "require" => Ok(PostgresTlsMode::Require),
        "verify_ca" | "verify-ca" => Ok(PostgresTlsMode::VerifyCa),
        "verify_full" | "verify-full" => Ok(PostgresTlsMode::VerifyFull),
        other => Err(anyhow::anyhow!(
            "unsupported supabase TLS mode {other:?}; expected disable, prefer, require, verify_ca, or verify_full"
        )),
    }
}
