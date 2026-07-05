// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use clap::{Args, Parser, Subcommand};
use ferrogate_auth::{ApiKeyAuthenticator, AuthServiceConfig, AuthServiceData};
use ferrogate_storage::{
    ControlPlaneDocuments, PostgresStorageConfig, PostgresTlsMode, RuntimeStorageOptions,
    RuntimeStorageRepositories, StorageProviderKind,
};
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Parser)]
#[command(name = "ferrogate-auth")]
#[command(about = "FerroGate tenant and RBAC REST API service")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the tenant and RBAC REST API service.
    Serve(ServeArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Address for the auth REST API service.
    #[arg(long, env = "FERROGATE_AUTH_LISTEN", default_value = "127.0.0.1:8090")]
    listen: String,
    /// Optional YAML data file with tenants, API keys, roles, and bindings.
    #[arg(long, env = "FERROGATE_AUTH_DATA")]
    data: Option<PathBuf>,
    /// Supabase PostgreSQL DSN for durable virtual API key resolution.
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_DSN")]
    supabase_dsn: Option<String>,
    /// Supabase/PostgreSQL TLS mode for durable virtual API key resolution.
    #[arg(
        long,
        env = "FERROGATE_AUTH_SUPABASE_TLS_MODE",
        default_value = "require"
    )]
    supabase_tls_mode: String,
    /// PostgreSQL schema holding the auth service's own tenant/RBAC tables.
    /// Dedicated by default so this service never shares a namespace with the
    /// gateway's own `ferrogate_control` schema or the billing service's
    /// schema in the same Supabase project (issue #156).
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_SCHEMA", default_value = "auth")]
    supabase_schema: Option<String>,
    /// Optional comma-separated PostgreSQL search path for Supabase.
    #[arg(
        long,
        env = "FERROGATE_AUTH_SUPABASE_SEARCH_PATH",
        value_delimiter = ','
    )]
    supabase_search_path: Vec<String>,
    /// Number of PostgreSQL connections used by the auth service.
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_POOL_SIZE", default_value_t = 4)]
    supabase_pool_size: usize,
    /// Supabase connect timeout in seconds.
    #[arg(
        long,
        env = "FERROGATE_AUTH_SUPABASE_CONNECT_TIMEOUT_SECS",
        default_value_t = 10
    )]
    supabase_connect_timeout_secs: u64,
    /// Supabase statement timeout in milliseconds.
    #[arg(
        long,
        env = "FERROGATE_AUTH_SUPABASE_STATEMENT_TIMEOUT_MILLIS",
        default_value_t = 30_000
    )]
    supabase_statement_timeout_millis: u64,
    /// Initialize missing Supabase schema objects before serving.
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_INIT_SCHEMA")]
    supabase_init_schema: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve(args) => {
            let data = match &args.data {
                Some(path) => AuthServiceData::load_yaml(path)?,
                None => AuthServiceData::default(),
            };
            let api_key_authenticator = supabase_api_key_authenticator(&args)?;
            // The admin console (register/login/session, issue #157) is only
            // wired up through `ferrogate auth serve` (see ferrogate-cli's
            // AuthServeArgs) -- this standalone binary is a secondary
            // entrypoint that predates the console and stays scoped to the
            // original virtual-key-resolution feature.
            ferrogate_auth::serve(AuthServiceConfig {
                listen: args.listen,
                data,
                api_key_authenticator,
                admin_console: None,
                cors_allowed_origin: None,
            })
        }
    }
}

fn supabase_api_key_authenticator(
    args: &ServeArgs,
) -> anyhow::Result<Option<Arc<dyn ApiKeyAuthenticator>>> {
    let Some(dsn) = args.supabase_dsn.as_deref() else {
        return Ok(None);
    };
    let dsn = dsn.trim();
    if dsn.is_empty() {
        return Ok(None);
    }

    let repositories = RuntimeStorageRepositories::supabase(
        PostgresStorageConfig {
            dsn: dsn.to_string(),
            pool_size: args.supabase_pool_size,
            tls_mode: parse_postgres_tls_mode(&args.supabase_tls_mode)?,
            tls_ca_cert_path: None,
            connect_timeout_secs: args.supabase_connect_timeout_secs,
            statement_timeout_millis: args.supabase_statement_timeout_millis,
            schema: args
                .supabase_schema
                .as_deref()
                .map(str::trim)
                .filter(|schema| !schema.is_empty())
                .map(ToOwned::to_owned),
            search_path: args
                .supabase_search_path
                .iter()
                .map(|item| item.trim())
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        },
        RuntimeStorageOptions {
            provider_order: vec![StorageProviderKind::Supabase],
            required: true,
            initialize_schema: args.supabase_init_schema,
            migration_mode: if args.supabase_init_schema {
                "auto".into()
            } else {
                "validate_only".into()
            },
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records: 0,
            audit_event_retention_records: 0,
        },
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;

    Ok(Some(Arc::new(
        ferrogate_auth::StorageApiKeyAuthenticator::new(Arc::new(repositories)),
    )))
}

fn parse_postgres_tls_mode(value: &str) -> anyhow::Result<PostgresTlsMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "disable" => Ok(PostgresTlsMode::Disable),
        "prefer" => Ok(PostgresTlsMode::Prefer),
        "require" => Ok(PostgresTlsMode::Require),
        "verify_ca" | "verify-ca" => Ok(PostgresTlsMode::VerifyCa),
        "verify_full" | "verify-full" => Ok(PostgresTlsMode::VerifyFull),
        other => Err(anyhow::anyhow!(
            "unsupported FERROGATE_AUTH_SUPABASE_TLS_MODE {other:?}; expected disable, prefer, require, verify_ca, or verify_full"
        )),
    }
}
