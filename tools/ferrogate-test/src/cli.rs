// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ferrogate-test")]
#[command(author = "jamesduan <https://x.com/JamesDuanL>")]
#[command(version)]
#[command(about = "FerroGate end-to-end test harness for admin, auth, and gateway APIs")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// List available local and Docker-backed scenarios.
    List,
    /// Run one Docker-backed cluster/container scenario.
    Run(DockerRunArgs),
    /// Run the full local API harness and optionally the Docker scenario set.
    RunAll(RunAllArgs),
    /// Run Admin API coverage against a real local FerroGate process.
    AdminApi(LocalArgs),
    /// Run auth service coverage against a real local ferrogate-auth process.
    AuthApi(AuthArgs),
    /// Run gateway API coverage against a real local FerroGate process.
    GatewayApi(LocalArgs),
    /// Run local Supabase-compatible Postgres restart durability coverage.
    SupabaseRestart(LocalArgs),
    /// Opt-in live Supabase connection, migration, status, and minimal persistence smoke.
    SupabaseLiveSmoke(SupabaseLiveRestartArgs),
    /// Opt-in live Supabase restart durability scenario.
    SupabaseLiveRestart(SupabaseLiveRestartArgs),
    /// Opt-in live Supabase and Token4AI OpenAI-compatible provider billing scenario.
    SupabaseLiveToken4aiProvider(SupabaseLiveToken4aiProviderArgs),
    /// Run local PostgreSQL-to-Supabase-compatible migration tooling coverage.
    SupabaseMigration(LocalArgs),
    /// Run local Docker-backed PostgreSQL restart durability coverage.
    PostgresRestart(LocalArgs),
    /// Run local Docker-backed PostgreSQL TLS restart durability coverage.
    PostgresTlsRestart(LocalArgs),
    /// Run local Docker-backed MySQL restart durability coverage.
    MysqlRestart(LocalArgs),
    /// Run local Docker-backed MySQL TLS restart durability coverage.
    MysqlTlsRestart(LocalArgs),
    /// CI entrypoint: run deterministic local Admin API, auth API, and gateway API E2E coverage.
    Ci(CiArgs),
}

#[derive(Debug, Args)]
pub(crate) struct DockerRunArgs {
    #[arg(value_enum)]
    pub(crate) scenario: DockerScenario,
    /// Docker image to verify. Defaults to a local build tag, but may point at a GHCR image.
    #[arg(long, env = "FERROGATE_TEST_IMAGE", default_value = IMAGE_TAG)]
    pub(crate) image: String,
}

#[derive(Debug, Args)]
pub(crate) struct RunAllArgs {
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    #[command(flatten)]
    pub(crate) auth: AuthArgs,
    /// Also run Docker-backed cluster, shared-state, and Redis scenarios.
    #[arg(long)]
    pub(crate) include_docker: bool,
    /// Docker image to verify. Defaults to a local build tag, but may point at a GHCR image.
    #[arg(long, env = "FERROGATE_TEST_IMAGE", default_value = IMAGE_TAG)]
    pub(crate) image: String,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct LocalArgs {
    /// Path to a built ferrogate binary. Defaults to target/debug/ferrogate.
    #[arg(
        long,
        env = "FERROGATE_TEST_FERROGATE_BIN",
        default_value = "target/debug/ferrogate"
    )]
    pub(crate) ferrogate_bin: PathBuf,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct AuthArgs {
    /// Path to a built ferrogate-auth binary. Defaults to target/debug/ferrogate-auth.
    #[arg(
        long,
        env = "FERROGATE_TEST_FERROGATE_AUTH_BIN",
        default_value = "target/debug/ferrogate-auth"
    )]
    pub(crate) ferrogate_auth_bin: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct CiArgs {
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    #[command(flatten)]
    pub(crate) auth: AuthArgs,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct SupabaseLiveRestartArgs {
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    /// Supabase direct or session-pooler Postgres DSN. Prefer FERROGATE_SUPABASE_DSN in shell/CI.
    #[arg(long, env = "FERROGATE_SUPABASE_DSN")]
    pub(crate) supabase_dsn: String,
    /// PostgreSQL TLS mode for the live Supabase connection.
    #[arg(
        long,
        env = "FERROGATE_SUPABASE_TLS_MODE",
        default_value = "verify_full"
    )]
    pub(crate) tls_mode: String,
    /// Optional root CA path for private CA deployments.
    #[arg(long, env = "FERROGATE_SUPABASE_TLS_CA_CERT_PATH")]
    pub(crate) tls_ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct SupabaseLiveToken4aiProviderArgs {
    #[command(flatten)]
    pub(crate) supabase: SupabaseLiveRestartArgs,
    /// OpenAI-compatible provider base URL for Token4AI AI Gateway.
    #[arg(
        long,
        env = "FERROGATE_TOKEN4AI_OPENAI_BASE_URL",
        default_value = "https://api.token4ai.cloud/v1"
    )]
    pub(crate) provider_base_url: String,
    /// Provider API key. Prefer FERROGATE_TOKEN4AI_OPENAI_API_KEY in shell/CI.
    #[arg(long, env = "FERROGATE_TOKEN4AI_OPENAI_API_KEY")]
    pub(crate) provider_api_key: String,
    /// Live model to call through the Token4AI OpenAI-compatible API.
    #[arg(
        long,
        env = "FERROGATE_TOKEN4AI_OPENAI_MODEL",
        default_value = "gpt-4o-mini"
    )]
    pub(crate) provider_model: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum DockerScenario {
    AnalyticsDirectClickhouse,
    AnalyticsVectorClickhouse,
    ClusterDrain,
    GuardrailComplete,
    GuardrailRequestDeny,
    GuardrailResponseRedact,
    SharedApiKey,
    SharedStateStale,
    SharedStateStartupUnavailable,
    RedisCounters,
}

impl DockerScenario {
    pub(crate) fn names() -> &'static [&'static str] {
        &[
            "analytics-direct-clickhouse",
            "analytics-vector-clickhouse",
            "cluster-drain",
            "guardrail-complete",
            "guardrail-request-deny",
            "guardrail-response-redact",
            "shared-api-key",
            "shared-state-stale",
            "shared-state-startup-unavailable",
            "redis-counters",
        ]
    }
}

pub(crate) const IMAGE_TAG: &str = "ferrogate:e2e-local";

pub(crate) struct Dispatch {
    pub(crate) admin: fn(&LocalArgs) -> Result<()>,
    pub(crate) auth: fn(&AuthArgs) -> Result<()>,
    pub(crate) gateway: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_live_smoke: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_restart: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_token4ai_provider: fn(&SupabaseLiveToken4aiProviderArgs) -> Result<()>,
    pub(crate) supabase_migration: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_tls_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) mysql_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) mysql_tls_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) docker: fn(DockerScenario, &str) -> Result<()>,
    pub(crate) run_all_admin_auth_gateway: fn(&LocalArgs, &AuthArgs, bool, &str) -> Result<()>,
    pub(crate) ci: fn(&LocalArgs, &AuthArgs) -> Result<()>,
}

pub(crate) fn run(dispatch: Dispatch) -> Result<()> {
    print_attribution_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::List => {
            println!(
                "local: admin-api, auth-api, gateway-api, ci, supabase-migration, supabase-restart, supabase-live-smoke (opt-in), supabase-live-restart (opt-in), supabase-live-token4ai-provider (opt-in), postgres-restart, postgres-tls-restart, mysql-restart, mysql-tls-restart"
            );
            println!("docker: {}", DockerScenario::names().join(", "));
            Ok(())
        }
        Commands::Run(args) => (dispatch.docker)(args.scenario, &args.image),
        Commands::RunAll(args) => (dispatch.run_all_admin_auth_gateway)(
            &args.local,
            &args.auth,
            args.include_docker,
            &args.image,
        ),
        Commands::AdminApi(args) => (dispatch.admin)(&args),
        Commands::AuthApi(args) => (dispatch.auth)(&args),
        Commands::GatewayApi(args) => (dispatch.gateway)(&args),
        Commands::SupabaseRestart(args) => (dispatch.supabase_restart)(&args),
        Commands::SupabaseLiveSmoke(args) => (dispatch.supabase_live_smoke)(&args),
        Commands::SupabaseLiveRestart(args) => (dispatch.supabase_live_restart)(&args),
        Commands::SupabaseLiveToken4aiProvider(args) => {
            (dispatch.supabase_live_token4ai_provider)(&args)
        }
        Commands::SupabaseMigration(args) => (dispatch.supabase_migration)(&args),
        Commands::PostgresRestart(args) => (dispatch.postgres_restart)(&args),
        Commands::PostgresTlsRestart(args) => (dispatch.postgres_tls_restart)(&args),
        Commands::MysqlRestart(args) => (dispatch.mysql_restart)(&args),
        Commands::MysqlTlsRestart(args) => (dispatch.mysql_tls_restart)(&args),
        Commands::Ci(args) => (dispatch.ci)(&args.local, &args.auth),
    }
}

fn print_attribution_banner() {
    println!("Token4AI Cloud Attribution");
    println!(
        "Developed by the commercial cloud service company represented by https://token4ai.cloud."
    );
    println!("Author: jamesduan (X: https://x.com/JamesDuanL)");
    println!("Created: 2026-06-11");
    println!(
        "description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure."
    );
    println!();
}
