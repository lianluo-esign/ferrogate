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
    /// Prove fixed runtime routes and methods are enforced by the OpenAPI contract.
    ApiContract(LocalArgs),
    /// Run reusable provider/guardrail/policy/quota runtime compliance contracts.
    ComponentCompliance(LocalArgs),
    /// Run reusable component contracts against a real Supabase schema.
    ComponentComplianceSupabase(SupabaseLiveRestartArgs),
    /// Run the gateway -> billing service usage-to-ledger chain (gpt-5.5).
    GatewayBillingChain(LocalArgs),
    /// Run function egress broker coverage against a real local FerroGate process.
    FunctionEgressApi(LocalArgs),
    /// Run the Cloudflare Worker branch of the function egress broker E2E (#435).
    FunctionEgressCloudflareApi(LocalArgs),
    /// Run the static-site publish/serve/per-file E2E family (#441).
    StaticSiteApi(LocalArgs),
    /// Run the caller-facing async agent-job submit/observe/collect/cancel E2E (#474).
    AgentJobsApi(LocalArgs),
    /// Run local Supabase-compatible Postgres restart durability coverage.
    SupabaseRestart(LocalArgs),
    /// Opt-in live Supabase connection, migration, status, and minimal persistence smoke.
    SupabaseLiveSmoke(SupabaseLiveRestartArgs),
    /// Opt-in live Supabase restart durability scenario.
    SupabaseLiveRestart(SupabaseLiveRestartArgs),
    /// Opt-in live Supabase and Token4AI OpenAI-compatible provider billing scenario.
    SupabaseLiveToken4aiProvider(SupabaseLiveToken4aiProviderArgs),
    /// Run Guardrail detector E2E and verify durable evidence directly in live Supabase.
    GuardrailSupabase(SupabaseLiveRestartArgs),
    /// Run config-selected Workers AI Llama Guard detector E2E against a local mock Workers AI endpoint (#430).
    GuardrailWorkersAiLlamaGuard(LocalArgs),
    /// Run per-user MCP OAuth identity isolation and DB-RBAC E2E against live Supabase.
    McpIdentitySupabase(SupabaseLiveRestartArgs),
    /// Prove target-capability RBAC write/read/runtime equality in live Supabase.
    TargetCapabilitySupabase(SupabaseLiveRestartArgs),
    /// Run local PostgreSQL-to-Supabase-compatible migration tooling coverage.
    SupabaseMigration(LocalArgs),
    /// Run local Docker-backed PostgreSQL restart durability coverage.
    PostgresRestart(LocalArgs),
    /// Run local Docker-backed PostgreSQL TLS restart durability coverage.
    PostgresTlsRestart(LocalArgs),
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
    /// Retain the unique live-test schema for explicit post-failure debugging.
    #[arg(
        long,
        env = "FERROGATE_TEST_KEEP_SUPABASE_SCHEMA",
        default_value_t = false
    )]
    pub(crate) keep_supabase_schema: bool,
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
    pub(crate) api_contract: fn(&LocalArgs) -> Result<()>,
    pub(crate) component_compliance: fn(&LocalArgs) -> Result<()>,
    pub(crate) component_compliance_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) gateway_billing_chain: fn(&LocalArgs) -> Result<()>,
    pub(crate) function_egress: fn(&LocalArgs) -> Result<()>,
    pub(crate) function_egress_cloudflare: fn(&LocalArgs) -> Result<()>,
    pub(crate) static_site: fn(&LocalArgs) -> Result<()>,
    pub(crate) agent_jobs: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_live_smoke: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_restart: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_token4ai_provider: fn(&SupabaseLiveToken4aiProviderArgs) -> Result<()>,
    pub(crate) guardrail_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) guardrail_workers_ai_llama_guard: fn(&LocalArgs) -> Result<()>,
    pub(crate) mcp_identity_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) target_capability_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_migration: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_tls_restart: fn(&LocalArgs) -> Result<()>,
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
                "local: admin-api, auth-api, gateway-api, api-contract, component-compliance, component-compliance-supabase (live Supabase required), ci, function-egress-cloudflare-api, static-site-api, agent-jobs-api, guardrail-supabase (live Supabase required), guardrail-workers-ai-llama-guard, mcp-identity-supabase (live Supabase required), target-capability-supabase (live Supabase required), supabase-migration, supabase-restart, supabase-live-smoke (opt-in), supabase-live-restart (opt-in), supabase-live-token4ai-provider (opt-in), postgres-restart, postgres-tls-restart"
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
        Commands::ApiContract(args) => (dispatch.api_contract)(&args),
        Commands::ComponentCompliance(args) => (dispatch.component_compliance)(&args),
        Commands::ComponentComplianceSupabase(args) => {
            (dispatch.component_compliance_supabase)(&args)
        }
        Commands::GatewayBillingChain(args) => (dispatch.gateway_billing_chain)(&args),
        Commands::FunctionEgressApi(args) => (dispatch.function_egress)(&args),
        Commands::FunctionEgressCloudflareApi(args) => (dispatch.function_egress_cloudflare)(&args),
        Commands::StaticSiteApi(args) => (dispatch.static_site)(&args),
        Commands::AgentJobsApi(args) => (dispatch.agent_jobs)(&args),
        Commands::SupabaseRestart(args) => (dispatch.supabase_restart)(&args),
        Commands::SupabaseLiveSmoke(args) => (dispatch.supabase_live_smoke)(&args),
        Commands::SupabaseLiveRestart(args) => (dispatch.supabase_live_restart)(&args),
        Commands::SupabaseLiveToken4aiProvider(args) => {
            (dispatch.supabase_live_token4ai_provider)(&args)
        }
        Commands::GuardrailSupabase(args) => (dispatch.guardrail_supabase)(&args),
        Commands::GuardrailWorkersAiLlamaGuard(args) => {
            (dispatch.guardrail_workers_ai_llama_guard)(&args)
        }
        Commands::McpIdentitySupabase(args) => (dispatch.mcp_identity_supabase)(&args),
        Commands::TargetCapabilitySupabase(args) => (dispatch.target_capability_supabase)(&args),
        Commands::SupabaseMigration(args) => (dispatch.supabase_migration)(&args),
        Commands::PostgresRestart(args) => (dispatch.postgres_restart)(&args),
        Commands::PostgresTlsRestart(args) => (dispatch.postgres_tls_restart)(&args),
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

#[cfg(test)]
#[path = "cli_test.rs"]
mod cli_test;
