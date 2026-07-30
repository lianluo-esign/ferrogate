// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

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
    /// Run the pinned official Tier-1 MCP client against candidate and legacy ingress.
    McpCandidateClientOfficial(LocalArgs),
    /// Prove a cf:// Worker-bound secret reaches a real provider request (#417).
    CloudflareSecretApi(LocalArgs),
    /// Prove fixed runtime routes and methods are enforced by the OpenAPI contract.
    ApiContract(LocalArgs),
    /// Run reusable provider/guardrail/policy/quota runtime compliance contracts.
    ComponentCompliance(LocalArgs),
    /// Run reusable component contracts against a real Supabase schema.
    ComponentComplianceSupabase(SupabaseLiveRestartArgs),
    /// Run the gateway -> billing service usage-to-ledger chain (gpt-5.5).
    GatewayBillingChain(LocalArgs),
    /// Run the managed x402 paid-egress loop-closure chain: policy -> merchant -> ledger (#354).
    X402PaidEgressChain(LocalArgs),
    /// Run function egress broker coverage against a real local FerroGate process.
    FunctionEgressApi(LocalArgs),
    /// Run the Cloudflare Worker branch of the function egress broker E2E (#435).
    FunctionEgressCloudflareApi(LocalArgs),
    /// Run the static-site publish/serve/per-file E2E family (#441).
    StaticSiteApi(LocalArgs),
    /// Run the #368 size+checksum-bound presigned staging upload E2E.
    AssetPresignApi(LocalArgs),
    /// Run aggregate gateway asset-buffer admission coverage (#529).
    AssetBufferAdmission(LocalArgs),
    /// Run the #344 static-resource registry lifecycle/quota/audit E2E.
    AssetRegistryApi(LocalArgs),
    /// Run the caller-facing async agent-job submit/observe/collect/cancel E2E (#474).
    AgentJobsApi(LocalArgs),
    /// Prove managed actions use the workspace's real project for policy and evidence (#519).
    ManagedActionProject(LocalArgs),
    /// Prove a failed D1 presence read renders Unknown without leaking backend details (#494).
    ObservedActivityD1Failure(LocalArgs),
    /// Prove tenancy lifecycle gates request-time and attach-time runtime paths (#514).
    LifecycleTenancy(LocalArgs),
    /// Prove tenancy lifecycle gates through a caller-supplied local PostgreSQL DSN (#514).
    LifecycleTenancyPostgres(PostgresLifecycleArgs),
    /// Prove tenancy lifecycle gates against a real live Supabase schema (#514).
    LifecycleTenancySupabase(SupabaseLiveRestartArgs),
    /// Run the #505 CLI mutation decision-receipt E2E: dry-run issues nothing,
    /// and the receipt's own rollback pointer reverses a guardrail policy
    /// revision with no identifier typed by hand.
    CliMutationReceipt(LocalArgs),
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
    /// Prove admin-console membership tiers mint and revoke gateway keys end-to-end (#517).
    AdminConsoleRolesSupabase(SupabaseLiveRestartArgs),
    /// Run local PostgreSQL-to-Supabase-compatible migration tooling coverage.
    SupabaseMigration(LocalArgs),
    /// Run local Docker-backed PostgreSQL restart durability coverage.
    PostgresRestart(LocalArgs),
    /// Run local Docker-backed PostgreSQL TLS restart durability coverage.
    PostgresTlsRestart(LocalArgs),
    /// Prove Worker lockfiles install, resolve, typecheck, and run from a clean checkout.
    WorkerRelease,
    /// Prove the shipped agent-worker binary emits the typed egress hold-edge discriminant (#353).
    AgentWorkerEgressWireStage(AgentWorkerArgs),
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
    #[command(flatten)]
    pub(crate) agent_worker: AgentWorkerArgs,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct AgentWorkerArgs {
    /// Path to a built agent-worker binary. Defaults to target/debug/agent-worker.
    #[arg(
        long,
        env = "FERROGATE_TEST_AGENT_WORKER_BIN",
        default_value = "target/debug/agent-worker"
    )]
    pub(crate) agent_worker_bin: PathBuf,
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
pub(crate) struct PostgresLifecycleArgs {
    #[command(flatten)]
    pub(crate) local: LocalArgs,
    /// Local PostgreSQL DSN for durable lifecycle coverage.
    #[arg(
        long,
        env = "FERROGATE_POSTGRES_DSN",
        default_value = "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=ferrogate sslmode=disable"
    )]
    pub(crate) postgres_dsn: String,
    /// PostgreSQL TLS mode for the local DSN.
    #[arg(long, env = "FERROGATE_POSTGRES_TLS_MODE", default_value = "disable")]
    pub(crate) postgres_tls_mode: String,
    /// Optional root CA path when the local PostgreSQL DSN requires TLS verification.
    #[arg(long, env = "FERROGATE_POSTGRES_TLS_CA_CERT_PATH")]
    pub(crate) postgres_tls_ca_cert_path: Option<PathBuf>,
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
    pub(crate) mcp_candidate_client_official: fn(&LocalArgs) -> Result<()>,
    pub(crate) cloudflare_secret: fn(&LocalArgs) -> Result<()>,
    pub(crate) api_contract: fn(&LocalArgs) -> Result<()>,
    pub(crate) component_compliance: fn(&LocalArgs) -> Result<()>,
    pub(crate) component_compliance_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) gateway_billing_chain: fn(&LocalArgs) -> Result<()>,
    pub(crate) x402_paid_egress_chain: fn(&LocalArgs) -> Result<()>,
    pub(crate) function_egress: fn(&LocalArgs) -> Result<()>,
    pub(crate) function_egress_cloudflare: fn(&LocalArgs) -> Result<()>,
    pub(crate) static_site: fn(&LocalArgs) -> Result<()>,
    pub(crate) asset_presign: fn(&LocalArgs) -> Result<()>,
    pub(crate) asset_buffer_admission: fn(&LocalArgs) -> Result<()>,
    pub(crate) asset_registry: fn(&LocalArgs) -> Result<()>,
    pub(crate) agent_jobs: fn(&LocalArgs) -> Result<()>,
    pub(crate) managed_action_project: fn(&LocalArgs) -> Result<()>,
    pub(crate) observed_activity_d1_failure: fn(&LocalArgs) -> Result<()>,
    pub(crate) lifecycle_tenancy: fn(&LocalArgs) -> Result<()>,
    pub(crate) lifecycle_tenancy_postgres: fn(&PostgresLifecycleArgs) -> Result<()>,
    pub(crate) lifecycle_tenancy_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) cli_mutation_receipt: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) supabase_live_smoke: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_restart: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_live_token4ai_provider: fn(&SupabaseLiveToken4aiProviderArgs) -> Result<()>,
    pub(crate) guardrail_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) guardrail_workers_ai_llama_guard: fn(&LocalArgs) -> Result<()>,
    pub(crate) mcp_identity_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) target_capability_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) admin_console_roles_supabase: fn(&SupabaseLiveRestartArgs) -> Result<()>,
    pub(crate) supabase_migration: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) postgres_tls_restart: fn(&LocalArgs) -> Result<()>,
    pub(crate) worker_release: fn() -> Result<()>,
    pub(crate) agent_worker_egress_wire_stage: fn(&Path) -> Result<()>,
    pub(crate) docker: fn(DockerScenario, &str) -> Result<()>,
    pub(crate) run_all_admin_auth_gateway: fn(&LocalArgs, &AuthArgs, bool, &str) -> Result<()>,
    pub(crate) ci: fn(&LocalArgs, &AuthArgs, &AgentWorkerArgs) -> Result<()>,
}

pub(crate) fn run(dispatch: Dispatch) -> Result<()> {
    print_attribution_banner();
    let cli = Cli::parse();
    match cli.command {
        Commands::List => {
            println!(
                "local: admin-api, auth-api, gateway-api, mcp-candidate-client-official (locked official npm opponent), cloudflare-secret-api, api-contract, component-compliance, component-compliance-supabase (live Supabase required), admin-console-roles-supabase (live Supabase required), ci, x402-paid-egress-chain, function-egress-cloudflare-api, static-site-api, asset-presign-api, asset-buffer-admission, asset-registry-api, agent-jobs-api, managed-action-project, observed-activity-d1-failure, lifecycle-tenancy, lifecycle-tenancy-postgres, lifecycle-tenancy-supabase (live Supabase required), cli-mutation-receipt, guardrail-supabase (live Supabase required), guardrail-workers-ai-llama-guard, mcp-identity-supabase (live Supabase required), target-capability-supabase (live Supabase required), supabase-migration, supabase-restart, supabase-live-smoke (opt-in), supabase-live-restart (opt-in), supabase-live-token4ai-provider (opt-in), postgres-restart, postgres-tls-restart, worker-release"
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
        Commands::McpCandidateClientOfficial(args) => {
            (dispatch.mcp_candidate_client_official)(&args)
        }
        Commands::CloudflareSecretApi(args) => (dispatch.cloudflare_secret)(&args),
        Commands::ApiContract(args) => (dispatch.api_contract)(&args),
        Commands::ComponentCompliance(args) => (dispatch.component_compliance)(&args),
        Commands::ComponentComplianceSupabase(args) => {
            (dispatch.component_compliance_supabase)(&args)
        }
        Commands::GatewayBillingChain(args) => (dispatch.gateway_billing_chain)(&args),
        Commands::X402PaidEgressChain(args) => (dispatch.x402_paid_egress_chain)(&args),
        Commands::FunctionEgressApi(args) => (dispatch.function_egress)(&args),
        Commands::FunctionEgressCloudflareApi(args) => (dispatch.function_egress_cloudflare)(&args),
        Commands::StaticSiteApi(args) => (dispatch.static_site)(&args),
        Commands::AssetPresignApi(args) => (dispatch.asset_presign)(&args),
        Commands::AssetBufferAdmission(args) => (dispatch.asset_buffer_admission)(&args),
        Commands::AssetRegistryApi(args) => (dispatch.asset_registry)(&args),
        Commands::AgentJobsApi(args) => (dispatch.agent_jobs)(&args),
        Commands::ManagedActionProject(args) => (dispatch.managed_action_project)(&args),
        Commands::ObservedActivityD1Failure(args) => (dispatch.observed_activity_d1_failure)(&args),
        Commands::LifecycleTenancy(args) => (dispatch.lifecycle_tenancy)(&args),
        Commands::LifecycleTenancyPostgres(args) => (dispatch.lifecycle_tenancy_postgres)(&args),
        Commands::LifecycleTenancySupabase(args) => (dispatch.lifecycle_tenancy_supabase)(&args),
        Commands::CliMutationReceipt(args) => (dispatch.cli_mutation_receipt)(&args),
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
        Commands::AdminConsoleRolesSupabase(args) => (dispatch.admin_console_roles_supabase)(&args),
        Commands::SupabaseMigration(args) => (dispatch.supabase_migration)(&args),
        Commands::PostgresRestart(args) => (dispatch.postgres_restart)(&args),
        Commands::PostgresTlsRestart(args) => (dispatch.postgres_tls_restart)(&args),
        Commands::WorkerRelease => (dispatch.worker_release)(),
        Commands::AgentWorkerEgressWireStage(args) => {
            (dispatch.agent_worker_egress_wire_stage)(&args.agent_worker_bin)
        }
        Commands::Ci(args) => (dispatch.ci)(&args.local, &args.auth, &args.agent_worker),
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
