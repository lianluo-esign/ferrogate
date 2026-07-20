// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ferrogate")]
#[command(
    author = "jamesduan <https://x.com/JamesDuanL>",
    version,
    about = "FerroGate, the Token4AI Cloud open-source Rust API Gateway and AI Gateway developed by jamesduan"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Args)]
pub(crate) struct ConfigArgs {
    #[arg(
        short,
        long,
        env = "FERROGATE_CONFIG",
        default_value = "Ferrogate/Caddyfile"
    )]
    pub(crate) config: PathBuf,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(
        short,
        long,
        env = "FERROGATE_CONFIG",
        default_value = "Ferrogate/Caddyfile"
    )]
    pub(crate) config: PathBuf,
    /// Start as the new Pingora process in a graceful upgrade.
    #[arg(long)]
    pub(crate) upgrade: bool,
}

#[derive(Debug, Args)]
pub(crate) struct ReloadArgs {
    #[arg(
        short,
        long,
        env = "FERROGATE_CONFIG",
        default_value = "Ferrogate/Caddyfile"
    )]
    pub(crate) config: PathBuf,
    /// Running gateway admin API base URL, for example http://127.0.0.1:8080.
    #[arg(long, env = "FERROGATE_ADMIN_URL")]
    pub(crate) admin_url: Option<String>,
    /// Bearer token with admin.write scope for the running gateway admin API.
    #[arg(long, env = "FERROGATE_ADMIN_TOKEN")]
    pub(crate) admin_token: Option<String>,
    /// Start a new `ferrogate run --upgrade` process and send SIGQUIT to the active pid.
    #[arg(long)]
    pub(crate) graceful_upgrade: bool,
}

#[derive(Debug, Args)]
pub(crate) struct HashKeyArgs {
    #[arg(long, env = "FERROGATE_KEY_SECRET")]
    pub(crate) secret: String,
}

#[derive(Debug, Args)]
pub(crate) struct AuthArgs {
    #[command(subcommand)]
    pub(crate) command: AuthCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AuthCommands {
    /// Run the tenant and RBAC REST API service.
    Serve(AuthServeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AdminApiArgs {
    #[command(subcommand)]
    pub(crate) command: AdminApiCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AdminApiCommands {
    /// Run the standalone admin-console API service (issue #315): a
    /// dedicated listener that authenticates admin callers and proxies the
    /// path-compatible /admin/v1/* (+ /v1/assets/*) surface to the gateway
    /// configured in the [admin_api] config section.
    Serve(ConfigArgs),
}

#[derive(Debug, Args)]
pub(crate) struct StorageArgs {
    #[command(subcommand)]
    pub(crate) command: StorageCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum StorageCommands {
    /// Migrate legacy durable control-plane state into Supabase.
    MigrateToSupabase(StorageMigrateToSupabaseArgs),
}

#[derive(Debug, Args)]
pub(crate) struct StorageMigrateToSupabaseArgs {
    /// Source durable provider. The current migration path supports postgres.
    #[arg(long, default_value = "postgres")]
    pub(crate) source_provider: String,
    /// Source PostgreSQL DSN. Prefer --source-postgres-dsn-env for shell history safety.
    #[arg(long, conflicts_with = "source_postgres_dsn_env")]
    pub(crate) source_postgres_dsn: Option<String>,
    /// Environment variable containing the source PostgreSQL DSN.
    #[arg(long, env = "FERROGATE_MIGRATION_SOURCE_POSTGRES_DSN_ENV")]
    pub(crate) source_postgres_dsn_env: Option<String>,
    /// Target Supabase DSN. Prefer --target-supabase-dsn-env for shell history safety.
    #[arg(long, conflicts_with = "target_supabase_dsn_env")]
    pub(crate) target_supabase_dsn: Option<String>,
    /// Environment variable containing the target Supabase DSN.
    #[arg(long, env = "FERROGATE_MIGRATION_TARGET_SUPABASE_DSN_ENV")]
    pub(crate) target_supabase_dsn_env: Option<String>,
    /// PostgreSQL/Supabase schema containing FerroGate storage tables.
    #[arg(long, default_value = "ferrogate_control")]
    pub(crate) postgres_schema: String,
    /// PostgreSQL/Supabase TLS mode for source and target connections.
    #[arg(long, default_value = "require")]
    pub(crate) postgres_tls_mode: String,
    /// Optional CA certificate path for PostgreSQL/Supabase TLS validation.
    #[arg(long)]
    pub(crate) postgres_tls_ca_cert_path: Option<String>,
    /// Run migration validation and counts without writing the target.
    #[arg(long, conflicts_with = "execute")]
    pub(crate) dry_run: bool,
    /// Write the exported source snapshot into Supabase.
    #[arg(long, conflicts_with = "dry_run")]
    pub(crate) execute: bool,
}

#[derive(Debug, Args)]
pub(crate) struct AuthServeArgs {
    /// Address for the auth REST API service.
    #[arg(long, env = "FERROGATE_AUTH_LISTEN", default_value = "127.0.0.1:8090")]
    pub(crate) listen: String,
    /// Optional YAML data file with tenants, API keys, roles, and bindings.
    #[arg(long, env = "FERROGATE_AUTH_DATA")]
    pub(crate) data: Option<PathBuf>,
    /// Supabase PostgreSQL DSN for durable hashed virtual API key resolution.
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_DSN")]
    pub(crate) supabase_dsn: Option<String>,
    /// Supabase/PostgreSQL TLS mode for durable virtual API key resolution.
    #[arg(
        long,
        env = "FERROGATE_AUTH_SUPABASE_TLS_MODE",
        default_value = "require"
    )]
    pub(crate) supabase_tls_mode: String,
    /// PostgreSQL schema holding the auth service's own tenant/RBAC tables.
    /// Dedicated by default so this service never shares a namespace with the
    /// gateway's own `ferrogate_control` schema or the billing service's
    /// schema in the same Supabase project (issue #156).
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_SCHEMA", default_value = "auth")]
    pub(crate) supabase_schema: Option<String>,
    /// Initialize missing Supabase schema objects before serving.
    #[arg(long, env = "FERROGATE_AUTH_SUPABASE_INIT_SCHEMA")]
    pub(crate) supabase_init_schema: bool,
    /// Shared secret used to sign/verify admin-console session tokens
    /// (issue #157). Enables the register/login/refresh/logout/me endpoints
    /// when set together with --supabase-dsn; prefer --admin-jwt-secret-env
    /// to keep the secret out of argv.
    ///
    /// IMPORTANT: registration provisions a tenant/project/workspace and a
    /// gateway-facing virtual API key that the *gateway* must also be able to
    /// see, so --supabase-schema above must be set to the SAME schema the
    /// gateway's own `storage.postgres_schema` uses (typically
    /// `ferrogate_control`) -- not left at this flag's own "auth" default,
    /// which is only correct when the admin console is disabled.
    #[arg(long, env = "FERROGATE_AUTH_ADMIN_JWT_SECRET")]
    pub(crate) admin_jwt_secret: Option<String>,
    /// Environment variable name holding the admin-console JWT secret.
    #[arg(long, env = "FERROGATE_AUTH_ADMIN_JWT_SECRET_ENV")]
    pub(crate) admin_jwt_secret_env: Option<String>,
    /// Origin reflected back as Access-Control-Allow-Origin on every response
    /// (including OPTIONS preflight), so a separately-deployed admin console
    /// frontend (issue #158/#159) can call this service cross-origin. Unset
    /// disables CORS headers entirely.
    #[arg(long, env = "FERROGATE_AUTH_CORS_ALLOWED_ORIGIN")]
    pub(crate) cors_allowed_origin: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct BillingArgs {
    #[command(subcommand)]
    pub(crate) command: BillingCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum BillingCommands {
    /// Run the token-usage billing REST service.
    Serve(BillingServeArgs),
}

#[derive(Debug, Args)]
pub(crate) struct BillingServeArgs {
    /// Address for the billing REST API service.
    #[arg(
        long,
        env = "FERROGATE_BILLING_LISTEN",
        default_value = "127.0.0.1:8092"
    )]
    pub(crate) listen: String,
    /// Optional JSON rate-card file (array of price entries or a full price
    /// book object). When omitted, a built-in default rate card is used.
    #[arg(long, env = "FERROGATE_BILLING_PRICING")]
    pub(crate) pricing: Option<PathBuf>,
    /// Credits charged per settled USD (`credits = total_cost_usd * this`).
    /// Overrides the value from the pricing file when set.
    #[arg(long, env = "FERROGATE_BILLING_CREDITS_PER_USD")]
    pub(crate) credits_per_usd: Option<f64>,
    /// Shared secret required on charge/ledger requests (`Authorization: Bearer
    /// <token>`). When set, unauthenticated requests are rejected; `/healthz`
    /// stays open. Prefer `--token-env` to keep the secret out of argv.
    #[arg(long, env = "FERROGATE_BILLING_TOKEN")]
    pub(crate) token: Option<String>,
    /// Environment variable name holding the billing shared secret.
    #[arg(long, env = "FERROGATE_BILLING_TOKEN_ENV")]
    pub(crate) token_env: Option<String>,
    /// Supabase PostgreSQL DSN for durable ledger persistence. When omitted,
    /// the ledger is kept in memory only.
    #[arg(long, env = "FERROGATE_BILLING_SUPABASE_DSN")]
    pub(crate) supabase_dsn: Option<String>,
    /// Supabase/PostgreSQL TLS mode for durable ledger persistence.
    #[arg(
        long,
        env = "FERROGATE_BILLING_SUPABASE_TLS_MODE",
        default_value = "require"
    )]
    pub(crate) supabase_tls_mode: String,
    /// PostgreSQL schema holding the billing service's own ledger/outbox
    /// tables. Dedicated by default so this service never shares a namespace
    /// with the gateway's own `ferrogate_control` schema or the auth
    /// service's schema in the same Supabase project (issue #156).
    #[arg(
        long,
        env = "FERROGATE_BILLING_SUPABASE_SCHEMA",
        default_value = "billing"
    )]
    pub(crate) supabase_schema: Option<String>,
    /// Initialize missing Supabase schema objects before serving.
    #[arg(long, env = "FERROGATE_BILLING_SUPABASE_INIT_SCHEMA")]
    pub(crate) supabase_init_schema: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run the FerroGate Pingora gateway server (alias: `gateway`).
    #[command(alias = "gateway")]
    Run(RunArgs),
    /// Run the tenant and RBAC auth REST service.
    Auth(AuthArgs),
    /// Run the standalone admin-console API service (issue #315).
    AdminApi(AdminApiArgs),
    /// Run the token-usage billing REST service.
    Billing(BillingArgs),
    /// Operate durable storage and migration tooling.
    Storage(Box<StorageArgs>),
    /// Validate configuration and print a summary.
    #[command(alias = "check")]
    Validate(ConfigArgs),
    /// Validate a candidate config or reload a running gateway through Admin API.
    Reload(ReloadArgs),
    /// Hash a virtual API key secret for durable configuration.
    HashKey(HashKeyArgs),
    /// Push/pull/list static assets through /v1/assets/* (issue #178).
    Assets(AssetsArgs),
    /// Create/list/assign sellable subscription plans (issue #168).
    Plans(PlansArgs),
}

#[derive(Debug, Args)]
pub(crate) struct AssetsArgs {
    #[command(subcommand)]
    pub(crate) command: AssetsCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum AssetsCommands {
    /// Upload a local file as a new asset version.
    Push(AssetsPushArgs),
    /// Download an asset's content to a local file (or stdout with `-`).
    Pull(AssetsIdentityArgs),
    /// List a tenant's assets, optionally filtered by asset type.
    List(AssetsListArgs),
    /// Delete one asset version.
    Delete(AssetsIdentityArgs),
}

#[derive(Debug, Args, Clone)]
pub(crate) struct AssetsConnectionArgs {
    /// Running gateway base URL, for example http://127.0.0.1:8080.
    #[arg(long, env = "FERROGATE_GATEWAY_URL")]
    pub(crate) gateway_url: String,
    /// Virtual API key with assets.read/assets.write scope.
    #[arg(long, env = "FERROGATE_API_KEY")]
    pub(crate) api_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct AssetsPushArgs {
    #[command(flatten)]
    pub(crate) connection: AssetsConnectionArgs,
    /// Local file to upload.
    pub(crate) path: PathBuf,
    /// Asset type, e.g. cli_tool, mcp_manifest, skill_bundle, static_site, config_file.
    #[arg(long = "type")]
    pub(crate) asset_type: String,
    /// Asset name.
    #[arg(long)]
    pub(crate) name: String,
    /// Asset version.
    #[arg(long)]
    pub(crate) version: String,
    /// Content-Type header to record; guessed from the file extension when omitted.
    #[arg(long)]
    pub(crate) content_type: Option<String>,
    /// Platform/arch variant (target triple), e.g. linux-x86_64 (#260). One
    /// logical version can carry several per-platform artifacts.
    #[arg(long)]
    pub(crate) platform: Option<String>,
    /// Also point this channel (latest/stable/canary or a free-form tag) at
    /// the pushed version (#260).
    #[arg(long)]
    pub(crate) channel: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct AssetsIdentityArgs {
    #[command(flatten)]
    pub(crate) connection: AssetsConnectionArgs,
    /// Asset type.
    #[arg(long = "type")]
    pub(crate) asset_type: String,
    /// Asset name.
    #[arg(long)]
    pub(crate) name: String,
    /// Exact version, a channel (latest/stable/canary/tag), or a semver range
    /// (`^1.2`, `~2.0`) to resolve at pull time (#260).
    #[arg(long)]
    pub(crate) version: String,
    /// Platform/arch variant (target triple) to select on pull (#260).
    #[arg(long)]
    pub(crate) platform: Option<String>,
    /// Output file for `pull` (defaults to stdout when omitted or `-`).
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub(crate) struct AssetsListArgs {
    #[command(flatten)]
    pub(crate) connection: AssetsConnectionArgs,
    /// Restrict the list to one asset type.
    #[arg(long = "type")]
    pub(crate) asset_type: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct PlansArgs {
    #[command(subcommand)]
    pub(crate) command: PlansCommands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum PlansCommands {
    /// Create a new sellable plan.
    Create(PlansCreateArgs),
    /// List every plan.
    List(PlansConnectionArgs),
    /// Assign an existing plan to an existing tenant.
    Assign(PlansAssignArgs),
}

#[derive(Debug, Args, Clone)]
pub(crate) struct PlansConnectionArgs {
    /// Running gateway base URL, for example http://127.0.0.1:8080.
    #[arg(long, env = "FERROGATE_GATEWAY_URL")]
    pub(crate) gateway_url: String,
    /// Virtual API key with admin.read/admin.write scope.
    #[arg(long, env = "FERROGATE_API_KEY")]
    pub(crate) api_key: String,
}

#[derive(Debug, Args)]
pub(crate) struct PlansCreateArgs {
    #[command(flatten)]
    pub(crate) connection: PlansConnectionArgs,
    /// Plan id; defaults to the slug when omitted.
    #[arg(long)]
    pub(crate) id: Option<String>,
    /// Human-readable plan name.
    #[arg(long)]
    pub(crate) name: String,
    /// URL-safe plan identifier.
    #[arg(long)]
    pub(crate) slug: String,
    /// Grant MCP tool governance access.
    #[arg(long)]
    pub(crate) mcp_enabled: bool,
    /// Grant self-hosted/managed worker dispatch eligibility.
    #[arg(long)]
    pub(crate) self_hosted_workers_enabled: bool,
    /// Grant /v1/assets/* hosting access.
    #[arg(long)]
    pub(crate) asset_hosting_enabled: bool,
    /// Grant Extension-backend /v1/tools/execute access.
    #[arg(long)]
    pub(crate) extension_tools_enabled: bool,
    /// Default requests-per-minute cap for tenants on this plan.
    #[arg(long)]
    pub(crate) default_rpm_limit: Option<u64>,
    /// Default tokens-per-minute cap for tenants on this plan.
    #[arg(long)]
    pub(crate) default_tpm_limit: Option<u64>,
    /// Default monthly budget (USD) for tenants on this plan.
    #[arg(long)]
    pub(crate) default_monthly_budget_usd: Option<f64>,
}

#[derive(Debug, Args)]
pub(crate) struct PlansAssignArgs {
    #[command(flatten)]
    pub(crate) connection: PlansConnectionArgs,
    /// Tenant account id to update.
    #[arg(long)]
    pub(crate) tenant_id: String,
    /// Plan id to assign to the tenant.
    #[arg(long)]
    pub(crate) plan_id: String,
}
