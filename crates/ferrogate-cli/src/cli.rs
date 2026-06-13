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
pub(crate) struct AuthServeArgs {
    /// Address for the auth REST API service.
    #[arg(long, env = "FERROGATE_AUTH_LISTEN", default_value = "127.0.0.1:8090")]
    pub(crate) listen: String,
    /// Optional YAML data file with tenants, API keys, roles, and bindings.
    #[arg(long, env = "FERROGATE_AUTH_DATA")]
    pub(crate) data: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run the FerroGate Pingora gateway server.
    Run(RunArgs),
    /// Run FerroGate side services.
    Auth(AuthArgs),
    /// Validate configuration and print a summary.
    #[command(alias = "check")]
    Validate(ConfigArgs),
    /// Validate a candidate config or reload a running gateway through Admin API.
    Reload(ReloadArgs),
    /// Hash a virtual API key secret for durable configuration.
    HashKey(HashKeyArgs),
}
