// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

use clap::{Args, Parser, Subcommand};
use ferrogate_auth::{AuthServiceConfig, AuthServiceData};
use std::path::PathBuf;

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve(args) => {
            let data = match args.data {
                Some(path) => AuthServiceData::load_yaml(path)?,
                None => AuthServiceData::default(),
            };
            ferrogate_auth::serve(AuthServiceConfig {
                listen: args.listen,
                data,
            })
        }
    }
}
