// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod acme;
mod approval;
mod auth;
mod cli;
mod config;
mod dashboard;
mod extensions;
mod gateway;
mod lifecycle;
mod metering;
mod responses;
mod routing;
#[cfg(test)]
mod routing_tests;
mod state;
mod storage;
mod telemetry;

use anyhow::Result as AnyResult;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    cli::{AuthCommands, Cli, Commands},
    config::Config,
    gateway::serve,
    lifecycle::{
        execute_admin_reload, execute_graceful_upgrade_reload, format_reload_report,
        format_validate_report,
    },
};

fn main() -> AnyResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => serve(Config::load(&args.config)?, Some(args.config), args.upgrade),
        Commands::Auth(args) => match args.command {
            AuthCommands::Serve(args) => {
                let data = match args.data {
                    Some(path) => ferrogate_auth::AuthServiceData::load_yaml(path)?,
                    None => ferrogate_auth::AuthServiceData::default(),
                };
                ferrogate_auth::serve(ferrogate_auth::AuthServiceConfig {
                    listen: args.listen,
                    data,
                    api_key_authenticator: None,
                })
            }
        },
        Commands::Storage(args) => storage::execute_storage_command(args.command),
        Commands::Validate(args) => {
            let config = Config::load(&args.config)?;
            println!("{}", format_validate_report(&config));
            Ok(())
        }
        Commands::Reload(args) => {
            let config = Config::load(&args.config)?;
            if args.graceful_upgrade {
                println!(
                    "{}",
                    execute_graceful_upgrade_reload(&args.config, &config)?
                );
            } else if let Some(admin_url) = args.admin_url.as_deref() {
                println!(
                    "{}",
                    execute_admin_reload(
                        admin_url,
                        args.admin_token.as_deref(),
                        &args.config,
                        &config
                    )?
                );
            } else {
                println!("{}", format_reload_report(&config));
            }
            Ok(())
        }
        Commands::HashKey(args) => {
            println!("{}", auth::hash_api_key_secret(&args.secret));
            Ok(())
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}
