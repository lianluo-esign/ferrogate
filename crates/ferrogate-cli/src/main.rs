mod auth;
mod cli;
mod config;
mod gateway;
mod lifecycle;
mod responses;
mod routing;
#[cfg(test)]
mod routing_tests;
mod state;

use anyhow::Result as AnyResult;
use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    cli::{Cli, Commands},
    config::Config,
    gateway::serve,
    lifecycle::{format_reload_report, format_validate_report},
};

fn main() -> AnyResult<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => serve(Config::load(&args.config)?),
        Commands::Validate(args) => {
            let config = Config::load(&args.config)?;
            println!("{}", format_validate_report(&config));
            Ok(())
        }
        Commands::Reload(args) => {
            let config = Config::load(&args.config)?;
            println!("{}", format_reload_report(&config));
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
