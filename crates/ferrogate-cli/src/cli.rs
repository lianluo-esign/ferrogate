use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "ferrogate")]
#[command(
    author,
    version,
    about = "FerroGate, the open-source Rust API Gateway and AI Gateway"
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

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Run the FerroGate Pingora gateway server.
    Run(ConfigArgs),
    /// Validate configuration and print a summary.
    #[command(alias = "check")]
    Validate(ConfigArgs),
    /// Reload a running gateway process. Planned for P2.
    Reload(ConfigArgs),
}
