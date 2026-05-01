use anyhow::{Context, Result};
use axum::{routing::get, Json, Router};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Parser)]
#[command(name = "ferrogate")]
#[command(
    author,
    version,
    about = "FerroGate, the open-source Rust gateway for AI traffic"
)]
struct Cli {
    #[arg(
        short,
        long,
        env = "FERROGATE_CONFIG",
        default_value = "ferrogate.toml"
    )]
    config: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the FerroGate server.
    Serve,
    /// Validate configuration and print a summary.
    Check,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Config {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    providers: Vec<Provider>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Provider {
    name: String,
    base_url: String,
    #[serde(default)]
    api_key_env: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
    service: &'a str,
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            providers: Vec::new(),
        }
    }
}

impl Config {
    fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file {}", path.display()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    match cli.command.unwrap_or(Commands::Serve) {
        Commands::Serve => serve(config).await,
        Commands::Check => {
            println!(
                "FerroGate config OK: listen={}, providers={}",
                config.listen,
                config.providers.len()
            );
            Ok(())
        }
    }
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn serve(config: Config) -> Result<()> {
    let addr: SocketAddr = config
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", config.listen))?;

    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/models", get(models))
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "FerroGate is listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn healthz() -> Json<HealthResponse<'static>> {
    Json(HealthResponse {
        status: "ok",
        service: "ferrogate",
    })
}

async fn models() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "object": "list",
        "data": []
    }))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_localhost_8080() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:8080");
        assert!(config.providers.is_empty());
    }

    #[test]
    fn parses_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrogate.toml");
        std::fs::write(
            &path,
            r#"
listen = "0.0.0.0:8080"

[[providers]]
name = "openai"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"
"#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].name, "openai");
    }
}
