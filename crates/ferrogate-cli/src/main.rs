// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

mod acme;
mod admin_api;
mod approval;
mod assets_cli;
mod auth;
mod billing;
mod billing_client;
mod budget_alerts;
mod builtin_tools;
mod cli;
mod command_tree;
mod completions;
mod config;
mod ctl;
mod dashboard;
mod extensions;
mod gateway;
mod lifecycle;
mod lifecycle_gate;
mod metering;
mod network_access;
mod plans_cli;
#[cfg(test)]
mod reference;
mod responses;
mod routing;
#[cfg(test)]
mod routing_tests;
mod service_storage;
mod state;
mod storage;
mod telemetry;
mod tokenizer;

use anyhow::Result as AnyResult;
use clap::FromArgMatches;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use std::sync::Arc;

use crate::{
    cli::{AdminApiCommands, AuthCommands, BillingCommands, Cli, Commands, ControlApiCommands},
    config::Config,
    gateway::serve,
    lifecycle::{
        execute_admin_reload, execute_graceful_upgrade_reload, format_reload_report,
        format_validate_report,
    },
    service_storage::{build_supabase_repositories, SupabaseConnection},
};

fn main() -> AnyResult<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    init_tracing();

    // Build the full command surface: the derived `ferrogate` tree plus the
    // generic Control Plane API resource families (#361–#365), whose entire
    // `ctl <group> <verb>` subtree is derived from the `ferrogate-cli-core`
    // registry metadata rather than hand-enumerated here (registering a new
    // family in the library needs no change in this binary). Assembled through
    // the shared `command_tree` helper so shell completions (`completions`) and
    // the generated command reference describe this EXACT command.
    let registry = command_tree::resource_registry();
    let command = command_tree::assembled_command(&registry);
    let matches = command.get_matches();

    // The resource families own their diagnostics (stderr) and map every
    // outcome onto a stable exit-code class, so they terminate the process
    // directly — exactly like #360's `ops`/`context` below.
    if let Some((ctl::CTL_COMMAND, ctl_matches)) = matches.subcommand() {
        std::process::exit(ctl::run_resource(&registry, ctl_matches));
    }

    let cli =
        Cli::from_arg_matches(&matches).map_err(|error| anyhow::anyhow!(error.to_string()))?;

    match cli.command {
        Commands::Run(args) => serve(Config::load(&args.config)?, Some(args.config), args.upgrade),
        Commands::Auth(args) => match args.command {
            AuthCommands::Serve(args) => {
                let data = match args.data {
                    Some(path) => ferrogate_auth::AuthServiceData::load_yaml(path)?,
                    None => ferrogate_auth::AuthServiceData::default(),
                };
                // When a Supabase DSN is provided, resolve hashed durable
                // virtual API keys against storage; otherwise fall back to the
                // YAML/in-memory RBAC authenticator. The same repositories
                // handle back the admin console (issue #157) when a JWT
                // secret is also configured.
                let repositories = match args.supabase_dsn.as_deref().map(str::trim) {
                    Some(dsn) if !dsn.is_empty() => {
                        Some(Arc::new(build_supabase_repositories(SupabaseConnection {
                            dsn,
                            tls_mode: &args.supabase_tls_mode,
                            tls_ca_cert_path: args.supabase_tls_ca_cert_path.as_deref(),
                            schema: args.supabase_schema.as_deref(),
                            init_schema: args.supabase_init_schema,
                        })?))
                    }
                    _ => None,
                };
                let api_key_authenticator = repositories.clone().map(|repositories| {
                    Arc::new(ferrogate_auth::StorageApiKeyAuthenticator::new(
                        repositories,
                    )) as Arc<dyn ferrogate_auth::ApiKeyAuthenticator>
                });
                let admin_jwt_secret = crate::service_storage::resolve_secret(
                    args.admin_jwt_secret.as_deref(),
                    args.admin_jwt_secret_env.as_deref(),
                )?;
                let admin_console = match (repositories, admin_jwt_secret) {
                    (Some(repositories), Some(jwt_secret)) => {
                        Some(ferrogate_auth::AdminConsoleConfig {
                            repositories,
                            jwt_secret,
                        })
                    }
                    (None, Some(_)) => anyhow::bail!(
                        "--admin-jwt-secret(-env) requires --supabase-dsn: the admin console \
                         needs durable storage to remember registered users across restarts"
                    ),
                    _ => None,
                };
                ferrogate_auth::serve(ferrogate_auth::AuthServiceConfig {
                    listen: args.listen,
                    data,
                    api_key_authenticator,
                    admin_console,
                    cors_allowed_origin: args.cors_allowed_origin,
                })
            }
        },
        // The standalone FerroGate Control Plane API service (issue #359,
        // formerly #315's admin-api) loads the SAME config file the gateway
        // runs from ([control_api] section, or the deprecated [admin_api]
        // alias, plus the shared [[api_keys]]/[storage]/[limits] sections),
        // so both processes agree on credentials and caps.
        Commands::ControlApi(args) => match args.command {
            ControlApiCommands::Serve(args) => {
                admin_api::execute_control_api_serve(Config::load(&args.config)?)
            }
        },
        // Deprecated alias retained for the migration window: identical
        // behavior to `control-api serve`, preceded by an actionable
        // deprecation notice.
        Commands::AdminApi(args) => match args.command {
            AdminApiCommands::Serve(args) => {
                admin_api::emit_admin_api_command_deprecation();
                admin_api::execute_control_api_serve(Config::load(&args.config)?)
            }
        },
        Commands::Billing(args) => match args.command {
            BillingCommands::Serve(args) => billing::execute_billing_serve(args),
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
        Commands::Assets(args) => assets_cli::execute_assets_command(args.command),
        Commands::Plans(args) => plans_cli::execute_plans_command(args.command),
        // The #360 Control Plane API client commands own their own diagnostics
        // (rendered to stderr) and map every outcome onto a stable exit-code
        // class, so they terminate the process directly rather than returning
        // an `anyhow` error into the generic `?` path.
        Commands::Context(args) => std::process::exit(ctl::run_context(args.command)),
        Commands::Ops(args) => std::process::exit(ctl::run_ops(args)),
        // Emit a shell completion script for the full assembled command tree
        // (issue #365). Additive and side-effect-free: writes to stdout only.
        Commands::Completions(args) => completions::execute(args.shell),
    }
}

/// Default log filter used when `RUST_LOG` is not set. Pingora's own crates
/// log their internal bootstrap/service lifecycle at `info`, which drowns out
/// FerroGate's own startup log line with noise an operator can't act on;
/// downgrade them to `warn` so only genuine Pingora warnings/errors surface,
/// while FerroGate's own crates keep logging at `info`. `RUST_LOG` still
/// takes full precedence when set, including to re-enable these at `debug`
/// for Pingora-level troubleshooting.
const DEFAULT_LOG_FILTER: &str = "info,\
    pingora=warn,\
    pingora_cache=warn,\
    pingora_core=warn,\
    pingora_error=warn,\
    pingora_header_serde=warn,\
    pingora_http=warn,\
    pingora_ketama=warn,\
    pingora_load_balancing=warn,\
    pingora_lru=warn,\
    pingora_pool=warn,\
    pingora_proxy=warn,\
    pingora_runtime=warn,\
    pingora_rustls=warn,\
    pingora_timeout=warn";

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .try_init();
}
