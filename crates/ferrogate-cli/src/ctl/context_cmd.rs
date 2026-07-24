// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `ferrogate context` — manage named Control Plane API client profiles
//! (issue #360).
//!
//! Create, list, show, select (`use`), and delete contexts persisted through
//! [`super::store`]. A context stores an endpoint, default scope, TLS policy,
//! and a *credential source* (which env var / stdin), **never a token value**,
//! so no verb here can print or write a secret. `list`/`show` render the
//! credential only through the foundation's `AuthSource::describe` (`env:VAR`,
//! `stdin`, `none`), which is secret-free by construction.

use ferrogate_cli_core::auth::AuthSource;
use ferrogate_cli_core::context::Context;
use ferrogate_cli_core::error::{CliError, CliResult};
use ferrogate_cli_core::output::Table;

use crate::cli::{ContextCommands, ContextCreateArgs};

use super::dispatch::report_error;
use super::store;

/// Dispatch a `context` verb and translate the result into a process exit code.
pub(crate) fn run_context(command: ContextCommands) -> i32 {
    match execute(command) {
        Ok(()) => 0,
        Err(error) => {
            report_error(&error);
            error.exit_class().code()
        }
    }
}

fn execute(command: ContextCommands) -> CliResult<()> {
    match command {
        ContextCommands::Create(args) => create(*args),
        ContextCommands::List => list(),
        ContextCommands::Show(args) => show(&args.name),
        ContextCommands::Use(args) => use_context(&args.name),
        ContextCommands::Delete(args) => delete(&args.name),
    }
}

/// Turn the credential-source flags into an [`AuthSource`]. The flags are
/// mutually exclusive to Clap; the collapse is still explicit so behavior does
/// not depend on trusting the parser.
fn auth_source(args: &ContextCreateArgs) -> AuthSource {
    if args.token_stdin {
        AuthSource::Stdin
    } else if let Some(var) = &args.token_env {
        AuthSource::Env { var: var.clone() }
    } else {
        AuthSource::None
    }
}

fn create(args: ContextCreateArgs) -> CliResult<()> {
    let auth = auth_source(&args);
    let mut context = Context::new(&args.name, &args.endpoint);
    context.tenant = args.tenant.clone();
    context.project = args.project.clone();
    context.workspace = args.workspace.clone();
    context.tls_insecure_skip_verify = args.insecure_skip_tls_verify;
    context.auth = auth.clone();

    let mut store = store::load()?;
    if store.get(&args.name).is_some() && !args.overwrite {
        return Err(CliError::usage(format!(
            "context '{}' already exists; pass --overwrite to replace it",
            args.name
        )));
    }
    store.upsert(context);
    if args.use_now {
        store.set_current(&args.name)?;
    }
    store::save(&store)?;

    // Diagnostics go to stderr; the credential is described, never printed.
    eprintln!(
        "created context '{}' (endpoint {}, auth {}){}",
        args.name,
        args.endpoint,
        auth.describe(),
        if args.use_now { ", now current" } else { "" }
    );
    Ok(())
}

fn list() -> CliResult<()> {
    let store = store::load()?;
    let headers = vec![
        "NAME".to_string(),
        "CURRENT".to_string(),
        "ENDPOINT".to_string(),
        "AUTH".to_string(),
        "TENANT".to_string(),
    ];
    let rows = store
        .contexts
        .iter()
        .map(|context| {
            let current = if store.current.as_deref() == Some(context.name.as_str()) {
                "*"
            } else {
                ""
            };
            vec![
                context.name.clone(),
                current.to_string(),
                context.endpoint.clone(),
                context.auth.describe(),
                context.tenant.clone().unwrap_or_else(|| "-".to_string()),
            ]
        })
        .collect();
    // Data → stdout. `describe` guarantees no secret is emitted.
    println!("{}", Table::new(headers, rows)?.render());
    if store.contexts.is_empty() {
        eprintln!("no contexts defined; create one with `ferrogate context create`");
    }
    Ok(())
}

fn show(name: &str) -> CliResult<()> {
    let store = store::load()?;
    let context = store
        .get(name)
        .ok_or_else(|| CliError::usage(format!("no such context '{name}'; run `context list`")))?;
    let optional = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_string());
    let rows = vec![
        vec!["name".to_string(), context.name.clone()],
        vec!["endpoint".to_string(), context.endpoint.clone()],
        vec!["tenant".to_string(), optional(&context.tenant)],
        vec!["project".to_string(), optional(&context.project)],
        vec!["workspace".to_string(), optional(&context.workspace)],
        // Credential SOURCE only — never the token value.
        vec!["auth".to_string(), context.auth.describe()],
        vec![
            "tls_insecure_skip_verify".to_string(),
            context.tls_insecure_skip_verify.to_string(),
        ],
        vec![
            "current".to_string(),
            (store.current.as_deref() == Some(name)).to_string(),
        ],
    ];
    println!(
        "{}",
        Table::new(vec!["FIELD".to_string(), "VALUE".to_string()], rows)?.render()
    );
    Ok(())
}

fn use_context(name: &str) -> CliResult<()> {
    let mut store = store::load()?;
    store.set_current(name)?;
    store::save(&store)?;
    eprintln!("selected context '{name}'");
    Ok(())
}

fn delete(name: &str) -> CliResult<()> {
    let mut store = store::load()?;
    if !store.remove(name) {
        return Err(CliError::usage(format!(
            "no such context '{name}'; nothing to delete"
        )));
    }
    store::save(&store)?;
    eprintln!("deleted context '{name}'");
    Ok(())
}

#[cfg(test)]
#[path = "context_cmd_test.rs"]
mod context_cmd_test;
