// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! `ferrogate billing serve` wiring: assemble the rate card and ledger sink,
//! then hand off to the standalone billing service in `ferrogate-billing`.

use std::{path::Path, sync::Arc};

use anyhow::Context;
use ferrogate_billing::{BillingServiceConfig, InMemoryLedgerSink, LedgerSink, PriceBook};
use ferrogate_storage::StorageLedgerSink;

use crate::{
    cli::BillingServeArgs,
    service_storage::{build_supabase_repositories, SupabaseConnection},
};

/// Launch the billing REST service, blocking for the process lifetime.
pub(crate) fn execute_billing_serve(args: BillingServeArgs) -> anyhow::Result<()> {
    let mut price_book = load_price_book(args.pricing.as_deref())?;
    if let Some(credits_per_usd) = args.credits_per_usd {
        price_book.credits_per_usd = credits_per_usd;
    }

    let token = resolve_token(&args)?;
    let sink = build_ledger_sink(&args)?;
    ferrogate_billing::serve(BillingServiceConfig {
        listen: args.listen,
        price_book,
        sink,
        token,
    })
}

/// Resolve the optional server-side shared secret from an inline value or a
/// named environment variable (issue #136).
fn resolve_token(args: &BillingServeArgs) -> anyhow::Result<Option<String>> {
    if let Some(token) = args.token.as_deref() {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(Some(token.to_string()));
        }
    }
    if let Some(env_name) = args.token_env.as_deref() {
        let env_name = env_name.trim();
        if !env_name.is_empty() {
            let token = std::env::var(env_name).with_context(|| {
                format!("failed to read billing token env {env_name}")
            })?;
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Ok(Some(token));
            }
        }
    }
    Ok(None)
}

/// Load the rate card from a JSON file, or fall back to the built-in default
/// covering the major vendors FerroGate proxies (gpt/claude/gemini/grok/deepseek).
fn load_price_book(path: Option<&Path>) -> anyhow::Result<PriceBook> {
    match path {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read billing rate card {}", path.display()))?;
            PriceBook::from_json_slice(&bytes)
                .with_context(|| format!("failed to parse billing rate card {}", path.display()))
        }
        None => Ok(PriceBook::with_default_rate_card()),
    }
}

/// Build the ledger sink: durable Supabase-backed when a DSN is supplied,
/// otherwise an in-memory ledger (ephemeral, suitable for local/dev/test).
fn build_ledger_sink(args: &BillingServeArgs) -> anyhow::Result<Arc<dyn LedgerSink>> {
    match args.supabase_dsn.as_deref().map(str::trim) {
        Some(dsn) if !dsn.is_empty() => {
            let repositories = build_supabase_repositories(SupabaseConnection {
                dsn,
                tls_mode: &args.supabase_tls_mode,
                schema: args.supabase_schema.as_deref(),
                init_schema: args.supabase_init_schema,
            })?;
            Ok(Arc::new(StorageLedgerSink::new(Arc::new(repositories))))
        }
        _ => Ok(Arc::new(InMemoryLedgerSink::default())),
    }
}
