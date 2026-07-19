// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-27
// description: FerroGate durable storage migration CLI.

use std::env;

use anyhow::{bail, Context, Result as AnyResult};
use ferrogate_storage::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories, StorageMigrationCounts,
};

use crate::cli::{StorageCommands, StorageMigrateToSupabaseArgs};

pub(crate) fn execute_storage_command(command: StorageCommands) -> AnyResult<()> {
    match command {
        StorageCommands::MigrateToSupabase(args) => migrate_to_supabase(args),
    }
}

fn migrate_to_supabase(args: StorageMigrateToSupabaseArgs) -> AnyResult<()> {
    let execute = args.execute;
    if !execute && !args.dry_run {
        eprintln!("no mode selected; defaulting to --dry-run");
    }

    let target_dsn = resolve_secret_value(
        "target Supabase DSN",
        args.target_supabase_dsn.as_deref(),
        args.target_supabase_dsn_env.as_deref(),
    )?;
    let tls_mode = parse_postgres_tls_mode(&args.postgres_tls_mode)?;
    let schema = args.postgres_schema.trim();
    if schema.is_empty() {
        bail!("--postgres-schema must not be empty");
    }
    let base_config = |dsn: String| PostgresStorageConfig {
        dsn,
        pool_size: 2,
        // This is an offline migration tool, and the first pool acquisition
        // includes the full TCP/TLS handshake to the (often remote) database:
        // a 1s deadline made the tool fail against real Supabase poolers
        // before the first query ran (#250). Generous is correct here; the
        // per-statement deadline below still bounds each operation.
        pool_acquire_timeout_millis: 30_000,
        tls_mode,
        tls_ca_cert_path: args
            .postgres_tls_ca_cert_path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(ToOwned::to_owned),
        connect_timeout_secs: 5,
        statement_timeout_millis: 30_000,
        schema: Some(schema.to_string()),
        search_path: vec!["public".into()],
    };

    let source = match args.source_provider.trim() {
        "postgres" => {
            let source_dsn = resolve_secret_value(
                "source postgres DSN",
                args.source_postgres_dsn.as_deref(),
                args.source_postgres_dsn_env.as_deref(),
            )?;
            RuntimeStorageRepositories::postgres_for_migration(base_config(source_dsn), false, true)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("failed to open source postgres storage for migration")?
        }
        other => bail!(
            "unsupported --source-provider {other}; current migration tooling supports postgres"
        ),
    };
    let snapshot = source
        .export_migration_snapshot()
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("failed to export source migration snapshot")?;
    let counts = snapshot.counts();

    if execute {
        let target =
            RuntimeStorageRepositories::supabase_for_migration(base_config(target_dsn), true, true)
                .map_err(|error| anyhow::anyhow!("{error}"))
                .context("failed to open target Supabase storage for migration")?;
        target
            .import_migration_snapshot(snapshot)
            .map_err(|error| anyhow::anyhow!("{error}"))
            .context("failed to import migration snapshot into Supabase")?;
        print_migration_report("executed", &counts);
    } else {
        let target = RuntimeStorageRepositories::supabase_for_migration(
            base_config(target_dsn),
            false,
            false,
        )
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("failed to validate target Supabase storage for migration")?;
        let _ = target.backend_evidence();
        print_migration_report("dry-run", &counts);
    }
    Ok(())
}

fn resolve_secret_value(
    label: &str,
    inline: Option<&str>,
    env_name: Option<&str>,
) -> AnyResult<String> {
    if let Some(value) = inline.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(value.to_string());
    }
    let env_name = env_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{label} requires inline value or env-name argument"))?;
    let value =
        env::var(env_name).with_context(|| format!("{label} env var {env_name} is not set"))?;
    if value.trim().is_empty() {
        bail!("{label} env var {env_name} must not be empty");
    }
    Ok(value)
}

fn parse_postgres_tls_mode(value: &str) -> AnyResult<PostgresTlsMode> {
    match value.trim() {
        "disable" => Ok(PostgresTlsMode::Disable),
        "prefer" => Ok(PostgresTlsMode::Prefer),
        "require" => Ok(PostgresTlsMode::Require),
        "verify_ca" | "verify-ca" => Ok(PostgresTlsMode::VerifyCa),
        "verify_full" | "verify-full" => Ok(PostgresTlsMode::VerifyFull),
        other => bail!(
            "--postgres-tls-mode must be disable, prefer, require, verify_ca, or verify_full, got {other}"
        ),
    }
}

fn print_migration_report(mode: &str, counts: &StorageMigrationCounts) {
    println!("FerroGate storage migration {mode}");
    println!("target=supabase");
    println!("api_keys={}", counts.api_keys);
    println!("tenants={}", counts.tenants);
    println!("policies={}", counts.policies);
    println!("gateway_configs={}", counts.gateway_configs);
    println!("agent_workflows={}", counts.agent_workflows);
    println!("skill_packages={}", counts.skill_packages);
    println!("prompt_templates={}", counts.prompt_templates);
    println!("plugin_registrations={}", counts.plugin_registrations);
    println!("mcp_servers={}", counts.mcp_servers);
    println!("agent_upstreams={}", counts.agent_upstreams);
    println!("tool_approvals={}", counts.tool_approvals);
    println!("billing_events={}", counts.billing_events);
    println!("usage_aggregates={}", counts.usage_aggregates);
    println!("request_logs={}", counts.request_logs);
    println!("audit_events={}", counts.audit_events);
    println!("agent_runs={}", counts.agent_runs);
    println!("agent_run_events={}", counts.agent_run_events);
    println!(
        "managed_worker_templates={}",
        counts.managed_worker_templates
    );
    println!("agent_worker_instances={}", counts.agent_worker_instances);
    println!("managed_worker_sessions={}", counts.managed_worker_sessions);
    println!(
        "managed_worker_lifecycle_events={}",
        counts.managed_worker_lifecycle_events
    );
    println!(
        "self_hosted_worker_registrations={}",
        counts.self_hosted_worker_registrations
    );
    println!(
        "self_hosted_worker_heartbeats={}",
        counts.self_hosted_worker_heartbeats
    );
    println!(
        "self_hosted_worker_telemetry_events={}",
        counts.self_hosted_worker_telemetry_events
    );
    println!(
        "self_hosted_worker_artifacts={}",
        counts.self_hosted_worker_artifacts
    );
    println!(
        "self_hosted_worker_checkpoints={}",
        counts.self_hosted_worker_checkpoints
    );
}
