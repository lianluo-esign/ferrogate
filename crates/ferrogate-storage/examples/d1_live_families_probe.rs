// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #447 observability families (real-account round trips).

//! Gate-owned live validation for the #447 D1 observability slice: run the
//! REAL `RuntimeStorageRepositories` D1 backend against a REAL Cloudflare D1
//! database — provision a control DB, apply the shipped SQLite schema, then
//! round-trip agent runs and request logs through the actual translated SQL
//! (`IN (?, …)` lists, `count(*) OVER()` pagination) and clean everything up.
//!
//! Opt-in only — requires FERROGATE_CF_ACCOUNT_ID / FERROGATE_CF_API_TOKEN.
//! Run: cargo run -p ferrogate-storage --example d1_live_families_probe

use std::sync::Arc;

use ferrogate_cloudflare::d1::{D1Client, D1CreateDatabaseRequest};
use ferrogate_cloudflare::{CloudflareClient, CloudflareConfig, EnvTokenResolver};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    CloudflareD1StorageOptions, RuntimeStorageRepositories, StoredAgentRun, StoredRequestLog,
};

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let account_id = std::env::var("FERROGATE_CF_ACCOUNT_ID")
        .map_err(|_| "FERROGATE_CF_ACCOUNT_ID is required (live probe is opt-in)")?;
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let client = CloudflareClient::new(config, Arc::new(EnvTokenResolver::from_process_env()))?;
    let d1 = D1Client::new(Arc::new(client));

    let name = format!(
        "ferrogate-gate-families-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    );
    println!("probe database: {name}");
    let created = d1
        .create_database(&D1CreateDatabaseRequest::named(name.clone()))
        .await?;
    let dbid = created
        .uuid
        .clone()
        .ok_or("create_database returned no uuid")?;

    let result = exercise(&d1, &dbid).await;

    // Cleanup on success AND failure (operator directive: no lingering
    // Cloudflare resources), then verify the exact name is gone.
    d1.delete_database(&dbid).await?;
    if d1
        .list_databases()
        .await?
        .iter()
        .any(|db| db.name.as_deref() == Some(name.as_str()))
    {
        return Err("probe database still listed after delete".into());
    }
    println!("deleted + verified absent");

    result?;
    println!("d1_live_families_probe: PASS");
    Ok(())
}

async fn exercise(d1: &D1Client, dbid: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Apply the shipped schema through the real /query surface.
    let statements: Vec<String> = SCHEMA
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for statement in &statements {
        d1.query(dbid, statement, &[]).await?;
    }
    println!("schema applied: {} statements", statements.len());

    // The REAL backend under test: the same construction route ferrogate-cli
    // uses (#445), against the live database.
    let repositories = RuntimeStorageRepositories::cloudflare_d1_from_client(
        d1.clone(),
        CloudflareD1StorageOptions {
            control_database_id: dbid.to_string(),
            tenant_databases: Default::default(),
            audit_event_retention_records: 100,
        },
    )?;

    // Agent-run upsert + read-back (INSERT ... ON CONFLICT translation).
    repositories
        .upsert_agent_run(StoredAgentRun {
            id: "gate-live-run".into(),
            request_id: "gate-live-req".into(),
            trace_id: Some("gate-live-trace".into()),
            tenant: TenantContext::default(),
            status: "running".into(),
            provider: "openai".into(),
            turns_executed: 1,
            output_recorded: false,
            started_at_unix: Some(1_753_000_000),
            completed_at_unix: None,
        })
        .await?;
    let run = repositories
        .agent_run("gate-live-run")
        .await
        .ok_or("agent_run read-back returned none")?;
    if run.status != "running" || run.provider != "openai" {
        return Err(format!("agent_run round-trip mismatch: {run:?}").into());
    }
    println!("agent run round-trip: ok");

    // Request log append + IN-list read (`= ANY($1)` -> `IN (?, …)` translation).
    repositories
        .append_request_log(StoredRequestLog {
            request_id: "gate-live-req".into(),
            trace_id: Some("gate-live-trace".into()),
            agent_run_id: Some("gate-live-run".into()),
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext::default(),
            route: Some("/v1/chat/completions".into()),
            provider: Some("openai".into()),
            logical_model: Some("fast-chat".into()),
            provider_model: Some("gpt-4o-mini".into()),
            gateway_config_id: None,
            gateway_config_revision: None,
            status_code: 200,
            error_code: None,
            prompt_recorded: false,
            response_recorded: false,
            prompt_body: None,
            response_body: None,
            cache_status: None,
            started_at_unix: Some(1_753_000_001),
            completed_at_unix: Some(1_753_000_002),
            parent_action_fingerprint: None,
        })
        .await;
    let by_run = repositories
        .request_logs_for_agent_runs(&["gate-live-run".to_string()])
        .await;
    if by_run.len() != 1 || by_run[0].request_id != "gate-live-req" {
        return Err(format!("IN-list request-log read mismatch: {} rows", by_run.len()).into());
    }
    println!("request log IN-list round-trip: ok");

    // Paginated read (`count(*) OVER()` translation).
    let page = repositories.request_logs_page(0, 10).await;
    if page.total != 1 || page.data.len() != 1 {
        return Err(format!(
            "pagination mismatch: total={}, page={}",
            page.total,
            page.data.len()
        )
        .into());
    }
    println!("count(*) OVER() pagination: ok (total={})", page.total);
    Ok(())
}
