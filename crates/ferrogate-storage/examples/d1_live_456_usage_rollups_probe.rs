// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #456 tenant-scoped usage-rollups family.

//! Gate-owned live validation for the #456 usage-rollups slice: drive the REAL
//! `get_usage_monthly_rollup` / `list_usage_monthly_rollups` /
//! `list_usage_metadata_rollups` reads and the `persist_usage_aggregate` durable
//! RMW of a `D1ControlPlaneStore` **through a live deployed `workers/d1-proxy`
//! Worker, routed onto per-tenant `[[d1_databases]]` bindings** against REAL
//! Cloudflare D1 databases. This is the coverage the #456 landing commit flags as
//! Not-tested: the monthly/metadata reads FANNING OUT across TWO tenant databases
//! and re-merging to the Postgres `ORDER BY`, the scoped metadata read routing to
//! one org's own database, and the `persist_usage_aggregate` two-statement atomic
//! batch (tenant_contexts upsert + usage_aggregate_rollups REPLACE) landing
//! durably — none of which the mocked-transport tests can prove against the real
//! proxy binding.
//!
//! The usage family is TENANT-SCOPED (like #455/#456 wallets): a scope's rollup
//! lives in its OWNING tenant's database, so the reads fan out over ALL
//! provisioned tenant bindings and `persist` routes by organization. This probe
//! REQUIRES the operator to deploy a `workers/d1-proxy` bound to a control probe
//! D1 (binding `DB`) and TWO tenant probe D1s (`TENANT_DB_<A>` + `TENANT_DB_<B>`),
//! seed `D1_PROXY_TOKEN`, and hand this probe the three database uuids + tenant
//! ids + Worker origin + token. Because the D1 backend does not run the settlement
//! rollup-increment maintenance, the probe SEEDS the monthly/metadata rows
//! directly through the proxy, exercises the four ops (fan-out order + scoped
//! routing + durable persist), cleans its own rows, and leaves the DBs + Worker
//! for the operator to tear down (operator directive: no lingering CF resources).
//!
//! Opt-in only. Required env:
//!   FERROGATE_CF_ACCOUNT_ID            - account for the REST D1 client
//!   FERROGATE_CF_API_TOKEN             - REST bearer (resolved via env://)
//!   FERROGATE_D1_CONTROL_DATABASE_ID   - uuid of the control D1 (Worker binding DB)
//!   FERROGATE_D1_TENANT_DATABASE_ID    - uuid of tenant A's D1 (binding TENANT_DB_<A>)
//!   FERROGATE_D1_TENANT_ID             - tenant A id (e.g. gate456acme)
//!   FERROGATE_D1_TENANT_DATABASE_ID_B  - uuid of tenant B's D1 (binding TENANT_DB_<B>)
//!   FERROGATE_D1_TENANT_ID_B           - tenant B id (e.g. gate456bravo)
//!   FERROGATE_D1_PROXY_BASE_URL        - deployed Worker origin (https://...workers.dev)
//!   FERROGATE_D1_PROXY_TOKEN           - Worker bearer (resolved via env://)
//!
//! SKIPS cleanly (prints a notice, exits 0) when FERROGATE_CF_ACCOUNT_ID is
//! unset, so running this without credentials is a no-op rather than a failure.
//! With it set but another required variable missing the probe hard-errors: a
//! half-configured environment is an operator mistake, not an opt-out
//! (`support/probe_env.rs`, #495).
//! Run: cargo run -p ferrogate-storage --example d1_live_456_usage_rollups_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_billing::TokenUsage;
use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    usage_metadata_rollup_id, usage_monthly_rollup_id, D1ControlPlaneStore,
    D1TenantDatabaseRegistry, QuotaScopeKind, RuntimeStorageRepositories, StorageError,
    StoredUsageAggregate,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_456_usage_rollups_probe";
const PERIOD: &str = "2026-07";
const PRIOR: &str = "2026-06";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = probe_env::opt_in(
        PROBE,
        &[
            "FERROGATE_CF_API_TOKEN",
            "FERROGATE_D1_CONTROL_DATABASE_ID",
            "FERROGATE_D1_TENANT_DATABASE_ID",
            "FERROGATE_D1_TENANT_ID",
            "FERROGATE_D1_TENANT_DATABASE_ID_B",
            "FERROGATE_D1_TENANT_ID_B",
            "FERROGATE_D1_PROXY_BASE_URL",
            "FERROGATE_D1_PROXY_TOKEN",
        ],
    )?
    else {
        return Ok(());
    };
    let account_id = env.account_id();
    let control_dbid = env.var("FERROGATE_D1_CONTROL_DATABASE_ID");
    let tenant_a_dbid = env.var("FERROGATE_D1_TENANT_DATABASE_ID");
    let tenant_a = env.var("FERROGATE_D1_TENANT_ID");
    let tenant_b_dbid = env.var("FERROGATE_D1_TENANT_DATABASE_ID_B");
    let tenant_b = env.var("FERROGATE_D1_TENANT_ID_B");
    let proxy_base = env.var("FERROGATE_D1_PROXY_BASE_URL");

    let resolver = Arc::new(EnvTokenResolver::from_process_env());
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let cloudflare = CloudflareClient::new(config, resolver.clone())?;
    let d1 = D1Client::new(Arc::new(cloudflare));

    let proxy = D1ProxyClient::new(
        proxy_base,
        Arc::new(ReqwestTransport::new()?),
        resolver.clone(),
        "env://FERROGATE_D1_PROXY_TOKEN",
    );

    // Each tenant DB needs the usage/tenant_contexts tables independently
    // (database-per-tenant topology).
    apply_schema(&d1, &tenant_a_dbid).await?;
    apply_schema(&d1, &tenant_b_dbid).await?;

    let mut tenant_databases = BTreeMap::new();
    tenant_databases.insert(tenant_a.clone(), tenant_a_dbid.clone());
    tenant_databases.insert(tenant_b.clone(), tenant_b_dbid.clone());
    let registry = D1TenantDatabaseRegistry {
        control_database_id: control_dbid.clone(),
        tenant_databases,
    };
    let store = D1ControlPlaneStore::new(d1, registry).with_proxy_client(proxy.clone());
    let repos = Arc::new(RuntimeStorageRepositories::cloudflare_d1(store, 100));

    // Best-effort clean of any residue from a prior run.
    reset_usage_tables(&proxy, &tenant_a).await?;
    reset_usage_tables(&proxy, &tenant_b).await?;

    let result = exercise(&repos, &proxy, &tenant_a, &tenant_b).await;

    // Row cleanup regardless of outcome (operator tears down the DBs + Worker).
    let _ = reset_usage_tables(&proxy, &tenant_a).await;
    let _ = reset_usage_tables(&proxy, &tenant_b).await;
    result?;

    println!("{PROBE}: PASS");
    Ok(())
}

async fn apply_schema(d1: &D1Client, dbid: &str) -> Result<(), Box<dyn std::error::Error>> {
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
    println!("schema applied to {dbid}: {} statements", statements.len());
    Ok(())
}

/// Mirror of `tenant_database_binding`: uppercase, non-alnum -> `_`, `TENANT_DB_`
/// prefix — so the probe's own seed/reset SQL targets the same binding the store
/// derives internally.
fn tenant_binding(tenant_id: &str) -> String {
    let mut out = String::from("TENANT_DB_");
    for c in tenant_id.chars() {
        out.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    out
}

/// Wipe a tenant's usage rows through the proxy's tenant binding (the probe owns
/// the DB).
async fn reset_usage_tables(
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    for table in [
        "usage_monthly_rollups",
        "usage_metadata_rollups",
        "usage_aggregate_rollups",
        "tenant_contexts",
    ] {
        let stmt = D1ProxyStatement::with_params(format!("DELETE FROM {table}"), vec![]);
        proxy.query_on(Some(&binding), &stmt).await?;
    }
    Ok(())
}

/// Seed one monthly rollup row into a tenant's DB (the D1 backend does not run
/// the settlement rollup-increment maintenance, so the probe writes them).
async fn seed_monthly(
    proxy: &D1ProxyClient,
    tenant_id: &str,
    period_month: &str,
    scope_type: QuotaScopeKind,
    scope_id: &str,
    total_tokens: i64,
    cost_usd: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    let stmt = D1ProxyStatement::with_params(
        "INSERT INTO usage_monthly_rollups \
         (id, period_month, scope_type, scope_id, prompt_tokens, completion_tokens, \
          total_tokens, cost_usd, request_count, error_count, updated_at_unix) \
         VALUES (?, ?, ?, ?, ?, 0, ?, ?, 1, 0, unixepoch())",
        vec![
            usage_monthly_rollup_id(period_month, scope_type, scope_id),
            period_month.to_string(),
            scope_type.as_str().to_string(),
            scope_id.to_string(),
            total_tokens.to_string(),
            total_tokens.to_string(),
            cost_usd.to_string(),
        ],
    );
    proxy.query_on(Some(&binding), &stmt).await?;
    Ok(())
}

/// Seed one metadata rollup row into a tenant's DB.
async fn seed_metadata(
    proxy: &D1ProxyClient,
    tenant_id: &str,
    period_month: &str,
    organization_id: &str,
    metadata_key: &str,
    metadata_value: &str,
    total_tokens: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    let stmt = D1ProxyStatement::with_params(
        "INSERT INTO usage_metadata_rollups \
         (id, period_month, organization_id, metadata_key, metadata_value, prompt_tokens, \
          completion_tokens, total_tokens, cost_usd, request_count, error_count, updated_at_unix) \
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, 1, 0, unixepoch())",
        vec![
            usage_metadata_rollup_id(period_month, organization_id, metadata_key, metadata_value),
            period_month.to_string(),
            organization_id.to_string(),
            metadata_key.to_string(),
            metadata_value.to_string(),
            total_tokens.to_string(),
            total_tokens.to_string(),
        ],
    );
    proxy.query_on(Some(&binding), &stmt).await?;
    Ok(())
}

/// Read back a single durable `usage_aggregate_rollups.total_tokens` for the
/// given aggregate id on a tenant binding (proves the persist RMW landed).
async fn durable_aggregate_total(
    proxy: &D1ProxyClient,
    tenant_id: &str,
    aggregate_id: &str,
) -> Result<Option<i64>, Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    let stmt = D1ProxyStatement::with_params(
        "SELECT total_tokens FROM usage_aggregate_rollups WHERE id = ?".to_string(),
        vec![aggregate_id.to_string()],
    );
    let result = proxy.query_on(Some(&binding), &stmt).await?;
    Ok(result
        .results
        .first()
        .and_then(|row| row.get("total_tokens"))
        .and_then(serde_json::Value::as_i64))
}

fn aggregate(org: &str, total: u64) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: format!("{org}:proj-1:key-1:fast-chat:openai"),
        organization_id: Some(org.to_string()),
        project_id: Some("proj-1".into()),
        api_key_id: Some("key-1".into()),
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        usage: TokenUsage::new(total, 0, total),
    }
}

/// Correctness for the four #456 usage ops driven through the real store's async
/// tenant-DB path.
async fn exercise(
    repos: &RuntimeStorageRepositories,
    proxy: &D1ProxyClient,
    tenant_a: &str,
    tenant_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Seed monthly rollups spread across two tenant DBs, two months, three scope
    // types (so the fan-out re-merge order is observable).
    seed_monthly(
        proxy,
        tenant_a,
        PERIOD,
        QuotaScopeKind::Project,
        "proj-1",
        30,
        1.5,
    )
    .await?;
    seed_monthly(
        proxy,
        tenant_a,
        PRIOR,
        QuotaScopeKind::Tenant,
        tenant_a,
        5,
        0.1,
    )
    .await?;
    seed_monthly(
        proxy,
        tenant_b,
        PERIOD,
        QuotaScopeKind::Key,
        "key-1",
        7,
        0.2,
    )
    .await?;
    // Seed metadata rollups, one per tenant (organization_id = the owning tenant).
    seed_metadata(proxy, tenant_a, PERIOD, tenant_a, "customer", "cust-z", 3).await?;
    seed_metadata(proxy, tenant_b, PERIOD, tenant_b, "customer", "cust-a", 9).await?;
    println!("0 seeded monthly + metadata rollups across two tenant DBs");

    // 1) get_usage_monthly_rollup fans out and finds tenant A's project rollup.
    let got = repos
        .get_usage_monthly_rollup(QuotaScopeKind::Project, "proj-1", PERIOD)
        .await?
        .ok_or("project rollup not found via fan-out")?;
    if got.total_tokens != 30 || got.scope_type != QuotaScopeKind::Project {
        return Err(format!("get_usage_monthly_rollup mismatch: {got:?}").into());
    }
    println!("1 get_usage_monthly_rollup(project) -> fan-out found total=30");

    // 2) list_usage_monthly_rollups fans out and orders period DESC, scope ASC.
    let listed = repos.list_usage_monthly_rollups().await?;
    let order: Vec<(String, String, String)> = listed
        .iter()
        .map(|r| {
            (
                r.period_month.clone(),
                r.scope_type.as_str().to_string(),
                r.scope_id.clone(),
            )
        })
        .collect();
    let expected = vec![
        (PERIOD.to_string(), "key".to_string(), "key-1".to_string()),
        (
            PERIOD.to_string(),
            "project".to_string(),
            "proj-1".to_string(),
        ),
        (
            PRIOR.to_string(),
            "tenant".to_string(),
            tenant_a.to_string(),
        ),
    ];
    if order != expected {
        return Err(format!("list_usage_monthly_rollups order mismatch: {order:?}").into());
    }
    println!("2 list_usage_monthly_rollups -> cross-tenant union, period DESC/scope ASC");

    // 3) scoped metadata read routes to tenant A's own DB.
    let scoped = repos
        .list_usage_metadata_rollups("customer", Some(tenant_a))
        .await?;
    if scoped.len() != 1 || scoped[0].metadata_value != "cust-z" {
        return Err(format!("scoped metadata read mismatch: {scoped:?}").into());
    }
    println!("3 list_usage_metadata_rollups(Some(orgA)) -> routed to orgA DB");

    // 4) operator metadata view fans out, ordered metadata_value ASC in-month.
    let operator = repos.list_usage_metadata_rollups("customer", None).await?;
    let values: Vec<String> = operator
        .iter()
        .filter(|r| r.metadata_key == "customer")
        .map(|r| r.metadata_value.clone())
        .collect();
    if values != vec!["cust-a".to_string(), "cust-z".to_string()] {
        return Err(format!("operator metadata view order mismatch: {values:?}").into());
    }
    println!("4 list_usage_metadata_rollups(None) -> fan-out, metadata_value ASC");

    // 5) persist_usage_aggregate writes the durable rollup on tenant A; the REPLACE
    // upsert overwrites on a second call (last-writer-wins, mirroring Postgres).
    let agg = aggregate(tenant_a, 30);
    repos.replace_usage_aggregate(agg.clone()).await?;
    let first = durable_aggregate_total(proxy, tenant_a, &agg.id)
        .await?
        .ok_or("aggregate rollup missing after persist")?;
    if first != 30 {
        return Err(format!("persist_usage_aggregate total mismatch: {first}").into());
    }
    repos
        .replace_usage_aggregate(aggregate(tenant_a, 42))
        .await?;
    let replaced = durable_aggregate_total(proxy, tenant_a, &agg.id)
        .await?
        .ok_or("aggregate rollup missing after REPLACE")?;
    if replaced != 42 {
        return Err(format!("persist REPLACE did not overwrite: {replaced}").into());
    }
    println!("5 persist_usage_aggregate -> durable rollup 30 then REPLACE->42 on tenant A");

    // 6) persist for an org-less / unprovisioned aggregate is NotFound (no tenant
    // DB) — the database-per-tenant divergence from Postgres.
    match repos
        .replace_usage_aggregate(StoredUsageAggregate {
            organization_id: None,
            ..aggregate(tenant_a, 1)
        })
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => return Err(format!("org-less persist must NotFound, got {other:?}").into()),
    }
    match repos
        .replace_usage_aggregate(aggregate("gate456-ghost", 1))
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(format!("unprovisioned persist must NotFound, got {other:?}").into());
        }
    }
    let _ = tenant_b; // tenant B participates via the fan-out reads above.
    println!("6 persist on org-less/unprovisioned aggregate -> typed NotFound");

    Ok(())
}
