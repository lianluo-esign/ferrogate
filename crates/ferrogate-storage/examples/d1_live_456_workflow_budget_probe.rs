// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #456/#279 tenant-scoped workflow-run budget family.

//! Gate-owned live validation for the #456 workflow-run budget slice: drive the
//! REAL `open`/`debit`/`topup`/`get`/`list` ops of a `D1ControlPlaneStore`
//! **through a live deployed `workers/d1-proxy` Worker, routed onto per-tenant
//! `[[d1_databases]]` bindings** against REAL Cloudflare D1 databases. This is the
//! coverage the #456 landing commit flags as Not-tested:
//!
//! - the `open` idempotent insert-then-reload batch (re-open fixes caps),
//! - `debit`'s optimistic-CAS commit + monotonic accumulation + fail-closed
//!   `Exceeded` flip + already-exhausted rejection,
//! - `topup`'s resumable-after-exhaustion reactivation,
//! - the id-only `get`/`debit`/`topup` fan-out locating the CORRECT tenant DB
//!   across TWO tenants, and `list` routing to the owning tenant DB,
//! - and — the property the mocked-transport tests cannot prove against the real
//!   proxy CAS — a CONCURRENT-debit race: N parallel debits against a tool-call
//!   budget of K let EXACTLY K through (`Applied`), no overspend, the same
//!   no-oversell guarantee the Postgres `SELECT ... FOR UPDATE` gives, here from
//!   the read->guarded-`UPDATE ... RETURNING`->retry loop under the SQLite
//!   per-database writer serialization.
//!
//! The family is TENANT-SCOPED (like #455): every op selects a per-tenant binding
//! (`TENANT_DB_<TENANT_ID>`); the id-only ops fan out over ALL provisioned tenant
//! bindings. So this probe REQUIRES the operator to deploy a `workers/d1-proxy`
//! bound to a control probe D1 (binding `DB`) and TWO tenant probe D1s
//! (`TENANT_DB_<TENANT_A>` + `TENANT_DB_<TENANT_B>`), seed `D1_PROXY_TOKEN`, and
//! hand this probe the three database uuids + tenant ids + Worker origin + token.
//! It reuses the SAME env vars as `d1_live_456_wallet_ops_probe`. The probe
//! applies the schema idempotently to both tenant DBs, exercises the ops, cleans
//! its own rows, and leaves the DBs + Worker for the operator to tear down
//! (operator directive: no lingering CF resources).
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
//! Run: cargo run -p ferrogate-storage --example d1_live_456_workflow_budget_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    workflow_run_budget_id, D1ControlPlaneStore, D1TenantDatabaseRegistry,
    RuntimeStorageRepositories, WorkflowBudgetDebit, WorkflowBudgetDimension,
    WorkflowRunBudgetCaps, WORKFLOW_RUN_BUDGET_ACTIVE, WORKFLOW_RUN_BUDGET_EXHAUSTED,
};

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");

/// The wall-clock deadline every non-deadline scenario uses: far in the future so
/// only the spend counters (not the clock) can breach.
const FAR_FUTURE_DEADLINE: i64 = 4_000_000_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

fn required(var: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(var).map_err(|_| format!("{var} is required (live probe is opt-in)").into())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let account_id = required("FERROGATE_CF_ACCOUNT_ID")?;
    let control_dbid = required("FERROGATE_D1_CONTROL_DATABASE_ID")?;
    let tenant_a_dbid = required("FERROGATE_D1_TENANT_DATABASE_ID")?;
    let tenant_a = required("FERROGATE_D1_TENANT_ID")?;
    let tenant_b_dbid = required("FERROGATE_D1_TENANT_DATABASE_ID_B")?;
    let tenant_b = required("FERROGATE_D1_TENANT_ID_B")?;
    let proxy_base = required("FERROGATE_D1_PROXY_BASE_URL")?;
    required("FERROGATE_D1_PROXY_TOKEN")?;

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

    // Each tenant DB needs the workflow_run_budgets table independently
    // (database-per-tenant topology).
    apply_schema(&d1, &tenant_a_dbid).await?;
    apply_schema(&d1, &tenant_b_dbid).await?;

    // The store the CLI builds, with the proxy bound AND both tenants registered
    // so `tenant_proxy_binding` resolves the derived bindings and the id-only ops
    // fan out over both tenant databases.
    let mut tenant_databases = BTreeMap::new();
    tenant_databases.insert(tenant_a.clone(), tenant_a_dbid.clone());
    tenant_databases.insert(tenant_b.clone(), tenant_b_dbid.clone());
    let registry = D1TenantDatabaseRegistry {
        control_database_id: control_dbid.clone(),
        tenant_databases,
    };
    let store = D1ControlPlaneStore::new(d1, registry).with_proxy_client(proxy.clone());
    let repos = Arc::new(RuntimeStorageRepositories::cloudflare_d1(store, 100));

    // Best-effort clean of any residue from a prior run (the probe owns these two
    // tenant DBs exclusively).
    reset_workflow_budgets(&proxy, &tenant_a).await?;
    reset_workflow_budgets(&proxy, &tenant_b).await?;

    let result = exercise(&repos, &tenant_a, &tenant_b).await;

    // Row cleanup regardless of outcome (operator tears down the DBs + Worker).
    let _ = reset_workflow_budgets(&proxy, &tenant_a).await;
    let _ = reset_workflow_budgets(&proxy, &tenant_b).await;
    result?;

    println!("d1_live_456_workflow_budget_probe: PASS");
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

/// Wipe a tenant's workflow-budget rows through the proxy's tenant binding (the
/// probe owns the DB).
async fn reset_workflow_budgets(
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    let stmt =
        D1ProxyStatement::with_params("DELETE FROM workflow_run_budgets".to_string(), vec![]);
    proxy.query_on(Some(&binding), &stmt).await?;
    Ok(())
}

/// Mirror of `tenant_database_binding`: uppercase, non-alnum -> `_`, `TENANT_DB_`
/// prefix. Kept here so the probe's own reset SQL targets the same binding the
/// store derives internally.
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

/// Single-writer correctness for open/debit/topup/get/list + the multi-writer
/// no-overspend race, driven through the real store's async tenant-DB path.
async fn exercise(
    repos: &Arc<RuntimeStorageRepositories>,
    tenant_a: &str,
    tenant_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_800_000_000;
    let run_a_id = workflow_run_budget_id("wf-invoice", 1, "run-a");
    let run_b_id = workflow_run_budget_id("wf-report", 2, "run-b");

    // 1) open on tenant A (cost cap 1000, tool-call cap 3), idempotent re-open
    //    fixes the caps (a wider re-declare is ignored).
    let opened = repos
        .open_workflow_run_budget(
            "wf-invoice",
            1,
            "run-a",
            tenant_a,
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(1000),
                token_budget: None,
                tool_call_budget: Some(3),
                wall_clock_deadline_unix: Some(FAR_FUTURE_DEADLINE),
            },
            now,
        )
        .await?;
    if opened.id != run_a_id
        || opened.cost_budget_credits != Some(1000)
        || opened.spent_credits != 0
    {
        return Err(format!("open mismatch: {opened:?}").into());
    }
    let reopened = repos
        .open_workflow_run_budget(
            "wf-invoice",
            1,
            "run-a",
            tenant_a,
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(9_999_999), // wider re-declare, MUST be ignored
                ..WorkflowRunBudgetCaps::default()
            },
            now + 1,
        )
        .await?;
    if reopened.cost_budget_credits != Some(1000) {
        return Err(format!("re-open widened an in-flight run's caps: {reopened:?}").into());
    }
    println!("1 open (tenant A) idempotent, caps fixed at first open");

    // 2) a SECOND run on tenant B — proves the id-only fan-out locates the right DB.
    repos
        .open_workflow_run_budget(
            "wf-report",
            2,
            "run-b",
            tenant_b,
            WorkflowRunBudgetCaps {
                token_budget: Some(500),
                ..WorkflowRunBudgetCaps::default()
            },
            now,
        )
        .await?;
    println!("2 open (tenant B) — a second run in a different tenant DB");

    // 3) debit accumulates monotonically (600 then 300 credits, 1 tool call each).
    match repos
        .debit_workflow_run_budget(&run_a_id, 600, 0, 1, now + 10)
        .await?
    {
        WorkflowBudgetDebit::Applied(b) if b.spent_credits == 600 && b.spent_tool_calls == 1 => {}
        other => return Err(format!("first debit mismatch: {other:?}").into()),
    }
    match repos
        .debit_workflow_run_budget(&run_a_id, 300, 0, 1, now + 20)
        .await?
    {
        WorkflowBudgetDebit::Applied(b) if b.spent_credits == 900 && b.spent_tool_calls == 2 => {}
        other => return Err(format!("second debit mismatch: {other:?}").into()),
    }
    println!("3 debit accumulates: 600 + 300 = 900 credits, 2 tool calls (optimistic-CAS commit)");

    // 4) id-only get/debit fan out to the CORRECT tenant DB across A and B.
    let got_a = repos
        .get_workflow_run_budget(&run_a_id)
        .await?
        .ok_or("run A vanished")?;
    let got_b = repos
        .get_workflow_run_budget(&run_b_id)
        .await?
        .ok_or("run B vanished")?;
    if got_a.tenant_id != tenant_a || got_b.tenant_id != tenant_b {
        return Err(format!(
            "id-only fan-out located the wrong tenant DB: A={:?} B={:?}",
            got_a.tenant_id, got_b.tenant_id
        )
        .into());
    }
    println!("4 get by id fans out to the correct tenant DB (A -> {tenant_a}, B -> {tenant_b})");

    // 5) a debit that would breach the cost cap is fail-closed Exceeded (no spend),
    //    flips to exhausted; a further debit stays Exceeded (already exhausted).
    match repos
        .debit_workflow_run_budget(&run_a_id, 500, 0, 0, now + 30)
        .await?
    {
        WorkflowBudgetDebit::Exceeded { dimension, budget } => {
            if dimension != WorkflowBudgetDimension::Cost
                || budget.status != WORKFLOW_RUN_BUDGET_EXHAUSTED
                || budget.spent_credits != 900
            {
                return Err(format!("exceeded mismatch: {dimension:?} {budget:?}").into());
            }
        }
        other => return Err(format!("cost breach must be Exceeded, got {other:?}").into()),
    }
    match repos
        .debit_workflow_run_budget(&run_a_id, 1, 0, 0, now + 40)
        .await?
    {
        WorkflowBudgetDebit::Exceeded { .. } => {}
        other => return Err(format!("exhausted run must reject, got {other:?}").into()),
    }
    println!("5 cost breach -> fail-closed Exceeded(Cost), run exhausted, no spend applied");

    // 6) top-up raises the cap and reactivates: the run resumes (Applied again).
    let topped = repos
        .topup_workflow_run_budget(&run_a_id, 1000, 0, 5, None, now + 50)
        .await?;
    if topped.status != WORKFLOW_RUN_BUDGET_ACTIVE || topped.cost_budget_credits != Some(2000) {
        return Err(format!("topup mismatch: {topped:?}").into());
    }
    match repos
        .debit_workflow_run_budget(&run_a_id, 500, 0, 1, now + 60)
        .await?
    {
        WorkflowBudgetDebit::Applied(b) if b.spent_credits == 1400 => {}
        other => return Err(format!("resumed debit mismatch: {other:?}").into()),
    }
    println!("6 top-up (+1000 cost) reactivates -> resumable, debit Applied again");

    // 7) list routes to the owning tenant DB (A has run-a; B has run-b).
    let list_a = repos.list_workflow_run_budgets(tenant_a).await?;
    let list_b = repos.list_workflow_run_budgets(tenant_b).await?;
    if !list_a.iter().any(|b| b.id == run_a_id) || list_a.iter().any(|b| b.id == run_b_id) {
        return Err(format!("list(A) should carry only run A: {list_a:?}").into());
    }
    if !list_b.iter().any(|b| b.id == run_b_id) || list_b.iter().any(|b| b.id == run_a_id) {
        return Err(format!("list(B) should carry only run B: {list_b:?}").into());
    }
    println!(
        "7 list routes to the owning tenant DB (A={} B={})",
        list_a.len(),
        list_b.len()
    );

    // 8) the keystone: N CONCURRENT debits against a tool-call budget of K let
    //    EXACTLY K through — no overspend, the optimistic-CAS no-oversell proof the
    //    mocked-transport tests cannot exercise against the real proxy.
    const K: i64 = 5;
    const N: usize = 24;
    repos
        .open_workflow_run_budget(
            "wf-fanout",
            1,
            "run-race",
            tenant_a,
            WorkflowRunBudgetCaps {
                tool_call_budget: Some(K),
                wall_clock_deadline_unix: Some(FAR_FUTURE_DEADLINE),
                ..WorkflowRunBudgetCaps::default()
            },
            now,
        )
        .await?;
    let race_id = workflow_run_budget_id("wf-fanout", 1, "run-race");

    let mut handles = Vec::with_capacity(N);
    for step in 0..N {
        let repos = Arc::clone(repos);
        let id = race_id.clone();
        handles.push(tokio::spawn(async move {
            repos
                .debit_workflow_run_budget(&id, 0, 0, 1, now + 100 + step as i64)
                .await
        }));
    }
    let mut applied = 0i64;
    let mut exceeded = 0usize;
    for handle in handles {
        match handle.await? {
            Ok(WorkflowBudgetDebit::Applied(_)) => applied += 1,
            Ok(WorkflowBudgetDebit::Exceeded { .. }) => exceeded += 1,
            Err(error) => return Err(format!("concurrent debit errored: {error}").into()),
        }
    }
    if applied != K || exceeded != N - K as usize {
        return Err(format!(
            "no-oversell violated: {applied} Applied / {exceeded} Exceeded (expected {K}/{})",
            N - K as usize
        )
        .into());
    }
    let final_race = repos
        .get_workflow_run_budget(&race_id)
        .await?
        .ok_or("race run vanished")?;
    if final_race.spent_tool_calls != K {
        return Err(format!(
            "durable overspend: spent_tool_calls={} (expected {K})",
            final_race.spent_tool_calls
        )
        .into());
    }
    println!(
        "8 {N} concurrent debits vs tool-call budget {K} -> EXACTLY {K} Applied, {exceeded} \
         Exceeded, durable spent={K} (no overspend)"
    );

    Ok(())
}
