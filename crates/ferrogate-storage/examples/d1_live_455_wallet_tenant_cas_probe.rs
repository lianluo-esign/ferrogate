// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #455 tenant-scoped wallet CAS family.

//! Gate-owned live validation for the #455 slice: drive the REAL wallet
//! reserve/settle/release + wallet CRUD family of a `D1ControlPlaneStore`
//! **through a live deployed `workers/d1-proxy` Worker, routed onto a per-tenant
//! `[[d1_databases]]` binding** against a REAL Cloudflare D1 database. This is
//! the coverage the #455 landing commit flagged as Not-tested: the reserve
//! no-oversell guarded conditional insert, the settle/release CAS, and — the
//! keystone — reserve-no-oversell atomicity under REAL concurrency, none of
//! which the mocked-transport tests can prove.
//!
//! Unlike the account-global #454 guardrail family (which routes to the fixed
//! control `env.DB` binding), the wallet family is TENANT-SCOPED: it selects a
//! per-tenant binding (`TENANT_DB_<TENANT_ID>`) onto every `/d1/batch` +
//! `/d1/query`. So this probe REQUIRES the operator to deploy a `workers/d1-proxy`
//! bound to BOTH a control probe D1 (binding `DB`) and a tenant probe D1
//! (binding `TENANT_DB_<TENANT_ID>` for this probe's `--tenant`), seed
//! `D1_PROXY_TOKEN`, and hand this probe the two database uuids + Worker origin +
//! token. The probe applies the schema idempotently to both, runs the wallet CAS
//! chain (single-writer correctness + a 10-way concurrent no-oversell burst),
//! proves the #450/#454 control-DB path still commits with the new `database`
//! field present, cleans its own rows, and leaves the DBs + Worker for the
//! operator to tear down (operator directive: no lingering CF resources).
//!
//! Opt-in only. Required env:
//!   FERROGATE_CF_ACCOUNT_ID          - account for the REST D1 client
//!   FERROGATE_CF_API_TOKEN           - REST bearer (resolved via env://)
//!   FERROGATE_D1_CONTROL_DATABASE_ID - uuid of the control D1 (Worker binding DB)
//!   FERROGATE_D1_TENANT_DATABASE_ID  - uuid of the tenant D1 (Worker binding TENANT_DB_<ID>)
//!   FERROGATE_D1_TENANT_ID           - tenant id whose binding was added (e.g. gate455acme)
//!   FERROGATE_D1_PROXY_BASE_URL      - deployed Worker origin (https://...workers.dev)
//!   FERROGATE_D1_PROXY_TOKEN         - Worker bearer (resolved via env://)
//!
//! SKIPS cleanly (prints a notice, exits 0) when FERROGATE_CF_ACCOUNT_ID is
//! unset, so running this without credentials is a no-op rather than a failure.
//! With it set but another required variable missing the probe hard-errors: a
//! half-configured environment is an operator mistake, not an opt-out
//! (`support/probe_env.rs`, #495).
//! Run: cargo run -p ferrogate-storage --example d1_live_455_wallet_tenant_cas_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    D1ControlPlaneStore, D1TenantDatabaseRegistry, RuntimeStorageRepositories, StorageError,
    StoredWallet, WalletReservationResult,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_455_wallet_tenant_cas_probe";

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
            "FERROGATE_D1_PROXY_BASE_URL",
            "FERROGATE_D1_PROXY_TOKEN",
        ],
    )?
    else {
        return Ok(());
    };
    let account_id = env.account_id();
    let control_dbid = env.var("FERROGATE_D1_CONTROL_DATABASE_ID");
    let tenant_dbid = env.var("FERROGATE_D1_TENANT_DATABASE_ID");
    let tenant_id = env.var("FERROGATE_D1_TENANT_ID");
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

    // Apply the shipped schema idempotently to BOTH probe databases over the REST
    // /query surface (each D1 DB needs the wallets/reservations/settlements +
    // guardrail tables independently in the database-per-tenant topology).
    apply_schema(&d1, &control_dbid).await?;
    apply_schema(&d1, &tenant_dbid).await?;

    // The store the CLI builds, but with the proxy bound AND the tenant registered
    // so `tenant_proxy_binding(tenant_id)` resolves to TENANT_DB_<ID> (production
    // wires this from the provisioner's tenant->database registry).
    let mut tenant_databases = BTreeMap::new();
    tenant_databases.insert(tenant_id.clone(), tenant_dbid.clone());
    let registry = D1TenantDatabaseRegistry {
        control_database_id: control_dbid.clone(),
        tenant_databases,
    };
    let store = D1ControlPlaneStore::new(d1, registry).with_proxy_client(proxy.clone());
    let repos = Arc::new(RuntimeStorageRepositories::cloudflare_d1(store, 100));

    // Best-effort clean of any residue from a prior run so assertions start from a
    // known floor (the probe owns these two probe DBs exclusively).
    reset_wallet_tables(&proxy, &tenant_id).await?;

    let result = exercise(&repos, &tenant_id).await;
    let concurrency = match &result {
        Ok(()) => concurrency_burst(&repos, &proxy, &tenant_id).await,
        Err(_) => Ok(()),
    };
    let control = match (&result, &concurrency) {
        (Ok(()), Ok(())) => control_db_path_unchanged(&proxy).await,
        _ => Ok(()),
    };
    // Row cleanup regardless of outcome (operator tears down the DBs + Worker; we
    // leave the tables empty).
    let _ = reset_wallet_tables(&proxy, &tenant_id).await;
    result?;
    concurrency?;
    control?;

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

/// Wipe this tenant's wallet rows through the proxy's tenant binding (the probe
/// owns the DB). Settlements/reservations first (children), then the wallet.
async fn reset_wallet_tables(
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    for table in ["wallet_settlements", "wallet_reservations", "wallets"] {
        let stmt = D1ProxyStatement::with_params(format!("DELETE FROM {table}"), vec![]);
        proxy.query_on(Some(&binding), &stmt).await?;
    }
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

fn wallet(tenant_id: &str, balance: i64, now: i64) -> StoredWallet {
    StoredWallet {
        id: tenant_id.to_string(),
        tenant_id: tenant_id.to_string(),
        balance_credits: balance,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: now,
        updated_at_unix: now,
    }
}

/// Single-writer correctness: the reserve/settle/release state machine + the
/// NoWallet/Insufficient/NotFound edges, all driven through the real store's
/// async tenant-DB path.
async fn exercise(
    repos: &RuntimeStorageRepositories,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_800_000_000;
    let ttl = now + 3_600;

    // 1) upsert + read-back the wallet through the tenant binding.
    repos.upsert_wallet(wallet(tenant_id, 1000, now)).await?;
    let w = repos
        .get_wallet(tenant_id)
        .await?
        .ok_or("wallet read-back returned none after upsert")?;
    if w.balance_credits != 1000 {
        return Err(format!("expected balance 1000, got {}", w.balance_credits).into());
    }
    println!("1 upsert_wallet -> get_wallet balance=1000 (tenant binding)");

    // 2) reserve 600 -> admitted (available 1000).
    let r1 = repos
        .reserve_wallet_credits("gate455-r1", tenant_id, 600, ttl, now)
        .await?;
    expect_reserved(&r1, 600)?;
    println!("2 reserve r1=600 -> Reserved (guarded conditional insert)");

    // 3) reserve another 600 -> Insufficient: available is 400 (1000 - 600 hold).
    let r2 = repos
        .reserve_wallet_credits("gate455-r2", tenant_id, 600, ttl, now)
        .await?;
    match r2 {
        WalletReservationResult::Insufficient {
            available_credits,
            requested_credits,
        } if available_credits == 400 && requested_credits == 600 => {}
        other => {
            return Err(format!("expected Insufficient(avail 400, req 600), got {other:?}").into())
        }
    }
    println!("3 reserve r2=600 -> Insufficient(available=400) (NO OVERSELL)");

    // 4) idempotent replay of r1 -> the same hold, no double-count.
    let r1b = repos
        .reserve_wallet_credits("gate455-r1", tenant_id, 600, ttl, now)
        .await?;
    expect_reserved(&r1b, 600)?;
    println!("4 reserve r1 replay -> Reserved (idempotent, same hold)");

    // 5) reserve exactly the remaining 400 -> admitted (available now 0).
    let r3 = repos
        .reserve_wallet_credits("gate455-r3", tenant_id, 400, ttl, now)
        .await?;
    expect_reserved(&r3, 400)?;
    println!("5 reserve r3=400 -> Reserved (exact-fit, available now 0)");

    // 6) reserve 1 more -> Insufficient(available 0): the guard admits nothing.
    let r4 = repos
        .reserve_wallet_credits("gate455-r4", tenant_id, 1, ttl, now)
        .await?;
    match r4 {
        WalletReservationResult::Insufficient {
            available_credits: 0,
            ..
        } => {}
        other => return Err(format!("expected Insufficient(available=0), got {other:?}").into()),
    }
    println!("6 reserve r4=1 -> Insufficient(available=0)");

    // 7) settle r1 -> real debit + ledger row; balance 1000 -> 400.
    let s1 = repos
        .settle_wallet_reservation("gate455-r1", now + 10)
        .await?;
    if !s1.newly_applied {
        return Err("first settle of r1 must be newly_applied".into());
    }
    if s1.settlement.delta_credits != -600 || s1.settlement.balance_after_credits != Some(400) {
        return Err(format!("settle ledger mismatch: {:?}", s1.settlement).into());
    }
    println!("7 settle r1 -> debit -600, balance_after=400, ledger row (atomic batch)");

    // 8) settle replay -> idempotent, returns the first settlement.
    let s1b = repos
        .settle_wallet_reservation("gate455-r1", now + 20)
        .await?;
    if s1b.newly_applied {
        return Err("settle replay of r1 must NOT be newly_applied".into());
    }
    if s1b.settlement.delta_credits != -600 {
        return Err(format!("settle replay ledger mismatch: {:?}", s1b.settlement).into());
    }
    println!("8 settle r1 replay -> newly_applied=false (idempotent capture)");

    // 9) release r3 (the active 400 hold) -> credits restored to available.
    let rel = repos
        .release_wallet_reservation("gate455-r3", now + 30)
        .await?;
    if rel.status != "released" {
        return Err(format!("expected released status, got {}", rel.status).into());
    }
    println!("9 release r3 -> released (guarded CAS restores available credits)");

    // 10) release replay -> idempotent.
    let rel2 = repos
        .release_wallet_reservation("gate455-r3", now + 40)
        .await?;
    if rel2.status != "released" {
        return Err(format!("release replay expected released, got {}", rel2.status).into());
    }
    println!("10 release r3 replay -> released (idempotent)");

    // 11) settle a released hold -> typed Conflict.
    match repos
        .settle_wallet_reservation("gate455-r3", now + 50)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => return Err(format!("settle(released) must Conflict, got {other:?}").into()),
    }
    println!("11 settle(released r3) -> typed Conflict");

    // 12) balance reflects only the settled debit: 1000 - 600 = 400.
    let w2 = repos
        .get_wallet(tenant_id)
        .await?
        .ok_or("wallet gone after settle/release")?;
    if w2.balance_credits != 400 {
        return Err(format!(
            "expected balance 400 after settle, got {}",
            w2.balance_credits
        )
        .into());
    }
    println!("12 get_wallet -> balance=400 (only the settled hold debited)");

    // 13) unprovisioned tenant: reserve -> NotFound (no binding), get_wallet -> None.
    match repos
        .reserve_wallet_credits("ghost-r", "gate455-ghost", 1, ttl, now)
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(
                format!("reserve on unprovisioned tenant must NotFound, got {other:?}").into(),
            )
        }
    }
    if repos.get_wallet("gate455-ghost").await?.is_some() {
        return Err("unprovisioned tenant get_wallet must be None".into());
    }
    println!("13 unprovisioned tenant -> reserve NotFound, get_wallet None");

    Ok(())
}

/// The keystone: fire N concurrent reserves against a balance that affords only
/// N-1, and prove exactly N-1 are admitted (no oversell) against a REAL D1
/// database — the guarantee mocked transport cannot exercise.
async fn concurrency_burst(
    repos: &Arc<RuntimeStorageRepositories>,
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    reset_wallet_tables(proxy, tenant_id).await?;
    let now = 1_800_100_000;
    let ttl = now + 3_600;
    // Balance 1000, each reserve 200 -> exactly 5 fit, 5 must be rejected.
    repos.upsert_wallet(wallet(tenant_id, 1000, now)).await?;

    let n = 10;
    let per = 200;
    let mut handles = Vec::new();
    for i in 0..n {
        let repos = Arc::clone(repos);
        let tenant = tenant_id.to_string();
        handles.push(tokio::spawn(async move {
            repos
                .reserve_wallet_credits(&format!("gate455-c{i}"), &tenant, per, ttl, now)
                .await
        }));
    }

    let mut reserved = 0;
    let mut insufficient = 0;
    for handle in handles {
        match handle.await?? {
            WalletReservationResult::Reserved(_) => reserved += 1,
            WalletReservationResult::Insufficient { .. } => insufficient += 1,
            WalletReservationResult::NoWallet => return Err("wallet exists".into()),
        }
    }
    if reserved != 5 || insufficient != 5 {
        return Err(format!(
            "concurrent no-oversell violated: {reserved} admitted, {insufficient} rejected (want 5/5)"
        )
        .into());
    }

    // Ground truth: the admitted holds sum to EXACTLY the balance, never more.
    let holds = repos.list_wallet_reservations(tenant_id).await?;
    let active_sum: i64 = holds
        .iter()
        .filter(|h| h.status == "active")
        .map(|h| h.amount_credits)
        .sum();
    if active_sum != 1000 {
        return Err(format!("active holds sum {active_sum} != balance 1000 (oversold!)").into());
    }
    println!(
        "CONCURRENCY: 10 parallel reserves of 200 vs balance 1000 -> exactly 5 admitted, 5 rejected; active holds sum=1000 (NO OVERSELL under real concurrency)"
    );
    Ok(())
}

/// Acceptance box: the #450/#454 control-DB path still commits with the new
/// optional `database` field present in the Worker. Drive an atomic batch AND a
/// single query against the control database with `database == None` (omitted on
/// the wire), proving the Worker's default branch still targets `env.DB`.
async fn control_db_path_unchanged(
    proxy: &D1ProxyClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let marker = "gate455-control-marker";
    // Atomic batch on the control DB (database omitted): insert a guardrail
    // revision row + read it back.
    let batch = vec![
        D1ProxyStatement::with_params(
            "INSERT INTO guardrail_policy_revisions \
             (policy_id, revision, immutable_id, created_at_unix, created_by, revision_json) \
             VALUES (?, 1, ?, 1800000000, 'gate', '{}') \
             ON CONFLICT (policy_id, revision) DO NOTHING"
                .to_string(),
            vec![marker.to_string(), marker.to_string()],
        ),
        D1ProxyStatement::with_params(
            "SELECT immutable_id FROM guardrail_policy_revisions WHERE policy_id = ?".to_string(),
            vec![marker.to_string()],
        ),
    ];
    let results = proxy.batch(&batch).await?;
    if results.len() != 2 || results[1].results.is_empty() {
        return Err("control-DB batch (database=None) did not commit/read back".into());
    }
    // Single query on the control DB (database omitted): delete it, RETURNING the id.
    let del = D1ProxyStatement::with_params(
        "DELETE FROM guardrail_policy_revisions WHERE policy_id = ? RETURNING immutable_id"
            .to_string(),
        vec![marker.to_string()],
    );
    let deleted = proxy.query(&del).await?;
    if deleted.results.is_empty() {
        return Err("control-DB query (database=None) RETURNING was empty".into());
    }
    println!(
        "CONTROL PATH: /d1/batch + /d1/query with `database` omitted still commit on env.DB (#450/#454 path unchanged)"
    );
    Ok(())
}

fn expect_reserved(
    result: &WalletReservationResult,
    amount: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        WalletReservationResult::Reserved(r) if r.amount_credits == amount => Ok(()),
        other => Err(format!("expected Reserved({amount}), got {other:?}").into()),
    }
}
