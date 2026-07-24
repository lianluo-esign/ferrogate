// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #456 tenant-scoped wallet balance/dunning/list ops.

//! Gate-owned live validation for the #456 slice: drive the REAL wallet
//! `settle_wallet_balance` / `adjust_wallet_balance` / `set_wallet_dunning` /
//! `list_wallets` ops of a `D1ControlPlaneStore` **through a live deployed
//! `workers/d1-proxy` Worker, routed onto per-tenant `[[d1_databases]]`
//! bindings** against REAL Cloudflare D1 databases. This is the coverage the
//! #456 landing commit flags as Not-tested: the `settle_wallet_balance`
//! claim-and-debit atomic batch (idempotent replay, records-without-wallet), the
//! `adjust`/`set_dunning` single-statement mutations, and — the divergence from
//! the account-global families — `list_wallets` fanning out across TWO tenant
//! databases and ordering the union, none of which the mocked-transport tests
//! can prove against the real proxy binding.
//!
//! The wallet family is TENANT-SCOPED (like #455): every op selects a per-tenant
//! binding (`TENANT_DB_<TENANT_ID>`). `list_wallets` fans out over ALL provisioned
//! tenant bindings, so this probe REQUIRES the operator to deploy a
//! `workers/d1-proxy` bound to a control probe D1 (binding `DB`) and TWO tenant
//! probe D1s (`TENANT_DB_<TENANT_A>` + `TENANT_DB_<TENANT_B>`), seed
//! `D1_PROXY_TOKEN`, and hand this probe the three database uuids + tenant ids +
//! Worker origin + token. The probe applies the schema idempotently to both
//! tenant DBs, exercises the four ops (single-writer correctness + idempotent
//! settlement replay + cross-tenant list), cleans its own rows, and leaves the
//! DBs + Worker for the operator to tear down (operator directive: no lingering
//! CF resources).
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
//! Run: cargo run -p ferrogate-storage --example d1_live_456_wallet_ops_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    D1ControlPlaneStore, D1TenantDatabaseRegistry, RuntimeStorageRepositories, StorageError,
    StoredWallet,
};

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");

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

    // Each tenant DB needs the wallets/reservations/settlements tables
    // independently (database-per-tenant topology).
    apply_schema(&d1, &tenant_a_dbid).await?;
    apply_schema(&d1, &tenant_b_dbid).await?;

    // The store the CLI builds, but with the proxy bound AND both tenants
    // registered so `tenant_proxy_binding` resolves the derived bindings and
    // `list_wallets` fans out over both tenant databases.
    let mut tenant_databases = BTreeMap::new();
    tenant_databases.insert(tenant_a.clone(), tenant_a_dbid.clone());
    tenant_databases.insert(tenant_b.clone(), tenant_b_dbid.clone());
    let registry = D1TenantDatabaseRegistry {
        control_database_id: control_dbid.clone(),
        tenant_databases,
    };
    let store = D1ControlPlaneStore::new(d1, registry).with_proxy_client(proxy.clone());
    let repos = Arc::new(RuntimeStorageRepositories::cloudflare_d1(store, 100));

    // Best-effort clean of any residue from a prior run so assertions start from
    // a known floor (the probe owns these two tenant DBs exclusively).
    reset_wallet_tables(&proxy, &tenant_a).await?;
    reset_wallet_tables(&proxy, &tenant_b).await?;

    let result = exercise(&repos, &tenant_a, &tenant_b).await;

    // Row cleanup regardless of outcome (operator tears down the DBs + Worker; we
    // leave the tables empty).
    let _ = reset_wallet_tables(&proxy, &tenant_a).await;
    let _ = reset_wallet_tables(&proxy, &tenant_b).await;
    result?;

    println!("d1_live_456_wallet_ops_probe: PASS");
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

/// Wipe a tenant's wallet rows through the proxy's tenant binding (the probe owns
/// the DB). Settlements/reservations first (children), then the wallet.
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

/// Single-writer correctness for the four #456 ops driven through the real store's
/// async tenant-DB path.
async fn exercise(
    repos: &RuntimeStorageRepositories,
    tenant_a: &str,
    tenant_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_800_000_000;

    // Seed both tenant wallets (upsert lands on each tenant binding).
    repos.upsert_wallet(wallet(tenant_a, 1000, now)).await?;
    repos.upsert_wallet(wallet(tenant_b, 5000, now)).await?;
    println!("0 seeded wallets: {tenant_a}=1000, {tenant_b}=5000");

    // 1) settle_wallet_balance debit: 1000 -> 400, ledger row records the delta.
    let s1 = repos
        .settle_wallet_balance("gate456-pay-1", tenant_a, -600, now + 10)
        .await?;
    if !s1.newly_applied
        || s1.settlement.delta_credits != -600
        || s1.settlement.balance_after_credits != Some(400)
    {
        return Err(format!("settle debit mismatch: {:?}", s1).into());
    }
    println!("1 settle_wallet_balance -600 -> newly_applied, balance_after=400");

    // 2) idempotent replay -> first outcome, no double debit.
    let s1b = repos
        .settle_wallet_balance("gate456-pay-1", tenant_a, -600, now + 20)
        .await?;
    if s1b.newly_applied || s1b.settlement.balance_after_credits != Some(400) {
        return Err(format!("settle replay mismatch: {:?}", s1b).into());
    }
    println!("2 settle replay -> newly_applied=false (idempotent, no re-debit)");

    // 3) replay with a changed amount -> typed Conflict.
    match repos
        .settle_wallet_balance("gate456-pay-1", tenant_a, -700, now + 25)
        .await
    {
        Err(StorageError::Conflict(_)) => {}
        other => return Err(format!("changed-amount replay must Conflict, got {other:?}").into()),
    }
    println!("3 settle replay w/ changed amount -> typed Conflict");

    // 4) balance reflects ONLY the settled debit (replay did not double-apply).
    let after = repos
        .get_wallet(tenant_a)
        .await?
        .ok_or("tenant_a wallet vanished")?;
    if after.balance_credits != 400 {
        return Err(format!(
            "expected balance 400 after settle, got {}",
            after.balance_credits
        )
        .into());
    }
    println!("4 get_wallet({tenant_a}) -> balance=400 (only the settled debit)");

    // 5) adjust_wallet_balance top-up: 400 -> 900, returns the post-update row.
    let adjusted = repos
        .adjust_wallet_balance(tenant_a, 500, now + 30)
        .await?
        .ok_or("adjust returned None for an existing wallet")?;
    if adjusted.balance_credits != 900 {
        return Err(format!(
            "expected balance 900 after adjust, got {}",
            adjusted.balance_credits
        )
        .into());
    }
    println!("5 adjust_wallet_balance +500 -> balance=900");

    // 6) set_wallet_dunning true -> false round-trips through the 0/1 affinity.
    repos.set_wallet_dunning(tenant_a, true, now + 40).await?;
    let dunned = repos
        .get_wallet(tenant_a)
        .await?
        .ok_or("tenant_a wallet vanished after set_dunning")?;
    if !dunned.dunning {
        return Err("set_wallet_dunning(true) did not persist".into());
    }
    repos.set_wallet_dunning(tenant_a, false, now + 50).await?;
    let undunned = repos
        .get_wallet(tenant_a)
        .await?
        .ok_or("tenant_a wallet vanished")?;
    if undunned.dunning {
        return Err("set_wallet_dunning(false) did not clear".into());
    }
    println!("6 set_wallet_dunning true->false round-trips (0/1 affinity)");

    // 7) list_wallets fans out over BOTH tenant DBs, ordered by tenant_id.
    let listed = repos.list_wallets().await?;
    let ours: Vec<StoredWallet> = listed
        .into_iter()
        .filter(|w| w.tenant_id == tenant_a || w.tenant_id == tenant_b)
        .collect();
    if ours.len() != 2 {
        return Err(format!("list_wallets expected 2 probe wallets, got {}", ours.len()).into());
    }
    // Ordering: ascending tenant_id across the cross-tenant union.
    let mut sorted = ours.clone();
    sorted.sort_by(|l, r| l.tenant_id.cmp(&r.tenant_id));
    if ours != sorted {
        return Err("list_wallets is not ordered by tenant_id".into());
    }
    println!("7 list_wallets -> cross-tenant fan-out over 2 tenant DBs, tenant_id-ordered");

    // 8) mutating ops on an UNPROVISIONED tenant are NotFound (no tenant DB to
    // route to) — the database-per-tenant divergence from Postgres.
    match repos
        .adjust_wallet_balance("gate456-ghost", 1, now + 60)
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(
                format!("adjust on unprovisioned tenant must NotFound, got {other:?}").into(),
            )
        }
    }
    match repos
        .set_wallet_dunning("gate456-ghost", true, now + 60)
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(
                format!("set_dunning on unprovisioned tenant must NotFound, got {other:?}").into(),
            )
        }
    }
    println!("8 adjust/set_dunning on unprovisioned tenant -> typed NotFound");

    Ok(())
}
