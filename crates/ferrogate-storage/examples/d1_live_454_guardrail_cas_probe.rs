// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #454 guardrail-binding CAS families.

//! Gate-owned live validation for the #454 slice: drive the REAL
//! `GuardrailPolicyRepository` guardrail-binding CAS transitions
//! (`activate` → re-`activate` → `archive` → `restore`) of a
//! `D1ControlPlaneStore` **through a live deployed `workers/d1-proxy` Worker
//! binding** against a REAL Cloudflare D1 database. This is the coverage the
//! landing commit flagged as Not-tested: the `UPDATE ... RETURNING` /
//! `INSERT ... ON CONFLICT DO NOTHING RETURNING` generation-guarded CAS is
//! otherwise exercised only against a mocked transport. Here the store's own
//! async path runs end-to-end: fail-closed proxy guard → REST read (verify the
//! revision exists) → REST read (current binding) → shared pure planner →
//! `/d1/query` CAS through the native `env.DB` binding → typed transition.
//!
//! Unlike the #449 REST probe, the CAS families REQUIRE a proxy Worker holding a
//! native D1 binding (the REST HTTP query API has no `RETURNING`), which is a
//! `wrangler deploy` step this Rust process cannot perform. So this probe is the
//! ASSERTIONS half: the operator deploys `workers/d1-proxy` bound to a probe D1,
//! seeds `D1_PROXY_TOKEN`, applies `sql/d1/001_init_d1.sql`, and hands this probe
//! the database uuid + Worker origin + token. The probe applies the schema
//! idempotently, runs the CAS chain, cleans its own rows, and leaves the D1 +
//! Worker for the operator to tear down (operator directive: no lingering CF
//! resources — the deploy/teardown wrapper owns that).
//!
//! Opt-in only. Required env:
//!   FERROGATE_CF_ACCOUNT_ID       - account for the REST D1 client
//!   FERROGATE_CF_API_TOKEN        - REST bearer (resolved via env://)
//!   FERROGATE_D1_PROBE_DATABASE_ID- uuid of the probe D1 the Worker is bound to
//!   FERROGATE_D1_PROXY_BASE_URL   - deployed Worker origin (https://...workers.dev)
//!   FERROGATE_D1_PROXY_TOKEN      - Worker bearer (resolved via env://)
//!
//! SKIPS cleanly (prints a notice, exits 0) when FERROGATE_CF_ACCOUNT_ID is
//! unset, so running this without credentials is a no-op rather than a failure.
//! With it set but another required variable missing the probe hard-errors: a
//! half-configured environment is an operator mistake, not an opt-out
//! (`support/probe_env.rs`, #495).
//! Run: cargo run -p ferrogate-storage --example d1_live_454_guardrail_cas_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, EnvTokenResolver, ReqwestTransport,
};
use ferrogate_storage::{
    D1ControlPlaneStore, D1TenantDatabaseRegistry, GuardrailPolicyRepository,
    RuntimeStorageRepositories, StorageError, StoredGuardrailPolicyRevision,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_454_guardrail_cas_probe";
const POLICY: &str = "gate-454-policy";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(env) = probe_env::opt_in(
        PROBE,
        &[
            "FERROGATE_CF_API_TOKEN",
            "FERROGATE_D1_PROBE_DATABASE_ID",
            "FERROGATE_D1_PROXY_BASE_URL",
            "FERROGATE_D1_PROXY_TOKEN",
        ],
    )?
    else {
        return Ok(());
    };
    let account_id = env.account_id();
    let dbid = env.var("FERROGATE_D1_PROBE_DATABASE_ID");
    let proxy_base = env.var("FERROGATE_D1_PROXY_BASE_URL");

    let resolver = Arc::new(EnvTokenResolver::from_process_env());
    let config = CloudflareConfig::new(account_id, "env://FERROGATE_CF_API_TOKEN");
    let cloudflare = CloudflareClient::new(config, resolver.clone())?;
    let d1 = D1Client::new(Arc::new(cloudflare));

    // The proxy client points at the deployed Worker (bound to the probe D1).
    let proxy = D1ProxyClient::new(
        proxy_base,
        Arc::new(ReqwestTransport::new()?),
        resolver.clone(),
        "env://FERROGATE_D1_PROXY_TOKEN",
    );

    // Apply the shipped schema idempotently over the REST /query surface, so a
    // fresh probe D1 gains guardrail_policy_revisions + guardrail_policy_bindings.
    apply_schema(&d1, &dbid).await?;

    // Same store the CLI builds, but with the proxy bound (production wires the
    // proxy from a deployment's Worker binding; here we bind it explicitly).
    let registry = D1TenantDatabaseRegistry {
        control_database_id: dbid.clone(),
        tenant_databases: BTreeMap::new(),
    };
    let store = D1ControlPlaneStore::new(d1, registry).with_proxy_client(proxy);
    let repos = RuntimeStorageRepositories::cloudflare_d1(store, 100);

    // Clean any residue from a prior run so assertions start from a known floor.
    reset(&repos)?;

    let result = exercise(&repos);
    // Best-effort row cleanup on success AND failure (operator tears down the
    // D1 + Worker; we leave the tables empty regardless of outcome).
    let _ = reset(&repos);
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
    println!("schema applied: {} statements", statements.len());
    Ok(())
}

/// Delete this probe's policy rows (bindings first, then revisions) so a re-run
/// is deterministic. Uses the REST surface via a fresh statement each call.
fn reset(repos: &RuntimeStorageRepositories) -> Result<(), StorageError> {
    // The binding delete goes through the proxy CAS only when a binding exists;
    // read it first and, if present, restore-to-None (the guarded DELETE branch).
    if let Some(binding) = repos.get_guardrail_policy_binding(POLICY)? {
        repos.restore_guardrail_policy_binding(POLICY, Some(binding.generation), None)?;
    }
    Ok(())
}

fn revision(rev: u32) -> StoredGuardrailPolicyRevision {
    StoredGuardrailPolicyRevision {
        id: format!("{POLICY}@{rev}"),
        policy_id: POLICY.into(),
        revision: rev,
        policy_json: format!("{{\"rules\":[],\"rev\":{rev}}}"),
        created_at_unix: 1_753_000_000 + rev as u64,
        created_by: "gate".into(),
    }
}

fn exercise(repos: &RuntimeStorageRepositories) -> Result<(), Box<dyn std::error::Error>> {
    // Seed three revisions (REST). `insert` conflicts on a duplicate
    // (policy_id, revision); a re-run against a reused probe D1 already has
    // them, so a Conflict here is benign — the CAS chain below is what matters.
    for rev in 1..=3 {
        match repos.insert_guardrail_policy_revision(revision(rev)) {
            Ok(()) | Err(StorageError::Conflict(_)) => {}
            Err(other) => return Err(other.into()),
        }
    }
    println!("seeded revisions 1 + 2 + 3");

    // A) First activation: binding absent -> INSERT ON CONFLICT DO NOTHING
    //    RETURNING (gen 0->1). previous is None; current points at revision 1.
    let a = repos.activate_guardrail_policy_revision(POLICY, 1, "gate", 1_800_000_100, false)?;
    if a.previous.is_some() {
        return Err("first activation should have no previous binding".into());
    }
    if a.current.active_revision != Some(1) {
        return Err(format!(
            "expected active_revision Some(1), got {:?}",
            a.current.active_revision
        )
        .into());
    }
    println!(
        "A first activation -> active=1 gen={} (INSERT CAS)",
        a.current.generation
    );

    // B) Re-activate to revision 2: binding present -> guarded UPDATE CAS under
    //    the read generation. The previously-active revision 1 auto-archives;
    //    generation strictly advances (the guard the whole slice exists for).
    let b = repos.activate_guardrail_policy_revision(POLICY, 2, "gate", 1_800_000_200, false)?;
    match b.previous.as_ref().map(|p| p.active_revision) {
        Some(Some(1)) => {}
        other => return Err(format!("expected previous active=Some(1), got {other:?}").into()),
    }
    if b.current.active_revision != Some(2) {
        return Err(format!(
            "expected active_revision Some(2), got {:?}",
            b.current.active_revision
        )
        .into());
    }
    if !b.current.archived_revisions.contains(&1) {
        return Err(format!(
            "re-activation should auto-archive rev 1, got {:?}",
            b.current.archived_revisions
        )
        .into());
    }
    if b.current.generation <= a.current.generation {
        return Err(format!(
            "generation must advance across guarded UPDATE: {} -> {}",
            a.current.generation, b.current.generation
        )
        .into());
    }
    println!(
        "B re-activate -> active=2 archived={:?} gen={} (guarded UPDATE CAS, gen advanced from {})",
        b.current.archived_revisions, b.current.generation, a.current.generation
    );

    // C) Domain guard, proven LIVE: archiving the ACTIVE revision (2) is
    //    rejected as a typed Conflict before any CAS write.
    match repos.archive_guardrail_policy_revision(POLICY, 2, "gate", 1_800_000_250) {
        Err(StorageError::Conflict(_)) => {}
        other => {
            return Err(
                format!("archiving the active revision must Conflict, got {other:?}").into(),
            )
        }
    }
    println!("C archive(active rev 2) -> typed Conflict (domain guard) ok");

    // D) Archive a NON-active revision (3): guarded UPDATE CAS pushes 3 into
    //    archived_revisions while active stays 2; generation advances.
    let d = repos.archive_guardrail_policy_revision(POLICY, 3, "gate", 1_800_000_300)?;
    if d.current.active_revision != Some(2) {
        return Err(format!(
            "archive of non-active must keep active=2, got {:?}",
            d.current.active_revision
        )
        .into());
    }
    if !d.current.archived_revisions.contains(&3) {
        return Err(format!(
            "archived_revisions should contain 3, got {:?}",
            d.current.archived_revisions
        )
        .into());
    }
    if d.current.generation <= b.current.generation {
        return Err("archive must advance generation".into());
    }
    println!(
        "D archive rev 3 -> active=2 archived={:?} gen={}",
        d.current.archived_revisions, d.current.generation
    );

    // E) Read-back through the REST surface reflects the CAS-committed state.
    let read = repos
        .get_guardrail_policy_binding(POLICY)?
        .ok_or("binding read-back returned none after archive")?;
    if read.active_revision != Some(2) || !read.archived_revisions.contains(&3) {
        return Err(format!("read-back mismatch: {read:?}").into());
    }
    if read.generation != d.current.generation {
        return Err(format!(
            "read-back generation {} != CAS generation {}",
            read.generation, d.current.generation
        )
        .into());
    }
    println!(
        "E read-back matches committed CAS state (active=2 gen {})",
        read.generation
    );

    // F) restore-to-None: guarded DELETE CAS under the current generation removes
    //    the binding row (the delete branch of restore).
    repos.restore_guardrail_policy_binding(POLICY, Some(read.generation), None)?;
    if repos.get_guardrail_policy_binding(POLICY)?.is_some() {
        return Err("binding should be gone after restore-to-None (guarded DELETE)".into());
    }
    println!("F restore-to-None -> guarded DELETE removed the binding");

    Ok(())
}
