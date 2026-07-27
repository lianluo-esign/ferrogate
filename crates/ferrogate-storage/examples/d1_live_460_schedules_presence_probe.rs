// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #460 tenant-scoped agent-schedule + observed-presence families.

//! Gate-owned live validation for the #460 slice: drive the REAL agent-schedule
//! (`upsert`/`get`/`list`/`list_all`/`list_due`/`delete`/`insert_fire`/
//! `list_fires`) and observed-agent-presence (`touch`/`list_since`) ops of a
//! `D1ControlPlaneStore` **through a live deployed `workers/d1-proxy` Worker,
//! routed onto per-tenant `[[d1_databases]]` bindings** against REAL Cloudflare D1
//! databases. This is the coverage the #460 landing commit flags as Not-tested:
//! the tenant-DB routing + id-only locate fan-out, the `delete` fire-log cascade,
//! the at-most-once fire gate, and — the property no mocked-transport test can
//! prove — the presence `max/min/+` coalescing upsert under a CONCURRENT
//! double-touch (a burst of touches for one key must fold into ONE row with the
//! summed count and the max last-seen).
//!
//! Both families are TENANT-SCOPED (like #455/#456): every op selects a per-tenant
//! binding (`TENANT_DB_<TENANT_ID>`), and `list_all`/`list_due`/`list_since(None)`
//! fan out over ALL provisioned tenant bindings — so this probe REQUIRES the
//! operator to deploy a `workers/d1-proxy` bound to a control probe D1 (binding
//! `DB`) and TWO tenant probe D1s (`TENANT_DB_<TENANT_A>` + `TENANT_DB_<TENANT_B>`),
//! seed `D1_PROXY_TOKEN`, and hand this probe the three database uuids + tenant
//! ids + Worker origin + token. The probe applies the schema idempotently to both
//! tenant DBs, exercises both families (routing + fan-out + the concurrent
//! coalesce), cleans its own rows, and leaves the DBs + Worker for the operator to
//! tear down (operator directive: no lingering CF resources).
//!
//! Opt-in only. Required env:
//!   FERROGATE_CF_ACCOUNT_ID            - account for the REST D1 client
//!   FERROGATE_CF_API_TOKEN             - REST bearer (resolved via env://)
//!   FERROGATE_D1_CONTROL_DATABASE_ID   - uuid of the control D1 (Worker binding DB)
//!   FERROGATE_D1_TENANT_DATABASE_ID    - uuid of tenant A's D1 (binding TENANT_DB_<A>)
//!   FERROGATE_D1_TENANT_ID             - tenant A id (e.g. gate460acme)
//!   FERROGATE_D1_TENANT_DATABASE_ID_B  - uuid of tenant B's D1 (binding TENANT_DB_<B>)
//!   FERROGATE_D1_TENANT_ID_B           - tenant B id (e.g. gate460bravo)
//!   FERROGATE_D1_PROXY_BASE_URL        - deployed Worker origin (https://...workers.dev)
//!   FERROGATE_D1_PROXY_TOKEN           - Worker bearer (resolved via env://)
//!
//! SKIPS cleanly (prints a notice, exits 0) when FERROGATE_CF_ACCOUNT_ID is
//! unset, so running this without credentials is a no-op rather than a failure.
//! With it set but another required variable missing the probe hard-errors: a
//! half-configured environment is an operator mistake, not an opt-out
//! (`support/probe_env.rs`, #495).
//! Run: cargo run -p ferrogate-storage --example d1_live_460_schedules_presence_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    agent_schedule_fire_id, CatchupPolicy, D1ControlPlaneStore, D1TenantDatabaseRegistry,
    ObservedAgentPresenceTouch, OverlapPolicy, RuntimeStorageRepositories, ScheduleFireOutcome,
    ScheduleSpecKind, ScheduleTargetKind, StorageError, StoredAgentSchedule,
    StoredAgentScheduleFire,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_460_schedules_presence_probe";

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

    // Each tenant DB needs the agent_schedules/agent_schedule_fires/
    // observed_agent_presence tables independently (database-per-tenant topology).
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

    // Best-effort clean of any residue from a prior run (the probe owns these DBs).
    reset_tables(&proxy, &tenant_a).await?;
    reset_tables(&proxy, &tenant_b).await?;

    let result = exercise(&repos, &tenant_a, &tenant_b).await;

    let _ = reset_tables(&proxy, &tenant_a).await;
    let _ = reset_tables(&proxy, &tenant_b).await;
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

/// Wipe a tenant's schedule + presence rows through the proxy's tenant binding.
async fn reset_tables(
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    for table in [
        "agent_schedule_fires",
        "agent_schedules",
        "observed_agent_presence",
    ] {
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

fn schedule(id: &str, tenant: &str, name: &str, next_fire: Option<i64>) -> StoredAgentSchedule {
    StoredAgentSchedule {
        schedule_id: id.into(),
        tenant_id: tenant.into(),
        workspace_id: "ws-1".into(),
        name: name.into(),
        enabled: true,
        spec_kind: ScheduleSpecKind::Interval,
        cron_expr: None,
        timezone: "UTC".into(),
        interval_secs: Some(3600),
        target_kind: ScheduleTargetKind::SelfHostedDispatch,
        target_json: "{\"agent\":\"a\"}".into(),
        overlap_policy: OverlapPolicy::Skip,
        catchup_policy: CatchupPolicy::SkipMissed,
        jitter_secs: 0,
        next_fire_at_unix: next_fire,
        last_fire_at_unix: None,
        created_at_unix: 1_800_000_000,
        updated_at_unix: 1_800_000_000,
        revision: 1,
    }
}

async fn exercise(
    repos: &Arc<RuntimeStorageRepositories>,
    tenant_a: &str,
    tenant_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_800_000_000;
    let sched_a = format!("{tenant_a}-sched-1");
    let sched_b = format!("{tenant_b}-sched-1");

    // 1) upsert routes to tenant A; get + list route/round-trip its row.
    repos
        .upsert_agent_schedule(schedule(&sched_a, tenant_a, "nightly", Some(now + 100)))
        .await?;
    let got = repos
        .get_agent_schedule(&sched_a)
        .await?
        .ok_or("get_agent_schedule missed the upserted row")?;
    if got.tenant_id != tenant_a || got.interval_secs != Some(3600) {
        return Err(format!("schedule decode mismatch: {got:?}").into());
    }
    let listed = repos.list_agent_schedules(tenant_a, None).await?;
    if !listed.iter().any(|s| s.schedule_id == sched_a) {
        return Err("list_agent_schedules missed the tenant's schedule".into());
    }
    println!("1 upsert/get/list_agent_schedules round-trip on tenant A");

    // 2) upsert on tenant B, then list_all fans out over BOTH tenant DBs.
    repos
        .upsert_agent_schedule(schedule(&sched_b, tenant_b, "hourly", Some(now + 50)))
        .await?;
    let all = repos.list_all_agent_schedules().await?;
    let ours: Vec<_> = all
        .iter()
        .filter(|s| s.schedule_id == sched_a || s.schedule_id == sched_b)
        .collect();
    if ours.len() != 2 {
        return Err(format!("list_all expected 2 probe schedules, got {}", ours.len()).into());
    }
    // Cross-tenant union ordered by tenant_id, workspace_id, name.
    let mut sorted = ours.clone();
    sorted.sort_by(|l, r| {
        l.tenant_id
            .cmp(&r.tenant_id)
            .then_with(|| l.workspace_id.cmp(&r.workspace_id))
            .then_with(|| l.name.cmp(&r.name))
    });
    if ours != sorted {
        return Err("list_all_agent_schedules is not tenant/workspace/name-ordered".into());
    }
    println!("2 list_all_agent_schedules fans out over 2 tenant DBs, ordered");

    // 3) list_due (cheapest-first, global) surfaces both (B's fires sooner).
    let due = repos.list_due_agent_schedules(now + 200, 10).await?;
    let due_ids: Vec<&str> = due.iter().map(|s| s.schedule_id.as_str()).collect();
    let a_pos = due_ids.iter().position(|id| *id == sched_a);
    let b_pos = due_ids.iter().position(|id| *id == sched_b);
    match (a_pos, b_pos) {
        (Some(a), Some(b)) if b < a => {}
        other => {
            return Err(format!("list_due order/coverage wrong: {other:?} in {due_ids:?}").into())
        }
    }
    println!("3 list_due_agent_schedules fans out, cheapest next-fire first");

    // 4) the at-most-once fire gate: first insert wins, replaying the SAME slot
    //    (even with a different fire id) loses.
    let slot = now + 100;
    let fire = StoredAgentScheduleFire {
        fire_id: agent_schedule_fire_id(&sched_a, slot),
        schedule_id: sched_a.clone(),
        scheduled_fire_at_unix: slot,
        fired_at_unix: slot,
        node_id: Some("gate-node".into()),
        outcome: ScheduleFireOutcome::Dispatched,
        dispatch_id: Some("disp-1".into()),
        run_id: None,
        detail: None,
    };
    if !repos.insert_agent_schedule_fire(fire.clone()).await? {
        return Err("first fire insert should win the slot".into());
    }
    let mut replay = fire.clone();
    replay.fire_id = "different-id".into();
    if repos.insert_agent_schedule_fire(replay).await? {
        return Err("replaying the same slot must lose (at-most-once)".into());
    }
    let fires = repos.list_agent_schedule_fires(&sched_a, 10).await?;
    if fires.len() != 1 || fires[0].scheduled_fire_at_unix != slot {
        return Err(format!("list_agent_schedule_fires wrong: {fires:?}").into());
    }
    println!("4 insert_agent_schedule_fire at-most-once gate + list_fires");

    // 5) delete cascades the fire log (FK-free D1 dialect) and removes the row.
    if !repos.delete_agent_schedule(&sched_a).await? {
        return Err("delete of an existing schedule should be true".into());
    }
    if repos.get_agent_schedule(&sched_a).await?.is_some() {
        return Err("schedule survived delete".into());
    }
    if !repos
        .list_agent_schedule_fires(&sched_a, 10)
        .await?
        .is_empty()
    {
        return Err("delete did not cascade the fire log".into());
    }
    // A fire for the now-unknown schedule is NotFound (no tenant DB to route into).
    match repos
        .insert_agent_schedule_fire(StoredAgentScheduleFire {
            fire_id: "orphan".into(),
            schedule_id: sched_a.clone(),
            scheduled_fire_at_unix: slot,
            fired_at_unix: slot,
            node_id: None,
            outcome: ScheduleFireOutcome::Dispatched,
            dispatch_id: None,
            run_id: None,
            detail: None,
        })
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(format!("fire for deleted schedule must NotFound, got {other:?}").into())
        }
    }
    println!("5 delete cascades fires; a fire for a deleted schedule is NotFound");

    // 6) upsert on an UNPROVISIONED tenant is NotFound (the write divergence).
    match repos
        .upsert_agent_schedule(schedule("ghost-sched", "gate460ghost", "n", Some(now)))
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(
                format!("upsert on unprovisioned tenant must NotFound, got {other:?}").into(),
            )
        }
    }
    println!("6 upsert_agent_schedule on unprovisioned tenant -> NotFound");

    // 7) presence touch coalesces to ONE row; list_since routes it back.
    repos
        .touch_observed_agent_presence(ObservedAgentPresenceTouch {
            tenant_id: tenant_a.into(),
            api_key_id: "vk-live".into(),
            seen_at_unix: now + 10,
        })
        .await?;
    let scoped = repos
        .list_observed_agent_presence_since(Some(tenant_a), now)
        .await?;
    let row = scoped
        .iter()
        .find(|r| r.api_key_id == "vk-live")
        .ok_or("list_since(Some) missed the touched key")?;
    if row.request_count != 1 || row.last_seen_at_unix != now + 10 {
        return Err(format!("first touch mismatch: {row:?}").into());
    }
    println!("7 touch + list_observed_agent_presence_since(Some) round-trip");

    // 8) the keystone: N CONCURRENT touches of the SAME key fold into ONE row with
    //    request_count == 1 (from step 7) + N and last_seen == the max timestamp —
    //    the coalescing max/min/+ upsert no mocked test can prove.
    const N: i64 = 16;
    let mut handles = Vec::with_capacity(N as usize);
    for i in 0..N {
        let repos = Arc::clone(repos);
        let tenant = tenant_a.to_string();
        handles.push(tokio::spawn(async move {
            repos
                .touch_observed_agent_presence(ObservedAgentPresenceTouch {
                    tenant_id: tenant,
                    api_key_id: "vk-live".into(),
                    // Spread the timestamps; the max must win last_seen.
                    seen_at_unix: now + 20 + i,
                })
                .await
        }));
    }
    for handle in handles {
        handle.await??;
    }
    let after = repos
        .list_observed_agent_presence_since(Some(tenant_a), now)
        .await?;
    let coalesced = after
        .iter()
        .find(|r| r.api_key_id == "vk-live")
        .ok_or("coalesced key vanished")?;
    if coalesced.request_count != 1 + N {
        return Err(format!(
            "concurrent coalesce lost updates: request_count={} (expected {})",
            coalesced.request_count,
            1 + N
        )
        .into());
    }
    if coalesced.last_seen_at_unix != now + 20 + (N - 1) {
        return Err(format!(
            "coalesce last_seen not max: {} (expected {})",
            coalesced.last_seen_at_unix,
            now + 20 + (N - 1)
        )
        .into());
    }
    println!(
        "8 {N} concurrent touches -> ONE row, request_count={}, last_seen=max (no lost update)",
        1 + N
    );

    // 9) a DELAYED older touch never regresses last_seen (monotonic max/min).
    repos
        .touch_observed_agent_presence(ObservedAgentPresenceTouch {
            tenant_id: tenant_a.into(),
            api_key_id: "vk-live".into(),
            seen_at_unix: now + 5, // older than every prior touch
        })
        .await?;
    let delayed = repos
        .list_observed_agent_presence_since(Some(tenant_a), now)
        .await?;
    let row = delayed
        .iter()
        .find(|r| r.api_key_id == "vk-live")
        .ok_or("key vanished after delayed touch")?;
    if row.last_seen_at_unix != now + 20 + (N - 1) || row.first_seen_at_unix != now + 5 {
        return Err(format!("delayed touch broke monotonic max/min: {row:?}").into());
    }
    if row.request_count != 2 + N {
        return Err(format!(
            "delayed touch did not increment count: {}",
            row.request_count
        )
        .into());
    }
    println!("9 delayed older touch keeps last_seen max, first_seen min, count++");

    // 10) operator cross-tenant view fans out over BOTH tenant DBs.
    repos
        .touch_observed_agent_presence(ObservedAgentPresenceTouch {
            tenant_id: tenant_b.into(),
            api_key_id: "vk-b".into(),
            seen_at_unix: now + 1000,
        })
        .await?;
    let operator = repos.list_observed_agent_presence_since(None, now).await?;
    let ours: Vec<_> = operator
        .iter()
        .filter(|r| r.tenant_id == tenant_a || r.tenant_id == tenant_b)
        .collect();
    if !ours.iter().any(|r| r.tenant_id == tenant_a)
        || !ours.iter().any(|r| r.tenant_id == tenant_b)
    {
        return Err("operator presence view did not fan out over both tenants".into());
    }
    // last_seen DESC across the union.
    let mut sorted = ours.clone();
    sorted.sort_by(|l, r| {
        r.last_seen_at_unix
            .cmp(&l.last_seen_at_unix)
            .then_with(|| l.tenant_id.cmp(&r.tenant_id))
            .then_with(|| l.api_key_id.cmp(&r.api_key_id))
    });
    if ours != sorted {
        return Err("operator presence view not last_seen-DESC ordered".into());
    }
    println!("10 list_observed_agent_presence_since(None) fans out, last_seen-DESC");

    // 11) touch on an UNPROVISIONED tenant is NotFound (the write divergence).
    match repos
        .touch_observed_agent_presence(ObservedAgentPresenceTouch {
            tenant_id: "gate460ghost".into(),
            api_key_id: "vk".into(),
            seen_at_unix: now,
        })
        .await
    {
        Err(StorageError::NotFound(_)) => {}
        other => {
            return Err(
                format!("touch on unprovisioned tenant must NotFound, got {other:?}").into(),
            )
        }
    }
    println!("11 touch_observed_agent_presence on unprovisioned tenant -> NotFound");

    Ok(())
}
