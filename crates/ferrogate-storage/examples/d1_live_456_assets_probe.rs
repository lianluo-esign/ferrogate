// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: Opt-in live D1 probe for the #456 tenant-scoped assets/channels/retention family.

//! Gate-owned live validation for the #456 asset slice: drive the REAL
//! `create_asset_within_quota` / `create_asset_if_absent` / `get_asset` /
//! `list_assets` / `list_all_assets` / `move_asset_channel_if_resolvable` /
//! `set_asset_version_yank` / `promote_pending_asset_visibility` /
//! `list_retention_policies` ops of a `D1ControlPlaneStore` **through a live
//! deployed `workers/d1-proxy` Worker, routed onto per-tenant `[[d1_databases]]`
//! bindings** against REAL Cloudflare D1 databases. This is the coverage the
//! #456 landing commit flags as Not-tested: the two concurrency invariants no
//! mocked transport can prove against real SQLite writer serialization —
//!
//!   * the #369 dual-unique CONCURRENT FIRST-PUSH: two parallel
//!     `create_asset_within_quota` for the SAME logical asset admit exactly one
//!     (`Admitted`), the loser gets the typed `AlreadyExists` (never a raw
//!     error), and the quota `CAST(? AS INTEGER)` guard actually admits;
//!   * the #367 MOVE-vs-YANK RACE: a channel move to a version raced against a
//!     yank of that same version can never both succeed — the channel is never
//!     left pointing at a yanked version.
//!
//! Plus the inline-BYTEA base64 round trip, the id-only fan-out reads, the
//! visibility promotion CAS, and the retention listing. The family is
//! TENANT-SCOPED (like #455/#456 wallets/usage): every write/tenant-read op
//! selects a per-tenant binding (`TENANT_DB_<TENANT_ID>`); the id-only reads +
//! `list_all_*` fan out over ALL provisioned tenant bindings, so this probe
//! REQUIRES a control probe D1 (binding `DB`) plus TWO tenant probe D1s.
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
//! Run: cargo run -p ferrogate-storage --example d1_live_456_assets_probe

use std::collections::BTreeMap;
use std::sync::Arc;

use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    CloudflareClient, CloudflareConfig, D1ProxyClient, D1ProxyStatement, EnvTokenResolver,
    ReqwestTransport,
};
use ferrogate_storage::{
    AssetPromotionTarget, AssetQuotaAdmission, AssetVisibility, AssetVisibilityPromotionOutcome,
    ChannelMoveOutcome, D1ControlPlaneStore, D1TenantDatabaseRegistry, RuntimeStorageRepositories,
    StoredAsset, StoredAssetChannel, StoredRetentionPolicy, VersionYankOutcome,
};

#[path = "support/probe_env.rs"]
mod probe_env;

const SCHEMA: &str = include_str!("../../../sql/d1/001_init_d1.sql");
const PROBE: &str = "d1_live_456_assets_probe";

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

    // Each tenant DB carries the stored_assets/asset_channels/retention_policies
    // tables independently (database-per-tenant topology).
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

    reset_asset_tables(&proxy, &tenant_a).await?;
    reset_asset_tables(&proxy, &tenant_b).await?;

    let result = exercise(&repos, &tenant_a, &tenant_b).await;

    let _ = reset_asset_tables(&proxy, &tenant_a).await;
    let _ = reset_asset_tables(&proxy, &tenant_b).await;
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

/// Wipe a tenant's asset rows through the proxy's tenant binding (the probe owns
/// the DB).
async fn reset_asset_tables(
    proxy: &D1ProxyClient,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = tenant_binding(tenant_id);
    for table in ["asset_channels", "retention_policies", "stored_assets"] {
        let stmt = D1ProxyStatement::with_params(format!("DELETE FROM {table}"), vec![]);
        proxy.query_on(Some(&binding), &stmt).await?;
    }
    Ok(())
}

/// Mirror of `tenant_database_binding`: uppercase, non-alnum -> `_`, `TENANT_DB_`
/// prefix.
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

fn asset_id(tenant: &str, name: &str, version: &str) -> String {
    format!("{tenant}:skill:{name}:{version}")
}

fn asset(
    tenant: &str,
    name: &str,
    version: &str,
    size: u64,
    content: &[u8],
    visibility: AssetVisibility,
    now: i64,
) -> StoredAsset {
    StoredAsset {
        id: asset_id(tenant, name, version),
        tenant_id: tenant.to_string(),
        project_id: None,
        asset_type: "skill".to_string(),
        name: name.to_string(),
        version: version.to_string(),
        content_type: "application/octet-stream".to_string(),
        content_hash: "sha".to_string(),
        size_bytes: size,
        content: content.to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility,
        created_at_unix: now,
        updated_at_unix: now,
    }
}

fn channel(tenant: &str, name: &str, channel: &str, version: &str, now: i64) -> StoredAssetChannel {
    StoredAssetChannel {
        id: format!("{tenant}:skill:{name}:{channel}"),
        tenant_id: tenant.to_string(),
        asset_type: "skill".to_string(),
        name: name.to_string(),
        channel: channel.to_string(),
        version: version.to_string(),
        updated_at_unix: now,
    }
}

async fn exercise(
    repos: &Arc<RuntimeStorageRepositories>,
    tenant_a: &str,
    tenant_b: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = 1_800_000_000;

    // 1) create_asset_within_quota admits under the quota; the inline BYTEA
    // round-trips base64 through get_asset (invariant 4).
    let admission = repos
        .create_asset_within_quota(
            asset(
                tenant_a,
                "greeter",
                "1.0.0",
                5,
                b"hello",
                AssetVisibility::Visible,
                now,
            ),
            Some(10_000),
        )
        .await?;
    if admission != AssetQuotaAdmission::Admitted {
        return Err(format!("expected Admitted, got {admission:?}").into());
    }
    let fetched = repos
        .get_asset(&asset_id(tenant_a, "greeter", "1.0.0"))
        .await?
        .ok_or("get_asset fan-out did not find the just-created asset")?;
    if fetched.content != b"hello" {
        return Err(format!("inline content round-trip failed: {:?}", fetched.content).into());
    }
    println!("1 create_asset_within_quota Admitted; get_asset content round-trips base64");

    // 2) over-quota is a definitive OverQuota (used 5, quota 6, attempt 5).
    let over = repos
        .create_asset_within_quota(
            asset(
                tenant_a,
                "big",
                "1.0.0",
                5,
                b"world",
                AssetVisibility::Visible,
                now,
            ),
            Some(6),
        )
        .await?;
    match over {
        AssetQuotaAdmission::OverQuota { .. } => {}
        other => return Err(format!("expected OverQuota, got {other:?}").into()),
    }
    println!("2 create_asset_within_quota over the quota -> OverQuota");

    // 3) #369 CONCURRENT FIRST-PUSH: two parallel admissions of the SAME logical
    // asset. SQLite serializes writers, so exactly one Admitted, one
    // AlreadyExists — never two inserts, never a raw error for the loser.
    let concurrent = asset(
        tenant_b,
        "race",
        "1.0.0",
        10,
        b"racecontent",
        AssetVisibility::Visible,
        now,
    );
    let (r1, r2) = (repos.clone(), repos.clone());
    let (c1, c2) = (concurrent.clone(), concurrent.clone());
    let left = tokio::spawn(async move { r1.create_asset_within_quota(c1, Some(1_000_000)).await });
    let right =
        tokio::spawn(async move { r2.create_asset_within_quota(c2, Some(1_000_000)).await });
    let outcomes = [left.await??, right.await??];
    let admitted = outcomes
        .iter()
        .filter(|o| **o == AssetQuotaAdmission::Admitted)
        .count();
    let already = outcomes
        .iter()
        .filter(|o| **o == AssetQuotaAdmission::AlreadyExists)
        .count();
    if admitted != 1 || already != 1 {
        return Err(format!(
            "concurrent first-push must be 1 Admitted + 1 AlreadyExists, got {outcomes:?}"
        )
        .into());
    }
    println!(
        "3 concurrent create_asset_within_quota -> exactly 1 Admitted + 1 AlreadyExists (#369)"
    );

    // 4) create_asset_if_absent idempotent loser.
    let inserted = repos
        .create_asset_if_absent(asset(
            tenant_a,
            "once",
            "1.0.0",
            4,
            b"once",
            AssetVisibility::Visible,
            now,
        ))
        .await?;
    let loser = repos
        .create_asset_if_absent(asset(
            tenant_a,
            "once",
            "1.0.0",
            4,
            b"once",
            AssetVisibility::Visible,
            now,
        ))
        .await?;
    if !inserted || loser {
        return Err(format!(
            "create_asset_if_absent expected true then false, got {inserted}/{loser}"
        )
        .into());
    }
    println!("4 create_asset_if_absent -> true then false (idempotent)");

    // 5) #367 MOVE-vs-YANK RACE. Seed two resolvable versions + a channel at
    // 1.0.0, then race move(channel -> 2.0.0) against yank(2.0.0). The invariant:
    // never both succeed, and the channel is never left on a yanked version.
    repos
        .upsert_asset(asset(
            tenant_a,
            "reg",
            "1.0.0",
            3,
            b"one",
            AssetVisibility::Visible,
            now,
        ))
        .await?;
    repos
        .upsert_asset(asset(
            tenant_a,
            "reg",
            "2.0.0",
            3,
            b"two",
            AssetVisibility::Visible,
            now,
        ))
        .await?;
    repos
        .upsert_asset_channel(channel(tenant_a, "reg", "stable", "1.0.0", now))
        .await?;
    let (r_move, r_yank) = (repos.clone(), repos.clone());
    let move_channel = channel(tenant_a, "reg", "stable", "2.0.0", now + 1);
    let yank_tenant = tenant_a.to_string();
    let move_handle =
        tokio::spawn(async move { r_move.move_asset_channel_if_resolvable(move_channel).await });
    let yank_handle = tokio::spawn(async move {
        r_yank
            .set_asset_version_yank(&yank_tenant, "skill", "reg", "2.0.0", true, now + 1)
            .await
    });
    let move_ok = matches!(move_handle.await??, ChannelMoveOutcome::Moved { .. });
    let yank_ok = matches!(yank_handle.await??, VersionYankOutcome::Applied { .. });
    if move_ok && yank_ok {
        return Err(
            "move-vs-yank race left BOTH succeeding (channel stranded on a yanked version)".into(),
        );
    }
    if !move_ok && !yank_ok {
        return Err("move-vs-yank race left BOTH failing (expected exactly one winner)".into());
    }
    // Final consistency: whatever version the channel points at must be non-yanked.
    let channels = repos.list_asset_channels(tenant_a, "skill", "reg").await?;
    let stable = channels
        .iter()
        .find(|c| c.channel == "stable")
        .ok_or("stable channel vanished")?;
    let target = repos
        .get_asset(&asset_id(tenant_a, "reg", &stable.version))
        .await?
        .ok_or("channel points at a missing version")?;
    if target.yanked {
        return Err("channel is pointing at a YANKED version -> #367 invariant broken".into());
    }
    println!(
        "5 move-vs-yank race -> exactly one winner (move_ok={move_ok}, yank_ok={yank_ok}); channel on non-yanked {}",
        stable.version
    );

    // 6) visibility promotion CAS (#378): a pending_scan asset promotes to visible.
    repos
        .upsert_asset(asset(
            tenant_a,
            "scan",
            "1.0.0",
            2,
            b"pd",
            AssetVisibility::PendingScan,
            now,
        ))
        .await?;
    let promotion = repos
        .promote_pending_asset_visibility(
            &asset_id(tenant_a, "scan", "1.0.0"),
            AssetPromotionTarget::Visible,
            now + 5,
        )
        .await?;
    if promotion
        != (AssetVisibilityPromotionOutcome::Promoted {
            to: AssetVisibility::Visible,
        })
    {
        return Err(format!("expected Promoted->Visible, got {promotion:?}").into());
    }
    // A second promote is a no-op NotPending (already terminal).
    let again = repos
        .promote_pending_asset_visibility(
            &asset_id(tenant_a, "scan", "1.0.0"),
            AssetPromotionTarget::Visible,
            now + 6,
        )
        .await?;
    if !matches!(again, AssetVisibilityPromotionOutcome::NotPending { .. }) {
        return Err(format!("re-promote must be NotPending, got {again:?}").into());
    }
    println!("6 promote_pending_asset_visibility -> Promoted then NotPending (CAS, #378)");

    // 7) retention policy round-trip + tenant-scoped list ordering.
    repos
        .upsert_retention_policy(StoredRetentionPolicy {
            id: format!("{tenant_a}:asset:*"),
            tenant_id: tenant_a.to_string(),
            resource_type: "asset".to_string(),
            scope: "*".to_string(),
            keep_last_n: Some(3),
            max_age_secs: None,
            min_age_secs: 3600,
            created_at_unix: now,
            updated_at_unix: now,
        })
        .await?;
    let policies = repos.list_retention_policies(tenant_a, "asset").await?;
    if policies.len() != 1
        || policies[0].keep_last_n != Some(3)
        || policies[0].max_age_secs.is_some()
    {
        return Err(format!("retention round-trip mismatch: {policies:?}").into());
    }
    println!("7 upsert/list_retention_policies round-trips (keep_last_n=3, max_age NULL)");

    // 8) list_all_assets fans out over BOTH tenant DBs and orders by tenant_id.
    let all = repos.list_all_assets().await?;
    let ours: Vec<StoredAsset> = all
        .into_iter()
        .filter(|a| a.tenant_id == tenant_a || a.tenant_id == tenant_b)
        .collect();
    let mut sorted = ours.clone();
    sorted.sort_by(|l, r| {
        l.tenant_id
            .cmp(&r.tenant_id)
            .then_with(|| l.asset_type.cmp(&r.asset_type))
            .then_with(|| l.name.cmp(&r.name))
            .then_with(|| l.version.cmp(&r.version))
    });
    if ours != sorted {
        return Err("list_all_assets is not ordered tenant_id, asset_type, name, version".into());
    }
    if !ours.iter().any(|a| a.tenant_id == *tenant_a)
        || !ours.iter().any(|a| a.tenant_id == *tenant_b)
    {
        return Err("list_all_assets did not fan out over BOTH tenant DBs".into());
    }
    println!("8 list_all_assets -> cross-tenant fan-out over 2 tenant DBs, canonically ordered");

    Ok(())
}
