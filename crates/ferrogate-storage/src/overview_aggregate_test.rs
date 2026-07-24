// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Repository-level coverage for the #339 control-plane overview
// aggregate. Proves the bounded inventory counts and durable
// lifetime/current-month token totals match the underlying repositories, that a
// tenant-scoped aggregate never leaks another tenant's counts, and (DSN-gated)
// that the Postgres COUNT/SUM pushdown returns the same numbers as the
// in-memory fold.

use ferrogate_billing::{BillingEvent, BillingUsageSource, ProviderAttempt, TokenUsage};
use ferrogate_core::TenantContext;

use crate::schema_routing_test_support::block_on;
use crate::{
    period_month_from_unix, AssetVisibility, RuntimeStorageRepositories, StorageProviderKind,
    StoredAgentRun, StoredApiKey, StoredAsset, StoredProject, StoredSelfHostedWorkerRegistration,
    StoredTenantAccount, StoredWorkspace,
};

/// A month in the "current" window and one clearly in a prior month, so the
/// aggregate's lifetime-vs-current-month split is exercised against real
/// `period_month` boundaries.
const CURRENT_UNIX: u64 = 1_783_036_800;
const PREVIOUS_UNIX: u64 = CURRENT_UNIX - 45 * 86_400;

fn tenant_ctx(org: &str) -> TenantContext {
    TenantContext {
        organization_id: Some(org.to_string()),
        team_id: None,
        project_id: None,
        workspace_id: None,
        user_id: None,
        api_key_id: None,
    }
}

fn tenant_account(id: &str) -> StoredTenantAccount {
    StoredTenantAccount {
        id: id.to_string(),
        name: id.to_string(),
        slug: id.to_string(),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn project(id: &str, tenant_id: &str) -> StoredProject {
    StoredProject {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        name: id.to_string(),
        slug: id.to_string(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn workspace(id: &str, project_id: &str, tenant_id: &str) -> StoredWorkspace {
    StoredWorkspace {
        id: id.to_string(),
        project_id: project_id.to_string(),
        tenant_id: tenant_id.to_string(),
        name: id.to_string(),
        slug: id.to_string(),
        environment: "default".into(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn api_key(id: &str, tenant_id: &str, project_id: &str, workspace_id: &str) -> StoredApiKey {
    StoredApiKey {
        id: id.to_string(),
        workspace_id: workspace_id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: project_id.to_string(),
        name: id.to_string(),
        key_prefix: "fg".into(),
        key_hash: format!("hash-{id}"),
        last4: "abcd".into(),
        enabled: true,
        scopes: Vec::new(),
        allowed_models: Vec::new(),
        allowed_providers: Vec::new(),
        tenant: tenant_ctx(tenant_id),
        monthly_token_budget: None,
        request_limit_per_minute: None,
        created_at_unix: 0,
        updated_at_unix: 0,
        rotated_at_unix: None,
        expires_at_unix: None,
        revoked_at_unix: None,
    }
}

fn asset(id: &str, tenant_id: &str, size_bytes: u64) -> StoredAsset {
    StoredAsset {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        project_id: None,
        asset_type: "binary".into(),
        name: id.to_string(),
        version: "1.0.0".into(),
        content_type: "application/octet-stream".into(),
        content_hash: format!("sha256:{id}"),
        size_bytes,
        content: vec![0_u8; size_bytes as usize],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: AssetVisibility::Visible,
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn agent_run(id: &str, tenant_id: &str, status: &str) -> StoredAgentRun {
    StoredAgentRun {
        id: id.to_string(),
        request_id: format!("req-{id}"),
        trace_id: None,
        tenant: tenant_ctx(tenant_id),
        status: status.to_string(),
        provider: "openai".into(),
        turns_executed: 1,
        output_recorded: true,
        started_at_unix: Some(CURRENT_UNIX),
        completed_at_unix: Some(CURRENT_UNIX),
    }
}

fn worker(id: &str, tenant_id: &str, status: &str) -> StoredSelfHostedWorkerRegistration {
    StoredSelfHostedWorkerRegistration {
        id: id.to_string(),
        tenant: tenant_ctx(tenant_id),
        workspace_id: "workspace".into(),
        worker_name: id.to_string(),
        status: status.to_string(),
        identity_fingerprint: format!("fp-{id}"),
        identity_expires_at_unix: None,
        orchestration_enabled: true,
        registered_at_unix: Some(CURRENT_UNIX),
        last_seen_at_unix: Some(CURRENT_UNIX),
        trust_level: "standard".into(),
        capability_envelope_json: "{}".into(),
        token_secret: "secret-value-long-enough".into(),
    }
}

fn billing_event(
    request_id: &str,
    tenant_id: &str,
    occurred_at_unix: u64,
    usage: TokenUsage,
    cost_usd: f64,
) -> BillingEvent {
    BillingEvent {
        request_id: request_id.to_string(),
        trace_id: None,
        provider_attempt: ProviderAttempt::for_request(request_id, 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: tenant_ctx(tenant_id),
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage,
        usage_source: BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(occurred_at_unix),
        cost_usd: Some(cost_usd),
        latency_ms: Some(100),
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

/// Seed two tenants with deliberately different inventory so a tenant-scoped
/// aggregate is provably narrower than the global one.
fn seed(repositories: &RuntimeStorageRepositories) {
    for tenant in ["tenant-a", "tenant-b"] {
        block_on(repositories.upsert_tenant_account(tenant_account(tenant))).unwrap();
    }

    // tenant-a: 2 projects, 3 workspaces, 2 keys, 2 assets (100 + 200 bytes),
    // 3 agent runs, 2 workers, current + previous month usage.
    for project_id in ["a-proj-1", "a-proj-2"] {
        block_on(repositories.upsert_project(project(project_id, "tenant-a"))).unwrap();
    }
    for (ws, proj) in [
        ("a-ws-1", "a-proj-1"),
        ("a-ws-2", "a-proj-1"),
        ("a-ws-3", "a-proj-2"),
    ] {
        block_on(repositories.upsert_workspace(workspace(ws, proj, "tenant-a"))).unwrap();
    }
    for key in ["a-key-1", "a-key-2"] {
        block_on(
            repositories.upsert_api_key_record(api_key(key, "tenant-a", "a-proj-1", "a-ws-1")),
        )
        .unwrap();
    }
    block_on(repositories.upsert_asset(asset("a-asset-1", "tenant-a", 100))).unwrap();
    block_on(repositories.upsert_asset(asset("a-asset-2", "tenant-a", 200))).unwrap();
    for (id, status) in [
        ("a-run-1", "succeeded"),
        ("a-run-2", "failed"),
        ("a-run-3", "running"),
    ] {
        block_on(repositories.upsert_agent_run(agent_run(id, "tenant-a", status))).unwrap();
    }
    for (id, status) in [("a-worker-1", "active"), ("a-worker-2", "draining")] {
        block_on(
            repositories.upsert_self_hosted_worker_registration(worker(id, "tenant-a", status)),
        )
        .unwrap();
    }
    block_on(repositories.append_billing_event(billing_event(
        "a-bill-current",
        "tenant-a",
        CURRENT_UNIX,
        TokenUsage::new(100, 50, 150),
        0.01,
    )))
    .unwrap();
    block_on(repositories.append_billing_event(billing_event(
        "a-bill-previous",
        "tenant-a",
        PREVIOUS_UNIX,
        TokenUsage::new(10, 5, 15),
        0.002,
    )))
    .unwrap();

    // tenant-b: 1 project, 1 workspace, 1 key, 1 asset (500 bytes), 1 run,
    // 1 worker, current-month usage only.
    block_on(repositories.upsert_project(project("b-proj-1", "tenant-b"))).unwrap();
    block_on(repositories.upsert_workspace(workspace("b-ws-1", "b-proj-1", "tenant-b"))).unwrap();
    block_on(
        repositories.upsert_api_key_record(api_key("b-key-1", "tenant-b", "b-proj-1", "b-ws-1")),
    )
    .unwrap();
    block_on(repositories.upsert_asset(asset("b-asset-1", "tenant-b", 500))).unwrap();
    block_on(repositories.upsert_agent_run(agent_run("b-run-1", "tenant-b", "succeeded"))).unwrap();
    block_on(repositories.upsert_self_hosted_worker_registration(worker(
        "b-worker-1",
        "tenant-b",
        "active",
    )))
    .unwrap();
    block_on(repositories.append_billing_event(billing_event(
        "b-bill-current",
        "tenant-b",
        CURRENT_UNIX,
        TokenUsage::new(7, 3, 10),
        0.005,
    )))
    .unwrap();
}

fn approx(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-9,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn overview_aggregate_global_matches_repositories() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    seed(&repositories);
    let current_month = period_month_from_unix(CURRENT_UNIX as i64);
    assert_ne!(current_month, period_month_from_unix(PREVIOUS_UNIX as i64));

    let global = block_on(repositories.overview_aggregate(None, &current_month)).unwrap();

    // Inventory counts must equal exactly what the list repositories hold --
    // the acceptance "counts match their repositories" check, done against the
    // live repository reads rather than hardcoded numbers.
    assert_eq!(
        global.tenants,
        block_on(repositories.list_tenant_accounts()).unwrap().len() as u64
    );
    assert_eq!(
        global.projects,
        block_on(repositories.list_projects()).unwrap().len() as u64
    );
    assert_eq!(
        global.workspaces,
        block_on(repositories.list_workspaces()).unwrap().len() as u64
    );
    assert_eq!(
        global.virtual_keys,
        block_on(repositories.list_api_key_records()).unwrap().len() as u64
    );
    assert_eq!(
        global.assets,
        block_on(repositories.list_all_assets()).unwrap().len() as u64
    );
    assert_eq!(
        global.agent_runs,
        block_on(repositories.agent_runs()).len() as u64
    );
    assert_eq!(
        global.self_hosted_workers,
        block_on(repositories.self_hosted_worker_registrations()).len() as u64
    );

    // Explicit expected shape.
    assert_eq!(global.tenants, 2);
    assert_eq!(global.projects, 3);
    assert_eq!(global.workspaces, 4);
    assert_eq!(global.virtual_keys, 3);
    assert_eq!(global.assets, 3);
    assert_eq!(global.asset_storage_bytes, 800);
    assert_eq!(global.agent_runs, 4);
    assert_eq!(global.agent_runs_by_status.get("succeeded"), Some(&2));
    assert_eq!(global.agent_runs_by_status.get("failed"), Some(&1));
    assert_eq!(global.agent_runs_by_status.get("running"), Some(&1));
    assert_eq!(global.self_hosted_workers, 3);
    assert_eq!(global.self_hosted_workers_by_status.get("active"), Some(&2));
    assert_eq!(
        global.self_hosted_workers_by_status.get("draining"),
        Some(&1)
    );

    // Lifetime = every month; current month excludes the previous-month rows.
    assert_eq!(global.usage_lifetime.total_tokens, 175);
    assert_eq!(global.usage_lifetime.prompt_tokens, 117);
    assert_eq!(global.usage_lifetime.completion_tokens, 58);
    assert_eq!(global.usage_lifetime.request_count, 3);
    approx(global.usage_lifetime.cost_usd, 0.017);
    assert_eq!(global.usage_current_month.total_tokens, 160);
    assert_eq!(global.usage_current_month.prompt_tokens, 107);
    assert_eq!(global.usage_current_month.request_count, 2);
    approx(global.usage_current_month.cost_usd, 0.015);
    // The current month is a strict subset of lifetime.
    assert!(global.usage_current_month.total_tokens < global.usage_lifetime.total_tokens);
}

#[test]
fn overview_aggregate_tenant_scope_does_not_leak_other_tenants() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    seed(&repositories);
    let current_month = period_month_from_unix(CURRENT_UNIX as i64);

    let scoped =
        block_on(repositories.overview_aggregate(Some("tenant-a"), &current_month)).unwrap();

    // Only tenant-a's rows -- never tenant-b's (500-byte asset, extra
    // project/workspace/key, its run/worker, its usage).
    assert_eq!(scoped.tenants, 1);
    assert_eq!(scoped.projects, 2);
    assert_eq!(scoped.workspaces, 3);
    assert_eq!(scoped.virtual_keys, 2);
    assert_eq!(scoped.assets, 2);
    assert_eq!(scoped.asset_storage_bytes, 300);
    assert_eq!(scoped.agent_runs, 3);
    assert_eq!(scoped.self_hosted_workers, 2);
    assert_eq!(scoped.agent_runs_by_status.get("succeeded"), Some(&1));
    assert_eq!(
        scoped.self_hosted_workers_by_status.get("draining"),
        Some(&1)
    );

    // Usage is tenant-a only: lifetime 150 + 15, current month 150.
    assert_eq!(scoped.usage_lifetime.total_tokens, 165);
    assert_eq!(scoped.usage_lifetime.request_count, 2);
    assert_eq!(scoped.usage_current_month.total_tokens, 150);
    assert_eq!(scoped.usage_current_month.request_count, 1);
    approx(scoped.usage_current_month.cost_usd, 0.01);

    // A tenant that owns nothing gets zeroed counts and empty usage -- an honest
    // "no rows for this scope", never another tenant's numbers.
    let empty =
        block_on(repositories.overview_aggregate(Some("tenant-nope"), &current_month)).unwrap();
    assert_eq!(empty.projects, 0);
    assert_eq!(empty.assets, 0);
    assert_eq!(empty.usage_lifetime.total_tokens, 0);
    assert!(empty.agent_runs_by_status.is_empty());
}

// ---------------------------------------------------------------------------
// DSN-gated live-Postgres coverage: the COUNT/SUM pushdown override must return
// the same aggregate the in-memory fold does. Gated on
// `FERROGATE_TEST_POSTGRES_DSN`; skips cleanly when unset (the test gate runs it
// live). Mirrors the repo's existing DSN-gated pattern
// (`asset_visibility_promotion_test.rs`).
// ---------------------------------------------------------------------------

use crate::schema_routing_test_support::{serialize_db_test, unique_schema, SchemaGuard};
use crate::{PostgresStorageConfig, PostgresTlsMode, POSTGRES_SCHEMA_SQL};

#[test]
fn live_overview_aggregate_pushdown_matches_repositories() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_overview_aggregate_pushdown_matches_repositories: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };

    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_overview_test");
    let _guard = SchemaGuard::new(&dsn, &schema);
    crate::schema_routing_test_support::run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\"; \
             SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL}"
        ),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        pool_size: 2,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.clone()),
        search_path: Vec::new(),
    };
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN");

    seed(&repositories);
    let current_month = period_month_from_unix(CURRENT_UNIX as i64);

    let global = block_on(repositories.overview_aggregate(None, &current_month)).unwrap();
    assert_eq!(global.tenants, 2);
    assert_eq!(global.projects, 3);
    assert_eq!(global.workspaces, 4);
    assert_eq!(global.virtual_keys, 3);
    assert_eq!(global.assets, 3);
    assert_eq!(global.asset_storage_bytes, 800);
    assert_eq!(global.agent_runs, 4);
    assert_eq!(global.agent_runs_by_status.get("failed"), Some(&1));
    assert_eq!(global.self_hosted_workers, 3);
    assert_eq!(global.usage_lifetime.total_tokens, 175);
    assert_eq!(global.usage_current_month.total_tokens, 160);
    approx(global.usage_lifetime.cost_usd, 0.017);

    // Tenant scoping pushes `WHERE tenant = $1` into every count/sum: no leak.
    let scoped =
        block_on(repositories.overview_aggregate(Some("tenant-a"), &current_month)).unwrap();
    assert_eq!(scoped.tenants, 1);
    assert_eq!(scoped.projects, 2);
    assert_eq!(scoped.assets, 2);
    assert_eq!(scoped.asset_storage_bytes, 300);
    assert_eq!(scoped.usage_lifetime.total_tokens, 165);
    assert_eq!(scoped.usage_current_month.total_tokens, 150);
}
