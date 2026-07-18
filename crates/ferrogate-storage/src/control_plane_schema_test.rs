// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-18
// description: DSN-gated schema-routing coverage for the remaining bare-query
// control-plane subsystems pinned in #239 (rbac, wallets, self-hosted workers,
// agent runs, audit logs). Each test proves a row written through the public
// repository API lands in the CONFIGURED `postgres_schema`, not the
// connection-default `public` schema -- the same masking scenario #237/#238
// fixed for the replay floor and usage-metadata rollups. All are gated on
// `FERROGATE_TEST_POSTGRES_DSN` and skip cleanly when it is unset.

use crate::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories, StoredAgentRun,
    StoredAuditEvent, StoredPermission, StoredSelfHostedWorkerRegistration, StoredWallet,
    POSTGRES_SCHEMA_SQL,
};
use ferrogate_core::TenantContext;

/// Run a batch of setup/teardown SQL against the test DSN over a throwaway
/// connection.
fn run_sql(dsn: &str, sql: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
                .await
                .expect("connect to the test postgres");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            client
                .batch_execute(sql)
                .await
                .expect("execute test setup/teardown sql");
            drop(client);
            let _ = driver.await;
        });
}

/// Count rows matching `sql` (a `SELECT COUNT(*)::BIGINT ...`) against the test
/// DSN. Used to prove which physical schema a control-plane row landed in.
fn count_rows(dsn: &str, sql: &str) -> i64 {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(async {
            let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
                .await
                .expect("connect to the test postgres");
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let row = client
                .query_one(sql, &[])
                .await
                .expect("count the control-plane probe rows");
            drop(client);
            let _ = driver.await;
            row.get::<_, i64>(0)
        })
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// Provision the FULL control-plane schema inside a fresh, unique, non-default
/// schema and open a Postgres-backed repository set pinned to it (no `public`
/// fallback in the search path, so any regression to a bare query would resolve
/// against the connection-default `public` schema).
fn open_repositories(dsn: &str, schema: &str) -> RuntimeStorageRepositories {
    run_sql(
        dsn,
        &format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; CREATE SCHEMA \"{schema}\";"),
    );
    // `POSTGRES_SCHEMA_SQL` carries no `public.`-qualified references, so it
    // lands entirely in the search-path schema we set first.
    run_sql(
        dsn,
        &format!("SET search_path TO \"{schema}\"; {POSTGRES_SCHEMA_SQL}"),
    );

    let config = PostgresStorageConfig {
        dsn: dsn.to_string(),
        pool_size: 2,
        pool_acquire_timeout_millis: 5_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 5,
        statement_timeout_millis: 5_000,
        schema: Some(schema.to_string()),
        search_path: Vec::new(),
    };
    RuntimeStorageRepositories::postgres_for_migration(config, false, false)
        .expect("open the postgres control plane against the test DSN")
}

/// Skip helper: returns the DSN or prints a skip notice and returns `None`.
fn dsn_or_skip(test: &str) -> Option<String> {
    match std::env::var("FERROGATE_TEST_POSTGRES_DSN") {
        Ok(dsn) => Some(dsn),
        Err(_) => {
            eprintln!("skipping {test}: FERROGATE_TEST_POSTGRES_DSN is not set");
            None
        }
    }
}

/// #239 (rbac): an rbac permission upsert must land in the configured schema.
#[test]
fn live_rbac_permission_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_rbac_permission_writes_to_configured_schema_not_public")
    else {
        return;
    };
    let schema = format!("ferrogate_cp_rbac_test_{}", std::process::id());
    let id = format!("perm-cp-239-{}", std::process::id());
    let key = format!("cp.239.permission.{}", std::process::id());

    // Shadow the table in `public` (masking scenario: table present in both).
    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.permissions ( \
                 id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, \
                 description TEXT NOT NULL DEFAULT '', \
                 created_at_unix BIGINT NOT NULL DEFAULT 0, \
                 updated_at_unix BIGINT NOT NULL DEFAULT 0); \
             DELETE FROM public.permissions WHERE id = '{id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    block_on(repositories.upsert_permission(StoredPermission {
        id: id.clone(),
        key: key.clone(),
        name: "cp-239".into(),
        description: "schema routing probe".into(),
        created_at_unix: 1_700_000_000,
        updated_at_unix: 1_700_000_000,
    }))
    .expect("upsert permission must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM \"{schema}\".permissions WHERE id = '{id}'")
        ),
        1,
        "the permission must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM public.permissions WHERE id = '{id}'")
        ),
        0,
        "the permission must NOT be misrouted to the public schema (#239)",
    );

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.permissions WHERE id = '{id}';"
        ),
    );
}

/// #239 (wallets): a wallet upsert must land in the configured schema.
#[test]
fn live_wallet_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_wallet_writes_to_configured_schema_not_public") else {
        return;
    };
    let schema = format!("ferrogate_cp_wallet_test_{}", std::process::id());
    let tenant_id = format!("tenant-cp-239-{}", std::process::id());

    // The wallet write requires its owning tenant (FK). `public.wallets` is
    // shadowed WITHOUT the FK -- it only needs to catch a misrouted insert.
    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.wallets ( \
                 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, \
                 balance_credits BIGINT NOT NULL DEFAULT 0, \
                 auto_recharge_threshold_credits BIGINT, \
                 auto_recharge_amount_credits BIGINT, \
                 dunning BOOLEAN NOT NULL DEFAULT FALSE, \
                 created_at_unix BIGINT NOT NULL DEFAULT 0, \
                 updated_at_unix BIGINT NOT NULL DEFAULT 0); \
             DELETE FROM public.wallets WHERE tenant_id = '{tenant_id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    // Seed the owning tenant inside the configured schema (satisfies the FK).
    run_sql(
        &dsn,
        &format!(
            "INSERT INTO \"{schema}\".tenants (id, name, slug, status) \
             VALUES ('{tenant_id}', 'cp-239', '{tenant_id}', 'active') \
             ON CONFLICT (id) DO NOTHING;"
        ),
    );
    block_on(repositories.upsert_wallet(StoredWallet {
        id: tenant_id.clone(),
        tenant_id: tenant_id.clone(),
        balance_credits: 1_000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 1_700_000_000,
        updated_at_unix: 1_700_000_000,
    }))
    .expect("upsert wallet must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".wallets WHERE tenant_id = '{tenant_id}'"
            )
        ),
        1,
        "the wallet must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM public.wallets WHERE tenant_id = '{tenant_id}'")
        ),
        0,
        "the wallet must NOT be misrouted to the public schema (#239)",
    );

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.wallets WHERE tenant_id = '{tenant_id}';"
        ),
    );
}

/// #239 (agent runs): an agent-run upsert must land in the configured schema.
#[test]
fn live_agent_run_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_agent_run_writes_to_configured_schema_not_public") else {
        return;
    };
    let schema = format!("ferrogate_cp_agent_run_test_{}", std::process::id());
    let id = format!("run-cp-239-{}", std::process::id());

    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.agent_runs ( \
                 id TEXT PRIMARY KEY, request_id TEXT NOT NULL, trace_id TEXT, tenant TEXT, \
                 status TEXT NOT NULL, provider TEXT, started_at_unix BIGINT NOT NULL, \
                 completed_at_unix BIGINT, run_json JSONB NOT NULL DEFAULT '{{}}'::JSONB); \
             DELETE FROM public.agent_runs WHERE id = '{id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    block_on(repositories.upsert_agent_run(StoredAgentRun {
        id: id.clone(),
        request_id: format!("req-{id}"),
        trace_id: None,
        tenant: TenantContext::default(),
        status: "running".into(),
        provider: "openai".into(),
        turns_executed: 1,
        output_recorded: false,
        started_at_unix: Some(1_700_000_000),
        completed_at_unix: None,
    }))
    .expect("upsert agent run must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM \"{schema}\".agent_runs WHERE id = '{id}'")
        ),
        1,
        "the agent run must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM public.agent_runs WHERE id = '{id}'")
        ),
        0,
        "the agent run must NOT be misrouted to the public schema (#239)",
    );

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.agent_runs WHERE id = '{id}';"
        ),
    );
}

/// #239 (audit logs): an audit-event append must land in the configured schema.
#[test]
fn live_audit_event_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_audit_event_writes_to_configured_schema_not_public") else {
        return;
    };
    let schema = format!("ferrogate_cp_audit_test_{}", std::process::id());
    let id = format!("audit-cp-239-{}", std::process::id());

    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.audit_events ( \
                 id TEXT PRIMARY KEY, request_id TEXT, trace_id TEXT, agent_run_id TEXT, \
                 workflow_id TEXT, workflow_version TEXT, workflow_node_id TEXT, cluster_id TEXT, \
                 node_id TEXT, actor_api_key_id TEXT, tenant TEXT, action TEXT NOT NULL, \
                 target TEXT, outcome TEXT NOT NULL, occurred_at_unix BIGINT NOT NULL, \
                 audit_json JSONB NOT NULL DEFAULT '{{}}'::JSONB); \
             DELETE FROM public.audit_events WHERE id = '{id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    block_on(repositories.append_audit_event(StoredAuditEvent {
        id: id.clone(),
        request_id: format!("req-{id}"),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: None,
        tenant: TenantContext::default(),
        action: "cp.239.probe".into(),
        target: "schema-routing".into(),
        outcome: "success".into(),
        message: "schema routing probe".into(),
        occurred_at_unix: Some(1_700_000_000),
    }));
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM \"{schema}\".audit_events WHERE id = '{id}'")
        ),
        1,
        "the audit event must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!("SELECT COUNT(*)::BIGINT FROM public.audit_events WHERE id = '{id}'")
        ),
        0,
        "the audit event must NOT be misrouted to the public schema (#239)",
    );

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.audit_events WHERE id = '{id}';"
        ),
    );
}

/// #239 (self-hosted workers): a worker registration upsert must land in the
/// configured schema.
#[test]
fn live_self_hosted_worker_registration_writes_to_configured_schema_not_public() {
    let Some(dsn) =
        dsn_or_skip("live_self_hosted_worker_registration_writes_to_configured_schema_not_public")
    else {
        return;
    };
    let schema = format!("ferrogate_cp_worker_test_{}", std::process::id());
    let id = format!("worker-cp-239-{}", std::process::id());

    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.self_hosted_worker_registrations ( \
                 id TEXT PRIMARY KEY, tenant TEXT, workspace_id TEXT NOT NULL, \
                 worker_name TEXT NOT NULL, status TEXT NOT NULL, \
                 identity_fingerprint TEXT NOT NULL, identity_expires_at_unix BIGINT, \
                 orchestration_enabled BOOLEAN NOT NULL DEFAULT FALSE, \
                 registered_at_unix BIGINT NOT NULL, last_seen_at_unix BIGINT, \
                 trust_level TEXT NOT NULL, \
                 capability_envelope_json JSONB NOT NULL DEFAULT '{{}}'::JSONB, \
                 token_secret TEXT NOT NULL DEFAULT ''); \
             DELETE FROM public.self_hosted_worker_registrations WHERE id = '{id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    block_on(repositories.upsert_self_hosted_worker_registration(
        StoredSelfHostedWorkerRegistration {
            id: id.clone(),
            tenant: TenantContext::default(),
            workspace_id: "workspace-cp-239".into(),
            worker_name: "cp-239".into(),
            status: "active".into(),
            identity_fingerprint: format!("fingerprint-{id}"),
            identity_expires_at_unix: None,
            orchestration_enabled: false,
            registered_at_unix: Some(1_700_000_000),
            last_seen_at_unix: None,
            trust_level: "trusted".into(),
            capability_envelope_json: "{}".into(),
            token_secret: "cp-239-secret-cp-239-secret".into(),
        },
    ))
    .expect("upsert self-hosted worker registration must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".self_hosted_worker_registrations \
                 WHERE id = '{id}'"
            )
        ),
        1,
        "the worker registration must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM public.self_hosted_worker_registrations \
                 WHERE id = '{id}'"
            )
        ),
        0,
        "the worker registration must NOT be misrouted to the public schema (#239)",
    );

    run_sql(
        &dsn,
        &format!(
            "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE; \
             DELETE FROM public.self_hosted_worker_registrations WHERE id = '{id}';"
        ),
    );
}
