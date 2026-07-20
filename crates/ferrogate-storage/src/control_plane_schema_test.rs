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

use crate::schema_routing_test_support::{
    block_on, count_rows, run_sql, serialize_db_test, unique_schema, SchemaGuard,
};
use crate::{
    PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories, StoredAgentRun,
    StoredAuditEvent, StoredPermission, StoredSelfHostedRunDispatch,
    StoredSelfHostedWorkerRegistration, StoredWallet, POSTGRES_SCHEMA_SQL,
};
use ferrogate_core::TenantContext;

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

    reopen_repositories(dsn, schema)
}

/// Open a second repository set pinned to an ALREADY-provisioned schema WITHOUT
/// re-running the schema DDL. Modelling a gateway restart against the same
/// durable store, the durably-persisted rows must survive across the two
/// instances (see [`live_self_hosted_lease_state_survives_gateway_restart`]).
fn reopen_repositories(dsn: &str, schema: &str) -> RuntimeStorageRepositories {
    let config = PostgresStorageConfig {
        dsn: dsn.to_string(),
        // One connection is enough for these single-op probes and keeps the
        // group's footprint on the shared live database minimal.
        pool_size: 1,
        // Generous timeouts: the operation deadline is bounded by
        // `statement_timeout_millis`, so a slow first-connection handshake to the
        // remote test database must not trip a tight 5s pool-acquisition deadline
        // (the source of the group-only flakes in #241).
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
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
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_rbac_test");
    let id = format!("perm-{schema}");
    let key = format!("cp.239.permission.{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema)
        .also(format!("DELETE FROM public.permissions WHERE id = '{id}';"));

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

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #239 (wallets): a wallet upsert must land in the configured schema.
#[test]
fn live_wallet_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_wallet_writes_to_configured_schema_not_public") else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_wallet_test");
    let tenant_id = format!("tenant-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.wallets WHERE tenant_id = '{tenant_id}';"
    ));

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

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #239 (agent runs): an agent-run upsert must land in the configured schema.
#[test]
fn live_agent_run_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_agent_run_writes_to_configured_schema_not_public") else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_agent_run_test");
    let id = format!("run-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema)
        .also(format!("DELETE FROM public.agent_runs WHERE id = '{id}';"));

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

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #239 (audit logs): an audit-event append must land in the configured schema.
#[test]
fn live_audit_event_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_audit_event_writes_to_configured_schema_not_public") else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_audit_test");
    let id = format!("audit-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.audit_events WHERE id = '{id}';"
    ));

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
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
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

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
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
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_worker_test");
    let id = format!("worker-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.self_hosted_worker_registrations WHERE id = '{id}';"
    ));

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

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #239 follow-up (wallets): the MULTI-statement `settle_wallet_balance` path
/// -- distinct from the already-covered single-statement `upsert_wallet` -- must
/// also land its `wallet_settlements` row (and `wallets` UPDATE) in the
/// configured schema, not `public`. This method opened a bare transaction with
/// no `SET LOCAL search_path`, so on a non-default schema the durable settlement
/// ledger split from every other wallet accessor.
#[test]
fn live_wallet_settlement_writes_to_configured_schema_not_public() {
    let Some(dsn) = dsn_or_skip("live_wallet_settlement_writes_to_configured_schema_not_public")
    else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_wsettle_test");
    let tenant_id = format!("tenant-{schema}");
    let settlement_id = format!("settle-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.wallet_settlements WHERE id = '{settlement_id}'; \
         DELETE FROM public.wallets WHERE tenant_id = '{tenant_id}';"
    ));

    // Shadow both wallet tables in `public` WITHOUT FKs -- they only need to
    // catch a misrouted settlement insert / balance update.
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
             CREATE TABLE IF NOT EXISTS public.wallet_settlements ( \
                 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, \
                 delta_credits BIGINT NOT NULL, balance_after_credits BIGINT, \
                 created_at_unix BIGINT NOT NULL DEFAULT 0); \
             DELETE FROM public.wallet_settlements WHERE id = '{settlement_id}'; \
             DELETE FROM public.wallets WHERE tenant_id = '{tenant_id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    // Seed the owning tenant + wallet in the configured schema (the settlement
    // UPDATEs an existing wallet row).
    run_sql(
        &dsn,
        &format!(
            "INSERT INTO \"{schema}\".tenants (id, name, slug, status) \
             VALUES ('{tenant_id}', 'cp-wsettle', '{tenant_id}', 'active') \
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
    .expect("seed wallet must not error");

    block_on(repositories.settle_wallet_balance(&settlement_id, &tenant_id, -250, 1_700_000_100))
        .expect("settle wallet balance must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".wallet_settlements \
                 WHERE id = '{settlement_id}'"
            )
        ),
        1,
        "the wallet settlement must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM public.wallet_settlements WHERE id = '{settlement_id}'"
            )
        ),
        0,
        "the wallet settlement must NOT be misrouted to the public schema (#239 follow-up)",
    );
    // The debit must have landed on the configured-schema wallet row.
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".wallets \
                 WHERE tenant_id = '{tenant_id}' AND balance_credits = 750"
            )
        ),
        1,
        "the debit must apply to the configured-schema wallet balance",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #239 follow-up (self-hosted dispatches): the MULTI-statement
/// `upsert_self_hosted_run_dispatch` writer -- distinct from the already-covered
/// worker-registration path -- must land its dispatch + capability rows in the
/// configured schema, not `public`. It opened a bare transaction with no
/// `SET LOCAL search_path` while its reader (`self_hosted_run_dispatches`) was
/// pinned, guaranteeing a read/write schema split on a non-default schema.
#[test]
fn live_self_hosted_run_dispatch_writes_to_configured_schema_not_public() {
    let Some(dsn) =
        dsn_or_skip("live_self_hosted_run_dispatch_writes_to_configured_schema_not_public")
    else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_dispatch_test");
    let dispatch_id = format!("dispatch-{schema}");
    let _guard = SchemaGuard::new(&dsn, &schema).also(format!(
        "DELETE FROM public.self_hosted_run_dispatch_capabilities WHERE dispatch_id = '{dispatch_id}'; \
         DELETE FROM public.self_hosted_run_dispatches WHERE dispatch_id = '{dispatch_id}';"
    ));

    // Shadow both dispatch tables in `public` WITHOUT FKs -- they only need to
    // catch a misrouted insert.
    run_sql(
        &dsn,
        &format!(
            "CREATE TABLE IF NOT EXISTS public.self_hosted_run_dispatches ( \
                 dispatch_id TEXT PRIMARY KEY, action TEXT NOT NULL, tenant TEXT, \
                 workspace_id TEXT NOT NULL, session_id TEXT NOT NULL, run_id TEXT NOT NULL, \
                 framework_adapter TEXT NOT NULL, workload_ref TEXT NOT NULL, \
                 queued_at_unix BIGINT NOT NULL, assigned_worker_id TEXT, lease_id TEXT, \
                 lease_expires_at_unix BIGINT, attempt BIGINT NOT NULL DEFAULT 0, \
                 acknowledged_status TEXT, acknowledged_at_unix BIGINT); \
             CREATE TABLE IF NOT EXISTS public.self_hosted_run_dispatch_capabilities ( \
                 dispatch_id TEXT NOT NULL, capability TEXT NOT NULL, \
                 PRIMARY KEY (dispatch_id, capability)); \
             DELETE FROM public.self_hosted_run_dispatch_capabilities WHERE dispatch_id = '{dispatch_id}'; \
             DELETE FROM public.self_hosted_run_dispatches WHERE dispatch_id = '{dispatch_id}';"
        ),
    );

    let repositories = open_repositories(&dsn, &schema);
    block_on(
        repositories.upsert_self_hosted_run_dispatch(StoredSelfHostedRunDispatch {
            dispatch_id: dispatch_id.clone(),
            action: "start".into(),
            tenant_id: String::new(),
            workspace_id: "workspace-cp-239".into(),
            session_id: "session-cp-239".into(),
            run_id: "run-cp-239".into(),
            framework_adapter: "langgraph".into(),
            required_capabilities: vec!["gpu".into(), "linux".into()],
            workload_ref: "oci://cp-239".into(),
            queued_at_unix: Some(1_700_000_000),
            assigned_worker_id: None,
            lease_id: None,
            lease_expires_at_unix: None,
            attempt: 0,
            acknowledged_status: None,
            acknowledged_at_unix: None,
            request_id: Some("fg-cp-239".into()),
            trace_id: Some("trace-cp-239".into()),
            agent_run_id: Some("run-cp-239".into()),
        }),
    )
    .expect("upsert self-hosted run dispatch must not error");
    drop(repositories);

    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".self_hosted_run_dispatches \
                 WHERE dispatch_id = '{dispatch_id}'"
            )
        ),
        1,
        "the dispatch must be persisted in the configured schema",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".self_hosted_run_dispatch_capabilities \
                 WHERE dispatch_id = '{dispatch_id}'"
            )
        ),
        2,
        "the dispatch capabilities must be persisted in the configured schema",
    );
    // #305 (migration 46): the correlation-key columns land populated in the
    // configured schema.
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".self_hosted_run_dispatches \
                 WHERE dispatch_id = '{dispatch_id}' \
                   AND request_id = 'fg-cp-239' \
                   AND trace_id = 'trace-cp-239' \
                   AND agent_run_id = 'run-cp-239'"
            )
        ),
        1,
        "the dispatch correlation keys must be persisted in the configured schema (#305)",
    );
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM public.self_hosted_run_dispatches \
                 WHERE dispatch_id = '{dispatch_id}'"
            )
        ),
        0,
        "the dispatch must NOT be misrouted to the public schema (#239 follow-up)",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #244 (durable dispatch lease queue): an IN-FLIGHT lease (assigned to a
/// worker, attempt 1, unacknowledged, deadline in the future) persisted before a
/// gateway restart must survive that restart. Modelling the restart as a SECOND
/// repository set opened over the SAME durable schema (the reload path
/// `AppState::try_new` runs through `self_hosted_run_dispatches()`), the reloaded
/// lease must carry the exact assignment / attempt / ack-window state -- so the
/// gateway resumes it (no drop) and does not re-lease it to another worker before
/// the deadline lapses (no double-deliver). The prior tests only proved a single
/// upsert's schema routing; this proves the lease state genuinely survives a
/// restart round-trip through Postgres.
#[test]
fn live_self_hosted_lease_state_survives_gateway_restart() {
    let Some(dsn) = dsn_or_skip("live_self_hosted_lease_state_survives_gateway_restart") else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_lease_restart_test");
    let dispatch_id = format!("dispatch-{schema}");
    let lease_id = format!("{dispatch_id}:attempt-1");
    let _guard = SchemaGuard::new(&dsn, &schema);

    // Instance #1 -- the pre-restart gateway. Persist an in-flight lease: run
    // leased to `worker-lease`, attempt 1, deadline 1_700_000_030, unacknowledged.
    let pre_restart = open_repositories(&dsn, &schema);
    // `self_hosted_run_dispatches.assigned_worker_id` FKs the worker
    // registration, so the assigned worker must exist first (as it does in the
    // live rebuild path, where registrations are reloaded alongside dispatches).
    block_on(pre_restart.upsert_self_hosted_worker_registration(
        StoredSelfHostedWorkerRegistration {
            id: "worker-lease".into(),
            tenant: TenantContext::default(),
            workspace_id: "workspace-lease".into(),
            worker_name: "lease-restart".into(),
            status: "active".into(),
            identity_fingerprint: "fingerprint-worker-lease".into(),
            identity_expires_at_unix: None,
            orchestration_enabled: true,
            registered_at_unix: Some(1_700_000_000),
            last_seen_at_unix: None,
            trust_level: "reported_by_self_hosted_worker".into(),
            capability_envelope_json: "{}".into(),
            token_secret: "lease-restart-secret-lease-restart".into(),
        },
    ))
    .expect("seed assigned worker registration must not error");
    block_on(
        pre_restart.upsert_self_hosted_run_dispatch(StoredSelfHostedRunDispatch {
            dispatch_id: dispatch_id.clone(),
            action: "start_run".into(),
            tenant_id: String::new(),
            workspace_id: "workspace-lease".into(),
            session_id: "session-lease".into(),
            run_id: "run-lease".into(),
            framework_adapter: "codex".into(),
            required_capabilities: vec!["logs".into()],
            workload_ref: "queue://runs/run-lease".into(),
            queued_at_unix: Some(1_700_000_000),
            assigned_worker_id: Some("worker-lease".into()),
            lease_id: Some(lease_id.clone()),
            lease_expires_at_unix: Some(1_700_000_030),
            attempt: 1,
            acknowledged_status: None,
            acknowledged_at_unix: None,
            request_id: Some("fg-lease-restart".into()),
            trace_id: Some("trace-lease-restart".into()),
            agent_run_id: Some("run-lease".into()),
        }),
    )
    .expect("persist in-flight lease must not error");
    // Simulate the gateway shutting down: drop every connection to the store.
    drop(pre_restart);

    // Instance #2 -- the post-restart gateway rebuilds from the SAME schema
    // WITHOUT re-provisioning it (no DDL), exactly as a real restart would.
    let restarted = reopen_repositories(&dsn, &schema);
    let dispatches = block_on(restarted.self_hosted_run_dispatches());
    drop(restarted);

    let restored = dispatches
        .iter()
        .find(|dispatch| dispatch.dispatch_id == dispatch_id)
        .expect("the in-flight lease must survive the gateway restart (no drop)");

    // No drop: the full assignment / attempt / ack-window state is intact, so the
    // restarted gateway can resume and honor the original worker's ack.
    assert_eq!(
        restored.assigned_worker_id.as_deref(),
        Some("worker-lease"),
        "the lease assignment must survive the restart",
    );
    assert_eq!(
        restored.lease_id.as_deref(),
        Some(lease_id.as_str()),
        "the lease id must survive the restart",
    );
    assert_eq!(
        restored.attempt, 1,
        "the attempt count must survive the restart (not reset to 0)",
    );
    assert_eq!(
        restored.lease_expires_at_unix,
        Some(1_700_000_030),
        "the ack window (lease deadline) must survive the restart",
    );
    assert_eq!(
        restored.acknowledged_status, None,
        "the lease must still read as unacknowledged after the restart",
    );
    assert_eq!(
        restored.required_capabilities,
        vec!["logs".to_string()],
        "the dispatch capabilities must survive the restart",
    );
    // #305: the correlation triple survives the restart round-trip too.
    assert_eq!(restored.request_id.as_deref(), Some("fg-lease-restart"));
    assert_eq!(restored.trace_id.as_deref(), Some("trace-lease-restart"));
    assert_eq!(restored.agent_run_id.as_deref(), Some("run-lease"));

    // No double-deliver: while the deadline holds, exactly one active lease row
    // remains bound to the original worker -- there is no second, unassigned copy
    // the restarted gateway could hand to a different worker.
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".self_hosted_run_dispatches \
                 WHERE run_id = 'run-lease' AND assigned_worker_id = 'worker-lease' \
                 AND acknowledged_status IS NULL"
            )
        ),
        1,
        "exactly one in-flight lease must remain bound to the original worker",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}

/// #250: the gateway's OWN schema initialization (`migration_mode: auto` /
/// `initialize_schema`) must create the configured `postgres_schema` and land
/// every table of `POSTGRES_SCHEMA_SQL` inside it -- NOT in the
/// connection-default schema (`public`). The sync driver did this per-session
/// (`CREATE SCHEMA IF NOT EXISTS ...; SET search_path ...`); when #221 removed
/// it, the async DDL transaction ran unpinned, so a fresh auto-migrated
/// deployment left the configured schema empty while validation (also
/// unpinned) still passed against `public`. Surfaced by the release e2e:
/// `expected ferrogate_control.control_plane_resources, got count 0`.
///
/// Deliberately does NOT pre-provision the schema: initialization itself must
/// create it, then validation (schema-pinned) must pass against it.
#[test]
fn live_initialize_schema_provisions_the_configured_schema_not_public() {
    let Some(dsn) =
        dsn_or_skip("live_initialize_schema_provisions_the_configured_schema_not_public")
    else {
        return;
    };
    let _db = serialize_db_test();
    let schema = unique_schema("ferrogate_cp_init_test");
    let _guard = SchemaGuard::new(&dsn, &schema);

    let config = PostgresStorageConfig {
        dsn: dsn.to_string(),
        pool_size: 1,
        pool_acquire_timeout_millis: 30_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 20,
        statement_timeout_millis: 30_000,
        schema: Some(schema.to_string()),
        search_path: Vec::new(),
    };
    // Guard against the leak class that #237/#250 hardened and that #253 found
    // already sitting in the live `public` schema: initialize_schema must not
    // create ANY control-plane table in `public`. `public` may already carry a
    // stale duplicate (historical, pre-pinning), so we assert the DELTA is zero
    // across this init rather than an absolute count -- a NEW leak still fails.
    let public_probe_tables = [
        "control_plane_resources",
        "control_plane_replay_floors",
        "storage_schema_migrations",
        "agent_schedules",
        "agent_schedule_fires",
    ];
    let public_probe_sql = format!(
        "SELECT COUNT(*)::BIGINT FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name IN ({})",
        public_probe_tables
            .iter()
            .map(|t| format!("'{t}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let public_before = count_rows(&dsn, &public_probe_sql);

    // initialize_schema = true (the auto-migration path under test) and
    // validate_schema = true (validation must resolve the configured schema).
    let repositories = RuntimeStorageRepositories::postgres_for_migration(config, true, true)
        .expect("schema initialization + validation against the configured schema");
    drop(repositories);

    let public_after = count_rows(&dsn, &public_probe_sql);
    assert_eq!(
        public_before, public_after,
        "initialize_schema must not create control-plane tables in `public` \
         (before={public_before}, after={public_after}); it must pin the configured schema {schema}",
    );

    // Migration 1's most fundamental table plus the current head's newest tables
    // (037_agent_schedules) must all exist in the CONFIGURED schema.
    for table in [
        "control_plane_resources",
        "control_plane_replay_floors",
        "agent_schedules",
        "agent_schedule_fires",
        "storage_schema_migrations",
    ] {
        assert_eq!(
            count_rows(
                &dsn,
                &format!(
                    "SELECT COUNT(*)::BIGINT FROM information_schema.tables \
                     WHERE table_schema = '{schema}' AND table_name = '{table}'"
                )
            ),
            1,
            "initialize_schema must create {table} inside the configured schema {schema}",
        );
    }

    // The migration ledger inside the configured schema must record the
    // current head (37 / 037_agent_schedules).
    assert_eq!(
        count_rows(
            &dsn,
            &format!(
                "SELECT COUNT(*)::BIGINT FROM \"{schema}\".storage_schema_migrations \
                 WHERE version = 37 AND name = '037_agent_schedules'"
            )
        ),
        1,
        "the configured schema's migration ledger must record head 37",
    );

    // Teardown is handled by `_guard` (RAII), which also runs on panic.
}
