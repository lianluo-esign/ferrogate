// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-11
// description: Unit tests for MCP identity storage, kept outside business logic.

use std::{
    future::Future,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

use super::*;
use crate::{
    async_postgres::AsyncPostgresPool, PostgresStorageConfig, PostgresTlsMode,
    StorageOperationCancelOutcome, StorageProviderKind, StorageSchemaEvidence, StoredAuditEvent,
};

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn audit_event(id: &str) -> StoredAuditEvent {
    StoredAuditEvent {
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
        id: id.into(),
        request_id: "request".into(),
        trace_id: Some("trace".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: Some("cluster".into()),
        node_id: Some("node".into()),
        actor_api_key_id: Some("key".into()),
        tenant: ferrogate_core::TenantContext {
            organization_id: Some("tenant".into()),
            ..Default::default()
        },
        action: "mcp.identity.resolve".into(),
        target: "mcp_server:identity".into(),
        outcome: "rejected".into(),
        message: "storage deadline".into(),
        occurred_at_unix: Some(1),
        parent_action_fingerprint: None,
    }
}

fn credential() -> StoredMcpOauthCredential {
    StoredMcpOauthCredential {
        id: "credential".into(),
        tenant_id: "tenant".into(),
        workspace_id: "workspace".into(),
        user_id: "user".into(),
        server_name: "server".into(),
        issuer: "https://issuer.invalid".into(),
        subject: "user".into(),
        token_type: "Bearer".into(),
        scopes: vec!["openid".into()],
        access_token_nonce: vec![1],
        access_token_ciphertext: vec![2],
        refresh_token_nonce: Some(vec![3]),
        refresh_token_ciphertext: Some(vec![4]),
        expires_at_unix: 1,
        key_version: 1,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: None,
        refresh_lease_expires_at_unix: None,
        created_at_unix: 1,
        updated_at_unix: 1,
        revoked_at_unix: None,
        last_refresh_outcome: None,
        last_revocation_outcome: None,
    }
}

fn repositories_with_credential() -> RuntimeStorageRepositories {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .insert("credential", credential());
    repositories
}

fn exhausted_postgres_store() -> PostgresControlPlaneStore {
    let config = PostgresStorageConfig {
        dsn: "host=127.0.0.1 port=1 user=postgres".into(),
        pool_size: 1,
        pool_acquire_timeout_millis: 40,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 1,
        statement_timeout_millis: 1_000,
        schema: None,
        search_path: Vec::new(),
    };
    PostgresControlPlaneStore {
        async_pool: Arc::new(AsyncPostgresPool::new(&config).expect("async test pool")),
        schema: StorageSchemaEvidence::postgres_expected(),
        usage_aggregates_mirror: crate::Mutex::new(crate::InMemoryRepository::new()),
        durable_worker_retention_records: 0,
        heartbeat_prune_ticks: crate::AtomicU64::new(0),
        telemetry_prune_ticks: crate::AtomicU64::new(0),
        artifact_prune_ticks: crate::AtomicU64::new(0),
        checkpoint_prune_ticks: crate::AtomicU64::new(0),
        agent_run_event_prune_ticks: crate::AtomicU64::new(0),
    }
}

#[test]
fn expired_operation_fences_async_mcp_identity_authorization_read() {
    let store = exhausted_postgres_store();
    let request = McpIdentityAccessRequest {
        tenant_id: "tenant".into(),
        workspace_id: "workspace".into(),
        user_id: "user".into(),
        server_name: "server".into(),
        permission_key: "mcp.identity.use".into(),
    };
    let operation = StorageOperation::new("authorize MCP refresh identity actor", Duration::ZERO);
    let started = Instant::now();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let error = runtime
        .block_on(store.authorize_mcp_identity_with_operation(&request, &operation))
        .expect_err("expired operation must bound the authorization read");

    assert!(matches!(
        error,
        StorageError::OperationDeadlineExceeded {
            operation: "authorize MCP refresh identity actor",
            stage: "authorization pool acquisition",
            commit_started: false,
        }
    ));
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(
        store.async_pool.metrics_snapshot(),
        crate::PostgresPoolMetricsSnapshot::default()
    );
}

#[test]
fn postgres_identity_authorization_is_one_short_nonlocking_read() {
    let query = postgres_mcp_identity_authorization_query();
    let normalized = query.to_ascii_uppercase();

    assert!(!query.contains(';'));
    assert!(!normalized.contains(" FOR UPDATE"));
    assert!(!normalized.contains(" FOR SHARE"));
    assert!(!normalized.contains(" LOCK "));
    assert!(!normalized.contains("PG_SLEEP"));
    assert!(!normalized.contains(" WITH "));
    assert!(normalized.contains("LEFT JOIN MCP_OAUTH_CREDENTIALS"));
    assert!(normalized.contains("CREDENTIAL.TENANT_ID=$1"));
    assert!(normalized.contains("CREDENTIAL.WORKSPACE_ID=$2"));
    assert!(normalized.contains("CREDENTIAL.USER_ID=$3"));
    assert!(normalized.contains("CREDENTIAL.SERVER_NAME=$4"));
    assert!(is_mcp_authorization_statement_timeout_code(Some(
        &tokio_postgres::error::SqlState::QUERY_CANCELED
    )));
    assert!(!is_mcp_authorization_statement_timeout_code(Some(
        &tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE
    )));
    assert!(!is_mcp_authorization_statement_timeout_code(None));
}

#[test]
fn expired_operation_fences_async_mcp_identity_audit_without_late_write() {
    let store = exhausted_postgres_store();
    let operation = StorageOperation::new("record MCP identity error audit", Duration::ZERO);
    let started = Instant::now();

    let error = block_on(store.append_mcp_identity_audit_event_with_operation(
        &audit_event("audit-deadline"),
        &operation,
    ))
    .expect_err("empty pool must fence the audit append");

    assert!(matches!(
        error,
        StorageError::OperationDeadlineExceeded {
            operation: "record MCP identity error audit",
            stage: "audit pool acquisition",
            commit_started: false,
        }
    ));
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(
        store.async_pool.metrics_snapshot(),
        crate::PostgresPoolMetricsSnapshot::default()
    );
}

#[test]
fn in_memory_mcp_identity_audit_append_still_persists_when_operation_is_available() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 16, 16);
    let operation =
        StorageOperation::new("record MCP identity error audit", Duration::from_secs(1));

    block_on(
        repositories
            .append_mcp_identity_audit_event_with_operation(audit_event("audit-ok"), &operation),
    )
    .expect("available audit repository must persist");

    let events = block_on(repositories.audit_events());
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "audit-ok");
}

#[test]
fn storage_operation_cancel_and_commit_have_exactly_one_winner() {
    let cancelled = StorageOperation::new("cancel winner", Duration::from_secs(1));
    assert_eq!(cancelled.cancel(), StorageOperationCancelOutcome::Cancelled);
    assert!(matches!(
        cancelled.begin_commit("test commit"),
        Err(StorageError::OperationCancelled { .. })
    ));

    let committing = StorageOperation::new("commit winner", Duration::from_secs(1));
    committing
        .begin_commit("test commit")
        .expect("commit fence must be acquired");
    assert_eq!(
        committing.cancel(),
        StorageOperationCancelOutcome::CommitStarted
    );
    committing.finish_commit();
    assert_eq!(committing.cancel(), StorageOperationCancelOutcome::Finished);
}

#[test]
fn only_explicit_completion_operations_reconcile_commit_after_deadline() {
    let renewal = StorageOperation::new("renewal", Duration::from_secs(1));
    let completion = StorageOperation::new_reconcilable_commit(
        "completion",
        Duration::from_secs(1),
        Duration::from_secs(10),
    );

    assert!(!renewal.reconciles_commit_after_deadline());
    assert!(completion.reconciles_commit_after_deadline());
    assert_eq!(
        completion.reconciliation_commit_timeout(),
        Some(Duration::from_secs(10))
    );
    assert_eq!(renewal.reconciliation_commit_timeout(), None);
    assert_eq!(
        mcp_refresh_transaction_statement_timeout_millis(
            Some(&completion),
            "refresh completion CAS"
        )
        .unwrap(),
        1_000
    );
    assert!(matches!(
        mcp_transaction_commit_outcome_unknown(&completion),
        StorageError::OperationCommitOutcomeUnknown {
            operation: "completion",
            stage: "transaction commit",
        }
    ));
}

#[test]
fn statement_timeout_rounds_up_without_overflow_or_early_cancellation() {
    assert_eq!(mcp_statement_timeout_millis(Duration::ZERO), 1);
    assert_eq!(mcp_statement_timeout_millis(Duration::from_nanos(1)), 1);
    assert_eq!(
        mcp_statement_timeout_millis(Duration::from_nanos(999_999)),
        1
    );
    assert_eq!(mcp_statement_timeout_millis(Duration::from_millis(1)), 1);
    assert_eq!(
        mcp_statement_timeout_millis(Duration::from_millis(1) + Duration::from_nanos(1)),
        2
    );
    assert_eq!(mcp_statement_timeout_millis(Duration::MAX), i32::MAX);
}

#[test]
fn transaction_sequence_recomputes_commit_budget_from_the_absolute_deadline() {
    let operation = StorageOperation::new("multi statement", Duration::from_millis(80));
    let first = mcp_statement_timeout_for_operation(&operation, "credential lock")
        .expect("credential lock timeout");
    std::thread::sleep(Duration::from_millis(20));
    let commit = mcp_statement_timeout_for_operation(&operation, "transaction commit")
        .expect("commit timeout");

    assert!(first <= 80);
    assert!(commit < first);
    std::thread::sleep(Duration::from_millis(70));
    assert!(matches!(
        mcp_statement_timeout_for_operation(&operation, "late statement"),
        Err(StorageError::OperationDeadlineExceeded {
            operation: "multi statement",
            stage: "late statement",
            commit_started: false,
        })
    ));
}

#[test]
fn cancelled_refresh_renewal_and_completion_cannot_mutate_later() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    let before = match &repositories.control_plane {
        RuntimeControlPlaneBackend::Memory(store) => store
            .lock()
            .expect("memory control plane lock")
            .mcp_oauth_credentials
            .get("credential")
            .expect("credential"),
        RuntimeControlPlaneBackend::Postgres(_) => panic!("expected memory control plane"),
    };

    let renewal = StorageOperation::new("cancelled renewal", Duration::from_secs(1));
    assert_eq!(renewal.cancel(), StorageOperationCancelOutcome::Cancelled);
    let renewal_error = block_on(repositories.renew_mcp_oauth_refresh_with_operation(
        &McpRefreshRenewRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: "owner".into(),
            expected_lease_expires_at_unix: 20,
            now_unix: 15,
            lease_ttl_secs: 10,
        },
        &renewal,
    ))
    .expect_err("cancelled renewal must be fenced");
    assert!(matches!(
        renewal_error,
        StorageError::OperationCancelled { .. }
    ));

    let mut refreshed = before.clone();
    refreshed.access_token_ciphertext = vec![99];
    refreshed.last_refresh_outcome = Some("refreshed".into());
    let completion = StorageOperation::new("cancelled completion", Duration::from_secs(1));
    assert_eq!(
        completion.cancel(),
        StorageOperationCancelOutcome::Cancelled
    );
    let completion_error = block_on(repositories.complete_mcp_oauth_refresh_with_operation(
        refreshed,
        "owner",
        &completion,
    ))
    .expect_err("cancelled completion must be fenced");
    assert!(matches!(
        completion_error,
        StorageError::OperationCancelled { .. }
    ));

    std::thread::sleep(Duration::from_millis(20));
    let after = match &repositories.control_plane {
        RuntimeControlPlaneBackend::Memory(store) => store
            .lock()
            .expect("memory control plane lock")
            .mcp_oauth_credentials
            .get("credential")
            .expect("credential"),
        RuntimeControlPlaneBackend::Postgres(_) => panic!("expected memory control plane"),
    };
    assert_eq!(after, before);
}

#[test]
fn in_memory_refresh_renewal_waiting_on_lock_past_deadline_cannot_extend_later() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 20),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    let operation = StorageOperation::new("lock-blocked renewal", Duration::from_millis(20));
    let request = McpRefreshRenewRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        expected_lease_expires_at_unix: 30,
        now_unix: 15,
        lease_ttl_secs: 100,
    };
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let guard = store.lock().expect("memory control plane lock");
    let result = std::thread::scope(|scope| {
        let renewal = scope.spawn(|| {
            block_on(repositories.renew_mcp_oauth_refresh_with_operation(&request, &operation))
        });
        std::thread::sleep(Duration::from_millis(50));
        drop(guard);
        renewal.join().expect("renewal worker")
    });
    assert!(matches!(
        result,
        Err(StorageError::OperationDeadlineExceeded {
            operation: "lock-blocked renewal",
            stage: "in-memory refresh renewal",
            commit_started: false,
        })
    ));
    let after =
        block_on(repositories.get_mcp_oauth_credential("tenant", "workspace", "user", "server"))
            .unwrap()
            .expect("credential");
    assert_eq!(after.refresh_lease_expires_at_unix, Some(30));
}

fn claim(
    repositories: &RuntimeStorageRepositories,
    lease_id: &str,
    now_unix: i64,
    lease_ttl_secs: i64,
) -> McpRefreshClaimOutcome {
    block_on(
        repositories.claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: lease_id.into(),
            now_unix,
            lease_ttl_secs,
        }),
    )
    .expect("refresh claim")
}

fn renew(
    repositories: &RuntimeStorageRepositories,
    lease_id: &str,
    now_unix: i64,
    lease_ttl_secs: i64,
) -> McpRefreshRenewOutcome {
    let expected_lease_expires_at_unix =
        block_on(repositories.get_mcp_oauth_credential("tenant", "workspace", "user", "server"))
            .expect("credential lookup")
            .and_then(|credential| credential.refresh_lease_expires_at_unix)
            .unwrap_or(now_unix);
    block_on(
        repositories.renew_mcp_oauth_refresh(&McpRefreshRenewRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: lease_id.into(),
            expected_lease_expires_at_unix,
            now_unix,
            lease_ttl_secs,
        }),
    )
    .expect("refresh renewal")
}

#[test]
fn refresh_lease_has_exactly_one_concurrent_winner() {
    let repositories = Arc::new(repositories_with_credential());
    let barrier = Arc::new(Barrier::new(6));
    let mut handles = Vec::new();
    for lease_id in [
        "lease-a", "lease-b", "lease-c", "lease-d", "lease-e", "lease-f",
    ] {
        let repositories = Arc::clone(&repositories);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            block_on(
                repositories.claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
                    tenant_id: "tenant".into(),
                    credential_id: "credential".into(),
                    expected_version: 1,
                    authorization_generation: 1,
                    lease_id: lease_id.into(),
                    now_unix: 10,
                    lease_ttl_secs: 10,
                }),
            )
            .expect("refresh claim")
        }));
    }
    let outcomes = handles
        .into_iter()
        .map(|handle| handle.join().expect("claim thread"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, McpRefreshClaimOutcome::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, McpRefreshClaimOutcome::Busy { .. }))
            .count(),
        5
    );
}

#[test]
fn postgres_refresh_claim_is_one_optimistic_cas_without_explicit_row_lock() {
    let query = postgres_refresh_claim_query();

    assert!(query.contains("UPDATE mcp_oauth_credentials"));
    assert!(query.contains("clock_timestamp()"));
    assert!(query.contains("version=$3"));
    assert!(query.contains("authorization_generation=$4"));
    assert!(query.contains("revoked_at_unix IS NULL"));
    assert!(query.contains("RETURNING"));
    assert!(!query.contains("FOR UPDATE"));
}

#[test]
fn refresh_mutation_transaction_has_one_local_setup_statement() {
    let query = mcp_refresh_transaction_setup_query();

    assert_eq!(query.matches("set_config(").count(), 4);
    assert!(query.contains("'ferrogate.tenant_id'"));
    assert!(query.contains("'ferrogate.platform_mode'"));
    assert!(query.contains("'lock_timeout'"));
    assert!(query.contains("'statement_timeout'"));
    assert_eq!(query.matches("true").count(), 4);
    assert!(!query.contains(';'));
    assert!(!query.contains("CREATE"));
}

#[test]
fn authoritative_refresh_reread_is_existing_schema_only() {
    let query = postgres_refresh_authoritative_reread_query();

    assert!(query.contains("mcp_oauth_credentials"));
    assert!(query.contains("clock_timestamp()"));
    assert!(!query.contains("CREATE"));
    assert!(!query.contains("ALTER"));
    assert!(!query.contains("INSERT"));
    assert!(!query.contains("UPDATE"));
    assert!(!query.contains("DELETE"));
    assert!(!query.contains("FOR UPDATE"));
}

#[test]
fn postgres_refresh_renewal_is_one_database_clock_cas_without_explicit_row_lock() {
    let query = postgres_refresh_renewal_query();

    assert!(query.contains("UPDATE mcp_oauth_credentials"));
    assert!(query.contains("clock_timestamp()"));
    assert!(query.contains("version=$3"));
    assert!(query.contains("authorization_generation=$4"));
    assert!(query.contains("refresh_lease_id=$5"));
    assert!(query.contains("refresh_lease_expires_at_unix=$7"));
    assert!(query.contains("revoked_at_unix IS NULL"));
    assert!(query.contains("RETURNING refresh_lease_expires_at_unix"));
    assert!(query.contains("credential.revoked_at_unix IS NOT NULL"));
    assert!(query.contains("NOT EXISTS (SELECT 1 FROM renewed)"));
    assert!(!query.contains("FOR UPDATE"));
}

#[test]
fn postgres_identity_revoke_is_one_atomic_statement_without_waiting_sql() {
    let query = postgres_mcp_identity_revoke_query();

    assert!(query.contains("WITH revoked AS"));
    assert!(query.contains("generation AS"));
    assert!(query.contains("consumed_flows AS"));
    assert!(query.contains("UPDATE mcp_oauth_credentials"));
    assert!(query.contains("INSERT INTO mcp_oauth_authorization_states"));
    assert!(query.contains("UPDATE mcp_oauth_flows AS flow"));
    assert!(!query.contains(';'));
    assert!(!query.contains("FOR UPDATE"));
    assert!(!query.contains("pg_sleep"));
}

#[test]
fn renewal_reconciliation_recovers_ack_lost_commit() {
    let request = McpRefreshRenewRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        expected_lease_expires_at_unix: 100,
        now_unix: 90,
        lease_ttl_secs: 30,
    };
    let current = McpRefreshLeaseState {
        tenant_matches: true,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: Some("owner".into()),
        refresh_lease_expires_at_unix: Some(120),
        revoked: false,
    };

    assert_eq!(
        reconcile_mcp_refresh_renewal_state(Some(&current), &request, 91),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 120
        }
    );
}

#[test]
fn renewal_reconciliation_distinguishes_uncommitted_and_revoked_state() {
    let request = McpRefreshRenewRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        expected_lease_expires_at_unix: 100,
        now_unix: 90,
        lease_ttl_secs: 30,
    };
    let unchanged = McpRefreshLeaseState {
        tenant_matches: true,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: Some("owner".into()),
        refresh_lease_expires_at_unix: Some(100),
        revoked: false,
    };
    let revoked = McpRefreshLeaseState {
        revoked: true,
        ..unchanged.clone()
    };

    assert_eq!(
        reconcile_mcp_refresh_renewal_state(Some(&unchanged), &request, 91),
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: 100
        }
    );
    assert_eq!(
        reconcile_mcp_refresh_renewal_state(Some(&revoked), &request, 91),
        McpRefreshRenewOutcome::Revoked
    );
    assert_eq!(
        reconcile_mcp_refresh_renewal_state(None, &request, 91),
        McpRefreshRenewOutcome::Missing
    );
}

#[test]
fn claim_reconciliation_recovers_only_matching_durable_lease() {
    let request = McpRefreshClaimRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        now_unix: 90,
        lease_ttl_secs: 30,
    };
    let mut current = credential();
    current.refresh_lease_id = Some("owner".into());
    current.refresh_lease_expires_at_unix = Some(120);

    assert!(matches!(
        reconcile_mcp_refresh_claim_state(Some(current.clone()), &request, 91),
        McpRefreshClaimOutcome::Acquired(credential)
            if credential.refresh_lease_id.as_deref() == Some("owner")
    ));

    current.refresh_lease_id = None;
    current.refresh_lease_expires_at_unix = None;
    assert!(matches!(
        reconcile_mcp_refresh_claim_state(Some(current), &request, 91),
        McpRefreshClaimOutcome::Changed(Some(_))
    ));
}

#[test]
fn postgres_refresh_claim_lock_conflict_is_a_short_conservative_busy() {
    assert_eq!(mcp_refresh_mutation_lock_timeout_millis(None).unwrap(), 1);
    let operation = StorageOperation::new("claim lock budget", Duration::from_secs(1));
    assert_eq!(
        mcp_refresh_mutation_lock_timeout_millis(Some(&operation)).unwrap(),
        1
    );
    let request = McpRefreshClaimRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "waiter".into(),
        now_unix: 100,
        lease_ttl_secs: 21,
    };

    assert_eq!(
        conservative_mcp_refresh_claim_busy(&request).unwrap(),
        McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 121
        }
    );
    assert!(is_mcp_refresh_lock_timeout_code(Some(
        &tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE
    )));
    assert!(!is_mcp_refresh_lock_timeout_code(Some(
        &tokio_postgres::error::SqlState::QUERY_CANCELED
    )));
    assert!(!is_mcp_refresh_lock_timeout_code(None));
}

#[test]
fn nonpositive_refresh_claim_ttl_does_not_mutate_the_credential() {
    let repositories = repositories_with_credential();
    for lease_ttl_secs in [0, -1] {
        let error = block_on(
            repositories.claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
                tenant_id: "tenant".into(),
                credential_id: "credential".into(),
                expected_version: 1,
                authorization_generation: 1,
                lease_id: "owner".into(),
                now_unix: 10,
                lease_ttl_secs,
            }),
        )
        .expect_err("nonpositive claim TTL must fail");
        assert!(error
            .to_string()
            .contains("refresh lease TTL must be greater than zero"));
    }
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let persisted = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    assert_eq!(persisted.refresh_lease_id, None);
    assert_eq!(persisted.refresh_lease_expires_at_unix, None);
}

#[test]
fn refresh_claim_uses_database_operation_time_for_takeover_and_full_ttl() {
    let mut expired_at_database = credential();
    expired_at_database.refresh_lease_id = Some("stale-owner".into());
    expired_at_database.refresh_lease_expires_at_unix = Some(95);
    let delayed_request = McpRefreshClaimRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "new-owner".into(),
        now_unix: 10,
        lease_ttl_secs: 10,
    };
    let database_now = 100;

    assert!(matches!(
        classify_mcp_refresh_claim(Some(expired_at_database), &delayed_request, database_now),
        McpRefreshClaimClassification::Acquirable(_)
    ));
    assert_eq!(
        require_refresh_lease_expiry(database_now, delayed_request.lease_ttl_secs).unwrap(),
        110
    );

    let mut active_at_database = credential();
    active_at_database.refresh_lease_id = Some("active-owner".into());
    active_at_database.refresh_lease_expires_at_unix = Some(105);
    let skewed_request = McpRefreshClaimRequest {
        now_unix: 1_000,
        ..delayed_request
    };
    assert!(matches!(
        classify_mcp_refresh_claim(Some(active_at_database), &skewed_request, database_now),
        McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 105
        })
    ));
}

#[test]
fn active_owner_classification_is_read_only_busy_from_database_clock() {
    let mut owned = credential();
    owned.refresh_lease_id = Some("owner".into());
    owned.refresh_lease_expires_at_unix = Some(120);
    let before = owned.clone();
    let request = McpRefreshClaimRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "waiter".into(),
        now_unix: 90,
        lease_ttl_secs: 20,
    };

    assert!(matches!(
        classify_mcp_refresh_claim(Some(owned.clone()), &request, 100),
        McpRefreshClaimClassification::Outcome(McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 120
        })
    ));
    assert_eq!(owned, before);
}

#[test]
fn refresh_lease_renewal_extends_exclusivity_until_safe_takeover() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 15),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 30
        }
    );
    assert_eq!(
        claim(&repositories, "contender", 21, 10),
        McpRefreshClaimOutcome::Busy {
            lease_expires_at_unix: 30
        }
    );
    assert!(matches!(
        claim(&repositories, "contender", 30, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 30, 11),
        McpRefreshRenewOutcome::OwnershipChanged
    );
    let mut stale = credential();
    stale.last_refresh_outcome = Some("refreshed".into());
    assert!(
        !block_on(repositories.complete_mcp_oauth_refresh(stale, "owner"))
            .expect("stale refresh completion")
    );
}

#[test]
fn same_tick_renewal_is_monotonic_and_expired_owner_cannot_renew() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 5),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 21
        }
    );
    assert_eq!(
        renew(&repositories, "owner", 21, 10),
        McpRefreshRenewOutcome::Expired {
            lease_expires_at_unix: Some(21)
        }
    );
    assert!(matches!(
        claim(&repositories, "contender", 21, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
}

#[test]
fn same_second_renewal_extends_claimed_lease_by_one_second() {
    let repositories = repositories_with_credential();
    let claimed = claim(&repositories, "owner", 10, 18);
    let McpRefreshClaimOutcome::Acquired(claimed) = claimed else {
        panic!("expected refresh claim");
    };
    assert_eq!(claimed.refresh_lease_expires_at_unix, Some(28));
    assert_eq!(
        renew(&repositories, "owner", 10, 18),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 29
        }
    );
}

#[test]
fn nonpositive_refresh_lease_ttl_does_not_mutate_the_active_lease() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    assert_eq!(
        renew(&repositories, "owner", 15, 0),
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: 20
        }
    );
    assert_eq!(
        renew(&repositories, "owner", 15, -1),
        McpRefreshRenewOutcome::NotExtended {
            lease_expires_at_unix: 20
        }
    );
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let persisted = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    assert_eq!(persisted.refresh_lease_expires_at_unix, Some(20));
}

#[test]
fn refresh_lease_expiry_is_derived_from_operation_time_after_queue_delay() {
    let request = McpRefreshRenewRequest {
        tenant_id: "tenant".into(),
        credential_id: "credential".into(),
        expected_version: 1,
        authorization_generation: 1,
        lease_id: "owner".into(),
        expected_lease_expires_at_unix: 105,
        now_unix: 10,
        lease_ttl_secs: 10,
    };
    let state = McpRefreshLeaseState {
        tenant_matches: true,
        version: 1,
        authorization_generation: 1,
        refresh_lease_id: Some("owner".into()),
        refresh_lease_expires_at_unix: Some(105),
        revoked: false,
    };
    let database_now = 100;
    let database_expiry = derive_refresh_lease_renewal_expiry(
        database_now,
        request.lease_ttl_secs,
        state.refresh_lease_expires_at_unix,
    );

    assert_eq!(derive_refresh_lease_expiry(request.now_unix, 10), Some(20));
    assert_eq!(database_expiry, Some(110));
    assert_eq!(
        mcp_refresh_renewal_rejection(Some(&state), &request, database_now, database_expiry),
        None
    );
}

#[test]
fn refresh_renewal_fails_closed_when_credential_version_changes() {
    let repositories = repositories_with_credential();
    assert!(matches!(
        claim(&repositories, "owner", 10, 10),
        McpRefreshClaimOutcome::Acquired(_)
    ));
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    let mut current = store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .get("credential")
        .expect("credential");
    current.version = 2;
    store
        .lock()
        .expect("memory control plane lock")
        .mcp_oauth_credentials
        .insert("credential", current);
    assert_eq!(
        renew(&repositories, "owner", 15, 15),
        McpRefreshRenewOutcome::CredentialChanged
    );
}

#[test]
fn revoke_supersedes_refresh_lease_and_pending_flow() {
    let repositories = repositories_with_credential();
    let request = McpIdentityAccessRequest {
        tenant_id: "tenant".into(),
        workspace_id: "workspace".into(),
        user_id: "user".into(),
        server_name: "server".into(),
        permission_key: "mcp.identity.revoke".into(),
    };
    let RuntimeControlPlaneBackend::Memory(store) = &repositories.control_plane else {
        panic!("expected memory control plane");
    };
    {
        let mut store = store.lock().expect("memory control plane lock");
        store
            .mcp_oauth_authorization_generations
            .insert(authorization_generation_key(&request), 1);
        store.mcp_oauth_flows.insert(
            "flow",
            StoredMcpOauthFlow {
                id: "flow".into(),
                tenant_id: "tenant".into(),
                workspace_id: "workspace".into(),
                user_id: "user".into(),
                server_name: "server".into(),
                pkce_nonce: vec![1],
                pkce_ciphertext: vec![2],
                oidc_nonce: "nonce".into(),
                authorization_generation: 1,
                created_at_unix: 1,
                expires_at_unix: 100,
                consumed_at_unix: None,
            },
        );
    }
    let claim = block_on(
        repositories.claim_mcp_oauth_refresh(&McpRefreshClaimRequest {
            tenant_id: "tenant".into(),
            credential_id: "credential".into(),
            expected_version: 1,
            authorization_generation: 1,
            lease_id: "lease".into(),
            now_unix: 10,
            lease_ttl_secs: 10,
        }),
    )
    .expect("refresh claim");
    assert!(matches!(claim, McpRefreshClaimOutcome::Acquired(_)));
    assert_eq!(
        renew(&repositories, "lease", 11, 19),
        McpRefreshRenewOutcome::Renewed {
            lease_expires_at_unix: 30
        }
    );
    block_on(repositories.revoke_mcp_oauth_identity(&request, 11, "local_revoked"))
        .expect("revoke")
        .expect("active credential");
    assert_eq!(
        renew(&repositories, "lease", 12, 28),
        McpRefreshRenewOutcome::Revoked
    );
    let flow = {
        let store = store.lock().expect("memory control plane lock");
        store.mcp_oauth_flows.get("flow").expect("flow")
    };
    assert_eq!(flow.consumed_at_unix, Some(11));
    let mut stale = credential();
    stale.last_refresh_outcome = Some("refreshed".into());
    assert!(
        !block_on(repositories.complete_mcp_oauth_refresh(stale, "lease"))
            .expect("late refresh completion")
    );
}
