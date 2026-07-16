// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-15
// description: Focused optimistic-CAS coverage for Guardrail policy bindings (#220).

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Barrier,
};

use crate::{
    guardrail_policy_revision_id, is_guardrail_policy_binding_cas_conflict,
    next_guardrail_activation_binding, next_guardrail_archive_binding, ControlPlaneDocuments,
    GuardrailPolicyRepository, PostgresStorageConfig, PostgresTlsMode, RuntimeControlPlaneBackend,
    RuntimeStorageOptions, RuntimeStorageRepositories, StorageError, StorageProviderKind,
    StoredGuardrailPolicyBinding, StoredGuardrailPolicyRevision,
    GUARDRAIL_POLICY_BINDING_DELETE_CAS_SQL, GUARDRAIL_POLICY_BINDING_INSERT_CAS_SQL,
    GUARDRAIL_POLICY_BINDING_UPDATE_CAS_SQL,
};

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(1);

struct LocalSchemaCleanup {
    dsn: String,
    schema: String,
    completed: bool,
}

impl LocalSchemaCleanup {
    fn drop_and_verify(&mut self) {
        let mut client = postgres::Client::connect(&self.dsn, postgres::NoTls)
            .expect("connect for exact local schema cleanup");
        client
            .batch_execute(&format!(
                "DROP SCHEMA {} CASCADE",
                crate::quote_postgres_identifier(&self.schema)
            ))
            .expect("drop exact local Guardrail CAS schema");
        let remaining: i64 = client
            .query_one(
                "SELECT COUNT(*)::bigint FROM information_schema.schemata WHERE schema_name = $1",
                &[&self.schema],
            )
            .unwrap()
            .get(0);
        assert_eq!(remaining, 0);
        self.completed = true;
    }
}

impl Drop for LocalSchemaCleanup {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Ok(mut client) = postgres::Client::connect(&self.dsn, postgres::NoTls) {
            let _ = client.batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {} CASCADE",
                crate::quote_postgres_identifier(&self.schema)
            ));
        }
    }
}

fn binding(
    active_revision: Option<u32>,
    archived_revisions: Vec<u32>,
    generation: u64,
) -> StoredGuardrailPolicyBinding {
    StoredGuardrailPolicyBinding {
        policy_id: "pii".into(),
        active_revision,
        archived_revisions,
        updated_at_unix: 10,
        updated_by: "admin".into(),
        generation,
    }
}

fn revision(revision: u32) -> StoredGuardrailPolicyRevision {
    StoredGuardrailPolicyRevision {
        id: guardrail_policy_revision_id("pii", revision),
        policy_id: "pii".into(),
        revision,
        policy_json: format!(r#"{{"revision":{revision}}}"#),
        created_at_unix: u64::from(revision),
        created_by: "admin".into(),
    }
}

#[test]
fn guardrail_binding_mutation_sql_is_short_indexed_cas_without_wait_locks() {
    let statements = [
        GUARDRAIL_POLICY_BINDING_INSERT_CAS_SQL,
        GUARDRAIL_POLICY_BINDING_UPDATE_CAS_SQL,
        GUARDRAIL_POLICY_BINDING_DELETE_CAS_SQL,
    ];
    for statement in statements {
        let normalized = statement.to_ascii_uppercase();
        assert!(!normalized.contains("PG_ADVISORY"));
        assert!(!normalized.contains("FOR UPDATE"));
        assert!(!normalized.contains("PG_SLEEP"));
        assert!(!normalized.contains("BEGIN"));
    }
    assert!(GUARDRAIL_POLICY_BINDING_UPDATE_CAS_SQL
        .contains("WHERE policy_id = $1 AND generation = $7"));
    assert!(GUARDRAIL_POLICY_BINDING_DELETE_CAS_SQL
        .contains("WHERE policy_id = $1 AND generation = $2"));
    assert!(GUARDRAIL_POLICY_BINDING_INSERT_CAS_SQL.contains("ON CONFLICT (policy_id) DO NOTHING"));
}

#[test]
fn activation_and_archive_are_computed_in_rust_with_monotonic_generation() {
    let previous = binding(Some(4), vec![3, 1, 3, 2], 7);
    let activated =
        next_guardrail_activation_binding(Some(&previous), "pii", 2, "operator", 20, false)
            .unwrap();
    assert_eq!(activated.active_revision, Some(2));
    assert_eq!(activated.archived_revisions, vec![1, 3, 4]);
    assert_eq!(activated.generation, 8);

    let archived =
        next_guardrail_archive_binding(Some(&activated), "pii", 5, "operator", 30).unwrap();
    assert_eq!(archived.active_revision, Some(2));
    assert_eq!(archived.archived_revisions, vec![1, 3, 4, 5]);
    assert_eq!(archived.generation, 9);
}

#[test]
fn rollback_validation_and_active_archive_rejection_remain_explicit() {
    let previous = binding(Some(2), vec![1], 4);
    let rollback =
        next_guardrail_activation_binding(Some(&previous), "pii", 1, "operator", 20, true).unwrap();
    assert_eq!(rollback.active_revision, Some(1));
    assert_eq!(rollback.archived_revisions, vec![2]);

    assert!(matches!(
        next_guardrail_activation_binding(
            Some(&previous),
            "pii",
            3,
            "operator",
            20,
            true,
        ),
        Err(StorageError::Conflict(message)) if message.contains("not archived")
    ));
    assert!(matches!(
        next_guardrail_archive_binding(Some(&previous), "pii", 2, "operator", 20),
        Err(StorageError::Conflict(message)) if message.contains("cannot be archived")
    ));
}

#[test]
fn stale_restore_cannot_overwrite_a_newer_in_memory_binding() {
    let repositories =
        RuntimeStorageRepositories::in_memory(vec![StorageProviderKind::Memory], 4, 4);
    repositories
        .insert_guardrail_policy_revision(revision(1))
        .unwrap();
    repositories
        .insert_guardrail_policy_revision(revision(2))
        .unwrap();

    let first = repositories
        .activate_guardrail_policy_revision("pii", 1, "admin", 10, false)
        .unwrap();
    let second = repositories
        .activate_guardrail_policy_revision("pii", 2, "admin", 20, false)
        .unwrap();
    let error = repositories
        .restore_guardrail_policy_binding("pii", Some(first.current.generation), first.previous)
        .unwrap_err();

    assert!(is_guardrail_policy_binding_cas_conflict(&error));
    assert_eq!(
        repositories
            .get_guardrail_policy_binding("pii")
            .unwrap()
            .unwrap(),
        second.current
    );
}

#[test]
fn legacy_binding_payload_defaults_generation_to_zero() {
    let binding: StoredGuardrailPolicyBinding = serde_json::from_str(
        r#"{"policy_id":"pii","active_revision":1,"archived_revisions":[],"updated_at_unix":1,"updated_by":"admin"}"#,
    )
    .unwrap();
    assert_eq!(binding.generation, 0);
}

#[test]
fn live_local_postgres_concurrent_writers_have_one_cas_winner() {
    let Ok(dsn) = std::env::var("FERROGATE_TEST_POSTGRES_DSN") else {
        eprintln!(
            "skipping live_local_postgres_concurrent_writers_have_one_cas_winner: \
             FERROGATE_TEST_POSTGRES_DSN is not set"
        );
        return;
    };
    let schema = format!(
        "ferrogate_guardrail_cas_{}_{}",
        std::process::id(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    let mut cleanup = LocalSchemaCleanup {
        dsn: dsn.clone(),
        schema: schema.clone(),
        completed: false,
    };
    let config = PostgresStorageConfig {
        dsn: dsn.clone(),
        pool_size: 2,
        pool_acquire_timeout_millis: 1_000,
        tls_mode: PostgresTlsMode::Disable,
        tls_ca_cert_path: None,
        connect_timeout_secs: 5,
        statement_timeout_millis: 5_000,
        schema: Some(schema.clone()),
        search_path: vec!["public".into()],
    };
    let repositories = RuntimeStorageRepositories::postgres(
        config,
        RuntimeStorageOptions {
            provider_order: vec![StorageProviderKind::Postgres],
            required: true,
            initialize_schema: true,
            migration_mode: "auto".into(),
            control_plane: ControlPlaneDocuments::default(),
            request_log_retention_records: 4,
            audit_event_retention_records: 4,
        },
    )
    .expect("initialize isolated local PostgreSQL schema");
    let store = match &repositories.control_plane {
        RuntimeControlPlaneBackend::Postgres(store) => Arc::clone(store),
        RuntimeControlPlaneBackend::Memory(_) => panic!("expected PostgreSQL control plane"),
    };

    let seed = binding(None, Vec::new(), 1);
    store
        .compare_and_swap_guardrail_policy_binding(None, &seed)
        .unwrap();
    let previous = store.get_guardrail_policy_binding("pii").unwrap().unwrap();
    let candidates = [
        next_guardrail_archive_binding(Some(&previous), "pii", 1, "writer-a", 20).unwrap(),
        next_guardrail_archive_binding(Some(&previous), "pii", 2, "writer-b", 20).unwrap(),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let handles = candidates.map(|candidate| {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            store.compare_and_swap_guardrail_policy_binding(Some(1), &candidate)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().expect("CAS writer panicked"));

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(is_guardrail_policy_binding_cas_conflict))
            .count(),
        1
    );
    let final_binding = store.get_guardrail_policy_binding("pii").unwrap().unwrap();
    assert_eq!(final_binding.generation, 2);
    assert!(matches!(
        final_binding.archived_revisions.as_slice(),
        [1] | [2]
    ));

    drop(store);
    drop(repositories);
    cleanup.drop_and_verify();
}
