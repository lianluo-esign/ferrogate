// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-06-11
// description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

//! Full-link control-plane persistence against a real Supabase/Postgres (#110).
//!
//! This penetrates a real Postgres (Supabase on the wire): it applies the
//! control-plane schema through the storage crate's Supabase wiring, writes
//! control-plane documents, and reads them back from the database — proving
//! migration, upsert, and read-back round-trip fidelity end to end rather than
//! against the in-memory repository. Gated on a reachable docker daemon so the
//! suite stays hermetic where Docker is absent.

use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

use ferrogate_core::TenantContext;
use ferrogate_storage::{
    ControlPlaneDocuments, PostgresStorageConfig, PostgresTlsMode, RuntimeStorageRepositories,
    StorageMigrationSnapshot, StoredAgentWorkerInstance, StoredManagedWorkerIsolationEvidence,
    StoredManagedWorkerIsolationPolicy, StoredManagedWorkerIsolationSelection,
    StoredManagedWorkerLifecycleEvent, StoredManagedWorkerSession, StoredManagedWorkerTemplate,
};

const IMAGE: &str = "postgres:16-alpine";

struct PgContainer {
    id: String,
    port: u16,
}

impl PgContainer {
    fn start() -> Option<Self> {
        if !docker_available() {
            return None;
        }
        let out = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "-e",
                "POSTGRES_PASSWORD=postgres",
                "-e",
                "POSTGRES_DB=ferrogate",
                "-e",
                "POSTGRES_USER=postgres",
                "-p",
                "127.0.0.1:0:5432",
                IMAGE,
            ])
            .output()
            .ok()?;
        if !out.status.success() {
            eprintln!(
                "supabase_roundtrip: docker run failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let port = match mapped_port(&id) {
            Some(port) => port,
            None => {
                remove(&id);
                return None;
            }
        };
        let container = Self { id, port };
        if !container.wait_ready(Duration::from_secs(45)) {
            eprintln!("supabase_roundtrip: postgres never became ready");
            return None;
        }
        Some(container)
    }

    fn config(&self) -> PostgresStorageConfig {
        PostgresStorageConfig {
            dsn: self.dsn(),
            pool_size: 1,
            tls_mode: PostgresTlsMode::Disable,
            tls_ca_cert_path: None,
            connect_timeout_secs: 5,
            statement_timeout_millis: 15_000,
            schema: None,
            search_path: Vec::new(),
        }
    }

    fn dsn(&self) -> String {
        format!(
            "host=127.0.0.1 port={} user=postgres password=postgres dbname=ferrogate connect_timeout=5",
            self.port
        )
    }

    fn wait_ready(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let dsn = self.dsn();
        while Instant::now() < deadline {
            if let Ok(mut client) = postgres::Client::connect(&dsn, postgres::NoTls) {
                if client.simple_query("SELECT 1").is_ok() {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(400));
        }
        false
    }
}

impl Drop for PgContainer {
    fn drop(&mut self) {
        remove(&self.id);
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn mapped_port(id: &str) -> Option<u16> {
    for _ in 0..20 {
        if let Ok(out) = Command::new("docker")
            .args(["port", id, "5432/tcp"])
            .output()
        {
            if out.status.success() {
                if let Some(port) = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|line| line.rsplit(':').next())
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .next()
                {
                    return Some(port);
                }
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
    None
}

fn remove(id: &str) {
    let _ = Command::new("docker").args(["rm", "-f", id]).output();
}

fn documents() -> ControlPlaneDocuments {
    ControlPlaneDocuments {
        api_keys: vec![(
            "key-supabase-roundtrip".to_string(),
            r#"{"id":"key-supabase-roundtrip","name":"roundtrip","organization_id":"org_rt"}"#
                .to_string(),
        )],
        tenants: vec![(
            "tenant-rt".to_string(),
            r#"{"id":"tenant-rt","name":"Roundtrip tenant"}"#.to_string(),
        )],
        policies: vec![(
            "policy-rt".to_string(),
            r#"{"id":"policy-rt","effect":"deny"}"#.to_string(),
        )],
        gateway_configs: vec![(
            "profile-rt".to_string(),
            r#"{"id":"profile-rt","cache_enabled":true}"#.to_string(),
        )],
        ..ControlPlaneDocuments::default()
    }
}

const RUN_ID: &str = "run-worker-rt";
const SESSION_ID: &str = "sess-worker-rt";
const TEMPLATE_ID: &str = "tmpl-worker-rt";
const INSTANCE_ID: &str = "awi-worker-rt";
const EVENT_ID: &str = "evt-worker-rt";

fn worker_lifecycle_snapshot() -> StorageMigrationSnapshot {
    let tenant = TenantContext {
        organization_id: Some("org_worker".into()),
        team_id: None,
        project_id: Some("proj_worker".into()),
        user_id: None,
        api_key_id: Some("key_worker".into()),
    };
    StorageMigrationSnapshot {
        managed_worker_templates: vec![StoredManagedWorkerTemplate {
            id: TEMPLATE_ID.into(),
            framework_adapter: "langgraph".into(),
            isolation_backend_kind: "firecracker".into(),
            enabled: true,
            max_tenant_sessions: Some(4),
            max_workspace_sessions: Some(2),
            created_at_unix: Some(1),
            updated_at_unix: Some(1),
        }],
        agent_worker_instances: vec![StoredAgentWorkerInstance {
            id: INSTANCE_ID.into(),
            process_name: "agent-worker-1".into(),
            host_id: Some("host-a".into()),
            worker_version: Some("2026.6.22".into()),
            status: "running".into(),
            started_at_unix: Some(1),
            last_seen_at_unix: Some(2),
            process_json: r#"{"pid":4242}"#.into(),
        }],
        managed_worker_sessions: vec![StoredManagedWorkerSession {
            id: SESSION_ID.into(),
            run_id: RUN_ID.into(),
            tenant: tenant.clone(),
            workspace_id: "ws-worker-rt".into(),
            worker_template_id: TEMPLATE_ID.into(),
            agent_worker_instance_id: Some(INSTANCE_ID.into()),
            status: "running".into(),
            isolation_backend_kind: "firecracker".into(),
            microvm_id: Some("vm-worker-rt".into()),
            capability_envelope_id: "cap-worker-rt".into(),
            requested_at_unix: Some(1),
            started_at_unix: Some(2),
            completed_at_unix: None,
            cleanup_completed_at_unix: None,
            capability_envelope_json: r#"{"network":"governed"}"#.into(),
            resource_limits_json: r#"{"cpu":2}"#.into(),
        }],
        managed_worker_lifecycle_events: vec![StoredManagedWorkerLifecycleEvent {
            id: EVENT_ID.into(),
            session_id: SESSION_ID.into(),
            run_id: RUN_ID.into(),
            tenant: tenant.clone(),
            workspace_id: "ws-worker-rt".into(),
            agent_worker_instance_id: Some(INSTANCE_ID.into()),
            status: "running".into(),
            action: "provision".into(),
            outcome: "succeeded".into(),
            occurred_at_unix: Some(2),
            evidence_json: r#"{"stage":"boot"}"#.into(),
        }],
        managed_worker_isolation_selections: vec![StoredManagedWorkerIsolationSelection {
            session_id: SESSION_ID.into(),
            run_id: RUN_ID.into(),
            tenant: tenant.clone(),
            workspace_id: "ws-worker-rt".into(),
            agent_worker_instance_id: Some(INSTANCE_ID.into()),
            backend_name: "firecracker".into(),
            backend_version: "1.7".into(),
            backend_kind: "microvm".into(),
            host_lifecycle_owner: "gateway".into(),
            gateway_controls_backend: true,
            capability_envelope_id: "cap-worker-rt".into(),
            selected_at_unix: Some(1),
        }],
        managed_worker_isolation_policies: vec![StoredManagedWorkerIsolationPolicy {
            session_id: SESSION_ID.into(),
            cpu_count: 2,
            memory_mib: 1024,
            disk_mib: 4096,
            max_runtime_millis: Some(600_000),
            direct_public_egress: false,
            gateway_control_channel: true,
            governed_egress: true,
            read_only_rootfs: true,
            writable_workspace: true,
            host_path_mounts: false,
        }],
        managed_worker_isolation_evidence: vec![StoredManagedWorkerIsolationEvidence {
            id: "eva-worker-rt".into(),
            session_id: SESSION_ID.into(),
            lifecycle_event_id: EVENT_ID.into(),
            run_id: RUN_ID.into(),
            tenant,
            workspace_id: "ws-worker-rt".into(),
            agent_worker_instance_id: Some(INSTANCE_ID.into()),
            isolation_instance_id: Some("vm-worker-rt".into()),
            action: "provision".into(),
            outcome: "succeeded".into(),
            failure_reason: None,
            occurred_at_unix: Some(2),
            evidence_json: r#"{"attestation":"ok"}"#.into(),
        }],
        ..StorageMigrationSnapshot::default()
    }
}

/// #109: a managed-worker session's full lifecycle & isolation record must
/// persist to real Supabase/Postgres and survive a fresh connection — proving
/// tenant-scoped worker governance is durable, not process-local.
#[test]
fn managed_worker_lifecycle_and_isolation_round_trip_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping managed-worker round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    storage
        .import_migration_snapshot(worker_lifecycle_snapshot())
        .expect("import managed-worker lifecycle into supabase must succeed");

    let counts = storage
        .export_migration_snapshot()
        .expect("export from supabase must succeed")
        .counts();
    assert_eq!(counts.managed_worker_templates, 1, "template must persist");
    assert_eq!(counts.agent_worker_instances, 1, "worker instance persists");
    assert_eq!(counts.managed_worker_sessions, 1, "session must persist");
    assert_eq!(
        counts.managed_worker_lifecycle_events, 1,
        "lifecycle event must persist"
    );
    assert_eq!(
        counts.managed_worker_isolation_selections, 1,
        "isolation selection must persist"
    );
    assert_eq!(
        counts.managed_worker_isolation_policies, 1,
        "isolation policy must persist"
    );
    assert_eq!(
        counts.managed_worker_isolation_evidence, 1,
        "isolation evidence must persist"
    );

    // Reopen a fresh handle: rows must be in Postgres, not memory, and the
    // session must keep its tenant scoping and backend selection intact.
    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let reexported = reopened
        .export_migration_snapshot()
        .expect("re-export must succeed");
    let rcounts = reexported.counts();
    assert_eq!(rcounts.managed_worker_sessions, 1);
    assert_eq!(rcounts.managed_worker_isolation_evidence, 1);

    let session = &reexported.managed_worker_sessions[0];
    assert_eq!(session.id, SESSION_ID);
    assert_eq!(session.run_id, RUN_ID);
    assert_eq!(session.worker_template_id, TEMPLATE_ID);
    assert_eq!(
        session.tenant.organization_id.as_deref(),
        Some("org_worker")
    );
    assert_eq!(session.isolation_backend_kind, "firecracker");

    let selection = &reexported.managed_worker_isolation_selections[0];
    assert!(
        selection.gateway_controls_backend,
        "gateway must remain the isolation backend owner across a reconnect"
    );
    assert_eq!(selection.backend_kind, "microvm");
}

#[test]
fn control_plane_documents_round_trip_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping supabase round-trip: docker daemon not available");
        return;
    };

    // Apply the schema and connect as the Supabase provider against real Postgres.
    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    // Write control-plane documents into the database.
    storage
        .import_migration_snapshot(StorageMigrationSnapshot {
            control_plane: documents(),
            ..StorageMigrationSnapshot::default()
        })
        .expect("import into supabase must succeed");

    // Read them back out of the database and assert round-trip fidelity.
    let exported = storage
        .export_migration_snapshot()
        .expect("export from supabase must succeed");
    let counts = exported.counts();
    assert_eq!(counts.api_keys, 1, "api key must persist to supabase");
    assert_eq!(counts.tenants, 1, "tenant must persist to supabase");
    assert_eq!(counts.policies, 1, "policy must persist to supabase");
    assert_eq!(counts.gateway_configs, 1, "gateway config must persist");

    let api_keys = exported.control_plane.api_keys;
    assert_eq!(api_keys[0].0, "key-supabase-roundtrip");
    assert!(api_keys[0].1.contains("org_rt"));

    // A second connection (fresh handle) must see the same rows — durable, not
    // process-local — proving the data landed in Postgres, not memory.
    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let reexported = reopened
        .export_migration_snapshot()
        .expect("re-export must succeed");
    assert_eq!(reexported.counts().api_keys, 1);
    assert_eq!(reexported.counts().tenants, 1);
    assert_eq!(
        reexported.control_plane.policies[0].0, "policy-rt",
        "policy id must survive a fresh connection"
    );
}
