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

use ferrogate_billing::{BillingEvent, BillingUsageSource, TokenUsage};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    quota_policy_id, ControlPlaneDocuments, PostgresStorageConfig, PostgresTlsMode, QuotaScopeKind,
    RuntimeStorageRepositories, StorageMigrationSnapshot, StoredAgentWorkerInstance, StoredApiKey,
    StoredManagedWorkerIsolationEvidence, StoredManagedWorkerIsolationPolicy,
    StoredManagedWorkerIsolationSelection, StoredManagedWorkerLifecycleEvent,
    StoredManagedWorkerSession, StoredManagedWorkerTemplate, StoredProject, StoredQuotaPolicy,
    StoredTenantAccount, StoredWorkspace,
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
        workspace_id: None,
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

/// Regression coverage for a real bug: the Postgres/Supabase `api_keys` table
/// shipped without `allowed_models`/`allowed_providers`/`monthly_token_budget`/
/// `request_limit_per_minute` columns, so those fields silently reset to
/// empty/`None` on every read-back against a real Postgres backend even
/// though the in-memory backend (and every unit test) round-tripped them
/// fine. This proves the fix against a real Postgres instance, not memory.
#[test]
fn virtual_api_key_governance_fields_round_trip_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping supabase round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    storage
        .upsert_tenant_account(StoredTenantAccount {
            id: "tenant-rt".into(),
            name: "Tenant RT".into(),
            slug: "tenant-rt".into(),
            status: "active".into(),
            plan_id: "free".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .expect("tenant upsert must succeed");
    storage
        .upsert_project(StoredProject {
            id: "project-rt".into(),
            tenant_id: "tenant-rt".into(),
            name: "Project RT".into(),
            slug: "project-rt".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .expect("project upsert must succeed");
    storage
        .upsert_workspace(StoredWorkspace {
            id: "workspace-rt".into(),
            project_id: "project-rt".into(),
            tenant_id: "tenant-rt".into(),
            name: "Workspace RT".into(),
            slug: "workspace-rt".into(),
            environment: "prod".into(),
            status: "active".into(),
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .expect("workspace upsert must succeed");

    let tenant = TenantContext {
        organization_id: Some("tenant-rt".into()),
        project_id: Some("project-rt".into()),
        workspace_id: Some("workspace-rt".into()),
        api_key_id: Some("vk-rt".into()),
        ..TenantContext::default()
    };
    storage
        .upsert_api_key_record(StoredApiKey {
            id: "vk-rt".into(),
            workspace_id: "workspace-rt".into(),
            tenant_id: "tenant-rt".into(),
            project_id: "project-rt".into(),
            name: "Live key".into(),
            key_prefix: "fg_live_rt_prefix".into(),
            key_hash: "sha256:deadbeef".into(),
            last4: "beef".into(),
            enabled: true,
            scopes: vec!["chat.completions".into()],
            allowed_models: vec!["fast-chat".into(), "smart-chat".into()],
            allowed_providers: vec!["openai".into()],
            tenant,
            monthly_token_budget: Some(500_000),
            request_limit_per_minute: Some(120),
            created_at_unix: 1,
            updated_at_unix: 1,
            rotated_at_unix: None,
            expires_at_unix: None,
            revoked_at_unix: None,
        })
        .expect("api key upsert must succeed");

    // Fresh connection: proves the governance fields landed in Postgres
    // columns, not just the process-local write path.
    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let reread = reopened
        .get_api_key_record("vk-rt")
        .expect("get must succeed")
        .expect("api key must exist after reconnect");

    assert_eq!(reread.allowed_models, vec!["fast-chat", "smart-chat"]);
    assert_eq!(reread.allowed_providers, vec!["openai"]);
    assert_eq!(reread.monthly_token_budget, Some(500_000));
    assert_eq!(reread.request_limit_per_minute, Some(120));

    let by_prefix = reopened
        .find_api_key_records_by_prefix("fg_live_rt_prefix")
        .expect("prefix lookup must succeed");
    assert_eq!(by_prefix.len(), 1);
    assert_eq!(by_prefix[0].allowed_models, vec!["fast-chat", "smart-chat"]);
}

#[test]
fn quota_policy_round_trips_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping supabase round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    storage
        .upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Tenant, "tenant-rt"),
            scope_type: QuotaScopeKind::Tenant,
            scope_id: "tenant-rt".into(),
            model_allowlist: vec!["fast-chat".into(), "smart-chat".into()],
            rpm_limit: Some(1_000),
            tpm_limit: Some(500_000),
            monthly_budget_usd: Some(250.5),
            alert_threshold_pcts: vec![50, 90],
            enabled: true,
            created_at_unix: 1,
            updated_at_unix: 1,
        })
        .expect("quota policy upsert must succeed");

    // Overwrite via the same (scope_type, scope_id) to prove the UNIQUE
    // constraint drives upsert semantics, not accumulation of duplicate rows.
    storage
        .upsert_quota_policy(StoredQuotaPolicy {
            id: quota_policy_id(QuotaScopeKind::Tenant, "tenant-rt"),
            scope_type: QuotaScopeKind::Tenant,
            scope_id: "tenant-rt".into(),
            model_allowlist: vec!["fast-chat".into()],
            rpm_limit: Some(500),
            tpm_limit: None,
            monthly_budget_usd: None,
            alert_threshold_pcts: vec![],
            enabled: false,
            created_at_unix: 1,
            updated_at_unix: 2,
        })
        .expect("quota policy re-upsert must succeed");

    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let policy = reopened
        .get_quota_policy(QuotaScopeKind::Tenant, "tenant-rt")
        .expect("get must succeed")
        .expect("policy must exist after reconnect");

    assert_eq!(policy.rpm_limit, Some(500));
    assert_eq!(policy.tpm_limit, None);
    assert_eq!(policy.monthly_budget_usd, None);
    assert!(!policy.enabled);
    assert_eq!(policy.model_allowlist, vec!["fast-chat"]);
    assert_eq!(reopened.list_quota_policies().unwrap().len(), 1);
}

/// P1-4: proves append_billing_event's settled cost/latency and the
/// tenant/project/workspace/key monthly rollup fan-out against a real
/// Postgres instance, including that workspace_id (previously dropped by
/// tenant_contexts missing that column) now survives a fresh reconnect.
#[test]
fn usage_cost_accounting_round_trips_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping supabase round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    let tenant = TenantContext {
        organization_id: Some("tenant-cost-rt".into()),
        team_id: None,
        project_id: Some("project-cost-rt".into()),
        workspace_id: Some("workspace-cost-rt".into()),
        user_id: None,
        api_key_id: Some("key-cost-rt".into()),
    };

    let recorded = storage
        .append_billing_event(BillingEvent {
            request_id: "req-cost-rt-1".into(),
            trace_id: None,
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: tenant.clone(),
            logical_model: "fast-chat".into(),
            provider: "openai".into(),
            provider_model: "gpt-4o-mini".into(),
            usage: TokenUsage::new(100, 50, 150),
            usage_source: BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1_783_036_800), // 2026-07
            cost_usd: Some(0.015),
            latency_ms: Some(240),
        })
        .expect("append_billing_event must succeed");
    assert!(
        recorded,
        "first insert of a new request_id must be recorded"
    );

    // Fresh connection: proves workspace attribution and settled cost/
    // latency landed in Postgres columns, not just the process-local path.
    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");

    let events = reopened.billing_events();
    let event = events
        .iter()
        .find(|event| event.request_id == "req-cost-rt-1")
        .expect("billing event must exist after reconnect");
    assert_eq!(
        event.tenant.workspace_id.as_deref(),
        Some("workspace-cost-rt")
    );
    assert_eq!(event.cost_usd, Some(0.015));
    assert_eq!(event.latency_ms, Some(240));

    for (scope_type, scope_id) in [
        (QuotaScopeKind::Tenant, "tenant-cost-rt"),
        (QuotaScopeKind::Project, "project-cost-rt"),
        (QuotaScopeKind::Workspace, "workspace-cost-rt"),
        (QuotaScopeKind::Key, "key-cost-rt"),
    ] {
        let rollup = reopened
            .get_usage_monthly_rollup(scope_type, scope_id, "2026-07")
            .expect("get_usage_monthly_rollup must succeed")
            .unwrap_or_else(|| panic!("rollup missing for {scope_type:?}/{scope_id}"));
        assert_eq!(rollup.total_tokens, 150);
        assert_eq!(rollup.request_count, 1);
        assert_eq!(rollup.error_count, 0);
        assert!((rollup.cost_usd - 0.015).abs() < 1e-9);
    }
}

/// Proves the standalone billing service's ledger persistence (issue #129)
/// against a real Postgres instance: a settled usage event is priced into a
/// `LedgerEntry` exactly as `ferrogate billing serve` does, written once
/// (idempotent on retry), and read back correctly after a fresh reconnect.
#[test]
fn billing_ledger_round_trips_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping billing ledger round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    // Price a usage event into a ledger entry exactly as the billing service does.
    let price_book = ferrogate_billing::PriceBook::new(vec![ferrogate_billing::PriceEntry::new(
        "token4ai",
        "gpt-5.5",
        ferrogate_billing::ModelPrice::usd(5.0, 15.0),
    )]);
    let event = ferrogate_billing::BillingEvent {
        request_id: "req-ledger-rt".into(),
        trace_id: Some("trace-ledger-rt".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_demo".into()),
            project_id: Some("project_gateway".into()),
            api_key_id: Some("client".into()),
            ..TenantContext::default()
        },
        logical_model: "gpt-5.5".into(),
        provider: "token4ai".into(),
        provider_model: "gpt-5.5".into(),
        usage: ferrogate_billing::TokenUsage::new(24, 30, 54),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: None,
        latency_ms: None,
    };
    let entry =
        ferrogate_billing::charge(&price_book, &event).expect("charge must price the event");

    // First write inserts; a retry is an idempotent no-op on the entry id.
    assert!(storage
        .append_billing_ledger_entry(&entry)
        .expect("ledger insert must succeed"));
    assert!(!storage
        .append_billing_ledger_entry(&entry)
        .expect("ledger re-insert must be idempotent"));

    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let fetched = reopened
        .billing_ledger_entry(&entry.id)
        .expect("get must succeed")
        .expect("ledger entry must exist after reconnect");

    assert_eq!(fetched.provider, "token4ai");
    assert_eq!(fetched.provider_model, "gpt-5.5");
    assert_eq!(fetched.usage.total_tokens, 54);
    assert!((fetched.cost.total_cost - 0.00057).abs() < 1e-9);
    assert!((fetched.credits - 570.0).abs() < 1e-6);
    assert_eq!(fetched.tenant.organization_id.as_deref(), Some("org_demo"));
    assert_eq!(
        reopened
            .list_billing_ledger_entries(&ferrogate_billing::LedgerListFilter::default(), 0, 10)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn billing_ledger_tenant_filter_is_pushed_into_the_query_through_real_supabase() {
    // Issue #149: the tenant filter narrows the SQL query itself, so a scoped
    // page correctly returns only that tenant's rows against a real Postgres.
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping billing ledger tenant-filter round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    let price_book = ferrogate_billing::PriceBook::new(vec![ferrogate_billing::PriceEntry::new(
        "token4ai",
        "gpt-5.5",
        ferrogate_billing::ModelPrice::usd(5.0, 15.0),
    )]);

    for org in ["org-a", "org-b"] {
        let event = ferrogate_billing::BillingEvent {
            request_id: format!("req-{org}"),
            trace_id: Some(format!("trace-{org}")),
            agent_run_id: None,
            workflow_id: None,
            workflow_version: None,
            workflow_node_id: None,
            cluster_id: None,
            node_id: None,
            tenant: TenantContext {
                organization_id: Some(org.into()),
                ..TenantContext::default()
            },
            logical_model: "gpt-5.5".into(),
            provider: "token4ai".into(),
            provider_model: "gpt-5.5".into(),
            usage: ferrogate_billing::TokenUsage::new(10, 20, 30),
            usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
            status_code: 200,
            occurred_at_unix: Some(1_800_000_000),
            cost_usd: None,
            latency_ms: None,
        };
        let entry = ferrogate_billing::charge(&price_book, &event).expect("must price");
        storage
            .append_billing_ledger_entry(&entry)
            .expect("ledger insert must succeed");
    }

    // Unfiltered: both rows.
    let all = storage
        .list_billing_ledger_entries(&ferrogate_billing::LedgerListFilter::default(), 0, 10)
        .unwrap();
    assert_eq!(all.len(), 2);

    // Scoped to org-a: only that tenant's row, straight from the SQL query.
    let scoped = storage
        .list_billing_ledger_entries(
            &ferrogate_billing::LedgerListFilter {
                organization_id: Some("org-a".into()),
                ..Default::default()
            },
            0,
            10,
        )
        .unwrap();
    assert_eq!(scoped.len(), 1);
    assert_eq!(scoped[0].tenant.organization_id.as_deref(), Some("org-a"));
}

#[test]
fn billing_report_outbox_round_trips_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping billing report outbox round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    let event = ferrogate_billing::BillingEvent {
        request_id: "req-outbox-rt".into(),
        trace_id: Some("trace-outbox-rt".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_demo".into()),
            ..TenantContext::default()
        },
        logical_model: "gpt-5.5".into(),
        provider: "token4ai".into(),
        provider_model: "gpt-5.5".into(),
        usage: ferrogate_billing::TokenUsage::new(10, 20, 30),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.01),
        latency_ms: None,
    };

    // Enqueue is idempotent on the id; due at t=100.
    storage
        .enqueue_billing_report("ferrogate:trace-outbox-rt:req-outbox-rt", &event, 100)
        .expect("enqueue must succeed");
    storage
        .enqueue_billing_report("ferrogate:trace-outbox-rt:req-outbox-rt", &event, 999)
        .expect("re-enqueue must be a no-op");

    // Not due before its time; due at/after 100.
    assert!(storage.list_due_billing_reports(50, 10).unwrap().is_empty());
    let due = storage.list_due_billing_reports(100, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event.provider_model, "gpt-5.5");
    assert_eq!(due[0].attempts, 0);

    // A failed delivery reschedules with a bumped attempt count.
    storage
        .reschedule_billing_report("ferrogate:trace-outbox-rt:req-outbox-rt", 5_000)
        .expect("reschedule must succeed");
    assert!(storage
        .list_due_billing_reports(100, 10)
        .unwrap()
        .is_empty());
    let rescheduled = storage.list_due_billing_reports(5_000, 10).unwrap();
    assert_eq!(rescheduled[0].attempts, 1);

    // A delivered report is deleted and no longer appears.
    storage
        .delete_billing_report("ferrogate:trace-outbox-rt:req-outbox-rt")
        .expect("delete must succeed");
    assert!(storage
        .list_due_billing_reports(1_000_000, 10)
        .unwrap()
        .is_empty());
}

#[test]
fn billing_report_dead_letter_round_trips_through_real_supabase() {
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping billing report dead-letter round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    let event = ferrogate_billing::BillingEvent {
        request_id: "req-dead-letter-rt".into(),
        trace_id: Some("trace-dead-letter-rt".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_demo".into()),
            ..TenantContext::default()
        },
        logical_model: "mystery-model".into(),
        provider: "unpriced-vendor".into(),
        provider_model: "mystery-model".into(),
        usage: ferrogate_billing::TokenUsage::new(10, 20, 30),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: None,
        latency_ms: None,
    };
    let id = "ferrogate:trace-dead-letter-rt:req-dead-letter-rt";
    storage
        .enqueue_billing_report(id, &event, 100)
        .expect("enqueue must succeed");

    // Dead-lettering removes the entry from the due queue...
    storage
        .dead_letter_billing_report(id, 200)
        .expect("dead-letter must succeed");
    assert!(storage
        .list_due_billing_reports(1_000_000, 10)
        .unwrap()
        .is_empty());

    // ...but keeps the row visible for operator inspection.
    let reopened =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), false, true)
            .expect("re-open against existing schema must succeed");
    let dead_lettered = reopened.list_dead_lettered_billing_reports(10).unwrap();
    assert_eq!(dead_lettered.len(), 1);
    assert_eq!(dead_lettered[0].id, id);
    assert_eq!(dead_lettered[0].event.provider_model, "mystery-model");
}

#[test]
fn append_billing_event_with_outbox_enqueue_commits_both_writes_atomically() {
    // Issue #150: the metering write and the durable outbox enqueue land in a
    // single transaction/round-trip rather than two sequential ones.
    let Some(container) = PgContainer::start() else {
        eprintln!("skipping combined billing append round-trip: docker daemon not available");
        return;
    };

    let storage =
        RuntimeStorageRepositories::supabase_for_migration(container.config(), true, true)
            .expect("supabase migration connect + schema init must succeed");

    let event = ferrogate_billing::BillingEvent {
        request_id: "req-combined-rt".into(),
        trace_id: Some("trace-combined-rt".into()),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("org_demo".into()),
            ..TenantContext::default()
        },
        logical_model: "gpt-5.5".into(),
        provider: "token4ai".into(),
        provider_model: "gpt-5.5".into(),
        usage: ferrogate_billing::TokenUsage::new(10, 20, 30),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.02),
        latency_ms: None,
    };
    let outbox_id = "ferrogate:trace-combined-rt:req-combined-rt";

    let outcome = storage
        .append_billing_event_with_outbox_enqueue(event.clone(), outbox_id, 100)
        .expect("combined append must succeed");
    assert!(outcome.recorded);
    assert!(outcome.enqueue_error.is_none());

    // Both the metering event and the outbox row exist from one call.
    assert_eq!(storage.billing_events().len(), 1);
    let due = storage.list_due_billing_reports(100, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, outbox_id);
    assert_eq!(due[0].event.request_id, "req-combined-rt");

    // A retry (same request_id) is idempotent: no duplicate metering event or
    // outbox row, and `recorded` reports the no-op.
    let retry = storage
        .append_billing_event_with_outbox_enqueue(event, outbox_id, 100)
        .expect("idempotent retry must succeed");
    assert!(!retry.recorded);
    assert_eq!(storage.billing_events().len(), 1);
    assert_eq!(storage.list_due_billing_reports(100, 10).unwrap().len(), 1);
}
