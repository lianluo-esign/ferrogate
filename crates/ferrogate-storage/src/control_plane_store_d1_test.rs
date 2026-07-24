// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: D1 control-plane backend tests (issue #420) against a mocked Cloudflare
// transport — provisioning lifecycle, query/param mapping, error mapping, the typed
// unimplemented-surface contract, and the Postgres<->D1 schema portability matrix.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, EnvTokenResolver, HttpRequest,
    HttpResponse, HttpTransport, RetryPolicy,
};

use crate::control_plane_store::ControlPlaneStore;
use crate::{
    api_key_tenant_context, is_unimplemented_backend_surface, D1ControlPlaneStore,
    D1TenantDatabaseRegistry, DeleteProjectOutcome, RuntimeStorageRepositories, StorageError,
    StoredApiKey, StoredTenantAccount, D1_TENANT_DATABASE_REGISTRY_ID,
    D1_TENANT_DATABASE_REGISTRY_KIND,
};

// --- Mocked transport plumbing (mirrors the ferrogate-cloudflare seams) ---

struct InstantClock;

#[async_trait]
impl Clock for InstantClock {
    async fn sleep(&self, _duration: Duration) {}
}

/// Records every request and replays a scripted FIFO of response bodies.
struct RecordingTransport {
    requests: Mutex<Vec<HttpRequest>>,
    responses: Mutex<VecDeque<HttpResponse>>,
}

impl RecordingTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }

    fn recorded(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, CloudflareError> {
        self.requests.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted transport ran out of responses"))
    }
}

fn response(status: u16, body: String) -> HttpResponse {
    HttpResponse {
        status,
        retry_after: None,
        body: body.into_bytes(),
    }
}

/// A successful single-statement query envelope with the given rows + changes.
fn query_ok(results: serde_json::Value, changes: u64) -> HttpResponse {
    response(
        200,
        format!(
            r#"{{"success":true,"errors":[],"result":[{{"results":{results},"success":true,
                "meta":{{"changes":{changes},"rows_read":1,"rows_written":1,"duration":0.2}}}}]}}"#
        ),
    )
}

fn empty_query_ok() -> HttpResponse {
    query_ok(serde_json::json!([]), 0)
}

fn create_database_ok(uuid: &str, name: &str) -> HttpResponse {
    response(
        200,
        format!(r#"{{"success":true,"errors":[],"result":{{"uuid":"{uuid}","name":"{name}"}}}}"#),
    )
}

fn delete_database_ok() -> HttpResponse {
    response(200, r#"{"success":true,"errors":[],"result":null}"#.into())
}

fn store_with_transport(
    registry: D1TenantDatabaseRegistry,
    responses: Vec<HttpResponse>,
) -> (D1ControlPlaneStore, Arc<RecordingTransport>) {
    let transport = Arc::new(RecordingTransport::new(responses));
    let client = D1Client::new(Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport.clone(),
        Arc::new(InstantClock),
        RetryPolicy::default(),
    )));
    (D1ControlPlaneStore::new(client, registry), transport)
}

fn control_registry() -> D1TenantDatabaseRegistry {
    D1TenantDatabaseRegistry::with_control_database("control-db")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn body_json(request: &HttpRequest) -> serde_json::Value {
    serde_json::from_slice(request.body.as_ref().expect("request should carry a body")).unwrap()
}

fn body_params(request: &HttpRequest) -> Vec<String> {
    body_json(request)["params"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

fn body_sql(request: &HttpRequest) -> String {
    body_json(request)["sql"].as_str().unwrap().to_string()
}

// --- Provisioning lifecycle ---

#[test]
fn provision_tenant_database_applies_schema_and_persists_registry() {
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            create_database_ok("acme-db", "ferrogate-tenant-acme"),
            // Schema batch applied to the new tenant database.
            query_ok(serde_json::json!([]), 0),
            // Registry document upsert into the control database.
            query_ok(serde_json::json!([]), 1),
        ],
    );

    let database_id = runtime()
        .block_on(store.provision_tenant_database("acme"))
        .expect("provisioning should succeed");
    assert_eq!(database_id, "acme-db");

    let requests = transport.recorded();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].url.ends_with("/accounts/acct-test/d1/database"));
    assert_eq!(body_json(&requests[0])["name"], "ferrogate-tenant-acme");

    // Schema batch runs against the NEW tenant database, carries the core
    // tables, and has comment lines stripped for the multi-statement API.
    assert!(requests[1].url.contains("/d1/database/acme-db/query"));
    let schema_sql = body_sql(&requests[1]);
    for table in [
        "control_plane_resources",
        "tenants",
        "projects",
        "workspaces",
        "api_keys",
        "storage_schema_migrations",
    ] {
        assert!(
            schema_sql.contains(&format!("CREATE TABLE IF NOT EXISTS {table}")),
            "schema batch should create {table}"
        );
    }
    assert!(!schema_sql.contains("--"), "comment lines must be stripped");

    // Registry persists through the config-document surface: the registry
    // kind/id land as the first two params of the control-db upsert.
    assert!(requests[2].url.contains("/d1/database/control-db/query"));
    let registry_params = body_params(&requests[2]);
    assert_eq!(registry_params[0], D1_TENANT_DATABASE_REGISTRY_KIND);
    assert_eq!(registry_params[1], D1_TENANT_DATABASE_REGISTRY_ID);
    let persisted = D1TenantDatabaseRegistry::from_document_json(&registry_params[2]).unwrap();
    assert_eq!(persisted.control_database_id, "control-db");
    assert_eq!(
        persisted.tenant_databases.get("acme").map(String::as_str),
        Some("acme-db")
    );

    // Idempotent: a second provision for the same tenant makes NO requests.
    let again = runtime()
        .block_on(store.provision_tenant_database("acme"))
        .unwrap();
    assert_eq!(again, "acme-db");
    assert_eq!(transport.recorded().len(), 3);
}

#[test]
fn deprovision_tenant_database_deletes_and_updates_registry() {
    let mut registry = control_registry();
    registry
        .tenant_databases
        .insert("acme".into(), "acme-db".into());
    let (store, transport) = store_with_transport(
        registry,
        vec![delete_database_ok(), query_ok(serde_json::json!([]), 1)],
    );

    let removed = runtime()
        .block_on(store.deprovision_tenant_database("acme"))
        .unwrap();
    assert!(removed);

    let requests = transport.recorded();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].url.ends_with("/d1/database/acme-db"));
    let persisted =
        D1TenantDatabaseRegistry::from_document_json(&body_params(&requests[1])[2]).unwrap();
    assert!(persisted.tenant_databases.is_empty());

    // Unknown tenant: no requests, Ok(false).
    let missing = runtime()
        .block_on(store.deprovision_tenant_database("ghost"))
        .unwrap();
    assert!(!missing);
    assert_eq!(transport.recorded().len(), 2);
}

#[test]
fn provision_rejects_tenant_ids_that_cannot_name_a_database() {
    let (store, transport) = store_with_transport(control_registry(), vec![]);
    let error = runtime()
        .block_on(store.provision_tenant_database("../oops"))
        .unwrap_err();
    assert!(matches!(error, StorageError::Runtime(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

// --- Query mapping: tenants (control database) ---

fn sample_tenant() -> StoredTenantAccount {
    StoredTenantAccount {
        id: "acme".into(),
        name: "Acme".into(),
        slug: "acme".into(),
        status: "active".into(),
        plan_id: "free".into(),
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
    }
}

#[test]
fn tenant_account_upsert_and_get_map_to_control_database_sql() {
    let tenant = sample_tenant();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "acme", "name": "Acme", "slug": "acme", "status": "active",
                    "plan_id": "free", "created_at_unix": 1_753_000_000_i64,
                    "updated_at_unix": 1_753_000_001_i64
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_tenant_account(tenant.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_tenant_account("acme"))
        .unwrap()
        .expect("tenant should decode");
    assert_eq!(fetched, tenant);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let upsert_sql = body_sql(&requests[0]);
    assert!(upsert_sql.starts_with("INSERT INTO tenants"));
    assert!(upsert_sql.contains("ON CONFLICT (id) DO UPDATE SET"));
    assert_eq!(
        body_params(&requests[0]),
        vec![
            "acme",
            "Acme",
            "acme",
            "active",
            "free",
            "1753000000",
            "1753000001"
        ]
    );
    assert!(body_sql(&requests[1]).contains("WHERE id = ?"));
}

// --- Query mapping: api keys (tenant database routing + fan-out) ---

fn sample_api_key() -> StoredApiKey {
    StoredApiKey {
        id: "key-1".into(),
        workspace_id: "ws-1".into(),
        tenant_id: "acme".into(),
        project_id: "proj-1".into(),
        name: "ci".into(),
        key_prefix: "fg-abc".into(),
        key_hash: "hash".into(),
        last4: "1234".into(),
        enabled: true,
        scopes: vec!["invoke".into()],
        allowed_models: vec!["gpt-5".into()],
        allowed_providers: Vec::new(),
        tenant: api_key_tenant_context("key-1", "acme", "proj-1", "ws-1"),
        monthly_token_budget: Some(1000),
        request_limit_per_minute: None,
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
        rotated_at_unix: None,
        expires_at_unix: Some(1_760_000_000),
        revoked_at_unix: None,
    }
}

fn sample_api_key_row() -> serde_json::Value {
    serde_json::json!({
        "id": "key-1", "workspace_id": "ws-1", "tenant_id": "acme",
        "project_id": "proj-1", "name": "ci", "key_prefix": "fg-abc",
        "key_hash": "hash", "last4": "1234", "enabled": 1,
        "scopes_json": "[\"invoke\"]", "allowed_models_json": "[\"gpt-5\"]",
        "allowed_providers_json": "[]", "monthly_token_budget": 1000,
        "request_limit_per_minute": null, "created_at_unix": 1_753_000_000_i64,
        "updated_at_unix": 1_753_000_001_i64, "rotated_at_unix": null,
        "expires_at_unix": 1_760_000_000_i64, "revoked_at_unix": null
    })
}

#[test]
fn api_key_round_trips_through_the_tenant_database() {
    let api_key = sample_api_key();
    let mut registry = control_registry();
    registry
        .tenant_databases
        .insert("acme".into(), "acme-db".into());
    let (store, transport) = store_with_transport(
        registry,
        vec![
            // Upsert routes to the TENANT database.
            query_ok(serde_json::json!([]), 1),
            // get_api_key_record fans out: control first (miss), tenant (hit).
            empty_query_ok(),
            query_ok(serde_json::json!([sample_api_key_row()]), 0),
        ],
    );

    runtime()
        .block_on(store.upsert_api_key_record(api_key.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_api_key_record("key-1"))
        .unwrap()
        .expect("api key should decode");
    // Round-trip: the row shape a D1 write produces decodes back into the
    // SAME StoredApiKey — the write/read halves agree on the column set.
    assert_eq!(fetched, api_key);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/acme-db/query"));
    let params = body_params(&requests[0]);
    assert_eq!(params.len(), 19);
    assert_eq!(params[8], "1", "enabled binds as SQLite 0/1");
    assert_eq!(params[9], "[\"invoke\"]");
    assert_eq!(params[12], "1000", "Some(budget) binds its number");
    assert_eq!(params[13], "", "None binds '' collapsed by NULLIF");
    assert!(body_sql(&requests[0]).contains("NULLIF(?, '')"));

    // Fan-out order: control database first, then the tenant database.
    assert!(requests[1].url.contains("/d1/database/control-db/query"));
    assert!(requests[2].url.contains("/d1/database/acme-db/query"));
}

#[test]
fn upsert_for_unprovisioned_tenant_is_a_typed_not_found() {
    let (store, transport) = store_with_transport(control_registry(), vec![]);
    let error = runtime()
        .block_on(store.upsert_api_key_record(sample_api_key()))
        .unwrap_err();
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(transport.recorded().is_empty());
}

// --- Query mapping: guarded deletes + meta decode ---

#[test]
fn delete_project_if_unreferenced_maps_referenced_counts() {
    let (store, _transport) = store_with_transport(
        control_registry(),
        vec![
            // Guarded DELETE touches nothing (meta.changes = 0)...
            query_ok(serde_json::json!([]), 0),
            // ...then the count probe reports the project exists + children.
            query_ok(
                serde_json::json!([{ "present": 1, "workspaces": 2, "virtual_keys": 1 }]),
                0,
            ),
        ],
    );

    let outcome = runtime()
        .block_on(store.delete_project_if_unreferenced("proj-1"))
        .unwrap();
    assert_eq!(
        outcome,
        DeleteProjectOutcome::Referenced {
            workspaces: 2,
            virtual_keys: 1,
        }
    );
}

#[test]
fn delete_workspace_decodes_meta_changes_into_bool() {
    let (store, _transport) =
        store_with_transport(control_registry(), vec![query_ok(serde_json::json!([]), 1)]);
    let deleted = runtime().block_on(store.delete_workspace("ws-1")).unwrap();
    assert!(deleted);

    let (store, _transport) =
        store_with_transport(control_registry(), vec![query_ok(serde_json::json!([]), 0)]);
    let deleted = runtime().block_on(store.delete_workspace("ws-1")).unwrap();
    assert!(!deleted);
}

// --- Config documents (sync surface over control_plane_resources) ---

#[test]
fn config_documents_route_through_control_plane_resources() {
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{ "document_json": "{\"id\":\"p1\"}" }]),
                0,
            ),
            query_ok(serde_json::json!([]), 1),
        ],
    );

    store
        .upsert_config_document("policy", "p1".into(), "{\"id\":\"p1\"}".into())
        .expect("upsert should succeed");
    let fetched = store
        .get_config_document("policy", "p1")
        .expect("get should succeed");
    assert_eq!(fetched.as_deref(), Some("{\"id\":\"p1\"}"));
    let deleted = store
        .delete_config_document("policy", "p1")
        .expect("delete should succeed");
    assert!(deleted);

    let requests = transport.recorded();
    assert!(body_sql(&requests[0]).contains("INSERT INTO control_plane_resources"));
    assert_eq!(body_params(&requests[0])[0], "policy");
    assert!(body_sql(&requests[2]).starts_with("DELETE FROM control_plane_resources"));
}

// --- Error mapping ---

#[test]
fn d1_error_envelope_maps_to_typed_storage_error() {
    let (store, _transport) = store_with_transport(
        control_registry(),
        vec![response(
            400,
            r#"{"success":false,"errors":[{"code":7500,"message":"no such table: tenants"}]}"#
                .into(),
        )],
    );

    let error = runtime()
        .block_on(store.get_tenant_account("acme"))
        .unwrap_err();
    match &error {
        StorageError::Runtime(message) => {
            assert!(message.contains("cloudflare d1"), "{message}");
            assert!(message.contains("no such table"), "{message}");
        }
        other => panic!("expected Runtime error, got {other:?}"),
    }
    assert!(!is_unimplemented_backend_surface(&error));
}

// --- The typed unimplemented-surface contract ---

#[test]
fn out_of_scope_trait_surface_errors_with_the_typed_contract() {
    let (store, transport) = store_with_transport(control_registry(), vec![]);

    let admin_error = runtime()
        .block_on(store.get_admin_user_by_id("u1"))
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&admin_error),
        "{admin_error:?}"
    );

    let plan_error = runtime().block_on(store.get_plan("free")).unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&plan_error),
        "{plan_error:?}"
    );

    let replay_error = store
        .get_snapshot_replay_floor("acme", "deploy-1")
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&replay_error),
        "{replay_error:?}"
    );

    // No unimplemented path may reach the network.
    assert!(transport.recorded().is_empty());
}

#[test]
fn per_entity_dispatch_arms_error_with_the_typed_contract() {
    let (store, _transport) = store_with_transport(control_registry(), vec![]);
    let repositories = RuntimeStorageRepositories::cloudflare_d1(store, 100);

    let wallet_error = runtime()
        .block_on(repositories.get_wallet("acme"))
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&wallet_error),
        "{wallet_error:?}"
    );

    let rbac_error = runtime()
        .block_on(repositories.list_permissions())
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&rbac_error),
        "{rbac_error:?}"
    );
}

// --- Portability matrix: Postgres vs D1 dialects of the core schema ---

mod portability {
    use std::collections::{BTreeMap, BTreeSet};

    const POSTGRES_SQL: &str = include_str!("../../../sql/001_init_postgres.sql");
    const D1_SQL: &str = include_str!("../../../sql/d1/001_init_d1.sql");

    const CORE_TABLES: [&str; 5] = [
        "control_plane_resources",
        "tenants",
        "projects",
        "workspaces",
        "api_keys",
    ];

    const CONSTRAINT_KEYWORDS: [&str; 5] = ["PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "CONSTRAINT"];

    /// Extract `table -> column set` from a migration file: CREATE TABLE
    /// bodies plus `ALTER TABLE .. ADD COLUMN IF NOT EXISTS ..` statements
    /// (the Postgres file adds several core columns that way).
    fn columns(sql: &str) -> BTreeMap<String, BTreeSet<String>> {
        let mut tables: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut current_table: Option<String> = None;
        let mut altering_table: Option<String> = None;
        for raw_line in sql.lines() {
            let line = raw_line.trim();
            if line.starts_with("--") || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("CREATE TABLE IF NOT EXISTS ") {
                let name = rest.split([' ', '(']).next().unwrap();
                current_table = Some(name.to_string());
                tables.entry(name.to_string()).or_default();
                continue;
            }
            if let Some(rest) = line.strip_prefix("ALTER TABLE ") {
                altering_table = Some(rest.split([' ', ';']).next().unwrap().to_string());
                // Single-line ALTERs fall through to the ADD COLUMN branch.
                if !rest.contains("ADD COLUMN IF NOT EXISTS ") {
                    continue;
                }
            }
            if let Some(position) = line.find("ADD COLUMN IF NOT EXISTS ") {
                if let Some(table) = altering_table.clone() {
                    let column = line[position + "ADD COLUMN IF NOT EXISTS ".len()..]
                        .split_whitespace()
                        .next()
                        .unwrap();
                    tables.entry(table).or_default().insert(column.to_string());
                }
                altering_table = None;
                continue;
            }
            if let Some(table) = current_table.clone() {
                if line.starts_with(");") || line == ")" {
                    current_table = None;
                    continue;
                }
                let first = line.split_whitespace().next().unwrap_or_default();
                if first.is_empty()
                    || CONSTRAINT_KEYWORDS
                        .iter()
                        .any(|keyword| first.eq_ignore_ascii_case(keyword))
                {
                    continue;
                }
                tables
                    .entry(table)
                    .or_default()
                    .insert(first.trim_end_matches(',').to_string());
            }
        }
        tables
    }

    /// The matrix: for every core table, the D1 (SQLite) migration exposes
    /// EXACTLY the columns the Postgres migration exposes, so the same
    /// logical operation compiles against either dialect's row shape.
    #[test]
    fn core_table_columns_match_between_postgres_and_d1() {
        let postgres = columns(POSTGRES_SQL);
        let d1 = columns(D1_SQL);
        for table in CORE_TABLES {
            let postgres_columns = postgres
                .get(table)
                .unwrap_or_else(|| panic!("postgres migration should define {table}"));
            let d1_columns = d1
                .get(table)
                .unwrap_or_else(|| panic!("d1 migration should define {table}"));
            assert_eq!(
                postgres_columns, d1_columns,
                "column set of {table} diverged between the Postgres and D1 dialects"
            );
        }
    }

    /// The D1 dialect must carry NO RLS/GUC scaffolding (isolation is
    /// database-per-tenant) and no cross-table FKs (documented divergence).
    #[test]
    fn d1_dialect_drops_rls_and_foreign_keys() {
        assert!(!D1_SQL.contains("ROW LEVEL SECURITY"));
        assert!(!D1_SQL.contains("current_setting"));
        assert!(!D1_SQL.contains("REFERENCES "));
    }
}
