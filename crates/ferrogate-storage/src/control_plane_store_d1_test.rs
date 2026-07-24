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
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, D1ProxyClient, EnvTokenResolver,
    HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};

use ferrogate_core::TenantContext;

use crate::control_plane_store::ControlPlaneStore;
use crate::{
    api_key_tenant_context, is_guardrail_policy_binding_cas_conflict,
    is_unimplemented_backend_surface, CloudflareD1StorageOptions, D1ControlPlaneStore,
    D1TenantDatabaseRegistry, DeleteProjectOutcome, QuotaScopeKind, ReplayDeadLetterOutcome,
    RuntimeStorageRepositories, StorageError, StoredAdminUser, StoredAdminUserRefreshToken,
    StoredAgentRun, StoredAgentRunEvent, StoredApiKey, StoredAuditEvent,
    StoredBudgetAlertNotification, StoredGuardrailPolicyBinding, StoredGuardrailPolicyRevision,
    StoredManagedWorkerTemplate, StoredPermission, StoredPlan, StoredQuotaPolicy, StoredRequestLog,
    StoredRole, StoredSelfHostedWorkerRegistration, StoredSiteDomain, StoredSsoProviderConfig,
    StoredTenantAccount, StoredTenantRoleBinding, StoredWallet, WalletReservationResult,
    D1_TENANT_DATABASE_REGISTRY_ID, D1_TENANT_DATABASE_REGISTRY_KIND,
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

/// A store wired with BOTH the REST transport (non-atomic path) AND a
/// proxy-Worker client backed by its own scripted transport (issue #450 atomic
/// path). The two transports are returned separately so a test can assert which
/// path a call took — the whole point of the atomic/REST split.
fn store_with_proxy(
    registry: D1TenantDatabaseRegistry,
    rest_responses: Vec<HttpResponse>,
    proxy_responses: Vec<HttpResponse>,
) -> (
    D1ControlPlaneStore,
    Arc<RecordingTransport>,
    Arc<RecordingTransport>,
) {
    let rest_transport = Arc::new(RecordingTransport::new(rest_responses));
    let client = D1Client::new(Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        rest_transport.clone(),
        Arc::new(InstantClock),
        RetryPolicy::default(),
    )));
    let proxy_transport = Arc::new(RecordingTransport::new(proxy_responses));
    let proxy = D1ProxyClient::new(
        "https://ferrogate-d1-proxy.example.workers.dev",
        proxy_transport.clone(),
        Arc::new(EnvTokenResolver::from_process_env()),
        "plaintext-proxy-token",
    );
    let store = D1ControlPlaneStore::new(client, registry).with_proxy_client(proxy);
    (store, rest_transport, proxy_transport)
}

/// One per-statement result inside a `/d1/batch` response.
fn proxy_statement_result(rows: serde_json::Value, changes: u64) -> serde_json::Value {
    serde_json::json!({
        "results": rows,
        "success": true,
        "meta": { "changes": changes, "rows_read": 1, "rows_written": 1 }
    })
}

/// A Cloudflare-style envelope wrapping the proxy Worker's per-statement batch
/// results (the shape `serializeResult` emits in workers/d1-proxy/src/index.ts).
fn proxy_batch_ok(statements: Vec<serde_json::Value>) -> HttpResponse {
    response(
        200,
        serde_json::json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": statements
        })
        .to_string(),
    )
}

/// A Cloudflare-style envelope wrapping the proxy Worker's SINGLE-statement
/// `/d1/query` result (the `result` field is one object, not an array). `rows`
/// are the `RETURNING` rows a CAS statement yields; an empty array is the
/// guard-missed / conflict signal.
fn proxy_query_ok(rows: serde_json::Value, changes: u64) -> HttpResponse {
    response(
        200,
        serde_json::json!({
            "success": true,
            "errors": [],
            "messages": [],
            "result": proxy_statement_result(rows, changes)
        })
        .to_string(),
    )
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

/// The string params of one proxy `/d1/batch` statement JSON value.
fn statement_params(statement: &serde_json::Value) -> Vec<String> {
    statement["params"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
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

    let asset_error = runtime().block_on(store.get_asset("a1")).unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&asset_error),
        "{asset_error:?}"
    );

    let schedule_error = runtime()
        .block_on(store.get_agent_schedule("s1"))
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&schedule_error),
        "{schedule_error:?}"
    );

    // A still-erroring sync surface: guardrail revisions/bindings READS moved
    // to the implemented set in issue #449, so the typed no-network contract is
    // now pinned on the generation-guarded CAS transition that stays out of
    // scope (it needs the compare-and-swap transaction the D1 HTTP API lacks).
    let guardrail_error = store
        .activate_guardrail_policy_revision("policy-1", 1, "admin", 0, false)
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&guardrail_error),
        "{guardrail_error:?}"
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

    // A still-erroring per-entity family (agent schedules) keeps the typed
    // contract; RBAC/site-domains/budget-alerts are implemented (issue #445)
    // and covered by their own round-trip tests below.
    let schedule_error = runtime()
        .block_on(repositories.get_agent_schedule("s1"))
        .unwrap_err();
    assert!(
        is_unimplemented_backend_surface(&schedule_error),
        "{schedule_error:?}"
    );
}

// --- Account-global entities (issue #440): admin users / SSO / quota / plans ---

fn sample_admin_user() -> StoredAdminUser {
    StoredAdminUser {
        id: "user-1".into(),
        email: "admin@example.com".into(),
        password_hash: "argon2$hash".into(),
        display_name: "Admin".into(),
        superadmin: true,
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
        last_login_at_unix: Some(1_753_000_500),
        disabled_at_unix: None,
    }
}

#[test]
fn admin_user_round_trips_through_the_control_database() {
    let user = sample_admin_user();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "user-1", "email": "admin@example.com",
                    "password_hash": "argon2$hash", "display_name": "Admin",
                    "superadmin": 1, "created_at_unix": 1_753_000_000_i64,
                    "updated_at_unix": 1_753_000_001_i64,
                    "last_login_at_unix": 1_753_000_500_i64, "disabled_at_unix": null
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_admin_user(user.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_admin_user_by_id("user-1"))
        .unwrap()
        .expect("admin user should decode");
    assert_eq!(fetched, user);

    let requests = transport.recorded();
    // Admin identity is account-global: writes route to the control database.
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let upsert_sql = body_sql(&requests[0]);
    assert!(upsert_sql.starts_with("INSERT INTO admin_users"));
    let params = body_params(&requests[0]);
    assert_eq!(params[4], "1", "superadmin binds as SQLite 0/1");
    assert_eq!(params[7], "1753000500", "Some(last_login) binds its number");
    assert_eq!(params[8], "", "None(disabled) binds '' collapsed by NULLIF");
    assert!(body_sql(&requests[1]).contains("WHERE id = ?"));
}

#[test]
fn admin_user_lookup_by_email_routes_to_control_database() {
    let (store, transport) =
        store_with_transport(control_registry(), vec![query_ok(serde_json::json!([]), 0)]);
    let found = runtime()
        .block_on(store.get_admin_user_by_email("missing@example.com"))
        .unwrap();
    assert!(found.is_none());
    assert!(body_sql(&transport.recorded()[0]).contains("WHERE email = ?"));
}

#[test]
fn admin_user_refresh_token_revoke_returns_change_count() {
    let token = StoredAdminUserRefreshToken {
        id: "tok-1".into(),
        user_id: "user-1".into(),
        token_hash: "hash".into(),
        tenant_id: Some("acme".into()),
        role: Some("owner".into()),
        created_at_unix: 1_753_000_000,
        expires_at_unix: 1_760_000_000,
        revoked_at_unix: None,
    };
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            // revoke_all reports two rows updated.
            query_ok(serde_json::json!([]), 2),
        ],
    );

    runtime()
        .block_on(store.upsert_admin_user_refresh_token(token))
        .expect("upsert should succeed");
    let revoked = runtime()
        .block_on(store.revoke_all_admin_user_refresh_tokens("user-1", 1_755_000_000))
        .unwrap();
    assert_eq!(revoked, 2);

    let revoke_sql = body_sql(&transport.recorded()[1]);
    assert!(revoke_sql.starts_with("UPDATE admin_user_refresh_tokens SET revoked_at_unix"));
    assert!(revoke_sql.contains("revoked_at_unix IS NULL"));
}

#[test]
fn sso_provider_config_round_trips_through_the_control_database() {
    let mut config = StoredSsoProviderConfig {
        tenant_id: "acme".into(),
        provider_kind: "oidc".into(),
        default_role: "member".into(),
        group_role_mapping: Default::default(),
        oidc_issuer: Some("https://idp.example.com".into()),
        oidc_client_id: Some("client-123".into()),
        oidc_client_secret_ref: Some("env://SSO_SECRET".into()),
        oidc_redirect_uri: Some("https://gw.example.com/callback".into()),
        oidc_group_claim: Some("groups".into()),
        saml_idp_entity_id: None,
        saml_idp_sso_url: None,
        saml_idp_certificate: None,
        saml_sp_entity_id: None,
        saml_acs_url: None,
        saml_email_attribute: None,
        saml_name_attribute: None,
        saml_groups_attribute: None,
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
    };
    config
        .group_role_mapping
        .insert("admins".into(), "owner".into());
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "tenant_id": "acme", "provider_kind": "oidc", "default_role": "member",
                    "group_role_mapping_json": "{\"admins\":\"owner\"}",
                    "oidc_issuer": "https://idp.example.com", "oidc_client_id": "client-123",
                    "oidc_client_secret_ref": "env://SSO_SECRET",
                    "oidc_redirect_uri": "https://gw.example.com/callback",
                    "oidc_group_claim": "groups", "saml_idp_entity_id": null,
                    "saml_idp_sso_url": null, "saml_idp_certificate": null,
                    "saml_sp_entity_id": null, "saml_acs_url": null,
                    "saml_email_attribute": null, "saml_name_attribute": null,
                    "saml_groups_attribute": null, "created_at_unix": 1_753_000_000_i64,
                    "updated_at_unix": 1_753_000_001_i64
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_sso_provider_config(config.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_sso_provider_config("acme"))
        .unwrap()
        .expect("sso config should decode");
    assert_eq!(fetched, config);
    assert!(body_sql(&transport.recorded()[0]).starts_with("INSERT INTO sso_provider_configs"));
}

#[test]
fn take_sso_pending_flow_consumes_once_and_honors_expiry() {
    let flow_row = serde_json::json!([{
        "state": "s1", "tenant_id": "acme", "provider_kind": "oidc",
        "code_verifier": "verifier", "request_id": null,
        "created_at_unix": 1_753_000_000_i64, "expires_at_unix": 1_753_000_600_i64
    }]);
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            // SELECT the row, then the consume+prune DELETE.
            query_ok(flow_row, 0),
            query_ok(serde_json::json!([]), 1),
        ],
    );

    let taken = runtime()
        .block_on(store.take_sso_pending_flow("s1", 1_753_000_100))
        .unwrap()
        .expect("unexpired flow should be returned");
    assert_eq!(taken.state, "s1");
    assert_eq!(taken.code_verifier.as_deref(), Some("verifier"));

    let requests = transport.recorded();
    assert_eq!(requests.len(), 2);
    assert!(body_sql(&requests[0]).contains("FROM sso_pending_flows"));
    let delete_sql = body_sql(&requests[1]);
    assert!(delete_sql.starts_with("DELETE FROM sso_pending_flows"));
    assert!(delete_sql.contains("expires_at_unix <= ?"));

    // An already-expired row is deleted but NOT returned to the caller.
    let expired_row = serde_json::json!([{
        "state": "s2", "tenant_id": "acme", "provider_kind": "oidc",
        "code_verifier": null, "request_id": null,
        "created_at_unix": 1_753_000_000_i64, "expires_at_unix": 1_753_000_050_i64
    }]);
    let (store, _transport) = store_with_transport(
        control_registry(),
        vec![query_ok(expired_row, 0), query_ok(serde_json::json!([]), 1)],
    );
    let none = runtime()
        .block_on(store.take_sso_pending_flow("s2", 1_753_000_100))
        .unwrap();
    assert!(none.is_none(), "expired flow must not be handed back");
}

fn sample_quota_policy() -> StoredQuotaPolicy {
    StoredQuotaPolicy {
        id: "quota-tenant-acme".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "acme".into(),
        model_allowlist: vec!["gpt-5".into()],
        rpm_limit: Some(600),
        tpm_limit: None,
        monthly_budget_usd: Some(12.5),
        asset_storage_quota_bytes: Some(1024),
        alert_threshold_pcts: vec![75, 90],
        enabled: true,
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
        monthly_egress_bytes_budget: None,
        download_rpm_limit: Some(30),
    }
}

#[test]
fn quota_policy_round_trips_with_dialect_mapping() {
    let policy = sample_quota_policy();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "quota-tenant-acme", "scope_type": "tenant", "scope_id": "acme",
                    "model_allowlist_json": "[\"gpt-5\"]", "rpm_limit": 600, "tpm_limit": null,
                    "monthly_budget_usd": 12.5, "enabled": 1,
                    "created_at_unix": 1_753_000_000_i64, "updated_at_unix": 1_753_000_001_i64,
                    "alert_threshold_pcts_json": "[75,90]", "asset_storage_quota_bytes": 1024,
                    "monthly_egress_bytes_budget": null, "download_rpm_limit": 30
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_quota_policy(policy.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_quota_policy(QuotaScopeKind::Tenant, "acme"))
        .unwrap()
        .expect("quota policy should decode");
    assert_eq!(fetched, policy);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let params = body_params(&requests[0]);
    assert_eq!(params[1], "tenant", "scope_type binds its enum string");
    assert_eq!(
        params[3], "[\"gpt-5\"]",
        "model allowlist binds as JSON text"
    );
    assert_eq!(params[5], "", "None(tpm) binds '' collapsed by NULLIF");
    assert_eq!(params[6], "12.5", "f64 budget binds as its decimal string");
    assert_eq!(params[7], "1", "enabled binds as SQLite 0/1");
    let get_sql = body_sql(&requests[1]);
    assert!(get_sql.contains("WHERE scope_type = ? AND scope_id = ?"));
}

fn sample_plan() -> StoredPlan {
    StoredPlan {
        id: "pro".into(),
        name: "Pro".into(),
        slug: "pro".into(),
        mcp_enabled: true,
        self_hosted_workers_enabled: false,
        admin_console_seats: Some(10),
        default_model_allowlist: vec!["gpt-5".into()],
        default_rpm_limit: Some(1000),
        default_tpm_limit: None,
        default_monthly_budget_usd: Some(100.0),
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
        asset_hosting_enabled: true,
        default_asset_storage_quota_bytes: Some(10_485_760),
        default_monthly_egress_bytes_budget: None,
        default_download_rpm_limit: None,
        extension_tools_enabled: false,
    }
}

#[test]
fn plan_round_trips_through_the_control_database() {
    let plan = sample_plan();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "pro", "name": "Pro", "slug": "pro", "mcp_enabled": 1,
                    "self_hosted_workers_enabled": 0, "admin_console_seats": 10,
                    "default_model_allowlist_json": "[\"gpt-5\"]", "default_rpm_limit": 1000,
                    "default_tpm_limit": null, "default_monthly_budget_usd": 100.0,
                    "created_at_unix": 1_753_000_000_i64, "updated_at_unix": 1_753_000_001_i64,
                    "asset_hosting_enabled": 1, "default_asset_storage_quota_bytes": 10_485_760_i64,
                    "extension_tools_enabled": 0, "default_monthly_egress_bytes_budget": null,
                    "default_download_rpm_limit": null
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_plan(plan.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_plan("pro"))
        .unwrap()
        .expect("plan should decode");
    assert_eq!(fetched, plan);
    assert!(body_sql(&transport.recorded()[0]).starts_with("INSERT INTO plans"));
}

// --- Account-global admin/config families (issue #445): RBAC / site domains /
// budget alert idempotency ledger ---

#[test]
fn permission_round_trips_through_the_control_database() {
    let permission = StoredPermission {
        id: "perm-1".into(),
        key: "assets.publish".into(),
        name: "Publish assets".into(),
        description: "Allows publishing assets".into(),
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
    };
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "perm-1", "key": "assets.publish", "name": "Publish assets",
                    "description": "Allows publishing assets",
                    "created_at_unix": 1_753_000_000_i64, "updated_at_unix": 1_753_000_001_i64
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_permission(permission.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_permission("perm-1"))
        .unwrap()
        .expect("permission should decode");
    assert_eq!(fetched, permission);

    let requests = transport.recorded();
    // RBAC is account-global: writes route to the control database.
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    assert!(body_sql(&requests[0]).starts_with("INSERT INTO permissions"));
    assert!(body_sql(&requests[1]).contains("WHERE id = ?"));
}

#[test]
fn role_round_trips_with_permission_keys_json() {
    let role = StoredRole {
        id: "role-1".into(),
        name: "Publisher".into(),
        slug: "publisher".into(),
        description: "Can publish".into(),
        permission_keys: vec!["assets.publish".into(), "assets.read".into()],
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
    };
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "role-1", "name": "Publisher", "slug": "publisher",
                    "description": "Can publish",
                    "permission_keys_json": "[\"assets.publish\",\"assets.read\"]",
                    "created_at_unix": 1_753_000_000_i64, "updated_at_unix": 1_753_000_001_i64
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_role(role.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_role("role-1"))
        .unwrap()
        .expect("role should decode");
    assert_eq!(fetched, role);

    let params = body_params(&transport.recorded()[0]);
    assert_eq!(
        params[4], "[\"assets.publish\",\"assets.read\"]",
        "permission_keys bind as JSON text (JSONB -> TEXT)"
    );
    assert!(body_sql(&transport.recorded()[0]).starts_with("INSERT INTO roles"));
}

#[test]
fn tenant_role_binding_binds_lists_and_unbinds() {
    let binding = StoredTenantRoleBinding {
        id: "acme:role-1".into(),
        tenant_id: "acme".into(),
        role_id: "role-1".into(),
        created_at_unix: 1_753_000_000,
    };
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "acme:role-1", "tenant_id": "acme", "role_id": "role-1",
                    "created_at_unix": 1_753_000_000_i64
                }]),
                0,
            ),
            query_ok(serde_json::json!([]), 1),
        ],
    );

    runtime()
        .block_on(store.bind_tenant_role(binding.clone()))
        .expect("bind should succeed");
    let listed = runtime()
        .block_on(store.list_tenant_role_bindings("acme"))
        .unwrap();
    assert_eq!(listed, vec![binding]);
    let unbound = runtime()
        .block_on(store.unbind_tenant_role("acme", "role-1"))
        .unwrap();
    assert!(unbound);

    let requests = transport.recorded();
    // Binding is idempotent on the deterministic id.
    assert!(body_sql(&requests[0]).contains("ON CONFLICT (id) DO NOTHING"));
    assert!(body_sql(&requests[1]).contains("WHERE tenant_id = ?"));
    let unbind_sql = body_sql(&requests[2]);
    assert!(unbind_sql.starts_with("DELETE FROM tenant_role_bindings"));
    assert!(unbind_sql.contains("tenant_id = ? AND role_id = ?"));
}

#[test]
fn site_domain_round_trips_and_filters_by_tenant() {
    let domain = StoredSiteDomain {
        hostname: "docs.example.com".into(),
        tenant_id: "acme".into(),
        site: "handbook".into(),
        created_at_unix: 1_753_000_000,
        updated_at_unix: 1_753_000_001,
    };
    let row = serde_json::json!([{
        "hostname": "docs.example.com", "tenant_id": "acme", "site": "handbook",
        "created_at_unix": 1_753_000_000_i64, "updated_at_unix": 1_753_000_001_i64
    }]);
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(row.clone(), 0),
            query_ok(row.clone(), 0),
            query_ok(row, 0),
            query_ok(serde_json::json!([]), 1),
        ],
    );

    runtime()
        .block_on(store.upsert_site_domain(domain.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.get_site_domain("docs.example.com"))
        .unwrap()
        .expect("domain should decode");
    assert_eq!(fetched, domain);
    let by_tenant = runtime()
        .block_on(store.list_site_domains(Some("acme")))
        .unwrap();
    assert_eq!(by_tenant, vec![domain.clone()]);
    let all = runtime().block_on(store.list_site_domains(None)).unwrap();
    assert_eq!(all, vec![domain]);
    let deleted = runtime()
        .block_on(store.delete_site_domain("docs.example.com"))
        .unwrap();
    assert!(deleted);

    let requests = transport.recorded();
    // hostname lookups carry no tenant context, so this family lives in the
    // control database rather than fanning out over tenant databases.
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    assert!(body_sql(&requests[0]).starts_with("INSERT INTO site_domains"));
    assert!(body_sql(&requests[2]).contains("WHERE tenant_id = ?"));
    assert!(
        !body_sql(&requests[3]).contains("WHERE tenant_id"),
        "the None tenant filter lists every hostname"
    );
}

#[test]
fn budget_alert_notification_ledger_round_trips() {
    let notification = StoredBudgetAlertNotification {
        id: "tenant:acme:2026-07:90".into(),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: "acme".into(),
        period_month: "2026-07".into(),
        threshold_pct: 90,
        notified_at_unix: 1_753_000_000,
    };
    let row = serde_json::json!([{
        "id": "tenant:acme:2026-07:90", "scope_type": "tenant", "scope_id": "acme",
        "period_month": "2026-07", "threshold_pct": 90, "notified_at_unix": 1_753_000_000_i64
    }]);
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(row.clone(), 0),
            query_ok(row, 0),
        ],
    );

    runtime()
        .block_on(store.record_budget_alert_notification(notification.clone()))
        .expect("record should succeed");
    let already = runtime()
        .block_on(store.budget_alert_already_notified("tenant:acme:2026-07:90"))
        .unwrap();
    assert!(already, "the recorded tier reads back as already notified");
    let listed = runtime()
        .block_on(store.list_budget_alert_notifications(QuotaScopeKind::Tenant, "acme", "2026-07"))
        .unwrap();
    assert_eq!(listed, vec![notification]);

    let requests = transport.recorded();
    let record_sql = body_sql(&requests[0]);
    assert!(record_sql.starts_with("INSERT INTO budget_alert_notifications"));
    // Idempotency ledger: exactly one row per (scope, period, tier).
    assert!(record_sql.contains("ON CONFLICT (id) DO NOTHING"));
    let params = body_params(&requests[0]);
    assert_eq!(params[1], "tenant", "scope_type binds its enum string");
    assert_eq!(params[4], "90", "threshold_pct binds as an integer string");
    assert!(body_sql(&requests[2]).contains("ORDER BY threshold_pct ASC"));
}

// --- Config construction route (issue #440) ---

#[test]
fn cloudflare_d1_from_client_seeds_registry_from_config() {
    let transport = Arc::new(RecordingTransport::new(vec![query_ok(
        serde_json::json!([{
            "id": "acme", "name": "Acme", "slug": "acme", "status": "active",
            "plan_id": "free", "created_at_unix": 1_753_000_000_i64,
            "updated_at_unix": 1_753_000_001_i64
        }]),
        0,
    )]));
    let client = D1Client::new(Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("acct-test", "plaintext-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport.clone(),
        Arc::new(InstantClock),
        RetryPolicy::default(),
    )));
    let mut options = CloudflareD1StorageOptions {
        control_database_id: "control-db".into(),
        tenant_databases: Default::default(),
        audit_event_retention_records: 50,
    };
    options
        .tenant_databases
        .insert("acme".into(), "acme-db".into());

    let repositories = RuntimeStorageRepositories::cloudflare_d1_from_client(client, options)
        .expect("config construction should succeed");

    // A control-plane read now works and routes to the seeded control database,
    // proving the registry was threaded from config into the live backend.
    let tenant = runtime()
        .block_on(repositories.get_tenant_account("acme"))
        .unwrap()
        .expect("tenant should decode");
    assert_eq!(tenant.id, "acme");
    assert!(transport.recorded()[0]
        .url
        .contains("/d1/database/control-db/query"));
}

// --- Observability append/analytics families (issue #447, control database) ---

fn sample_agent_run() -> StoredAgentRun {
    StoredAgentRun {
        id: "run-1".into(),
        request_id: "req-1".into(),
        trace_id: Some("trace-1".into()),
        tenant: TenantContext::default(),
        status: "running".into(),
        provider: "openai".into(),
        turns_executed: 2,
        output_recorded: true,
        started_at_unix: Some(1_753_000_000),
        completed_at_unix: None,
    }
}

fn sample_agent_run_event() -> StoredAgentRunEvent {
    StoredAgentRunEvent {
        id: "evt-1".into(),
        run_id: "run-1".into(),
        request_id: "req-1".into(),
        trace_id: None,
        tenant: TenantContext::default(),
        turn: 1,
        kind: "tool_call".into(),
        target: "search".into(),
        outcome: "success".into(),
        tool_call_id: Some("call-1".into()),
        message: None,
        occurred_at_unix: Some(1_753_000_010),
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
    }
}

fn sample_request_log() -> StoredRequestLog {
    StoredRequestLog {
        request_id: "req-1".into(),
        trace_id: Some("trace-1".into()),
        agent_run_id: Some("run-1".into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext::default(),
        route: Some("/v1/chat".into()),
        provider: Some("openai".into()),
        logical_model: Some("gpt-5".into()),
        provider_model: Some("gpt-5-2026".into()),
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(1_753_000_000),
        completed_at_unix: Some(1_753_000_002),
        parent_action_fingerprint: None,
    }
}

fn sample_audit_event() -> StoredAuditEvent {
    StoredAuditEvent {
        id: "audit-1".into(),
        request_id: "req-1".into(),
        trace_id: None,
        agent_run_id: Some("run-1".into()),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: Some("key-1".into()),
        tenant: TenantContext::default(),
        action: "invoke".into(),
        target: "gpt-5".into(),
        outcome: "success".into(),
        message: "ok".into(),
        occurred_at_unix: Some(1_753_000_005),
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
        parent_action_fingerprint: None,
    }
}

#[test]
fn agent_run_round_trips_through_the_control_database() {
    let run = sample_agent_run();
    let run_json = serde_json::to_string(&run).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{ "document_json": run_json.clone() }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_agent_run(run.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.agent_run("run-1"))
        .expect("agent run should decode");
    assert_eq!(fetched, run);

    let requests = transport.recorded();
    // Observability families route to the control database, not per-tenant.
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let upsert_sql = body_sql(&requests[0]);
    assert!(upsert_sql.starts_with("INSERT INTO agent_runs"));
    assert!(upsert_sql.contains("ON CONFLICT (id) DO UPDATE SET"));
    let params = body_params(&requests[0]);
    assert_eq!(params[0], "run-1");
    assert_eq!(params[1], "req-1");
    assert_eq!(
        params[3], "1753000000",
        "started_at binds as its integer string"
    );
    assert_eq!(
        params[4], "",
        "None(completed) binds '' collapsed by NULLIF"
    );
    assert_eq!(
        params[5], run_json,
        "the full run persists as its json document"
    );
    assert!(body_sql(&requests[1]).contains("run_json AS document_json"));
}

#[test]
fn request_log_appends_and_pages_from_the_control_database() {
    let log = sample_request_log();
    let log_json = serde_json::to_string(&log).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{ "document_json": log_json, "total": 1_i64 }]),
                0,
            ),
        ],
    );

    runtime().block_on(store.append_request_log(log.clone()));
    let page = runtime().block_on(store.request_logs_page(0, 20));
    assert_eq!(page.total, 1);
    assert_eq!(page.offset, 0);
    assert_eq!(page.limit, 20);
    assert_eq!(page.data, vec![log]);

    let requests = transport.recorded();
    let append_sql = body_sql(&requests[0]);
    assert!(append_sql.starts_with("INSERT INTO request_logs"));
    assert!(append_sql.contains("ON CONFLICT (request_id) DO UPDATE SET"));
    // agent_run_id collapses '' -> NULL; the request json is the last param.
    assert!(append_sql.contains("NULLIF(?, '')"));
    let page_sql = body_sql(&requests[1]);
    assert!(page_sql.contains("count(*) OVER() AS total"));
    assert!(
        page_sql.contains("LIMIT 20 OFFSET 0"),
        "page offset/limit inline as integer literals: {page_sql}"
    );
}

#[test]
fn audit_events_append_list_and_delete_by_id_set() {
    let event = sample_audit_event();
    let event_json = serde_json::to_string(&event).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "document_json": event_json }]), 0),
            query_ok(serde_json::json!([]), 2),
        ],
    );

    runtime().block_on(store.append_audit_event(event.clone()));
    let listed = runtime().block_on(store.audit_events());
    assert_eq!(listed, vec![event]);
    let deleted = runtime()
        .block_on(store.delete_audit_events(&["audit-1".into(), "audit-2".into()]))
        .unwrap();
    assert_eq!(deleted, 2);

    let requests = transport.recorded();
    // Append is idempotent by primary key (ON CONFLICT DO NOTHING).
    assert!(body_sql(&requests[0]).contains("ON CONFLICT (id) DO NOTHING"));
    assert!(body_sql(&requests[1]).contains("audit_json AS document_json"));
    let delete_sql = body_sql(&requests[2]);
    assert!(delete_sql.starts_with("DELETE FROM audit_events WHERE id IN (?, ?)"));
    assert_eq!(body_params(&requests[2]), vec!["audit-1", "audit-2"]);

    // The empty id set short-circuits with NO network round trip.
    let (empty_store, empty_transport) = store_with_transport(control_registry(), vec![]);
    let none = runtime()
        .block_on(empty_store.delete_audit_events(&[]))
        .unwrap();
    assert_eq!(none, 0);
    assert!(empty_transport.recorded().is_empty());
}

#[test]
fn agent_run_events_filter_by_run_id_set() {
    let event = sample_agent_run_event();
    let event_json = serde_json::to_string(&event).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "document_json": event_json }]), 0),
        ],
    );

    runtime()
        .block_on(store.append_agent_run_event(event.clone()))
        .expect("append should succeed");
    let events = runtime().block_on(store.agent_run_events_for_runs(&["run-1".into()]));
    assert_eq!(events, vec![event]);

    let requests = transport.recorded();
    assert!(body_sql(&requests[0]).starts_with("INSERT INTO agent_run_events"));
    let for_runs_sql = body_sql(&requests[1]);
    assert!(for_runs_sql.contains("WHERE run_id IN (?)"));
    assert_eq!(body_params(&requests[1]), vec!["run-1"]);

    // The empty run-id set short-circuits with no further query.
    let empty = runtime().block_on(store.agent_run_events_for_runs(&[]));
    assert!(empty.is_empty());
    assert_eq!(transport.recorded().len(), 2);
}

#[test]
fn agent_run_summary_seed_ids_unions_all_four_sources() {
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![query_ok(
            serde_json::json!([{ "run_id": "run-9" }, { "run_id": "run-3" }]),
            0,
        )],
    );

    let ids = runtime().block_on(store.agent_run_summary_seed_ids(Some("req-1"), 25));
    assert_eq!(ids, vec!["run-9".to_string(), "run-3".to_string()]);

    let sql = body_sql(&transport.recorded()[0]);
    assert!(sql.contains("FROM agent_runs"));
    assert!(sql.contains("FROM agent_run_events"));
    assert!(sql.contains("FROM request_logs WHERE agent_run_id IS NOT NULL"));
    assert!(sql.contains("FROM audit_events"));
    assert!(sql.contains("UNION ALL"));
    assert!(sql.contains("LIMIT 25"));
    // The request_id filter binds once per subquery: four positional params.
    assert_eq!(
        body_params(&transport.recorded()[0]),
        vec!["req-1", "req-1", "req-1", "req-1"]
    );

    // Absent request_id binds NO params (unfiltered UNION over the four tables).
    let (unfiltered, unfiltered_transport) =
        store_with_transport(control_registry(), vec![empty_query_ok()]);
    let _ = runtime().block_on(unfiltered.agent_run_summary_seed_ids(None, 10));
    assert!(
        body_params(&unfiltered_transport.recorded()[0]).is_empty(),
        "the None filter binds no params"
    );
}

#[test]
fn snapshot_replay_floor_upserts_monotonically_and_reads_back() {
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            // advance: the max() upsert then the follow-up SELECT.
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "last_accepted_revision": 42_i64 }]), 0),
            // get.
            query_ok(serde_json::json!([{ "last_accepted_revision": 42_i64 }]), 0),
        ],
    );

    let floor = store
        .advance_snapshot_replay_floor("acme", "deploy-1", 42, 1_753_000_000)
        .unwrap();
    assert_eq!(floor, 42);
    let read = store
        .get_snapshot_replay_floor("acme", "deploy-1")
        .unwrap()
        .expect("floor should be present");
    assert_eq!(read, 42);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let upsert_sql = body_sql(&requests[0]);
    assert!(upsert_sql.starts_with("INSERT INTO control_plane_replay_floors"));
    assert!(
        upsert_sql.contains("max("),
        "the monotonic upsert uses SQLite max(): {upsert_sql}"
    );
    assert_eq!(
        body_params(&requests[0]),
        vec!["acme", "deploy-1", "42", "1753000000"]
    );
    // No RETURNING: the resulting floor comes from a follow-up SELECT.
    assert!(body_sql(&requests[1]).contains("SELECT last_accepted_revision"));

    // An absent floor reads back as None.
    let (missing_store, _missing_transport) =
        store_with_transport(control_registry(), vec![empty_query_ok()]);
    let missing = missing_store
        .get_snapshot_replay_floor("acme", "deploy-2")
        .unwrap();
    assert!(missing.is_none());
}

// --- Billing / guardrail / worker stores (issue #449, control database) ---

fn sample_billing_event(request_id: &str) -> ferrogate_billing::BillingEvent {
    ferrogate_billing::BillingEvent {
        request_id: request_id.into(),
        trace_id: Some(format!("trace-{request_id}")),
        provider_attempt: ferrogate_billing::ProviderAttempt::for_request(request_id, 0),
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some("acme".into()),
            ..TenantContext::default()
        },
        logical_model: "chat".into(),
        provider: "openai".into(),
        provider_model: "gpt-4o-mini".into(),
        usage: ferrogate_billing::TokenUsage::new(1, 1, 2),
        usage_source: ferrogate_billing::BillingUsageSource::ProviderUsage,
        status_code: 200,
        occurred_at_unix: Some(1_800_000_000),
        cost_usd: Some(0.000_01),
        latency_ms: Some(3),
        metadata: std::collections::BTreeMap::new(),
        wallet_delta_credits: None,
        wallet_balance_after_credits: None,
    }
}

#[test]
fn billing_event_appends_idempotently_and_pages_from_the_control_database() {
    let event = sample_billing_event("req-1");
    let event_doc = serde_json::to_string(&event).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            // INSERT ... ON CONFLICT DO NOTHING lands the row.
            query_ok(serde_json::json!([]), 1),
            // count(*) OVER() page carries the doc + window total.
            query_ok(
                serde_json::json!([{ "document_json": event_doc, "total": 1_i64 }]),
                0,
            ),
        ],
    );

    let inserted = runtime()
        .block_on(store.append_billing_event(event.clone()))
        .expect("append should succeed");
    assert!(inserted);
    let page = runtime().block_on(store.billing_events_page(0, 20));
    assert_eq!(page.total, 1);
    assert_eq!(page.data, vec![event.clone()]);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let append_sql = body_sql(&requests[0]);
    assert!(append_sql.starts_with("INSERT INTO billing_events"));
    assert!(append_sql.contains("ON CONFLICT (billing_event_id) DO NOTHING"));
    // request_id is the second projection param (billing_event_id, request_id, ...).
    assert_eq!(body_params(&requests[0])[1], "req-1");
    assert!(body_sql(&requests[1]).contains("count(*) OVER()"));

    // A conflicting replay (changes = 0) reloads and returns false, not a row.
    let (replay_store, _replay_transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 0),
            query_ok(serde_json::json!([{ "document_json": event_doc }]), 0),
        ],
    );
    let replayed = runtime()
        .block_on(replay_store.append_billing_event(event))
        .expect("idempotent replay should not error");
    assert!(!replayed);
}

#[test]
fn billing_ledger_entry_appends_and_reads_back_from_control_database() {
    let entry = ferrogate_billing::charge(
        &ferrogate_billing::PriceBook::default(),
        &sample_billing_event("req-ledger"),
    )
    .expect("settled cost prices without a rate card");
    let entry_doc = serde_json::to_string(&entry).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "document_json": entry_doc }]), 0),
        ],
    );

    let inserted = runtime()
        .block_on(store.append_billing_ledger_entry(&entry))
        .expect("append should succeed");
    assert!(inserted);
    let fetched = runtime()
        .block_on(store.billing_ledger_entry(&entry.id))
        .unwrap()
        .expect("ledger entry should decode");
    assert_eq!(fetched, entry);

    let append_sql = body_sql(&transport.recorded()[0]);
    assert!(append_sql.starts_with("INSERT INTO billing_ledger"));
    assert!(append_sql.contains("ON CONFLICT (id) DO NOTHING"));
}

#[test]
fn billing_report_outbox_enqueues_lists_due_and_replays() {
    let event = sample_billing_event("req-1");
    let event_doc = serde_json::to_string(&event).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "report-1", "event_json": event_doc,
                    "attempts": 0_i64, "next_attempt_unix": 100_i64,
                    "dead_lettered_at_unix": null
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.enqueue_billing_report("report-1", &event, 100))
        .expect("enqueue should succeed");
    let due = runtime()
        .block_on(store.list_due_billing_reports(1_000, 10))
        .expect("list due should succeed");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, "report-1");
    assert_eq!(due[0].event, event);

    let requests = transport.recorded();
    assert!(body_sql(&requests[0]).starts_with("INSERT INTO billing_report_outbox"));
    let due_sql = body_sql(&requests[1]);
    assert!(due_sql.contains("next_attempt_unix <= ?"));
    assert!(due_sql.contains("dead_lettered_at_unix IS NULL"));

    // Replay: a guarded UPDATE fires, then a follow-up SELECT reports the
    // now-cleared row -- no `UPDATE ... RETURNING` on the HTTP query API.
    let cleared_doc = serde_json::to_string(&event).unwrap();
    let (replay_store, replay_transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{
                    "id": "report-1", "event_json": cleared_doc,
                    "attempts": 0_i64, "next_attempt_unix": 500_i64,
                    "dead_lettered_at_unix": null
                }]),
                0,
            ),
        ],
    );
    let outcome = runtime()
        .block_on(replay_store.replay_dead_lettered_billing_report("report-1", 500))
        .expect("replay should succeed");
    match outcome {
        ReplayDeadLetterOutcome::Replayed(entry) => assert_eq!(entry.id, "report-1"),
        other => panic!("expected Replayed, got {other:?}"),
    }
    let replay_sql = body_sql(&replay_transport.recorded()[0]);
    assert!(replay_sql.contains("dead_lettered_at_unix = NULL"));
    assert!(replay_sql.contains("dead_lettered_at_unix IS NOT NULL"));
}

fn sample_guardrail_revision() -> StoredGuardrailPolicyRevision {
    StoredGuardrailPolicyRevision {
        id: "policy-1@1".into(),
        policy_id: "policy-1".into(),
        revision: 1,
        policy_json: "{\"rules\":[]}".into(),
        created_at_unix: 1_753_000_000,
        created_by: "admin".into(),
    }
}

#[test]
fn guardrail_policy_revision_inserts_reads_and_rejects_replays() {
    let revision = sample_guardrail_revision();
    let revision_doc = serde_json::to_string(&revision).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "document_json": revision_doc }]), 0),
        ],
    );

    store
        .insert_guardrail_policy_revision(revision.clone())
        .expect("insert should succeed");
    let fetched = store
        .get_guardrail_policy_revision("policy-1", 1)
        .unwrap()
        .expect("revision should decode");
    assert_eq!(fetched, revision);

    let insert_sql = body_sql(&transport.recorded()[0]);
    assert!(insert_sql.starts_with("INSERT INTO guardrail_policy_revisions"));
    assert!(insert_sql.contains("ON CONFLICT (policy_id, revision) DO NOTHING"));

    // An idempotency-key replay (no rows changed) is a typed Conflict.
    let (conflict_store, _conflict_transport) =
        store_with_transport(control_registry(), vec![query_ok(serde_json::json!([]), 0)]);
    let error = conflict_store
        .insert_guardrail_policy_revision(sample_guardrail_revision())
        .unwrap_err();
    assert!(matches!(error, StorageError::Conflict(_)), "{error:?}");
}

#[test]
fn managed_worker_template_upserts_and_lists_from_the_control_database() {
    let template = StoredManagedWorkerTemplate {
        id: "tmpl-1".into(),
        framework_adapter: "langgraph".into(),
        isolation_backend_kind: "firecracker".into(),
        enabled: true,
        max_tenant_sessions: Some(4),
        max_workspace_sessions: None,
        created_at_unix: Some(1_753_000_000),
        updated_at_unix: Some(1_753_000_001),
    };
    let template_doc = serde_json::to_string(&template).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(serde_json::json!([{ "document_json": template_doc }]), 0),
        ],
    );

    runtime()
        .block_on(store.upsert_managed_worker_template(template.clone()))
        .expect("upsert should succeed");
    let templates = runtime().block_on(store.managed_worker_templates());
    assert_eq!(templates, vec![template]);

    let requests = transport.recorded();
    assert!(requests[0].url.contains("/d1/database/control-db/query"));
    let upsert_sql = body_sql(&requests[0]);
    assert!(upsert_sql.starts_with("INSERT INTO managed_worker_templates"));
    assert!(upsert_sql.contains("ON CONFLICT (id) DO UPDATE"));
    assert!(body_sql(&requests[1]).contains("FROM managed_worker_templates"));
}

#[test]
fn self_hosted_worker_registration_round_trips_and_activity_stats_aggregate() {
    let registration = StoredSelfHostedWorkerRegistration {
        id: "worker-1".into(),
        tenant: TenantContext {
            organization_id: Some("acme".into()),
            ..TenantContext::default()
        },
        workspace_id: "ws-1".into(),
        worker_name: "runner".into(),
        status: "active".into(),
        identity_fingerprint: "sha256:abc".into(),
        identity_expires_at_unix: None,
        orchestration_enabled: true,
        registered_at_unix: Some(1_753_000_000),
        last_seen_at_unix: None,
        trust_level: "trusted".into(),
        capability_envelope_json: "{}".into(),
        token_secret: "secret".into(),
    };
    let registration_doc = serde_json::to_string(&registration).unwrap();
    let (store, transport) = store_with_transport(
        control_registry(),
        vec![
            query_ok(serde_json::json!([]), 1),
            query_ok(
                serde_json::json!([{ "document_json": registration_doc }]),
                0,
            ),
            query_ok(
                serde_json::json!([{
                    "telemetry_event_count": 3_i64, "latest_event_at_unix": 1_753_000_500_i64,
                    "artifact_count": 1_i64, "latest_artifact_at_unix": 1_753_000_400_i64,
                    "checkpoint_count": 0_i64, "latest_checkpoint_at_unix": null
                }]),
                0,
            ),
        ],
    );

    runtime()
        .block_on(store.upsert_self_hosted_worker_registration(registration.clone()))
        .expect("upsert should succeed");
    let fetched = runtime()
        .block_on(store.self_hosted_worker_registration("worker-1"))
        .expect("registration should decode");
    assert_eq!(fetched, registration);

    let stats = runtime().block_on(store.self_hosted_worker_activity_stats("worker-1"));
    assert_eq!(stats.telemetry_event_count, 3);
    assert_eq!(stats.latest_event_at_unix, Some(1_753_000_500));
    assert_eq!(stats.artifact_count, 1);
    assert_eq!(stats.checkpoint_count, 0);
    assert_eq!(stats.latest_checkpoint_at_unix, None);

    let requests = transport.recorded();
    assert!(body_sql(&requests[0]).starts_with("INSERT INTO self_hosted_worker_registrations"));
    assert!(body_sql(&requests[1]).contains("WHERE id = ?"));
    let stats_sql = body_sql(&requests[2]);
    assert!(stats_sql.contains("count(*)"));
    assert!(stats_sql.contains("self_hosted_worker_telemetry_events"));
}

// --- Atomic op over the proxy-Worker /d1/batch binding (issue #450) ---

/// The KEYSTONE proof: `append_billing_event_with_outbox_enqueue` constructs the
/// two-statement ATOMIC batch (metering insert + outbox enqueue) and routes it
/// through the proxy Worker's `/d1/batch`, NOT the REST query API.
#[test]
fn append_billing_event_with_outbox_enqueue_builds_atomic_batch() {
    let event = sample_billing_event("req-1");
    let billing_event_id = ferrogate_billing::ledger::ledger_entry_id(&event);
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        // The recorded path takes ONE atomic batch and no REST round trip.
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // Statement 0 (metering insert) RETURNS its id -> newly recorded.
            proxy_statement_result(
                serde_json::json!([{ "billing_event_id": billing_event_id }]),
                1,
            ),
            // Statement 1 (outbox enqueue) inserts a row, no RETURNING.
            proxy_statement_result(serde_json::json!([]), 1),
        ])],
    );

    let outcome = runtime()
        .block_on(store.append_billing_event_with_outbox_enqueue(event.clone(), "outbox-1", 100))
        .expect("atomic append should succeed");
    assert!(
        outcome.recorded,
        "the RETURNING row means the event was recorded"
    );
    assert!(
        outcome.enqueue_error.is_none(),
        "atomic backends never surface a partial enqueue error"
    );

    // The REST transport was never touched: the recorded path is a single atomic
    // batch, exactly the round-trip win the binding buys over REST.
    assert!(
        rest_transport.recorded().is_empty(),
        "the recorded path must not hit the REST query API"
    );

    // Exactly one POST to /d1/batch, bearer-authenticated with the proxy token.
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(
        request.url.ends_with("/d1/batch"),
        "url was {}",
        request.url
    );
    assert_eq!(request.bearer_token, "plaintext-proxy-token");

    // The body is the atomic { statements: [metering, outbox] } envelope.
    let body = body_json(request);
    let statements = body["statements"].as_array().expect("statements array");
    assert_eq!(
        statements.len(),
        2,
        "the atomic unit is exactly two statements"
    );

    // Statement 0: metering insert, ON CONFLICT DO NOTHING, RETURNING (the
    // REST API has none of this — that is why the binding exists).
    let metering_sql = statements[0]["sql"].as_str().unwrap();
    assert!(metering_sql.starts_with("INSERT INTO billing_events"));
    assert!(metering_sql.contains("ON CONFLICT (billing_event_id) DO NOTHING"));
    assert!(metering_sql.contains("RETURNING billing_event_id"));
    let metering_params = statement_params(&statements[0]);
    assert_eq!(metering_params.len(), 5);
    assert_eq!(metering_params[0], billing_event_id);
    assert_eq!(metering_params[1], "req-1");
    assert_eq!(metering_params[2], "0"); // provider_attempt_index bound as a string
    assert_eq!(metering_params[3], "1800000000"); // occurred_at_unix
    assert_eq!(
        serde_json::from_str::<ferrogate_billing::BillingEvent>(&metering_params[4]).unwrap(),
        event,
        "the fifth metering param is the full event_json document"
    );

    // Statement 1: outbox enqueue, ON CONFLICT DO NOTHING, idempotent on id.
    let outbox_sql = statements[1]["sql"].as_str().unwrap();
    assert!(outbox_sql.starts_with("INSERT INTO billing_report_outbox"));
    assert!(outbox_sql.contains("ON CONFLICT (id) DO NOTHING"));
    let outbox_params = statement_params(&statements[1]);
    assert_eq!(outbox_params.len(), 3);
    assert_eq!(outbox_params[0], "outbox-1");
    assert_eq!(outbox_params[1], "100"); // next_attempt_unix
    assert_eq!(
        serde_json::from_str::<ferrogate_billing::BillingEvent>(&outbox_params[2]).unwrap(),
        event,
    );
}

/// On an idempotent replay the metering insert conflicts (no RETURNING row); the
/// op re-verifies the stored settlement over the REST reload path and reports
/// `recorded = false` without erroring.
#[test]
fn append_billing_event_with_outbox_enqueue_replay_verifies_settlement() {
    let event = sample_billing_event("req-1");
    let event_doc = serde_json::to_string(&event).unwrap();
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        // REST reload of the already-recorded event for the settlement compare.
        vec![query_ok(
            serde_json::json!([{ "document_json": event_doc }]),
            0,
        )],
        // Both statements no-op (changes 0, no RETURNING row) -> not recorded.
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0),
        ])],
    );

    let outcome = runtime()
        .block_on(store.append_billing_event_with_outbox_enqueue(event, "outbox-1", 100))
        .expect("idempotent replay should not error");
    assert!(
        !outcome.recorded,
        "a conflicting metering insert is not newly recorded"
    );
    assert!(outcome.enqueue_error.is_none());

    // The atomic batch went to the proxy; the settlement reload went to REST.
    assert_eq!(proxy_transport.recorded().len(), 1);
    let reload = rest_transport.recorded();
    assert_eq!(reload.len(), 1);
    assert!(body_sql(&reload[0]).contains("FROM billing_events WHERE billing_event_id = ?"));
}

/// Without a bound proxy Worker the atomic op fails closed with the typed
/// unimplemented-surface error, exactly like the still-deferred atomic families
/// — and never reaches the network.
#[test]
fn append_billing_event_with_outbox_enqueue_without_proxy_is_unimplemented() {
    let (store, transport) = store_with_transport(control_registry(), Vec::new());
    let error = runtime()
        .block_on(store.append_billing_event_with_outbox_enqueue(
            sample_billing_event("req-1"),
            "outbox-1",
            100,
        ))
        .expect_err("a REST-only backend cannot serve the atomic op");
    assert!(is_unimplemented_backend_surface(&error), "{error:?}");
    assert!(
        transport.recorded().is_empty(),
        "the unimplemented path must not hit the network"
    );
}

// --- Guardrail binding CAS transitions over the proxy /d1/query binding
// (issue #454) ---

fn sample_guardrail_binding(
    active_revision: Option<u32>,
    archived_revisions: Vec<u32>,
    generation: u64,
) -> StoredGuardrailPolicyBinding {
    StoredGuardrailPolicyBinding {
        policy_id: "policy-1".into(),
        active_revision,
        archived_revisions,
        updated_at_unix: 1_753_000_050,
        updated_by: "admin".into(),
        generation,
    }
}

/// The `binding_json` param a CAS statement carries, decoded back into a
/// binding (the read path's `binding_json AS document_json` round trip).
fn statement_binding_json(
    statement: &serde_json::Value,
    index: usize,
) -> StoredGuardrailPolicyBinding {
    let params = statement_params(statement);
    serde_json::from_str(&params[index]).expect("binding_json param should decode")
}

/// A FIRST activation (no prior binding) builds the INSERT-branch guarded CAS
/// (`ON CONFLICT (policy_id) DO NOTHING RETURNING policy_id`) over the proxy
/// `/d1/query` binding, NOT the REST query API, and returns the computed
/// transition when the RETURNING row proves the write landed.
#[test]
fn activate_guardrail_policy_revision_first_activation_builds_insert_cas() {
    let revision_doc = serde_json::to_string(&sample_guardrail_revision()).unwrap();
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        // REST #1: the revision-exists check. REST #2: the no-prior-binding read.
        vec![
            query_ok(serde_json::json!([{ "document_json": revision_doc }]), 0),
            query_ok(serde_json::json!([]), 0),
        ],
        // Proxy: the guarded INSERT returns its policy_id -> the write landed.
        vec![proxy_query_ok(
            serde_json::json!([{ "policy_id": "policy-1" }]),
            1,
        )],
    );

    let transition = store
        .activate_guardrail_policy_revision("policy-1", 1, "admin", 1_753_000_100, false)
        .expect("first activation should land");
    assert!(transition.previous.is_none());
    assert_eq!(transition.current.active_revision, Some(1));
    assert_eq!(transition.current.generation, 1);
    assert!(transition.current.archived_revisions.is_empty());
    assert_eq!(transition.current.updated_by, "admin");

    // The CAS went to the proxy `/d1/query`, never the REST query API.
    let proxy_requests = proxy_transport.recorded();
    assert_eq!(proxy_requests.len(), 1);
    assert!(proxy_requests[0].url.ends_with("/d1/query"));
    assert_eq!(proxy_requests[0].bearer_token, "plaintext-proxy-token");
    let statement = body_json(&proxy_requests[0]);
    let sql = statement["sql"].as_str().unwrap();
    assert!(sql.starts_with("INSERT INTO guardrail_policy_bindings"));
    assert!(sql.contains("ON CONFLICT (policy_id) DO NOTHING"));
    assert!(sql.contains("RETURNING policy_id"));
    let params = statement_params(&statement);
    assert_eq!(params[0], "policy-1");
    assert_eq!(params[1], "1"); // active_revision bound as string, NULLIF-guarded
    assert_eq!(params[3], "1"); // generation
    assert_eq!(
        statement_binding_json(&statement, 4).active_revision,
        Some(1)
    );

    // The two REST calls were the non-atomic reads only (no REST CAS).
    assert_eq!(rest_transport.recorded().len(), 2);
}

/// Activating over an EXISTING binding builds the UPDATE-branch guarded CAS
/// (`WHERE policy_id = ? AND generation = ? RETURNING policy_id`), guarding on
/// the previous generation, and archives the displaced active revision.
#[test]
fn activate_guardrail_policy_revision_over_existing_builds_update_cas() {
    let revision_doc = serde_json::to_string(&sample_guardrail_revision()).unwrap();
    let binding_doc = serde_json::to_string(&sample_guardrail_binding(Some(2), vec![], 3)).unwrap();
    let (store, _rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        vec![
            query_ok(serde_json::json!([{ "document_json": revision_doc }]), 0),
            query_ok(serde_json::json!([{ "document_json": binding_doc }]), 0),
        ],
        vec![proxy_query_ok(
            serde_json::json!([{ "policy_id": "policy-1" }]),
            1,
        )],
    );

    let transition = store
        .activate_guardrail_policy_revision("policy-1", 1, "ops", 1_753_000_200, false)
        .expect("activation over an existing binding should land");
    assert_eq!(transition.previous.map(|b| b.generation), Some(3));
    assert_eq!(transition.current.active_revision, Some(1));
    assert_eq!(transition.current.generation, 4); // previous 3 + 1
    assert_eq!(transition.current.archived_revisions, vec![2]); // displaced active

    let statement = body_json(&proxy_transport.recorded()[0]);
    let sql = statement["sql"].as_str().unwrap();
    assert!(sql.starts_with("UPDATE guardrail_policy_bindings"));
    assert!(sql.contains("WHERE policy_id = ? AND generation = ?"));
    assert!(sql.contains("RETURNING policy_id"));
    let params = statement_params(&statement);
    // [active_revision, updated_at_unix, generation, binding_json, policy_id, expected_gen]
    assert_eq!(params[0], "1");
    assert_eq!(params[2], "4"); // new generation
    assert_eq!(params[4], "policy-1");
    assert_eq!(params[5], "3"); // expected (previous) generation is the CAS guard
}

/// An empty `RETURNING` set is the lost-update signal (the guard missed): it
/// maps to the typed guardrail CAS `Conflict`.
#[test]
fn activate_guardrail_policy_revision_cas_conflict_is_typed() {
    let revision_doc = serde_json::to_string(&sample_guardrail_revision()).unwrap();
    let binding_doc = serde_json::to_string(&sample_guardrail_binding(Some(2), vec![], 3)).unwrap();
    let (store, _rest_transport, _proxy_transport) = store_with_proxy(
        control_registry(),
        vec![
            query_ok(serde_json::json!([{ "document_json": revision_doc }]), 0),
            query_ok(serde_json::json!([{ "document_json": binding_doc }]), 0),
        ],
        // The guarded UPDATE matched no row -> empty RETURNING -> conflict.
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );

    let error = store
        .activate_guardrail_policy_revision("policy-1", 1, "ops", 1_753_000_200, false)
        .expect_err("a lost-update CAS must surface a conflict");
    assert!(
        is_guardrail_policy_binding_cas_conflict(&error),
        "{error:?}"
    );
}

/// Activating an unknown revision is `NotFound` and never reaches the CAS proxy.
#[test]
fn activate_guardrail_policy_revision_missing_revision_is_not_found() {
    let (store, _rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        // The revision-exists check comes back empty.
        vec![query_ok(serde_json::json!([]), 0)],
        Vec::new(),
    );

    let error = store
        .activate_guardrail_policy_revision("policy-1", 9, "ops", 1_753_000_200, false)
        .expect_err("an unknown revision cannot be activated");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(
        proxy_transport.recorded().is_empty(),
        "a missing revision must not reach the CAS proxy"
    );
}

/// Archiving a non-active revision builds the UPDATE-branch guarded CAS and adds
/// the revision to `archived_revisions` while leaving the active one in place.
#[test]
fn archive_guardrail_policy_revision_builds_update_cas() {
    let revision_doc = serde_json::to_string(&sample_guardrail_revision()).unwrap();
    let binding_doc = serde_json::to_string(&sample_guardrail_binding(Some(1), vec![], 2)).unwrap();
    let (store, _rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        vec![
            query_ok(serde_json::json!([{ "document_json": revision_doc }]), 0),
            query_ok(serde_json::json!([{ "document_json": binding_doc }]), 0),
        ],
        vec![proxy_query_ok(
            serde_json::json!([{ "policy_id": "policy-1" }]),
            1,
        )],
    );

    let transition = store
        .archive_guardrail_policy_revision("policy-1", 2, "ops", 1_753_000_300)
        .expect("archiving a non-active revision should land");
    assert_eq!(transition.current.active_revision, Some(1)); // active unchanged
    assert_eq!(transition.current.archived_revisions, vec![2]);
    assert_eq!(transition.current.generation, 3);

    let sql = body_json(&proxy_transport.recorded()[0])["sql"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(sql.starts_with("UPDATE guardrail_policy_bindings"));
    assert!(sql.contains("WHERE policy_id = ? AND generation = ?"));
}

/// Restoring back to "no binding" (rollback of a first activation) builds the
/// DELETE-branch guarded CAS over the proxy; an empty RETURNING set conflicts.
#[test]
fn restore_guardrail_policy_binding_delete_branch_builds_delete_cas() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([{ "policy_id": "policy-1" }]),
            1,
        )],
    );

    store
        .restore_guardrail_policy_binding("policy-1", Some(5), None)
        .expect("delete-branch restore should land");

    // No REST reads: restore is given its target generation directly.
    assert!(rest_transport.recorded().is_empty());
    let statement = body_json(&proxy_transport.recorded()[0]);
    let sql = statement["sql"].as_str().unwrap();
    assert!(sql.starts_with("DELETE FROM guardrail_policy_bindings"));
    assert!(sql.contains("WHERE policy_id = ? AND generation = ?"));
    assert!(sql.contains("RETURNING policy_id"));
    let params = statement_params(&statement);
    assert_eq!(params, vec!["policy-1".to_string(), "5".to_string()]);

    // The same guarded DELETE against a moved generation is a typed conflict.
    let (conflict_store, _rest, _proxy) = store_with_proxy(
        control_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let error = conflict_store
        .restore_guardrail_policy_binding("policy-1", Some(5), None)
        .expect_err("a guard miss must conflict");
    assert!(
        is_guardrail_policy_binding_cas_conflict(&error),
        "{error:?}"
    );
}

/// Restoring a captured binding uses the generation-guarded UPDATE branch under
/// `next_generation(expected)`.
#[test]
fn restore_guardrail_policy_binding_restore_branch_builds_update_cas() {
    let (store, _rest_transport, proxy_transport) = store_with_proxy(
        control_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([{ "policy_id": "policy-1" }]),
            1,
        )],
    );

    let restored = sample_guardrail_binding(Some(1), vec![2], 4);
    store
        .restore_guardrail_policy_binding("policy-1", Some(4), Some(restored))
        .expect("restore-branch should land");

    let statement = body_json(&proxy_transport.recorded()[0]);
    let sql = statement["sql"].as_str().unwrap();
    assert!(sql.starts_with("UPDATE guardrail_policy_bindings"));
    let params = statement_params(&statement);
    // generation is bumped to next(expected) = 5; the guard is the expected 4.
    assert_eq!(params[2], "5");
    assert_eq!(params[5], "4");
    assert_eq!(statement_binding_json(&statement, 3).generation, 5);
}

/// Every guardrail CAS transition fails closed with the typed
/// unimplemented-surface error on a REST-only backend and never hits the
/// network — exactly like the billing keystone without a bound proxy.
#[test]
fn guardrail_cas_without_proxy_is_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(control_registry(), Vec::new());

    let activate = store
        .activate_guardrail_policy_revision("policy-1", 1, "ops", 1, false)
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&activate), "{activate:?}");

    let archive = store
        .archive_guardrail_policy_revision("policy-1", 1, "ops", 1)
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&archive), "{archive:?}");

    let restore = store
        .restore_guardrail_policy_binding("policy-1", Some(1), None)
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&restore), "{restore:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented CAS path must not hit the network"
    );
}

// --- Tenant-scoped wallet family over the proxy binding (issue #455) ---

/// A registry with the control DB plus one PROVISIONED tenant ("acme"), whose
/// derived proxy binding name is `TENANT_DB_ACME`.
fn tenant_registry() -> D1TenantDatabaseRegistry {
    let mut registry = D1TenantDatabaseRegistry::with_control_database("control-db");
    registry
        .tenant_databases
        .insert("acme".to_string(), "tenant-acme-db".to_string());
    registry
}

/// A `wallet_reservations` row shaped as the proxy Worker serializes it (integer
/// affinities as JSON numbers, `settlement_id` as null/string).
fn reservation_row(
    id: &str,
    amount: i64,
    status: &str,
    expires_at: i64,
    settlement_id: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "tenant_id": "acme",
        "amount_credits": amount,
        "status": status,
        "expires_at_unix": expires_at,
        "settlement_id": settlement_id,
        "created_at_unix": 100,
        "updated_at_unix": 100,
    })
}

/// The #455 keystone proof: `reserve_wallet_credits` builds the no-oversell
/// guarded 3-statement atomic batch and routes it onto the TENANT binding
/// (`TENANT_DB_ACME`), never the REST query API and never the control DB.
#[test]
fn reserve_wallet_credits_builds_atomic_batch_on_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // S0 probe: no existing hold for this id.
            proxy_statement_result(serde_json::json!([]), 0),
            // S1 guarded insert: RETURNING id -> the guard admitted the hold.
            proxy_statement_result(serde_json::json!([{ "id": "hold-1" }]), 1),
            // S2 wallet-state (unused on success).
            proxy_statement_result(
                serde_json::json!([{ "balance_credits": 1000, "outstanding_credits": 0 }]),
                0,
            ),
        ])],
    );

    let result = runtime()
        .block_on(store.reserve_wallet_credits("hold-1", "acme", 500, 2000, 100))
        .expect("reserve should succeed");
    match result {
        WalletReservationResult::Reserved(hold) => {
            assert_eq!(hold.id, "hold-1");
            assert_eq!(hold.tenant_id, "acme");
            assert_eq!(hold.amount_credits, 500);
            assert_eq!(hold.status, "active");
            assert_eq!(hold.expires_at_unix, 2000);
        }
        other => panic!("expected Reserved, got {other:?}"),
    }

    assert!(
        rest_transport.recorded().is_empty(),
        "a tenant-scoped wallet op must not touch the REST query API"
    );
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/batch"));
    assert_eq!(requests[0].bearer_token, "plaintext-proxy-token");
    let body = body_json(&requests[0]);
    // The keystone: the atomic batch is selected onto the TENANT binding.
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let statements = body["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 3, "probe + guarded insert + state read");
    // S1 carries the reserve-no-oversell guard translated from Postgres
    // `FOR UPDATE` + SUM(live holds): an available-balance predicate + RETURNING.
    let guard = statements[1]["sql"].as_str().unwrap();
    assert!(guard.starts_with("INSERT INTO wallet_reservations"));
    assert!(guard.contains("<= w.balance_credits - COALESCE("));
    assert!(guard.contains("status = 'active' AND r.expires_at_unix > ?"));
    assert!(guard.contains("ON CONFLICT (id) DO NOTHING"));
    assert!(guard.contains("RETURNING id"));
    let guard_params = statement_params(&statements[1]);
    assert_eq!(guard_params[0], "hold-1");
    assert_eq!(guard_params[1], "acme");
    assert_eq!(guard_params[2], "500");
    assert_eq!(guard_params[3], "2000"); // expires_at_unix
}

/// RETURNING-empty on the guarded insert, with a wallet-state row present, is the
/// insufficient-balance signal → the typed `Insufficient` outcome carrying the
/// computed available balance.
#[test]
fn reserve_wallet_credits_insufficient_is_typed_result() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0), // no existing
            proxy_statement_result(serde_json::json!([]), 0), // guard did NOT admit
            proxy_statement_result(
                serde_json::json!([{ "balance_credits": 300, "outstanding_credits": 100 }]),
                0,
            ),
        ])],
    );

    let result = runtime()
        .block_on(store.reserve_wallet_credits("hold-2", "acme", 500, 2000, 100))
        .expect("insufficient is an Ok outcome, not an error");
    match result {
        WalletReservationResult::Insufficient {
            available_credits,
            requested_credits,
        } => {
            assert_eq!(available_credits, 200); // balance 300 - 100 outstanding
            assert_eq!(requested_credits, 500);
        }
        other => panic!("expected Insufficient, got {other:?}"),
    }
}

/// RETURNING-empty with NO wallet-state row (the tenant never opened a wallet) is
/// the opt-in `NoWallet` outcome, not an error (issue #169 opt-in wallets).
#[test]
fn reserve_wallet_credits_without_wallet_is_no_wallet() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0), // no wallet row
        ])],
    );

    let result = runtime()
        .block_on(store.reserve_wallet_credits("hold-3", "acme", 500, 2000, 100))
        .expect("no wallet is an Ok outcome");
    assert!(matches!(result, WalletReservationResult::NoWallet));
}

/// Re-reserving the same id (the probe hits) returns the existing hold
/// (idempotent), without consuming the guarded-insert path.
#[test]
fn reserve_wallet_credits_idempotent_replay_returns_existing() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(
                serde_json::json!([reservation_row("hold-1", 500, "active", 2000, None)]),
                0,
            ),
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0),
        ])],
    );

    let result = runtime()
        .block_on(store.reserve_wallet_credits("hold-1", "acme", 500, 2000, 100))
        .expect("replay should return the existing hold");
    match result {
        WalletReservationResult::Reserved(hold) => assert_eq!(hold.id, "hold-1"),
        other => panic!("expected Reserved(existing), got {other:?}"),
    }
}

/// `settle_wallet_reservation` locates the holding tenant DB (fan-out read) then
/// captures the hold as one atomic batch — both routed onto the tenant binding.
#[test]
fn settle_wallet_reservation_captures_over_tenant_binding() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            // locate: the fan-out read finds the active hold in acme's DB.
            proxy_query_ok(
                serde_json::json!([reservation_row("hold-1", 500, "active", 5000, None)]),
                0,
            ),
            // capture batch: S0 debit (no RETURNING), S1 ledger RETURNING the
            // post-debit balance, S2 flip active->settled RETURNING the hold.
            proxy_batch_ok(vec![
                proxy_statement_result(serde_json::json!([]), 1),
                proxy_statement_result(serde_json::json!([{ "balance_after_credits": 500 }]), 1),
                proxy_statement_result(
                    serde_json::json!([reservation_row(
                        "hold-1",
                        500,
                        "settled",
                        5000,
                        Some("hold-1")
                    )]),
                    1,
                ),
            ]),
        ],
    );

    let settlement = runtime()
        .block_on(store.settle_wallet_reservation("hold-1", 1000))
        .expect("settle should capture the hold");
    assert!(settlement.newly_applied);
    assert_eq!(settlement.settlement.id, "hold-1");
    assert_eq!(settlement.settlement.delta_credits, -500);
    assert_eq!(settlement.settlement.balance_after_credits, Some(500));
    assert_eq!(settlement.reservation.status, "settled");

    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].url.ends_with("/d1/query"));
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    let capture = body_json(&requests[1]);
    assert!(requests[1].url.ends_with("/d1/batch"));
    assert_eq!(capture["database"], "TENANT_DB_ACME");
    let statements = capture["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 3);
    // The final CAS flips only from the active state (concurrent-settle safe).
    let flip = statements[2]["sql"].as_str().unwrap();
    assert!(flip.contains("SET status = 'settled'"));
    assert!(flip.contains("WHERE id = ? AND status = 'active'"));
    assert!(flip.contains("RETURNING"));
}

/// Replaying an already-settled hold returns the first durable settlement
/// (`newly_applied = false`) — the locate read short-circuits before any batch.
#[test]
fn settle_wallet_reservation_replay_returns_first_settlement() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([reservation_row(
                    "hold-1",
                    500,
                    "settled",
                    5000,
                    Some("hold-1")
                )]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([{
                    "id": "hold-1", "tenant_id": "acme", "delta_credits": -500,
                    "balance_after_credits": 500, "created_at_unix": 100
                }]),
                0,
            ),
        ],
    );

    let settlement = runtime()
        .block_on(store.settle_wallet_reservation("hold-1", 1000))
        .expect("settled replay is not an error");
    assert!(!settlement.newly_applied);
    assert_eq!(settlement.settlement.delta_credits, -500);
    // Two reads (locate + settlement load), NO capture batch.
    assert_eq!(proxy_transport.recorded().len(), 2);
    assert!(proxy_transport.recorded()[1].url.ends_with("/d1/query"));
}

/// `release_wallet_reservation` locates the holding DB then runs the guarded
/// `active -> released` CAS on the tenant binding.
#[test]
fn release_wallet_reservation_cas_over_tenant_binding() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([reservation_row("hold-1", 500, "active", 5000, None)]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([reservation_row("hold-1", 500, "released", 5000, None)]),
                1,
            ),
        ],
    );

    let released = runtime()
        .block_on(store.release_wallet_reservation("hold-1", 1000))
        .expect("release should cancel the hold");
    assert_eq!(released.status, "released");

    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2);
    let cas = body_json(&requests[1]);
    assert_eq!(cas["database"], "TENANT_DB_ACME");
    let sql = cas["sql"].as_str().unwrap();
    assert!(sql.contains("SET status = 'released'"));
    assert!(sql.contains("WHERE id = ? AND status = 'active' RETURNING"));
}

/// Releasing a settled hold is a typed `Conflict` (a captured spend is
/// irreversible) — detected on the locate read, no CAS attempted.
#[test]
fn release_wallet_reservation_on_settled_is_conflict() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([reservation_row(
                "hold-1",
                500,
                "settled",
                5000,
                Some("hold-1")
            )]),
            0,
        )],
    );

    let error = runtime()
        .block_on(store.release_wallet_reservation("hold-1", 1000))
        .expect_err("cannot release a settled hold");
    assert!(matches!(error, StorageError::Conflict(_)), "{error:?}");
    assert_eq!(
        proxy_transport.recorded().len(),
        1,
        "only the locate read ran"
    );
}

/// `upsert_wallet` + `get_wallet` both route to the tenant binding; `dunning`'s
/// SQLite 0/1 affinity decodes back to bool.
#[test]
fn wallet_crud_routes_to_the_tenant_binding() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([]), 1), // upsert
            proxy_query_ok(
                serde_json::json!([{
                    "id": "acme", "tenant_id": "acme", "balance_credits": 1000,
                    "auto_recharge_threshold_credits": null, "auto_recharge_amount_credits": null,
                    "dunning": 0, "created_at_unix": 100, "updated_at_unix": 100
                }]),
                0,
            ),
        ],
    );

    let wallet = StoredWallet {
        id: "acme".into(),
        tenant_id: "acme".into(),
        balance_credits: 1000,
        auto_recharge_threshold_credits: None,
        auto_recharge_amount_credits: None,
        dunning: false,
        created_at_unix: 100,
        updated_at_unix: 100,
    };
    runtime()
        .block_on(store.upsert_wallet(wallet))
        .expect("upsert should route to the tenant DB");
    let loaded = runtime()
        .block_on(store.get_wallet("acme"))
        .expect("get should route")
        .expect("wallet present");
    assert_eq!(loaded.balance_credits, 1000);
    assert!(!loaded.dunning);

    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2);
    let upsert = body_json(&requests[0]);
    assert_eq!(upsert["database"], "TENANT_DB_ACME");
    assert!(upsert["sql"]
        .as_str()
        .unwrap()
        .starts_with("INSERT INTO wallets"));
    assert_eq!(body_json(&requests[1])["database"], "TENANT_DB_ACME");
}

/// `get_wallet` for an UNPROVISIONED tenant is `Ok(None)` (opt-in), and makes no
/// network round trip.
#[test]
fn get_wallet_unprovisioned_tenant_is_none() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let loaded = runtime()
        .block_on(store.get_wallet("ghost"))
        .expect("get on an unprovisioned tenant is not an error");
    assert!(loaded.is_none());
    assert!(
        proxy_transport.recorded().is_empty(),
        "an unprovisioned read makes no round trip"
    );
}

/// Reserving for an UNPROVISIONED tenant (no tenant DB to hold the wallet) is a
/// typed `NotFound` — a database-per-tenant divergence from Postgres's NoWallet.
#[test]
fn reserve_wallet_credits_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.reserve_wallet_credits("hold-1", "ghost", 500, 2000, 100))
        .expect_err("cannot reserve against an unprovisioned tenant");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// Without a bound proxy Worker the whole reserve/settle/release trio fails
/// closed with the typed unimplemented-surface error and never hits the network,
/// exactly like the still-deferred atomic families.
#[test]
fn wallet_atomic_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let reserve = runtime()
        .block_on(store.reserve_wallet_credits("hold-1", "acme", 500, 2000, 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&reserve), "{reserve:?}");

    let settle = runtime()
        .block_on(store.settle_wallet_reservation("hold-1", 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&settle), "{settle:?}");

    let release = runtime()
        .block_on(store.release_wallet_reservation("hold-1", 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&release), "{release:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented wallet path must not hit the network"
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
