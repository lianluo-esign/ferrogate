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
use base64::Engine as _;
use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, D1ProxyClient, EnvTokenResolver,
    HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};

use ferrogate_core::TenantContext;

use crate::control_plane_store::ControlPlaneStore;
use crate::{
    api_key_tenant_context, is_guardrail_policy_binding_cas_conflict,
    is_unimplemented_backend_surface, AssetPromotionTarget, AssetQuotaAdmission, AssetVisibility,
    AssetVisibilityPromotionOutcome, CatchupPolicy, ChannelMoveOutcome, CloudflareD1StorageOptions,
    D1ControlPlaneStore, D1TenantDatabaseRegistry, DeleteProjectOutcome,
    ObservedAgentPresenceTouch, OverlapPolicy, QuotaScopeKind, ReplayDeadLetterOutcome,
    RuntimeStorageRepositories, ScheduleFireOutcome, ScheduleSpecKind, ScheduleTargetKind,
    StorageError, StoredAdminUser, StoredAdminUserRefreshToken, StoredAgentRun,
    StoredAgentRunEvent, StoredAgentSchedule, StoredAgentScheduleFire, StoredApiKey, StoredAsset,
    StoredAssetChannel, StoredAuditEvent, StoredBudgetAlertNotification,
    StoredGuardrailPolicyBinding, StoredGuardrailPolicyRevision, StoredManagedWorkerTemplate,
    StoredPermission, StoredPlan, StoredQuotaPolicy, StoredRequestLog, StoredRetentionPolicy,
    StoredRole, StoredSelfHostedWorkerRegistration, StoredSiteDomain, StoredSsoProviderConfig,
    StoredTenantAccount, StoredTenantRoleBinding, StoredUsageAggregate, StoredWallet, TokenUsage,
    VariantDeleteOutcome, VersionYankOutcome, WalletReservationResult, WorkflowBudgetDebit,
    WorkflowBudgetDimension, WorkflowRunBudgetCaps, D1_TENANT_DATABASE_REGISTRY_ID,
    D1_TENANT_DATABASE_REGISTRY_KIND, WORKFLOW_RUN_BUDGET_ACTIVE, WORKFLOW_RUN_BUDGET_EXHAUSTED,
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
        agent_cost_budget_usd: Some(7.5),
        asset_storage_quota_bytes: Some(1024),
        asset_max_object_bytes: Some(512),
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
                    "monthly_egress_bytes_budget": null, "download_rpm_limit": 30,
                    "asset_max_object_bytes": 512, "agent_cost_budget_usd": 7.5
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
        default_asset_max_object_bytes: Some(2_097_152),
        default_agent_cost_budget_usd: Some(60.0),
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
                    "default_download_rpm_limit": null, "default_asset_max_object_bytes": 2_097_152_i64,
                    "default_agent_cost_budget_usd": 60.0
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
    // The amount param MUST be CAST to INTEGER: D1's proxy binds ALL params as
    // TEXT, and this guard compares the bound `?` against an arithmetic
    // expression (no column affinity), so without the CAST SQLite ranks TEXT
    // above every INTEGER and the no-oversell guard NEVER admits (issue #455).
    assert!(guard.contains("AND CAST(? AS INTEGER) <= w.balance_credits - COALESCE("));
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

// --- Tenant-scoped wallet balance/dunning/list ops (issue #456) ---

/// A registry with the control DB plus TWO provisioned tenants ("acme", "bravo"),
/// used to prove `list_wallets`' cross-tenant fan-out over per-tenant databases.
fn two_tenant_registry() -> D1TenantDatabaseRegistry {
    let mut registry = D1TenantDatabaseRegistry::with_control_database("control-db");
    registry
        .tenant_databases
        .insert("acme".to_string(), "tenant-acme-db".to_string());
    registry
        .tenant_databases
        .insert("bravo".to_string(), "tenant-bravo-db".to_string());
    registry
}

/// A `wallet_settlements` row shaped as the proxy Worker serializes it.
fn settlement_row(id: &str, delta: i64, balance_after: Option<i64>) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "tenant_id": "acme",
        "delta_credits": delta,
        "balance_after_credits": balance_after,
        "created_at_unix": 100,
    })
}

/// A `wallets` row shaped as the proxy Worker serializes it (SQLite integer
/// affinities as JSON numbers; `dunning` as 0/1).
fn wallet_row(tenant: &str, balance: i64) -> serde_json::Value {
    serde_json::json!({
        "id": tenant,
        "tenant_id": tenant,
        "balance_credits": balance,
        "auto_recharge_threshold_credits": null,
        "auto_recharge_amount_credits": null,
        "dunning": 0,
        "created_at_unix": 100,
        "updated_at_unix": 100,
    })
}

/// `settle_wallet_balance` records the debit + ledger row as one atomic batch on
/// the TENANT binding: a guarded wallet debit, the guarded settlement claim
/// reading the post-debit balance, and a read-back — with the delta `CAST` to
/// INTEGER (the #455 numeric-affinity lesson).
#[test]
fn settle_wallet_balance_records_debit_over_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // S0 debit applied (1 change).
            proxy_statement_result(serde_json::json!([]), 1),
            // S1 claim RETURNING the post-debit balance -> this call recorded it.
            proxy_statement_result(serde_json::json!([{ "balance_after_credits": 400 }]), 1),
            // S2 read-back of the durable settlement.
            proxy_statement_result(
                serde_json::json!([settlement_row("pay-1", -600, Some(400))]),
                0,
            ),
        ])],
    );

    let outcome = runtime()
        .block_on(store.settle_wallet_balance("pay-1", "acme", -600, 1000))
        .expect("settle_wallet_balance should record the debit");
    assert!(outcome.newly_applied);
    assert_eq!(outcome.settlement.id, "pay-1");
    assert_eq!(outcome.settlement.delta_credits, -600);
    assert_eq!(outcome.settlement.balance_after_credits, Some(400));

    assert!(
        rest_transport.recorded().is_empty(),
        "a tenant-scoped wallet op must not touch the REST query API"
    );
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/batch"));
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let statements = body["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 3, "debit + settlement claim + read-back");
    // S0: guarded debit, delta CAST to INTEGER (arithmetic against an INTEGER
    // column; D1 binds params as TEXT — the #455 lesson).
    let debit = statements[0]["sql"].as_str().unwrap();
    assert!(debit.contains("balance_credits = balance_credits + CAST(? AS INTEGER)"));
    assert!(debit.contains("NOT EXISTS(SELECT 1 FROM wallet_settlements WHERE id = ?)"));
    // S1: guarded settlement claim reading the post-debit balance, RETURNING the
    // "this call recorded it" signal.
    let claim = statements[1]["sql"].as_str().unwrap();
    assert!(claim.starts_with("INSERT INTO wallet_settlements"));
    assert!(claim.contains("WHERE NOT EXISTS(SELECT 1 FROM wallet_settlements WHERE id = ?)"));
    assert!(claim.contains("ON CONFLICT (id) DO NOTHING"));
    assert!(claim.contains("RETURNING balance_after_credits"));
    // S2: durable read-back for the outcome + replay guard.
    let read = statements[2]["sql"].as_str().unwrap();
    assert!(read.starts_with("SELECT"));
    assert!(read.contains("FROM wallet_settlements WHERE id = ?"));
    // Debit param binding: CAST'd delta, now, tenant, settlement id.
    let debit_params = statement_params(&statements[0]);
    assert_eq!(debit_params, vec!["-600", "1000", "acme", "pay-1"]);
}

/// Replaying a settlement returns the FIRST durable outcome (`newly_applied =
/// false`): the guarded debit + claim both skip, the read-back yields the
/// already-recorded row.
#[test]
fn settle_wallet_balance_replay_returns_first_outcome() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0), // debit skipped
            proxy_statement_result(serde_json::json!([]), 0), // claim inserted nothing
            proxy_statement_result(
                serde_json::json!([settlement_row("pay-1", -600, Some(400))]),
                0,
            ),
        ])],
    );

    let outcome = runtime()
        .block_on(store.settle_wallet_balance("pay-1", "acme", -600, 2000))
        .expect("replay is not an error");
    assert!(!outcome.newly_applied);
    assert_eq!(outcome.settlement.delta_credits, -600);
    assert_eq!(outcome.settlement.balance_after_credits, Some(400));
}

/// A replay whose tenant or amount changed is a typed `Conflict` (mirrors the
/// Postgres/memory settlement-id idempotency guard).
#[test]
fn settle_wallet_balance_replay_changed_amount_is_conflict() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(
                serde_json::json!([settlement_row("pay-1", -600, Some(400))]),
                0,
            ),
        ])],
    );

    let error = runtime()
        .block_on(store.settle_wallet_balance("pay-1", "acme", -700, 2000))
        .expect_err("a changed-amount replay must conflict");
    assert!(matches!(error, StorageError::Conflict(_)), "{error:?}");
}

/// `settle_wallet_balance` on an UNPROVISIONED tenant is a typed `NotFound` (no
/// tenant DB to hold the ledger) — the database-per-tenant divergence from
/// Postgres, which would still record the settlement. No network round trip.
#[test]
fn settle_wallet_balance_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.settle_wallet_balance("pay-1", "ghost", -600, 1000))
        .expect_err("cannot settle against an unprovisioned tenant");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// `adjust_wallet_balance` is one `UPDATE ... RETURNING` on the tenant binding,
/// delta `CAST` to INTEGER; returns the post-update row.
#[test]
fn adjust_wallet_balance_updates_over_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([wallet_row("acme", 1500)]),
            1,
        )],
    );

    let wallet = runtime()
        .block_on(store.adjust_wallet_balance("acme", 500, 2000))
        .expect("adjust should succeed")
        .expect("existing wallet returns Some");
    assert_eq!(wallet.balance_credits, 1500);

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/query"));
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.contains("balance_credits = balance_credits + CAST(? AS INTEGER)"));
    assert!(sql.contains("WHERE tenant_id = ? RETURNING"));
    assert_eq!(body_params(&requests[0]), vec!["500", "2000", "acme"]);
}

/// `adjust_wallet_balance` on a provisioned tenant with NO wallet row is
/// `Ok(None)` (opt-in), not an error — the `UPDATE` matched nothing.
#[test]
fn adjust_wallet_balance_no_wallet_is_none() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let result = runtime()
        .block_on(store.adjust_wallet_balance("acme", 500, 2000))
        .expect("no wallet is not an error");
    assert!(result.is_none());
}

/// `adjust_wallet_balance` on an UNPROVISIONED tenant is `NotFound` (the #455
/// convention), where Postgres returns `Ok(None)`. No round trip.
#[test]
fn adjust_wallet_balance_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.adjust_wallet_balance("ghost", 500, 2000))
        .expect_err("cannot adjust an unprovisioned tenant");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// `set_wallet_dunning` is one `UPDATE` on the tenant binding; the bool binds as
/// SQLite's 0/1 affinity.
#[test]
fn set_wallet_dunning_updates_over_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 1)],
    );

    runtime()
        .block_on(store.set_wallet_dunning("acme", true, 2000))
        .expect("set_wallet_dunning should succeed");

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.starts_with("UPDATE wallets SET dunning = ?"));
    assert!(sql.contains("WHERE tenant_id = ?"));
    // dunning -> "1", then now, then tenant.
    assert_eq!(body_params(&requests[0]), vec!["1", "2000", "acme"]);
}

/// `set_wallet_dunning` on an UNPROVISIONED tenant is `NotFound` (the #455
/// convention), where Postgres is a silent no-op. No round trip.
#[test]
fn set_wallet_dunning_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.set_wallet_dunning("ghost", true, 2000))
        .expect_err("cannot set dunning on an unprovisioned tenant");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// `list_wallets` (cross-tenant) fans out over EVERY provisioned tenant binding —
/// D1 is database-per-tenant, so each tenant's single wallet lives in its own DB
/// — reading each `wallets` table and ordering the union by `tenant_id`.
#[test]
fn list_wallets_fans_out_over_tenant_bindings() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            // Fan-out is registry (BTreeMap) order: acme first, then bravo.
            proxy_query_ok(serde_json::json!([wallet_row("acme", 1000)]), 0),
            proxy_query_ok(serde_json::json!([wallet_row("bravo", 2000)]), 0),
        ],
    );

    let wallets = runtime()
        .block_on(store.list_wallets())
        .expect("list_wallets should fan out");
    assert_eq!(wallets.len(), 2);
    assert_eq!(wallets[0].tenant_id, "acme");
    assert_eq!(wallets[0].balance_credits, 1000);
    assert_eq!(wallets[1].tenant_id, "bravo");
    assert_eq!(wallets[1].balance_credits, 2000);

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(
        requests.len(),
        2,
        "one read per provisioned tenant database"
    );
    // Each read is an unfiltered whole-table scan of the tenant DB's wallets.
    let first = body_json(&requests[0]);
    assert_eq!(first["database"], "TENANT_DB_ACME");
    let first_sql = first["sql"].as_str().unwrap();
    assert!(first_sql.starts_with("SELECT"));
    assert!(first_sql.contains("FROM wallets"));
    assert!(
        !first_sql.contains("WHERE"),
        "cross-tenant list is unfiltered"
    );
    assert_eq!(body_json(&requests[1])["database"], "TENANT_DB_BRAVO");
}

/// `list_wallets` with no provisioned tenants is `Ok(empty)` and makes no round
/// trip (but still requires a bound proxy).
#[test]
fn list_wallets_empty_registry_is_empty() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(control_registry(), Vec::new(), Vec::new());
    let wallets = runtime()
        .block_on(store.list_wallets())
        .expect("empty registry lists no wallets");
    assert!(wallets.is_empty());
    assert!(proxy_transport.recorded().is_empty());
}

/// Without a bound proxy Worker the whole #456 wallet balance/dunning/list op set
/// fails closed with the typed unimplemented-surface error and never hits the
/// network, exactly like the still-deferred atomic families.
#[test]
fn wallet_balance_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let settle = runtime()
        .block_on(store.settle_wallet_balance("pay-1", "acme", -600, 1000))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&settle), "{settle:?}");

    let adjust = runtime()
        .block_on(store.adjust_wallet_balance("acme", 500, 1000))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&adjust), "{adjust:?}");

    let dunning = runtime()
        .block_on(store.set_wallet_dunning("acme", true, 1000))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&dunning), "{dunning:?}");

    let list = runtime()
        .block_on(store.list_wallets())
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list), "{list:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented wallet path must not hit the network"
    );
}

// --- Tenant-scoped usage rollups + persist_usage_aggregate RMW (issue #456) ---

/// A `usage_monthly_rollups` row shaped as the proxy Worker serializes it
/// (integer affinities as JSON numbers, cost_usd as a JSON number).
fn monthly_rollup_row(
    period_month: &str,
    scope_type: &str,
    scope_id: &str,
    total_tokens: i64,
    cost_usd: f64,
) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{period_month}:{scope_type}:{scope_id}"),
        "period_month": period_month,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "prompt_tokens": total_tokens,
        "completion_tokens": 0,
        "total_tokens": total_tokens,
        "cost_usd": cost_usd,
        "request_count": 1,
        "error_count": 0,
        "updated_at_unix": 100,
    })
}

/// A `usage_metadata_rollups` row shaped as the proxy Worker serializes it.
fn metadata_rollup_row(
    period_month: &str,
    organization_id: &str,
    metadata_key: &str,
    metadata_value: &str,
    total_tokens: i64,
) -> serde_json::Value {
    serde_json::json!({
        "id": format!("{period_month}:{organization_id}:{metadata_key}:{metadata_value}"),
        "period_month": period_month,
        "organization_id": organization_id,
        "metadata_key": metadata_key,
        "metadata_value": metadata_value,
        "prompt_tokens": total_tokens,
        "completion_tokens": 0,
        "total_tokens": total_tokens,
        "cost_usd": 0.0,
        "request_count": 1,
        "error_count": 0,
        "updated_at_unix": 100,
    })
}

/// A usage aggregate attributed to `org` (its owning tenant), a project, and a
/// key — the routing/tenant-context inputs `persist_usage_aggregate` uses.
fn sample_usage_aggregate(org: Option<&str>) -> StoredUsageAggregate {
    StoredUsageAggregate {
        id: format!("{}:proj-1:key-1:fast-chat:openai", org.unwrap_or("_")),
        organization_id: org.map(str::to_string),
        project_id: Some("proj-1".into()),
        api_key_id: Some("key-1".into()),
        logical_model: "fast-chat".into(),
        provider: "openai".into(),
        usage: TokenUsage::new(10, 20, 30),
    }
}

/// `persist_usage_aggregate` records the tenant_contexts upsert + the
/// usage_aggregate_rollups REPLACE as ONE atomic `/d1/batch` on the OWNING
/// tenant's binding (routed by organization), mirroring the Postgres transaction.
/// Tokens are stored values (no CAST — the `upsert_wallet` convention); the
/// REPLACE reads them back via `excluded.*`.
#[test]
fn persist_usage_aggregate_writes_context_and_rollup_batch_on_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // S0 tenant_contexts upsert (no RETURNING) + S1 rollup REPLACE.
            proxy_statement_result(serde_json::json!([]), 1),
            proxy_statement_result(serde_json::json!([]), 1),
        ])],
    );

    let aggregate = sample_usage_aggregate(Some("acme"));
    runtime()
        .block_on(store.persist_usage_aggregate(&aggregate))
        .expect("persist should write the durable rollup");

    assert!(
        rest_transport.recorded().is_empty(),
        "a tenant-scoped usage write must not touch the REST query API"
    );
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/batch"));
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let statements = body["statements"].as_array().unwrap();
    assert_eq!(
        statements.len(),
        2,
        "tenant_contexts upsert + rollup REPLACE"
    );

    // S0: tenant_contexts INSERT ... ON CONFLICT DO NOTHING (the
    // upsert_tenant_context_parts half), absent parts stored NULL via NULLIF.
    let context = statements[0]["sql"].as_str().unwrap();
    assert!(context.starts_with("INSERT INTO tenant_contexts"));
    assert!(context.contains("ON CONFLICT (id) DO NOTHING"));
    assert!(context.contains("NULLIF(?, '')"));
    // Deterministic tenant-context id + org/project/api_key parts.
    let context_params = statement_params(&statements[0]);
    assert_eq!(
        context_params,
        vec![
            "org:acme|team:|project:proj-1|workspace:|user:|api_key:key-1",
            "acme",
            "proj-1",
            "key-1",
        ]
    );

    // S1: usage_aggregate_rollups REPLACE (INSERT ... ON CONFLICT DO UPDATE SET
    // ... = excluded ...), the replace_usage_rollup half. Tokens are stored
    // (no CAST); updated_at_unix uses unixepoch() (the Postgres NOW() analogue).
    let rollup = statements[1]["sql"].as_str().unwrap();
    assert!(rollup.starts_with("INSERT INTO usage_aggregate_rollups"));
    assert!(rollup.contains("ON CONFLICT (id) DO UPDATE SET"));
    assert!(rollup.contains("prompt_tokens = excluded.prompt_tokens"));
    assert!(rollup.contains("total_tokens = excluded.total_tokens"));
    assert!(rollup.contains("unixepoch()"));
    assert!(
        !rollup.contains("CAST("),
        "stored token values are affinity-coerced, not summed in an expression"
    );
    let rollup_params = statement_params(&statements[1]);
    assert_eq!(
        rollup_params,
        vec![
            "acme:proj-1:key-1:fast-chat:openai",
            "org:acme|team:|project:proj-1|workspace:|user:|api_key:key-1",
            "fast-chat",
            "openai",
            "10",
            "20",
            "30",
        ]
    );
}

/// An org-less aggregate has no tenant database to route to, so
/// `persist_usage_aggregate` is a typed `NotFound` (the database-per-tenant
/// divergence from Postgres, which records it under a null-org context). No
/// network round trip.
#[test]
fn persist_usage_aggregate_org_less_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.persist_usage_aggregate(&sample_usage_aggregate(None)))
        .expect_err("an org-less aggregate has no tenant DB");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// `persist_usage_aggregate` for an UNPROVISIONED tenant is a typed `NotFound`
/// (no tenant DB) — no network round trip.
#[test]
fn persist_usage_aggregate_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.persist_usage_aggregate(&sample_usage_aggregate(Some("ghost"))))
        .expect_err("an unprovisioned tenant has no D1 database");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy_transport.recorded().is_empty());
}

/// `get_usage_monthly_rollup` fans out over the provisioned tenant bindings (a
/// scope's rollup lives in its owning tenant DB; the signature carries no tenant
/// id) and decodes the first match, mapping the TEXT scope_type back to the enum.
#[test]
fn get_usage_monthly_rollup_fans_out_and_decodes() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([monthly_rollup_row("2026-07", "project", "proj-1", 30, 1.5)]),
            0,
        )],
    );

    let rollup = runtime()
        .block_on(store.get_usage_monthly_rollup(QuotaScopeKind::Project, "proj-1", "2026-07"))
        .expect("get should succeed")
        .expect("row present");
    assert_eq!(rollup.scope_type, QuotaScopeKind::Project);
    assert_eq!(rollup.scope_id, "proj-1");
    assert_eq!(rollup.period_month, "2026-07");
    assert_eq!(rollup.total_tokens, 30);
    assert_eq!(rollup.cost_usd, 1.5);

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(
        requests.len(),
        1,
        "one probe on the single provisioned tenant"
    );
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.contains("FROM usage_monthly_rollups"));
    assert!(sql.contains("WHERE scope_type = ? AND scope_id = ? AND period_month = ?"));
    assert_eq!(
        body_params(&requests[0]),
        vec!["project", "proj-1", "2026-07"]
    );
}

/// `get_usage_monthly_rollup` returns `Ok(None)` when no tenant DB holds the row,
/// after probing EVERY provisioned binding.
#[test]
fn get_usage_monthly_rollup_absent_is_none() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([]), 0),
            proxy_query_ok(serde_json::json!([]), 0),
        ],
    );

    let rollup = runtime()
        .block_on(store.get_usage_monthly_rollup(QuotaScopeKind::Key, "key-9", "2026-07"))
        .expect("get should succeed");
    assert!(rollup.is_none());
    assert_eq!(
        proxy_transport.recorded().len(),
        2,
        "probes both tenant DBs before concluding absent"
    );
}

/// `list_usage_monthly_rollups` fans out over every provisioned tenant DB and
/// re-sorts the union to the Postgres order `period_month DESC, scope_type ASC,
/// scope_id ASC`.
#[test]
fn list_usage_monthly_rollups_fans_out_and_orders() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            // acme DB: two months, scope_type ordering across the union.
            proxy_query_ok(
                serde_json::json!([
                    monthly_rollup_row("2026-06", "tenant", "acme", 5, 0.1),
                    monthly_rollup_row("2026-07", "project", "proj-1", 30, 1.5),
                ]),
                0,
            ),
            // bravo DB: same latest month, a scope_type that sorts before project.
            proxy_query_ok(
                serde_json::json!([monthly_rollup_row("2026-07", "key", "key-1", 7, 0.2)]),
                0,
            ),
        ],
    );

    let rollups = runtime()
        .block_on(store.list_usage_monthly_rollups())
        .expect("list should fan out");
    let ordered: Vec<(String, QuotaScopeKind, String)> = rollups
        .iter()
        .map(|r| (r.period_month.clone(), r.scope_type, r.scope_id.clone()))
        .collect();
    assert_eq!(
        ordered,
        vec![
            // 2026-07 first (period DESC); within it 'key' < 'project' (scope ASC).
            ("2026-07".into(), QuotaScopeKind::Key, "key-1".into()),
            ("2026-07".into(), QuotaScopeKind::Project, "proj-1".into()),
            ("2026-06".into(), QuotaScopeKind::Tenant, "acme".into()),
        ]
    );

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2, "one whole-table read per tenant DB");
    let first_sql = body_json(&requests[0])["sql"].as_str().unwrap().to_string();
    assert!(first_sql.contains("FROM usage_monthly_rollups"));
    assert!(
        !first_sql.contains("WHERE"),
        "cross-tenant list is unfiltered"
    );
}

/// `list_usage_metadata_rollups` with `Some(org)` routes to that org's OWN
/// database, filtering by metadata_key + organization_id and ordering
/// `period_month ASC, metadata_value ASC` (the Postgres scoped read).
#[test]
fn list_usage_metadata_rollups_scoped_routes_to_org_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([metadata_rollup_row(
                "2026-07", "acme", "customer", "cust-a", 30
            ),]),
            0,
        )],
    );

    let rollups = runtime()
        .block_on(store.list_usage_metadata_rollups("customer", Some("acme")))
        .expect("scoped metadata read should route to the org DB");
    assert_eq!(rollups.len(), 1);
    assert_eq!(rollups[0].organization_id, "acme");
    assert_eq!(rollups[0].metadata_value, "cust-a");

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.contains("WHERE metadata_key = ? AND organization_id = ?"));
    assert!(sql.contains("ORDER BY period_month ASC, metadata_value ASC"));
    assert_eq!(body_params(&requests[0]), vec!["customer", "acme"]);
}

/// A `Some(org)` read for an UNPROVISIONED (or empty/legacy) org is `Ok(empty)`
/// with no round trip — the opt-in contract (matching `get_wallet`).
#[test]
fn list_usage_metadata_rollups_unprovisioned_org_is_empty() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let rollups = runtime()
        .block_on(store.list_usage_metadata_rollups("customer", Some("ghost")))
        .expect("unprovisioned org -> empty");
    assert!(rollups.is_empty());

    let empty = runtime()
        .block_on(store.list_usage_metadata_rollups("customer", Some("")))
        .expect("empty/legacy org -> empty");
    assert!(empty.is_empty());
    assert!(proxy_transport.recorded().is_empty());
}

/// `list_usage_metadata_rollups(None)` is the platform-operator global view: it
/// fans out over every provisioned tenant DB (metadata_key filter only) and
/// re-sorts the union to `period_month ASC, metadata_value ASC`.
#[test]
fn list_usage_metadata_rollups_operator_view_fans_out() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([metadata_rollup_row(
                    "2026-07", "acme", "customer", "cust-z", 3
                ),]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([metadata_rollup_row(
                    "2026-07", "bravo", "customer", "cust-a", 9
                ),]),
                0,
            ),
        ],
    );

    let rollups = runtime()
        .block_on(store.list_usage_metadata_rollups("customer", None))
        .expect("operator view should fan out");
    let ordered: Vec<String> = rollups.iter().map(|r| r.metadata_value.clone()).collect();
    // Same month across both DBs -> ordered by metadata_value ASC in the union.
    assert_eq!(ordered, vec!["cust-a", "cust-z"]);

    assert!(rest_transport.recorded().is_empty());
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2, "one read per provisioned tenant DB");
    let sql = body_json(&requests[0])["sql"].as_str().unwrap().to_string();
    assert!(sql.contains("WHERE metadata_key = ?"));
    assert!(
        !sql.contains("organization_id = ?"),
        "the operator view does not filter by org"
    );
    assert_eq!(body_params(&requests[0]), vec!["customer"]);
}

/// Without a bound proxy Worker the whole #456 usage-rollup op set fails closed
/// with the typed unimplemented-surface error and never hits the network.
#[test]
fn usage_rollup_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let persist = runtime()
        .block_on(store.persist_usage_aggregate(&sample_usage_aggregate(Some("acme"))))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&persist), "{persist:?}");

    let get = runtime()
        .block_on(store.get_usage_monthly_rollup(QuotaScopeKind::Tenant, "acme", "2026-07"))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&get), "{get:?}");

    let list = runtime()
        .block_on(store.list_usage_monthly_rollups())
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list), "{list:?}");

    let metadata = runtime()
        .block_on(store.list_usage_metadata_rollups("customer", None))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&metadata), "{metadata:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented usage path must not hit the network"
    );
}

// --- Tenant-scoped assets + channels + retention family (issue #456) ---

/// Base64 the proxy content round trip uses (invariant 4).
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A `StoredAsset` whose inline `content` is always `b"hello"` (5 bytes) but
/// whose declared `size_bytes` is caller-chosen, so the quota guard can be
/// exercised independently of the actual blob.
fn sample_asset(id: &str, tenant: &str, size: u64) -> StoredAsset {
    StoredAsset {
        id: id.to_string(),
        tenant_id: tenant.to_string(),
        project_id: None,
        asset_type: "skill".to_string(),
        name: "greeter".to_string(),
        version: "1.0.0".to_string(),
        content_type: "application/octet-stream".to_string(),
        content_hash: "sha".to_string(),
        size_bytes: size,
        content: b"hello".to_vec(),
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: AssetVisibility::Visible,
        created_at_unix: 100,
        updated_at_unix: 100,
    }
}

/// A `stored_assets` row shaped as the proxy Worker serializes it (integer
/// affinities as JSON numbers, `content` base64, NULLs as JSON null).
#[allow(clippy::too_many_arguments)]
fn asset_row(
    id: &str,
    tenant: &str,
    asset_type: &str,
    name: &str,
    version: &str,
    size: i64,
    content: &[u8],
    yanked: i64,
    visibility: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "tenant_id": tenant,
        "project_id": null,
        "asset_type": asset_type,
        "name": name,
        "version": version,
        "content_type": "application/octet-stream",
        "content_hash": "sha",
        "size_bytes": size,
        "content": b64(content),
        "created_at_unix": 100,
        "updated_at_unix": 100,
        "storage_uri": null,
        "variant": "",
        "yanked": yanked,
        "visibility": visibility,
    })
}

fn channel_row(
    id: &str,
    tenant: &str,
    asset_type: &str,
    name: &str,
    channel: &str,
    version: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "tenant_id": tenant,
        "asset_type": asset_type,
        "name": name,
        "channel": channel,
        "version": version,
        "updated_at_unix": 100,
    })
}

/// A Cloudflare-style proxy error envelope (the shape the Worker emits for a
/// rolled-back D1 execution failure; code 5001 maps to a plain API error).
fn proxy_error(status: u16, code: u32, message: &str) -> HttpResponse {
    response(
        status,
        serde_json::json!({
            "success": false,
            "errors": [{ "code": code, "message": message }],
            "messages": [],
            "result": null
        })
        .to_string(),
    )
}

/// The #456/#455 keystone for assets: `create_asset_within_quota` builds the
/// pre-state + guarded-insert atomic batch onto the TENANT binding, and the
/// quota arithmetic CASTs the size/bound param to INTEGER (the #455 TEXT-vs-
/// INTEGER lesson) so the guard actually admits.
#[test]
fn create_asset_within_quota_admits_with_cast_guard_on_tenant_binding() {
    let (store, rest_transport, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // S0 pre-state: fresh id, no tuple, 100 bytes already used.
            proxy_statement_result(
                serde_json::json!([{ "id_exists": 0, "tuple_exists": 0, "used_bytes": 100 }]),
                0,
            ),
            // S1 guarded insert: RETURNING a row -> admitted.
            proxy_statement_result(serde_json::json!([{ "1": 1 }]), 1),
        ])],
    );

    let admission = runtime()
        .block_on(store.create_asset_within_quota(
            sample_asset("acme:skill:greeter:1.0.0", "acme", 500),
            Some(10_000),
        ))
        .expect("admit under quota");
    assert_eq!(admission, AssetQuotaAdmission::Admitted);

    assert!(
        rest_transport.recorded().is_empty(),
        "a tenant-scoped asset op must not touch the REST query API"
    );
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/batch"));
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let statements = body["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2, "pre-state read + guarded insert");
    let guard = statements[1]["sql"].as_str().unwrap();
    assert!(guard.starts_with("INSERT INTO stored_assets"));
    // The size + bound enter arithmetic against the INTEGER size_bytes column;
    // the proxy binds TEXT, so both MUST be CAST or the guard never admits.
    assert!(guard.contains("+ CAST(? AS INTEGER)"), "{guard}");
    assert!(guard.contains("<= CAST(? AS INTEGER)"), "{guard}");
    // Bare ON CONFLICT DO NOTHING suppresses BOTH unique constraints (#369).
    assert!(guard.contains("ON CONFLICT DO NOTHING"), "{guard}");
    assert!(guard.contains("RETURNING 1"), "{guard}");
    // The inline content round-trips base64 (invariant 4) as insert param #9.
    let params = statement_params(&statements[1]);
    assert_eq!(params[9], b64(b"hello"));
    assert_eq!(params[8], "500", "size_bytes bind");
}

/// A fresh id whose bytes would overshoot the tenant quota is a definitive,
/// pre-write `OverQuota` — nothing inserted.
#[test]
fn create_asset_within_quota_over_quota_is_typed() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(
                serde_json::json!([{ "id_exists": 0, "tuple_exists": 0, "used_bytes": 9_800 }]),
                0,
            ),
            proxy_statement_result(serde_json::json!([]), 0), // guard did NOT admit
        ])],
    );

    let admission = runtime()
        .block_on(store.create_asset_within_quota(
            sample_asset("acme:skill:greeter:1.0.0", "acme", 500),
            Some(10_000),
        ))
        .expect("over-quota is an Ok outcome");
    match admission {
        AssetQuotaAdmission::OverQuota {
            used_bytes,
            attempted_bytes,
            quota_bytes,
        } => {
            assert_eq!(used_bytes, 9_800);
            assert_eq!(attempted_bytes, 500);
            assert_eq!(quota_bytes, 10_000);
        }
        other => panic!("expected OverQuota, got {other:?}"),
    }
}

/// An id/composite that already exists (the #369 dual-unique first-push loser)
/// is a typed `AlreadyExists`, never a raw error, even though the guard did not
/// insert — classified from the pre-state read.
#[test]
fn create_asset_within_quota_existing_is_already_exists() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // tuple already present under a rival id; guard blocks the insert.
            proxy_statement_result(
                serde_json::json!([{ "id_exists": 0, "tuple_exists": 1, "used_bytes": 100 }]),
                0,
            ),
            proxy_statement_result(serde_json::json!([]), 0),
        ])],
    );

    let admission = runtime()
        .block_on(store.create_asset_within_quota(
            sample_asset("acme:skill:greeter:1.0.0", "acme", 500),
            Some(10_000),
        ))
        .expect("already-exists is an Ok outcome");
    assert_eq!(admission, AssetQuotaAdmission::AlreadyExists);
}

/// Defense in depth: even a SURFACED SQLite `UNIQUE constraint failed` (the D1
/// proxy equivalent of Postgres 23505) is mapped to `AlreadyExists`, never a
/// raw `StorageError` the gateway would turn into a 503.
#[test]
fn create_asset_within_quota_surfaced_unique_violation_is_already_exists() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_error(
            502,
            5001,
            "d1 batch failed (rolled back): UNIQUE constraint failed: \
             stored_assets.tenant_id, stored_assets.asset_type",
        )],
    );

    let admission =
        runtime()
            .block_on(store.create_asset_within_quota(
                sample_asset("acme:skill:greeter:1.0.0", "acme", 500),
                None,
            ))
            .expect("a surfaced unique violation is the AlreadyExists loser");
    assert_eq!(admission, AssetQuotaAdmission::AlreadyExists);
}

/// `create_asset_if_absent` is a single guarded `INSERT ... ON CONFLICT DO
/// NOTHING RETURNING id`: a RETURNING row -> `true`; empty -> the idempotent
/// loser `false`.
#[test]
fn create_asset_if_absent_returns_true_then_false() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([{ "id": "acme:skill:greeter:1.0.0" }]), 1),
            proxy_query_ok(serde_json::json!([]), 0),
        ],
    );

    let inserted = runtime()
        .block_on(store.create_asset_if_absent(sample_asset("acme:skill:greeter:1.0.0", "acme", 5)))
        .expect("first push inserts");
    assert!(inserted);
    let loser = runtime()
        .block_on(store.create_asset_if_absent(sample_asset("acme:skill:greeter:1.0.0", "acme", 5)))
        .expect("second push is the idempotent loser");
    assert!(!loser);

    let sql = body_json(&proxy_transport.recorded()[0])["sql"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(sql.contains("ON CONFLICT DO NOTHING"), "{sql}");
    assert!(sql.contains("RETURNING id"), "{sql}");
    assert_eq!(
        body_json(&proxy_transport.recorded()[0])["database"],
        "TENANT_DB_ACME"
    );
}

/// A surfaced UNIQUE violation on `create_asset_if_absent` is the idempotent
/// `Ok(false)` loser, not a raw error.
#[test]
fn create_asset_if_absent_surfaced_unique_violation_is_false() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_error(
            502,
            5001,
            "d1 query failed: UNIQUE constraint failed: stored_assets.tenant_id",
        )],
    );

    let loser = runtime()
        .block_on(store.create_asset_if_absent(sample_asset("acme:skill:greeter:1.0.0", "acme", 5)))
        .expect("surfaced unique violation -> Ok(false)");
    assert!(!loser);
}

/// `get_asset` carries no tenant, so it fans out over the provisioned tenant
/// bindings and decodes the base64 inline content byte-for-byte (invariant 4).
#[test]
fn get_asset_fans_out_and_decodes_inline_content() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            // acme's DB: not here.
            proxy_query_ok(serde_json::json!([]), 0),
            // bravo's DB: found, content base64("hello world").
            proxy_query_ok(
                serde_json::json!([asset_row(
                    "bravo:skill:greeter:1.0.0",
                    "bravo",
                    "skill",
                    "greeter",
                    "1.0.0",
                    11,
                    b"hello world",
                    0,
                    "visible"
                )]),
                0,
            ),
        ],
    );

    let asset = runtime()
        .block_on(store.get_asset("bravo:skill:greeter:1.0.0"))
        .expect("fan-out read")
        .expect("found in bravo's DB");
    assert_eq!(asset.id, "bravo:skill:greeter:1.0.0");
    assert_eq!(asset.content, b"hello world");
    assert_eq!(asset.size_bytes, 11);
    let requests = proxy_transport.recorded();
    assert_eq!(requests.len(), 2, "fan out over acme then bravo");
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    assert_eq!(body_json(&requests[1])["database"], "TENANT_DB_BRAVO");
}

/// `list_assets` routes to the tenant binding and orders `name, version` (the
/// Postgres order) when filtered by asset_type.
#[test]
fn list_assets_routes_to_tenant_binding_and_orders() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([asset_row(
                "acme:skill:greeter:1.0.0",
                "acme",
                "skill",
                "greeter",
                "1.0.0",
                5,
                b"hello",
                0,
                "visible"
            )]),
            0,
        )],
    );

    let assets = runtime()
        .block_on(store.list_assets("acme", Some("skill")))
        .expect("list");
    assert_eq!(assets.len(), 1);
    let request = &proxy_transport.recorded()[0];
    assert_eq!(body_json(request)["database"], "TENANT_DB_ACME");
    let sql = body_sql(request);
    assert!(
        sql.contains("WHERE tenant_id = ? AND asset_type = ?"),
        "{sql}"
    );
    assert!(sql.contains("ORDER BY name ASC, version ASC"), "{sql}");
}

/// `list_withheld_assets` server-side filters to the non-`visible` rows.
#[test]
fn list_withheld_assets_filters_non_visible() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([asset_row(
                "acme:skill:greeter:2.0.0",
                "acme",
                "skill",
                "greeter",
                "2.0.0",
                5,
                b"hello",
                0,
                "pending_scan"
            )]),
            0,
        )],
    );

    let withheld = runtime()
        .block_on(store.list_withheld_assets("acme", None))
        .expect("list withheld");
    assert_eq!(withheld.len(), 1);
    assert_eq!(withheld[0].visibility, AssetVisibility::PendingScan);
    let sql = body_sql(&proxy_transport.recorded()[0]);
    assert!(sql.contains("visibility <> 'visible'"), "{sql}");
}

/// An unprovisioned tenant has no database, so the opt-in list is EMPTY (not an
/// error) and never hits the network.
#[test]
fn list_assets_unprovisioned_tenant_is_empty() {
    let (store, _rest, proxy_transport) =
        store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let assets = runtime()
        .block_on(store.list_assets("ghost", None))
        .expect("unprovisioned -> empty");
    assert!(assets.is_empty());
    assert!(proxy_transport.recorded().is_empty());
}

/// `delete_asset` fans out and reports the change from the binding that held it.
#[test]
fn delete_asset_fans_out_and_reports_change() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([]), 0), // acme: nothing deleted
            proxy_query_ok(serde_json::json!([]), 1), // bravo: one row deleted
        ],
    );
    let deleted = runtime()
        .block_on(store.delete_asset("bravo:skill:greeter:1.0.0"))
        .expect("delete");
    assert!(deleted);
    assert_eq!(proxy_transport.recorded().len(), 2);
}

/// `list_all_assets` fans out over every provisioned tenant DB and re-sorts the
/// union to the Postgres `tenant_id, asset_type, name, version` order.
#[test]
fn list_all_assets_fans_out_and_sorts() {
    let (store, _rest, _proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([asset_row(
                    "acme:skill:zeta:1.0.0",
                    "acme",
                    "skill",
                    "zeta",
                    "1.0.0",
                    5,
                    b"hello",
                    0,
                    "visible"
                )]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([asset_row(
                    "bravo:skill:alpha:1.0.0",
                    "bravo",
                    "skill",
                    "alpha",
                    "1.0.0",
                    5,
                    b"hello",
                    0,
                    "visible"
                )]),
                0,
            ),
        ],
    );
    let all = runtime()
        .block_on(store.list_all_assets())
        .expect("list all");
    assert_eq!(all.len(), 2);
    // acme < bravo by tenant_id, regardless of per-DB fetch order.
    assert_eq!(all[0].tenant_id, "acme");
    assert_eq!(all[1].tenant_id, "bravo");
}

/// The #367 keystone: `move_asset_channel_if_resolvable` builds a single-batch
/// guarded upsert whose resolvability check (`EXISTS(version) AND NOT
/// EXISTS(yanked variant)`) and the channel write share one transaction, so a
/// concurrent yank/delete can never strand the channel. A RETURNING row is the
/// durable move; S0 carries the prior target for audit.
#[test]
fn move_asset_channel_if_resolvable_guards_and_moves() {
    let channel = StoredAssetChannel {
        id: "acme:skill:greeter:stable".to_string(),
        tenant_id: "acme".to_string(),
        asset_type: "skill".to_string(),
        name: "greeter".to_string(),
        channel: "stable".to_string(),
        version: "2.0.0".to_string(),
        updated_at_unix: 200,
    };
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            // S0 prior target: the channel pointed at 1.0.0.
            proxy_statement_result(serde_json::json!([{ "version": "1.0.0" }]), 0),
            // S1 guarded upsert: resolvable -> RETURNING the new version.
            proxy_statement_result(serde_json::json!([{ "version": "2.0.0" }]), 1),
        ])],
    );

    let outcome = runtime()
        .block_on(store.move_asset_channel_if_resolvable(channel))
        .expect("move");
    match outcome {
        ChannelMoveOutcome::Moved { prior_version } => {
            assert_eq!(prior_version.as_deref(), Some("1.0.0"));
        }
        other => panic!("expected Moved, got {other:?}"),
    }
    let body = body_json(&proxy_transport.recorded()[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let guard = body["statements"][1]["sql"].as_str().unwrap();
    assert!(
        guard.contains("WHERE EXISTS(SELECT 1 FROM stored_assets"),
        "{guard}"
    );
    assert!(guard.contains("AND version = ? AND yanked = 1"), "{guard}");
    assert!(guard.contains("RETURNING version"), "{guard}");
}

/// A move whose target version is absent/yanked yields an empty RETURNING set →
/// the typed `TargetNotResolvable`, nothing written.
#[test]
fn move_asset_channel_target_not_resolvable_is_typed() {
    let channel = StoredAssetChannel {
        id: "acme:skill:greeter:stable".to_string(),
        tenant_id: "acme".to_string(),
        asset_type: "skill".to_string(),
        name: "greeter".to_string(),
        channel: "stable".to_string(),
        version: "9.9.9".to_string(),
        updated_at_unix: 200,
    };
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0),
            proxy_statement_result(serde_json::json!([]), 0), // not resolvable
        ])],
    );
    let outcome = runtime()
        .block_on(store.move_asset_channel_if_resolvable(channel))
        .expect("move");
    assert_eq!(outcome, ChannelMoveOutcome::TargetNotResolvable);
}

/// Yanking a channel-referenced version is fail-closed: rejected with
/// `ReferencedByChannel`, classified from the atomic state read.
#[test]
fn set_asset_version_yank_rejected_when_referenced() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(
                serde_json::json!([{ "variant_count": 2, "referenced_count": 1 }]),
                0,
            ),
            proxy_statement_result(serde_json::json!([]), 0), // guard blocked the update
        ])],
    );
    let outcome = runtime()
        .block_on(store.set_asset_version_yank("acme", "skill", "greeter", "1.0.0", true, 300))
        .expect("yank");
    assert_eq!(outcome, VersionYankOutcome::ReferencedByChannel);
}

/// An unreferenced yank applies to every variant; the S1 guard carries the
/// `? = '0'` short-circuit so an UNyank skips the reference check entirely.
#[test]
fn set_asset_version_yank_applies_over_tenant_binding() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(
                serde_json::json!([{ "variant_count": 2, "referenced_count": 0 }]),
                0,
            ),
            proxy_statement_result(serde_json::json!([{ "id": "a" }, { "id": "b" }]), 2),
        ])],
    );
    let outcome = runtime()
        .block_on(store.set_asset_version_yank("acme", "skill", "greeter", "1.0.0", true, 300))
        .expect("yank");
    assert_eq!(outcome, VersionYankOutcome::Applied { variants: 2 });
    let guard = body_json(&proxy_transport.recorded()[0])["statements"][1]["sql"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        guard.contains("? = '0' OR NOT EXISTS(SELECT 1 FROM asset_channels"),
        "{guard}"
    );
}

/// Deleting the LAST resolvable variant of a channel-referenced version is
/// rejected with `BlockedByChannel` (the #367 invariant from the delete side).
#[test]
fn delete_asset_variant_blocked_when_last_resolvable_and_referenced() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(
                serde_json::json!([{
                    "id_present": 1, "other_resolvable": 0, "referenced_count": 1
                }]),
                0,
            ),
            proxy_statement_result(serde_json::json!([]), 0),
        ])],
    );
    let outcome = runtime()
        .block_on(store.delete_asset_variant_if_unreferenced(
            "acme:skill:greeter:1.0.0",
            "acme",
            "skill",
            "greeter",
            "1.0.0",
        ))
        .expect("variant delete");
    assert_eq!(outcome, VariantDeleteOutcome::BlockedByChannel);
}

/// `promote_pending_asset_visibility` locates the holding tenant DB (fan-out
/// probe), then runs the guarded CAS: a RETURNING row is the durable promotion.
#[test]
fn promote_pending_asset_visibility_promotes_over_located_binding() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            // locate probe: found in acme's DB.
            proxy_query_ok(serde_json::json!([{ "id": "acme:skill:greeter:1.0.0" }]), 0),
            // CAS batch: S0 RETURNING the new state, S1 unused.
            proxy_batch_ok(vec![
                proxy_statement_result(serde_json::json!([{ "visibility": "visible" }]), 1),
                proxy_statement_result(serde_json::json!([{ "visibility": "visible" }]), 0),
            ]),
        ],
    );
    let outcome = runtime()
        .block_on(store.promote_pending_asset_visibility(
            "acme:skill:greeter:1.0.0",
            AssetPromotionTarget::Visible,
            400,
        ))
        .expect("promote");
    assert_eq!(
        outcome,
        AssetVisibilityPromotionOutcome::Promoted {
            to: AssetVisibility::Visible
        }
    );
    let cas = body_json(&proxy_transport.recorded()[1]);
    let sql = cas["statements"][0]["sql"].as_str().unwrap();
    assert!(
        sql.contains("WHERE id = ? AND visibility = 'pending_scan'"),
        "{sql}"
    );
    assert!(sql.contains("RETURNING visibility"), "{sql}");
}

/// A promote for an id no provisioned tenant DB holds is `NotFound` (the CAS
/// batch is never issued).
#[test]
fn promote_pending_asset_visibility_absent_is_not_found() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)], // locate probe: not found
    );
    let outcome = runtime()
        .block_on(store.promote_pending_asset_visibility(
            "ghost:skill:x:1.0.0",
            AssetPromotionTarget::Visible,
            400,
        ))
        .expect("promote absent");
    assert_eq!(outcome, AssetVisibilityPromotionOutcome::NotFound);
    assert_eq!(
        proxy_transport.recorded().len(),
        1,
        "only the locate probe, no CAS"
    );
}

/// Fail-closed (#366/#378): a terminal row whose persisted visibility token is
/// unknown resolves to `Quarantined`, never silently downloadable.
#[test]
fn promote_fail_closed_unknown_token_is_quarantined() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([{ "id": "acme:skill:greeter:1.0.0" }]), 0),
            proxy_batch_ok(vec![
                // CAS did not fire (row is terminal, not pending_scan).
                proxy_statement_result(serde_json::json!([]), 0),
                // ... and its persisted token is corrupt/unknown -> Quarantined.
                proxy_statement_result(serde_json::json!([{ "visibility": "corrupted" }]), 0),
            ]),
        ],
    );
    let outcome = runtime()
        .block_on(store.promote_pending_asset_visibility(
            "acme:skill:greeter:1.0.0",
            AssetPromotionTarget::Visible,
            400,
        ))
        .expect("promote terminal");
    assert_eq!(
        outcome,
        AssetVisibilityPromotionOutcome::NotPending {
            current: AssetVisibility::Quarantined
        }
    );
}

/// `list_retention_policies` routes to the tenant binding and orders by scope.
#[test]
fn list_retention_policies_routes_and_orders() {
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([{
                "id": "acme:asset:*",
                "tenant_id": "acme",
                "resource_type": "asset",
                "scope": "*",
                "keep_last_n": 5,
                "max_age_secs": null,
                "min_age_secs": 3600,
                "created_at_unix": 100,
                "updated_at_unix": 100,
            }]),
            0,
        )],
    );
    let policies: Vec<StoredRetentionPolicy> = runtime()
        .block_on(store.list_retention_policies("acme", "asset"))
        .expect("list retention");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].keep_last_n, Some(5));
    assert_eq!(policies[0].max_age_secs, None);
    assert_eq!(policies[0].min_age_secs, 3600);
    let request = &proxy_transport.recorded()[0];
    assert_eq!(body_json(request)["database"], "TENANT_DB_ACME");
    assert!(
        body_sql(request).contains("ORDER BY scope ASC"),
        "{}",
        body_sql(request)
    );
}

/// `upsert_asset_channel` routes to the channel's tenant binding as a
/// move-by-upsert on the id.
#[test]
fn upsert_asset_channel_routes_to_tenant_binding() {
    let channel = StoredAssetChannel {
        id: "acme:skill:greeter:latest".to_string(),
        tenant_id: "acme".to_string(),
        asset_type: "skill".to_string(),
        name: "greeter".to_string(),
        channel: "latest".to_string(),
        version: "1.0.0".to_string(),
        updated_at_unix: 100,
    };
    let (store, _rest, proxy_transport) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 1)],
    );
    runtime()
        .block_on(store.upsert_asset_channel(channel))
        .expect("upsert channel");
    let request = &proxy_transport.recorded()[0];
    assert_eq!(body_json(request)["database"], "TENANT_DB_ACME");
    let sql = body_sql(request);
    assert!(sql.starts_with("INSERT INTO asset_channels"), "{sql}");
    assert!(sql.contains("ON CONFLICT (id) DO UPDATE SET"), "{sql}");
}

/// `list_all_asset_channels` fans out and re-sorts to the Postgres order.
#[test]
fn list_all_asset_channels_fans_out_and_sorts() {
    let (store, _rest, _proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([channel_row(
                    "acme:skill:greeter:latest",
                    "acme",
                    "skill",
                    "greeter",
                    "latest",
                    "1.0.0"
                )]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([channel_row(
                    "bravo:skill:greeter:latest",
                    "bravo",
                    "skill",
                    "greeter",
                    "latest",
                    "2.0.0"
                )]),
                0,
            ),
        ],
    );
    let channels = runtime()
        .block_on(store.list_all_asset_channels())
        .expect("list all channels");
    assert_eq!(channels.len(), 2);
    assert_eq!(channels[0].tenant_id, "acme");
    assert_eq!(channels[1].tenant_id, "bravo");
}

/// Without a bound proxy Worker the whole atomic asset family fails closed with
/// the typed unimplemented-surface error and never touches the network — exactly
/// like the wallet/usage families on a REST-only deployment.
#[test]
fn asset_family_without_proxy_is_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let create =
        runtime()
            .block_on(store.create_asset_within_quota(
                sample_asset("acme:skill:greeter:1.0.0", "acme", 5),
                None,
            ))
            .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&create), "{create:?}");

    let get = runtime()
        .block_on(store.get_asset("acme:skill:greeter:1.0.0"))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&get), "{get:?}");

    let list = runtime()
        .block_on(store.list_assets("acme", None))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list), "{list:?}");

    let mv = runtime()
        .block_on(store.move_asset_channel_if_resolvable(StoredAssetChannel {
            id: "acme:skill:greeter:stable".to_string(),
            tenant_id: "acme".to_string(),
            asset_type: "skill".to_string(),
            name: "greeter".to_string(),
            channel: "stable".to_string(),
            version: "1.0.0".to_string(),
            updated_at_unix: 100,
        }))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&mv), "{mv:?}");

    let promote = runtime()
        .block_on(store.promote_pending_asset_visibility(
            "acme:skill:greeter:1.0.0",
            AssetPromotionTarget::Visible,
            1,
        ))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&promote), "{promote:?}");

    let retention = runtime()
        .block_on(store.list_retention_policies("acme", "asset"))
        .expect_err("no proxy -> unimplemented");
    assert!(
        is_unimplemented_backend_surface(&retention),
        "{retention:?}"
    );

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented asset path must not hit the network"
    );
}

// --- Tenant-scoped workflow-run execution budgets over the proxy binding
// (issue #456/#279) ---

/// A `workflow_run_budgets` row shaped as the proxy Worker serializes it (integer
/// affinities as JSON numbers, absent caps as JSON null). Fixed workflow/run
/// identity; the caps/counters/status vary per scenario.
#[allow(clippy::too_many_arguments)]
fn workflow_budget_row(
    id: &str,
    cost_budget: Option<i64>,
    token_budget: Option<i64>,
    tool_call_budget: Option<i64>,
    deadline: Option<i64>,
    spent_credits: i64,
    spent_tokens: i64,
    spent_tool_calls: i64,
    status: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "workflow_id": "wf",
        "workflow_version": 1,
        "run_id": "run-1",
        "tenant_id": "acme",
        "cost_budget_credits": cost_budget,
        "token_budget": token_budget,
        "tool_call_budget": tool_call_budget,
        "wall_clock_deadline_unix": deadline,
        "spent_credits": spent_credits,
        "spent_tokens": spent_tokens,
        "spent_tool_calls": spent_tool_calls,
        "status": status,
        "created_at_unix": 100,
        "updated_at_unix": 100,
    })
}

/// `open` is an idempotent insert-then-reload as ONE atomic `/d1/batch` routed
/// onto the run's OWNING tenant binding — never the REST query API, never the
/// control DB. Caps ride `NULLIF(?, '')` (stored value, no CAST).
#[test]
fn open_workflow_run_budget_batches_insert_and_reload_on_tenant_binding() {
    let (store, rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 1), // S0 insert
            proxy_statement_result(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    Some(5000),
                    Some(3),
                    None,
                    0,
                    0,
                    0,
                    "active"
                )]),
                0,
            ), // S1 reload
        ])],
    );

    let budget = runtime()
        .block_on(store.open_workflow_run_budget(
            "wf",
            1,
            "run-1",
            "acme",
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(1000),
                token_budget: Some(5000),
                tool_call_budget: Some(3),
                wall_clock_deadline_unix: None,
            },
            100,
        ))
        .expect("open should succeed");
    assert_eq!(budget.id, "wf:1:run-1");
    assert_eq!(budget.cost_budget_credits, Some(1000));
    assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_ACTIVE);

    assert!(
        rest.recorded().is_empty(),
        "a tenant-scoped workflow-budget op must not touch the REST query API"
    );
    let requests = proxy.recorded();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].url.ends_with("/d1/batch"));
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let statements = body["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2, "idempotent insert + reload");
    let insert = statements[0]["sql"].as_str().unwrap();
    assert!(insert.starts_with("INSERT INTO workflow_run_budgets"));
    assert!(insert.contains("ON CONFLICT (id) DO NOTHING"));
    assert!(insert.contains("NULLIF(?, '')"));
    let insert_params = statement_params(&statements[0]);
    assert_eq!(insert_params[0], "wf:1:run-1"); // deterministic id
    assert_eq!(insert_params[5], "1000"); // cost cap
    assert_eq!(insert_params[8], ""); // deadline None -> '' -> SQL NULL
    let reload = statements[1]["sql"].as_str().unwrap();
    assert!(reload.starts_with("SELECT"));
    assert!(reload.contains("FROM workflow_run_budgets WHERE id = ?"));
}

/// Re-opening the same (workflow, run) returns the EXISTING envelope unchanged:
/// the `DO NOTHING` insert is a no-op and the reload yields the pre-existing row,
/// so a later step re-declaring wider caps can never widen an in-flight run.
#[test]
fn open_workflow_run_budget_idempotent_returns_existing_envelope() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_batch_ok(vec![
            proxy_statement_result(serde_json::json!([]), 0), // insert did nothing
            proxy_statement_result(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    250,
                    0,
                    0,
                    "active"
                )]),
                0,
            ),
        ])],
    );

    let budget = runtime()
        .block_on(store.open_workflow_run_budget(
            "wf",
            1,
            "run-1",
            "acme",
            WorkflowRunBudgetCaps {
                cost_budget_credits: Some(9999), // re-declared wider, MUST be ignored
                ..WorkflowRunBudgetCaps::default()
            },
            200,
        ))
        .expect("re-open returns the existing envelope");
    assert_eq!(budget.cost_budget_credits, Some(1000));
    assert_eq!(budget.spent_credits, 250);
}

/// `open` is a tenant-DB WRITE, so an UNPROVISIONED tenant (no DB to insert into)
/// is a typed `NotFound` — the database-per-tenant divergence, offline.
#[test]
fn open_workflow_run_budget_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.open_workflow_run_budget(
            "wf",
            1,
            "run-1",
            "ghost",
            WorkflowRunBudgetCaps::default(),
            100,
        ))
        .expect_err("unprovisioned tenant -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy.recorded().is_empty());
}

/// A fitting debit locates the run's tenant DB, then commits via the guarded
/// increment CAS — both onto the TENANT binding. The keystone: the spend sums and
/// the fit-guard counters are `CAST(? AS INTEGER)` (the #455 numeric lesson), and
/// the guard pins the FULL read-set (status + counters + caps).
#[test]
fn debit_workflow_run_budget_applies_over_tenant_binding() {
    let (store, rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    Some(3),
                    None,
                    0,
                    0,
                    0,
                    "active"
                )]),
                0,
            ), // locate
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    Some(3),
                    None,
                    100,
                    0,
                    1,
                    "active"
                )]),
                1,
            ), // guarded increment RETURNING
        ],
    );

    let result = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", 100, 0, 1, 150))
        .expect("debit should succeed");
    match result {
        WorkflowBudgetDebit::Applied(budget) => {
            assert_eq!(budget.spent_credits, 100);
            assert_eq!(budget.spent_tool_calls, 1);
            assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_ACTIVE);
        }
        other => panic!("expected Applied, got {other:?}"),
    }

    assert!(rest.recorded().is_empty());
    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "locate + guarded increment");
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    assert_eq!(body_json(&requests[1])["database"], "TENANT_DB_ACME");
    let inc = body_sql(&requests[1]);
    assert!(inc.starts_with("UPDATE workflow_run_budgets SET"));
    assert!(inc.contains("spent_credits = spent_credits + CAST(? AS INTEGER)"));
    assert!(inc.contains("WHERE id = ? AND status = 'active'"));
    assert!(inc.contains("AND spent_credits = CAST(? AS INTEGER)"));
    assert!(inc.contains("cost_budget_credits IS CAST(NULLIF(?, '') AS INTEGER)"));
    assert!(inc.contains("RETURNING"));
    // The guarded increment binds the debit amounts first, then the read-snapshot
    // counters it CAS-guards on (all zero at the fresh read).
    let inc_params = body_params(&requests[1]);
    assert_eq!(inc_params[0], "100"); // cost delta
    assert_eq!(inc_params[2], "1"); // tool-call delta
    assert_eq!(inc_params[4], "wf:1:run-1"); // guarded id
    assert_eq!(inc_params[5], "0"); // guarded spent_credits (read snapshot)
}

/// A debit that would breach a capped dimension applies NO spend and flips the
/// run to `exhausted` via the guarded flip CAS (fail-closed). The returned
/// dimension is the first breached one; the counters are unchanged.
#[test]
fn debit_workflow_run_budget_exceeded_flips_to_exhausted() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    950,
                    0,
                    0,
                    "active"
                )]),
                0,
            ), // locate: 950 spent of a 1000 cap
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    950,
                    0,
                    0,
                    "exhausted"
                )]),
                1,
            ), // guarded flip RETURNING: counters UNCHANGED, status exhausted
        ],
    );

    let result = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", 100, 0, 0, 150))
        .expect("exceeded is an Ok outcome, not an error");
    match result {
        WorkflowBudgetDebit::Exceeded { dimension, budget } => {
            assert_eq!(dimension, WorkflowBudgetDimension::Cost);
            assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_EXHAUSTED);
            assert_eq!(budget.spent_credits, 950, "no spend applied on breach");
        }
        other => panic!("expected Exceeded, got {other:?}"),
    }

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "locate + guarded flip");
    let flip = body_sql(&requests[1]);
    assert!(flip.contains("SET status = 'exhausted'"));
    assert!(flip.contains("WHERE id = ? AND status = 'active'"));
    assert!(flip.contains("cost_budget_credits IS CAST(NULLIF(?, '') AS INTEGER)"));
    assert!(flip.contains("RETURNING"));
}

/// An ALREADY-exhausted run rejects the debit from the located read alone — no
/// second write is issued (it never clobbers a concurrent reactivation).
#[test]
fn debit_workflow_run_budget_already_exhausted_returns_exceeded_without_write() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([workflow_budget_row(
                "wf:1:run-1",
                Some(1000),
                None,
                None,
                None,
                500,
                0,
                0,
                "exhausted"
            )]),
            0,
        )],
    );

    let result = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", 1, 0, 0, 150))
        .expect("exhausted is an Ok outcome");
    assert!(matches!(result, WorkflowBudgetDebit::Exceeded { .. }));
    assert_eq!(
        proxy.recorded().len(),
        1,
        "an already-exhausted read returns without a second write"
    );
}

/// The optimistic-CAS keystone: when the guarded increment RETURNS EMPTY (a
/// concurrent debit landed between the read and the update), the impl re-reads the
/// committed state and RE-ISSUES the guarded UPDATE — guarding on the RELOADED
/// counters, never a stale read — so the debit is never lost.
#[test]
fn debit_workflow_run_budget_retries_on_cas_conflict() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    0,
                    0,
                    0,
                    "active"
                )]),
                0,
            ), // locate: spent 0
            proxy_query_ok(serde_json::json!([]), 0), // 1st increment: guard missed
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    100,
                    0,
                    0,
                    "active"
                )]),
                0,
            ), // reload: a racer committed +100
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    None,
                    150,
                    0,
                    0,
                    "active"
                )]),
                1,
            ), // 2nd increment: success (100 + 50)
        ],
    );

    let result = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", 50, 0, 0, 150))
        .expect("debit should succeed after the CAS retry");
    match result {
        WorkflowBudgetDebit::Applied(budget) => assert_eq!(budget.spent_credits, 150),
        other => panic!("expected Applied, got {other:?}"),
    }

    let requests = proxy.recorded();
    assert_eq!(
        requests.len(),
        4,
        "locate + increment(miss) + reload + increment(retry)"
    );
    // The retry's guard binds the RELOADED counter (100), proving the re-read.
    let retry_params = body_params(&requests[3]);
    assert_eq!(retry_params[5], "100");
}

/// A debit against an unknown run id (the id-only fan-out finds nothing) is a
/// typed `NotFound`.
#[test]
fn debit_workflow_run_budget_unknown_is_not_found() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)], // locate: no match on the only tenant
    );
    let error = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:missing", 1, 0, 0, 150))
        .expect_err("unknown run -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
}

/// A negative debit amount is a typed `Conflict` (mirroring Postgres/memory) and
/// never hits the network.
#[test]
fn debit_workflow_run_budget_negative_amount_is_conflict() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", -1, 0, 0, 150))
        .expect_err("negative amount -> Conflict");
    assert!(matches!(error, StorageError::Conflict(_)), "{error:?}");
    assert!(proxy.recorded().is_empty());
}

/// Without a bound proxy Worker the atomic `open`/`debit`/`topup` (+ the id-only
/// `get`) fail closed with the typed unimplemented-surface error and never hit the
/// network, exactly like the still-deferred atomic families.
#[test]
fn workflow_run_budget_atomic_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let open = runtime()
        .block_on(store.open_workflow_run_budget(
            "wf",
            1,
            "run-1",
            "acme",
            WorkflowRunBudgetCaps::default(),
            100,
        ))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&open), "{open:?}");

    let debit = runtime()
        .block_on(store.debit_workflow_run_budget("wf:1:run-1", 1, 0, 0, 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&debit), "{debit:?}");

    let topup = runtime()
        .block_on(store.topup_workflow_run_budget("wf:1:run-1", 1, 0, 0, None, 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&topup), "{topup:?}");

    let get = runtime()
        .block_on(store.get_workflow_run_budget("wf:1:run-1"))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&get), "{get:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented workflow-budget path must not hit the network"
    );
}

/// A top-up locates the run's tenant DB, then raises the caps + extends the
/// deadline + reactivates via the caps-guarded CAS, applying the SHARED
/// `apply_topup` arithmetic (1000 + 500 = 1500; deadline max(500, 900) = 900).
#[test]
fn topup_workflow_run_budget_raises_caps_and_reactivates() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1000),
                    None,
                    None,
                    Some(500),
                    1000,
                    0,
                    0,
                    "exhausted"
                )]),
                0,
            ), // locate
            proxy_query_ok(
                serde_json::json!([workflow_budget_row(
                    "wf:1:run-1",
                    Some(1500),
                    None,
                    None,
                    Some(900),
                    1000,
                    0,
                    0,
                    "active"
                )]),
                1,
            ), // guarded caps write RETURNING
        ],
    );

    let budget = runtime()
        .block_on(store.topup_workflow_run_budget("wf:1:run-1", 500, 0, 0, Some(900), 200))
        .expect("topup should succeed");
    assert_eq!(budget.cost_budget_credits, Some(1500));
    assert_eq!(budget.wall_clock_deadline_unix, Some(900));
    assert_eq!(budget.status, WORKFLOW_RUN_BUDGET_ACTIVE);

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "locate + guarded caps write");
    let write = body_sql(&requests[1]);
    assert!(write.contains("cost_budget_credits = NULLIF(?, '')"));
    assert!(write.contains("status = 'active'"));
    assert!(
        write.contains("WHERE id = ? AND cost_budget_credits IS CAST(NULLIF(?, '') AS INTEGER)")
    );
    // The write binds the RECOMPUTED absolute caps from the shared apply_topup.
    let write_params = body_params(&requests[1]);
    assert_eq!(write_params[0], "1500"); // raised cost cap
    assert_eq!(write_params[3], "900"); // extended deadline
}

/// A top-up against an unknown run id is a typed `NotFound`.
#[test]
fn topup_workflow_run_budget_unknown_is_not_found() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let error = runtime()
        .block_on(store.topup_workflow_run_budget("wf:1:missing", 1, 0, 0, None, 200))
        .expect_err("unknown run -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
}

/// `get` carries only the run id, so it FANS OUT over the provisioned tenant
/// bindings and returns the first match, selected onto the tenant binding.
#[test]
fn get_workflow_run_budget_locates_over_tenant_binding() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([workflow_budget_row(
                "wf:1:run-1",
                Some(1000),
                None,
                None,
                None,
                100,
                0,
                0,
                "active"
            )]),
            0,
        )],
    );
    let budget = runtime()
        .block_on(store.get_workflow_run_budget("wf:1:run-1"))
        .expect("get should succeed")
        .expect("budget present");
    assert_eq!(budget.spent_credits, 100);
    assert_eq!(
        body_json(&proxy.recorded()[0])["database"],
        "TENANT_DB_ACME"
    );
}

/// `get` for an unknown run id (no binding answers) is `Ok(None)`.
#[test]
fn get_workflow_run_budget_missing_is_none() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let budget = runtime()
        .block_on(store.get_workflow_run_budget("wf:1:missing"))
        .expect("get should succeed");
    assert!(budget.is_none());
}

/// `list` carries the tenant id, so it routes straight to that tenant's own DB
/// and orders `created_at_unix DESC, id ASC` to match Postgres.
#[test]
fn list_workflow_run_budgets_routes_to_tenant_binding() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([
                workflow_budget_row(
                    "wf:1:run-2",
                    Some(1000),
                    None,
                    None,
                    None,
                    0,
                    0,
                    0,
                    "active"
                ),
                workflow_budget_row("wf:1:run-1", Some(500), None, None, None, 0, 0, 0, "active"),
            ]),
            0,
        )],
    );
    let budgets = runtime()
        .block_on(store.list_workflow_run_budgets("acme"))
        .expect("list should succeed");
    assert_eq!(budgets.len(), 2);

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 1);
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.contains("WHERE tenant_id = ?"));
    assert!(sql.contains("ORDER BY created_at_unix DESC, id ASC"));
}

/// `list` for an UNPROVISIONED tenant is EMPTY (opt-in read) and makes no round
/// trip — the wallet-family opt-in read contract.
#[test]
fn list_workflow_run_budgets_unprovisioned_is_empty() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let budgets = runtime()
        .block_on(store.list_workflow_run_budgets("ghost"))
        .expect("list on an unprovisioned tenant is not an error");
    assert!(budgets.is_empty());
    assert!(
        proxy.recorded().is_empty(),
        "an unprovisioned list makes no round trip"
    );
}

// --- Tenant-scoped agent schedules + fire ledger (issue #460/#246) ---

/// A cron schedule the store's tenant-DB writes route by `tenant_id`.
fn sample_agent_schedule(
    id: &str,
    tenant: &str,
    workspace: &str,
    name: &str,
) -> StoredAgentSchedule {
    StoredAgentSchedule {
        schedule_id: id.into(),
        tenant_id: tenant.into(),
        workspace_id: workspace.into(),
        name: name.into(),
        enabled: true,
        spec_kind: ScheduleSpecKind::Cron,
        cron_expr: Some("0 2 * * *".into()),
        timezone: "UTC".into(),
        interval_secs: None,
        target_kind: ScheduleTargetKind::SelfHostedDispatch,
        target_json: "{}".into(),
        overlap_policy: OverlapPolicy::Skip,
        catchup_policy: CatchupPolicy::SkipMissed,
        jitter_secs: 0,
        next_fire_at_unix: Some(2000),
        last_fire_at_unix: None,
        created_at_unix: 100,
        updated_at_unix: 100,
        revision: 1,
    }
}

/// An `agent_schedules` row shaped as the proxy Worker serializes it (integer/
/// boolean affinities as JSON numbers, nullable columns as null).
fn schedule_row(
    id: &str,
    tenant: &str,
    workspace: &str,
    name: &str,
    next_fire: i64,
) -> serde_json::Value {
    serde_json::json!({
        "schedule_id": id,
        "tenant_id": tenant,
        "workspace_id": workspace,
        "name": name,
        "enabled": 1,
        "spec_kind": "cron",
        "cron_expr": "0 2 * * *",
        "timezone": "UTC",
        "interval_secs": null,
        "target_kind": "self_hosted_dispatch",
        "target_json": "{}",
        "overlap_policy": "skip",
        "catchup_policy": "skip_missed",
        "jitter_secs": 0,
        "next_fire_at_unix": next_fire,
        "last_fire_at_unix": null,
        "created_at_unix": 100,
        "updated_at_unix": 100,
        "revision": 1,
    })
}

fn sample_fire(fire_id: &str, schedule_id: &str, slot: i64) -> StoredAgentScheduleFire {
    StoredAgentScheduleFire {
        fire_id: fire_id.into(),
        schedule_id: schedule_id.into(),
        scheduled_fire_at_unix: slot,
        fired_at_unix: slot + 1,
        node_id: Some("node-a".into()),
        outcome: ScheduleFireOutcome::Dispatched,
        dispatch_id: Some("disp-1".into()),
        run_id: None,
        detail: None,
    }
}

/// An `agent_schedule_fires` row shaped as the proxy Worker serializes it.
fn fire_row(fire_id: &str, schedule_id: &str, slot: i64) -> serde_json::Value {
    serde_json::json!({
        "fire_id": fire_id,
        "schedule_id": schedule_id,
        "scheduled_fire_at_unix": slot,
        "fired_at_unix": slot + 1,
        "node_id": "node-a",
        "outcome": "dispatched",
        "dispatch_id": "disp-1",
        "run_id": null,
        "detail": null,
    })
}

/// `upsert_agent_schedule` routes the single-statement upsert onto the OWNING
/// tenant binding — never the REST query API, never the control DB. Timestamps/
/// counters are stored values (NO CAST); nullable columns ride `NULLIF(?, '')`.
#[test]
fn upsert_agent_schedule_routes_to_tenant_binding() {
    let (store, rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 1)],
    );

    runtime()
        .block_on(
            store
                .upsert_agent_schedule(sample_agent_schedule("sched-1", "acme", "ws-1", "nightly")),
        )
        .expect("upsert should route to the tenant DB");

    assert!(
        rest.recorded().is_empty(),
        "a tenant-scoped schedule op must not touch the REST query API"
    );
    let requests = proxy.recorded();
    assert_eq!(requests.len(), 1);
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.starts_with("INSERT INTO agent_schedules"));
    assert!(sql.contains("ON CONFLICT (schedule_id) DO UPDATE SET"));
    assert!(
        sql.contains("NULLIF(?, '')"),
        "nullable cols map '' -> NULL"
    );
    assert!(
        !sql.contains("CAST"),
        "no bound param enters an arithmetic expression, so no CAST"
    );
    let params = statement_params(&body);
    assert_eq!(params[0], "sched-1");
    assert_eq!(params[1], "acme");
    assert_eq!(params[4], "1", "enabled -> SQLite 0/1 affinity");
    assert_eq!(params[5], "cron");
    assert_eq!(params[6], "0 2 * * *");
    assert_eq!(params[8], "", "interval_secs None -> '' -> SQL NULL");
    assert_eq!(params[9], "self_hosted_dispatch");
    assert_eq!(params[14], "2000", "next_fire_at_unix");
    assert_eq!(params[15], "", "last_fire_at_unix None -> ''");
}

/// A malformed `target_json` is rejected up front (like Postgres), before any
/// network round trip.
#[test]
fn upsert_agent_schedule_invalid_target_json_is_rejected() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let mut schedule = sample_agent_schedule("sched-1", "acme", "ws-1", "nightly");
    schedule.target_json = "not json{".into();
    let error = runtime()
        .block_on(store.upsert_agent_schedule(schedule))
        .expect_err("invalid target_json must be rejected");
    assert!(matches!(error, StorageError::Runtime(_)), "{error:?}");
    assert!(
        proxy.recorded().is_empty(),
        "validation fails before any round trip"
    );
}

/// `upsert` is a tenant-DB WRITE, so an UNPROVISIONED tenant is a typed
/// `NotFound` (the database-per-tenant divergence), offline.
#[test]
fn upsert_agent_schedule_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error =
        runtime()
            .block_on(store.upsert_agent_schedule(sample_agent_schedule(
                "sched-1", "ghost", "ws-1", "nightly",
            )))
            .expect_err("unprovisioned tenant -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy.recorded().is_empty());
}

/// `get_agent_schedule` carries only an id, so it FANS OUT over the provisioned
/// tenant bindings and returns the first match, decoding the enum/boolean
/// columns back to the `Stored*` shape.
#[test]
fn get_agent_schedule_fans_out_and_decodes() {
    let (store, _rest, proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            // acme has no such schedule; bravo holds it (fan-out is registry order).
            proxy_query_ok(serde_json::json!([]), 0),
            proxy_query_ok(
                serde_json::json!([schedule_row("sched-1", "bravo", "ws-9", "nightly", 2000)]),
                0,
            ),
        ],
    );

    let schedule = runtime()
        .block_on(store.get_agent_schedule("sched-1"))
        .expect("get should fan out")
        .expect("schedule present in a tenant DB");
    assert_eq!(schedule.tenant_id, "bravo");
    assert_eq!(schedule.spec_kind, ScheduleSpecKind::Cron);
    assert_eq!(schedule.target_kind, ScheduleTargetKind::SelfHostedDispatch);
    assert_eq!(schedule.overlap_policy, OverlapPolicy::Skip);
    assert!(schedule.enabled);

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "one locate read per provisioned tenant");
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    assert_eq!(body_json(&requests[1])["database"], "TENANT_DB_BRAVO");
}

/// `get` for an id no provisioned tenant holds is `Ok(None)`.
#[test]
fn get_agent_schedule_unknown_is_none() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let schedule = runtime()
        .block_on(store.get_agent_schedule("ghost"))
        .expect("unknown id is not an error");
    assert!(schedule.is_none());
}

/// `list_agent_schedules` routes to the tenant binding and orders by name; the
/// workspace variant adds the `workspace_id` predicate.
#[test]
fn list_agent_schedules_routes_and_orders() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([schedule_row("s1", "acme", "ws-1", "alpha", 2000)]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([schedule_row("s2", "acme", "ws-2", "beta", 2000)]),
                0,
            ),
        ],
    );

    let all = runtime()
        .block_on(store.list_agent_schedules("acme", None))
        .expect("tenant list should route");
    assert_eq!(all.len(), 1);
    let scoped = runtime()
        .block_on(store.list_agent_schedules("acme", Some("ws-2")))
        .expect("workspace list should route");
    assert_eq!(scoped.len(), 1);

    let requests = proxy.recorded();
    assert_eq!(body_json(&requests[0])["database"], "TENANT_DB_ACME");
    let all_sql = body_sql(&requests[0]);
    assert!(all_sql.contains("WHERE tenant_id = ? ORDER BY name ASC"));
    assert!(
        !all_sql.contains("AND workspace_id = ?"),
        "the unscoped list carries no workspace predicate"
    );
    let scoped_sql = body_sql(&requests[1]);
    assert!(scoped_sql.contains("WHERE tenant_id = ? AND workspace_id = ? ORDER BY name ASC"));
    assert_eq!(body_params(&requests[1]), vec!["acme", "ws-2"]);
}

/// `list_agent_schedules` for an UNPROVISIONED tenant is EMPTY (opt-in read),
/// offline.
#[test]
fn list_agent_schedules_unprovisioned_is_empty() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let listed = runtime()
        .block_on(store.list_agent_schedules("ghost", None))
        .expect("unprovisioned list is not an error");
    assert!(listed.is_empty());
    assert!(proxy.recorded().is_empty());
}

/// `list_all_agent_schedules` fans out over every provisioned tenant DB and
/// re-sorts the union to the Postgres `tenant_id, workspace_id, name` order.
#[test]
fn list_all_agent_schedules_fans_out_and_sorts() {
    let (store, _rest, proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([
                    schedule_row("s2", "acme", "ws-1", "zeta", 2000),
                    schedule_row("s1", "acme", "ws-1", "alpha", 2000),
                ]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([schedule_row("s3", "bravo", "ws-1", "beta", 2000)]),
                0,
            ),
        ],
    );

    let all = runtime()
        .block_on(store.list_all_agent_schedules())
        .expect("list_all should fan out");
    let order: Vec<(&str, &str)> = all
        .iter()
        .map(|s| (s.tenant_id.as_str(), s.name.as_str()))
        .collect();
    assert_eq!(
        order,
        vec![("acme", "alpha"), ("acme", "zeta"), ("bravo", "beta")],
        "union re-sorted by tenant, workspace, name"
    );
    assert_eq!(proxy.recorded().len(), 2, "one read per provisioned tenant");
}

/// `list_due_agent_schedules` fans out with a per-binding `LIMIT`, then re-sorts
/// the union next-fire-ascending and truncates to a GLOBAL `limit` — the same
/// top-`limit` cheapest set Postgres's single-table `ORDER BY ... LIMIT` yields.
#[test]
fn list_due_agent_schedules_fans_out_and_truncates() {
    let (store, _rest, proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([
                    schedule_row("s1", "acme", "ws-1", "a", 120),
                    schedule_row("s3", "acme", "ws-1", "c", 140),
                ]),
                0,
            ),
            proxy_query_ok(
                serde_json::json!([schedule_row("s2", "bravo", "ws-1", "b", 130)]),
                0,
            ),
        ],
    );

    let due = runtime()
        .block_on(store.list_due_agent_schedules(200, 2))
        .expect("due scan should fan out");
    let fires: Vec<i64> = due.iter().map(|s| s.next_fire_at_unix.unwrap()).collect();
    assert_eq!(fires, vec![120, 130], "cheapest two across the union");

    let sql = body_sql(&proxy.recorded()[0]);
    assert!(sql.contains("WHERE enabled = 1 AND next_fire_at_unix IS NOT NULL"));
    assert!(sql.contains("next_fire_at_unix <= ? ORDER BY next_fire_at_unix ASC LIMIT 2"));
    assert!(
        !sql.contains("CAST"),
        "column-vs-param compare needs no CAST"
    );
}

/// `delete_agent_schedule` locates the holding tenant DB, then deletes the fire
/// rows AND the schedule as ONE atomic batch (replacing the Postgres
/// `ON DELETE CASCADE` the FK-free D1 dialect drops). `RETURNING` reports it
/// existed.
#[test]
fn delete_agent_schedule_cascades_fires_over_located_binding() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            // Locate: acme holds the schedule.
            proxy_query_ok(
                serde_json::json!([schedule_row("sched-1", "acme", "ws-1", "nightly", 2000)]),
                0,
            ),
            // Delete batch: S0 fires delete (no RETURNING), S1 schedule delete
            // RETURNING the id it removed.
            proxy_batch_ok(vec![
                proxy_statement_result(serde_json::json!([]), 3),
                proxy_statement_result(serde_json::json!([{ "schedule_id": "sched-1" }]), 1),
            ]),
        ],
    );

    let deleted = runtime()
        .block_on(store.delete_agent_schedule("sched-1"))
        .expect("delete should succeed");
    assert!(deleted, "RETURNING a row means the schedule existed");

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "locate + delete batch");
    assert!(requests[0].url.ends_with("/d1/query"));
    assert!(requests[1].url.ends_with("/d1/batch"));
    let batch = body_json(&requests[1]);
    assert_eq!(batch["database"], "TENANT_DB_ACME");
    let statements = batch["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2, "cascade fires + delete schedule");
    assert!(statements[0]["sql"]
        .as_str()
        .unwrap()
        .starts_with("DELETE FROM agent_schedule_fires WHERE schedule_id = ?"));
    let schedule_delete = statements[1]["sql"].as_str().unwrap();
    assert!(schedule_delete.starts_with("DELETE FROM agent_schedules WHERE schedule_id = ?"));
    assert!(schedule_delete.contains("RETURNING schedule_id"));
}

/// `delete` for an id no tenant holds is `Ok(false)` (the fan-out found nothing).
#[test]
fn delete_agent_schedule_unknown_is_false() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let deleted = runtime()
        .block_on(store.delete_agent_schedule("ghost"))
        .expect("unknown delete is not an error");
    assert!(!deleted);
}

/// `insert_agent_schedule_fire` locates the schedule's tenant DB, then runs the
/// at-most-once `ON CONFLICT DO NOTHING RETURNING` gate: a RETURNING row means
/// THIS caller won the slot (`true`).
#[test]
fn insert_agent_schedule_fire_locates_and_wins_slot() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            // Locate the schedule.
            proxy_query_ok(
                serde_json::json!([schedule_row("sched-1", "acme", "ws-1", "nightly", 2000)]),
                0,
            ),
            // Guarded insert RETURNING the fire id -> won the slot.
            proxy_query_ok(serde_json::json!([{ "fire_id": "fire-1" }]), 1),
        ],
    );

    let won = runtime()
        .block_on(store.insert_agent_schedule_fire(sample_fire("fire-1", "sched-1", 1500)))
        .expect("insert fire should succeed");
    assert!(won, "RETURNING a row means this caller recorded the slot");

    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "locate + guarded insert");
    let insert = body_json(&requests[1]);
    assert_eq!(insert["database"], "TENANT_DB_ACME");
    let sql = insert["sql"].as_str().unwrap();
    assert!(sql.starts_with("INSERT INTO agent_schedule_fires"));
    assert!(sql.contains("ON CONFLICT (schedule_id, scheduled_fire_at_unix) DO NOTHING"));
    assert!(sql.contains("RETURNING fire_id"));
    assert!(!sql.contains("CAST"), "no arithmetic on a bound param");
    let params = statement_params(&insert);
    assert_eq!(params[0], "fire-1");
    assert_eq!(params[1], "sched-1");
    assert_eq!(params[2], "1500", "scheduled_fire_at_unix");
    assert_eq!(params[4], "node-a");
    assert_eq!(params[5], "dispatched");
    assert_eq!(params[7], "", "run_id None -> '' -> SQL NULL");
}

/// A losing racer (the slot already recorded) gets an EMPTY `RETURNING` -> the
/// idempotent `false`, so the slot never double-fires.
#[test]
fn insert_agent_schedule_fire_conflict_is_false() {
    let (store, _rest, _proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(
                serde_json::json!([schedule_row("sched-1", "acme", "ws-1", "nightly", 2000)]),
                0,
            ),
            proxy_query_ok(serde_json::json!([]), 0), // DO NOTHING -> no RETURNING row
        ],
    );

    let won = runtime()
        .block_on(store.insert_agent_schedule_fire(sample_fire("fire-1", "sched-1", 1500)))
        .expect("a conflict is an Ok(false), not an error");
    assert!(!won, "a concurrent instance already recorded the slot");
}

/// A fire for an unknown schedule is `NotFound` (no tenant DB to route it into —
/// the write divergence), after the locate fan-out finds nothing.
#[test]
fn insert_agent_schedule_fire_unknown_schedule_is_not_found() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 0)],
    );
    let error = runtime()
        .block_on(store.insert_agent_schedule_fire(sample_fire("fire-1", "ghost", 1500)))
        .expect_err("unknown schedule -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert_eq!(proxy.recorded().len(), 1, "locate only, no insert");
}

/// `list_agent_schedule_fires` fans out and re-merges to the Postgres
/// `scheduled_fire_at_unix DESC` order, truncated to `limit`.
#[test]
fn list_agent_schedule_fires_fans_out_and_orders() {
    let (store, _rest, proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            // acme holds this schedule's fires; bravo has none.
            proxy_query_ok(
                serde_json::json!([
                    fire_row("f2", "sched-1", 200),
                    fire_row("f1", "sched-1", 100),
                ]),
                0,
            ),
            proxy_query_ok(serde_json::json!([]), 0),
        ],
    );

    let fires = runtime()
        .block_on(store.list_agent_schedule_fires("sched-1", 10))
        .expect("list fires should fan out");
    let slots: Vec<i64> = fires.iter().map(|f| f.scheduled_fire_at_unix).collect();
    assert_eq!(slots, vec![200, 100], "newest slot first");
    assert_eq!(fires[0].outcome, ScheduleFireOutcome::Dispatched);

    let sql = body_sql(&proxy.recorded()[0]);
    assert!(sql.contains("WHERE schedule_id = ? ORDER BY scheduled_fire_at_unix DESC LIMIT 10"));
}

/// Without a bound proxy Worker the whole agent-schedule family fails closed with
/// the typed unimplemented-surface error and never hits the network.
#[test]
fn agent_schedule_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let upsert = runtime()
        .block_on(store.upsert_agent_schedule(sample_agent_schedule("s1", "acme", "ws-1", "n")))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&upsert), "{upsert:?}");

    let get = runtime()
        .block_on(store.get_agent_schedule("s1"))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&get), "{get:?}");

    let list = runtime()
        .block_on(store.list_agent_schedules("acme", None))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list), "{list:?}");

    let list_all = runtime()
        .block_on(store.list_all_agent_schedules())
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list_all), "{list_all:?}");

    let due = runtime()
        .block_on(store.list_due_agent_schedules(100, 10))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&due), "{due:?}");

    let delete = runtime()
        .block_on(store.delete_agent_schedule("s1"))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&delete), "{delete:?}");

    let fire = runtime()
        .block_on(store.insert_agent_schedule_fire(sample_fire("f1", "s1", 100)))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&fire), "{fire:?}");

    let fires = runtime()
        .block_on(store.list_agent_schedule_fires("s1", 10))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&fires), "{fires:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented schedule path must not hit the network"
    );
}

// --- Tenant-scoped observed-agent presence (issue #460/#357) ---

/// An `observed_agent_presence` row shaped as the proxy Worker serializes it.
fn presence_row(tenant: &str, api_key: &str, last_seen: i64, count: i64) -> serde_json::Value {
    serde_json::json!({
        "tenant_id": tenant,
        "api_key_id": api_key,
        "first_seen_at_unix": 100,
        "last_seen_at_unix": last_seen,
        "request_count": count,
        "updated_at_unix": last_seen,
    })
}

/// `touch_observed_agent_presence` routes the coalesced conditional upsert onto
/// the tenant binding using SQLite's scalar `max`/`min` (NOT GREATEST/LEAST) over
/// the `excluded.*` columns + `request_count += excluded.request_count` — and
/// needs NO CAST (excluded columns already carry INTEGER affinity).
#[test]
fn touch_observed_agent_presence_coalesces_over_tenant_binding() {
    let (store, rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(serde_json::json!([]), 1)],
    );

    runtime()
        .block_on(
            store.touch_observed_agent_presence(ObservedAgentPresenceTouch {
                tenant_id: "acme".into(),
                api_key_id: "vk-1".into(),
                seen_at_unix: 500,
            }),
        )
        .expect("touch should route to the tenant DB");

    assert!(rest.recorded().is_empty());
    let requests = proxy.recorded();
    assert_eq!(requests.len(), 1);
    let body = body_json(&requests[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.starts_with("INSERT INTO observed_agent_presence"));
    assert!(sql.contains("ON CONFLICT (tenant_id, api_key_id) DO UPDATE SET"));
    assert!(
        sql.contains("max(observed_agent_presence.last_seen_at_unix, excluded.last_seen_at_unix)")
    );
    assert!(sql
        .contains("min(observed_agent_presence.first_seen_at_unix, excluded.first_seen_at_unix)"));
    assert!(sql.contains(
        "request_count = observed_agent_presence.request_count + excluded.request_count"
    ));
    assert!(!sql.contains("GREATEST"), "SQLite has no GREATEST");
    assert!(!sql.contains("LEAST"), "SQLite has no LEAST");
    assert!(
        !sql.contains("CAST"),
        "excluded columns already INTEGER-affinity"
    );
    // VALUES seeds first=last=updated=seen, request_count literal 1.
    let params = statement_params(&body);
    assert_eq!(params, vec!["acme", "vk-1", "500", "500", "500"]);
}

/// A re-touch of the SAME key issues the SAME single-row coalescing upsert onto
/// the same tenant binding (the durable max/min/+ merge is proven live) — never a
/// second row, never a REST/control-DB write.
#[test]
fn touch_observed_agent_presence_retouch_repeats_coalescing_upsert() {
    let (store, rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([]), 1),
            proxy_query_ok(serde_json::json!([]), 1),
        ],
    );

    for seen in [500, 400] {
        runtime()
            .block_on(
                store.touch_observed_agent_presence(ObservedAgentPresenceTouch {
                    tenant_id: "acme".into(),
                    api_key_id: "vk-1".into(),
                    seen_at_unix: seen,
                }),
            )
            .expect("touch should route");
    }

    assert!(rest.recorded().is_empty());
    let requests = proxy.recorded();
    assert_eq!(requests.len(), 2, "each touch is one upsert");
    for request in &requests {
        let body = body_json(request);
        assert_eq!(body["database"], "TENANT_DB_ACME");
        assert!(body["sql"]
            .as_str()
            .unwrap()
            .starts_with("INSERT INTO observed_agent_presence"));
    }
    // The delayed (older) touch still binds its own timestamp; the durable
    // max/min keeps last-seen monotonic (asserted in the live probe).
    assert_eq!(statement_params(&body_json(&requests[1]))[2], "400");
}

/// `touch` on an UNPROVISIONED tenant is a typed `NotFound` (the write
/// divergence), offline.
#[test]
fn touch_observed_agent_presence_unprovisioned_tenant_is_not_found() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let error = runtime()
        .block_on(
            store.touch_observed_agent_presence(ObservedAgentPresenceTouch {
                tenant_id: "ghost".into(),
                api_key_id: "vk-1".into(),
                seen_at_unix: 500,
            }),
        )
        .expect_err("unprovisioned tenant -> NotFound");
    assert!(matches!(error, StorageError::NotFound(_)), "{error:?}");
    assert!(proxy.recorded().is_empty());
}

/// `list_observed_agent_presence_since(Some(tenant), ...)` routes the window read
/// to that tenant's binding with the tenant-scoped ORDER BY.
#[test]
fn list_observed_agent_presence_since_scoped_routes_to_tenant() {
    let (store, _rest, proxy) = store_with_proxy(
        tenant_registry(),
        Vec::new(),
        vec![proxy_query_ok(
            serde_json::json!([
                presence_row("acme", "vk-2", 300, 5),
                presence_row("acme", "vk-1", 200, 3),
            ]),
            0,
        )],
    );

    let rows = runtime()
        .block_on(store.list_observed_agent_presence_since(Some("acme"), 150))
        .expect("scoped window read should route");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].api_key_id, "vk-2");
    assert_eq!(rows[0].request_count, 5);

    let body = body_json(&proxy.recorded()[0]);
    assert_eq!(body["database"], "TENANT_DB_ACME");
    let sql = body["sql"].as_str().unwrap();
    assert!(sql.contains("WHERE tenant_id = ? AND last_seen_at_unix >= ?"));
    assert!(sql.contains("ORDER BY last_seen_at_unix DESC, api_key_id ASC"));
    assert!(
        !sql.contains("CAST"),
        "column-vs-param compare needs no CAST"
    );
    assert_eq!(body_params(&proxy.recorded()[0]), vec!["acme", "150"]);
}

/// A scoped window read for an UNPROVISIONED org is EMPTY (opt-in), offline.
#[test]
fn list_observed_agent_presence_since_scoped_unprovisioned_is_empty() {
    let (store, _rest, proxy) = store_with_proxy(tenant_registry(), Vec::new(), Vec::new());
    let rows = runtime()
        .block_on(store.list_observed_agent_presence_since(Some("ghost"), 150))
        .expect("unprovisioned scoped read is not an error");
    assert!(rows.is_empty());
    assert!(proxy.recorded().is_empty());
}

/// The operator `None` view FANS OUT over every provisioned tenant DB and
/// re-sorts the union to the Postgres `last_seen DESC, tenant ASC, api_key ASC`.
#[test]
fn list_observed_agent_presence_since_operator_view_fans_out() {
    let (store, _rest, proxy) = store_with_proxy(
        two_tenant_registry(),
        Vec::new(),
        vec![
            proxy_query_ok(serde_json::json!([presence_row("acme", "vk-1", 300, 2)]), 0),
            proxy_query_ok(
                serde_json::json!([presence_row("bravo", "vk-9", 500, 4)]),
                0,
            ),
        ],
    );

    let rows = runtime()
        .block_on(store.list_observed_agent_presence_since(None, 100))
        .expect("operator view should fan out");
    let order: Vec<(&str, i64)> = rows
        .iter()
        .map(|r| (r.tenant_id.as_str(), r.last_seen_at_unix))
        .collect();
    assert_eq!(
        order,
        vec![("bravo", 500), ("acme", 300)],
        "newest last-seen first across the cross-tenant union"
    );
    assert_eq!(proxy.recorded().len(), 2, "one read per provisioned tenant");
    let sql = body_sql(&proxy.recorded()[0]);
    assert!(sql.contains("WHERE last_seen_at_unix >= ?"));
    assert!(sql.contains("ORDER BY last_seen_at_unix DESC, tenant_id ASC, api_key_id ASC"));
}

/// Without a bound proxy Worker the observed-presence ops fail closed with the
/// typed unimplemented-surface error and never hit the network.
#[test]
fn observed_presence_ops_without_proxy_are_unimplemented_and_offline() {
    let (store, transport) = store_with_transport(tenant_registry(), Vec::new());

    let touch = runtime()
        .block_on(
            store.touch_observed_agent_presence(ObservedAgentPresenceTouch {
                tenant_id: "acme".into(),
                api_key_id: "vk-1".into(),
                seen_at_unix: 500,
            }),
        )
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&touch), "{touch:?}");

    let list = runtime()
        .block_on(store.list_observed_agent_presence_since(None, 100))
        .expect_err("no proxy -> unimplemented");
    assert!(is_unimplemented_backend_surface(&list), "{list:?}");

    assert!(
        transport.recorded().is_empty(),
        "the unimplemented presence path must not hit the network"
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

    /// The tenant-scoped `workflow_run_budgets` ledger (issue #456/#279) exposes
    /// EXACTLY the columns its Postgres table does, so the same open/debit/topup
    /// arithmetic compiles against either dialect's row shape.
    #[test]
    fn workflow_run_budgets_columns_match_between_postgres_and_d1() {
        let postgres = columns(POSTGRES_SQL);
        let d1 = columns(D1_SQL);
        let postgres_columns = postgres
            .get("workflow_run_budgets")
            .expect("postgres migration should define workflow_run_budgets");
        let d1_columns = d1
            .get("workflow_run_budgets")
            .expect("d1 migration should define workflow_run_budgets");
        assert_eq!(
            postgres_columns, d1_columns,
            "column set of workflow_run_budgets diverged between the Postgres and D1 dialects"
        );
    }

    /// The tenant-scoped agent-schedule families (issue #460/#246) expose EXACTLY
    /// the columns their Postgres tables do, so the same upsert/read/fire SQL
    /// compiles against either dialect's row shape.
    #[test]
    fn agent_schedule_columns_match_between_postgres_and_d1() {
        let postgres = columns(POSTGRES_SQL);
        let d1 = columns(D1_SQL);
        for table in [
            "agent_schedules",
            "agent_schedule_fires",
            "observed_agent_presence",
        ] {
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

    /// Issue #517: the membership `role` column is a PRIVILEGE TIER (it picks
    /// the scopes a console session's gateway key is minted with), so both
    /// dialects must constrain it to the same four values. The D1 twin shipped
    /// with no CHECK at all, which meant the column accepted anything on that
    /// backend.
    #[test]
    fn membership_role_domain_matches_between_postgres_and_d1() {
        const DOMAIN: &str =
            "role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer'))";
        for (dialect, sql) in [("postgres", POSTGRES_SQL), ("d1", D1_SQL)] {
            let table = sql
                .split("CREATE TABLE IF NOT EXISTS admin_user_tenant_memberships")
                .nth(1)
                .unwrap_or_else(|| {
                    panic!("{dialect} migration should define admin_user_tenant_memberships")
                })
                .split(");")
                .next()
                .unwrap();
            assert!(
                table.contains(DOMAIN),
                "{dialect} admin_user_tenant_memberships.role must be constrained to the four \
                 membership tiers; got:{table}"
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
