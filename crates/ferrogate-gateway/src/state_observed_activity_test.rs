// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: End-to-end wiring proof (#357) for the durable observed-agent
// presence path on the in-memory backend: recording an unattributed
// virtual-API-key request via `record_request_log` folds a durable presence
// touch that the observed-agent-activity derivation then reads back as a
// running Unknown row (durable_presence_backed = true). Proves the loop the
// pure-derivation tests cannot: hot-path touch -> durable store -> read.

use super::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, D1ProxyClient, EnvTokenResolver,
    HttpRequest, HttpResponse, HttpTransport, RetryPolicy,
};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    D1ControlPlaneStore, D1TenantDatabaseRegistry, RuntimeStorageRepositories, StoredRequestLog,
};

const PRIVATE_BACKEND_DIAGNOSTIC: &str =
    "connect failed: https://account-secret.example/db/tenant-private-uuid";
const PRIVATE_PROXY_BASE: &str = "https://account-secret.example/d1";

struct ImmediateClock;

#[async_trait]
impl Clock for ImmediateClock {
    async fn sleep(&self, _duration: Duration) {}
}

struct FailingPresenceTransport {
    request_log_json: String,
    presence_read_attempts: AtomicUsize,
}

impl FailingPresenceTransport {
    fn new(request_log: &StoredRequestLog) -> Self {
        Self {
            request_log_json: serde_json::to_string(request_log).expect("serialize request log"),
            presence_read_attempts: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl HttpTransport for FailingPresenceTransport {
    async fn execute(
        &self,
        request: HttpRequest,
    ) -> Result<ferrogate_cloudflare::HttpResponse, CloudflareError> {
        let body: serde_json::Value = request
            .body
            .as_deref()
            .and_then(|body| serde_json::from_slice(body).ok())
            .unwrap_or(serde_json::Value::Null);
        let sql = body
            .get("sql")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let is_presence_window_read = request.url.starts_with(PRIVATE_PROXY_BASE)
            && sql.contains("FROM observed_agent_presence")
            && sql.contains("last_seen_at_unix >= ?");
        if is_presence_window_read {
            self.presence_read_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(CloudflareError::Transport(
                PRIVATE_BACKEND_DIAGNOSTIC.to_string(),
            ));
        }

        let rows = if sql.contains("SELECT request_json AS document_json FROM request_logs") {
            serde_json::json!([{ "document_json": self.request_log_json.clone() }])
        } else {
            serde_json::json!([])
        };
        let query_result = serde_json::json!({
            "results": rows,
            "success": true,
            "meta": { "changes": 0 }
        });
        let result = if request.url.starts_with(PRIVATE_PROXY_BASE) {
            query_result
        } else {
            serde_json::json!([query_result])
        };
        Ok(HttpResponse {
            status: 200,
            retry_after: None,
            body: serde_json::json!({
                "success": true,
                "errors": [],
                "messages": [],
                "result": result
            })
            .to_string()
            .into_bytes(),
        })
    }
}

fn state_with_failing_presence_store(
    request_log: &StoredRequestLog,
) -> (AppState, Arc<FailingPresenceTransport>) {
    let transport = Arc::new(FailingPresenceTransport::new(request_log));
    let rest_client = D1Client::new(Arc::new(CloudflareClient::from_parts(
        CloudflareConfig::new("account-private", "plaintext-rest-token"),
        Arc::new(EnvTokenResolver::from_process_env()),
        transport.clone(),
        Arc::new(ImmediateClock),
        RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        },
    )));
    let proxy_client = D1ProxyClient::new(
        PRIVATE_PROXY_BASE,
        transport.clone(),
        Arc::new(EnvTokenResolver::from_process_env()),
        "plaintext-proxy-token",
    );
    let store = D1ControlPlaneStore::new(
        rest_client,
        D1TenantDatabaseRegistry {
            control_database_id: "control-private-uuid".into(),
            tenant_databases: BTreeMap::from([("tenant-a".into(), "tenant-private-uuid".into())]),
        },
    )
    .with_proxy_client(proxy_client);
    let repositories = Arc::new(RuntimeStorageRepositories::cloudflare_d1(store, 16));
    let state = AppState::try_new_with_repositories(Config::default(), repositories, false)
        .expect("app state with selectively failing D1 presence store");
    (state, transport)
}

fn recent_request_log(
    request_id: &str,
    tenant: &str,
    api_key: &str,
    seen_at_unix: u64,
) -> StoredRequestLog {
    StoredRequestLog {
        request_id: request_id.into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: Some(tenant.into()),
            team_id: None,
            project_id: Some("project-1".into()),
            workspace_id: Some("workspace-1".into()),
            user_id: None,
            api_key_id: Some(api_key.into()),
        },
        route: Some("chat.completions".into()),
        provider: Some("openai".into()),
        logical_model: Some("fast-chat".into()),
        provider_model: Some("gpt-test".into()),
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(seen_at_unix),
        completed_at_unix: Some(seen_at_unix),
        parent_action_fingerprint: None,
    }
}

#[test]
fn recording_a_request_log_backs_observed_activity_with_durable_presence() {
    let state = AppState::new(Config::default());
    // "Now-ish": a timestamp inside the default 60s running window so the
    // derivation (which reads the real clock) reports the key running.
    let now = now_unix_seconds().expect("clock");

    state.record_request_log(recent_request_log("req-1", "tenant-a", "key-1", now));

    // The durable presence store was touched (memory backend writes inline).
    let presence = ferrogate_sync_bridge::block_on_sync_bridge(
        state
            .repositories
            .list_observed_agent_presence_since(Some("tenant-a"), 0),
    )
    .expect("presence read");
    assert_eq!(presence.len(), 1, "one coalesced presence row for the key");
    assert_eq!(presence[0].api_key_id, "key-1");
    assert_eq!(presence[0].request_count, 1);

    // And the observed-activity surface reports the key as a running Unknown
    // row whose recency is backed by the durable presence signal.
    let rows = state.observed_agent_activity(Some("tenant-a")).rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "observed:tenant-a:key-1");
    assert_eq!(rows[0].display_name, "Unknown");
    assert_eq!(rows[0].status, "running");
    assert_eq!(
        rows[0].evidence.durable_presence_backed,
        Some(true),
        "the running decision must be backed by the durable presence store"
    );
    assert_eq!(rows[0].running_ttl_seconds, 60, "config default TTL");
}

#[test]
fn repeated_requests_for_one_key_coalesce_into_a_single_presence_row() {
    let state = AppState::new(Config::default());
    let now = now_unix_seconds().expect("clock");

    state.record_request_log(recent_request_log("req-1", "tenant-a", "key-1", now));
    state.record_request_log(recent_request_log("req-2", "tenant-a", "key-1", now));
    state.record_request_log(recent_request_log("req-3", "tenant-a", "key-1", now));

    let presence = ferrogate_sync_bridge::block_on_sync_bridge(
        state
            .repositories
            .list_observed_agent_presence_since(Some("tenant-a"), 0),
    )
    .expect("presence read");
    assert_eq!(presence.len(), 1, "three requests, one presence row");
    assert_eq!(
        presence[0].request_count, 3,
        "each request coalesces into the count",
    );
}

#[test]
fn failed_presence_read_is_unknown_and_redacts_backend_diagnostic() {
    let stale = now_unix_seconds().expect("clock").saturating_sub(3_600);
    let request_log = recent_request_log("req-presence-failure", "tenant-a", "key-1", stale);
    let (state, transport) = state_with_failing_presence_store(&request_log);

    let report = state.observed_agent_activity(Some("tenant-a"));

    assert_eq!(
        transport.presence_read_attempts.load(Ordering::SeqCst),
        1,
        "the fixture must fail the exact presence-window read once",
    );
    assert_eq!(report.presence_feed.status, "unavailable");
    assert!(report.presence_feed.rows_may_be_incomplete);
    assert_eq!(
        report.presence_feed.unavailable_reason.as_deref(),
        Some(PRESENCE_READ_FAILED),
    );
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].status, "unknown");
    assert_eq!(
        report.rows[0]
            .evidence
            .presence_unavailable_reason
            .as_deref(),
        Some(PRESENCE_READ_FAILED),
    );

    let tenant_visible_reason = format!(
        "{} {}",
        report.presence_feed.unavailable_reason.as_deref().unwrap(),
        report.rows[0].evidence.reason,
    );
    assert!(!tenant_visible_reason.contains("https://"));
    assert!(!tenant_visible_reason.contains("account-secret.example"));
    assert!(!tenant_visible_reason.contains("tenant-private-uuid"));
    assert!(!tenant_visible_reason.contains(PRIVATE_BACKEND_DIAGNOSTIC));
}
