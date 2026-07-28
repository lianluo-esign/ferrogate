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
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrogate_cloudflare::d1::D1Client;
use ferrogate_cloudflare::{
    Clock, CloudflareClient, CloudflareConfig, CloudflareError, D1ProxyClient, EnvTokenResolver,
    HttpRequest, HttpTransport, RetryPolicy,
};
use ferrogate_core::TenantContext;
use ferrogate_storage::{
    D1ControlPlaneStore, D1TenantDatabaseRegistry, RuntimeStorageRepositories, StoredRequestLog,
};

const PRIVATE_BACKEND_DIAGNOSTIC: &str =
    "connect failed: https://account-secret.example/db/tenant-private-uuid";

struct ImmediateClock;

#[async_trait]
impl Clock for ImmediateClock {
    async fn sleep(&self, _duration: Duration) {}
}

struct FailingPresenceTransport;

#[async_trait]
impl HttpTransport for FailingPresenceTransport {
    async fn execute(
        &self,
        _request: HttpRequest,
    ) -> Result<ferrogate_cloudflare::HttpResponse, CloudflareError> {
        Err(CloudflareError::Transport(
            PRIVATE_BACKEND_DIAGNOSTIC.to_string(),
        ))
    }
}

fn state_with_failing_presence_store() -> AppState {
    let transport = Arc::new(FailingPresenceTransport);
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
        "https://account-secret.example/d1",
        transport,
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
    AppState::try_new_with_repositories(Config::default(), repositories, false)
        .expect("app state with failing D1 presence store")
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
    let state = state_with_failing_presence_store();
    let stale = now_unix_seconds().expect("clock").saturating_sub(3_600);
    state.record_request_log(recent_request_log(
        "req-presence-failure",
        "tenant-a",
        "key-1",
        stale,
    ));

    let report = state.observed_agent_activity(Some("tenant-a"));

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
