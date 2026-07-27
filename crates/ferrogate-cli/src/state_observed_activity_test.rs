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

use ferrogate_core::TenantContext;
use ferrogate_storage::StoredRequestLog;

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
