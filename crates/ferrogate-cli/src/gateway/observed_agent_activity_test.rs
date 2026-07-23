// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Deterministic tests for the #357 observed-agent-activity
// detection/presentation pass. No clock sleeps: `now_unix` is injected so the
// running/TTL boundary is exercised exactly.

use std::collections::{HashMap, HashSet};

use ferrogate_core::TenantContext;
use ferrogate_storage::StoredRequestLog;

use super::{
    derive_observed_agent_activity, ObservedActivityInputs, UsageContribution,
    OBSERVED_ACTIVITY_RUNNING_TTL_SECONDS,
};

fn log(
    request_id: &str,
    tenant: Option<&str>,
    api_key: Option<&str>,
    agent_run_id: Option<&str>,
    started: Option<u64>,
    completed: Option<u64>,
) -> StoredRequestLog {
    StoredRequestLog {
        request_id: request_id.into(),
        trace_id: None,
        agent_run_id: agent_run_id.map(str::to_string),
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: TenantContext {
            organization_id: tenant.map(str::to_string),
            team_id: None,
            project_id: Some("project-1".into()),
            workspace_id: Some("workspace-1".into()),
            user_id: None,
            api_key_id: api_key.map(str::to_string),
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
        started_at_unix: started,
        completed_at_unix: completed,
        parent_action_fingerprint: None,
    }
}

fn empty_inputs<'a>(
    logs: &'a [StoredRequestLog],
    attributed: &'a HashSet<String>,
    usage: &'a HashMap<String, UsageContribution>,
    names: &'a HashMap<String, String>,
    now_unix: u64,
) -> ObservedActivityInputs<'a> {
    ObservedActivityInputs {
        request_logs: logs,
        attributed_run_ids: attributed,
        usage_by_request_id: usage,
        credential_names: names,
        tenant_scope: None,
        now_unix,
        running_ttl_seconds: OBSERVED_ACTIVITY_RUNNING_TTL_SECONDS,
    }
}

#[test]
fn unattributed_key_with_recent_activity_surfaces_one_running_unknown_row() {
    let logs = vec![
        log(
            "r1",
            Some("tenant-a"),
            Some("key-1"),
            None,
            Some(1_000),
            Some(1_010),
        ),
        log(
            "r2",
            Some("tenant-a"),
            Some("key-1"),
            None,
            Some(1_020),
            Some(1_030),
        ),
    ];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    // now is 40s after the last request -> within the 60s TTL.
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_070);

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(
        rows.len(),
        1,
        "one shared key collapses to one observed row"
    );
    let row = &rows[0];
    // View contract fields (exact).
    assert_eq!(row.id, "observed:tenant-a:key-1");
    assert_eq!(row.source, "virtual_api_key");
    assert_eq!(row.identity_status, "unattributed");
    assert_eq!(row.display_name, "Unknown");
    assert_eq!(row.status, "running");
    assert_eq!(row.status_basis, "recent_api_key_activity");
    assert_eq!(row.tenant_id, "tenant-a");
    assert_eq!(row.project_id.as_deref(), Some("project-1"));
    assert_eq!(row.workspace_id.as_deref(), Some("workspace-1"));
    assert_eq!(row.api_key_id, "key-1");
    assert_eq!(row.first_seen_at_unix, 1_000);
    assert_eq!(row.last_seen_at_unix, 1_030);
    assert_eq!(row.running_ttl_seconds, 60);
    // Evidence explains the decision and counts both requests.
    assert_eq!(row.evidence.request_count, 2);
    assert_eq!(row.evidence.seconds_since_last_seen, 40);
    assert!(row.evidence.within_running_window);
    assert!(!row.evidence.usage_evidence_available);
    assert!(row.evidence.total_tokens.is_none());
}

#[test]
fn key_without_recent_activity_is_reported_inactive_not_running() {
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        None,
        Some(1_000),
        Some(1_010),
    )];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    // now is 61s after last request -> just past the 60s TTL boundary.
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_071);

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "inactive");
    assert!(!rows[0].evidence.within_running_window);
    assert_eq!(rows[0].evidence.seconds_since_last_seen, 61);
}

#[test]
fn running_ttl_boundary_is_inclusive() {
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        None,
        Some(1_000),
        Some(1_010),
    )];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    // Exactly 60s since last seen -> still running (<= TTL).
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_070);
    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows[0].status, "running");
    assert_eq!(rows[0].evidence.seconds_since_last_seen, 60);
}

#[test]
fn managed_or_self_hosted_verified_identity_is_not_reclassified_as_unknown() {
    // Two logs on the same key: one attributed to a verified run ("mw-run"),
    // one direct/unattributed.
    let logs = vec![
        log(
            "r1",
            Some("tenant-a"),
            Some("key-1"),
            Some("mw-run"),
            Some(1_000),
            Some(1_010),
        ),
        log(
            "r2",
            Some("tenant-a"),
            Some("key-1"),
            None,
            Some(1_020),
            Some(1_030),
        ),
    ];
    let mut attributed = HashSet::new();
    attributed.insert("mw-run".to_string());
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_050);

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows.len(), 1);
    // Only the direct request is counted; the verified-run request is excluded.
    assert_eq!(rows[0].evidence.request_count, 1);
    assert_eq!(rows[0].first_seen_at_unix, 1_020);
}

#[test]
fn fully_attributed_key_produces_no_unknown_row() {
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        Some("mw-run"),
        Some(1_000),
        Some(1_010),
    )];
    let mut attributed = HashSet::new();
    attributed.insert("mw-run".to_string());
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_050);

    let rows = derive_observed_agent_activity(&inputs);
    assert!(rows.is_empty());
}

#[test]
fn spoofed_agent_run_id_that_matches_no_verified_run_stays_unknown() {
    // Caller supplies an agent_run_id, but no verified run exists for it.
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        Some("spoofed-run"),
        Some(1_000),
        Some(1_010),
    )];
    let attributed = HashSet::new(); // no verified runs
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_020);

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, "running");
    assert_eq!(rows[0].identity_status, "unattributed");
}

#[test]
fn tenant_scope_isolates_other_tenants() {
    let logs = vec![
        log(
            "r1",
            Some("tenant-a"),
            Some("key-a"),
            None,
            Some(1_000),
            Some(1_010),
        ),
        log(
            "r2",
            Some("tenant-b"),
            Some("key-b"),
            None,
            Some(1_000),
            Some(1_010),
        ),
    ];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    let mut inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_020);
    inputs.tenant_scope = Some("tenant-a");

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].tenant_id, "tenant-a");
    assert_eq!(rows[0].api_key_id, "key-a");
}

#[test]
fn requests_without_durable_key_or_tenant_are_out_of_scope() {
    let logs = vec![
        // No api_key_id (e.g. a static/YAML key without a durable owner).
        log("r1", Some("tenant-a"), None, None, Some(1_000), Some(1_010)),
        // No tenant owner.
        log("r2", None, Some("key-x"), None, Some(1_000), Some(1_010)),
    ];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_020);

    let rows = derive_observed_agent_activity(&inputs);
    assert!(rows.is_empty());
}

#[test]
fn usage_and_credential_evidence_are_folded_when_available() {
    let logs = vec![
        log(
            "r1",
            Some("tenant-a"),
            Some("key-1"),
            None,
            Some(1_000),
            Some(1_010),
        ),
        log(
            "r2",
            Some("tenant-a"),
            Some("key-1"),
            None,
            Some(1_020),
            Some(1_030),
        ),
    ];
    let attributed = HashSet::new();
    let mut usage = HashMap::new();
    usage.insert(
        "r1".to_string(),
        UsageContribution {
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cost_usd: Some(0.02),
        },
    );
    // r2 has no usage evidence -> partial evidence, still not invented.
    let mut names = HashMap::new();
    names.insert("key-1".to_string(), "prod-agent-key".to_string());
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_050);

    let rows = derive_observed_agent_activity(&inputs);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.credential_name.as_deref(), Some("prod-agent-key"));
    assert!(row.evidence.usage_evidence_available);
    assert_eq!(row.evidence.total_tokens, Some(15));
    assert_eq!(row.evidence.prompt_tokens, Some(10));
    assert_eq!(row.evidence.completion_tokens, Some(5));
    assert_eq!(row.evidence.cost_usd, Some(0.02));
}

#[test]
fn missing_usage_evidence_is_unavailable_never_invented() {
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        None,
        Some(1_000),
        Some(1_010),
    )];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_020);

    let rows = derive_observed_agent_activity(&inputs);
    assert!(!rows[0].evidence.usage_evidence_available);
    assert!(rows[0].evidence.total_tokens.is_none());
    assert!(rows[0].evidence.cost_usd.is_none());
}

#[test]
fn serialized_row_carries_exact_contract_strings() {
    let logs = vec![log(
        "r1",
        Some("tenant-a"),
        Some("key-1"),
        None,
        Some(1_000),
        Some(1_010),
    )];
    let attributed = HashSet::new();
    let usage = HashMap::new();
    let names = HashMap::new();
    let inputs = empty_inputs(&logs, &attributed, &usage, &names, 1_020);

    let rows = derive_observed_agent_activity(&inputs);
    let json = serde_json::to_value(&rows[0]).unwrap();
    assert_eq!(json["id"], "observed:tenant-a:key-1");
    assert_eq!(json["source"], "virtual_api_key");
    assert_eq!(json["identity_status"], "unattributed");
    assert_eq!(json["display_name"], "Unknown");
    assert_eq!(json["status"], "running");
    assert_eq!(json["status_basis"], "recent_api_key_activity");
    assert_eq!(json["running_ttl_seconds"], 60);
    assert_eq!(json["evidence"]["evidence_source"], "request_logs");
    // Optional usage fields are omitted (not null) when unavailable.
    assert!(json["evidence"].get("total_tokens").is_none());
    // Optional credential hint omitted when absent.
    assert!(json.get("credential_name").is_none());
}
