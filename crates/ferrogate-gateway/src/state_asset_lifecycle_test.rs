// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Coverage for the #263 asset lifecycle sweeper against an
// in-memory AppState: retention keep-last-N + channel-pin survivors + quota
// reconciliation, dry-run report-only, tenant isolation, and tenant cascade
// purge with an audit trail. Assets are inline (no bucket) so no live/prod
// bucket is ever touched.

use super::*;

use ferrogate_storage::{
    stored_asset_id, StoredAsset, StoredAssetChannel, StoredAuditEvent, StoredRequestLog,
    RETENTION_RESOURCE_REQUEST_LOG, RETENTION_SCOPE_DEFAULT,
};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn lifecycle_config(
    enabled: bool,
    dry_run: bool,
    keep_last_n: Option<u64>,
) -> ferrogate_config::AssetLifecycleConfig {
    ferrogate_config::AssetLifecycleConfig {
        enabled,
        dry_run,
        default_keep_last_n: keep_last_n,
        retention_min_age_secs: 0,
        ..ferrogate_config::AssetLifecycleConfig::default()
    }
}

fn state_with(config: ferrogate_config::AssetLifecycleConfig) -> AppState {
    AppState::new(Config {
        asset_lifecycle: config,
        ..Config::default()
    })
}

fn inline_asset(tenant: &str, name: &str, version: &str, created: i64) -> StoredAsset {
    StoredAsset {
        id: stored_asset_id(tenant, "cli_tool", name, version),
        tenant_id: tenant.into(),
        project_id: None,
        asset_type: "cli_tool".into(),
        name: name.into(),
        version: version.into(),
        content_type: "application/octet-stream".into(),
        content_hash: "hash".into(),
        size_bytes: 100,
        content: vec![1, 2, 3],
        storage_uri: None,
        variant: String::new(),
        yanked: false,
        visibility: Default::default(),
        created_at_unix: created,
        updated_at_unix: created,
    }
}

fn seed_four_versions(state: &AppState, tenant: &str) {
    for (index, version) in ["1.0.0", "1.1.0", "1.2.0", "1.3.0"].iter().enumerate() {
        block_on(state.upsert_asset(inline_asset(
            tenant,
            "rg",
            version,
            100 + index as i64 * 100,
        )))
        .unwrap();
    }
}

#[test]
fn disabled_sweeper_is_a_no_op() {
    let state = state_with(lifecycle_config(false, false, Some(1)));
    seed_four_versions(&state, "t1");
    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report, AssetLifecycleSweepReport::default());
    let remaining = block_on(state.list_assets("t1", Some("cli_tool"))).unwrap();
    assert_eq!(remaining.len(), 4);
}

#[test]
fn keep_last_two_prunes_the_two_oldest_and_reconciles_quota() {
    let state = state_with(lifecycle_config(true, false, Some(2)));
    seed_four_versions(&state, "t1");
    assert_eq!(
        block_on(state.tenant_asset_storage_bytes_used("t1")).unwrap(),
        400
    );

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report.retention_pruned, 2);
    assert_eq!(report.retention_freed_bytes, 200);

    let mut remaining: Vec<String> = block_on(state.list_assets("t1", Some("cli_tool")))
        .unwrap()
        .into_iter()
        .map(|asset| asset.version)
        .collect();
    remaining.sort();
    assert_eq!(remaining, vec!["1.2.0".to_string(), "1.3.0".to_string()]);
    // Quota is a live SUM over remaining rows -> freed bytes are reconciled.
    assert_eq!(
        block_on(state.tenant_asset_storage_bytes_used("t1")).unwrap(),
        200
    );
}

#[test]
fn channel_pinned_version_survives_the_prune() {
    let state = state_with(lifecycle_config(true, false, Some(2)));
    seed_four_versions(&state, "t1");
    // Pin the oldest version, which would otherwise be pruned.
    block_on(state.upsert_asset_channel(StoredAssetChannel {
        id: "t1:cli_tool:rg:stable".into(),
        tenant_id: "t1".into(),
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        channel: "stable".into(),
        version: "1.0.0".into(),
        updated_at_unix: 100,
    }))
    .unwrap();

    let report = block_on(state.sweep_asset_lifecycle_once());
    // Only 1.1.0 is pruned: 1.0.0 pinned, 1.2.0/1.3.0 within keep-last-2.
    assert_eq!(report.retention_pruned, 1);
    let mut remaining: Vec<String> = block_on(state.list_assets("t1", Some("cli_tool")))
        .unwrap()
        .into_iter()
        .map(|asset| asset.version)
        .collect();
    remaining.sort();
    assert_eq!(remaining, vec!["1.0.0", "1.2.0", "1.3.0"]);
}

#[test]
fn dry_run_reports_but_deletes_nothing() {
    let state = state_with(lifecycle_config(true, true, Some(2)));
    seed_four_versions(&state, "t1");

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert!(report.dry_run);
    assert_eq!(report.retention_would_prune, 2);
    assert_eq!(report.retention_pruned, 0);
    // Nothing deleted.
    assert_eq!(
        block_on(state.list_assets("t1", Some("cli_tool")))
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn retention_is_tenant_isolated() {
    let state = state_with(lifecycle_config(true, false, Some(1)));
    seed_four_versions(&state, "t1");
    seed_four_versions(&state, "t2");

    block_on(state.sweep_asset_lifecycle_once());

    // t1 keeps only its newest; t2 likewise -- neither tenant's prune touched
    // the other's rows.
    assert_eq!(
        block_on(state.list_assets("t1", Some("cli_tool")))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        block_on(state.list_assets("t2", Some("cli_tool")))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn specific_scope_policy_overrides_the_config_default() {
    // Config default keeps last 3, but a per-asset policy row keeps last 1.
    let state = state_with(lifecycle_config(true, false, Some(3)));
    seed_four_versions(&state, "t1");
    block_on(
        state
            .repositories
            .upsert_retention_policy(asset_retention_policy(
                "t1",
                "cli_tool/rg",
                Some(1),
                None,
                0,
                0,
            )),
    )
    .unwrap();

    block_on(state.sweep_asset_lifecycle_once());
    // The scoped keep-last-1 wins -> only the newest survives.
    assert_eq!(
        block_on(state.list_assets("t1", Some("cli_tool")))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn tenant_purge_removes_all_rows_channels_and_audits() {
    let state = state_with(lifecycle_config(false, false, None));
    seed_four_versions(&state, "t1");
    seed_four_versions(&state, "t2");
    block_on(state.upsert_asset_channel(StoredAssetChannel {
        id: "t1:cli_tool:rg:stable".into(),
        tenant_id: "t1".into(),
        asset_type: "cli_tool".into(),
        name: "rg".into(),
        channel: "stable".into(),
        version: "1.3.0".into(),
        updated_at_unix: 100,
    }))
    .unwrap();

    let purged = block_on(state.purge_tenant_assets("t1", "tenant offboarding"));
    assert_eq!(purged, 4);

    // Zero rows + zero channels remain for t1; t2 untouched.
    assert!(block_on(state.list_assets("t1", Some("cli_tool")))
        .unwrap()
        .is_empty());
    assert!(block_on(state.list_asset_channels("t1", "cli_tool", "rg"))
        .unwrap()
        .is_empty());
    assert_eq!(
        block_on(state.list_assets("t2", Some("cli_tool")))
            .unwrap()
            .len(),
        4
    );

    // The purge left an audit trail naming what was removed.
    let audits = block_on(state.repositories.audit_events());
    assert!(audits.iter().any(|event| {
        event.action == "asset.tenant.purge"
            && event.message.contains("purged 4")
            && event.tenant.organization_id.as_deref() == Some("t1")
    }));
}

#[test]
fn prune_emits_an_audit_event() {
    let state = state_with(lifecycle_config(true, false, Some(1)));
    seed_four_versions(&state, "t1");
    block_on(state.sweep_asset_lifecycle_once());
    let audits = block_on(state.repositories.audit_events());
    assert!(audits
        .iter()
        .any(|event| event.action == "asset.retention.prune" && event.message.contains("pruned")));
}

// -- #284: compliance-data retention (request_logs / audit_events) --

fn now_secs() -> i64 {
    now_unix_seconds().unwrap() as i64
}

fn tenant_ctx(org: &str) -> ferrogate_core::TenantContext {
    ferrogate_core::TenantContext {
        organization_id: Some(org.to_string()),
        ..ferrogate_core::TenantContext::default()
    }
}

fn request_log(id: &str, org: &str, started: i64, response_recorded: bool) -> StoredRequestLog {
    StoredRequestLog {
        request_id: id.into(),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        tenant: tenant_ctx(org),
        route: None,
        provider: None,
        logical_model: None,
        provider_model: None,
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: 200,
        error_code: None,
        prompt_recorded: false,
        response_recorded,
        prompt_body: None,
        response_body: response_recorded.then(|| "body".to_string()),
        cache_status: None,
        started_at_unix: Some(started.max(0) as u64),
        completed_at_unix: None,
        parent_action_fingerprint: None,
    }
}

fn audit_event(id: &str, org: &str, occurred: i64) -> StoredAuditEvent {
    StoredAuditEvent {
        action_fingerprint: None,
        decision: None,
        decision_reason: None,
        output_disposition: None,
        id: id.into(),
        request_id: format!("req-{id}"),
        trace_id: None,
        agent_run_id: None,
        workflow_id: None,
        workflow_version: None,
        workflow_node_id: None,
        cluster_id: None,
        node_id: None,
        actor_api_key_id: None,
        tenant: tenant_ctx(org),
        action: "test.action".into(),
        target: "t".into(),
        outcome: "committed".into(),
        message: "m".into(),
        occurred_at_unix: Some(occurred.max(0) as u64),
        parent_action_fingerprint: None,
    }
}

/// Config with compliance retention enabled and the given per-table defaults.
fn compliance_config(
    dry_run: bool,
    request_log_max_age: Option<i64>,
    audit_event_max_age: Option<i64>,
    response_body_max_age: Option<i64>,
) -> ferrogate_config::AssetLifecycleConfig {
    ferrogate_config::AssetLifecycleConfig {
        enabled: true,
        dry_run,
        retention_min_age_secs: 0,
        default_request_log_max_age_secs: request_log_max_age,
        default_audit_event_max_age_secs: audit_event_max_age,
        default_response_body_max_age_secs: response_body_max_age,
        ..ferrogate_config::AssetLifecycleConfig::default()
    }
}

#[test]
fn request_logs_past_max_age_are_pruned_while_audit_events_floor_survives() {
    // request_logs TTL 100s; audit_events have NO configured TTL (their longer
    // legal floor -> never pruned). Ancient rows of both are seeded.
    let state = state_with(compliance_config(false, Some(100), None, None));
    block_on(
        state
            .repositories
            .append_request_log(request_log("req-old", "t1", 1_000, false)),
    );
    block_on(state.repositories.append_request_log(request_log(
        "req-fresh",
        "t1",
        now_secs(),
        false,
    )));
    block_on(
        state
            .repositories
            .append_audit_event(audit_event("aud-old", "t1", 1_000)),
    );

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report.request_logs_pruned, 1);
    assert_eq!(report.audit_events_pruned, 0);

    let logs: Vec<String> = block_on(state.repositories.request_logs())
        .into_iter()
        .map(|log| log.request_id)
        .collect();
    assert_eq!(logs, vec!["req-fresh".to_string()]);

    // The ancient audit row survives its longer floor.
    let audits = block_on(state.repositories.audit_events());
    assert!(audits.iter().any(|event| event.id == "aud-old"));
    // The purge audited itself (evidence of deletion).
    assert!(audits
        .iter()
        .any(|event| event.action == "request_logs.retention.prune"
            && event.message.contains("purged 1")));
}

#[test]
fn disabled_compliance_retention_is_a_no_op() {
    let mut config = compliance_config(false, Some(1), Some(1), None);
    config.enabled = false;
    let state = state_with(config);
    block_on(
        state
            .repositories
            .append_request_log(request_log("req-old", "t1", 1_000, false)),
    );
    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report, AssetLifecycleSweepReport::default());
    assert_eq!(block_on(state.repositories.request_logs()).len(), 1);
}

#[test]
fn compliance_dry_run_reports_but_deletes_nothing() {
    let state = state_with(compliance_config(true, Some(100), None, None));
    block_on(
        state
            .repositories
            .append_request_log(request_log("req-old", "t1", 1_000, false)),
    );
    let report = block_on(state.sweep_asset_lifecycle_once());
    assert!(report.dry_run);
    assert_eq!(report.request_logs_would_prune, 1);
    assert_eq!(report.request_logs_pruned, 0);
    assert_eq!(block_on(state.repositories.request_logs()).len(), 1);
}

#[test]
fn compliance_retention_is_tenant_isolated_via_per_tenant_policy() {
    // No config default -> only t1's explicit request_logs policy prunes;
    // t2 has no policy, so its ancient row is untouched.
    let state = state_with(compliance_config(false, None, None, None));
    block_on(
        state
            .repositories
            .upsert_retention_policy(log_retention_policy(
                "t1",
                RETENTION_RESOURCE_REQUEST_LOG,
                RETENTION_SCOPE_DEFAULT,
                None,
                Some(100),
                0,
                0,
            )),
    )
    .unwrap();
    block_on(
        state
            .repositories
            .append_request_log(request_log("t1-old", "t1", 1_000, false)),
    );
    block_on(
        state
            .repositories
            .append_request_log(request_log("t2-old", "t2", 1_000, false)),
    );

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report.request_logs_pruned, 1);

    let logs: Vec<String> = block_on(state.repositories.request_logs())
        .into_iter()
        .map(|log| log.request_id)
        .collect();
    assert_eq!(logs, vec!["t2-old".to_string()]);
}

#[test]
fn response_body_captures_get_the_shortest_ttl() {
    // General request_log TTL is effectively infinite; only the shorter
    // response-body TTL prunes the response-recorded row.
    let state = state_with(compliance_config(
        false,
        Some(1_000_000_000_000),
        None,
        Some(100),
    ));
    block_on(
        state
            .repositories
            .append_request_log(request_log("plain", "t1", 1_000, false)),
    );
    block_on(
        state
            .repositories
            .append_request_log(request_log("with-body", "t1", 1_000, true)),
    );

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report.request_logs_pruned, 1);
    let logs: Vec<String> = block_on(state.repositories.request_logs())
        .into_iter()
        .map(|log| log.request_id)
        .collect();
    assert_eq!(logs, vec!["plain".to_string()]);
}

#[test]
fn audit_events_past_max_age_are_pruned_and_audited() {
    let state = state_with(compliance_config(false, None, Some(100), None));
    block_on(
        state
            .repositories
            .append_audit_event(audit_event("aud-old", "t1", 1_000)),
    );
    block_on(
        state
            .repositories
            .append_audit_event(audit_event("aud-fresh", "t1", now_secs())),
    );

    let report = block_on(state.sweep_asset_lifecycle_once());
    assert_eq!(report.audit_events_pruned, 1);

    let audits = block_on(state.repositories.audit_events());
    assert!(audits.iter().all(|event| event.id != "aud-old"));
    assert!(audits.iter().any(|event| event.id == "aud-fresh"));
    assert!(audits
        .iter()
        .any(|event| event.action == "audit_events.retention.prune"));
}
