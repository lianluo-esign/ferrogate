// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for the agent-schedule admin mutation -> stored
// schedule conversion (#251), kept out of the handler body.

use super::*;
use ferrogate_config::Config;
use ferrogate_storage::{StoredProject, StoredTenantAccount, StoredWorkspace};

fn interval_mutation() -> AdminAgentScheduleMutation {
    AdminAgentScheduleMutation {
        id: Some("sched-1".to_string()),
        tenant_id: Some("tenant-a".to_string()),
        workspace_id: Some("ws-a".to_string()),
        name: Some("nightly".to_string()),
        enabled: Some(true),
        spec_kind: Some("interval".to_string()),
        cron_expr: None,
        timezone: None,
        interval_secs: Some(300),
        target_kind: Some("self_hosted_dispatch".to_string()),
        target: Some(serde_json::json!({"required_capabilities": ["shell"]})),
        overlap_policy: None,
        catchup_policy: None,
        jitter_secs: None,
    }
}

fn tenant(id: &str, status: &str) -> StoredTenantAccount {
    StoredTenantAccount {
        id: id.into(),
        name: id.into(),
        slug: id.into(),
        status: status.into(),
        plan_id: "free".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn project(id: &str, tenant_id: &str) -> StoredProject {
    StoredProject {
        id: id.into(),
        tenant_id: tenant_id.into(),
        name: id.into(),
        slug: id.into(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

fn workspace(id: &str, project_id: &str, tenant_id: &str) -> StoredWorkspace {
    StoredWorkspace {
        id: id.into(),
        project_id: project_id.into(),
        tenant_id: tenant_id.into(),
        name: id.into(),
        slug: id.into(),
        environment: "production".into(),
        status: "active".into(),
        created_at_unix: 0,
        updated_at_unix: 0,
    }
}

async fn seed_scope(state: &AppState, tenant_id: &str, project_id: &str, workspace_id: &str) {
    state
        .upsert_tenant_account(tenant(tenant_id, "active"))
        .await
        .expect("seed tenant");
    state
        .upsert_project(project(project_id, tenant_id))
        .await
        .expect("seed project");
    state
        .upsert_workspace(workspace(workspace_id, project_id, tenant_id))
        .await
        .expect("seed workspace");
}

#[test]
fn create_interval_schedule_seeds_next_fire_from_now() {
    let schedule = agent_schedule_from_mutation(None, interval_mutation(), None, 1_000)
        .expect("valid interval schedule");
    assert_eq!(schedule.schedule_id, "sched-1");
    assert_eq!(schedule.spec_kind, ScheduleSpecKind::Interval);
    assert_eq!(schedule.interval_secs, Some(300));
    assert_eq!(schedule.next_fire_at_unix, Some(1_300));
    assert_eq!(schedule.revision, 1);
    assert_eq!(schedule.created_at_unix, 1_000);
    // Defaults applied for unspecified policy fields.
    assert_eq!(schedule.overlap_policy, OverlapPolicy::Skip);
    assert_eq!(schedule.catchup_policy, CatchupPolicy::SkipMissed);
    assert_eq!(schedule.timezone, "UTC");
}

#[test]
fn interval_schedule_requires_positive_interval() {
    let mut mutation = interval_mutation();
    mutation.interval_secs = Some(0);
    let error = agent_schedule_from_mutation(None, mutation, None, 1_000)
        .expect_err("zero interval must be rejected");
    assert!(error.contains("interval_secs > 0"), "{error}");
}

#[test]
fn cron_schedule_requires_valid_expression() {
    let mut mutation = interval_mutation();
    mutation.spec_kind = Some("cron".to_string());
    mutation.interval_secs = None;
    mutation.cron_expr = Some("not a cron".to_string());
    let error = agent_schedule_from_mutation(None, mutation, None, 1_000)
        .expect_err("invalid cron must be rejected");
    assert!(error.to_lowercase().contains("cron"), "{error}");
}

#[test]
fn patch_merges_over_existing_and_bumps_revision() {
    let existing = agent_schedule_from_mutation(None, interval_mutation(), None, 1_000)
        .expect("seed schedule");
    // A pause: send only `enabled=false`; every other field inherits.
    let patch = AdminAgentScheduleMutation {
        id: None,
        tenant_id: None,
        workspace_id: None,
        name: None,
        enabled: Some(false),
        spec_kind: None,
        cron_expr: None,
        timezone: None,
        interval_secs: None,
        target_kind: None,
        target: None,
        overlap_policy: None,
        catchup_policy: None,
        jitter_secs: None,
    };
    let updated = agent_schedule_from_mutation(Some("sched-1"), patch, Some(&existing), 2_000)
        .expect("valid patch");
    assert!(!updated.enabled, "pause toggles enabled off");
    assert_eq!(updated.name, "nightly", "unspecified fields inherit");
    assert_eq!(updated.interval_secs, Some(300));
    assert_eq!(updated.revision, existing.revision + 1);
    assert_eq!(updated.created_at_unix, existing.created_at_unix);
    assert_eq!(updated.updated_at_unix, 2_000);
}

#[test]
fn path_id_and_body_id_mismatch_is_rejected() {
    let mut mutation = interval_mutation();
    mutation.id = Some("other-id".to_string());
    let error = agent_schedule_from_mutation(Some("sched-1"), mutation, None, 1_000)
        .expect_err("id mismatch must be rejected");
    assert!(error.contains("must match"), "{error}");
}

#[test]
fn create_requires_tenant_workspace_and_name() {
    let mutation = AdminAgentScheduleMutation {
        id: Some("sched-1".to_string()),
        tenant_id: None,
        workspace_id: None,
        name: None,
        enabled: None,
        spec_kind: Some("interval".to_string()),
        cron_expr: None,
        timezone: None,
        interval_secs: Some(60),
        target_kind: Some("self_hosted_dispatch".to_string()),
        target: None,
        overlap_policy: None,
        catchup_policy: None,
        jitter_secs: None,
    };
    let error = agent_schedule_from_mutation(None, mutation, None, 1_000)
        .expect_err("missing tenant must be rejected");
    assert!(error.contains("tenant_id is required"), "{error}");
}

#[test]
fn target_must_be_a_json_object() {
    let mut mutation = interval_mutation();
    mutation.target = Some(serde_json::json!("not-an-object"));
    let error = agent_schedule_from_mutation(None, mutation, None, 1_000)
        .expect_err("non-object target must be rejected");
    assert!(error.contains("target must be a JSON object"), "{error}");
}

#[test]
fn query_param_extracts_named_value() {
    assert_eq!(
        query_param(Some("tenant=acme&workspace=ws1"), "tenant").as_deref(),
        Some("acme")
    );
    assert_eq!(
        query_param(Some("tenant=acme&workspace=ws1"), "workspace").as_deref(),
        Some("ws1")
    );
    assert_eq!(query_param(Some("tenant=acme"), "missing"), None);
    assert_eq!(query_param(None, "tenant"), None);
}

#[tokio::test]
async fn schedule_create_requires_a_real_active_tenancy_chain() {
    let state = AppState::new(Config::default());
    let schedule = agent_schedule_from_mutation(None, interval_mutation(), None, 1_000)
        .expect("valid schedule shape");

    let missing = require_agent_schedule_tenancy(&state, &schedule, None)
        .await
        .expect_err("orphan schedule must fail");
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.code, "tenant_not_found");

    state
        .upsert_tenant_account(tenant("tenant-a", "active"))
        .await
        .expect("seed tenant");
    let missing = require_agent_schedule_tenancy(&state, &schedule, None)
        .await
        .expect_err("missing workspace must fail");
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.code, "workspace_not_found");

    seed_scope(&state, "tenant-a", "project-a", "ws-a").await;
    require_agent_schedule_tenancy(&state, &schedule, None)
        .await
        .expect("active durable chain accepts schedule");

    for status in ["disabled", "suspended", "deleted"] {
        state
            .upsert_tenant_account(tenant("tenant-a", status))
            .await
            .expect("change tenant lifecycle");
        let inactive = require_agent_schedule_tenancy(&state, &schedule, None)
            .await
            .expect_err("inactive tenant must refuse create");
        assert_eq!(inactive.status, StatusCode::FORBIDDEN, "for {status}");
        assert_eq!(inactive.code, "inactive_tenancy_reference", "for {status}");
    }

    state
        .upsert_tenant_account(tenant("tenant-a", "active"))
        .await
        .expect("reactivate tenant");
    for status in ["disabled", "suspended", "deleted"] {
        let mut inactive_workspace = workspace("ws-a", "project-a", "tenant-a");
        inactive_workspace.status = status.into();
        state
            .upsert_workspace(inactive_workspace)
            .await
            .expect("change workspace lifecycle");
        let inactive = require_agent_schedule_tenancy(&state, &schedule, None)
            .await
            .expect_err("inactive workspace must refuse create");
        assert_eq!(inactive.status, StatusCode::FORBIDDEN, "for {status}");
        assert_eq!(inactive.code, "inactive_tenancy_reference", "for {status}");
    }
}

#[tokio::test]
async fn schedule_repoint_is_gated_but_same_scope_pause_remains_available() {
    let state = AppState::new(Config::default());
    seed_scope(&state, "tenant-a", "project-a", "ws-a").await;
    seed_scope(&state, "tenant-b", "project-b", "ws-b").await;
    let existing = agent_schedule_from_mutation(None, interval_mutation(), None, 1_000)
        .expect("seed schedule");

    state
        .upsert_tenant_account(tenant("tenant-a", "suspended"))
        .await
        .expect("suspend original tenant");
    let mut paused = existing.clone();
    paused.enabled = false;
    require_agent_schedule_tenancy(&state, &paused, Some(&existing))
        .await
        .expect("same-scope pause is containment, not an attach");

    state
        .upsert_tenant_account(tenant("tenant-b", "suspended"))
        .await
        .expect("suspend destination tenant");
    let mut repointed = paused;
    repointed.tenant_id = "tenant-b".into();
    repointed.workspace_id = "ws-b".into();
    let inactive = require_agent_schedule_tenancy(&state, &repointed, Some(&existing))
        .await
        .expect_err("disabled schedule cannot be repointed into inactive tenancy");
    assert_eq!(inactive.status, StatusCode::FORBIDDEN);
    assert_eq!(inactive.code, "inactive_tenancy_reference");
}

#[tokio::test]
async fn schedule_rejects_a_workspace_owned_by_another_tenant() {
    let state = AppState::new(Config::default());
    seed_scope(&state, "tenant-a", "project-a", "ws-a").await;
    seed_scope(&state, "tenant-b", "project-b", "ws-b").await;
    let mut schedule = agent_schedule_from_mutation(None, interval_mutation(), None, 1_000)
        .expect("valid schedule shape");
    schedule.workspace_id = "ws-b".into();

    let mismatch = require_agent_schedule_tenancy(&state, &schedule, None)
        .await
        .expect_err("cross-tenant workspace must fail");
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.code, "invalid_agent_schedule");
}
