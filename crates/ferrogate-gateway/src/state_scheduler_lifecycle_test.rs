// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-29
// description: Focused scheduler lifecycle regression coverage for issue #578.

use super::*;
use ferrogate_storage::{
    ScheduleSpecKind, ScheduleTargetKind, StoredAgentSchedule, StoredProject, StoredTenantAccount,
    StoredWorkspace,
};

fn scheduler_enabled_config() -> Config {
    let mut config = Config::default();
    config.scheduler.enabled = true;
    config
}

fn tenant(status: &str) -> StoredTenantAccount {
    StoredTenantAccount {
        id: "tenant-a".into(),
        name: "Tenant A".into(),
        slug: "tenant-a".into(),
        status: status.into(),
        plan_id: "free".into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn project(status: &str) -> StoredProject {
    StoredProject {
        id: "project-a".into(),
        tenant_id: "tenant-a".into(),
        name: "Project A".into(),
        slug: "project-a".into(),
        status: status.into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

fn workspace(status: &str) -> StoredWorkspace {
    StoredWorkspace {
        id: "ws-a".into(),
        project_id: "project-a".into(),
        tenant_id: "tenant-a".into(),
        name: "Workspace A".into(),
        slug: "ws-a".into(),
        environment: "prod".into(),
        status: status.into(),
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

async fn seed_active_scope(state: &AppState) {
    state
        .upsert_tenant_account(tenant("active"))
        .await
        .expect("seed tenant");
    state
        .upsert_project(project("active"))
        .await
        .expect("seed project");
    state
        .upsert_workspace(workspace("active"))
        .await
        .expect("seed workspace");
}

async fn set_lifecycle_status(state: &AppState, ancestor: &str, status: &str) {
    match ancestor {
        "tenant" => state
            .upsert_tenant_account(tenant(status))
            .await
            .expect("change tenant lifecycle"),
        "project" => state
            .upsert_project(project(status))
            .await
            .expect("change project lifecycle"),
        "workspace" => state
            .upsert_workspace(workspace(status))
            .await
            .expect("change workspace lifecycle"),
        other => panic!("unknown lifecycle ancestor {other}"),
    }
}

fn interval_schedule(schedule_id: &str, next_fire_at_unix: i64) -> StoredAgentSchedule {
    StoredAgentSchedule {
        schedule_id: schedule_id.into(),
        tenant_id: "tenant-a".into(),
        workspace_id: "ws-a".into(),
        name: "nightly".into(),
        enabled: true,
        spec_kind: ScheduleSpecKind::Interval,
        cron_expr: None,
        timezone: "UTC".into(),
        interval_secs: Some(60),
        target_kind: ScheduleTargetKind::SelfHostedDispatch,
        target_json: "{\"required_capabilities\":[\"shell\"]}".into(),
        overlap_policy: OverlapPolicy::Skip,
        catchup_policy: CatchupPolicy::SkipMissed,
        jitter_secs: 0,
        next_fire_at_unix: Some(next_fire_at_unix),
        last_fire_at_unix: None,
        created_at_unix: 1,
        updated_at_unix: 1,
        revision: 1,
    }
}

fn assert_lifecycle_error(fire: &StoredAgentScheduleFire, code: &str) {
    assert_eq!(fire.outcome, ScheduleFireOutcome::Error);
    assert_eq!(
        fire.dispatch_id, None,
        "lifecycle refusal must not enqueue a self-hosted dispatch"
    );
    assert_eq!(
        fire.run_id, None,
        "lifecycle refusal must not create or link an agent run"
    );
    let detail = fire.detail.as_deref().expect("error detail recorded");
    assert!(
        detail.starts_with(code),
        "expected lifecycle code {code} in detail, got {detail:?}"
    );
}

#[tokio::test]
async fn background_tick_refuses_inactive_tenancy_before_dispatching_work() {
    for (ancestor, status, code) in [
        ("tenant", "suspended", "tenancy_suspended"),
        ("project", "disabled", "tenancy_disabled"),
        ("workspace", "deleted", "tenancy_deleted"),
    ] {
        let state = AppState::new(scheduler_enabled_config());
        seed_active_scope(&state).await;
        let now = now_unix_seconds().unwrap_or_default() as i64;
        let schedule_id = format!("tick-{ancestor}-{status}");
        state
            .repositories
            .upsert_agent_schedule(interval_schedule(&schedule_id, now))
            .await
            .expect("seed active schedule");
        set_lifecycle_status(&state, ancestor, status).await;

        state.sweep_agent_schedules_once().await;

        let fires = state
            .repositories
            .list_agent_schedule_fires(&schedule_id, 10)
            .await
            .expect("list fires");
        assert_eq!(fires.len(), 1, "for {ancestor} {status}");
        assert_lifecycle_error(&fires[0], code);
        assert!(
            state
                .repositories
                .self_hosted_run_dispatches()
                .await
                .is_empty(),
            "background lifecycle refusal for {ancestor} {status} must not leave worker work"
        );
        assert!(
            state.repositories.agent_runs().await.is_empty(),
            "background lifecycle refusal for {ancestor} {status} must not create agent runs"
        );
    }
}

#[tokio::test]
async fn run_now_refuses_inactive_tenancy_and_resumes_after_reactivation() {
    let state = AppState::new(scheduler_enabled_config());
    seed_active_scope(&state).await;
    let mut schedule = interval_schedule("manual-agent-run-lifecycle", i64::MAX / 2);
    schedule.target_kind = ScheduleTargetKind::AgentRun;
    schedule.target_json = "{}".into();
    state
        .repositories
        .upsert_agent_schedule(schedule.clone())
        .await
        .expect("seed active schedule");

    set_lifecycle_status(&state, "project", "disabled").await;
    let refused = state
        .run_agent_schedule_now(
            &schedule,
            Some(&ScheduleFireCorrelation {
                request_id: "fg-run-now-lifecycle-refused",
                trace_id: Some("trace-run-now-lifecycle-refused"),
            }),
        )
        .await
        .expect("run-now records refused fire");
    assert_lifecycle_error(&refused, "tenancy_disabled");
    assert!(
        state.repositories.agent_runs().await.is_empty(),
        "run-now lifecycle refusal must not create an agent run"
    );
    assert!(
        state
            .repositories
            .self_hosted_run_dispatches()
            .await
            .is_empty(),
        "run-now lifecycle refusal must not enqueue worker work"
    );

    set_lifecycle_status(&state, "project", "active").await;
    let accepted = state
        .run_agent_schedule_now(
            &schedule,
            Some(&ScheduleFireCorrelation {
                request_id: "fg-run-now-lifecycle-reactivated",
                trace_id: Some("trace-run-now-lifecycle-reactivated"),
            }),
        )
        .await
        .expect("run-now records reactivated fire");
    assert_eq!(accepted.outcome, ScheduleFireOutcome::Dispatched);
    assert_eq!(accepted.dispatch_id, None);
    let run_id = accepted.run_id.as_deref().expect("reactivated run linked");
    let run = state
        .agent_run_record(run_id)
        .expect("reactivated run created");
    assert_eq!(run.status, "running");
    assert_eq!(run.tenant.organization_id.as_deref(), Some("tenant-a"));
    assert_eq!(run.tenant.workspace_id.as_deref(), Some("ws-a"));
}
