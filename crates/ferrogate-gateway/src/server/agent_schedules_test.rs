// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Unit tests for the agent-schedule admin mutation -> stored
// schedule conversion (#251), kept out of the handler body.

use super::*;

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
