// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// description: Unit coverage for the #339 overview envelope assembler. Proves
// the never-fake-a-zero contract (a failed durable aggregate becomes an
// `unavailable` section with `data` absent, while runtime data stays
// available), the scope labeling, and the bounded + evidence-carrying alert
// summary -- all without a live gateway or store.

use super::*;
use ferrogate_storage::{ControlPlaneOverviewAggregate, OverviewUsageTotals};

fn sample_runtime() -> AdminOverviewRuntime {
    AdminOverviewRuntime {
        providers: AdminOverviewEnabledCount {
            total: 4,
            enabled: 3,
        },
        models: AdminOverviewEnabledCount {
            total: 10,
            enabled: 8,
        },
        static_api_keys: 2,
        prompt_templates: 1,
        upstreams: AdminOverviewEnabledCount {
            total: 0,
            enabled: 0,
        },
        routes: AdminOverviewEnabledCount {
            total: 0,
            enabled: 0,
        },
        plugins: AdminOverviewActiveCount {
            total: 3,
            active: 2,
        },
        tools: 5,
        mcp_servers: AdminOverviewMcpServers {
            total: 2,
            connected: 1,
            disconnected: 1,
        },
    }
}

#[test]
fn unavailable_aggregate_never_becomes_a_zero() {
    let overview = build_overview(
        1000,
        OverviewScope::Global,
        sample_runtime(),
        Vec::new(),
        "2026-07".into(),
        Err("boom".into()),
    );

    assert_eq!(overview.runtime.status, "ok");
    assert!(overview.runtime.data.is_some());
    assert_eq!(overview.control_plane.status, "unavailable");
    assert!(overview.control_plane.data.is_none());
    assert_eq!(overview.control_plane.error.as_deref(), Some("boom"));
    assert_eq!(overview.usage.status, "unavailable");
    assert!(overview.usage.data.is_none());

    // Alerts remain available but must declare the durable source unknown, not
    // silently report zero failures.
    assert_eq!(overview.alerts.status, "ok");
    let alerts = overview.alerts.data.as_ref().unwrap();
    assert!(alerts.unavailable_sources.contains(&"control_plane_store"));

    // The serialized JSON must not carry a fabricated `data` object for the
    // failed sections.
    let json = serde_json::to_value(&overview).unwrap();
    assert_eq!(json["control_plane"]["status"], "unavailable");
    assert!(json["control_plane"].get("data").is_none());
    assert!(json["usage"].get("data").is_none());
    assert_eq!(json["scope"]["kind"], "global");
    assert!(json["scope"].get("tenant_id").is_none());
    assert_eq!(json["object"], "control_plane.overview");
}

#[test]
fn ok_aggregate_populates_sections_and_derives_failure_alerts() {
    let mut aggregate = ControlPlaneOverviewAggregate {
        tenants: 3,
        projects: 5,
        assets: 2,
        asset_storage_bytes: 900,
        agent_runs: 4,
        usage_lifetime: OverviewUsageTotals {
            total_tokens: 500,
            ..Default::default()
        },
        usage_current_month: OverviewUsageTotals {
            total_tokens: 120,
            ..Default::default()
        },
        ..Default::default()
    };
    aggregate.agent_runs_by_status.insert("succeeded".into(), 2);
    aggregate.agent_runs_by_status.insert("failed".into(), 2);
    aggregate
        .self_hosted_workers_by_status
        .insert("draining".into(), 1);
    aggregate.self_hosted_workers = 1;

    let overview = build_overview(
        2000,
        OverviewScope::Tenant("tenant-a".into()),
        sample_runtime(),
        Vec::new(),
        "2026-07".into(),
        Ok(aggregate),
    );

    assert_eq!(overview.scope.kind, "tenant");
    assert_eq!(overview.scope.tenant_id.as_deref(), Some("tenant-a"));
    let control_plane = overview.control_plane.data.as_ref().unwrap();
    assert_eq!(control_plane.tenants, 3);
    assert_eq!(control_plane.projects, 5);
    assert_eq!(control_plane.assets.count, 2);
    assert_eq!(control_plane.assets.storage_bytes, 900);
    let usage = overview.usage.data.as_ref().unwrap();
    assert_eq!(usage.lifetime.total_tokens, 500);
    assert_eq!(usage.current_month.total_tokens, 120);
    assert_eq!(usage.current_period_month, "2026-07");

    let alerts = overview.alerts.data.as_ref().unwrap();
    assert!(alerts.unavailable_sources.is_empty());
    let failed = alerts
        .entries
        .iter()
        .find(|alert| alert.kind == "agent_runs_failed")
        .expect("a failed-agent-run alert");
    assert_eq!(failed.count, Some(2));
    // The alert carries the exact repository status label as evidence, plus a
    // follow-up admin API reference.
    let evidence = failed.evidence.iter().find(|e| e.id == "failed").unwrap();
    assert_eq!(evidence.reference.as_deref(), Some("/admin/v1/agent-runs"));
    assert!(alerts
        .entries
        .iter()
        .any(|alert| alert.kind == "self_hosted_workers_unhealthy"));
}

#[test]
fn alerts_entries_are_bounded() {
    let runtime_alerts: Vec<AdminOverviewAlert> = (0..(MAX_ALERTS + 5))
        .map(|index| AdminOverviewAlert {
            kind: "provider_unhealthy",
            severity: "critical",
            summary: format!("provider-{index}"),
            count: Some(1),
            detected_at_unix: 1,
            evidence: Vec::new(),
            evidence_truncated: false,
        })
        .collect();

    let overview = build_overview(
        1,
        OverviewScope::Global,
        sample_runtime(),
        runtime_alerts,
        "2026-07".into(),
        Err("x".into()),
    );
    let alerts = overview.alerts.data.as_ref().unwrap();
    assert!(alerts.truncated);
    assert_eq!(alerts.entries.len(), MAX_ALERTS);
}

#[test]
fn failure_alert_evidence_is_bounded() {
    let mut aggregate = ControlPlaneOverviewAggregate::default();
    for index in 0..(MAX_ALERT_EVIDENCE + 10) {
        aggregate
            .agent_runs_by_status
            .insert(format!("failed_{index:03}"), 1);
        aggregate.agent_runs += 1;
    }

    let overview = build_overview(
        1,
        OverviewScope::Global,
        sample_runtime(),
        Vec::new(),
        "2026-07".into(),
        Ok(aggregate),
    );
    let alerts = overview.alerts.data.as_ref().unwrap();
    let failed = alerts
        .entries
        .iter()
        .find(|alert| alert.kind == "agent_runs_failed")
        .unwrap();
    assert!(failed.evidence_truncated);
    assert_eq!(failed.evidence.len(), MAX_ALERT_EVIDENCE);
    // The total count still reflects every failing bucket, not the truncated
    // evidence length -- truncation bounds the evidence, never the tally.
    assert_eq!(failed.count, Some((MAX_ALERT_EVIDENCE + 10) as u64));
}

#[test]
fn status_classification_matches_terminal_states() {
    assert!(is_failure_status("failed"));
    assert!(is_failure_status("timed_out"));
    assert!(is_failure_status("error"));
    assert!(is_failure_status("aborted"));
    assert!(!is_failure_status("succeeded"));
    assert!(!is_failure_status("running"));
    assert!(!is_failure_status("completed"));

    assert!(is_worker_pressure_status("draining"));
    assert!(is_worker_pressure_status("stale"));
    assert!(is_worker_pressure_status("failed"));
    assert!(!is_worker_pressure_status("active"));
}
