// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Tether-bypass detection tests (issue #471): provider usage in excess of
//   gateway-metered usage is a loud, typed breach; a missing provider source is UNATTESTED
//   (never a pass); a gateway-source failure propagates instead of faking a total bypass.

use super::{
    verdict_for, RunTokenUsage, ScriptedRunUsageSource, TetherAuditError, TetherAuditor,
    TetherTolerance, TetherVerdict, TetherWindow, UsageSource,
};
use crate::cloudflare_agent_memory::AgentInstanceIdentity;

fn identity() -> AgentInstanceIdentity {
    AgentInstanceIdentity::new("tenant-a", "sess-1", "run-9")
}

fn window() -> TetherWindow {
    TetherWindow::new(1_000, 2_000)
}

#[test]
fn matching_usage_is_tethered() {
    let gateway = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let provider = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let report = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap();
    assert_eq!(report.verdict, TetherVerdict::Tethered);
    assert!(report.verdict.is_proven_tethered());
    assert!(!report.verdict.is_breach());
}

#[test]
fn provider_usage_the_gateway_never_saw_is_a_breach() {
    let gateway = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    // The agent called the provider directly for one extra exchange.
    let provider =
        ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(9, 40_900, 8_300));
    let report = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap();
    assert!(report.verdict.is_breach(), "got {:?}", report.verdict);
    assert!(!report.verdict.is_proven_tethered());
    assert_eq!(report.verdict.severity(), "critical");
    match report.verdict {
        TetherVerdict::Breached {
            unmetered_requests,
            unmetered_input_tokens,
            unmetered_output_tokens,
        } => {
            assert_eq!(unmetered_requests, 4);
            assert_eq!(unmetered_input_tokens, 40_000 - 512);
            assert_eq!(unmetered_output_tokens, 8_000 - 512);
        }
        other => panic!("expected a breach, got {other:?}"),
    }
    assert!(report.alarm_line().contains("tether_breached"));
}

#[test]
fn small_accounting_noise_is_absorbed_by_the_tolerance() {
    let gateway = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let provider =
        ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(5, 1_400, 800));
    let report = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap();
    assert_eq!(report.verdict, TetherVerdict::Tethered);
}

#[test]
fn gateway_metering_more_than_the_provider_is_not_a_breach() {
    // Guardrail-blocked and cached requests are metered but never reach the
    // provider; that direction must never be reported as a tether failure.
    let gateway =
        ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(40, 90_000, 30_000));
    let provider = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let report = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap();
    assert_eq!(report.verdict, TetherVerdict::Tethered);
}

#[test]
fn no_provider_source_is_unattested_not_a_pass() {
    let gateway = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let report = TetherAuditor::<_, ScriptedRunUsageSource>::gateway_only(gateway)
        .audit(&identity(), &window())
        .unwrap();
    assert!(matches!(report.verdict, TetherVerdict::Unattested { .. }));
    assert!(
        !report.verdict.is_proven_tethered(),
        "an unattested run must never count as tethered"
    );
    assert_eq!(report.verdict.severity(), "warn");
    assert_eq!(report.provider, None);
    assert!(report.alarm_line().contains("provider_tokens=unknown"));
}

#[test]
fn provider_source_failure_degrades_to_unattested_carrying_the_reason() {
    let gateway = ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(4, 900, 300));
    let provider =
        ScriptedRunUsageSource::new().failing(UsageSource::ProviderAccount, "429 rate limited");
    let report = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap();
    match report.verdict {
        TetherVerdict::Unattested { reason } => assert!(reason.contains("429"), "got {reason}"),
        other => panic!("expected Unattested, got {other:?}"),
    }
}

#[test]
fn gateway_source_failure_propagates_instead_of_faking_a_total_bypass() {
    let gateway =
        ScriptedRunUsageSource::new().failing(UsageSource::GatewayMeter, "storage unavailable");
    let provider =
        ScriptedRunUsageSource::new().with_run("run-9", RunTokenUsage::new(9, 40_900, 8_300));
    let err = TetherAuditor::new(gateway, provider)
        .audit(&identity(), &window())
        .unwrap_err();
    assert!(
        matches!(err, TetherAuditError::Source { .. }),
        "got {err:?}"
    );
}

#[test]
fn tolerance_is_configurable_and_zero_slack_catches_a_single_token() {
    let verdict = verdict_for(
        &RunTokenUsage::new(1, 100, 50),
        &RunTokenUsage::new(1, 101, 50),
        &TetherTolerance {
            request_slack: 0,
            token_slack: 0,
        },
    );
    assert!(verdict.is_breach(), "got {verdict:?}");
    assert_eq!(verdict.unmetered_tokens(), 1);
}
