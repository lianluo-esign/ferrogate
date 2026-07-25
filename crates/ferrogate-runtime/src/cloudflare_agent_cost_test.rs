// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Cost-governance enforcement-core tests (issue #428, slice A) — exact cost
//   arithmetic + the WS 20:1 and egress-passthrough encodings, every budget decision
//   threshold crossing, the kill-switch invoking destroy/cancel with the identity-derived
//   instance name, the dispatch guard, receipt assembly, and per-identity attribution. No
//   network: the control surface and usage source are mocks.

use std::future::Future;
use std::sync::Arc;

use ferrogate_storage::{RuntimeStorageRepositories, StorageProviderKind};

use super::{
    evaluate, should_dispatch, AgentBudgetPolicy, AgentBurnLedger, AgentBurnLedgerError,
    AgentCostAttribution, AgentCostGovernor, AgentCostReceipt, AgentRuntimeUsageSample,
    AgentRuntimeUsageSource, BudgetDecision, CfRuntimeCostModel, CfRuntimePricing,
    CostGovernorError, CostWindow, InMemoryAgentBurnLedger, KillMode, ScriptedUsageSource,
    StorageAgentBurnLedger, DEFAULT_DO_REQUEST_USD_PER_MILLION,
    DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS, DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION,
    DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION, DEFAULT_STORAGE_USD_PER_GB_MONTH,
    DEFAULT_WARN_FRACTION, SECONDS_PER_BILLING_MONTH, WEBSOCKET_MESSAGES_PER_BILLED_REQUEST,
};
use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_worker::{MockCloudflareCall, MockCloudflareControlSurface};

/// tokio's `macros`/test features are not enabled for this crate, so drive async
/// entry points on a bare current-thread runtime (no IO/timer needed).
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build current-thread test runtime")
        .block_on(fut)
}

const EPS: f64 = 1e-9;

fn assert_close(got: f64, want: f64, what: &str) {
    assert!(
        (got - want).abs() < EPS,
        "{what}: got {got}, want {want} (delta {})",
        (got - want).abs()
    );
}

fn identity(run: &str) -> AgentInstanceIdentity {
    AgentInstanceIdentity::new("tenant-a", "sess-1", run)
}

// ---------------------------------------------------------------------------
// Cost arithmetic
// ---------------------------------------------------------------------------

#[test]
fn pricing_defaults_match_named_constants() {
    let p = CfRuntimePricing::default();
    assert_close(
        p.do_request_usd_per_million,
        DEFAULT_DO_REQUEST_USD_PER_MILLION,
        "do request price",
    );
    assert_close(
        p.duration_usd_per_million_gb_seconds,
        DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS,
        "duration price",
    );
    assert_close(
        p.sqlite_rows_read_usd_per_million,
        DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION,
        "rows read price",
    );
    assert_close(
        p.sqlite_rows_written_usd_per_million,
        DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION,
        "rows written price",
    );
    assert_close(
        p.storage_usd_per_gb_month,
        DEFAULT_STORAGE_USD_PER_GB_MONTH,
        "storage price",
    );
    assert_close(
        p.websocket_messages_per_billed_request,
        WEBSOCKET_MESSAGES_PER_BILLED_REQUEST,
        "ws ratio",
    );
}

#[test]
fn cost_breakdown_is_exact_on_known_inputs() {
    let sample = AgentRuntimeUsageSample {
        do_requests: 2_000_000,                           // 2.0 * $0.15  = $0.30
        duration_gb_seconds: 4_000_000.0,                 // 4.0 * $12.50 = $50.00
        sqlite_rows_read: 10_000_000,                     // 10.0 * $0.001 = $0.01
        sqlite_rows_written: 3_000_000,                   // 3.0 * $1.00  = $3.00
        stored_bytes: 2_000_000_000,                      // 2 GB
        stored_window_seconds: SECONDS_PER_BILLING_MONTH, // * 1 month * $0.20 = $0.40
        ws_inbound_messages: 40_000_000,                  // /20 = 2M requests * $0.15 = $0.30
        metered_egress_usd: 1.25,                         // pass-through
    };
    let model = CfRuntimeCostModel::new();
    let b = model.breakdown(&sample);
    assert_close(b.do_requests_usd, 0.30, "do requests");
    assert_close(b.duration_usd, 50.0, "duration");
    assert_close(b.sqlite_rows_read_usd, 0.01, "rows read");
    assert_close(b.sqlite_rows_written_usd, 3.00, "rows written");
    assert_close(b.storage_usd, 0.40, "storage");
    assert_close(b.websocket_usd, 0.30, "websocket");
    assert_close(b.metered_egress_usd, 1.25, "egress");
    assert_close(b.total_usd, 55.26, "total");
    assert_close(model.cost_usd(&sample), 55.26, "cost_usd == total");
}

#[test]
fn websocket_messages_are_billed_twenty_to_one() {
    // Only WS activity: 40M inbound messages -> 2M billed requests -> $0.30.
    let mut sample = AgentRuntimeUsageSample::zero();
    sample.ws_inbound_messages = 40_000_000;
    let model = CfRuntimeCostModel::new();
    let b = model.breakdown(&sample);
    assert_close(b.do_requests_usd, 0.0, "no direct do requests");
    assert_close(b.websocket_usd, 0.30, "ws billed at do-rate / 20");
    assert_close(b.total_usd, 0.30, "total");
}

#[test]
fn metered_egress_is_passed_through_not_recomputed() {
    let mut sample = AgentRuntimeUsageSample::zero();
    sample.metered_egress_usd = 7.77;
    let model = CfRuntimeCostModel::new();
    let b = model.breakdown(&sample);
    assert_close(b.metered_egress_usd, 7.77, "egress verbatim");
    assert_close(b.total_usd, 7.77, "egress is the only cost");
}

#[test]
fn pricing_is_configurable_without_code_change() {
    let pricing = CfRuntimePricing {
        do_request_usd_per_million: 0.30, // doubled list price
        ..CfRuntimePricing::default()
    };
    let model = CfRuntimeCostModel::with_pricing(pricing);
    let mut sample = AgentRuntimeUsageSample::zero();
    sample.do_requests = 1_000_000;
    assert_close(model.cost_usd(&sample), 0.30, "uses overridden coefficient");
}

// ---------------------------------------------------------------------------
// Budget evaluation
// ---------------------------------------------------------------------------

#[test]
fn evaluate_three_tier_threshold_crossings() {
    // ceiling $100, warn at 80%, no degrade tier.
    let policy = AgentBudgetPolicy::new(100.0, "v1");
    assert_close(policy.warn_threshold_usd(), 80.0, "warn threshold");

    // Under warn -> Allow.
    assert!(matches!(
        evaluate(&policy, 0.0, 10.0),
        BudgetDecision::Allow
    ));
    assert!(matches!(
        evaluate(&policy, 79.999, 0.0),
        BudgetDecision::Allow
    ));
    // Exactly at warn (boundary inclusive) -> Throttle.
    assert!(matches!(
        evaluate(&policy, 70.0, 10.0),
        BudgetDecision::Throttle { .. }
    ));
    // Between warn and ceiling -> Throttle.
    assert!(matches!(
        evaluate(&policy, 90.0, 0.0),
        BudgetDecision::Throttle { .. }
    ));
    // Just under ceiling -> still Throttle.
    assert!(matches!(
        evaluate(&policy, 99.999, 0.0),
        BudgetDecision::Throttle { .. }
    ));
    // Exactly at ceiling (boundary inclusive) -> Kill.
    assert!(matches!(
        evaluate(&policy, 60.0, 40.0),
        BudgetDecision::Kill { .. }
    ));
    // Over ceiling -> Kill.
    assert!(matches!(
        evaluate(&policy, 100.0, 50.0),
        BudgetDecision::Kill { .. }
    ));
}

#[test]
fn evaluate_four_tier_with_degrade() {
    // ceiling $100, warn 50%, degrade 80%.
    let policy = AgentBudgetPolicy::new(100.0, "v2")
        .with_warn_fraction(0.5)
        .with_degrade_fraction(0.8);
    assert_close(policy.warn_threshold_usd(), 50.0, "warn");
    assert_close(policy.degrade_threshold_usd().unwrap(), 80.0, "degrade");

    assert!(matches!(
        evaluate(&policy, 40.0, 0.0),
        BudgetDecision::Allow
    ));
    assert!(matches!(
        evaluate(&policy, 50.0, 0.0),
        BudgetDecision::Throttle { .. }
    ));
    assert!(matches!(
        evaluate(&policy, 79.0, 0.0),
        BudgetDecision::Throttle { .. }
    ));
    assert!(matches!(
        evaluate(&policy, 80.0, 0.0),
        BudgetDecision::Degrade { .. }
    ));
    assert!(matches!(
        evaluate(&policy, 95.0, 0.0),
        BudgetDecision::Degrade { .. }
    ));
    assert!(matches!(
        evaluate(&policy, 100.0, 0.0),
        BudgetDecision::Kill { .. }
    ));
}

#[test]
fn decision_labels_and_dispatch_semantics() {
    assert_eq!(BudgetDecision::Allow.class_label(), "allow");
    assert!(BudgetDecision::Allow.permits_dispatch());
    assert!(!BudgetDecision::Allow.is_terminal());

    let throttle = BudgetDecision::Throttle { reason: "r".into() };
    assert_eq!(throttle.class_label(), "throttle");
    assert!(!throttle.permits_dispatch());
    assert!(!throttle.is_terminal());

    let degrade = BudgetDecision::Degrade { reason: "r".into() };
    assert_eq!(degrade.class_label(), "degrade");
    assert!(!degrade.permits_dispatch());

    let kill = BudgetDecision::Kill { reason: "r".into() };
    assert_eq!(kill.class_label(), "kill");
    assert!(!kill.permits_dispatch());
    assert!(kill.is_terminal());
}

#[test]
fn policy_validation_rejects_malformed_shapes() {
    assert!(AgentBudgetPolicy::new(100.0, "v").validate().is_ok());
    assert!(AgentBudgetPolicy::new(0.0, "v").validate().is_err());
    assert!(AgentBudgetPolicy::new(100.0, "v")
        .with_warn_fraction(1.5)
        .validate()
        .is_err());
    // degrade below warn is rejected.
    assert!(AgentBudgetPolicy::new(100.0, "v")
        .with_warn_fraction(0.8)
        .with_degrade_fraction(0.5)
        .validate()
        .is_err());
    assert_close(
        AgentBudgetPolicy::new(100.0, "v").warn_fraction,
        DEFAULT_WARN_FRACTION,
        "default warn fraction",
    );
}

// ---------------------------------------------------------------------------
// Burn ledger
// ---------------------------------------------------------------------------

#[test]
fn in_memory_ledger_accumulates_per_identity() {
    let mut ledger = InMemoryAgentBurnLedger::new();
    let a = identity("run-a");
    let b = identity("run-b");
    assert_close(
        block_on(ledger.get(&a)).expect("get a"),
        0.0,
        "unseen is zero",
    );
    assert_close(
        block_on(ledger.add(&a, 2.5)).expect("add a"),
        2.5,
        "first add returns total",
    );
    assert_close(
        block_on(ledger.add(&a, 1.5)).expect("add a"),
        4.0,
        "second add accumulates",
    );
    assert_close(
        block_on(ledger.get(&a)).expect("get a"),
        4.0,
        "get reflects burn",
    );
    // A different run is tracked independently.
    assert_close(
        block_on(ledger.get(&b)).expect("get b"),
        0.0,
        "distinct identity untouched",
    );
    assert_close(
        block_on(ledger.add(&b, 9.0)).expect("add b"),
        9.0,
        "distinct identity",
    );
    assert_close(
        block_on(ledger.get(&a)).expect("get a"),
        4.0,
        "first identity unchanged",
    );
}

// ---------------------------------------------------------------------------
// Durable storage-backed burn ledger (#428 slice B-runtime)
// ---------------------------------------------------------------------------

/// An in-memory-backed [`RuntimeStorageRepositories`] (the same public ctor the
/// B-storage tests use) to exercise [`StorageAgentBurnLedger`] through the real
/// durable facade with no network.
fn storage_repos() -> Arc<RuntimeStorageRepositories> {
    Arc::new(RuntimeStorageRepositories::in_memory(
        vec![StorageProviderKind::Memory],
        16,
        16,
    ))
}

#[test]
fn storage_ledger_accumulates_and_reads_through_the_durable_facade() {
    let mut ledger = StorageAgentBurnLedger::new(storage_repos(), "2026-07");
    let id = identity("run-1");
    assert_close(
        block_on(ledger.get(&id)).expect("unseen"),
        0.0,
        "unseen is zero",
    );
    assert_close(
        block_on(ledger.add(&id, 2.5)).expect("add"),
        2.5,
        "first add returns durable total",
    );
    assert_close(
        block_on(ledger.add(&id, 1.5)).expect("add"),
        4.0,
        "second add accumulates durably",
    );
    assert_close(
        block_on(ledger.get(&id)).expect("read"),
        4.0,
        "get reads the durable accumulated total",
    );
}

#[test]
fn storage_ledger_folds_every_run_of_the_same_agent_into_one_budget() {
    // Two DIFFERENT runs (run_id) of the SAME agent (session_id) must share one
    // durable per-agent total — the whole point of keying on the stable agent
    // component, not the per-run id.
    let mut ledger = StorageAgentBurnLedger::new(storage_repos(), "2026-07");
    let run_a = AgentInstanceIdentity::new("tenant-a", "sess-1", "run-a");
    let run_b = AgentInstanceIdentity::new("tenant-a", "sess-1", "run-b");
    block_on(ledger.add(&run_a, 3.0)).expect("run a");
    block_on(ledger.add(&run_b, 4.0)).expect("run b");
    assert_close(
        block_on(ledger.get(&run_a)).expect("via run a"),
        7.0,
        "runs of one agent fold into a single budget",
    );
    assert_close(
        block_on(ledger.get(&run_b)).expect("via run b"),
        7.0,
        "either run observes the shared per-agent total",
    );
}

#[test]
fn storage_ledger_keeps_distinct_agents_and_periods_independent() {
    let repos = storage_repos();
    let agent1 = AgentInstanceIdentity::new("tenant-a", "agent-1", "run-x");
    let agent2 = AgentInstanceIdentity::new("tenant-a", "agent-2", "run-y");

    // Distinct agents (session_id) under one period accumulate independently.
    let mut jul = StorageAgentBurnLedger::new(repos.clone(), "2026-07");
    block_on(jul.add(&agent1, 1.0)).expect("agent1 jul");
    block_on(jul.add(&agent2, 2.0)).expect("agent2 jul");
    assert_close(
        block_on(jul.get(&agent1)).expect("a1"),
        1.0,
        "distinct agents independent",
    );
    assert_close(
        block_on(jul.get(&agent2)).expect("a2"),
        2.0,
        "distinct agents independent",
    );

    // A different PERIOD over the SAME store + agent is a separate budget.
    let mut aug = StorageAgentBurnLedger::new(repos, "2026-08");
    assert_close(
        block_on(aug.get(&agent1)).expect("aug unseen"),
        0.0,
        "a new period starts at zero",
    );
    block_on(aug.add(&agent1, 5.0)).expect("agent1 aug");
    assert_close(
        block_on(aug.get(&agent1)).expect("aug read"),
        5.0,
        "august burn is independent of july",
    );
    assert_close(
        block_on(jul.get(&agent1)).expect("jul intact"),
        1.0,
        "july total unchanged by august writes",
    );
}

/// A ledger whose reads/writes ALWAYS fail — used to prove the enforce path and
/// the dispatch guard fail **closed** (propagate the error) instead of treating a
/// storage failure as zero burn.
struct FailingLedger;

#[async_trait::async_trait]
impl AgentBurnLedger for FailingLedger {
    async fn get(&self, _identity: &AgentInstanceIdentity) -> Result<f64, AgentBurnLedgerError> {
        Err(AgentBurnLedgerError::Storage(
            "simulated store outage".into(),
        ))
    }

    async fn add(
        &mut self,
        _identity: &AgentInstanceIdentity,
        _cost_usd: f64,
    ) -> Result<f64, AgentBurnLedgerError> {
        Err(AgentBurnLedgerError::Storage(
            "simulated store outage".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Dispatch guard
// ---------------------------------------------------------------------------

#[test]
fn should_dispatch_reflects_burn_against_policy() {
    let policy = AgentBudgetPolicy::new(10.0, "v1"); // warn 8.0, kill 10.0
    let mut ledger = InMemoryAgentBurnLedger::new();
    let id = identity("run-1");

    // Fresh: allowed.
    assert!(block_on(should_dispatch(&ledger, &policy, &id)).expect("dispatch"));

    // Cross the warn threshold -> throttle -> refuse dispatch.
    block_on(ledger.add(&id, 8.5)).expect("add");
    assert!(!block_on(should_dispatch(&ledger, &policy, &id)).expect("dispatch"));

    // Cross the ceiling -> kill -> refuse dispatch.
    block_on(ledger.add(&id, 5.0)).expect("add");
    assert!(!block_on(should_dispatch(&ledger, &policy, &id)).expect("dispatch"));
}

// ---------------------------------------------------------------------------
// Receipt assembly
// ---------------------------------------------------------------------------

#[test]
fn attribution_projects_identity_and_mints_instance_name() {
    let attribution = AgentCostAttribution::from_identity(&identity("run-1")).expect("valid");
    assert_eq!(attribution.tenant_id, "tenant-a");
    assert_eq!(attribution.session_id, "sess-1");
    assert_eq!(attribution.run_id, "run-1");
    assert_eq!(attribution.instance_name, "fg.tenant-a.sess-1.run-1");

    // An invalid triple is rejected (separator inside a component).
    let bad = AgentInstanceIdentity::new("ten.ant", "s", "r");
    assert!(matches!(
        AgentCostAttribution::from_identity(&bad),
        Err(CostGovernorError::InvalidIdentity(_))
    ));
}

#[test]
fn receipt_assembles_and_round_trips_through_serde() {
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 9.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let model = CfRuntimeCostModel::new();
    let breakdown = model.breakdown(&sample);
    let policy = AgentBudgetPolicy::new(10.0, "policy-7"); // warn 8.0
    let decision = evaluate(&policy, 0.0, breakdown.total_usd); // 9.0 -> Throttle
    assert!(matches!(decision, BudgetDecision::Throttle { .. }));

    let receipt = AgentCostReceipt::assemble(&id, &sample, &breakdown, 9.0, &policy, decision)
        .expect("build");
    assert_eq!(
        receipt.attribution.instance_name,
        "fg.tenant-a.sess-1.run-1"
    );
    assert_close(receipt.this_window_cost_usd, 9.0, "window cost");
    assert_close(receipt.accumulated_burn_usd, 9.0, "accumulated");
    assert_eq!(receipt.policy_version, "policy-7");
    assert!(receipt.threshold_crossed);
    assert_eq!(receipt.decision.class_label(), "throttle");
    assert_eq!(
        receipt.audit_event_ref,
        "cost.enforcement.fg.tenant-a.sess-1.run-1.throttle"
    );

    let json = serde_json::to_value(&receipt).expect("serialize");
    assert_eq!(json["decision"]["decision"], "throttle");
    assert_eq!(
        json["attribution"]["instanceName"],
        "fg.tenant-a.sess-1.run-1"
    );
    let restored: AgentCostReceipt = serde_json::from_value(json).expect("deserialize");
    assert_eq!(restored, receipt);
}

#[test]
fn allow_receipt_has_no_threshold_crossed() {
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 1.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let model = CfRuntimeCostModel::new();
    let breakdown = model.breakdown(&sample);
    let policy = AgentBudgetPolicy::new(100.0, "v1");
    let decision = evaluate(&policy, 0.0, breakdown.total_usd);
    let receipt = AgentCostReceipt::assemble(&id, &sample, &breakdown, 1.0, &policy, decision)
        .expect("build");
    assert_eq!(receipt.decision.class_label(), "allow");
    assert!(!receipt.threshold_crossed);
}

// ---------------------------------------------------------------------------
// Enforcement wiring (control surface)
// ---------------------------------------------------------------------------

fn governor(
    ceiling: f64,
) -> AgentCostGovernor<MockCloudflareControlSurface, InMemoryAgentBurnLedger> {
    AgentCostGovernor::new(
        CfRuntimeCostModel::new(),
        AgentBudgetPolicy::new(ceiling, "v1"),
        InMemoryAgentBurnLedger::new(),
        MockCloudflareControlSurface::new(),
    )
}

#[test]
fn kill_invokes_destroy_with_identity_derived_instance_name() {
    let id = identity("run-1");
    // Cost $5 against a $1 ceiling -> Kill.
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor(1.0);
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");

    assert!(matches!(receipt.decision, BudgetDecision::Kill { .. }));
    assert!(receipt.threshold_crossed);
    assert_close(receipt.accumulated_burn_usd, 5.0, "burn recorded");

    // The mock control surface's destroy was invoked with EXACTLY the minted
    // instance name derived from the identity triple.
    assert_eq!(
        gov.control().calls(),
        &[MockCloudflareCall::CleanupRun {
            run_ref: "fg.tenant-a.sess-1.run-1".to_string(),
        }]
    );
}

#[test]
fn kill_in_cancel_mode_invokes_fiber_cancel() {
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor(1.0).with_kill_mode(KillMode::Cancel);
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");
    assert!(matches!(receipt.decision, BudgetDecision::Kill { .. }));

    match gov.control().calls() {
        [MockCloudflareCall::CancelRun { run_ref, reason }] => {
            assert_eq!(run_ref, "fg.tenant-a.sess-1.run-1");
            assert!(!reason.is_empty(), "cancel carries the kill reason");
        }
        other => panic!("expected a single CancelRun, got {other:?}"),
    }
}

#[test]
fn allow_does_not_touch_the_control_surface() {
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 1.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor(100.0);
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");
    assert!(matches!(receipt.decision, BudgetDecision::Allow));
    assert!(!receipt.threshold_crossed);
    assert!(
        gov.control().calls().is_empty(),
        "no destroy/cancel on allow"
    );
    // Still dispatchable.
    assert!(block_on(gov.should_dispatch(&id)).expect("dispatch"));
}

#[test]
fn throttle_records_burn_and_halts_dispatch_without_killing() {
    let id = identity("run-1");
    // ceiling $10, warn $8; a $9 window lands in the throttle band.
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 9.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor(10.0);
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");
    assert!(matches!(receipt.decision, BudgetDecision::Throttle { .. }));
    assert!(
        gov.control().calls().is_empty(),
        "throttle performs no control call"
    );
    // The recorded burn IS the halt-dispatch flag the guard reads.
    assert_close(
        block_on(gov.ledger().get(&id)).expect("get"),
        9.0,
        "burn recorded",
    );
    assert!(
        !block_on(gov.should_dispatch(&id)).expect("dispatch"),
        "over-warn agent is not dispatchable"
    );
}

#[test]
fn enforce_attributes_burn_per_identity() {
    let mut gov = governor(100.0);
    let run1 = identity("run-1");
    let run2 = identity("run-2");
    let s = |usd: f64| AgentRuntimeUsageSample {
        metered_egress_usd: usd,
        ..AgentRuntimeUsageSample::zero()
    };
    block_on(gov.enforce(&run1, s(3.0))).expect("run1");
    block_on(gov.enforce(&run1, s(2.0))).expect("run1 again");
    block_on(gov.enforce(&run2, s(7.0))).expect("run2");
    assert_close(
        block_on(gov.ledger().get(&run1)).expect("run1"),
        5.0,
        "run1 accumulates",
    );
    assert_close(
        block_on(gov.ledger().get(&run2)).expect("run2"),
        7.0,
        "run2 separate",
    );
}

#[test]
fn enforce_rejects_an_invalid_identity_before_any_side_effect() {
    let mut gov = governor(1.0);
    let bad = AgentInstanceIdentity::new("", "s", "r"); // empty tenant
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let err = block_on(gov.enforce(&bad, sample)).expect_err("must reject");
    assert!(matches!(err, CostGovernorError::InvalidIdentity(_)));
    assert!(
        gov.control().calls().is_empty(),
        "no control call for an invalid identity"
    );
    assert_close(
        block_on(gov.ledger().get(&bad)).expect("get"),
        0.0,
        "no burn recorded",
    );
}

#[test]
fn governor_enforces_over_a_durable_storage_ledger_per_agent() {
    // A governor wired to the DURABLE ledger: burn accumulates through the
    // ferrogate-storage facade, folds every run of the same agent, and the
    // dispatch guard reflects the durable total.
    let ledger = StorageAgentBurnLedger::new(storage_repos(), "2026-07");
    let mut gov = AgentCostGovernor::new(
        CfRuntimeCostModel::new(),
        AgentBudgetPolicy::new(10.0, "v1"), // warn $8, kill $10
        ledger,
        MockCloudflareControlSurface::new(),
    );
    let s = |usd: f64| AgentRuntimeUsageSample {
        metered_egress_usd: usd,
        ..AgentRuntimeUsageSample::zero()
    };

    // Run #1 of the agent: $4 -> Allow, durably recorded, still dispatchable.
    let run1 = AgentInstanceIdentity::new("tenant-a", "sess-1", "run-1");
    let r1 = block_on(gov.enforce(&run1, s(4.0))).expect("enforce run1");
    assert!(matches!(r1.decision, BudgetDecision::Allow));
    assert_close(r1.accumulated_burn_usd, 4.0, "durable burn recorded");
    assert!(block_on(gov.should_dispatch(&run1)).expect("dispatch"));

    // Run #2 of the SAME agent (different run_id): its $5 folds into the same
    // durable per-agent total ($9) -> Throttle; dispatch is now refused for the
    // agent regardless of which run asks.
    let run2 = AgentInstanceIdentity::new("tenant-a", "sess-1", "run-2");
    let r2 = block_on(gov.enforce(&run2, s(5.0))).expect("enforce run2");
    assert!(matches!(r2.decision, BudgetDecision::Throttle { .. }));
    assert_close(
        r2.accumulated_burn_usd,
        9.0,
        "durable per-agent burn folds across runs",
    );
    assert!(
        !block_on(gov.should_dispatch(&run1)).expect("dispatch"),
        "over-warn agent is not dispatchable via its first run either",
    );
    assert!(!block_on(gov.should_dispatch(&run2)).expect("dispatch"));
}

#[test]
fn enforce_fails_closed_when_the_ledger_errors() {
    // A ledger/storage failure must NOT be swallowed into a zero burn (which
    // would let an over-budget agent keep spending): enforce propagates the
    // error and takes NO control side effect.
    let mut gov = AgentCostGovernor::new(
        CfRuntimeCostModel::new(),
        AgentBudgetPolicy::new(1.0, "v1"),
        FailingLedger,
        MockCloudflareControlSurface::new(),
    );
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let err = block_on(gov.enforce(&id, sample)).expect_err("ledger error must propagate");
    assert!(
        matches!(err, CostGovernorError::Ledger(_)),
        "fail closed: a store error is not treated as zero burn"
    );
    assert!(
        gov.control().calls().is_empty(),
        "no destroy/cancel off a phantom zero burn"
    );
    // The dispatch guard also fails closed (propagates) rather than allowing.
    assert!(
        matches!(
            block_on(gov.should_dispatch(&id)),
            Err(CostGovernorError::Ledger(_))
        ),
        "dispatch guard fails closed on a ledger error"
    );
}

// ---------------------------------------------------------------------------
// Usage source seam
// ---------------------------------------------------------------------------

#[test]
fn enforce_from_scripted_source_matches_direct_enforce() {
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        do_requests: 1_000_000,
        metered_egress_usd: 4.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let source = ScriptedUsageSource::new().with_default(sample.clone());

    let mut gov = governor(100.0);
    let window = CostWindow::new(0, 60_000);
    let via_source =
        block_on(gov.enforce_from_source(&id, window, &source)).expect("enforce from source");

    // Same sample enforced directly yields an equal receipt.
    let mut gov2 = governor(100.0);
    let direct = block_on(gov2.enforce(&id, sample)).expect("direct enforce");
    assert_eq!(via_source, direct);
}

#[test]
fn scripted_source_can_target_a_specific_run() {
    let source = ScriptedUsageSource::new()
        .with_default(AgentRuntimeUsageSample::zero())
        .with_run_sample(
            "run-hot",
            AgentRuntimeUsageSample {
                metered_egress_usd: 42.0,
                ..AgentRuntimeUsageSample::zero()
            },
        );
    let window = CostWindow::new(0, 1000);
    let hot = block_on(source.usage_for(&identity("run-hot"), window)).expect("hot");
    assert_close(hot.metered_egress_usd, 42.0, "run-specific sample");
    let cold = block_on(source.usage_for(&identity("run-cold"), window)).expect("cold");
    assert_close(cold.metered_egress_usd, 0.0, "default sample");
}

#[test]
fn cost_window_duration_is_saturating_seconds() {
    assert_close(
        CostWindow::new(1_000, 61_000).duration_seconds(),
        60.0,
        "60s window",
    );
    // End before start does not underflow.
    assert_close(
        CostWindow::new(5_000, 1_000).duration_seconds(),
        0.0,
        "saturating",
    );
}
