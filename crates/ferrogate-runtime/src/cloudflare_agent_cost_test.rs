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
use std::time::Duration;

use ferrogate_storage::{RuntimeStorageRepositories, StorageProviderKind};

use super::{
    evaluate, should_dispatch, AgentBudgetPolicy, AgentBurnLedger, AgentBurnLedgerError,
    AgentCostAttribution, AgentCostGovernor, AgentCostReceipt, AgentRuntimeUsageSample,
    AgentRuntimeUsageSource, BudgetDecision, CancelSettleWindow, CfRuntimeCostModel,
    CfRuntimePricing, ContainerUsageSample, CostGovernorError, CostWindow, InMemoryAgentBurnLedger,
    KillMode, ScriptedUsageSource, StorageAgentBurnLedger,
    DEFAULT_CONTAINER_DISK_USD_PER_GB_SECOND, DEFAULT_CONTAINER_EGRESS_USD_PER_GB,
    DEFAULT_CONTAINER_MEMORY_USD_PER_GIB_SECOND, DEFAULT_CONTAINER_VCPU_USD_PER_SECOND,
    DEFAULT_DO_REQUEST_USD_PER_MILLION, DEFAULT_DURATION_USD_PER_MILLION_GB_SECONDS,
    DEFAULT_SQLITE_ROWS_READ_USD_PER_MILLION, DEFAULT_SQLITE_ROWS_WRITTEN_USD_PER_MILLION,
    DEFAULT_STORAGE_USD_PER_GB_MONTH, DEFAULT_WARN_FRACTION, SECONDS_PER_BILLING_MONTH,
    WEBSOCKET_MESSAGES_PER_BILLED_REQUEST,
};
use crate::cloudflare_agent_memory::AgentInstanceIdentity;
use crate::cloudflare_worker::{
    CloudflareRunStatus, MockCloudflareCall, MockCloudflareControlSurface,
};

/// tokio's `macros`/test features are not enabled for this crate, so drive async
/// entry points on a bare current-thread runtime. The timer IS enabled: a
/// `KillMode::Cancel` settle window with a non-zero backoff awaits `sleep`, and
/// without a time driver that is a panic rather than a wait.
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
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
    // Cloudflare Containers coefficients (#473).
    assert_close(
        p.container_vcpu_usd_per_second,
        DEFAULT_CONTAINER_VCPU_USD_PER_SECOND,
        "container vcpu price",
    );
    assert_close(
        p.container_memory_usd_per_gib_second,
        DEFAULT_CONTAINER_MEMORY_USD_PER_GIB_SECOND,
        "container memory price",
    );
    assert_close(
        p.container_disk_usd_per_gb_second,
        DEFAULT_CONTAINER_DISK_USD_PER_GB_SECOND,
        "container disk price",
    );
    assert_close(
        p.container_egress_usd_per_gb,
        DEFAULT_CONTAINER_EGRESS_USD_PER_GB,
        "container egress price",
    );
}

#[test]
fn container_pricing_defaults_are_the_published_cloudflare_rates() {
    // Pinned so a silent edit to a rate is a failing test, not a mis-bill.
    // Source: <https://developers.cloudflare.com/containers/pricing/> (2026-07).
    assert_close(DEFAULT_CONTAINER_VCPU_USD_PER_SECOND, 0.000_020, "vCPU-s");
    assert_close(
        DEFAULT_CONTAINER_MEMORY_USD_PER_GIB_SECOND,
        0.000_002_5,
        "GiB-s",
    );
    assert_close(
        DEFAULT_CONTAINER_DISK_USD_PER_GB_SECOND,
        0.000_000_07,
        "GB-s",
    );
    // Region-tiered egress; the default is the North America & Europe rate.
    assert_close(DEFAULT_CONTAINER_EGRESS_USD_PER_GB, 0.025, "egress NA/EU");
    assert_close(
        super::CONTAINER_EGRESS_USD_PER_GB_OCEANIA_KOREA_TAIWAN,
        0.05,
        "egress Oceania/KR/TW",
    );
    assert_close(super::CONTAINER_EGRESS_USD_PER_GB_ROW, 0.04, "egress RoW");
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
        container: Some(ContainerUsageSample::zero()),    // present feed, $0.00
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
    assert_eq!(
        b.container_usd,
        Some(0.0),
        "present container feed, no burn"
    );
    assert!(b.total_is_complete(), "every class priced");
    assert_close(b.total_usd, 55.26, "total");
    assert_close(model.cost_usd(&sample), 55.26, "cost_usd == total");
}

// ---------------------------------------------------------------------------
// Cloudflare Containers cost arithmetic (#473)
// ---------------------------------------------------------------------------

/// A container-only sample: the four CF Containers meters, no DO/Workers or
/// model spend, so each class is asserted in isolation.
fn container_only(container: ContainerUsageSample) -> AgentRuntimeUsageSample {
    AgentRuntimeUsageSample {
        container: Some(container),
        ..AgentRuntimeUsageSample::zero()
    }
}

#[test]
fn container_cost_breakdown_is_exact_on_known_inputs() {
    // Published CF Containers rates (Workers Paid), chosen to land on round USD:
    //   vCPU   1_000_000 vCPU-s   * $0.000020   = $20.00
    //   memory 4_000_000 GiB-s    * $0.0000025  = $10.00
    //   disk 100_000_000 GB-s     * $0.00000007 =  $7.00
    //   egress       400 GB       * $0.025      = $10.00
    //                                    subtotal $47.00
    let sample = container_only(ContainerUsageSample {
        vcpu_seconds: 1_000_000.0,
        memory_gib_seconds: 4_000_000.0,
        disk_gb_seconds: 100_000_000.0,
        network_egress_gb: 400.0,
    });
    let model = CfRuntimeCostModel::new();
    let b = model.breakdown(&sample);

    assert_close(b.container_vcpu_usd.expect("vcpu"), 20.0, "container vcpu");
    assert_close(
        b.container_memory_usd.expect("memory"),
        10.0,
        "container memory",
    );
    assert_close(b.container_disk_usd.expect("disk"), 7.0, "container disk");
    assert_close(
        b.container_egress_usd.expect("egress"),
        10.0,
        "container egress",
    );
    assert_close(
        b.container_usd.expect("subtotal"),
        47.0,
        "container subtotal",
    );

    // Container spend is its OWN resource class: nothing leaked into the
    // DO/Workers buckets or the model-spend pass-through.
    assert_close(b.duration_usd, 0.0, "not folded into DO duration");
    assert_close(b.do_requests_usd, 0.0, "not folded into DO requests");
    assert_close(b.storage_usd, 0.0, "not folded into DO storage");
    assert_close(b.metered_egress_usd, 0.0, "not folded into model egress");

    assert!(b.total_is_complete(), "container feed present");
    assert_close(b.total_usd, 47.0, "total");
    assert_close(model.cost_usd(&sample), 47.0, "cost_usd == total");
}

#[test]
fn container_cost_adds_to_the_do_workers_total_without_double_counting() {
    // The DO/Workers sample from `cost_breakdown_is_exact_on_known_inputs`
    // ($55.26) plus the $47.00 container sample above: the two tiers are
    // additive, and `total_usd` stays the sum of the per-class fields.
    let sample = AgentRuntimeUsageSample {
        do_requests: 2_000_000,
        duration_gb_seconds: 4_000_000.0,
        sqlite_rows_read: 10_000_000,
        sqlite_rows_written: 3_000_000,
        stored_bytes: 2_000_000_000,
        stored_window_seconds: SECONDS_PER_BILLING_MONTH,
        ws_inbound_messages: 40_000_000,
        metered_egress_usd: 1.25,
        container: Some(ContainerUsageSample {
            vcpu_seconds: 1_000_000.0,
            memory_gib_seconds: 4_000_000.0,
            disk_gb_seconds: 100_000_000.0,
            network_egress_gb: 400.0,
        }),
    };
    let b = CfRuntimeCostModel::new().breakdown(&sample);
    assert_close(b.container_usd.expect("container"), 47.0, "container class");
    assert_close(b.total_usd, 102.26, "55.26 DO/Workers + 47.00 container");

    // `total_usd` is exactly the sum of every per-class field.
    let summed = b.do_requests_usd
        + b.duration_usd
        + b.sqlite_rows_read_usd
        + b.sqlite_rows_written_usd
        + b.storage_usd
        + b.websocket_usd
        + b.metered_egress_usd
        + b.container_vcpu_usd.expect("vcpu")
        + b.container_memory_usd.expect("memory")
        + b.container_disk_usd.expect("disk")
        + b.container_egress_usd.expect("egress");
    assert_close(b.total_usd, summed, "total == sum of per-class fields");
}

#[test]
fn container_pricing_is_configurable_without_code_change() {
    // Every container coefficient is overridable; doubling each doubles its
    // class exactly, and nothing else moves.
    let pricing = CfRuntimePricing {
        container_vcpu_usd_per_second: DEFAULT_CONTAINER_VCPU_USD_PER_SECOND * 2.0,
        container_memory_usd_per_gib_second: DEFAULT_CONTAINER_MEMORY_USD_PER_GIB_SECOND * 2.0,
        container_disk_usd_per_gb_second: DEFAULT_CONTAINER_DISK_USD_PER_GB_SECOND * 2.0,
        // A deployment outside NA/EU overrides to the published regional rate.
        container_egress_usd_per_gb: super::CONTAINER_EGRESS_USD_PER_GB_OCEANIA_KOREA_TAIWAN,
        ..CfRuntimePricing::default()
    };
    let sample = container_only(ContainerUsageSample {
        vcpu_seconds: 1_000_000.0,
        memory_gib_seconds: 4_000_000.0,
        disk_gb_seconds: 100_000_000.0,
        network_egress_gb: 400.0,
    });
    let b = CfRuntimeCostModel::with_pricing(pricing).breakdown(&sample);
    assert_close(b.container_vcpu_usd.expect("vcpu"), 40.0, "doubled vcpu");
    assert_close(b.container_memory_usd.expect("mem"), 20.0, "doubled memory");
    assert_close(b.container_disk_usd.expect("disk"), 14.0, "doubled disk");
    // 400 GB * $0.05 = $20.00 at the Oceania/Korea/Taiwan rate.
    assert_close(b.container_egress_usd.expect("egress"), 20.0, "region rate");
    assert_close(b.total_usd, 94.0, "overridden coefficients drive the total");
}

// ---------------------------------------------------------------------------
// Absent container telemetry is UNAVAILABLE, never zero (#473; cf. #458/#464)
// ---------------------------------------------------------------------------

#[test]
fn absent_container_telemetry_does_not_read_as_zero_cost() {
    let model = CfRuntimeCostModel::new();

    // (a) Feed ABSENT: every container class is `None`, the total is flagged
    //     incomplete, and NOTHING anywhere claims $0.00 of container spend.
    let absent = AgentRuntimeUsageSample::zero().without_container_telemetry();
    assert_eq!(absent.container, None, "no container feed");
    let b = model.breakdown(&absent);
    assert_eq!(b.container_vcpu_usd, None, "vcpu unknown, not zero");
    assert_eq!(b.container_memory_usd, None, "memory unknown, not zero");
    assert_eq!(b.container_disk_usd, None, "disk unknown, not zero");
    assert_eq!(b.container_egress_usd, None, "egress unknown, not zero");
    assert_eq!(b.container_usd, None, "subtotal unknown, not zero");
    assert!(b.container_cost_is_unavailable(), "flagged unavailable");
    assert!(!b.total_is_complete(), "total is only a lower bound");

    // (b) Feed PRESENT and genuinely zero: a DIFFERENT, stronger claim.
    let present_zero = AgentRuntimeUsageSample::zero();
    let b0 = model.breakdown(&present_zero);
    assert_eq!(b0.container_usd, Some(0.0), "feed answered: really $0.00");
    assert!(!b0.container_cost_is_unavailable(), "not unavailable");
    assert!(b0.total_is_complete(), "total is the whole cost");

    // The two states are not equal — `None` can never be mistaken for zero.
    assert_ne!(b.container_usd, b0.container_usd);

    // (c) On the wire the absent feed is an explicit `null`, never `0`, and it
    //     is NOT omitted from the JSON.
    let json = serde_json::to_value(&b).expect("serialize breakdown");
    assert!(json.get("containerUsd").is_some(), "field is emitted");
    assert!(json["containerUsd"].is_null(), "null, not 0");
    assert!(json["containerVcpuUsd"].is_null(), "null, not 0");

    // (d) The durable receipt hoists the flag to the top level, so an operator
    //     reading a receipt knows the burn it acted on was a lower bound.
    let id = identity("run-1");
    let policy = AgentBudgetPolicy::new(100.0, "v1");
    let decision = evaluate(&policy, 0.0, b.total_usd);
    let receipt = AgentCostReceipt::assemble(&id, &absent, &b, b.total_usd, &policy, decision)
        .expect("build");
    assert!(
        receipt.container_cost_unavailable,
        "receipt says container cost is unknown"
    );
    let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
    assert_eq!(receipt_json["containerCostUnavailable"], true);
    assert!(receipt_json["sample"]["container"].is_null(), "sample null");
    let restored: AgentCostReceipt =
        serde_json::from_value(receipt_json).expect("deserialize receipt");
    assert_eq!(restored, receipt, "unavailability survives a round trip");
}

#[test]
fn a_pre_473_sample_deserializes_as_unavailable_not_zero() {
    // A usage sample minted before #473 carries no `container` key at all. The
    // only honest reading is "we do not know", so it must land as `None`.
    let legacy = serde_json::json!({
        "doRequests": 1_000_000,
        "durationGbSeconds": 0.0,
        "sqliteRowsRead": 0,
        "sqliteRowsWritten": 0,
        "storedBytes": 0,
        "storedWindowSeconds": 0.0,
        "wsInboundMessages": 0,
        "meteredEgressUsd": 0.0
    });
    let sample: AgentRuntimeUsageSample = serde_json::from_value(legacy).expect("deserialize");
    assert_eq!(sample.container, None, "legacy record: container unknown");
    let b = CfRuntimeCostModel::new().breakdown(&sample);
    assert!(b.container_cost_is_unavailable());
    assert!(!b.total_is_complete());

    // A pricing config written before #473 likewise falls back to the CF list
    // rates, NOT to 0.0 — a zero coefficient would re-introduce "containers are
    // free" through the config file.
    let legacy_pricing = serde_json::json!({
        "doRequestUsdPerMillion": 0.15,
        "durationUsdPerMillionGbSeconds": 12.50,
        "sqliteRowsReadUsdPerMillion": 0.001,
        "sqliteRowsWrittenUsdPerMillion": 1.00,
        "storageUsdPerGbMonth": 0.20,
        "websocketMessagesPerBilledRequest": 20.0
    });
    let pricing: CfRuntimePricing = serde_json::from_value(legacy_pricing).expect("deserialize");
    assert_close(
        pricing.container_vcpu_usd_per_second,
        DEFAULT_CONTAINER_VCPU_USD_PER_SECOND,
        "legacy config keeps the list rate, not 0",
    );
    assert_close(
        pricing.container_memory_usd_per_gib_second,
        DEFAULT_CONTAINER_MEMORY_USD_PER_GIB_SECOND,
        "legacy config keeps the list rate, not 0",
    );
    assert_close(
        pricing.container_disk_usd_per_gb_second,
        DEFAULT_CONTAINER_DISK_USD_PER_GB_SECOND,
        "legacy config keeps the list rate, not 0",
    );
    assert_close(
        pricing.container_egress_usd_per_gb,
        DEFAULT_CONTAINER_EGRESS_USD_PER_GB,
        "legacy config keeps the list rate, not 0",
    );
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
    governor_with_surface(ceiling, MockCloudflareControlSurface::new())
}

/// A governor over a specific control-surface double — used to script what the
/// run reports AFTER a cooperative cancel.
fn governor_with_surface(
    ceiling: f64,
    surface: MockCloudflareControlSurface,
) -> AgentCostGovernor<MockCloudflareControlSurface, InMemoryAgentBurnLedger> {
    AgentCostGovernor::new(
        CfRuntimeCostModel::new(),
        AgentBudgetPolicy::new(ceiling, "v1"),
        InMemoryAgentBurnLedger::new(),
        surface,
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
fn kill_in_cancel_mode_cancels_then_verifies_and_escalates_when_the_run_survives() {
    // ISSUE #414 ITEM 1, THE MONEY PATH. `cancel_run` is COOPERATIVE — the
    // gateway Worker aborts a signal the workload observes; there is no fiber
    // primitive in the pinned SDK. A workload that IGNORES the signal keeps
    // running and keeps spending, so a budget kill that stopped at "cancel
    // returned Stopped" reported a kill it had not performed. `KillMode::Cancel`
    // therefore re-reads the run and destroys it when it is still alive.
    //
    // WHY `Running` IS A REACHABLE POST-CANCEL STATUS. It was not, for a while:
    // the Worker's `cancel` wrote `status:"stopped"` unconditionally, so the only
    // status this escalation could ever observe was the terminal one the cancel
    // itself had written, and the scripted `Running` below described a run the
    // deployed Worker could not produce. The Worker now leaves the status alone
    // when it merely SIGNALLED a workload, so a defiant run really does read
    // `running` here — see `workers/agent-gateway/test/lifecycle.test.ts`,
    // "a cancel the workload IGNORES is NOT reported as stopped".
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    // The surface keeps reporting Running after the cancel: the workload
    // ignored the signal.
    let mut gov = governor_with_surface(
        1.0,
        MockCloudflareControlSurface::new().reporting_status(CloudflareRunStatus::Running),
    )
    .with_kill_mode(KillMode::Cancel)
    // A run that NEVER settles exhausts the window whatever its size; pin it to
    // one read so this case asserts the escalation, not the wait.
    .with_cancel_settle_window(CancelSettleWindow::IMMEDIATE);
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");
    assert!(matches!(receipt.decision, BudgetDecision::Kill { .. }));

    match gov.control().calls() {
        [MockCloudflareCall::CancelRun { run_ref, reason }, MockCloudflareCall::RunStatus { run_ref: checked }, MockCloudflareCall::CleanupRun { run_ref: killed }] =>
        {
            assert_eq!(run_ref, "fg.tenant-a.sess-1.run-1");
            assert!(!reason.is_empty(), "cancel carries the kill reason");
            assert_eq!(checked, run_ref, "the SAME instance must be verified");
            assert_eq!(killed, run_ref, "and the SAME instance destroyed");
        }
        other => panic!("expected cancel -> status -> cleanup, got {other:?}"),
    }
}

#[test]
fn kill_in_cancel_mode_does_not_destroy_a_run_the_cancel_actually_stopped() {
    // The other half: when the workload DID honor the abort signal, the soft
    // path is enough and the instance is left alone. Without this, the
    // escalation above would just be "always destroy" wearing a cancel costume.
    //
    // `Stopped` is only a truthful input here because the Worker writes it from
    // the invoke path after a workload has actually unwound — see
    // `kill_is_settled`'s doc for what goes wrong when a cancel stamps it itself.
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor_with_surface(
        1.0,
        MockCloudflareControlSurface::new().reporting_status(CloudflareRunStatus::Stopped),
    )
    .with_kill_mode(KillMode::Cancel);
    block_on(gov.enforce(&id, sample)).expect("enforce");

    let calls = gov.control().calls();
    assert!(
        matches!(
            calls,
            [
                MockCloudflareCall::CancelRun { .. },
                MockCloudflareCall::RunStatus { .. }
            ]
        ),
        "expected cancel -> status and NO cleanup, got {calls:?}"
    );
}

#[test]
fn kill_in_cancel_mode_waits_out_a_workload_that_is_still_unwinding() {
    // ISSUE #414 REWORK. The escalation's input is a race, not a fact. The
    // Worker writes `stopped` from the invoke path only after a signalled
    // workload has actually unwound, and the dispatch contract is written for
    // harnesses that thread `signal` through real I/O — so a workload that is
    // OBEYING the cancel still reads `running` for the first read or two.
    //
    // Without a settle window, `KillMode::Cancel`'s documented "softer stop
    // that tries to preserve the instance" is unreachable for any non-instant
    // unwind: the single immediate read sees `running` and `cleanup_run` DROPs
    // the run's state, chat history, schedules and credential records. Here the
    // run settles on the third read, inside the window, so it must survive.
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let mut gov = governor_with_surface(
        1.0,
        MockCloudflareControlSurface::new().scripting_statuses([
            CloudflareRunStatus::Running,
            CloudflareRunStatus::Running,
            CloudflareRunStatus::Stopped,
        ]),
    )
    .with_kill_mode(KillMode::Cancel)
    // Zero backoff: the window's SHAPE (re-read until settled) is what is under
    // test, and a wall-clock delay would only make the suite slower.
    .with_cancel_settle_window(CancelSettleWindow::new(3, Duration::ZERO));
    block_on(gov.enforce(&id, sample)).expect("enforce");

    let calls = gov.control().calls();
    assert!(
        matches!(
            calls,
            [
                MockCloudflareCall::CancelRun { .. },
                MockCloudflareCall::RunStatus { .. },
                MockCloudflareCall::RunStatus { .. },
                MockCloudflareCall::RunStatus { .. }
            ]
        ),
        "a run that settles inside the window must NOT be destroyed, got {calls:?}"
    );
}

#[test]
fn cancel_settle_window_is_bounded_so_a_defiant_run_is_still_destroyed() {
    // The other edge: the window is a grace period, not an unbounded wait. A
    // workload that ignores the signal keeps spending, so the window must
    // expire and escalate. Exactly `retries + 1` reads, then the destroy.
    let id = identity("run-1");
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 5.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let window = CancelSettleWindow::new(2, Duration::ZERO);
    assert_eq!(window.max_wait(), Duration::ZERO);
    let mut gov = governor_with_surface(
        1.0,
        MockCloudflareControlSurface::new().reporting_status(CloudflareRunStatus::Running),
    )
    .with_kill_mode(KillMode::Cancel)
    .with_cancel_settle_window(window);
    block_on(gov.enforce(&id, sample)).expect("enforce");

    let calls = gov.control().calls();
    assert!(
        matches!(
            calls,
            [
                MockCloudflareCall::CancelRun { .. },
                MockCloudflareCall::RunStatus { .. },
                MockCloudflareCall::RunStatus { .. },
                MockCloudflareCall::RunStatus { .. },
                MockCloudflareCall::CleanupRun { .. }
            ]
        ),
        "the window must expire after retries+1 reads and destroy, got {calls:?}"
    );
}

#[test]
fn the_default_cancel_settle_window_actually_waits() {
    // The default is what production runs with, and a zero-retry default would
    // silently reinstate the destroy-on-first-read behaviour this rework
    // removed while every zero-backoff test above still passed.
    let window = CancelSettleWindow::default();
    assert!(
        window.max_wait() > Duration::ZERO,
        "the default window must grant a real grace period"
    );
    assert!(
        window.max_wait() <= Duration::from_secs(1),
        "an over-budget run that ignores the signal keeps burning during the window"
    );
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

// ---------------------------------------------------------------------------
// #473: a container-heavy run now crosses the ceiling it used to slip under
// ---------------------------------------------------------------------------

/// The DO/Workers + model-spend side of one hour of a coding-agent run. Small,
/// because the agent's real work happens in the container, not the DO:
///
/// ```text
///   do_requests         200_000 /1e6 * $0.15   = $0.030
///   duration        8_000 GB-s /1e6 * $12.50   = $0.100
///   rows read     1_000_000 rows /1e6 * $0.001 = $0.001
///   rows written    100_000 rows /1e6 * $1.00  = $0.100
///   metered egress (model/tool spend)          = $0.250
///                                       total    $0.481
/// ```
const NON_CONTAINER_USD: f64 = 0.481;

/// One hour on a `standard-4` container instance (4 vCPU / 12 GiB / 20 GB disk —
/// the tier a long-running coding agent uses), at the published CF rates:
///
/// ```text
///   vCPU    4 * 3600 = 14_400 vCPU-s * $0.000020   = $0.28800
///   memory 12 * 3600 = 43_200 GiB-s  * $0.0000025  = $0.10800
///   disk   20 * 3600 = 72_000 GB-s   * $0.00000007 = $0.00504
///   egress                    2 GB   * $0.025      = $0.05000
///                                          total     $0.45104
/// ```
const CONTAINER_USD: f64 = 0.45104;

fn coding_agent_hour() -> AgentRuntimeUsageSample {
    AgentRuntimeUsageSample {
        do_requests: 200_000,
        duration_gb_seconds: 8_000.0,
        sqlite_rows_read: 1_000_000,
        sqlite_rows_written: 100_000,
        stored_bytes: 0,
        stored_window_seconds: 0.0,
        ws_inbound_messages: 0,
        metered_egress_usd: 0.25,
        container: Some(ContainerUsageSample {
            vcpu_seconds: 14_400.0,
            memory_gib_seconds: 43_200.0,
            disk_gb_seconds: 72_000.0,
            network_egress_gb: 2.0,
        }),
    }
}

#[test]
fn container_heavy_run_now_crosses_the_ceiling_it_previously_slipped_under() {
    // The budget: a $0.90 ceiling, warn at 80% = $0.72.
    const CEILING: f64 = 0.90;
    let id = identity("run-coding-agent");

    // ---- BEFORE #473: containers unpriced ---------------------------------
    // The pre-#473 model saw only the DO/Workers drivers, i.e. exactly what this
    // engine now computes when the container feed is absent: $0.481. That is
    // under the $0.72 warn threshold, so the run is ALLOWED, the kill switch
    // never fires, and the agent stays dispatchable — while really burning
    // $0.93204/hour against a $0.90 cap.
    let unpriced = coding_agent_hour().without_container_telemetry();
    let mut before = governor(CEILING);
    let r_before = block_on(before.enforce(&id, unpriced)).expect("enforce");
    assert_close(
        r_before.this_window_cost_usd,
        NON_CONTAINER_USD,
        "container spend scores as nothing",
    );
    assert!(
        matches!(r_before.decision, BudgetDecision::Allow),
        "the run slips under the ceiling: {:?}",
        r_before.decision
    );
    assert!(!r_before.threshold_crossed, "no threshold crossed");
    assert!(
        before.control().calls().is_empty(),
        "kill switch never fires on the under-counted run"
    );
    assert!(
        block_on(before.should_dispatch(&id)).expect("dispatch"),
        "the budget engine keeps admitting the run"
    );
    // ...but it is at least HONEST that it under-counted: the receipt is flagged
    // rather than silently claiming the container tier was free.
    assert!(
        r_before.container_cost_unavailable,
        "an under-counted run is flagged, not silently allowed"
    );

    // ---- AFTER #473: the same run, container feed priced -------------------
    let priced = coding_agent_hour();
    let mut after = governor(CEILING);
    let r_after = block_on(after.enforce(&id, priced)).expect("enforce");

    // Container spend lands in its OWN resource class, attributable per axis.
    let b = &r_after.breakdown;
    assert_close(b.container_vcpu_usd.expect("vcpu"), 0.288, "vcpu class");
    assert_close(b.container_memory_usd.expect("mem"), 0.108, "memory class");
    assert_close(b.container_disk_usd.expect("disk"), 0.00504, "disk class");
    assert_close(b.container_egress_usd.expect("eg"), 0.05, "egress class");
    assert_close(
        b.container_usd.expect("subtotal"),
        CONTAINER_USD,
        "container subtotal",
    );
    assert!(b.total_is_complete(), "nothing left unpriced");
    assert!(!r_after.container_cost_unavailable);

    // The total is now the truth: $0.481 + $0.45104 = $0.93204 >= the $0.90
    // ceiling. Note it also clears the $0.72 warn threshold that the unpriced
    // run ($0.481) sat comfortably below.
    assert_close(
        r_after.this_window_cost_usd,
        NON_CONTAINER_USD + CONTAINER_USD,
        "total_usd stays the sum of the per-class fields",
    );
    assert_close(r_after.this_window_cost_usd, 0.93204, "priced hourly burn");
    assert!(
        NON_CONTAINER_USD < after.policy().warn_threshold_usd(),
        "the unpriced cost was under even the warn threshold",
    );
    assert!(
        r_after.this_window_cost_usd >= CEILING,
        "the priced cost crosses the hard ceiling",
    );

    // And the enforcement actually happens: Kill, and the kill switch tears the
    // run down through the control surface with the identity-derived name.
    assert!(
        matches!(r_after.decision, BudgetDecision::Kill { .. }),
        "container-heavy run is killed: {:?}",
        r_after.decision
    );
    assert!(r_after.threshold_crossed);
    assert_eq!(
        after.control().calls(),
        &[MockCloudflareCall::CleanupRun {
            run_ref: "fg.tenant-a.sess-1.run-coding-agent".to_string(),
        }],
        "the kill switch fires on the run the identity names"
    );
    assert!(
        !block_on(after.should_dispatch(&id)).expect("dispatch"),
        "no further dispatch for the over-budget agent"
    );
}

#[test]
fn container_spend_alone_can_exhaust_a_budget() {
    // Even with ZERO model spend and a trivial DO footprint, container time
    // alone must be able to trip the budget — otherwise a purely local
    // (no-LLM-call) runaway loop in the sandbox is invisible to the cap.
    let id = identity("run-loop");
    let sample = container_only(ContainerUsageSample {
        vcpu_seconds: 14_400.0,       // 4 vCPU * 1h
        memory_gib_seconds: 43_200.0, // 12 GiB * 1h
        disk_gb_seconds: 72_000.0,    // 20 GB * 1h
        network_egress_gb: 2.0,
    });
    let mut gov = governor(0.40); // ceiling below the $0.45104 container burn
    let receipt = block_on(gov.enforce(&id, sample)).expect("enforce");
    assert_close(
        receipt.this_window_cost_usd,
        CONTAINER_USD,
        "container only",
    );
    assert_close(receipt.breakdown.metered_egress_usd, 0.0, "no model spend");
    assert!(
        matches!(receipt.decision, BudgetDecision::Kill { .. }),
        "container burn alone trips the cap: {:?}",
        receipt.decision
    );
    assert_eq!(gov.control().calls().len(), 1, "kill switch fired");
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
