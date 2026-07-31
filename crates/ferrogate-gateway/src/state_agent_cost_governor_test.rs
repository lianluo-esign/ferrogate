// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Unit tests for the #428 agent cost governor product wiring --
// proves the governor is no longer inert: default-off stays off, an over-budget
// agent is refused at admission, the kill switch destroys through the
// product-built governor, and a ledger failure refuses instead of admitting.

use super::*;

use ferrogate_runtime::{
    AgentBurnLedgerError, AgentRuntimeUsageSample, BudgetDecision, MockCloudflareCall,
    MockCloudflareControlSurface,
};

fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

const TENANT_ID: &str = "tenant-1";
const AGENT_KEY: &str = "key-1";
const RUN_ID: &str = "run-1";

/// Whether the admission lets the caller start the run: both the default-off
/// `Unbudgeted` path and a governed, under-budget `Admitted` verdict do.
fn permits_dispatch(admission: &AgentRunAdmission) -> bool {
    !matches!(admission, AgentRunAdmission::Refused { .. })
}

fn tenant() -> ferrogate_core::TenantContext {
    ferrogate_core::TenantContext {
        organization_id: Some(TENANT_ID.to_string()),
        project_id: Some("project-1".to_string()),
        workspace_id: Some("ws-1".to_string()),
        ..ferrogate_core::TenantContext::default()
    }
}

fn agent_budget_quota_policy(agent_cost_budget_usd: Option<f64>) -> StoredQuotaPolicy {
    StoredQuotaPolicy {
        id: format!("tenant:{TENANT_ID}"),
        scope_type: QuotaScopeKind::Tenant,
        scope_id: TENANT_ID.to_string(),
        model_allowlist: vec![],
        rpm_limit: None,
        tpm_limit: None,
        monthly_budget_usd: None,
        asset_storage_quota_bytes: None,
        asset_max_object_bytes: None,
        agent_cost_budget_usd,
        alert_threshold_pcts: vec![],
        monthly_egress_bytes_budget: None,
        download_rpm_limit: None,
        enabled: true,
        created_at_unix: 1,
        updated_at_unix: 1,
    }
}

/// An `AppState` whose tenant chain configures `ceiling_usd` as its agent cost
/// budget (or nothing at all when `None`).
fn state_with_agent_budget(ceiling_usd: Option<f64>) -> AppState {
    let state = AppState::new(Config::default());
    if let Some(ceiling_usd) = ceiling_usd {
        block_on(state.upsert_quota_policy(agent_budget_quota_policy(Some(ceiling_usd))))
            .expect("seed tenant quota policy");
    }
    state
}

/// Seed durable burn for this tenant/agent in the period the product governor
/// reads, through the same atomic facade the ledger writes with.
fn seed_burn(state: &AppState, usd: f64) {
    block_on(state.repositories.add_agent_burn(
        TENANT_ID,
        AGENT_KEY,
        &state.current_period_month(),
        usd,
    ))
    .expect("seed durable agent burn");
}

fn durable_burn(state: &AppState) -> Option<f64> {
    block_on(
        state
            .repositories
            .get_agent_burn(TENANT_ID, AGENT_KEY, &state.current_period_month()),
    )
    .expect("read durable agent burn")
}

// ---------------------------------------------------------------------------
// Default-off: an unbudgeted tenant must be byte-identical to the pre-#428 path
// ---------------------------------------------------------------------------

#[test]
fn an_unbudgeted_tenant_constructs_no_governor_and_dispatches_exactly_as_before() {
    // THE default-off guard. No quota policy anywhere in the chain => the
    // constructor must hand back `None` (not a zero-ceiling governor, which
    // would instantly Kill every run on every unbudgeted tenant) and admission
    // must report `Unbudgeted`, which leaves the handler on the untouched path.
    let state = state_with_agent_budget(None);

    let governor = block_on(state.agent_cost_governor(&tenant(), UnhostedAgentControlSurface))
        .expect("resolution must succeed when nothing is configured");
    assert!(
        governor.is_none(),
        "an unbudgeted tenant must construct no governor at all",
    );

    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID));
    assert_eq!(admission, AgentRunAdmission::Unbudgeted);
    assert!(permits_dispatch(&admission));

    // The default-off path must not even touch the durable ledger: no burn row
    // is created for an unbudgeted tenant's admission.
    assert_eq!(durable_burn(&state), None);
}

#[test]
fn an_unbudgeted_tenant_is_unaffected_by_burn_already_recorded_against_it() {
    // Burn can exist: `AppState::record_agent_burn` writes it from the settled
    // metering path (`state_billing_metering.rs`) for every request carrying an
    // `agent_run_id`, deliberately WITHOUT consulting whether a ceiling is
    // configured -- an operator sizes a budget from the burn they can already
    // see. With no ceiling there is nothing to breach, so admission must still
    // be the untouched default-off path.
    let state = state_with_agent_budget(None);
    seed_burn(&state, 10_000.0);

    assert_eq!(
        block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID)),
        AgentRunAdmission::Unbudgeted,
    );
}

// ---------------------------------------------------------------------------
// Governed admission
// ---------------------------------------------------------------------------

#[test]
fn a_tenant_within_budget_is_admitted_and_names_the_winning_policy_version() {
    let state = state_with_agent_budget(Some(100.0));
    seed_burn(&state, 10.0);

    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID));

    assert_eq!(
        admission,
        AgentRunAdmission::Admitted {
            // The scope that actually won the chain's `min`, so the audit trail
            // names the control-plane row that governed the run.
            policy_version: "quota:tenant:tenant-1".to_string(),
        },
    );
    assert!(permits_dispatch(&admission));
}

#[test]
fn a_tenant_over_budget_is_refused_at_admission() {
    // The core "no longer inert" proof: a configured ceiling plus durable burn
    // at/over it now REFUSES the run instead of admitting it.
    let state = state_with_agent_budget(Some(100.0));
    seed_burn(&state, 100.0);

    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID));

    let AgentRunAdmission::Refused {
        status,
        code,
        message,
    } = &admission
    else {
        panic!("an over-budget agent must be refused, got {admission:?}");
    };
    assert_eq!(*status, http::StatusCode::PAYMENT_REQUIRED);
    assert_eq!(*code, AGENT_BUDGET_EXCEEDED_CODE);
    assert!(
        message.contains("quota:tenant:tenant-1"),
        "the refusal must name the governing policy version: {message}",
    );
    assert!(!permits_dispatch(&admission));
}

#[test]
fn budget_pressure_below_the_hard_ceiling_also_halts_new_dispatch() {
    // `permits_dispatch` is true only for `Allow`: at the default 0.8 warn
    // fraction a burn of 80 against a 100 ceiling is a Throttle, which must
    // still refuse a NEW run (an existing run is not torn down there, but no
    // further spend may be started).
    let state = state_with_agent_budget(Some(100.0));
    seed_burn(&state, 80.0);

    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID));

    assert!(
        !permits_dispatch(&admission),
        "throttle-tier pressure must halt new dispatch, got {admission:?}",
    );
}

#[test]
fn burn_recorded_by_the_governor_is_what_the_next_admission_refuses_on() {
    // End-to-end through the product constructor, with no test-only ledger: the
    // governor prices a window and folds it into the DURABLE store, and the very
    // next admission reads that same store and refuses. This is the loop that
    // was previously open (a resolvable ceiling nothing consulted).
    let state = state_with_agent_budget(Some(50.0));
    let identity = AgentInstanceIdentity::new(TENANT_ID, AGENT_KEY, RUN_ID);

    assert!(
        permits_dispatch(&block_on(state.admit_agent_run(
            &tenant(),
            AGENT_KEY,
            RUN_ID
        ))),
        "a fresh agent under a 50 USD ceiling must be admitted",
    );

    let mut governor =
        block_on(state.agent_cost_governor(&tenant(), MockCloudflareControlSurface::new()))
            .expect("a configured budget must build a governor")
            .expect("a configured budget must build a governor");
    // Metered egress is a pass-through USD amount, so this window costs exactly
    // 60 USD without depending on any pricing coefficient.
    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 60.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let receipt = block_on(governor.enforce(&identity, sample)).expect("enforce the window");

    assert_eq!(receipt.accumulated_burn_usd, 60.0);
    assert_eq!(durable_burn(&state), Some(60.0));
    assert!(
        !permits_dispatch(&block_on(state.admit_agent_run(
            &tenant(),
            AGENT_KEY,
            RUN_ID
        ))),
        "the burn the governor recorded must halt the next dispatch",
    );
}

// ---------------------------------------------------------------------------
// Kill switch: the product-constructed governor destroys the over-budget run
// ---------------------------------------------------------------------------

#[test]
fn a_breach_destroys_the_run_through_the_product_constructed_governor() {
    // Same product constructor as the gateway uses, handed the mock control
    // surface so the kill switch is observable without Cloudflare. Proves the
    // governor this state builds does not merely decide `Kill` -- it issues the
    // `this.destroy()` control call against the run's minted instance name.
    let state = state_with_agent_budget(Some(50.0));
    let mut governor =
        block_on(state.agent_cost_governor(&tenant(), MockCloudflareControlSurface::new()))
            .expect("a configured budget must build a governor")
            .expect("a configured budget must build a governor");
    let identity = AgentInstanceIdentity::new(TENANT_ID, AGENT_KEY, RUN_ID);

    let sample = AgentRuntimeUsageSample {
        metered_egress_usd: 75.0,
        ..AgentRuntimeUsageSample::zero()
    };
    let receipt = block_on(governor.enforce(&identity, sample)).expect("enforce the window");

    assert!(
        matches!(receipt.decision, BudgetDecision::Kill { .. }),
        "burn past the ceiling must be a Kill, got {:?}",
        receipt.decision,
    );
    assert_eq!(
        governor.control().calls(),
        &[MockCloudflareCall::CleanupRun {
            run_ref: "fg.tenant-1.key-1.run-1".to_string(),
        }],
        "the breach must destroy exactly the run the identity names",
    );
    assert_eq!(receipt.policy_version, "quota:tenant:tenant-1");
}

#[test]
fn the_gateway_control_surface_refuses_to_fake_a_destroy_it_cannot_perform() {
    // The gateway's own agent runs are not Cloudflare-hosted, so there is no DO
    // to `destroy()`. The surface it hands the governor must report that loudly
    // rather than returning a success that never happened.
    let mut surface = UnhostedAgentControlSurface;
    let error = surface
        .cleanup_run("fg.tenant-1.key-1.run-1")
        .expect_err("an unhosted run must not report a fabricated destroy");
    assert!(
        matches!(error, CloudflareControlSurfaceError::NotReady(_)),
        "expected NotReady, got {error:?}",
    );
}

// ---------------------------------------------------------------------------
// Fail closed
// ---------------------------------------------------------------------------

#[test]
fn a_ledger_failure_refuses_dispatch_instead_of_reading_zero_burn() {
    // The fail-closed contract, provable without a durable store that can be
    // made to fail: `Err` must refuse, exactly like `Ok(false)`, and must NEVER
    // be collapsed into "no burn recorded => admit".
    let admission = agent_run_admission(
        "quota:tenant:tenant-1",
        Err(CostGovernorError::Ledger(AgentBurnLedgerError::Storage(
            "control-plane store unavailable".to_string(),
        ))),
    );

    let AgentRunAdmission::Refused {
        status,
        code,
        message,
    } = &admission
    else {
        panic!("a ledger failure must refuse dispatch, got {admission:?}");
    };
    assert_eq!(*status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(*code, AGENT_BUDGET_UNAVAILABLE_CODE);
    assert!(
        message.contains("control-plane store unavailable"),
        "the refusal must carry the underlying store failure: {message}",
    );
    assert!(!permits_dispatch(&admission));
}

#[test]
fn only_an_explicit_allow_verdict_admits_the_run() {
    // Locks the whole verdict mapping so a future refactor cannot quietly widen
    // the admitting arm.
    assert!(permits_dispatch(&agent_run_admission(
        "quota:tenant:tenant-1",
        Ok(true)
    )));
    assert!(!permits_dispatch(&agent_run_admission(
        "quota:tenant:tenant-1",
        Ok(false)
    )));
    assert!(!permits_dispatch(&agent_run_admission(
        "quota:tenant:tenant-1",
        Err(CostGovernorError::Usage("no sample".to_string())),
    )));
}

#[test]
fn a_configured_but_unusable_ceiling_refuses_instead_of_falling_back_to_unbudgeted() {
    // A garbage ceiling must not silently disable enforcement (that would be the
    // unbounded-spend hole this slice closes) and must not be treated as an
    // unbudgeted tenant.
    let state = state_with_agent_budget(Some(-5.0));

    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID));

    let AgentRunAdmission::Refused { status, code, .. } = &admission else {
        panic!("an unusable configured ceiling must refuse, got {admission:?}");
    };
    assert_eq!(*status, http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(*code, AGENT_BUDGET_UNAVAILABLE_CODE);
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

#[test]
fn burn_accumulates_per_agent_across_runs_not_per_run() {
    // The ledger keys on the STABLE agent component, so a second run of the same
    // agent inherits the first run's burn -- otherwise every run would get its
    // own untethered budget and the ceiling would never bind.
    let state = state_with_agent_budget(Some(100.0));
    seed_burn(&state, 95.0);

    assert!(
        !permits_dispatch(&block_on(state.admit_agent_run(
            &tenant(),
            AGENT_KEY,
            "a-brand-new-run"
        ))),
        "a new run of an over-budget agent must not get a fresh budget",
    );
    assert!(
        permits_dispatch(&block_on(state.admit_agent_run(
            &tenant(),
            "a-different-agent",
            RUN_ID
        ))),
        "a different agent under the same tenant keeps its own budget",
    );
}

// ---------------------------------------------------------------------------
// The burn writer: without it the ceiling can never bind
// ---------------------------------------------------------------------------

#[test]
fn settled_agent_spend_accumulates_into_the_durable_ledger_the_ceiling_reads() {
    // THE loop-closing test. Before the writer landed, `agent_cost_burn` was
    // only ever written by tests, so admission read 0.0 forever and a configured
    // ceiling could not bind no matter how much an agent spent. Deleting the
    // `record_agent_burn` call from `state_billing_metering.rs` turns this red.
    let state = state_with_agent_budget(Some(100.0));
    assert_eq!(durable_burn(&state), None, "no burn before any spend");

    let mut running = 0.0;
    for spend in [40.0, 45.0] {
        running += spend;
        let total = block_on(state.record_agent_burn(&tenant(), AGENT_KEY, RUN_ID, spend))
            .expect("a positive settled cost must be recorded");
        assert!(
            (total - running).abs() < 1e-9,
            "the ledger must return the post-add total, got {total} want {running}",
        );
    }

    // 85 USD of burn against a 100 USD ceiling is past the 0.8 warn threshold,
    // so the NEXT dispatch is refused -- the ceiling now binds on real spend.
    let admission = block_on(state.admit_agent_run(&tenant(), AGENT_KEY, "next-run"));
    let AgentRunAdmission::Refused { status, code, .. } = &admission else {
        panic!("recorded burn past the threshold must refuse the next run, got {admission:?}");
    };
    assert_eq!(*status, http::StatusCode::PAYMENT_REQUIRED);
    assert_eq!(*code, AGENT_BUDGET_EXCEEDED_CODE);
}

#[test]
fn burn_is_recorded_for_an_unbudgeted_tenant_so_an_operator_can_size_a_budget() {
    // Deliberately asymmetric with admission's default-off: writing a burn row
    // changes no request's outcome, and `GET /admin/v1/agent-cost-burn` has to
    // show spend BEFORE a ceiling exists -- that is how the ceiling gets chosen.
    let state = state_with_agent_budget(None);

    assert_eq!(
        block_on(state.record_agent_burn(&tenant(), AGENT_KEY, RUN_ID, 12.5)),
        Some(12.5),
    );
    assert_eq!(durable_burn(&state), Some(12.5));
    assert_eq!(
        block_on(state.admit_agent_run(&tenant(), AGENT_KEY, RUN_ID)),
        AgentRunAdmission::Unbudgeted,
        "recording burn must not turn an unbudgeted tenant into a governed one",
    );
}

#[test]
fn a_non_finite_or_non_positive_settled_cost_never_reaches_the_ledger() {
    // A NaN delta would poison the accumulated total permanently: every later
    // threshold comparison against NaN is false, so the ceiling silently stops
    // binding. A negative delta would let a metering bug CREDIT burn back.
    let state = state_with_agent_budget(Some(100.0));
    seed_burn(&state, 10.0);

    for delta in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
        assert_eq!(
            block_on(state.record_agent_burn(&tenant(), AGENT_KEY, RUN_ID, delta)),
            None,
            "a {delta} delta must not be written",
        );
    }
    assert_eq!(
        durable_burn(&state),
        Some(10.0),
        "the seeded total must be untouched by every rejected delta",
    );
}

#[test]
fn only_requests_carrying_an_agent_run_id_attribute_burn() {
    // This runs on EVERY metered request. A plain chat/responses request has no
    // `agent_run_id` and must never touch the burn ledger; an agent request
    // attributes to the same `(tenant, api_key_id)` pair admission reads back.
    let mut tenant = tenant();
    tenant.api_key_id = Some(AGENT_KEY.to_string());

    assert_eq!(
        AppState::agent_burn_attribution(&tenant, None),
        None,
        "a non-agent request must not attribute burn",
    );
    assert_eq!(
        AppState::agent_burn_attribution(&tenant, Some("   ")),
        None,
        "a blank agent_run_id is not a run",
    );
    assert_eq!(
        AppState::agent_burn_attribution(&tenant, Some(RUN_ID)),
        Some((AGENT_KEY, RUN_ID)),
        "the agent key must be the api key id admission keys on",
    );

    // No api key: the spend is still real, so it folds into the one legible
    // per-tenant row rather than being dropped or keyed on "".
    let mut anonymous = tenant.clone();
    anonymous.api_key_id = None;
    assert_eq!(
        AppState::agent_burn_attribution(&anonymous, Some(RUN_ID)),
        Some((UNATTRIBUTED_AGENT_KEY, RUN_ID)),
    );
}
