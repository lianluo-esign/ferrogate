// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Coverage for the #428 slice-B-surface agent-cost-burn admin read.
// Proves the presentation projection + the never-fake-a-zero contract (a failed
// durable list becomes an explicit Unavailable, never an empty Available list),
// the period resolution (default = current billing month, honoring a valid
// ?period), and -- through the real AppState list method the handler calls --
// RBAC no-leak: a tenant-scoped read can never observe another tenant's burn.

use super::*;

use ferrogate_storage::StoredAgentCostBurn;

use crate::config::Config;
use crate::state::AppState;
use ferrogate_sync_bridge::block_on_sync_bridge;

fn stored(tenant: &str, agent: &str, period: &str, usd: f64, updated: i64) -> StoredAgentCostBurn {
    StoredAgentCostBurn {
        tenant_id: tenant.into(),
        agent_key: agent.into(),
        period: period.into(),
        accumulated_usd: usd,
        first_seen_unix: updated,
        updated_at_unix: updated,
    }
}

#[test]
fn ok_path_projects_stored_rows_to_presentation_rows_in_order() {
    let rows = vec![
        stored("tenant-a", "agent-2", "2026-07", 9.0, 1_700),
        stored("tenant-a", "agent-1", "2026-07", 3.0, 1_650),
    ];
    match build_agent_cost_burn_outcome(Ok(rows)) {
        AgentCostBurnOutcome::Available(rows) => {
            assert_eq!(rows.len(), 2);
            // Storage-provided order (biggest total first) is preserved.
            assert_eq!(rows[0].agent_key, "agent-2");
            assert_eq!(rows[0].tenant_id, "tenant-a");
            assert_eq!(rows[0].period, "2026-07");
            assert_eq!(rows[0].accumulated_usd, 9.0);
            assert_eq!(rows[0].updated_at_unix, 1_700);
            assert_eq!(rows[1].agent_key, "agent-1");
            // The projection drops internal bookkeeping (first_seen_unix): the
            // serialized row carries exactly the surface fields.
            let json = serde_json::to_value(&rows[0]).unwrap();
            assert_eq!(json["tenant_id"], "tenant-a");
            assert_eq!(json["agent_key"], "agent-2");
            assert_eq!(json["period"], "2026-07");
            assert_eq!(json["accumulated_usd"], 9.0);
            assert_eq!(json["updated_at_unix"], 1_700);
            assert!(json.get("first_seen_unix").is_none());
        }
        AgentCostBurnOutcome::Unavailable(_) => panic!("ok read must be Available"),
    }
}

#[test]
fn unavailable_store_is_not_a_fake_zero() {
    // A durable-store failure must surface as Unavailable (the handler renders a
    // 503), never as an empty Available list -- an empty list would read as
    // "this agent burned nothing", fabricating a zero.
    match build_agent_cost_burn_outcome(Err("store down".into())) {
        AgentCostBurnOutcome::Unavailable(message) => assert_eq!(message, "store down"),
        AgentCostBurnOutcome::Available(_) => {
            panic!("a store failure must not degrade to an empty available list")
        }
    }
}

#[test]
fn period_defaults_to_current_month_and_honors_a_valid_override() {
    // 2026-07-25T00:00:00Z -> 1_784_937_600. With no param, the default is the
    // current billing month derived exactly like the usage rollups.
    let now = ferrogate_storage::period_month_from_unix(1_784_937_600);
    assert_eq!(now, "2026-07");
    assert_eq!(
        resolve_agent_cost_burn_period(None, 1_784_937_600),
        "2026-07"
    );

    // A well-formed ?period wins.
    assert_eq!(
        resolve_agent_cost_burn_period(Some("2026-03"), 1_784_937_600),
        "2026-03"
    );
    // A malformed/blank period is ignored in favor of the current month (the
    // surface stays usable, never 500s on a bad param).
    assert_eq!(
        resolve_agent_cost_burn_period(Some("2026-13"), 1_784_937_600),
        "2026-07"
    );
    assert_eq!(
        resolve_agent_cost_burn_period(Some("garbage"), 1_784_937_600),
        "2026-07"
    );
    assert_eq!(
        resolve_agent_cost_burn_period(Some(""), 1_784_937_600),
        "2026-07"
    );
}

#[test]
fn query_param_extracts_period_value() {
    assert_eq!(
        query_param(Some("period=2026-05"), "period"),
        Some("2026-05")
    );
    assert_eq!(
        query_param(Some("limit=10&period=2026-05&offset=0"), "period"),
        Some("2026-05")
    );
    assert_eq!(query_param(Some("limit=10"), "period"), None);
    assert_eq!(query_param(None, "period"), None);
}

#[test]
fn tenant_scoped_read_cannot_see_another_tenants_burn() {
    // RBAC no-leak, end-to-end through the AppState method the handler calls:
    // seed two tenants' burn for the same period, then read as a tenant-scoped
    // admin. Only the caller's tenant is ever returned.
    let state = AppState::new(Config::default());
    let repositories = state.repositories_arc();
    let period = "2026-07";
    block_on_sync_bridge(repositories.add_agent_burn("tenant-a", "agent-1", period, 4.0))
        .expect("seed a1");
    block_on_sync_bridge(repositories.add_agent_burn("tenant-a", "agent-2", period, 6.0))
        .expect("seed a2");
    block_on_sync_bridge(repositories.add_agent_burn("tenant-b", "agent-9", period, 99.0))
        .expect("seed b9");

    // Tenant-scoped admin (organization_id = Some("tenant-a")): only tenant-a.
    let scoped =
        block_on_sync_bridge(state.list_agent_cost_burn(Some("tenant-a"), period)).expect("scoped");
    assert_eq!(scoped.len(), 2, "tenant-a's two agents only");
    assert!(
        scoped.iter().all(|row| row.tenant_id == "tenant-a"),
        "a tenant-scoped read must never leak another tenant's burn",
    );
    assert_eq!(scoped[0].agent_key, "agent-2", "biggest total first");

    // Platform operator (organization_id = None): the cross-tenant view.
    let operator =
        block_on_sync_bridge(state.list_agent_cost_burn(None, period)).expect("operator");
    assert_eq!(operator.len(), 3, "operator sees all tenants");
    assert_eq!(
        operator[0].tenant_id, "tenant-b",
        "biggest total across tenants"
    );
}
