// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-23
// description: Unit tests for the async agent-workflow gating readers
// (issue #372 — finishing #330's read-side). Proves the now-`async`
// `workflow_run_started_at` / `workflow_run_last_successful_node_id` /
// `workflow_edge_transition_error` return the correct allow/deny/values, with
// tenant scoping preserved, once the `block_on_sync_bridge` was dropped. Kept
// outside business logic per the testing-architecture layout.

use super::*;
use crate::config::{AgentWorkflowEdge, AgentWorkflowNode, AgentWorkflowNodeKind};

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn workflow_request_log(org: &str, node: &str, status: u16, ts: u64) -> StoredRequestLog {
    StoredRequestLog {
        request_id: format!("req-{org}-{node}-{ts}"),
        trace_id: None,
        agent_run_id: Some("shared-run-id".into()),
        workflow_id: Some("wf".into()),
        workflow_version: Some(1),
        workflow_node_id: Some(node.into()),
        cluster_id: None,
        node_id: None,
        tenant: ferrogate_core::TenantContext {
            organization_id: Some(org.to_string()),
            ..Default::default()
        },
        route: None,
        provider: None,
        logical_model: None,
        provider_model: None,
        gateway_config_id: None,
        gateway_config_revision: None,
        status_code: status,
        error_code: None,
        prompt_recorded: false,
        response_recorded: false,
        prompt_body: None,
        response_body: None,
        cache_status: None,
        started_at_unix: Some(ts),
        completed_at_unix: Some(ts),
        parent_action_fingerprint: None,
    }
}

fn edge_workflow() -> AgentWorkflowPolicy {
    // Linear graph: start -> review. Only that transition is legal; `review`
    // has an incoming edge so it cannot be the run's first node.
    AgentWorkflowPolicy {
        id: "wf".into(),
        name: "wf".into(),
        version: 1,
        enabled: true,
        organization_ids: Vec::new(),
        project_ids: Vec::new(),
        api_key_ids: Vec::new(),
        nodes: vec![
            AgentWorkflowNode {
                id: "start".into(),
                kind: AgentWorkflowNodeKind::Model,
                model: None,
                providers: Vec::new(),
                tool: None,
                max_iterations: None,
                token_budget: None,
            },
            AgentWorkflowNode {
                id: "review".into(),
                kind: AgentWorkflowNodeKind::Model,
                model: None,
                providers: Vec::new(),
                tool: None,
                max_iterations: None,
                token_budget: None,
            },
        ],
        edges: vec![AgentWorkflowEdge {
            from: "start".into(),
            to: "review".into(),
            condition: None,
        }],
        max_model_calls: None,
        max_tool_calls: None,
        max_parallelism: None,
        max_iterations: None,
        timeout_millis: None,
        token_budget: None,
    }
}

#[test]
fn workflow_run_started_at_is_scoped_to_the_callers_tenant() {
    // #228: agent_run_id is client-supplied and not tenant-namespaced. A request
    // log recorded for tenant-a's run must NOT feed tenant-b's (or an
    // operator's) run-gating just because tenant-b reuses the id. #372: the
    // reader is now async and awaited (no `block_on_sync_bridge`).
    let state = AppState::new(Config::default());
    state.record_request_log(workflow_request_log("tenant-a", "start", 200, 100));

    // tenant-a sees its own run start; tenant-b (same agent_run_id) does not,
    // and neither does a platform operator (org None).
    assert_eq!(
        block_on(state.workflow_run_started_at("wf", 1, "shared-run-id", Some("tenant-a"))),
        Some(100),
    );
    assert_eq!(
        block_on(state.workflow_run_started_at("wf", 1, "shared-run-id", Some("tenant-b"))),
        None,
        "tenant-b must not read tenant-a's run timestamps via a shared agent_run_id",
    );
    assert_eq!(
        block_on(state.workflow_run_started_at("wf", 1, "shared-run-id", None)),
        None,
        "an operator must not inherit a tenant's run start",
    );
}

#[test]
fn workflow_run_last_successful_node_id_is_scoped_and_tracks_latest_success() {
    let state = AppState::new(Config::default());
    // Two successful steps for tenant-a; the later one (higher ts) wins.
    state.record_request_log(workflow_request_log("tenant-a", "start", 200, 100));
    state.record_request_log(workflow_request_log("tenant-a", "review", 200, 200));
    // A failed step must not become the "last successful" node.
    state.record_request_log(workflow_request_log("tenant-a", "publish", 500, 300));

    assert_eq!(
        block_on(state.workflow_run_last_successful_node_id(
            "wf",
            1,
            "shared-run-id",
            Some("tenant-a"),
        )),
        Some("review".into()),
        "the latest 2xx node wins and a 5xx step is ignored",
    );
    assert_eq!(
        block_on(state.workflow_run_last_successful_node_id(
            "wf",
            1,
            "shared-run-id",
            Some("tenant-b"),
        )),
        None,
        "tenant-b must not read tenant-a's node history via a shared agent_run_id",
    );
}

#[test]
fn workflow_edge_transition_error_allows_legal_transitions_and_denies_others() {
    let state = AppState::new(Config::default());
    let workflow = edge_workflow();
    let org = Some("tenant-a");

    // No prior successful node yet: a node WITH incoming edges cannot start the
    // run (deny), but the graph's entry node (no incoming edges) may (allow).
    assert!(
        block_on(state.workflow_edge_transition_error(&workflow, "shared-run-id", "review", org))
            .is_some(),
        "review has incoming edges and must not start the run",
    );
    assert!(
        block_on(state.workflow_edge_transition_error(&workflow, "shared-run-id", "start", org))
            .is_none(),
        "start has no incoming edges and may open the run",
    );

    // Record a successful `start`; now `start -> review` is legal, but any
    // transition not backed by a configured edge is denied.
    state.record_request_log(workflow_request_log("tenant-a", "start", 200, 100));
    assert!(
        block_on(state.workflow_edge_transition_error(&workflow, "shared-run-id", "review", org))
            .is_none(),
        "start -> review is a configured edge and must be allowed",
    );
    assert!(
        block_on(state.workflow_edge_transition_error(&workflow, "shared-run-id", "start", org))
            .is_none(),
        "re-entering the same node is allowed",
    );
    assert!(
        block_on(state.workflow_edge_transition_error(&workflow, "shared-run-id", "ghost", org))
            .is_some(),
        "a transition with no configured edge must be denied",
    );

    // Edge-less workflows have no transition gate at all.
    let mut open = edge_workflow();
    open.edges.clear();
    assert!(
        block_on(state.workflow_edge_transition_error(&open, "shared-run-id", "review", org))
            .is_none(),
        "a workflow with no edges never denies a transition",
    );
}
