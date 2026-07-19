// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-19
// description: Workflow-graph-level policy resolution for multi-step agent runs
// (issue #279). Per-request quota resolution (`quota.rs`) governs one request's
// scope chain; this module resolves the graph-level execution ENVELOPE that
// spans an entire run -- composing a workflow's caps with a node's caps
// (min-across, a node may tighten but never widen the graph ceiling), the pure
// fail-closed pre-flight of a step's spend against the durable
// `StoredWorkflowRunBudget` ledger, and the per-node model/provider allowlist
// evaluated at dispatch (before the provider call, not after).

use ferrogate_storage::{StoredWorkflowRunBudget, WorkflowBudgetDimension};

/// Fail-closed denial code: a workflow node dispatched a model its node-level
/// allowlist does not permit (issue #279 acceptance: fails closed at dispatch).
pub const WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE: &str = "workflow_node_model_not_allowed";
/// Fail-closed denial code: a workflow node dispatched to a provider its
/// node-level allowlist does not permit.
pub const WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE: &str = "workflow_node_provider_not_allowed";

/// A workflow run's execution-budget caps as expressed by CONFIG (a workflow
/// policy or one of its nodes), before it is opened into a durable
/// `StoredWorkflowRunBudget`. `None` in any dimension means "unbounded at this
/// level". Unlike the durable row, the wall-clock cap here is a relative
/// DURATION (`wall_clock_millis`), converted to an absolute deadline via
/// [`WorkflowBudgetCaps::deadline_unix`] when the run starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkflowBudgetCaps {
    /// USD cost ceiling, in integer credits (the wallet's unit).
    pub cost_budget_credits: Option<i64>,
    pub token_budget: Option<i64>,
    pub tool_call_budget: Option<i64>,
    pub wall_clock_millis: Option<u64>,
}

impl WorkflowBudgetCaps {
    /// True when no dimension is capped -- the run has no graph-level envelope
    /// and needs no durable budget row.
    pub fn is_unbounded(&self) -> bool {
        self.cost_budget_credits.is_none()
            && self.token_budget.is_none()
            && self.tool_call_budget.is_none()
            && self.wall_clock_millis.is_none()
    }

    /// The absolute wall-clock deadline (unix seconds) for a run that started at
    /// `started_at_unix`, or `None` when no wall-clock cap applies. The millis
    /// duration is rounded UP to whole seconds so a sub-second cap still yields a
    /// non-zero window.
    pub fn deadline_unix(&self, started_at_unix: i64) -> Option<i64> {
        self.wall_clock_millis.map(|millis| {
            let seconds = millis.div_ceil(1_000) as i64;
            started_at_unix.saturating_add(seconds)
        })
    }
}

/// Compose a workflow's graph-level caps with a node's caps into the effective
/// envelope for a step dispatched at that node (issue #279). Each dimension is
/// the `min` of the two: a node may TIGHTEN the graph ceiling but can never
/// widen it, mirroring `resolve_effective_quota`'s min-across-the-chain rule.
/// A `None` (unbounded) side is dominated by any `Some` cap on the other side.
pub fn resolve_workflow_budget_envelope(
    graph: WorkflowBudgetCaps,
    node: WorkflowBudgetCaps,
) -> WorkflowBudgetCaps {
    WorkflowBudgetCaps {
        cost_budget_credits: min_opt(graph.cost_budget_credits, node.cost_budget_credits),
        token_budget: min_opt(graph.token_budget, node.token_budget),
        tool_call_budget: min_opt(graph.tool_call_budget, node.tool_call_budget),
        wall_clock_millis: min_opt(graph.wall_clock_millis, node.wall_clock_millis),
    }
}

fn min_opt<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

/// A workflow run's budget was exhausted for a step. `code` is the
/// dimension-qualified fail-closed code (e.g. `workflow_budget_exceeded:cost`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowBudgetDenial {
    pub dimension: WorkflowBudgetDimension,
    pub code: String,
    pub message: String,
}

/// Pure, fail-closed pre-flight of a step's proposed spend against a run's
/// durable envelope (issue #279). Denies when the run is already exhausted or
/// when adding `(cost, tokens, tool_calls)` at `now_unix` would breach any
/// capped dimension -- WITHOUT mutating the ledger. The durable
/// `debit_workflow_run_budget` remains the authoritative, atomic enforcement
/// under a row lock; this lets a caller reject a step (or choose a cheaper node)
/// before attempting the debit.
pub fn preflight_workflow_budget(
    budget: &StoredWorkflowRunBudget,
    cost_credits: i64,
    tokens: i64,
    tool_calls: i64,
    now_unix: i64,
) -> Result<(), WorkflowBudgetDenial> {
    if budget.status == ferrogate_storage::WORKFLOW_RUN_BUDGET_EXHAUSTED {
        let dimension = budget
            .dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix)
            .unwrap_or(WorkflowBudgetDimension::Cost);
        return Err(budget_denial(dimension, &budget.run_id));
    }
    match budget.dimension_exceeded_by(cost_credits, tokens, tool_calls, now_unix) {
        Some(dimension) => Err(budget_denial(dimension, &budget.run_id)),
        None => Ok(()),
    }
}

fn budget_denial(dimension: WorkflowBudgetDimension, run_id: &str) -> WorkflowBudgetDenial {
    WorkflowBudgetDenial {
        dimension,
        code: dimension.denial_code(),
        message: format!(
            "workflow run {run_id} execution budget exhausted on the {} dimension",
            dimension.as_str()
        ),
    }
}

/// A workflow node's dispatch allowlist (issue #279): the model it is pinned to
/// (if any) and the set of providers it may dispatch to. Evaluated at dispatch
/// by [`evaluate_node_dispatch`].
#[derive(Debug, Clone, Copy)]
pub struct WorkflowNodeDispatchPolicy<'a> {
    pub node_id: &'a str,
    /// The single model this node is restricted to, if any. `None` = the node
    /// does not restrict the model.
    pub model: Option<&'a str>,
    /// The providers this node may dispatch to. Empty = unrestricted.
    pub providers: &'a [String],
}

/// A node dispatched a model/provider its node-level allowlist forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowNodeDispatchDenial {
    pub code: String,
    pub message: String,
}

/// Fail-closed evaluation of a workflow node's model/provider allowlist against
/// the model/provider a step is ACTUALLY dispatching (issue #279 acceptance:
/// "Node-level model allowlist violation fails closed at dispatch, not after the
/// provider call"). A node that pins a model rejects any other model; a node
/// with a provider allowlist rejects any provider outside it. `None` on either
/// requested side means that facet is not being dispatched and is not gated
/// (e.g. a tool-only node with no model call).
pub fn evaluate_node_dispatch(
    node: WorkflowNodeDispatchPolicy<'_>,
    requested_model: Option<&str>,
    requested_provider: Option<&str>,
) -> Result<(), WorkflowNodeDispatchDenial> {
    if let (Some(pinned), Some(requested)) = (node.model, requested_model) {
        if pinned != requested {
            return Err(WorkflowNodeDispatchDenial {
                code: WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE.to_string(),
                message: format!(
                    "workflow node {} is restricted to model {pinned}; dispatch of model \
                     {requested} is not allowed",
                    node.node_id
                ),
            });
        }
    }
    if !node.providers.is_empty() {
        if let Some(requested) = requested_provider {
            if !node.providers.iter().any(|allowed| allowed == requested) {
                return Err(WorkflowNodeDispatchDenial {
                    code: WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE.to_string(),
                    message: format!(
                        "workflow node {} is not allowed to dispatch to provider {requested}",
                        node.node_id
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrogate_storage::{StoredWorkflowRunBudget, WORKFLOW_RUN_BUDGET_ACTIVE};

    fn caps(
        cost: Option<i64>,
        tokens: Option<i64>,
        tools: Option<i64>,
        wall: Option<u64>,
    ) -> WorkflowBudgetCaps {
        WorkflowBudgetCaps {
            cost_budget_credits: cost,
            token_budget: tokens,
            tool_call_budget: tools,
            wall_clock_millis: wall,
        }
    }

    fn budget(caps: WorkflowBudgetCaps, spent: (i64, i64, i64)) -> StoredWorkflowRunBudget {
        StoredWorkflowRunBudget {
            id: "wf:1:run-1".into(),
            workflow_id: "wf".into(),
            workflow_version: 1,
            run_id: "run-1".into(),
            tenant_id: "tenant-1".into(),
            cost_budget_credits: caps.cost_budget_credits,
            token_budget: caps.token_budget,
            tool_call_budget: caps.tool_call_budget,
            wall_clock_deadline_unix: caps.deadline_unix(0),
            spent_credits: spent.0,
            spent_tokens: spent.1,
            spent_tool_calls: spent.2,
            status: WORKFLOW_RUN_BUDGET_ACTIVE.into(),
            created_at_unix: 0,
            updated_at_unix: 0,
        }
    }

    #[test]
    fn envelope_composition_takes_the_min_and_a_node_can_only_tighten() {
        let graph = caps(Some(1_000), Some(10_000), Some(20), Some(60_000));
        // The node tightens cost + tools below the graph, tries to WIDEN tokens
        // (must be clamped to the graph's 10_000), and leaves wall-clock unset.
        let node = caps(Some(250), Some(999_999), Some(5), None);
        let envelope = resolve_workflow_budget_envelope(graph, node);
        assert_eq!(envelope.cost_budget_credits, Some(250));
        assert_eq!(envelope.token_budget, Some(10_000));
        assert_eq!(envelope.tool_call_budget, Some(5));
        assert_eq!(envelope.wall_clock_millis, Some(60_000));
    }

    #[test]
    fn envelope_composition_treats_none_as_unbounded() {
        let envelope = resolve_workflow_budget_envelope(
            caps(None, None, None, None),
            caps(Some(7), None, None, None),
        );
        assert_eq!(envelope.cost_budget_credits, Some(7));
        assert!(envelope.token_budget.is_none());
        assert!(resolve_workflow_budget_envelope(
            caps(None, None, None, None),
            caps(None, None, None, None)
        )
        .is_unbounded());
    }

    #[test]
    fn deadline_rounds_millis_up_to_whole_seconds() {
        assert_eq!(
            caps(None, None, None, Some(1)).deadline_unix(100),
            Some(101)
        );
        assert_eq!(
            caps(None, None, None, Some(1_000)).deadline_unix(100),
            Some(101)
        );
        assert_eq!(
            caps(None, None, None, Some(1_001)).deadline_unix(100),
            Some(102)
        );
        assert_eq!(caps(None, None, None, None).deadline_unix(100), None);
    }

    #[test]
    fn preflight_allows_a_step_that_fits_every_dimension() {
        let b = budget(caps(Some(100), Some(1_000), Some(10), None), (10, 100, 1));
        assert!(preflight_workflow_budget(&b, 5, 50, 1, 0).is_ok());
    }

    #[test]
    fn preflight_denies_on_the_first_breached_dimension_with_a_distinct_code() {
        // A $0.10 (=100-credit) cost ceiling: the run has spent 95 and a step
        // costing 10 would take it to 105 > 100 -> fail closed on cost.
        let b = budget(caps(Some(100), None, None, None), (95, 0, 0));
        let denial = preflight_workflow_budget(&b, 10, 0, 0, 0)
            .expect_err("a step that would exceed the cost ceiling must be denied");
        assert_eq!(denial.dimension, WorkflowBudgetDimension::Cost);
        assert_eq!(denial.code, "workflow_budget_exceeded:cost");

        // Tool-call count ceiling exhausted.
        let b = budget(caps(None, None, Some(3), None), (0, 0, 3));
        let denial = preflight_workflow_budget(&b, 0, 0, 1, 0).unwrap_err();
        assert_eq!(denial.dimension, WorkflowBudgetDimension::ToolCalls);
        assert_eq!(denial.code, "workflow_budget_exceeded:tool_calls");
    }

    #[test]
    fn preflight_denies_at_or_after_the_wall_clock_deadline() {
        // Deadline is started_at(0) + ceil(5000/1000)=5s.
        let b = budget(caps(None, None, None, Some(5_000)), (0, 0, 0));
        assert!(preflight_workflow_budget(&b, 0, 0, 0, 4).is_ok());
        let denial = preflight_workflow_budget(&b, 0, 0, 0, 5).unwrap_err();
        assert_eq!(denial.dimension, WorkflowBudgetDimension::WallClock);
        assert_eq!(denial.code, "workflow_budget_exceeded:wall_clock");
    }

    #[test]
    fn preflight_on_an_exhausted_run_denies_every_step() {
        let mut b = budget(caps(Some(100), None, None, None), (100, 0, 0));
        b.status = ferrogate_storage::WORKFLOW_RUN_BUDGET_EXHAUSTED.into();
        // Even a zero-spend step is denied while the run is exhausted.
        assert!(preflight_workflow_budget(&b, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn node_model_allowlist_fails_closed_at_dispatch() {
        let providers = Vec::<String>::new();
        let node = WorkflowNodeDispatchPolicy {
            node_id: "n1",
            model: Some("fast-chat"),
            providers: &providers,
        };
        // The pinned model is allowed.
        assert!(evaluate_node_dispatch(node, Some("fast-chat"), None).is_ok());
        // A different model fails closed with the distinct model code.
        let denial = evaluate_node_dispatch(node, Some("smart-chat"), None).unwrap_err();
        assert_eq!(denial.code, WORKFLOW_NODE_MODEL_NOT_ALLOWED_CODE);
        assert!(denial.message.contains("fast-chat") && denial.message.contains("smart-chat"));
    }

    #[test]
    fn node_provider_allowlist_fails_closed_at_dispatch() {
        let providers = vec!["openai".to_string(), "anthropic".to_string()];
        let node = WorkflowNodeDispatchPolicy {
            node_id: "n2",
            model: None,
            providers: &providers,
        };
        assert!(evaluate_node_dispatch(node, None, Some("anthropic")).is_ok());
        let denial = evaluate_node_dispatch(node, None, Some("cohere")).unwrap_err();
        assert_eq!(denial.code, WORKFLOW_NODE_PROVIDER_NOT_ALLOWED_CODE);

        // An unrestricted node (no model pin, empty provider list) allows any
        // dispatch -- the missing-config-is-unrestricted rule.
        let empty = Vec::<String>::new();
        let open = WorkflowNodeDispatchPolicy {
            node_id: "n3",
            model: None,
            providers: &empty,
        };
        assert!(evaluate_node_dispatch(open, Some("anything"), Some("anywhere")).is_ok());
    }
}
