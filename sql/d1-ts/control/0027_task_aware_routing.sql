-- ===========================================================================
-- Task-aware auto-routing with a cost/quality dial (#699)
--
-- Two columns, one per consent, both DEFAULT to the pre-#699 behaviour.
--
-- ## quota_policies.online_eval_cost_quality_routing
--
-- The DIAL. When on, the router may act on this tenant's leg-quality aggregate
-- for a request its task classifier calls EASY: it drops every below-floor
-- (lagging) candidate and serves the CHEAPEST survivor instead of the operator's
-- hand-written order. Acting on the signal is a strictly larger consent than
-- measuring it (`0026`'s coverage knob copies a prompt; this reaches into the
-- served ladder), so it is its own opt-in beside the other `online_eval_*`
-- controls on the tenant's governance row rather than a fleet var. DEFAULT 0 is
-- OFF, and off is byte-identical to before this slice — which itself already
-- includes `0026`'s demote pass (a permutation, never a filter).
--
-- Stored INTEGER, like `online_eval_enabled` (`0009`), because it is a boolean
-- and `apps/gateway/src/evals/policy.ts::truthy` reads a SQLite 0/1 the same way
-- it reads a JSON boolean.
--
-- ## request_logs.routing_decision
--
-- The EXPLAINABLE verdict. One flat TEXT line
-- (`cost_quality task=easy(short_single_turn) applied=true eligible=… filtered=…`)
-- recording WHY a request got the model it did: the classifier verdict, the
-- candidates that cleared the quality floor, and the ones dropped for lagging.
-- A single TEXT column, the low-friction shape `delegation_chain` (#691) uses,
-- rather than structured columns nothing yet queries on. NULL for every request
-- whose tenant did not opt the dial in, which is almost all of them.
-- ===========================================================================

ALTER TABLE quota_policies ADD COLUMN online_eval_cost_quality_routing INTEGER NOT NULL DEFAULT 0;

ALTER TABLE request_logs ADD COLUMN routing_decision TEXT;
