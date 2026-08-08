-- ===========================================================================
-- Task-aware auto-routing: the explainable decision, tenant-side (#699)
--
-- The tenant object is authoritative for a request log whose tenant is already
-- known; control-D1 keeps only the fleet projection (its column is added by the
-- matching control migration, `0027_task_aware_routing.sql`).
--
-- `routing_decision` is the cost/quality dial's rendered verdict — one flat TEXT
-- line recording the classifier's easy/hard call, the candidates that cleared
-- the quality floor, and the ones dropped for lagging. NULL for every request
-- whose tenant did not opt the dial in.
-- ===========================================================================

ALTER TABLE request_logs ADD COLUMN routing_decision TEXT;
