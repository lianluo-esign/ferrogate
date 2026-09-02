-- ===========================================================================
-- Drop the two agent-run compatibility projection tables (Track A red-line)
--
-- `agent_runs` / `agent_run_events` in the CONTROL store were derived
-- cross-tenant projection *mirrors* (#859 keyed them by `projection_key`).
-- Their authoritative home is each tenant's TenantDataObject, fed by the
-- agent-runtime `AgentRunState` object (`runs/evidence.ts`), and every reader
-- now targets that tenant object:
--
--   * control-plane `GET /admin/v1/agent-runs`           — roster fan-out
--   * control-plane `GET /admin/v1/agent-runs/{run_id}`  — owner fan-out
--     (`findRunOwners`, preserving the 409 `ambiguous_agent_run_id` contract)
--   * control-plane investigations                      — tenant evidence rows
--
-- The agent-runtime mirror write (`mirrorBestEffort`) was removed in the same
-- change, so the control copies have no remaining writer or reader. Keeping the
-- empty mirrors implies a second source of truth and lets a future writer
-- bypass tenant isolation — the exact red line this program eliminates.
-- `IF EXISTS` keeps this idempotent for fresh and already migrated control
-- databases (0013 / 0036 precedent). Neither table is referenced by an inbound
-- foreign key, so drop order is free. Their indexes drop with them.
--
-- Deploy order: the control-plane reader flip and the agent-runtime writer stop
-- must be live BEFORE the gateway (which defines ControlDataObject) ships this
-- migration, or the still-deployed readers would hit `no such table`.
-- ===========================================================================

DROP TABLE IF EXISTS agent_run_events;
DROP TABLE IF EXISTS agent_runs;
