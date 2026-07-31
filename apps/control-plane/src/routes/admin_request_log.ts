/**
 * Contract group `admin_request_log` (5 operations) — the evidence/audit reads:
 * request logs and their JSONL export, admin audit events, guardrail
 * evaluations, and investigations.
 *
 * All `admin.read`. Two of them additionally carry an `rbac_action`
 * (`guardrails.evidence.read` on `listGuardrailEvaluations` and
 * `getGuardrailInvestigation`) — that second gate is applied by the table-driven
 * auth middleware from the contract, so it is not repeated here.
 */
import { type GroupModule, crudGroup, readOnlyCollection } from "./resource.js";

export const adminRequestLogRoutes: GroupModule = crudGroup("admin_request_log", [
  readOnlyCollection("request-logs", "request_log"),
  readOnlyCollection("request-log-exports", "request_log_export"),
  readOnlyCollection("audit-events", "audit_event"),
  readOnlyCollection("guardrail-evaluations", "guardrail_evaluation"),
  readOnlyCollection("investigations", "investigation"),
]);
