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

/**
 * PORT-TODO(P: inventory-edge-control §9.3 evidence) — all five feeds read document
 * collections that NOTHING in the tree writes, so each answers an empty
 * `AdminList` on every deployment.
 *
 * The evidence exists; it is just somewhere else:
 *
 *   - `audit-events` — `store/d1.ts` appends a real `audit_events` row for every
 *     applied mutation (and `apps/gateway/src/assets/d1.ts` appends more). The
 *     only reader of that table is the gateway's asset audit tail; this route
 *     reads the `audit-events` DOCUMENT collection instead, which is empty. The
 *     admin surface therefore cannot show the audit trail it is carefully
 *     recording — closing this is a query against `AUDIT_TABLE` with
 *     `tenantScopeSql`'s equivalent on `audit_events.tenant`.
 *   - `request-logs` / `request-log-exports` — the control schema has a
 *     `request_logs` table with no writer and no reader anywhere in
 *     `apps/<app>/src`; the gateway meters to `billing_events`/`billing_ledger` and
 *     emits telemetry, but never persists a request log row. Rust
 *     `handle_admin_request_logs` pages a real store.
 *     `adapters.ts::StoreRuntimeStatus.metrics()` publishes
 *     `ferrogate_request_log_entries` off this same empty collection, so the
 *     Prometheus gauge is pinned at 0 for the same reason.
 *   - `guardrail-evaluations` / `investigations` — same shape; the guardrail
 *     verdicts the gateway produces are not persisted for this feed.
 */
export const adminRequestLogRoutes: GroupModule = crudGroup("admin_request_log", [
  readOnlyCollection("request-logs", "request_log"),
  readOnlyCollection("request-log-exports", "request_log_export"),
  readOnlyCollection("audit-events", "audit_event"),
  readOnlyCollection("guardrail-evaluations", "guardrail_evaluation"),
  readOnlyCollection("investigations", "investigation"),
]);
