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
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { AUDIT_TABLE } from "../store/d1.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

/**
 * The tenant fence for `audit_events`, which is NARROWER than the document
 * store's read fence and deliberately so.
 *
 * `store/query.ts::visibleTo` lets a tenant-scoped caller see un-attributed
 * (platform) rows, because configuration defaults have to be readable for
 * `resolved-defaults` to work. Evidence is the opposite case: an un-attributed
 * audit row records a PLATFORM OPERATOR's mutation, and that is not a tenant's
 * to read. Rust agrees and is explicit about it —
 * `state_agent_runtime.rs:292` filters
 * `event.tenant.organization_id.as_deref() == Some(tenant_id)`, i.e. strict
 * equality, so `NULL` matches nobody.
 */
function auditTenantFence(scope: CallerScope): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: ` WHERE ${AUDIT_TABLE}.tenant = ?`, params: [scope.tenantId] };
}

interface AuditEventRow {
  readonly id: string;
  readonly request_id: string;
  readonly agent_run_id: string | null;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  readonly audit_json: string;
  readonly total: number;
}

/**
 * Project one durable row onto the wire.
 *
 * The ROW's columns are applied last and therefore win: `audit_json` is
 * operator-influenced data (it embeds a `collection` and a `resource_id` that
 * came from a request body), and a document that could rename its own `id` or
 * `request_id` would let a mutation forge its own correlation.
 */
function auditEventDocument(row: AuditEventRow): StoreRecord {
  let audit: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(row.audit_json);
    audit =
      typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    // A row whose document does not parse is still evidence THAT something
    // happened; dropping it would put a hole in the trail exactly where
    // something went wrong.
    audit = {};
  }
  return {
    ...audit,
    id: row.id,
    request_id: row.request_id,
    agent_run_id: row.agent_run_id,
    tenant_id: row.tenant,
    occurred_at_unix: row.occurred_at_unix,
  };
}

/**
 * `GET /admin/v1/audit-events` — the durable admin audit trail.
 *
 * ## Why this is not the generic list handler
 *
 * It used to be, and that was the defect. `D1ControlPlaneStore` appends an
 * `audit_events` row for every applied mutation (`store/d1.ts::#audit`), while
 * the generic handler paged the `audit-events` DOCUMENT collection in
 * `control_plane_resources` — which has no writer. So every deployment recorded
 * a complete audit trail and served an empty one, and an operator asking who
 * changed a policy was answered "nobody did". A missing evidence row is how you
 * conclude a change was not made, so this failure mode lies rather than errors.
 *
 * Parity source: `crates/ferrogate-gateway/src/server/local.rs:4501`
 * (`handle_admin_audit_events`) over
 * `crates/ferrogate-storage/src/control_plane_store_d1/observability.rs:247`.
 * Three details are taken from there rather than from the generic handler:
 *
 *  1. **`ORDER BY occurred_at_unix ASC, id ASC`** — oldest first, and `id` is
 *     the tiebreaker so a page boundary inside one second cannot re-serve or
 *     skip a row.
 *  2. **`count(*) OVER()`** — `total` is the count BEFORE the window, computed
 *     in the same statement as the page so the two cannot disagree under a
 *     concurrent write.
 *  3. **`AdminList::paginated` unconditionally.** Unlike every other admin
 *     list, this operation does not fork on "was there a query string": Rust
 *     builds the paginated envelope on both paths. A trail client that got a
 *     bare `{object,data}` for an un-queried request could not tell a first
 *     page from the whole history.
 */
function listAuditEventsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const db = deps.controlDatabase;

    if (db === null) {
      // No control database means no `audit_events` table AND no durable store
      // to have written one — `controlDatabase` is `null` exactly when
      // `CONTROL_PLANE_STORE = "memory"` or no `DB` is bound. Reading the
      // document collection here is not a downgraded answer, it is the only
      // audit surface such a deployment has.
      const page = await deps.store.list("audit-events", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const fence = auditTenantFence(scope);
    const rows = await db
      .prepare(
        `SELECT id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json,
                count(*) OVER() AS total
           FROM ${AUDIT_TABLE}${fence.sql}
          ORDER BY occurred_at_unix ASC, id ASC
          LIMIT ? OFFSET ?`,
      )
      .bind(...fence.params, query.limit, query.offset)
      .all<AuditEventRow>();

    // `count(*) OVER()` is on every row and absent when there are none; an
    // empty page past the end of a non-empty table therefore reports 0 rather
    // than the true total, which matches what a client can do with it (there is
    // nothing there) and is what the windowed Rust query answers too.
    const total = rows.results[0]?.total ?? 0;
    return json(
      c,
      200,
      adminListPaginated(rows.results.map(auditEventDocument), total, query.offset, query.limit),
    );
  };
}

/**
 * PORT-TODO(P: inventory-edge-control §9.3 evidence) — KEPT, narrowed: the
 * `audit-events` leg is CLOSED (see {@link listAuditEventsHandler}); the other
 * four still read document collections that nothing in the tree writes, so each
 * answers an empty `AdminList` on every deployment.
 *
 * Where the missing evidence actually is, and what closing each would take:
 *
 *   - `request-logs` / `request-log-exports` — the control schema has a
 *     `request_logs` table with no writer and no reader anywhere in
 *     `apps/<app>/src`; the gateway meters to `billing_events`/`billing_ledger` and
 *     emits telemetry, but never persists a request log row. Rust
 *     `handle_admin_request_logs` pages a real store. **This one cannot be
 *     closed from this app**: the WRITER is on the gateway's inference path
 *     (`apps/gateway/src/metering/`), which is a different Worker and a
 *     different owner. The read side here is ready for it — the same shape as
 *     `listAuditEventsHandler` over `request_logs` — and is deliberately NOT
 *     written speculatively, because a reader over a table with no writer is
 *     indistinguishable from the defect this wave is closing.
 *     `adapters.ts::StoreRuntimeStatus.metrics()` publishes
 *     `ferrogate_request_log_entries` off the same empty collection, so the
 *     Prometheus gauge is pinned at 0 for the same reason and heals with it.
 *   - `guardrail-evaluations` / `investigations` — same shape, one step worse:
 *     `guardrail_evaluations` / `guardrail_check_evaluations` **do not exist in
 *     `sql/d1-ts/` at all** (readiness §2.4), so guardrail evidence is
 *     in-memory-only fleet-wide. Closing this needs a migration first, which is
 *     the migrations slice's to add — `wrangler.toml`'s `migrations_dir` and
 *     `vitest.config.ts` read the same directory, so a table invented here
 *     would make the tests and the deployment disagree about the schema.
 */
export const adminRequestLogRoutes: GroupModule = crudGroup(
  "admin_request_log",
  [
    readOnlyCollection("request-logs", "request_log"),
    readOnlyCollection("request-log-exports", "request_log_export"),
    readOnlyCollection("audit-events", "audit_event"),
    readOnlyCollection("guardrail-evaluations", "guardrail_evaluation"),
    readOnlyCollection("investigations", "investigation"),
  ],
  { listAdminAuditEvents: listAuditEventsHandler() },
);
