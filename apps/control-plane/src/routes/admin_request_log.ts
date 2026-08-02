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
import { AUDIT_TABLE, REQUEST_LOG_TABLE } from "../store/d1.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  raw,
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

// ---------------------------------------------------------------------------
// `request_logs` — the per-inference-decision evidence trail (#664)
// ---------------------------------------------------------------------------

/**
 * The tenant fence for `request_logs`.
 *
 * Identical in shape and in reasoning to {@link auditTenantFence}, and stated
 * separately rather than shared because the two tables' `tenant` columns are
 * independent facts: an audit row's tenant is the tenant a MUTATION touched,
 * a request log's is the tenant the CREDENTIAL resolved to. Folding them into
 * one helper would make a later divergence in either look like a typo.
 *
 * STRICT equality, so a `NULL` tenant matches nobody. A request log with no
 * tenant is a platform-operator call (or an anonymous one), and handing those
 * to a tenant would be handing them the operator's own traffic — the same
 * narrowing the audit fence documents, and the property
 * `test/request-logs-read.test.ts` proves from BOTH tenants' sides plus the
 * export.
 */
function requestLogTenantFence(scope: CallerScope): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: ` WHERE ${REQUEST_LOG_TABLE}.tenant = ?`, params: [scope.tenantId] };
}

/**
 * The projection every `request_logs` read shares.
 *
 * Written once and named here so the list and the export cannot drift into
 * answering different documents for the same row — which is exactly how a SIEM
 * pipeline and a console end up disagreeing about what happened.
 */
const REQUEST_LOG_COLUMNS =
  "request_id, trace_id, agent_run_id, tenant, project, workspace, api_key_id, " +
  "route, provider, logical_model, provider_model, status_code, error_code, cache_status, " +
  "latency_ms, prompt_tokens, completion_tokens, total_tokens, " +
  "guardrail_verdict, guardrail_policy_id, streamed, " +
  "started_at_unix, completed_at_unix, request_json";

/**
 * `ORDER BY started_at_unix DESC, request_id ASC`.
 *
 * NEWEST FIRST, which is the one place this reader deliberately differs from
 * {@link listAuditEventsHandler} (oldest first, mirroring Rust's
 * `audit_events_page`). An audit trail is read forwards as a history; a request
 * log is read backwards from an incident — "what did the gateway just do" — and
 * `idx_request_logs_tenant_started` is declared DESC for exactly that query.
 *
 * `request_id` is the tiebreaker, and it is load-bearing rather than tidy:
 * `started_at_unix` is whole SECONDS, a busy gateway puts thousands of rows in
 * one of them, and an unstable sort inside a second lets a page boundary
 * re-serve one row and skip another. An evidence export that silently drops a
 * decision is worse than one that errors.
 */
const REQUEST_LOG_ORDER = `ORDER BY started_at_unix DESC, request_id ASC`;

interface RequestLogRow {
  readonly request_id: string;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly tenant: string | null;
  readonly project: string | null;
  readonly workspace: string | null;
  readonly api_key_id: string | null;
  readonly route: string | null;
  readonly provider: string | null;
  readonly logical_model: string | null;
  readonly provider_model: string | null;
  readonly status_code: number | null;
  readonly error_code: string | null;
  readonly cache_status: string | null;
  readonly latency_ms: number | null;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly guardrail_verdict: string | null;
  readonly guardrail_policy_id: string | null;
  readonly streamed: number | null;
  readonly started_at_unix: number;
  readonly completed_at_unix: number | null;
  readonly request_json: string;
  readonly total?: number;
}

/**
 * Project one durable row onto the wire.
 *
 * The COLUMNS are applied last and therefore win, for the same reason
 * {@link auditEventDocument} gives: `request_json` is assembled on the data
 * plane from operator- and CALLER-influenced material (request metadata tags,
 * a model name off the request body), and a document that could rename its own
 * `tenant_id` would be a document that could put itself in another tenant's
 * export. The fence is a SQL predicate on the column, so the wire field has to
 * be the column too or the two disagree.
 *
 * The document is still spread in first rather than dropped: it is the
 * extension point for facts a later slice adds without a migration, and
 * discarding it would make this reader lossy the moment the writer learns
 * something new.
 */
function requestLogDocument(row: RequestLogRow): StoreRecord {
  let document: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(row.request_json);
    document =
      typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    // A row whose document does not parse is still evidence THAT a request
    // happened, and every fact an auditor asks for is in the columns. Dropping
    // it would put a hole in the trail exactly where something went wrong.
    document = {};
  }
  return {
    ...document,
    object: "request_log",
    id: row.request_id,
    request_id: row.request_id,
    trace_id: row.trace_id,
    agent_run_id: row.agent_run_id,
    tenant_id: row.tenant,
    project_id: row.project,
    workspace_id: row.workspace,
    api_key_id: row.api_key_id,
    route: row.route,
    provider: row.provider,
    logical_model: row.logical_model,
    provider_model: row.provider_model,
    status_code: row.status_code,
    error_code: row.error_code,
    cache_status: row.cache_status,
    latency_ms: row.latency_ms,
    prompt_tokens: row.prompt_tokens,
    completion_tokens: row.completion_tokens,
    total_tokens: row.total_tokens,
    guardrail_verdict: row.guardrail_verdict,
    guardrail_policy_id: row.guardrail_policy_id,
    streamed: row.streamed === 1,
    started_at_unix: row.started_at_unix,
    completed_at_unix: row.completed_at_unix,
  };
}

/** One fenced, ordered page of `request_logs`, with the pre-window total. */
async function requestLogPage(
  db: D1Database,
  scope: CallerScope,
  limit: number,
  offset: number,
): Promise<{ rows: RequestLogRow[]; total: number }> {
  const fence = requestLogTenantFence(scope);
  const result = await db
    .prepare(
      `SELECT ${REQUEST_LOG_COLUMNS}, count(*) OVER() AS total
         FROM ${REQUEST_LOG_TABLE}${fence.sql}
        ${REQUEST_LOG_ORDER}
        LIMIT ? OFFSET ?`,
    )
    .bind(...fence.params, limit, offset)
    .all<RequestLogRow>();
  // `count(*) OVER()` is on every row and absent when there are none, so an
  // empty page past the end reports 0 — the same reading `listAuditEvents`
  // takes, and the same one the windowed Rust query answers.
  return { rows: result.results, total: result.results[0]?.total ?? 0 };
}

/**
 * `GET /admin/v1/request-logs` — the durable per-decision evidence trail.
 *
 * ## Why this is not the generic list handler
 *
 * It used to be, and that was the defect (#664). The generic handler paged the
 * `request-logs` DOCUMENT collection in `control_plane_resources`, which has no
 * writer, so the operation answered `{"object":"list","data":[]}` on every
 * deployment while the gateway served traffic — a live, authenticated,
 * contract-conformant API telling an auditor that nothing happened. The absence
 * of a record is how you conclude a decision was not made, so this failure mode
 * lies rather than errors.
 *
 * The other half of the defect was that nothing wrote the table; that is
 * `apps/gateway/src/requestlog/` (a different Worker on the same CONTROL
 * database) and it landed in the same change. A reader over a table with no
 * writer is indistinguishable from the defect being closed, which is precisely
 * why the previous author refused to write one speculatively — the note that
 * stood here said so — and why this one arrives WITH the writer.
 *
 * Three details are shared with {@link listAuditEventsHandler} deliberately:
 * `count(*) OVER()` so the total and the page cannot disagree under a
 * concurrent write; the paginated envelope UNCONDITIONALLY, so a client cannot
 * mistake a first page for the whole history; and a strict-equality tenant
 * fence. It differs in the sort direction, for the reason
 * {@link REQUEST_LOG_ORDER} gives.
 */
function listRequestLogsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const db = deps.controlDatabase;

    if (db === null) {
      // No control database means no `request_logs` table AND no gateway
      // writing one — `controlDatabase` is `null` exactly when
      // `CONTROL_PLANE_STORE = "memory"` or no `DB` is bound. The document
      // collection is the only request-log surface such a deployment has.
      const page = await deps.store.list("request-logs", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const page = await requestLogPage(db, scope, query.limit, query.offset);
    return json(
      c,
      200,
      adminListPaginated(
        page.rows.map(requestLogDocument),
        page.total,
        query.offset,
        query.limit,
      ),
    );
  };
}

/**
 * The export's page size when the caller names none.
 *
 * Larger than the list default (100) because the two operations answer
 * different questions — a console pages, a SIEM ingest wants a bulk pull — and
 * bounded rather than unlimited because a Worker materializes the page in
 * memory before it writes it. An operator who wants the whole trail pages it
 * with `?offset=`, which is exactly what a resumable export needs anyway: an
 * unbounded single response that dies at 2 GB has exported nothing.
 */
const REQUEST_LOG_EXPORT_DEFAULT_LIMIT = 1_000;
const REQUEST_LOG_EXPORT_MAX_LIMIT = 10_000;

/**
 * `GET /admin/v1/request-log-exports` — the same evidence as JSON Lines.
 *
 * `application/x-ndjson`, one complete decision per line, no enclosing array
 * and no envelope: that is what makes it appendable and streamable into a SIEM,
 * and it is the format's whole reason for existing over the JSON list. An empty
 * result is an EMPTY BODY rather than `[]`, because `[]` is not valid JSONL and
 * a consumer that `JSON.parse`s per line would fail on it.
 *
 * Same fence, same projection and same order as {@link listRequestLogsHandler},
 * by construction — {@link requestLogPage} is the only query. A SIEM export
 * that could see a row the console cannot is a cross-tenant leak with a
 * different front door, so the two must not have two implementations.
 */
function exportRequestLogsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const query = parseListQuery(
      new URL(c.req.url),
      REQUEST_LOG_EXPORT_DEFAULT_LIMIT,
      REQUEST_LOG_EXPORT_MAX_LIMIT,
    );
    const db = deps.controlDatabase;

    const records =
      db === null
        ? (await deps.store.list("request-log-exports", scope, query)).items
        : (await requestLogPage(db, scope, query.limit, query.offset)).rows.map(
            requestLogDocument,
          );

    const body = records.map((record) => JSON.stringify(record)).join("\n");
    return raw(
      c,
      200,
      // The charset is explicit because `application/x-ndjson` is not a type
      // any runtime recognises as text: without it, a consumer calling
      // `.text()` on the body is warned that the result may be corrupted, and
      // some HTTP clients will hand back bytes rather than a string.
      "application/x-ndjson; charset=utf-8",
      // A trailing newline only when there IS a line: JSONL readers treat a
      // blank line as an error, and an empty export must be zero bytes.
      body === "" ? "" : `${body}\n`,
    );
  };
}

/**
 * PORT-TODO(P: inventory-edge-control §9.3 evidence) — KEPT, narrowed twice:
 * the `audit-events` leg is CLOSED (see {@link listAuditEventsHandler}) and so
 * are `request-logs` / `request-log-exports` (#664, see
 * {@link listRequestLogsHandler}). The remaining two still read document
 * collections that nothing in the tree writes, so each answers an empty
 * `AdminList` on every deployment:
 *
 *   - `guardrail-evaluations` / `investigations` — one step worse than the
 *     request-log case was: `guardrail_evaluations` /
 *     `guardrail_check_evaluations` **do not exist in `sql/d1-ts/` at all**
 *     (readiness §2.4), so guardrail evidence is in-memory-only fleet-wide.
 *     Closing this needs a migration first — `wrangler.toml`'s
 *     `migrations_dir` and `vitest.config.ts` read the same directory, so the
 *     shape of the fix is the one #664 used: land the migration, the writer and
 *     the reader together, never the reader alone.
 *
 * Note that the request-log gauge heals with this change:
 * `adapters.ts::StoreRuntimeStatus.metrics()` publishes
 * `ferrogate_request_log_entries` off the DOCUMENT collection, which is still
 * empty — the gauge is pinned at 0 and now UNDER-reports a table that has rows.
 * That is a smaller lie than before but still a lie, and it is left alone here
 * on purpose: the metrics surface has its own owner and its own gate, and
 * changing a Prometheus series inside an evidence-reader change would be two
 * behaviours in one commit.
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
  {
    listAdminAuditEvents: listAuditEventsHandler(),
    listAdminRequestLogs: listRequestLogsHandler(),
    exportAdminRequestLogsJsonl: exportRequestLogsHandler(),
  },
);
