/**
 * Contract group `admin_request_log` (5 operations) — the evidence/audit reads:
 * request logs and their JSONL export, admin audit events, guardrail
 * evaluations, and investigations.
 *
 * ## The pump reads through this module, not around it (#683)
 *
 * `src/siem/source.ts` — the export pump that pushes the same evidence to a
 * customer's SIEM — imports {@link requestLogTenantFence},
 * {@link REQUEST_LOG_COLUMNS}, {@link requestLogDocument},
 * {@link auditTenantFence} and {@link auditEventDocument} from here rather than
 * restating any of them. That is the same argument the JSONL export already
 * makes one level down: a push path that could see a row the console cannot is
 * a cross-tenant leak with a different front door, and a push path that
 * PROJECTED a row differently would make a customer's SIEM and this API
 * disagree about what happened. The pump differs from these handlers in exactly
 * two ways, both stated where they occur: it walks time FORWARDS (a cursor has
 * to), and it pages by keyset rather than by offset.
 *
 * All `admin.read`. Two of them additionally carry an `rbac_action`
 * (`guardrails.evidence.read` on `listGuardrailEvaluations` and
 * `getGuardrailInvestigation`) — that second gate is applied by the table-driven
 * auth middleware from the contract, so it is not repeated here.
 */
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import {
  AUDIT_TABLE,
  GUARDRAIL_CHECK_TABLE,
  GUARDRAIL_EVALUATION_TABLE,
  REQUEST_LOG_TABLE,
} from "../store/d1.js";
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
export function auditTenantFence(scope: CallerScope): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: ` WHERE ${AUDIT_TABLE}.tenant = ?`, params: [scope.tenantId] };
}

export interface AuditEventRow {
  readonly id: string;
  readonly request_id: string;
  readonly agent_run_id: string | null;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  readonly audit_json: string;
  /** The tamper-evidence columns (#684); NULL on rows written by an unchained writer. */
  readonly chain_key: string | null;
  readonly seq: number | null;
  readonly prev_hash: string | null;
  readonly row_hash: string | null;
  /**
   * `count(*) OVER()`. OPTIONAL because the SIEM pump (`src/siem/source.ts`)
   * reuses this row shape and this projection without the window function — it
   * pages by KEYSET, so a pre-window total would be a second full scan per
   * batch for a number nothing reads.
   */
  readonly total?: number;
}

/**
 * Project one durable row onto the wire.
 *
 * The ROW's columns are applied last and therefore win: `audit_json` is
 * operator-influenced data (it embeds a `collection` and a `resource_id` that
 * came from a request body), and a document that could rename its own `id` or
 * `request_id` would let a mutation forge its own correlation.
 *
 * ## Why the raw `audit_json` string is published TOO (#684)
 *
 * The tamper-evidence chain commits to the stored BYTES of `audit_json`, so a
 * customer recomputing a row's digest needs those bytes. The spread fields
 * cannot supply them: re-serializing a parsed object reorders keys and changes
 * whitespace, so a verifier working from them would fail an intact row. The
 * string is therefore carried verbatim alongside its parsed fields — redundant
 * for a reader that only wants to know what happened, load-bearing for one
 * asking whether it can trust the answer.
 */
export function auditEventDocument(row: AuditEventRow): StoreRecord {
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
    audit_json: row.audit_json,
    chain_key: row.chain_key,
    seq: row.seq,
    prev_hash: row.prev_hash,
    row_hash: row.row_hash,
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
                chain_key, seq, prev_hash, row_hash,
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
export function requestLogTenantFence(scope: CallerScope): { sql: string; params: string[] } {
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
export const REQUEST_LOG_COLUMNS =
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

export interface RequestLogRow {
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
export function requestLogDocument(row: RequestLogRow): StoreRecord {
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
      adminListPaginated(page.rows.map(requestLogDocument), page.total, query.offset, query.limit),
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
        : (await requestLogPage(db, scope, query.limit, query.offset)).rows.map(requestLogDocument);

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

// ---------------------------------------------------------------------------
// `guardrail_evaluations` / `guardrail_check_evaluations` — screening evidence
// (#665)
// ---------------------------------------------------------------------------

/**
 * The tenant fence for `guardrail_evaluations`.
 *
 * Third statement of the same predicate, and stated separately for the reason
 * {@link requestLogTenantFence} gives: the three tables' `tenant` columns are
 * independent facts, and folding them into one helper would make a later
 * divergence in any of them look like a typo rather than a decision.
 *
 * STRICT equality, so a `NULL` tenant matches nobody. An evaluation with no
 * tenant screened a platform-operator (or anonymous) call; handing those to a
 * tenant would tell it which models the operator calls and what its own
 * detectors flag. `test/guardrail-evidence-read.test.ts` proves this from BOTH
 * tenants' sides and from the investigation view, whose leak would be worse
 * still: the investigation joins identity, route and cost.
 */
function guardrailTenantFence(
  scope: CallerScope,
  alias = GUARDRAIL_EVALUATION_TABLE,
): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: `${alias}.tenant = ?`, params: [scope.tenantId] };
}

const GUARDRAIL_EVALUATION_COLUMNS =
  "id, request_id, trace_id, agent_run_id, subject_id, tenant, scope_type, scope_id, " +
  "target, protocol, stage, mode, policy_id, policy_revision, verdict, action, " +
  "enforcement_status, latency_ms, finding_count, input_fingerprint, action_fingerprint, " +
  "occurred_at_unix, evaluation_json";

/**
 * `ORDER BY occurred_at_unix DESC, id ASC` — newest first, like the request log
 * and unlike the audit trail, because guardrail evidence is read backwards from
 * an incident ("what did screening just refuse") rather than forwards as a
 * history. `idx_guardrail_evaluations_tenant_time` is declared DESC for it.
 *
 * `id` is the tiebreaker and it is load-bearing rather than tidy: one request
 * produces one evaluation PER policy@revision PER stage, all stamped with the
 * same whole second, so an unstable sort inside that second lets a page
 * boundary re-serve one row and skip another.
 */
const GUARDRAIL_EVALUATION_ORDER = "ORDER BY occurred_at_unix DESC, id ASC";

interface GuardrailEvaluationRow {
  readonly id: string;
  readonly request_id: string;
  readonly trace_id: string | null;
  readonly agent_run_id: string | null;
  readonly subject_id: string | null;
  readonly tenant: string | null;
  readonly scope_type: string;
  readonly scope_id: string | null;
  readonly target: string;
  readonly protocol: string;
  readonly stage: string;
  readonly mode: string;
  readonly policy_id: string;
  readonly policy_revision: number;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly latency_ms: number;
  readonly finding_count: number;
  readonly input_fingerprint: string;
  readonly action_fingerprint: string | null;
  readonly occurred_at_unix: number;
  readonly evaluation_json: string;
  readonly total?: number;
}

interface GuardrailCheckRow {
  readonly id: string;
  readonly evaluation_id: string;
  readonly check_id: string;
  readonly detector_id: string;
  readonly detector_version: string;
  readonly config_digest: string;
  readonly verdict: string;
  readonly action: string;
  readonly enforcement_status: string;
  readonly error_kind: string | null;
  readonly check_json: string;
}

/** A stored JSON document, or `{}` when it does not parse. */
function documentOf(raw: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(raw);
    return typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch {
    // A row whose document does not parse is still evidence THAT screening
    // happened, and every fact an auditor asks for first is in the columns.
    return {};
  }
}

/** Project one child row onto the wire. */
function guardrailCheckDocument(row: GuardrailCheckRow): StoreRecord {
  return {
    ...documentOf(row.check_json),
    id: row.id,
    evaluation_id: row.evaluation_id,
    check_id: row.check_id,
    detector_id: row.detector_id,
    detector_version: row.detector_version,
    config_digest: row.config_digest,
    verdict: row.verdict,
    action: row.action,
    enforcement_status: row.enforcement_status,
    error_kind: row.error_kind,
  };
}

/**
 * Project one evaluation, with its checks attached.
 *
 * The COLUMNS win over the document for the reason {@link requestLogDocument}
 * gives: `evaluation_json` is assembled on the data plane out of
 * detector-influenced material (a category name comes from a detector's own
 * response), and a document that could rename its own `tenant_id` would be a
 * document that could put itself in another tenant's investigation. The fence
 * is a predicate on the COLUMN, so the wire field has to be the column too.
 */
function guardrailEvaluationDocument(
  row: GuardrailEvaluationRow,
  checks: readonly StoreRecord[],
): StoreRecord {
  return {
    ...documentOf(row.evaluation_json),
    object: "guardrail_evaluation",
    id: row.id,
    request_id: row.request_id,
    trace_id: row.trace_id,
    agent_run_id: row.agent_run_id,
    subject_id: row.subject_id,
    tenant_id: row.tenant,
    scope_type: row.scope_type,
    scope_id: row.scope_id,
    target: row.target,
    protocol: row.protocol,
    stage: row.stage,
    mode: row.mode,
    policy_id: row.policy_id,
    policy_revision: row.policy_revision,
    verdict: row.verdict,
    action: row.action,
    enforcement_status: row.enforcement_status,
    latency_ms: row.latency_ms,
    finding_count: row.finding_count,
    input_fingerprint: row.input_fingerprint,
    action_fingerprint: row.action_fingerprint,
    occurred_at_unix: row.occurred_at_unix,
    checks,
  };
}

/** `?` placeholders for an `IN` list. */
function placeholders(count: number): string {
  return new Array(count).fill("?").join(", ");
}

/**
 * The child rows for a page of evaluations, in ONE query.
 *
 * One query rather than one per evaluation because a D1 round trip inside a
 * loop over a 100-row page is 100 round trips, and because a partial failure
 * halfway through would publish some decisions with their detectors and some
 * without — which reads as "no detector fired" rather than as an error.
 */
async function guardrailChecksFor(
  db: D1Database,
  evaluationIds: readonly string[],
): Promise<Map<string, StoreRecord[]>> {
  const byEvaluation = new Map<string, StoreRecord[]>();
  if (evaluationIds.length === 0) return byEvaluation;
  const rows = await db
    .prepare(
      `SELECT id, evaluation_id, check_id, detector_id, detector_version, config_digest,
              verdict, action, enforcement_status, error_kind, check_json
         FROM ${GUARDRAIL_CHECK_TABLE}
        WHERE evaluation_id IN (${placeholders(evaluationIds.length)})
        ORDER BY evaluation_id ASC, check_id ASC`,
    )
    .bind(...evaluationIds)
    .all<GuardrailCheckRow>();
  for (const row of rows.results) {
    const bucket = byEvaluation.get(row.evaluation_id);
    if (bucket === undefined) byEvaluation.set(row.evaluation_id, [guardrailCheckDocument(row)]);
    else bucket.push(guardrailCheckDocument(row));
  }
  return byEvaluation;
}

/** One fenced, ordered page of `guardrail_evaluations`, checks attached. */
async function guardrailEvaluationPage(
  db: D1Database,
  scope: CallerScope,
  limit: number,
  offset: number,
): Promise<{ records: StoreRecord[]; total: number }> {
  const fence = guardrailTenantFence(scope);
  const rows = await db
    .prepare(
      `SELECT ${GUARDRAIL_EVALUATION_COLUMNS}, count(*) OVER() AS total
         FROM ${GUARDRAIL_EVALUATION_TABLE}${fence.sql === "" ? "" : ` WHERE ${fence.sql}`}
        ${GUARDRAIL_EVALUATION_ORDER}
        LIMIT ? OFFSET ?`,
    )
    .bind(...fence.params, limit, offset)
    .all<GuardrailEvaluationRow>();
  const checks = await guardrailChecksFor(
    db,
    rows.results.map((row) => row.id),
  );
  return {
    records: rows.results.map((row) => guardrailEvaluationDocument(row, checks.get(row.id) ?? [])),
    // `count(*) OVER()` is on every row and absent when there are none — the
    // same reading the two sibling readers take.
    total: rows.results[0]?.total ?? 0,
  };
}

/**
 * `GET /admin/v1/guardrail-evaluations` — every screening decision, newest
 * first.
 *
 * ## Why this is not the generic list handler
 *
 * It used to be, and that was the defect (#665). The generic handler paged the
 * `guardrail-evaluations` DOCUMENT collection in `control_plane_resources`,
 * which has no writer, so an authenticated, RBAC-gated compliance API answered
 * "no guardrail ever evaluated anything" on every deployment while the gateway
 * screened traffic. The other half of the defect was that the evidence TABLES
 * did not exist, so the fix is the one #664 used: the migration, the writer
 * (`apps/gateway/src/guardrails/`) and this reader in one change, never the
 * reader alone.
 */
function listGuardrailEvaluationsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);
    const db = deps.controlDatabase;

    if (db === null) {
      // No control database means no evidence tables AND no gateway writing
      // them. The document collection is the only guardrail-evidence surface
      // such a deployment has.
      const page = await deps.store.list("guardrail-evaluations", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const page = await guardrailEvaluationPage(db, scope, query.limit, query.offset);
    return json(c, 200, adminListPaginated(page.records, page.total, query.offset, query.limit));
  };
}

// ---------------------------------------------------------------------------
// The investigation view
// ---------------------------------------------------------------------------

/** The three selectors `docs/guardrails/investigation-view.md` documents. */
const INVESTIGATION_SELECTORS = ["request_id", "trace_id", "agent_run_id"] as const;
type InvestigationSelector = (typeof INVESTIGATION_SELECTORS)[number];

/**
 * How many correlated requests one investigation may join.
 *
 * A `trace_id` or an `agent_run_id` legitimately spans many requests (an agent
 * run is a whole conversation), and the response is materialized in memory
 * before it is written. Bounded rather than unbounded because an investigation
 * that dies at 2 GB has investigated nothing; the bound is stated here rather
 * than left implicit so a truncated timeline is a decision with a number
 * attached.
 */
const INVESTIGATION_MAX_REQUESTS = 50;

/** Rows a table contributes to the timeline, as documents. */
interface TimelineLeg {
  readonly records: StoreRecord[];
}

/**
 * `GET /admin/v1/investigations` — who / why / target / action / cost for ONE
 * request, joined across every evidence table in the control database.
 *
 * ## The order of operations is the fence
 *
 * The selector is resolved FIRST, against the two tenant-fenced evidence tables
 * (`guardrail_evaluations` and `request_logs`). If neither yields a row the
 * answer is 404 — and that is what makes the un-fenced legs safe: `billing_events`
 * has no tenant column at all (its rows are keyed by `request_id`), so it is
 * only ever read for request ids the caller has ALREADY been shown to own. A
 * reader that queried billing first and fenced afterwards would leak the
 * existence and the cost of another tenant's request through a 200/404
 * difference.
 *
 * ## What is joined, and what is honestly empty
 *
 * Joined for real, all from the CONTROL database: `requests` (`request_logs`,
 * #664), `guardrail_evaluations` + their checks (#665), `audit_events`,
 * `agent_runs` / `agent_events`, `billing_events` and the cost summed from
 * them.
 *
 * `approvals` is `[]` and stays `[]`: there is no approvals table in
 * `sql/d1-ts/control/`, and fabricating an empty array is the honest answer
 * ("this deployment records no approvals") where inventing rows would not be.
 * The field is in the response because the documented schema requires it and a
 * client that switched on its presence would break on a version skew, not
 * because this reader knows something about approvals.
 */
function getGuardrailInvestigationHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const url = new URL(c.req.url);

    const selected = INVESTIGATION_SELECTORS.map((name): [InvestigationSelector, string | null] => [
      name,
      url.searchParams.get(name),
    ]).filter((entry): entry is [InvestigationSelector, string] => {
      const value = entry[1];
      return value !== null && value.trim() !== "";
    });
    if (selected.length !== 1) {
      throw new HttpError(
        400,
        "invalid_request",
        `exactly one of ${INVESTIGATION_SELECTORS.join(", ")} is required`,
      );
    }
    const [column, value] = selected[0] as [InvestigationSelector, string];
    const selector = `${column}=${value}`;

    const db = deps.controlDatabase;
    if (db === null) {
      // Nothing writes the evidence tables in a memory-store deployment, so
      // there is nothing to investigate and saying so is the truthful answer.
      throw new HttpError(404, "guardrail_investigation_not_found", `no evidence for ${selector}`);
    }

    // ---- 1. The two FENCED evidence tables resolve the selector ------------
    const evaluationFence = guardrailTenantFence(scope);
    const evaluationRows = await db
      .prepare(
        `SELECT ${GUARDRAIL_EVALUATION_COLUMNS}
           FROM ${GUARDRAIL_EVALUATION_TABLE}
          WHERE ${column} = ?${evaluationFence.sql === "" ? "" : ` AND ${evaluationFence.sql}`}
          ${GUARDRAIL_EVALUATION_ORDER}
          LIMIT ?`,
      )
      .bind(value, ...evaluationFence.params, INVESTIGATION_MAX_REQUESTS)
      .all<GuardrailEvaluationRow>();

    const requestFence = requestLogTenantFence(scope);
    const requestRows = await db
      .prepare(
        `SELECT ${REQUEST_LOG_COLUMNS}
           FROM ${REQUEST_LOG_TABLE}
          WHERE ${column} = ?${
            requestFence.sql === "" ? "" : ` AND ${requestFence.sql.replace(/^ WHERE /, "")}`
          }
          ${REQUEST_LOG_ORDER}
          LIMIT ?`,
      )
      .bind(value, ...requestFence.params, INVESTIGATION_MAX_REQUESTS)
      .all<RequestLogRow>();

    if (evaluationRows.results.length === 0 && requestRows.results.length === 0) {
      throw new HttpError(404, "guardrail_investigation_not_found", `no evidence for ${selector}`);
    }

    const requestIds = [
      ...new Set([
        ...evaluationRows.results.map((row) => row.request_id),
        ...requestRows.results.map((row) => row.request_id),
      ]),
    ].slice(0, INVESTIGATION_MAX_REQUESTS);

    // ---- 2. Everything else hangs off the ids the fence already cleared ----
    const checks = await guardrailChecksFor(
      db,
      evaluationRows.results.map((row) => row.id),
    );
    const audit = await investigationLeg(
      db,
      `SELECT id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json,
              chain_key, seq, prev_hash, row_hash
         FROM ${AUDIT_TABLE}
        WHERE request_id IN (${placeholders(requestIds.length)})
        ORDER BY occurred_at_unix ASC, id ASC`,
      requestIds,
      (row) => auditEventDocument(row as AuditEventRow),
    );
    const agentRuns = await investigationLeg(
      db,
      `SELECT id, request_id, tenant, started_at_unix, completed_at_unix, run_json
         FROM agent_runs
        WHERE request_id IN (${placeholders(requestIds.length)})
        ORDER BY started_at_unix ASC, id ASC`,
      requestIds,
      (row) => correlatedDocument(row as Record<string, unknown>, "run_json", "agent_run"),
    );
    const agentEvents = await investigationLeg(
      db,
      `SELECT id, run_id, request_id, tenant, occurred_at_unix, event_json
         FROM agent_run_events
        WHERE request_id IN (${placeholders(requestIds.length)})
        ORDER BY occurred_at_unix ASC, id ASC`,
      requestIds,
      (row) => correlatedDocument(row as Record<string, unknown>, "event_json", "agent_run_event"),
    );
    const billing = await investigationLeg(
      db,
      `SELECT billing_event_id, request_id, provider_attempt_index, occurred_at_unix, event_json
         FROM billing_events
        WHERE request_id IN (${placeholders(requestIds.length)})
        ORDER BY occurred_at_unix ASC, billing_event_id ASC`,
      requestIds,
      (row) =>
        correlatedDocument(
          row as Record<string, unknown>,
          "event_json",
          "billing_event",
          "billing_event_id",
        ),
    );

    const totalCostUsd = billing.records.reduce((sum, record) => {
      const cost = record["cost_usd"];
      return typeof cost === "number" && Number.isFinite(cost) ? sum + cost : sum;
    }, 0);

    const evaluations = evaluationRows.results.map((row) =>
      guardrailEvaluationDocument(row, checks.get(row.id) ?? []),
    );
    const requests = requestRows.results.map(requestLogDocument);

    return json(c, 200, {
      object: "guardrail_investigation",
      selector,
      identity: investigationIdentity(evaluationRows.results, requestRows.results),
      agent_runs: agentRuns.records,
      agent_events: agentEvents.records,
      requests,
      guardrail_evaluations: evaluations,
      audit_events: audit.records,
      // See the docblock: there is no approvals table in this schema.
      approvals: [],
      billing_events: billing.records,
      total_cost_usd: totalCostUsd,
      final_outcome: finalOutcome(evaluationRows.results, requestRows.results),
    });
  };
}

/** Run one `WHERE request_id IN (...)` leg and project its rows. */
async function investigationLeg(
  db: D1Database,
  sql: string,
  requestIds: readonly string[],
  project: (row: unknown) => StoreRecord,
): Promise<TimelineLeg> {
  if (requestIds.length === 0) return { records: [] };
  const rows = await db
    .prepare(sql)
    .bind(...requestIds)
    .all<Record<string, unknown>>();
  return { records: rows.results.map(project) };
}

/**
 * A correlated row published as its stored document plus its columns.
 *
 * Same precedence rule as everywhere else in this module — the columns are
 * applied last, so a document cannot rename the `request_id` that is the
 * investigation's join key.
 *
 * `idColumn` exists because `billing_events` spells its primary key
 * `billing_event_id`, not `id`. Publishing it under BOTH names rather than
 * renaming it: `id` is what makes every element of the timeline addressable in
 * the same way, and the original column is what a reader cross-checking against
 * the table needs.
 */
function correlatedDocument(
  row: Record<string, unknown>,
  documentColumn: string,
  object: string,
  idColumn = "id",
): StoreRecord {
  const { [documentColumn]: raw, ...columns } = row;
  return {
    ...documentOf(typeof raw === "string" ? raw : "{}"),
    ...columns,
    id: String(columns[idColumn] ?? ""),
    object,
  };
}

/**
 * WHO — the calling identity, taken from the evidence rather than from the
 * query.
 *
 * The guardrail row is preferred because it carries the resolved SCOPE
 * (`scope_type`/`scope_id`) and the acting credential (`subject_id`); the
 * request log is the fallback for a request that reached no guardrail policy.
 * `null` when neither knows, which is the honest answer for an anonymous call —
 * an identity block full of nulls would read as a redaction rather than as an
 * absence.
 */
function investigationIdentity(
  evaluations: readonly GuardrailEvaluationRow[],
  requests: readonly RequestLogRow[],
): Record<string, unknown> | null {
  const evaluation = evaluations[0];
  if (evaluation !== undefined) {
    return {
      organization_id: evaluation.tenant,
      api_key_id: evaluation.subject_id,
      scope_type: evaluation.scope_type,
      scope_id: evaluation.scope_id,
    };
  }
  const request = requests[0];
  if (request === undefined) return null;
  return {
    organization_id: request.tenant,
    project_id: request.project,
    workspace_id: request.workspace,
    api_key_id: request.api_key_id,
  };
}

/**
 * `final_outcome` — `blocked` / `failed` / `succeeded` / `decision_only`.
 *
 * A guardrail BLOCK wins over the HTTP status, and deliberately: a request the
 * gateway refused at 403 and a request the provider failed at 403 are the same
 * status and different incidents, and the evidence knows which happened.
 * `decision_only` is the case with evidence but no request log — screening ran
 * on a path (MCP, an agent tool call) that writes no inference row.
 */
function finalOutcome(
  evaluations: readonly GuardrailEvaluationRow[],
  requests: readonly RequestLogRow[],
): string {
  if (evaluations.some((row) => row.action === "block" && row.enforcement_status === "enforced")) {
    return "blocked";
  }
  const request = requests[0];
  if (request === undefined) return "decision_only";
  const status = request.status_code ?? 0;
  if (status >= 400) return "failed";
  return status > 0 ? "succeeded" : "decision_only";
}

/**
 * PORT-TODO(P: inventory-edge-control §9.3 evidence) — CLOSED. Every leg of
 * this group now reads a table with a writer: `audit-events` (see
 * {@link listAuditEventsHandler}), `request-logs` / `request-log-exports`
 * (#664, {@link listRequestLogsHandler}) and — with this change —
 * `guardrail-evaluations` / `investigations` (#665,
 * {@link listGuardrailEvaluationsHandler} and
 * {@link getGuardrailInvestigationHandler}) over
 * `sql/d1-ts/control/0004_guardrail_evaluations.sql`.
 *
 * The two `readOnlyCollection` declarations below are KEPT even though every
 * operation in them now has an override: they are what `crudGroup` matches the
 * contract's operation ids against, and deleting them would make the build
 * throw rather than silently drop a route.
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
    listGuardrailEvaluations: listGuardrailEvaluationsHandler(),
    getGuardrailInvestigation: getGuardrailInvestigationHandler(),
  },
);
