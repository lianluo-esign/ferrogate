/**
 * Contract group `admin_cost_record` (2 operations) — per-request cost
 * attribution and the chargeback export (#677).
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES
 * ============================================================================
 *
 * Finance could read a MONTHLY rollup by metadata key
 * (`usage_metadata_rollups`) and a per-agent burn (`agent_cost_burn`), and
 * could not answer the question a chargeback conversation actually starts with:
 * *which customer, which project, which key, which model, which tag and which
 * agent run produced this $4,200*. There was no per-request cost surface in the
 * tree, and nothing to hand an FP&A team.
 *
 * Both halves of the answer were already durable and nothing joined them:
 *
 *  - `request_logs` (#664) — one row per DECISION, carrying the authenticated
 *    tenant / project / workspace / key, the resolved model, the agent run and
 *    the outcome;
 *  - `billing_events` (#663, #667) — one row per priced provider ATTEMPT,
 *    carrying `cost_usd`, the cached/reasoning token split, and the request
 *    metadata tags.
 *
 * ============================================================================
 * A JOIN, NOT A THIRD TABLE — AND WHY THAT IS THE WHOLE DESIGN
 * ============================================================================
 *
 * The obvious shape is a `cost_records` table the gateway writes on every
 * request. It is the wrong shape. A third durable figure for the same money is
 * a figure that can DISAGREE with `billing_ledger`, and the day it does, an
 * operator has two numbers and no way to tell which one billed the customer.
 * That is a reconciliation problem, not a feature.
 *
 * So there is no migration in this change and no new writer. The cost on every
 * row here is `SUM(billing_events.event_json -> cost_usd)` — the same documents
 * `D1LedgerStore.record` wrote in the same batch as the `billing_ledger` row,
 * and the same ones the #665 investigation view already sums. If the ledger
 * moves, this moves with it, by construction.
 *
 * ============================================================================
 * THE FENCE, AND WHY THE ORDER OF THE TWO TABLES IS THE FENCE
 * ============================================================================
 *
 * `billing_events` has NO tenant column — its rows are keyed by `request_id`,
 * because the metering path identifies a charge by its provider attempt. So it
 * cannot fence itself, and it is never the driving side of this query.
 *
 * The query is driven by `request_logs`, whose `tenant` column carries the
 * AUTHENTICATED tenant and is fenced with strict equality
 * ({@link costRecordTenantFence}); `billing_events` is reached only through a
 * `LEFT JOIN` and an `EXISTS` predicate on a `request_id` the fence has already
 * cleared. Both of those can NARROW the fenced set and neither can widen it.
 * `getGuardrailInvestigation` states the same rule for the same reason.
 *
 * The cost of driving from the fenced side is stated rather than hidden: a
 * `billing_events` row whose `request_logs` row is absent — because the log has
 * aged past its retention horizon (#664's sweeper), or because a future metered
 * path writes no inference log — contributes nothing here. That is a
 * deliberately conservative failure: the export under-reports visibly (the
 * request is simply not in it) rather than emitting a cost with no owner, which
 * is the one thing a chargeback file must never do.
 */
import { HttpError } from "../middleware/errors.js";
import { type CsvValue, encodeCsv } from "../export/csv.js";
import { type ParquetColumn, type ParquetValue, encodeParquet } from "../export/parquet.js";
import type { CallerScope, StoreRecord } from "../ports.js";
import { adminListPaginated, parseListQuery } from "../responses.js";
import { BILLING_EVENT_TABLE, REQUEST_LOG_TABLE } from "../store/d1.js";
import {
  type GroupModule,
  type Handler,
  crudGroup,
  depsOf,
  json,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

/** `object` on every cost record, in the list and in the JSONL export alike. */
const COST_RECORD_OBJECT = "cost_record";

/**
 * The tenant fence for the chargeback surface.
 *
 * Stated separately from `admin_request_log.ts::requestLogTenantFence` for the
 * reason that file gives about its own siblings: these predicates read
 * independent facts and folding them into one helper would make a later
 * divergence in any of them look like a typo rather than a decision. It is the
 * same shape and the same strictness — a `NULL` tenant matches nobody, because
 * an un-attributed request is a platform-operator call and its COST is the
 * operator's own, not a tenant's to read.
 *
 * A cost record is the most identity-dense document this product publishes: it
 * names a customer, the feature they ran, the key they ran it with and what it
 * cost. A leak here is a competitive-intelligence leak, not just a privacy one.
 */
function costRecordTenantFence(scope: CallerScope): { sql: string; params: string[] } {
  if (scope.kind === "platform_operator") return { sql: "", params: [] };
  return { sql: `rl.tenant = ?`, params: [scope.tenantId] };
}

/**
 * The per-request aggregate over `billing_events`, as a derived table.
 *
 * ## Why it is aggregated BEFORE the join
 *
 * #135: one request can be several provider ATTEMPTS, each with its own
 * `billing_events` row. A plain `LEFT JOIN billing_events` would emit one
 * output row per attempt, so every retried request would appear twice in a
 * chargeback export and the customer would be billed twice for a retry the
 * gateway performed on their behalf. Aggregating first makes the chargeback
 * unit the REQUEST, which is what the issue asks for.
 *
 * ## Why `SUM(json_extract(...))` rather than `SUM(COALESCE(..., 0))` for cost
 *
 * Because a SUM over rows that are all NULL is NULL, and that is the answer we
 * want. #663's whole point is that a usage nothing could price still leaves a
 * durable, re-priceable row with NO `cost_usd`; collapsing that to `0` would
 * report a free request where the truth is an unknown one, and an operator
 * reconciling a bill would never find the gap. The TOKEN sums do use
 * `COALESCE(..., 0)`, because a missing counter there really is zero
 * consumption of that kind.
 *
 * ## Why every extract is guarded by `json_valid`
 *
 * `json_extract` RAISES on malformed JSON, so one corrupt `event_json` row
 * would take the entire chargeback report down with a 500 — an outage of the
 * whole surface caused by a single bad row. Guarded, a corrupt row instead
 * counts as an ATTEMPT WITH AN UNKNOWN COST: it is included in
 * `billed_attempts` and in `unpriced_attempts`, so it is visible and
 * re-priceable, and it can never masquerade as a priced $0.
 *
 * ## Why the tags come from the HIGHEST attempt index
 *
 * Request metadata is a REQUEST fact, so every attempt of one request carries
 * the same map and any of them would do. It is pinned to the highest attempt
 * anyway — via SQLite's documented bare-column rule, where a query with exactly
 * one `MAX()` takes its bare columns from the row that produced the maximum —
 * so that two reads of the same data cannot disagree if that assumption ever
 * stops holding.
 */
const COST_AGGREGATE = `(
    SELECT request_id,
           SUM(CASE WHEN json_valid(event_json)
                    THEN json_extract(event_json, '$.cost_usd') END)             AS cost_usd,
           COUNT(*)                                                              AS billed_attempts,
           SUM(CASE WHEN json_valid(event_json)
                     AND json_extract(event_json, '$.cost_usd') IS NOT NULL
                    THEN 0 ELSE 1 END)                                           AS unpriced_attempts,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.prompt_tokens'), 0)
                    ELSE 0 END)                                                  AS prompt_tokens,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.completion_tokens'), 0)
                    ELSE 0 END)                                                  AS completion_tokens,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.total_tokens'), 0)
                    ELSE 0 END)                                                  AS total_tokens,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.cached_input_tokens'), 0)
                    ELSE 0 END)                                                  AS cached_input_tokens,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.cache_write_tokens'), 0)
                    ELSE 0 END)                                                  AS cache_write_tokens,
           SUM(CASE WHEN json_valid(event_json)
                    THEN COALESCE(json_extract(event_json, '$.usage.reasoning_tokens'), 0)
                    ELSE 0 END)                                                  AS reasoning_tokens,
           MAX(provider_attempt_index)                                           AS last_attempt_index,
           CASE WHEN json_valid(event_json)
                THEN json_extract(event_json, '$.metadata') END                  AS tags_json
      FROM ${BILLING_EVENT_TABLE}
     GROUP BY request_id
  )`;

/**
 * The projection every cost read shares.
 *
 * Named once so the list and the three export formats cannot drift into
 * answering different documents for the same request — which is how a console
 * and a finance spreadsheet end up disagreeing about a number that is on an
 * invoice.
 *
 * The three basic token counters prefer the METERED figure and fall back to the
 * request log's. Not for redundancy: they are the same counters from two
 * recorders, and the priced record has to be the authority for anything that
 * sits next to a cost, or a row could carry tokens from one source and money
 * from the other. The fallback exists for a request that was never metered at
 * all — a guardrail block, a 429 — where the decision log is the only usage
 * fact there is. `COALESCE` is exactly right here and `0` is not a trap: a
 * metered request always produces a number (possibly `0`), so the fallback fires
 * only when there is no metering row.
 */
const COST_RECORD_COLUMNS = `rl.request_id, rl.trace_id, rl.agent_run_id, rl.tenant, rl.project,
       rl.workspace, rl.api_key_id, rl.route, rl.provider, rl.logical_model, rl.provider_model,
       rl.status_code, rl.error_code, rl.cache_status, rl.streamed, rl.latency_ms,
       rl.started_at_unix, rl.completed_at_unix,
       COALESCE(cost.prompt_tokens, rl.prompt_tokens)         AS prompt_tokens,
       COALESCE(cost.completion_tokens, rl.completion_tokens) AS completion_tokens,
       COALESCE(cost.total_tokens, rl.total_tokens)           AS total_tokens,
       cost.cached_input_tokens, cost.cache_write_tokens, cost.reasoning_tokens,
       cost.cost_usd, cost.billed_attempts, cost.unpriced_attempts, cost.tags_json`;

/**
 * `ORDER BY started_at_unix DESC, request_id ASC` — the same order the request
 * log reads in, and for the same two reasons.
 *
 * Newest first because a cost question is asked backwards from a bill. And
 * `request_id` as the tiebreaker is load-bearing rather than tidy:
 * `started_at_unix` is whole SECONDS, a busy gateway puts thousands of requests
 * in one of them, and an unstable sort inside a second lets a page boundary
 * re-serve one row and skip another. In an evidence export that is a missing
 * decision; in a chargeback export it is a missing charge, which someone
 * eventually notices in a reconciliation and cannot explain.
 */
const COST_RECORD_ORDER = "ORDER BY rl.started_at_unix DESC, rl.request_id ASC";

interface CostRecordRow {
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
  readonly streamed: number | null;
  readonly latency_ms: number | null;
  readonly started_at_unix: number;
  readonly completed_at_unix: number | null;
  readonly prompt_tokens: number | null;
  readonly completion_tokens: number | null;
  readonly total_tokens: number | null;
  readonly cached_input_tokens: number | null;
  readonly cache_write_tokens: number | null;
  readonly reasoning_tokens: number | null;
  readonly cost_usd: number | null;
  readonly billed_attempts: number | null;
  readonly unpriced_attempts: number | null;
  readonly tags_json: string | null;
  readonly total?: number;
}

/** The stored metadata map, or `{}` when there is none or it does not parse. */
function tagsOf(raw: string | null): Record<string, string> {
  if (raw === null) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null) return {};
    const tags: Record<string, string> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      // Metadata is bounded to string values at ingress (#171); anything else
      // is stringified rather than dropped, because losing an attribution key
      // silently is worse than publishing an odd-looking one.
      tags[key] = typeof value === "string" ? value : String(value);
    }
    return tags;
  } catch {
    return {};
  }
}

/**
 * Project one joined row onto the wire.
 *
 * ## The three states of "what did this cost", kept apart
 *
 * | `metered` | `priced` | `cost_usd` | what happened                          |
 * |---|---|---|---|
 * | `false` | `false` | `null` | nothing metered it — refused, rate-limited |
 * | `true`  | `false` | `null` | metered, nothing could price it (#663)     |
 * | `true`  | `false` | a number | SOME attempts priced, some not           |
 * | `true`  | `true`  | a number | fully priced                             |
 *
 * Collapsing any two of those into "$0" is the failure this whole surface has
 * to avoid: a finance total built on it would be quietly, unfalsifiably low.
 * `unpriced_attempts` is published so an operator can find exactly the rows a
 * re-price would change.
 */
function costRecordDocument(row: CostRecordRow): StoreRecord {
  const metered = row.billed_attempts !== null && row.billed_attempts > 0;
  const unpricedAttempts = row.unpriced_attempts ?? 0;
  return {
    object: COST_RECORD_OBJECT,
    // `id` is the request id: the chargeback unit IS the request, and every
    // other evidence surface (`request-logs`, `investigations`, `audit-events`)
    // is addressable by the same key, so a finance row joins to its evidence.
    id: row.request_id,
    request_id: row.request_id,
    trace_id: row.trace_id,
    agent_run_id: row.agent_run_id,
    tenant_id: row.tenant,
    project_id: row.project,
    workspace_id: row.workspace,
    api_key_id: row.api_key_id,
    provider: row.provider,
    logical_model: row.logical_model,
    provider_model: row.provider_model,
    route: row.route,
    status_code: row.status_code,
    error_code: row.error_code,
    cache_status: row.cache_status,
    streamed: row.streamed === 1,
    latency_ms: row.latency_ms,
    started_at_unix: row.started_at_unix,
    completed_at_unix: row.completed_at_unix,
    prompt_tokens: row.prompt_tokens,
    completion_tokens: row.completion_tokens,
    total_tokens: row.total_tokens,
    // #667's counters exist only on the metering document. `null` rather than
    // `0` when there is none: `0` would assert the provider reported no cached
    // tokens, which nobody ever asked it.
    cached_input_tokens: metered ? (row.cached_input_tokens ?? 0) : null,
    cache_write_tokens: metered ? (row.cache_write_tokens ?? 0) : null,
    reasoning_tokens: metered ? (row.reasoning_tokens ?? 0) : null,
    cost_usd: row.cost_usd,
    metered,
    priced: metered && unpricedAttempts === 0 && row.cost_usd !== null,
    billed_attempts: row.billed_attempts ?? 0,
    unpriced_attempts: unpricedAttempts,
    tags: tagsOf(row.tags_json),
  };
}

// ---------------------------------------------------------------------------
// Filters — the six dimensions the "Done when" names, plus a time window
// ---------------------------------------------------------------------------

/** One `AND`-ed predicate and its bound parameters. */
interface Predicate {
  readonly sql: string;
  readonly params: (string | number)[];
}

/** A trimmed, non-empty query parameter, or `undefined`. */
function param(url: URL, name: string): string | undefined {
  const value = url.searchParams.get(name)?.trim() ?? "";
  return value === "" ? undefined : value;
}

/** A non-negative integer query parameter, or `undefined`. */
function intParam(url: URL, name: string): number | undefined {
  const value = param(url, name);
  if (value === undefined) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined;
}

/**
 * The `?tag=` predicate — the ONE filter that reads the un-fenced table.
 *
 * `tag=team:growth` matches the pair; `tag=team` matches the KEY's presence,
 * which is how an operator asks "everything that carries a team attribution at
 * all" before they know the values. The first colon splits, so a value may
 * itself contain colons (`tag=owner:svc:checkout` is `owner` → `svc:checkout`).
 *
 * `json_each` over the metadata map rather than
 * `json_extract(event_json, '$.metadata.' || ?)`: building a JSON PATH out of a
 * caller-supplied key would make the key a fragment of an expression, and a key
 * containing `.` or `[` would silently select a different — possibly another
 * tenant's — field of the document. The table-valued form binds the key as a
 * VALUE, so it cannot be anything but a key.
 *
 * The `COALESCE(...)` around the extract is not decoration: `json_each(NULL)`
 * raises, so a metering row with no `metadata` at all (or with a corrupt
 * document) would otherwise fail the whole query rather than simply not match.
 *
 * This predicate can only ever NARROW the fenced set — it is an `EXISTS`
 * correlated on `rl.request_id`, which the tenant fence has already
 * constrained. `test/cost-records-read.test.ts` proves that from both tenants'
 * sides.
 */
function tagPredicate(tag: string): Predicate {
  const separator = tag.indexOf(":");
  const key = separator === -1 ? tag : tag.slice(0, separator);
  const value = separator === -1 ? undefined : tag.slice(separator + 1);
  const valueClause = value === undefined ? "" : " AND tag.value = ?";
  const params: (string | number)[] = value === undefined ? [key] : [key, value];
  return {
    sql: `EXISTS (
            SELECT 1
              FROM ${BILLING_EVENT_TABLE} be,
                   json_each(COALESCE(CASE WHEN json_valid(be.event_json)
                                           THEN json_extract(be.event_json, '$.metadata') END,
                                      '{}')) tag
             WHERE be.request_id = rl.request_id AND tag.key = ?${valueClause})`,
    params,
  };
}

/**
 * Every filter the caller asked for, as `AND`-ed predicates.
 *
 * `tenant` is here rather than folded into the fence ON PURPOSE. For a platform
 * operator it is a narrowing; for a tenant caller it is ALSO just a narrowing,
 * because it is `AND`-ed with a fence that already pins `rl.tenant`. Asking for
 * someone else's tenant therefore yields the empty set instead of their data —
 * a filter that REPLACED the fence would be a one-parameter cross-tenant read
 * of the most sensitive report in the product.
 */
function costFilters(url: URL): Predicate[] {
  const predicates: Predicate[] = [];
  const push = (sql: string, ...params: (string | number)[]): void => {
    predicates.push({ sql, params });
  };

  const tenant = param(url, "tenant");
  if (tenant !== undefined) push("rl.tenant = ?", tenant);

  const project = param(url, "project");
  if (project !== undefined) push("rl.project = ?", project);

  const workspace = param(url, "workspace");
  if (workspace !== undefined) push("rl.workspace = ?", workspace);

  const apiKeyId = param(url, "api_key_id");
  if (apiKeyId !== undefined) push("rl.api_key_id = ?", apiKeyId);

  const agentRunId = param(url, "agent_run_id");
  if (agentRunId !== undefined) push("rl.agent_run_id = ?", agentRunId);

  const provider = param(url, "provider");
  if (provider !== undefined) push("rl.provider = ?", provider);

  // EITHER spelling. Finance asks for "claude-3-5-sonnet" and does not know
  // whether the row holds the model the caller NAMED or the dated snapshot the
  // provider was actually asked for; matching only one of them would silently
  // drop half of that model's spend, which is the failure mode this whole
  // surface exists to end.
  const model = param(url, "model");
  if (model !== undefined) push("(rl.logical_model = ? OR rl.provider_model = ?)", model, model);

  // `since` INCLUSIVE, `until` EXCLUSIVE, so two adjacent billing periods
  // partition the traffic instead of both claiming the boundary second.
  const since = intParam(url, "since");
  if (since !== undefined) push("rl.started_at_unix >= ?", since);
  const until = intParam(url, "until");
  if (until !== undefined) push("rl.started_at_unix < ?", until);

  const tag = param(url, "tag");
  if (tag !== undefined) predicates.push(tagPredicate(tag));

  return predicates;
}

// ---------------------------------------------------------------------------
// The page
// ---------------------------------------------------------------------------

/**
 * One fenced, filtered, ordered page of cost records, with the pre-window
 * total.
 *
 * `count(*) OVER()` computes the total in the SAME statement as the page, so
 * the two cannot disagree under a concurrent write — the device every sibling
 * evidence reader uses. It is the count of what the caller MAY see, because it
 * is computed after the fence and after the filters; a total that counted rows
 * the fence hides would leak the existence of another tenant's traffic through
 * a number.
 */
async function costRecordPage(
  db: D1Database,
  scope: CallerScope,
  url: URL,
  limit: number,
  offset: number,
): Promise<{ rows: CostRecordRow[]; total: number }> {
  const fence = costRecordTenantFence(scope);
  const filters = costFilters(url);
  const clauses = [...(fence.sql === "" ? [] : [fence.sql]), ...filters.map((f) => f.sql)];
  const where = clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
  const params: (string | number)[] = [
    ...fence.params,
    ...filters.flatMap((filter) => filter.params),
  ];

  const result = await db
    .prepare(
      `SELECT ${COST_RECORD_COLUMNS}, count(*) OVER() AS total
         FROM ${REQUEST_LOG_TABLE} rl
         LEFT JOIN ${COST_AGGREGATE} cost ON cost.request_id = rl.request_id${where}
        ${COST_RECORD_ORDER}
        LIMIT ? OFFSET ?`,
    )
    .bind(...params, limit, offset)
    .all<CostRecordRow>();

  // `count(*) OVER()` is on every row and absent when there are none, so an
  // empty page past the end reports 0 — the reading every sibling reader takes.
  return { rows: result.results, total: result.results[0]?.total ?? 0 };
}

/**
 * `GET /admin/v1/cost-records` — per-request cost, newest first.
 *
 * The paginated envelope UNCONDITIONALLY, like the two sibling evidence lists:
 * a client that got a bare `{object,data}` for an un-queried request could not
 * tell a first page from the whole month, and on a spend report that difference
 * is a wrong number rather than a missing one.
 */
function listCostRecordsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const db = deps.controlDatabase;

    if (db === null) {
      // No control database means neither table exists AND no gateway is
      // writing them — `controlDatabase` is `null` exactly when
      // `CONTROL_PLANE_STORE = "memory"` or no `DB` is bound. An empty page is
      // the truthful answer for a deployment that records no cost, and it is
      // the same answer the sibling evidence readers give.
      return json(c, 200, adminListPaginated([], 0, query.offset, query.limit));
    }

    const page = await costRecordPage(db, scope, url, query.limit, query.offset);
    return json(
      c,
      200,
      adminListPaginated(page.rows.map(costRecordDocument), page.total, query.offset, query.limit),
    );
  };
}

// ---------------------------------------------------------------------------
// The export
// ---------------------------------------------------------------------------

/**
 * The export's page size when the caller names none, and its ceiling.
 *
 * Larger than the list default because the two operations answer different
 * questions — a console pages, a finance pull wants a month — and BOUNDED
 * rather than unlimited because a Worker materializes the whole file in memory
 * before it writes it (a Parquet file especially: the column chunks cannot be
 * laid out until every value is known). An operator who wants more pages with
 * `?offset=`, which is what a resumable export needs anyway; an unbounded
 * single response that dies at 2 GB has exported nothing.
 */
const COST_EXPORT_DEFAULT_LIMIT = 1_000;
const COST_EXPORT_MAX_LIMIT = 10_000;

/**
 * The FIXED column projection of the tabular exports.
 *
 * Order is part of the contract: a chargeback CSV is loaded by a spreadsheet
 * macro or a warehouse `COPY` that indexes columns positionally, so reordering
 * these is a breaking change and is pinned by
 * `test/cost-records-read.test.ts`. New columns go on the END.
 *
 * `tags` is one JSON-encoded column rather than one column per key, because the
 * key SET is per tenant and per request — a column-per-key projection would
 * make the schema of the export depend on which rows happened to be in it, so
 * two months of the same query would not concatenate.
 */
const COST_EXPORT_COLUMNS: readonly ParquetColumn[] = [
  { name: "request_id", type: "string" },
  { name: "started_at_unix", type: "int64" },
  { name: "completed_at_unix", type: "int64" },
  { name: "tenant_id", type: "string" },
  { name: "project_id", type: "string" },
  { name: "workspace_id", type: "string" },
  { name: "api_key_id", type: "string" },
  { name: "agent_run_id", type: "string" },
  { name: "trace_id", type: "string" },
  { name: "provider", type: "string" },
  { name: "logical_model", type: "string" },
  { name: "provider_model", type: "string" },
  { name: "route", type: "string" },
  { name: "status_code", type: "int64" },
  { name: "error_code", type: "string" },
  { name: "cache_status", type: "string" },
  { name: "streamed", type: "boolean" },
  { name: "latency_ms", type: "int64" },
  { name: "prompt_tokens", type: "int64" },
  { name: "completion_tokens", type: "int64" },
  { name: "total_tokens", type: "int64" },
  { name: "cached_input_tokens", type: "int64" },
  { name: "cache_write_tokens", type: "int64" },
  { name: "reasoning_tokens", type: "int64" },
  { name: "cost_usd", type: "double" },
  { name: "priced", type: "boolean" },
  { name: "metered", type: "boolean" },
  { name: "billed_attempts", type: "int64" },
  { name: "unpriced_attempts", type: "int64" },
  { name: "tags", type: "string" },
];

const COST_EXPORT_COLUMN_NAMES = COST_EXPORT_COLUMNS.map((column) => column.name);

/** The export formats this surface can actually produce. */
const COST_EXPORT_FORMATS = ["csv", "jsonl", "parquet"] as const;
type CostExportFormat = (typeof COST_EXPORT_FORMATS)[number];

/**
 * Resolve `?format=`, defaulting to CSV and REFUSING anything else.
 *
 * A 400 rather than a silent fallback: a pipeline that asked for Parquet and
 * was handed CSV would either fail far away from the cause or, worse, parse the
 * bytes as something they are not. The issue's "Done when" names CSV first,
 * which is also what an analyst opening one file wants, so it is the default.
 */
function resolveFormat(url: URL): CostExportFormat {
  const requested = param(url, "format")?.toLowerCase() ?? "csv";
  const match = COST_EXPORT_FORMATS.find((format) => format === requested);
  if (match === undefined) {
    throw new HttpError(
      400,
      "invalid_request",
      `unsupported export format ${JSON.stringify(requested)}; expected one of ${COST_EXPORT_FORMATS.join(", ")}`,
    );
  }
  return match;
}

/** Flatten one record onto the tabular projection. `tags` becomes JSON text. */
function tabularRow(record: StoreRecord): Record<string, ParquetValue & CsvValue> {
  const row: Record<string, ParquetValue & CsvValue> = {};
  for (const name of COST_EXPORT_COLUMN_NAMES) {
    const value = record[name];
    if (name === "tags") {
      row[name] = JSON.stringify(value ?? {});
    } else if (value === null || value === undefined) {
      row[name] = null;
    } else if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      row[name] = value;
    } else {
      row[name] = String(value);
    }
  }
  return row;
}

/**
 * A downloadable response, text or binary, with the same correlation headers
 * `raw()` puts on an inline one.
 *
 * `resource.ts::raw` cannot be reused: it takes a `string` body, and a Parquet
 * file is bytes — round-tripping those through a JS string would re-encode
 * every byte above 0x7f as UTF-8 and corrupt the file. It also does not set
 * `content-disposition`, which every one of these three formats needs: an
 * export is SAVED, and a browser that names the file `cost-record-exports`
 * with no extension has produced something nobody can open.
 *
 * Written here rather than added to `resource.ts` because this is the only
 * download operation in this Worker; if a second one appears, this moves and
 * both use it.
 */
function attachment(
  c: Parameters<Handler>[0],
  contentType: string,
  filename: string,
  body: string | Uint8Array,
): Response {
  const requestId = c.get("requestId") ?? null;
  const headers: Record<string, string> = {
    "content-type": contentType,
    "content-disposition": `attachment; filename="${filename}"`,
  };
  if (requestId !== null) {
    headers["x-request-id"] = requestId;
    headers["x-trace-id"] = requestId;
  }
  return new Response(body as unknown as BodyInit, { status: 200, headers });
}

/**
 * `GET /admin/v1/cost-record-exports` — the same records as CSV, JSONL or
 * Parquet.
 *
 * Same fence, same filters, same projection and same order as
 * {@link listCostRecordsHandler}, by construction: {@link costRecordPage} is
 * the only query either of them runs. An export that could see a row the list
 * cannot is a cross-tenant leak with a different front door, so the two must
 * not have two implementations — and `test/cost-records-read.test.ts` drives
 * the fence through ALL THREE formats for exactly that reason.
 */
function exportCostRecordsHandler(): Handler {
  return async (c) => {
    const deps = depsOf(c);
    const scope = scopeOf(c);
    const url = new URL(c.req.url);
    // Parsed BEFORE the query, so an unsupported format is a 400 rather than a
    // full table scan followed by a 400.
    const format = resolveFormat(url);
    const query = parseListQuery(url, COST_EXPORT_DEFAULT_LIMIT, COST_EXPORT_MAX_LIMIT);
    const db = deps.controlDatabase;

    const records =
      db === null
        ? []
        : (await costRecordPage(db, scope, url, query.limit, query.offset)).rows.map(
            costRecordDocument,
          );

    if (format === "jsonl") {
      const body = records.map((record) => JSON.stringify(record)).join("\n");
      return attachment(
        c,
        // The charset is explicit because `application/x-ndjson` is not a type
        // any runtime recognises as text, and a consumer calling `.text()` on
        // the body is otherwise warned the result may be corrupted.
        "application/x-ndjson; charset=utf-8",
        "ferrogate-cost-records.jsonl",
        // A trailing newline only when there IS a line: JSONL readers treat a
        // blank line as an error, so an empty export must be zero bytes.
        body === "" ? "" : `${body}\n`,
      );
    }

    const rows = records.map(tabularRow);
    if (format === "parquet") {
      return attachment(
        c,
        "application/vnd.apache.parquet",
        "ferrogate-cost-records.parquet",
        encodeParquet(COST_EXPORT_COLUMNS, rows),
      );
    }

    return attachment(
      c,
      // `text/csv` with an explicit charset and the RFC 4180 `header=present`
      // parameter, so a reader does not have to guess whether the first line is
      // data — which, for a spend report, is a row of money-shaped garbage.
      "text/csv; charset=utf-8; header=present",
      "ferrogate-cost-records.csv",
      encodeCsv(COST_EXPORT_COLUMN_NAMES, rows),
    );
  };
}

/**
 * The two `readOnlyCollection` declarations are what `crudGroup` matches the
 * contract's operation ids against; both operations have an override, and
 * deleting the declarations would make the build throw rather than silently
 * drop a route.
 *
 * There is deliberately no `cost-records` DOCUMENT collection behind them: this
 * group has no memory-store fallback, because a memory deployment has no
 * `request_logs` and no `billing_events` to join and inventing an empty
 * document collection would be the exact defect #664 and #665 each had to undo.
 */
export const adminCostRecordRoutes: GroupModule = crudGroup(
  "admin_cost_record",
  [
    readOnlyCollection("cost-records", COST_RECORD_OBJECT),
    readOnlyCollection("cost-record-exports", "cost_record_export"),
  ],
  {
    listAdminCostRecords: listCostRecordsHandler(),
    exportAdminCostRecords: exportCostRecordsHandler(),
  },
);
