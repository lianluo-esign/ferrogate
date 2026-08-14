/**
 * Contract group `billing` (7 operations) — six read-only feeds plus the one
 * write: replaying a dead-lettered outbox report.
 *
 * ```
 *   GET  /admin/v1/billing-events                 (compat alias of metering-events)
 *   GET  /admin/v1/metering-events
 *   GET  /admin/v1/metering-export-status
 *   GET  /admin/v1/usage-aggregates
 *   GET  /admin/v1/usage-reports
 *   GET  /admin/v1/billing-outbox-dead-letters
 *   POST /admin/v1/billing-outbox-dead-letters/{report_id}/replay   admin.write
 * ```
 *
 * Everything except `replay` is a read: metering data is produced by the data
 * plane, and an admin-writable metering event would be a billing forgery
 * primitive. `listAdminBillingEventsCompat` is exactly what its name says — the
 * legacy spelling of the metering feed, kept because clients depend on it; it
 * reads the SAME collection so the two can never disagree.
 *
 * **`replay` is idempotent by dead-letter id and must not double-emit.** A
 * dead letter that has already been replayed is a `409`, not a second emission:
 * re-emitting a settled billing report is a double-charge. The replay marks the
 * row and records when, so the transition is auditable.
 *
 * `replay` addresses the ROW — `billing_report_outbox`, which is where the
 * gateway's sweeper actually dead-letters a report — and falls back to the
 * legacy `billing-outbox-dead-letters` document when one exists. The row half is
 * the 1:1 port of Rust `server/billing_outbox.rs`; see
 * {@link replayOutboxReportRow}.
 */
import type { Context } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope, ControlPlaneDeps, ControlPlaneEnv, StoreRecord } from "../ports.js";
import {
  adminListPaginated,
  adminListPaginatedWithMetadata,
  derivedControlProjectionMetadata,
  parseListQuery,
} from "../responses.js";
import { tenantDatabaseFor } from "../store/tenancy.js";
import { provisionedTenantPage, tenantFanoutOffset } from "../store/tenant-fanout.js";
import {
  type GroupModule,
  crudGroup,
  json,
  pathParam,
  readOnlyCollection,
  scopeOf,
} from "./resource.js";

const METERING_EVENTS = "metering-events";
const DEAD_LETTERS = "billing-outbox-dead-letters";
const USAGE_AGGREGATE_TABLE = "usage_aggregate_rollups";
const BILLING_EVENTS_TABLE = "billing_events";

/**
 * Server-side narrowing for the billing-event feeds (#967).
 *
 * The feed answered `offset`/`limit` but nothing else, so an operator console asking "what did
 * THIS tenant spend on THAT provider last week" had to pull the fleet's events down and filter
 * them in the browser — the load a paginated feed exists to avoid, and one that silently truncates
 * once the page limit is reached (the filtered rows may not be in the page that was fetched).
 *
 * `occurred_at_unix` is a real column and carries an index. The rest of the billing decision —
 * provider, model, status, the billing group that supplied the multiplier — lives inside
 * `event_json`, so those predicates are `json_extract`. That is a scan, but it runs INSIDE the
 * tenant fence and only when a filter was asked for, and it replaces shipping the whole feed.
 */
export interface BillingEventFilter {
  readonly sql: string;
  readonly params: (string | number)[];
}

export function billingEventFilters(url: URL): BillingEventFilter[] {
  const out: BillingEventFilter[] = [];
  const value = (name: string): string | undefined => {
    const raw = url.searchParams.get(name);
    const trimmed = raw?.trim();
    return trimmed === undefined || trimmed === "" ? undefined : trimmed;
  };
  const push = (sql: string, ...params: (string | number)[]): void => {
    out.push({ sql, params });
  };

  const provider = value("provider");
  if (provider !== undefined) push("json_extract(event_json, '$.provider') = ?", provider);

  // EITHER spelling, for the same reason the cost feed matches both: the caller knows the model
  // they asked for, not whether the row recorded the logical name or the provider's snapshot.
  const model = value("model");
  if (model !== undefined) {
    push(
      "(json_extract(event_json, '$.logical_model') = ? OR json_extract(event_json, '$.provider_model') = ?)",
      model,
      model,
    );
  }

  const status = value("status");
  if (status !== undefined) {
    const parsed = Number.parseInt(status, 10);
    if (Number.isSafeInteger(parsed)) push("json_extract(event_json, '$.status_code') = ?", parsed);
  }

  const group = value("billing_group_id") ?? value("group");
  if (group !== undefined) {
    push("json_extract(event_json, '$.metadata.billing_group_id') = ?", group);
  }

  // `since` INCLUSIVE, `until` EXCLUSIVE, so two adjacent windows partition the feed instead of
  // both claiming the boundary second — the convention the cost feed already documents.
  const since = value("since");
  if (since !== undefined) {
    const parsed = Number.parseInt(since, 10);
    if (Number.isSafeInteger(parsed)) push("occurred_at_unix >= ?", parsed);
  }
  const until = value("until");
  if (until !== undefined) {
    const parsed = Number.parseInt(until, 10);
    if (Number.isSafeInteger(parsed)) push("occurred_at_unix < ?", parsed);
  }

  return out;
}

/**
 * The same narrowing, applied to the LEGACY document rows.
 *
 * The feed merges three sources — the tenant object's typed rows, the control mirror, and the
 * legacy `metering-events` documents — and a filter that reaches only the SQL two lets the third
 * leak unfiltered rows into a narrowed page (`?provider=nobody` answered with the documents).
 * Stated over the projected document so it cannot drift from what the caller is shown.
 */
export function billingEventDocumentMatches(
  record: StoreRecord,
  url: URL,
): boolean {
  const want = (name: string): string | undefined => {
    const raw = url.searchParams.get(name);
    const trimmed = raw?.trim();
    return trimmed === undefined || trimmed === "" ? undefined : trimmed;
  };
  const str = (value: unknown): string | null => (typeof value === "string" ? value : null);

  const provider = want("provider");
  if (provider !== undefined && str(record.provider) !== provider) return false;

  const model = want("model");
  if (model !== undefined && str(record.logical_model) !== model && str(record.provider_model) !== model) {
    return false;
  }

  const status = want("status");
  if (status !== undefined) {
    const parsed = Number.parseInt(status, 10);
    if (Number.isSafeInteger(parsed) && record.status_code !== parsed) return false;
  }

  const group = want("billing_group_id") ?? want("group");
  if (group !== undefined) {
    const metadata = record.metadata;
    const actual =
      typeof metadata === "object" && metadata !== null
        ? str((metadata as Record<string, unknown>).billing_group_id)
        : null;
    if (actual !== group) return false;
  }

  const occurred = typeof record.occurred_at_unix === "number" ? record.occurred_at_unix : null;
  const since = want("since");
  if (since !== undefined) {
    const parsed = Number.parseInt(since, 10);
    if (Number.isSafeInteger(parsed) && (occurred === null || occurred < parsed)) return false;
  }
  const until = want("until");
  if (until !== undefined) {
    const parsed = Number.parseInt(until, 10);
    if (Number.isSafeInteger(parsed) && (occurred === null || occurred >= parsed)) return false;
  }

  return true;
}

/** Apply the document-level narrowing to a legacy page, leaving its shape intact. */
function narrowLegacy(
  page: { items: readonly StoreRecord[]; total: number },
  url?: URL,
): { items: StoreRecord[]; total: number } {
  if (url === undefined) return { items: [...page.items], total: page.total };
  const items = page.items.filter((record) => billingEventDocumentMatches(record, url));
  return { items, total: items.length };
}

/** Join filter predicates onto a WHERE that may or may not already exist. */
function withFilters(
  base: string,
  baseParams: (string | number)[],
  filters: readonly BillingEventFilter[],
): { where: string; params: (string | number)[] } {
  if (filters.length === 0) return { where: base, params: baseParams };
  const clauses = filters.map((f) => f.sql).join(" AND ");
  const params = [...baseParams, ...filters.flatMap((f) => f.params)];
  return { where: base === "" ? `WHERE ${clauses}` : `${base} AND ${clauses}`, params };
}

interface UsageAggregateRow {
  readonly id: string;
  readonly tenant?: string;
  readonly tenant_context_id: string;
  readonly organization_id: string | null;
  readonly project_id: string | null;
  readonly api_key_id: string | null;
  readonly logical_model: string;
  readonly provider: string;
  readonly prompt_tokens: number;
  readonly completion_tokens: number;
  readonly total_tokens: number;
}

const USAGE_AGGREGATE_COLUMNS =
  "r.id, r.tenant, r.tenant_context_id, r.organization_id, r.project_id, r.api_key_id, " +
  "r.logical_model, r.provider, r.prompt_tokens, r.completion_tokens, r.total_tokens";

const TENANT_USAGE_AGGREGATE_COLUMNS =
  "r.id, r.tenant_context_id, c.organization_id, c.project_id, c.api_key_id, " +
  "r.logical_model, r.provider, r.prompt_tokens, r.completion_tokens, r.total_tokens";

interface BillingEventAuthorityRow {
  readonly billing_event_id: string;
  readonly tenant_id: string;
  readonly request_id: string;
  readonly provider_attempt_index: number;
  readonly occurred_at_unix: number;
  readonly event_json: string;
  readonly total?: number;
}

interface BillingOutboxAuthorityRow {
  readonly id: string;
  readonly tenant_id: string;
  readonly attempts: number;
  readonly next_attempt_unix: number;
  readonly dead_lettered_at_unix: number;
  readonly created_at_unix: number;
  readonly updated_at_unix: number;
  readonly event_json: string;
  readonly total?: number;
}

function documentOf(raw: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(raw);
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function billingEventDocument(row: BillingEventAuthorityRow): StoreRecord {
  return {
    ...documentOf(row.event_json),
    id: row.billing_event_id,
    tenant_id: row.tenant_id,
    request_id: row.request_id,
    provider_attempt_index: row.provider_attempt_index,
    occurred_at_unix: row.occurred_at_unix,
  };
}

function billingOutboxDocument(row: BillingOutboxAuthorityRow): StoreRecord {
  return {
    ...documentOf(row.event_json),
    id: row.id,
    tenant_id: row.tenant_id,
    attempts: row.attempts,
    next_attempt_unix: row.next_attempt_unix,
    dead_lettered_at_unix: row.dead_lettered_at_unix,
    created_at_unix: row.created_at_unix,
    updated_at_unix: row.updated_at_unix,
    status: "dead_lettered",
  };
}

/** Billing authority is the tenant DO when present; older/native tenants use the control mirror. */
async function tenantBillingDatabaseFor(
  deps: ControlPlaneDeps,
  tenantId: string,
): Promise<D1Database | null> {
  // Use the dispatching router, not the provisioning router: a deployment may
  // still have native-binding tenants while newer tenants use Durable Objects.
  // The dispatcher's handle source is the physical authority for this tenant.
  const handle = await tenantDatabaseFor(deps.tenantDatabases, tenantId);
  return handle === null || handle.source !== "durable_object" ? null : handle.db;
}

function billingAuthorityKey(record: StoreRecord): string {
  return `${String(record.tenant_id ?? "")}\u0000${String(record.id)}`;
}

function addBillingPage(
  rowsByKey: Map<string, StoreRecord>,
  page: { items: readonly StoreRecord[]; total: number },
): { total: number; duplicates: number } {
  let duplicates = 0;
  for (const item of page.items) {
    const key = billingAuthorityKey(item);
    if (rowsByKey.has(key)) duplicates += 1;
    rowsByKey.set(key, item);
  }
  return { total: page.total, duplicates };
}

async function tenantBillingEventPage(
  deps: ControlPlaneDeps,
  tenantId: string,
  limit: number,
  filters: readonly BillingEventFilter[] = [],
  url?: URL,
): Promise<{ items: StoreRecord[]; total: number }> {
  const rowsByKey = new Map<string, StoreRecord>();
  let sourceTotal = 0;
  let duplicates = 0;
  const legacy = await deps.store.list(
    METERING_EVENTS,
    { kind: "tenant", tenantId },
    {
      offset: 0,
      limit,
      paginate: false,
      search: null,
      filters: {},
    },
  );
  ({ total: sourceTotal, duplicates } = addBillingPage(rowsByKey, narrowLegacy(legacy, url)));
  const control = await controlBillingEventPage(deps.controlDatabase, limit, tenantId, filters);
  const controlAdded = addBillingPage(rowsByKey, control);
  sourceTotal += controlAdded.total;
  duplicates += controlAdded.duplicates;
  const db = await tenantBillingDatabaseFor(deps, tenantId);
  if (db !== null) {
    const narrowed = withFilters("WHERE tenant_id = ?", [tenantId], filters);
    const result = await db
      .prepare(
        `SELECT billing_event_id, tenant_id, request_id, provider_attempt_index,
                occurred_at_unix, event_json, count(*) OVER() AS total
           FROM ${BILLING_EVENTS_TABLE}
          ${narrowed.where}
          ORDER BY occurred_at_unix DESC, billing_event_id ASC
          LIMIT ? OFFSET 0`,
      )
      .bind(...narrowed.params, limit)
      .all<BillingEventAuthorityRow>();
    const authority = {
      items: result.results.map(billingEventDocument),
      total: result.results[0]?.total ?? 0,
    };
    const authorityAdded = addBillingPage(rowsByKey, authority);
    sourceTotal += authorityAdded.total;
    duplicates += authorityAdded.duplicates;
  }
  const items = [...rowsByKey.values()].sort(byBillingTime);
  return {
    items: items.slice(0, limit),
    total: Math.max(items.length, sourceTotal - duplicates),
  };
}

async function controlBillingEventPage(
  db: D1Database | null,
  limit: number,
  tenantId?: string,
  filters: readonly BillingEventFilter[] = [],
): Promise<{ items: StoreRecord[]; total: number }> {
  if (db === null) return { items: [], total: 0 };
  const narrowed = withFilters(
    tenantId === undefined ? "" : "WHERE tenant_id = ?",
    tenantId === undefined ? [] : [tenantId],
    filters,
  );
  const result = await db
    .prepare(
      `SELECT billing_event_id, tenant_id, request_id, provider_attempt_index,
              occurred_at_unix, event_json, count(*) OVER() AS total
         FROM ${BILLING_EVENTS_TABLE}
        ${narrowed.where}
        ORDER BY occurred_at_unix DESC, billing_event_id ASC
        LIMIT ? OFFSET 0`,
    )
    .bind(...narrowed.params, limit)
    .all<BillingEventAuthorityRow>();
  return {
    items: result.results.map(billingEventDocument),
    total: result.results[0]?.total ?? 0,
  };
}

async function tenantBillingOutboxPage(
  deps: ControlPlaneDeps,
  tenantId: string,
  limit: number,
): Promise<{ items: StoreRecord[]; total: number }> {
  const rowsByKey = new Map<string, StoreRecord>();
  let sourceTotal = 0;
  let duplicates = 0;
  const legacy = await deps.store.list(
    DEAD_LETTERS,
    { kind: "tenant", tenantId },
    {
      offset: 0,
      limit,
      paginate: false,
      search: null,
      filters: {},
    },
  );
  ({ total: sourceTotal, duplicates } = addBillingPage(rowsByKey, legacy));
  const control = await controlBillingOutboxPage(deps.controlDatabase, limit, tenantId);
  const controlAdded = addBillingPage(rowsByKey, control);
  sourceTotal += controlAdded.total;
  duplicates += controlAdded.duplicates;
  const db = await tenantBillingDatabaseFor(deps, tenantId);
  if (db !== null) {
    const result = await db
      .prepare(
        `SELECT id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix,
                created_at_unix, updated_at_unix, event_json, count(*) OVER() AS total
           FROM ${BILLING_OUTBOX_TABLE}
          WHERE tenant_id = ? AND dead_lettered_at_unix IS NOT NULL
          ORDER BY dead_lettered_at_unix DESC, id ASC
          LIMIT ? OFFSET 0`,
      )
      .bind(tenantId, limit)
      .all<BillingOutboxAuthorityRow>();
    const authority = {
      items: result.results.map(billingOutboxDocument),
      total: result.results[0]?.total ?? 0,
    };
    const authorityAdded = addBillingPage(rowsByKey, authority);
    sourceTotal += authorityAdded.total;
    duplicates += authorityAdded.duplicates;
  }
  const items = [...rowsByKey.values()].sort(byBillingTime);
  return {
    items: items.slice(0, limit),
    total: Math.max(items.length, sourceTotal - duplicates),
  };
}

async function controlBillingOutboxPage(
  db: D1Database | null,
  limit: number,
  tenantId?: string,
): Promise<{ items: StoreRecord[]; total: number }> {
  if (db === null) return { items: [], total: 0 };
  const tenantPredicate = tenantId === undefined ? "" : " AND tenant_id = ?";
  const params = tenantId === undefined ? [limit] : [tenantId, limit];
  const result = await db
    .prepare(
      `SELECT id, tenant_id, attempts, next_attempt_unix, dead_lettered_at_unix,
              created_at_unix, updated_at_unix, event_json, count(*) OVER() AS total
         FROM ${BILLING_OUTBOX_TABLE}
        WHERE dead_lettered_at_unix IS NOT NULL${tenantPredicate}
        ORDER BY dead_lettered_at_unix DESC, id ASC
        LIMIT ? OFFSET 0`,
    )
    .bind(...params)
    .all<BillingOutboxAuthorityRow>();
  return {
    items: result.results.map(billingOutboxDocument),
    total: result.results[0]?.total ?? 0,
  };
}

function byBillingTime(left: StoreRecord, right: StoreRecord): number {
  const leftTime = Number(left.occurred_at_unix ?? left.dead_lettered_at_unix ?? 0);
  const rightTime = Number(right.occurred_at_unix ?? right.dead_lettered_at_unix ?? 0);
  return rightTime - leftTime || String(left.id).localeCompare(String(right.id));
}

async function listBillingAuthority(
  deps: ControlPlaneDeps,
  scope: CallerScope,
  query: ReturnType<typeof parseListQuery>,
  kind: "events" | "outbox",
  tenantOffset = 0,
  filters: readonly BillingEventFilter[] = [],
  url?: URL,
): Promise<{
  items: StoreRecord[];
  total: number;
  tenantPage?: Awaited<ReturnType<typeof provisionedTenantPage>>;
}> {
  // Billing rows remain authoritative in the tenant object. The control rows
  // below are compatibility projections/directory entries, never dashboard
  // rollups and never invoice inputs. Read only enough from each live tenant
  // to assemble this bounded admin page.
  const fetchLimit = Math.max(1, Math.min(deps.listMaxLimit, query.offset + query.limit));
  if (scope.kind === "tenant") {
    const page =
      kind === "events"
        ? tenantBillingEventPage(deps, scope.tenantId, fetchLimit, filters, url)
        : tenantBillingOutboxPage(deps, scope.tenantId, fetchLimit);
    return page.then((result) => ({
      items: result.items.slice(query.offset, query.offset + query.limit),
      total: result.total,
    }));
  }

  const tenantPage = await provisionedTenantPage(deps.tenantDatabases, tenantOffset);

  const rowsById = new Map<string, StoreRecord>();
  let sourceTotal = 0;
  let duplicates = 0;
  const legacy = await deps.store.list(kind === "events" ? METERING_EVENTS : DEAD_LETTERS, scope, {
    ...query,
    offset: 0,
    limit: fetchLimit,
    paginate: false,
  });
  const legacyAdded = addBillingPage(rowsById, narrowLegacy(legacy, url));
  sourceTotal += legacyAdded.total;
  duplicates += legacyAdded.duplicates;

  // The un-attributed control rows are a SOURCE of this feed like any other, so the filters have
  // to reach them too. Passing them only to the per-tenant reads left these rows in every narrowed
  // page: `?provider=zzz-nobody` still answered with the fleet's un-attributed events.
  const control =
    kind === "events"
      ? await controlBillingEventPage(deps.controlDatabase, fetchLimit, undefined, filters)
      : await controlBillingOutboxPage(deps.controlDatabase, fetchLimit);
  const controlAdded = addBillingPage(rowsById, control);
  sourceTotal += controlAdded.total;
  duplicates += controlAdded.duplicates;

  for (const tenantId of tenantPage.tenantIds) {
    const page =
      kind === "events"
        ? await tenantBillingEventPage(deps, tenantId, fetchLimit, filters, url)
        : await tenantBillingOutboxPage(deps, tenantId, fetchLimit);
    const tenantAdded = addBillingPage(rowsById, page);
    sourceTotal += tenantAdded.total;
    duplicates += tenantAdded.duplicates;
  }

  const items = [...rowsById.values()].sort(byBillingTime);
  return {
    items: items.slice(query.offset, query.offset + query.limit),
    total: Math.max(items.length, sourceTotal - duplicates),
    tenantPage,
  };
}

function listBillingAuthorityHandler(
  kind: "events" | "outbox",
): (c: Context<ControlPlaneEnv>) => Promise<Response> {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const url = new URL(c.req.url);
    const query = parseListQuery(url, deps.listDefaultLimit, deps.listMaxLimit);
    const page = await listBillingAuthority(
      deps,
      scope,
      query,
      kind,
      tenantFanoutOffset(url),
      kind === "events" ? billingEventFilters(url) : [],
      kind === "events" ? url : undefined,
    );
    return json(c, 200, {
      ...adminListPaginated(page.items, page.total, query.offset, query.limit),
      ...(page.tenantPage === undefined
        ? {}
        : {
            tenant_page: {
              offset: page.tenantPage.offset,
              limit: page.tenantPage.limit,
              total: page.tenantPage.total,
              has_more: page.tenantPage.hasMore,
            },
          }),
    });
  };
}

function usageAggregateDocument(row: UsageAggregateRow): StoreRecord {
  return {
    object: "usage_aggregate",
    id: row.id,
    organization_id: row.organization_id,
    project_id: row.project_id,
    api_key_id: row.api_key_id,
    logical_model: row.logical_model,
    provider: row.provider,
    usage: {
      prompt_tokens: row.prompt_tokens,
      completion_tokens: row.completion_tokens,
      total_tokens: row.total_tokens,
    },
  };
}

async function tenantUsageAggregatePage(
  deps: ControlPlaneDeps,
  tenantId: string,
  limit: number,
  offset: number,
): Promise<{ records: StoreRecord[]; total: number }> {
  const db = await tenantBillingDatabaseFor(deps, tenantId);
  if (db === null) {
    if (deps.controlDatabase === null) {
      const page = await deps.store.list(
        "usage-aggregates",
        { kind: "tenant", tenantId },
        {
          offset,
          limit,
          paginate: false,
          search: null,
          filters: {},
        },
      );
      return { records: [...page.items], total: page.total };
    }
    return controlUsageAggregatePage(deps.controlDatabase, limit, offset, tenantId);
  }
  const result = await db
    .prepare(
      `SELECT ${TENANT_USAGE_AGGREGATE_COLUMNS}, count(*) OVER() AS total
         FROM ${USAGE_AGGREGATE_TABLE} r
        JOIN tenant_contexts c ON c.id = r.tenant_context_id
        WHERE c.organization_id = ?
        ORDER BY r.updated_at_unix DESC, r.id ASC
        LIMIT ? OFFSET ?`,
    )
    .bind(tenantId, limit, offset)
    .all<UsageAggregateRow & { readonly total?: number }>();
  return {
    records: result.results.map(usageAggregateDocument),
    total: result.results[0]?.total ?? 0,
  };
}

async function controlUsageAggregatePage(
  db: D1Database,
  limit: number,
  offset: number,
  tenantId?: string,
): Promise<{ records: StoreRecord[]; total: number }> {
  const where = tenantId === undefined ? "" : "WHERE r.tenant = ?";
  const params = tenantId === undefined ? [limit, offset] : [tenantId, limit, offset];
  const result = await db
    .prepare(
      `SELECT ${USAGE_AGGREGATE_COLUMNS}, count(*) OVER() AS total
         FROM ${USAGE_AGGREGATE_TABLE} r
        ${where}
        ORDER BY updated_at_unix DESC, id ASC
        LIMIT ? OFFSET ?`,
    )
    .bind(...params)
    .all<UsageAggregateRow & { readonly total?: number }>();
  return {
    records: result.results.map(usageAggregateDocument),
    total: result.results[0]?.total ?? 0,
  };
}

function listAdminUsageAggregates(): (c: Context<ControlPlaneEnv>) => Promise<Response> {
  return async (c) => {
    const deps = c.get("deps");
    const scope = scopeOf(c);
    const query = parseListQuery(new URL(c.req.url), deps.listDefaultLimit, deps.listMaxLimit);

    if (scope.kind === "tenant") {
      const page = await tenantUsageAggregatePage(deps, scope.tenantId, query.limit, query.offset);
      return json(c, 200, adminListPaginated(page.records, page.total, query.offset, query.limit));
    }

    if (deps.controlDatabase === null) {
      const page = await deps.store.list("usage-aggregates", scope, query);
      return json(c, 200, adminListPaginated(page.items, page.total, query.offset, query.limit));
    }

    const page = await controlUsageAggregatePage(deps.controlDatabase, query.limit, query.offset);
    return json(
      c,
      200,
      adminListPaginatedWithMetadata(
        page.records,
        page.total,
        query.offset,
        query.limit,
        derivedControlProjectionMetadata(),
      ),
    );
  };
}

/** Billing outbox table in tenant authority and the legacy control projection. */
export const BILLING_OUTBOX_TABLE = "billing_report_outbox";

/**
 * Whether THIS deployment has the gateway's outbox table at all.
 *
 * The table belongs to the migrations slice, and a control database that has
 * never had the gateway's billing families applied simply does not have it —
 * which is a different thing from a database that has it and cannot be read.
 * The distinction is drawn STRUCTURALLY (a `sqlite_master` lookup) rather than
 * by string-matching a D1 error, because the two states must produce opposite
 * answers below: "not provisioned" degrades to the document-only transition
 * this route has always performed, while "provisioned but unreadable" must
 * REFUSE, so the operator can retry instead of burning the one-shot 409 guard
 * on a replay that re-armed nothing.
 */
async function outboxTableExists(db: D1Database): Promise<boolean> {
  const row = await db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(BILLING_OUTBOX_TABLE)
    .first<{ name: string }>();
  return row !== null;
}

/**
 * Put a dead-lettered outbox row back on the sweeper's due list.
 *
 * The three columns are exactly the ones `BILLING_OUTBOX_LIST_DUE_SQL` in
 * `apps/gateway/src/metering/d1.ts` filters and orders on, which is why all
 * three move together: clearing `dead_lettered_at_unix` alone would leave the
 * row's `next_attempt_unix` wherever the backoff ladder had pushed it, and
 * resetting `attempts` alone would not make it selectable at all.
 *
 * Returns whether a row was actually re-armed. `RETURNING` (D1 supports it on a
 * native binding) is what makes that answer real rather than assumed.
 *
 * THROWS a 503 `HttpError` when the table is there and the write fails. Never a
 * silent `false`: "the re-arm did not happen" and "there was nothing to re-arm"
 * are different facts and the caller acts on them differently.
 */
async function rearmOutboxRow(
  router: { control(): D1Database },
  reportId: string,
  now: number,
): Promise<boolean> {
  const db = controlDatabase(router);
  if (db === null) {
    // No control database on this deployment — nothing to re-arm, and the
    // document transition below is still the correct, safe half.
    return false;
  }
  if (!(await outboxProvisioned(db))) return false;
  return (await casReplayOutboxRow(db, reportId, now)) !== null;
}

/** The control binding, or `null` on a deployment that has none. */
function controlDatabase(router: { control(): D1Database }): D1Database | null {
  try {
    return router.control();
  } catch {
    return null;
  }
}

/** {@link outboxTableExists}, with an unreadable database as a fail-closed 503. */
async function outboxProvisioned(db: D1Database): Promise<boolean> {
  try {
    return await outboxTableExists(db);
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox could not be reached: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** The re-armed outbox row, as `RETURNING` reports it. */
interface RearmedRow {
  readonly id: string;
  readonly attempts: number;
  readonly next_attempt_unix: number;
}

/**
 * The compare-and-swap itself: put the row back on the sweeper's due list, but
 * ONLY while it is still dead-lettered.
 *
 * `AND dead_lettered_at_unix IS NOT NULL` is the whole at-most-once guard and is
 * not decoration — it refuses to touch a row that is already live in the retry
 * ladder, so a second replay cannot reset the `attempts` counter of a report the
 * sweeper is currently backing off on, and two concurrent replays resolve to a
 * single winner (Rust `billing_outbox_replay_test.rs::
 * concurrent_replays_of_one_row_resolve_to_a_single_winner`).
 *
 * `null` ⇒ the CAS did not fire. THROWS a 503 when the write itself failed:
 * "the re-arm did not happen" and "there was nothing to re-arm" are different
 * facts and the caller acts on them differently.
 */
async function casReplayOutboxRow(
  db: D1Database,
  reportId: string,
  now: number,
  tenantId?: string,
): Promise<RearmedRow | null> {
  try {
    const tenantPredicate = tenantId === undefined ? "" : " AND tenant_id = ?";
    const values = tenantId === undefined ? [now, now, reportId] : [now, now, reportId, tenantId];
    return await db
      .prepare(
        `UPDATE ${BILLING_OUTBOX_TABLE}
            SET dead_lettered_at_unix = NULL,
                attempts = 0,
                next_attempt_unix = ?,
                updated_at_unix = ?
          WHERE id = ? AND dead_lettered_at_unix IS NOT NULL${tenantPredicate}
          RETURNING id, attempts, next_attempt_unix`,
      )
      .bind(...values)
      .first<RearmedRow>();
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox row could not be re-armed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** One `billing_report_outbox` row, plus the tenant its event names. */
interface OutboxReportRow {
  readonly id: string;
  readonly deadLettered: boolean;
  /** Explicit tenant column on the tenant authority, with JSON fallback for legacy rows. */
  readonly tenantId: string;
  readonly db: D1Database;
  readonly tenantAuthoritative: boolean;
}

/**
 * Read the physical outbox row — the thing a REAL dead letter is.
 *
 * Rust `handle_admin_billing_outbox_dead_letter_replay` reads the row BEFORE the
 * CAS for one reason: it needs the report's owning tenant to authorize against,
 * and the row's owner never changes, so there is no time-of-use gap that matters
 * (the CAS re-checks the only thing that does change — the dead-letter state).
 *
 * `null` means the row is not there, which on this deployment also covers "no
 * control database" and "the billing families were never migrated". Both degrade
 * to the caller's 404, never to a fabricated success.
 */
async function readControlOutboxReportRow(
  router: { control(): D1Database },
  reportId: string,
): Promise<OutboxReportRow | null> {
  const db = controlDatabase(router);
  if (db === null) return null;
  if (!(await outboxProvisioned(db))) return null;

  let row: {
    id: string;
    tenant_id: string | null;
    dead_lettered_at_unix: number | null;
    event_json: string;
  } | null;
  try {
    row = await db
      .prepare(
        `SELECT id, tenant_id, dead_lettered_at_unix, event_json
           FROM ${BILLING_OUTBOX_TABLE} WHERE id = ?`,
      )
      .bind(reportId)
      .first<{
        id: string;
        tenant_id: string | null;
        dead_lettered_at_unix: number | null;
        event_json: string;
      }>();
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the billing outbox could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (row === null) return null;
  return {
    id: row.id,
    deadLettered: row.dead_lettered_at_unix !== null,
    tenantId: row.tenant_id?.trim() || reportTenantOf(row.event_json),
    db,
    tenantAuthoritative: false,
  };
}

/** Read a tenant-authoritative dead-letter row from its own Durable Object. */
async function readTenantOutboxReportRow(
  deps: ControlPlaneDeps,
  tenantId: string,
  reportId: string,
): Promise<OutboxReportRow | null> {
  const db = await tenantBillingDatabaseFor(deps, tenantId);
  if (db === null) return null;
  try {
    const row = await db
      .prepare(
        `SELECT id, tenant_id, dead_lettered_at_unix
           FROM ${BILLING_OUTBOX_TABLE}
          WHERE id = ? AND tenant_id = ?`,
      )
      .bind(reportId, tenantId)
      .first<{ id: string; tenant_id: string; dead_lettered_at_unix: number | null }>();
    if (row === null) return null;
    return {
      id: row.id,
      deadLettered: row.dead_lettered_at_unix !== null,
      tenantId: row.tenant_id,
      db,
      tenantAuthoritative: true,
    };
  } catch (error) {
    throw new HttpError(
      503,
      "storage_unavailable",
      `the tenant billing outbox could not be read: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Locate tenant authority first, then the legacy control projection. */
async function locateOutboxReport(
  deps: ControlPlaneDeps,
  scope: CallerScope,
  reportId: string,
): Promise<OutboxReportRow | null> {
  if (scope.kind === "tenant") {
    if (scope.tenantId.trim() === "") {
      return readControlOutboxReportRow(deps.tenantDatabases, reportId);
    }
    const tenantRow = await readTenantOutboxReportRow(deps, scope.tenantId, reportId);
    if (tenantRow !== null) return tenantRow;
    // A provisioned Durable Object is the settlement authority even when its
    // row is absent. Never fall through to a stale control compatibility copy;
    // the caller must observe not-found and the tenant object's ledger remains
    // the only source that can be re-armed.
    if ((await tenantBillingDatabaseFor(deps, scope.tenantId)) !== null) return null;
  } else {
    // A control outbox row carries the owning tenant. Route to that tenant's
    // object before considering any compatibility fallback; invoices and
    // replay settlement must never be driven from a cached fleet projection.
    const control = await readControlOutboxReportRow(deps.tenantDatabases, reportId);
    if (control !== null && control.tenantId !== "") {
      const authoritativeDb = await tenantBillingDatabaseFor(deps, control.tenantId);
      if (authoritativeDb !== null) {
        const tenantRow = await readTenantOutboxReportRow(deps, control.tenantId, reportId);
        return tenantRow;
      }
    }

    // A native-binding or legacy control row has no tenant-object shortcut.
    // Keep the collision check explicitly bounded; a wider fleet must be
    // replayed with tenant scope so this money mutation never scans an
    // unbounded namespace. This also checks a control row whose stale owner
    // differs from a live tenant row with the same report id.
    const tenantPage = await provisionedTenantPage(deps.tenantDatabases);
    if (tenantPage.hasMore) {
      throw new HttpError(
        409,
        "billing_report_tenant_scope_required",
        `billing report ${reportId} has no tenant directory entry; replay it with a tenant-scoped key because this fleet exceeds the ${tenantPage.limit}-tenant live lookup bound`,
      );
    }
    const matches: OutboxReportRow[] = [];
    for (const tenantId of tenantPage.tenantIds) {
      const tenantRow = await readTenantOutboxReportRow(deps, tenantId, reportId);
      if (tenantRow !== null) matches.push(tenantRow);
    }
    if (matches.length > 1) {
      throw new HttpError(
        409,
        "dead_letter_ambiguous",
        `billing report ${reportId} exists for multiple tenants; replay it with a tenant-scoped key`,
      );
    }
    if (matches.length === 1) {
      const tenantRow = matches[0];
      if (tenantRow !== undefined && control !== null && control.tenantId !== tenantRow.tenantId) {
        throw new HttpError(
          409,
          "dead_letter_ambiguous",
          `billing report ${reportId} exists for multiple tenants; replay it with a tenant-scoped key`,
        );
      }
      return tenantRow ?? null;
    }
    return control;
  }
  return readControlOutboxReportRow(deps.tenantDatabases, reportId);
}

/**
 * The owning tenant of an outbox row, read off the `BillingEvent` it carries.
 *
 * Rust: `entry.event.tenant.organization_id.as_deref().unwrap_or("")`. The empty
 * string is the fail-closed answer, and it is fail-closed precisely because it
 * is unforgeable as a real tenant id — a row whose event names no tenant (or
 * whose document will not parse) is therefore reachable by a platform operator
 * and by nobody else, rather than by everybody.
 */
function reportTenantOf(eventJson: string): string {
  let document: unknown;
  try {
    document = JSON.parse(eventJson);
  } catch {
    return "";
  }
  if (typeof document !== "object" || document === null) return "";
  const tenant = (document as { tenant?: unknown }).tenant;
  if (typeof tenant !== "object" || tenant === null) return "";
  const organizationId = (tenant as { organization_id?: unknown }).organization_id;
  return typeof organizationId === "string" ? organizationId : "";
}

/**
 * Rust `auth.rs::authorize_tenant_scope` — a platform operator passes, a
 * tenant-scoped caller passes only on strict equality, and everything else is
 * `403 tenant_scope_denied`.
 *
 * This runs BEFORE the CAS. A refusal that had already mutated the row would be
 * the worst of both worlds: the report moves and the caller is told it did not.
 */
function authorizeReportTenant(scope: CallerScope, reportTenantId: string): void {
  if (scope.kind === "platform_operator") return;
  if (scope.tenantId === reportTenantId && reportTenantId !== "") return;
  throw new HttpError(
    403,
    "tenant_scope_denied",
    "API key is not authorized to access this tenant's resources",
  );
}

/**
 * Replay a REAL dead letter — a `billing_report_outbox` row — which is the only
 * kind that exists outside a test fixture.
 *
 * A 1:1 port of Rust
 * `server/billing_outbox.rs::handle_admin_billing_outbox_dead_letter_replay`,
 * including its status/code taxonomy:
 *
 * ```
 *   row absent                  404 dead_letter_not_found
 *   row owned by another tenant 403 tenant_scope_denied     (before the CAS)
 *   row not dead-lettered       409 dead_letter_not_replayable
 *   row vanished under the CAS  404 dead_letter_not_found
 *   CAS fired                   200 billing_outbox_dead_letter_replay
 * ```
 *
 * ## Why this is idempotent, and why it cannot double-charge
 *
 * There is exactly ONE idempotency key here and it is not a new one: the report
 * id IS `billing_ledger.id` IS `billing_events.billing_event_id`, the
 * ledger-entry key the billing service dedups on (Rust `responses.rs:1190` says
 * so in as many words). Replay does not write money — it clears the row's
 * dead-letter mark so `apps/gateway`'s cron sweeper picks it up again, and that
 * delivery path is already idempotent on the same key
 * (`BILLING_EVENT_INSERT_SQL` is `ON CONFLICT DO NOTHING`, and `listDue` reports
 * `settled: true` because its `JOIN billing_ledger` proves the charge already
 * committed). Nothing on this path parses, re-serializes or arithmetics the
 * stored credits, so the lossless integer in `entry_json.credits_exact` is never
 * routed through a float.
 *
 * The at-most-once property is therefore entirely the CAS in
 * {@link casReplayOutboxRow}, and the 409 above is what an operator sees when it
 * refuses.
 *
 * ## What this does NOT do
 *
 * It does not emit. The billing Queue producer binding is declared on
 * `apps/gateway/wrangler.toml` and Queue bindings resolve at DEPLOY time, so
 * this Worker authorizes and re-arms while the gateway's sweeper delivers on its
 * next minute. `emitted: true` would be the dangerous lie — an operator reading
 * it during a billing incident would stop chasing a report that has not gone
 * anywhere yet.
 */
async function replayOutboxReportRow(
  c: Context<ControlPlaneEnv>,
  deps: ControlPlaneDeps,
  scope: CallerScope,
  reportId: string,
): Promise<Response> {
  const row = await locateOutboxReport(deps, scope, reportId);
  if (row === null) {
    throw new HttpError(
      404,
      "dead_letter_not_found",
      `no billing-outbox report with id ${reportId}`,
    );
  }
  // Read-then-authorize BEFORE the CAS (Rust's own comment): the row's owning
  // tenant never changes, so this is a stable ownership check.
  authorizeReportTenant(scope, row.tenantId);

  const now = Math.floor(Date.now() / 1000);
  const rearmed = await casReplayOutboxRow(
    row.db,
    reportId,
    now,
    row.tenantAuthoritative ? row.tenantId : undefined,
  );
  if (rearmed === null) {
    if (row.deadLettered) {
      // Dead-lettered at the read, gone at the CAS: either a concurrent replay
      // won, or a concurrent successful delivery reaped the row. Both mean this
      // caller must not be told it re-armed anything.
      const current = await locateOutboxReport(deps, scope, reportId);
      if (current === null) {
        throw new HttpError(
          404,
          "dead_letter_not_found",
          `no billing-outbox report with id ${reportId}`,
        );
      }
    }
    throw new HttpError(
      409,
      "dead_letter_not_replayable",
      `billing report ${reportId} is not dead-lettered; nothing to replay`,
    );
  }

  return json(c, 200, {
    // Rust `responses.rs::AdminBillingOutboxReplayResponse`.
    object: "billing_outbox_dead_letter_replay",
    id: rearmed.id,
    replayed: true,
    dead_lettered: false,
    attempts: rearmed.attempts,
    next_attempt_unix: rearmed.next_attempt_unix,
    // Not Rust fields; carried over from the document path so an operator
    // driving either shape reads the same two facts about propagation.
    rearmed: true,
    emitted: false,
    propagation: "on_next_outbox_sweep",
  });
}

/**
 * Billing feeds read typed authority first. Tenant-scoped calls address one
 * tenant Durable Object; platform calls perform a full-key fan-out over the
 * provisioned tenant roster and merge legacy control compatibility rows. The
 * response remains paginated, but the complete key set is required for an exact
 * union total after authority precedence and de-duplication.
 *
 * The document collections remain as a compatibility fallback for deployments
 * that have not mounted the typed billing schema.
 *
 * Both list and replay retain a strict row-level tenant fence. Control rows are
 * compatibility data only; a tenant Durable Object row wins when both surfaces
 * contain the same id.
 */
export const billingRoutes: GroupModule = crudGroup(
  "billing",
  [
    readOnlyCollection(METERING_EVENTS, "metering_event"),
    readOnlyCollection("metering-export-status", "metering_export_status"),
    readOnlyCollection("usage-aggregates", "usage_aggregate"),
    readOnlyCollection("usage-reports", "usage_report"),
    readOnlyCollection(DEAD_LETTERS, "billing_outbox_dead_letter"),
  ],
  {
    listAdminUsageAggregates: listAdminUsageAggregates(),
    listAdminMeteringEvents: listBillingAuthorityHandler("events"),
    listBillingOutboxDeadLetters: listBillingAuthorityHandler("outbox"),
    /**
     * The legacy `/admin/v1/billing-events` spelling. Reads the SAME rows as
     * `/admin/v1/metering-events` — a separate collection would let the two
     * feeds drift, which is precisely the bug a "compat alias" is supposed to
     * prevent.
     */
    listAdminBillingEventsCompat: listBillingAuthorityHandler("events"),

    replayBillingOutboxDeadLetter: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const reportId = pathParam(c, "report_id");

      // A legacy document may share an id with the real typed row after the
      // billing authority moved. Always resolve physical authority first, so a
      // document cannot make replay re-arm the wrong database or report success
      // without touching the tenant Durable Object row.
      const physical = await locateOutboxReport(deps, scope, reportId);
      if (physical !== null) {
        return await replayOutboxReportRow(c, deps, scope, reportId);
      }

      const record = await deps.store.get(DEAD_LETTERS, scope, reportId);
      if (record === null) {
        // No DOCUMENT — which is the state a REAL dead letter is always in, so
        // this is the path that actually matters. See
        // {@link replayOutboxReportRow}.
        return await replayOutboxReportRow(c, deps, scope, reportId);
      }
      // Idempotence guard: re-emitting a settled report double-charges.
      if (record.replayed === true) {
        throw new HttpError(
          409,
          "conflict",
          `billing outbox dead letter ${reportId} has already been replayed`,
        );
      }

      // MARKER CLOSED — the `inventory-data-billing §2.5 "billing_report_outbox"`
      // marker that stood here, whose second reason read: "There is no
      // drainer to hand the row to … the Cron sweep that would drain it is
      // itself unbuilt … Re-arming a row nothing reads would look like a queued
      // re-emission and be a no-op, which is the worst of both. It closes when
      // the sweep lands (this route then re-arms the row in the same call)").
      //
      // The sweep landed. `apps/gateway/wrangler.toml` now carries
      // `[triggers] crons = ["* * * * *"]` on the DEFAULT export, and
      // `apps/gateway/src/metering/outbox.ts`'s `MeteringUsageSink.sweep`
      // selects due rows with `BILLING_OUTBOX_LIST_DUE_SQL`
      // (`dead_lettered_at_unix IS NULL AND next_attempt_unix <= now`). So this
      // route now does exactly what the marker said it would: it RE-ARMS the
      // shared row, which lives in the same control database this Worker binds
      // (`deps.tenantDatabases.control()`; the gateway binds it as
      // `BILLING_DB`, `database_name = "ferrogate-control"`).
      //
      // ORDER IS LOAD-BEARING — re-arm FIRST, mark the document SECOND. A crash
      // between them then leaves a re-armed row and an unmarked document, so
      // the operator can replay again and the sweep still delivers (it is
      // idempotent on the ledger entry id). The other order leaves a report
      // marked "replayed" that nothing will ever pick up — permanently stuck,
      // and invisible.
      //
      // The `AND dead_lettered_at_unix IS NOT NULL` in the WHERE is a CAS, not
      // decoration: it refuses to touch a row that is already live in the
      // retry ladder, so a replay cannot reset the `attempts` counter of a
      // report the sweeper is currently backing off on.
      //
      // WHAT REMAINS TRUE, and why `emitted` is still `false`: this Worker does
      // not perform the re-emission itself. The billing Queue producer binding
      // is declared on `apps/gateway/wrangler.toml`
      // (`[[queues.producers]] binding = "BILLING"`), Queue bindings resolve at
      // DEPLOY time, and this app's `wrangler.toml` does not name that queue.
      // The endpoint authorizes and re-arms; the gateway's sweeper emits, on its
      // next minute. `emitted: true` would be the dangerous lie — an operator
      // reading it during a billing incident would stop chasing a report that
      // has not gone anywhere yet.
      const now = Math.floor(Date.now() / 1000);
      const rearmed = await rearmOutboxRow(deps.tenantDatabases, reportId, now);

      const stored = await deps.store.merge(DEAD_LETTERS, scope, reportId, {
        replayed: true,
        replayed_at: now,
        status: "replayed",
        rearmed,
      });
      return json(c, 200, {
        object: "billing_outbox_dead_letter",
        billing_outbox_dead_letter: stored,
        replayed: true,
        /**
         * Whether the shared `billing_report_outbox` row was actually put back
         * on the sweeper's due list. `false` means the dead-letter DOCUMENT
         * existed but the physical row did not (already drained, already
         * re-armed, or never written), and an operator needs to see that
         * difference rather than infer it.
         */
        rearmed,
        emitted: false,
        propagation: "on_next_outbox_sweep",
      });
    },
  },
);
