/**
 * The admin response envelopes.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/responses.rs`
 * (`AdminList`, `AdminDeleteResponse`) and
 * `server/admin_list_query.rs` (`list_response`) +
 * `state.rs` (`AdminPagination::from_query`).
 *
 * Two shapes matter and they are NOT interchangeable:
 *
 *  - `AdminList::new(data)`       → `{ object: "list", data }`
 *  - `AdminList::paginated(...)`  → `{ object: "list", data, total, offset, limit }`
 *
 * Rust picks between them on `query.is_none()` — a list request with *no query
 * string at all* answers the un-paginated envelope, and any query string (even
 * an unrelated filter) switches it to the paginated one. The `Option` fields
 * are `skip_serializing_if = "Option::is_none"`, so the un-paginated envelope
 * genuinely omits the three keys rather than sending nulls.
 */
import type { ListPage, ListQuery, StoreRecord } from "./ports.js";

/** Rust `AdminList<T>`. `total`/`offset`/`limit` are omitted when absent. */
export interface AdminList<T> {
  readonly object: "list";
  readonly data: readonly T[];
  readonly total?: number;
  readonly offset?: number;
  readonly limit?: number;
  /** Optional evidence provenance for projection-backed operator reads. */
  readonly source?: string;
  /** Unix seconds at which the projection-backed read was assembled. */
  readonly as_of_unix?: number;
}

/** Rust `AdminList::new` — the un-paginated envelope. */
export function adminList<T>(data: readonly T[]): AdminList<T> {
  return { object: "list", data };
}

/** Rust `AdminList::paginated`. */
export function adminListPaginated<T>(
  data: readonly T[],
  total: number,
  offset: number,
  limit: number,
): AdminList<T> {
  return { object: "list", data, total, offset, limit };
}

export const DERIVED_CONTROL_PROJECTION_SOURCE = "derived_control_projection" as const;

export interface EvidenceResponseMetadata {
  readonly source: typeof DERIVED_CONTROL_PROJECTION_SOURCE;
  readonly as_of_unix: number;
}

/** Metadata that tells an operator a fleet read is a bounded control projection. */
export function derivedControlProjectionMetadata(now = Date.now()): EvidenceResponseMetadata {
  return {
    source: DERIVED_CONTROL_PROJECTION_SOURCE,
    as_of_unix: Math.floor(now / 1_000),
  };
}

/** Add optional evidence provenance without changing the existing list fields. */
export function adminListPaginatedWithMetadata<T>(
  data: readonly T[],
  total: number,
  offset: number,
  limit: number,
  metadata: EvidenceResponseMetadata,
): AdminList<T> {
  return { ...adminListPaginated(data, total, offset, limit), ...metadata };
}

export function evidenceResponseHeaders(
  metadata: EvidenceResponseMetadata,
): Record<string, string> {
  return {
    "x-ferrogate-evidence-source": metadata.source,
    "x-ferrogate-evidence-as-of-unix": String(metadata.as_of_unix),
  };
}

/** Rust `admin_list_query::list_response` — the `query.is_none()` fork. */
export function listResponse(page: ListPage, query: ListQuery): AdminList<StoreRecord> {
  if (!query.paginate) return adminList(page.items);
  return adminListPaginated(page.items, page.total, query.offset, query.limit);
}

/** Rust `AdminDeleteResponse { object, id, deleted }`, answered with 200. */
export interface AdminDeleteResponse {
  readonly object: string;
  readonly id: string;
  readonly deleted: true;
}

export function adminDeleted(object: string, id: string): AdminDeleteResponse {
  return { object, id, deleted: true };
}

/**
 * The single-item mutation envelope: `{ object: "<name>", "<name>": record }`
 * (Rust e.g. `AdminAgentScheduleMutationResponse { object, agent_schedule }`).
 *
 * PORT-TODO(P: inventory-edge-control §1.2 wire shape) — the "envelope key equals
 * `object`" rule holds for most of the Rust structs but NOT for all of them, and
 * three resources are wrong on the wire today:
 *
 * | resource | Rust envelope | this port |
 * |---|---|---|
 * | `/admin/v1/api-keys` | `{ object: "api_key", key }` (`responses.rs:1096`) | `{ object: "api_key", api_key }` |
 * | `/admin/v1/mcp-servers` | `{ object: "mcp_server", server }` (`responses.rs:1900`, `local.rs:698`) | `{ object: "mcp_server", mcp_server }` |
 * | `/admin/v1/tenant-accounts` | `{ object: "tenant_account", tenant }` (`server/virtual_keys.rs:320`) | `{ object: "tenant_account", tenant_account }` |
 *
 * Any client that reads `body.key` / `body.server` / `body.tenant` — which is
 * what the Rust-era SDKs and the admin console did — gets `undefined`. The fix
 * is a per-collection `envelopeKey` on `CollectionSpec` defaulting to `object`,
 * not a rename of `object` (which is a separate, correct field).
 */
export function adminItem(object: string, record: unknown): Record<string, unknown> {
  return { object, [object]: record };
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/** Rust `default_admin_list_limit()`. */
export const DEFAULT_ADMIN_LIST_LIMIT = 100;
/** Rust `default_admin_list_max_limit()`. */
export const DEFAULT_ADMIN_LIST_MAX_LIMIT = 1_000;

/** Query keys that are pagination/search controls rather than record filters. */
const RESERVED_QUERY_KEYS = new Set(["offset", "limit", "search", "q", "tenant_offset"]);

/**
 * Rust `AdminPagination::from_query` + the `?search=` / filter extraction the
 * admin list handlers do around it.
 *
 * Faithful details: an unparseable `offset`/`limit` keeps the running value
 * (Rust `value.parse().unwrap_or(offset)`), `limit == 0` resets to the default,
 * and the result is clamped to `max_limit`.
 */
export function parseListQuery(
  url: URL,
  defaultLimit = DEFAULT_ADMIN_LIST_LIMIT,
  maxLimit = DEFAULT_ADMIN_LIST_MAX_LIMIT,
): ListQuery {
  const params = url.searchParams;
  let offset = 0;
  let limit = defaultLimit;

  const rawOffset = params.get("offset");
  if (rawOffset !== null) {
    const parsed = Number.parseInt(rawOffset, 10);
    if (Number.isSafeInteger(parsed) && parsed >= 0) offset = parsed;
  }
  const rawLimit = params.get("limit");
  if (rawLimit !== null) {
    const parsed = Number.parseInt(rawLimit, 10);
    if (Number.isSafeInteger(parsed) && parsed >= 0) limit = parsed;
  }
  if (limit === 0) limit = defaultLimit;
  limit = Math.min(limit, maxLimit);

  const search = (params.get("search") ?? params.get("q") ?? "").trim();
  const filters: Record<string, string> = {};
  for (const [key, value] of params.entries()) {
    if (RESERVED_QUERY_KEYS.has(key)) continue;
    const trimmed = value.trim();
    if (trimmed !== "") filters[key] = trimmed;
  }

  return {
    offset,
    limit,
    // Rust forks on "was there a query string at all", not on which keys it had.
    paginate: url.search !== "",
    search: search === "" ? null : search,
    filters,
  };
}
