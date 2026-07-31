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
const RESERVED_QUERY_KEYS = new Set(["offset", "limit", "search", "q"]);

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
