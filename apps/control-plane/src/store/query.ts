/**
 * The list semantics both {@link ControlPlaneStore} implementations share.
 *
 * `search`, `?k=v` filtering, tenant visibility and pagination are extracted
 * here for one reason: the in-memory store is the reference implementation the
 * existing 131 tests pin, and the D1 store must behave IDENTICALLY. If each one
 * re-derived `matchesSearch` the two would drift on exactly the details nobody
 * writes an assertion for — case folding, which fields `?search=` scans, whether
 * a missing field matches an empty filter value.
 *
 * The D1 store therefore does in SQL only what SQL can do without changing
 * meaning (narrow by `resource_kind`, and — the security-critical one — the
 * tenant predicate), and reuses these predicates for the rest. See
 * `d1.ts` for the note on when that costs a full-collection read.
 */
import type { CallerScope, ListPage, ListQuery, StoreRecord } from "../ports.js";

/** Fields a `?search=` scans, in the order Rust's `matches_search` receives them. */
export const SEARCH_FIELDS = ["id", "name", "hostname", "status", "description", "kind", "type"];

export function matchesSearch(record: StoreRecord, search: string | null): boolean {
  if (search === null) return true;
  const needle = search.toLowerCase();
  return SEARCH_FIELDS.some((field) => {
    const value = record[field];
    return typeof value === "string" && value.toLowerCase().includes(needle);
  });
}

export function matchesFilters(
  record: StoreRecord,
  filters: Readonly<Record<string, string>>,
): boolean {
  return Object.entries(filters).every(([key, expected]) => {
    const value = record[key];
    if (value === undefined || value === null) return false;
    return String(value) === expected;
  });
}

/**
 * A tenant-scoped caller may only see rows attributed to its own tenant.
 *
 * An un-attributed row is global/platform data; a tenant caller may read it but
 * (see `create`/`replace`) never claims it. Rows belonging to another tenant are
 * invisible — not forbidden, INVISIBLE, so the 404 a cross-tenant read gets is
 * indistinguishable from "no such row".
 */
export function visibleTo(record: StoreRecord, scope: CallerScope): boolean {
  if (scope.kind === "platform_operator") return true;
  const owner = record.tenant_id;
  if (owner === undefined || owner === null) return true;
  return owner === scope.tenantId;
}

/**
 * A tenant-scoped caller may only MUTATE rows attributed to its own tenant.
 *
 * Strictly narrower than {@link visibleTo}, and the difference is the whole
 * point: an un-attributed row is PLATFORM data — a global `role`, a shared
 * `policy`, a `plan` other tenants are billed against — which every tenant may
 * read (hiding it would break `resolved-defaults`) and none may write. Rust
 * `filter_by_tenant_scope` (`auth.rs:428`) is strict equality on both sides;
 * this port widened it for reads deliberately and, until the wave-15
 * certification, had carried the widened predicate onto `replace`, `merge`,
 * `mergeIf`, `remove` and the `atomic` batch as well. A tenant administrator
 * holding `admin.write` — an intended configuration — could therefore edit or
 * delete any platform row.
 *
 * The refusal is `null`/`false`, i.e. a 404 indistinguishable from "no such
 * row", for the same reason the cross-tenant case is: a distinct status would
 * confirm the row exists.
 */
export function writableBy(record: StoreRecord, scope: CallerScope): boolean {
  if (scope.kind === "platform_operator") return true;
  return record.tenant_id === scope.tenantId;
}

/** True when a query narrows nothing beyond the collection itself. */
export function isUnfilteredQuery(query: ListQuery): boolean {
  return query.search === null && Object.keys(query.filters).length === 0;
}

/** Apply `search` + `filters`, then the page window. `total` is pre-pagination. */
export function pageOf(records: readonly StoreRecord[], query: ListQuery): ListPage {
  const matched = records.filter(
    (record) => matchesSearch(record, query.search) && matchesFilters(record, query.filters),
  );
  if (!query.paginate) return { items: matched, total: matched.length };
  return {
    items: matched.slice(query.offset, query.offset + query.limit),
    total: matched.length,
  };
}
