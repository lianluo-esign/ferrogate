/**
 * Page-envelope introspection — the input to the CLI's honesty notices.
 *
 * Clean-room port of the pagination half of
 * `ferrogate-control-plane-client::transport` (inventory-edge-control.md §2.1).
 *
 * The contract this exists to keep: **never print a continuation that does not
 * exist, and never present page one as the page the operator asked for.** A
 * cursor endpoint cannot be walked with `--offset`/`--all-pages`, and saying
 * otherwise (or exiting 0 with the wrong page) is the defect this module
 * prevents.
 */
import type { JsonValue } from "@ferrogate/core";

/** Default page size when `--limit` is not given but `--all-pages` is. */
export const DEFAULT_PAGE_SIZE = 100;

/** Envelope keys the item array can live under. */
export const PAGE_ITEM_KEYS = ["data"] as const;
const PAGE_TOTAL_KEYS = ["total"] as const;
const PAGE_WINDOW_KEYS = ["offset", "limit"] as const;
/** Presence of ANY of these marks the endpoint as cursor-paginated. */
const PAGE_CURSOR_KEYS = [
  "after_event_id",
  "cursor_reset",
  "has_more",
  "next_after_event_id",
  "next_cursor",
] as const;

export interface PageEnvelope {
  readonly itemsKey?: string;
  readonly items: readonly JsonValue[];
  readonly total?: number;
  readonly limit?: number;
  readonly offset?: number;
  readonly cursor: boolean;
}

/** What a cursor endpoint said about continuing. */
export type PageCursorState =
  | { readonly kind: "resume"; readonly key: string; readonly value: string }
  | { readonly kind: "exhausted" }
  | { readonly kind: "unknown" };

function asObject(body: JsonValue): Record<string, JsonValue> | undefined {
  return body !== null && typeof body === "object" && !Array.isArray(body)
    ? (body as Record<string, JsonValue>)
    : undefined;
}

function asUnsigned(value: JsonValue | undefined): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

/** Classify a cursor body, or `undefined` when the endpoint is not cursor-paged. */
export function pageCursorState(body: JsonValue): PageCursorState | undefined {
  const map = asObject(body);
  if (map === undefined) return undefined;
  if (!PAGE_CURSOR_KEYS.some((key) => key in map)) return undefined;
  if (map.has_more === false) return { kind: "exhausted" };

  const nextKeys = PAGE_CURSOR_KEYS.filter((key) => key.startsWith("next_"));
  for (const key of nextKeys) {
    const value = map[key];
    if (value !== undefined && value !== null) {
      return {
        kind: "resume",
        key,
        value: typeof value === "string" ? value : JSON.stringify(value),
      };
    }
  }
  if (nextKeys.some((key) => key in map)) return { kind: "exhausted" };
  return { kind: "unknown" };
}

/** Describe a body as a page, or `undefined` when it is not a listing. */
export function pageEnvelope(body: JsonValue): PageEnvelope | undefined {
  if (Array.isArray(body)) {
    return { items: body, cursor: false };
  }
  const map = asObject(body);
  if (map === undefined) return undefined;
  const key = PAGE_ITEM_KEYS.find((candidate) => Array.isArray(map[candidate]));
  if (key === undefined) return undefined;
  const items = map[key] as JsonValue[];
  let total: number | undefined;
  for (const totalKey of PAGE_TOTAL_KEYS) {
    const value = asUnsigned(map[totalKey]);
    if (value !== undefined) {
      total = value;
      break;
    }
  }
  const limit = asUnsigned(map.limit);
  const offset = asUnsigned(map.offset);
  return {
    itemsKey: key,
    items,
    ...(total === undefined ? {} : { total }),
    ...(limit === undefined ? {} : { limit }),
    ...(offset === undefined ? {} : { offset }),
    cursor: PAGE_CURSOR_KEYS.some((cursorKey) => cursorKey in map),
  };
}

/** The next offset window, or `undefined` when the walk is complete. */
export function nextPage(
  current: { offset: number; limit?: number },
  returned: number,
  total: number | undefined,
): { offset: number; limit?: number } | undefined {
  if (returned === 0) return undefined;
  const nextOffset = current.offset + returned;
  if (total !== undefined) {
    if (nextOffset >= total) return undefined;
  } else if (current.limit !== undefined && returned < current.limit) {
    return undefined;
  }
  return { offset: nextOffset, ...(current.limit === undefined ? {} : { limit: current.limit }) };
}

/**
 * Merge every walked page into one document, dropping the now-meaningless page
 * window and cursor keys so the merged body cannot be misread as page one.
 */
export function mergePages(
  body: JsonValue,
  itemsKey: string | undefined,
  merged: readonly JsonValue[],
): JsonValue {
  const map = asObject(body);
  if (itemsKey === undefined || map === undefined) return [...merged];
  const out: Record<string, JsonValue> = { ...map, [itemsKey]: [...merged] };
  for (const stale of [...PAGE_WINDOW_KEYS, ...PAGE_CURSOR_KEYS, "next_offset"]) {
    delete out[stale];
  }
  return out;
}
