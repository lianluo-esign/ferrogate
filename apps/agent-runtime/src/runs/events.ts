/**
 * SSE framing for the two streaming operations this Worker owns:
 * `GET /v1/agent-jobs/{run_id}/events` and `POST /v1/agents/{name}/message:stream`.
 *
 * `ROUTE-MAP.md` lists both as streaming surfaces whose framing must be
 * preserved. The Rust side writes `text/event-stream` with the conventional
 * `id:` / `event:` / `data:` triple and a terminal `[DONE]` sentinel; this is
 * that framing, byte for byte, plus the two things a long-lived CF stream needs
 * that a short Rust response did not: periodic `:` comment heartbeats (so an
 * intermediary does not reap an idle connection) and `Last-Event-ID` resume.
 */
import { HttpError } from "../middleware/errors.js";
import type { StoredRunEvent } from "./model.js";

/** The `[DONE]` sentinel every FerroGate SSE stream terminates with. */
export const SSE_DONE = "[DONE]";

/** Headers every SSE response carries. */
export const SSE_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "text/event-stream; charset=utf-8",
  "cache-control": "no-cache, no-transform",
  connection: "keep-alive",
  // Defeats proxy buffering, which would otherwise defeat the whole point.
  "x-accel-buffering": "no",
};

/**
 * Encode one SSE frame.
 *
 * Multi-line payloads are split across repeated `data:` lines, which is what the
 * spec requires and what a naive `data: ${json}` gets wrong the moment a payload
 * contains a newline. Every frame ends with the mandatory blank line.
 */
export function sseFrame(options: {
  readonly id?: string;
  readonly event?: string;
  readonly data: string;
  /** Reconnect hint in milliseconds, sent once at stream open. */
  readonly retryMs?: number;
}): string {
  let frame = "";
  if (options.retryMs !== undefined) frame += `retry: ${options.retryMs}\n`;
  if (options.id !== undefined) frame += `id: ${options.id}\n`;
  if (options.event !== undefined) frame += `event: ${options.event}\n`;
  for (const line of options.data.split("\n")) frame += `data: ${line}\n`;
  return `${frame}\n`;
}

/** An SSE comment — the keep-alive heartbeat. Ignored by every client. */
export function sseComment(text: string): string {
  return `: ${text}\n\n`;
}

/** Render a run-timeline row as its SSE frame. */
export function runEventFrame(event: StoredRunEvent): string {
  return sseFrame({ id: event.id, event: event.kind, data: JSON.stringify(event) });
}

/** The terminal frame. */
export function doneFrame(): string {
  return sseFrame({ event: "done", data: SSE_DONE });
}

/** `true` when the caller asked for the streaming representation. */
export function wantsEventStream(headers: Headers): boolean {
  const accept = headers.get("accept");
  if (accept === null) return false;
  return accept
    .split(",")
    .map((part) => part.split(";")[0]?.trim().toLowerCase() ?? "")
    .includes("text/event-stream");
}

/**
 * Parse the resume cursor.
 *
 * `Last-Event-ID` (the SSE reconnect header the browser sends automatically)
 * wins over the `after_event_id` query parameter, because a reconnecting client
 * cannot rewrite its own URL. Both name the LAST event the client already saw.
 */
export function resumeCursor(headers: Headers, query: URLSearchParams): string | null {
  const lastEventId = headers.get("last-event-id")?.trim();
  if (lastEventId !== undefined && lastEventId !== "") return lastEventId;
  // `AgentJobEventCursor::from_query` matches `"after_event_id" | "after"`, and
  // treats an empty value as absent (`if !value.is_empty()`).
  for (const name of ["after_event_id", "after"] as const) {
    const value = query.get(name)?.trim();
    if (value !== undefined && value !== "") return value;
  }
  return null;
}

/** Default / maximum page size for the paged (non-SSE) event feed. */
export const EVENT_PAGE_DEFAULT_LIMIT = 100;
export const EVENT_PAGE_MAX_LIMIT = 500;

/**
 * `AgentJobEventCursor::from_query`'s `limit` half (`agent_jobs.rs:1411`).
 *
 * ## The marker that stood here is CLOSED (cutover finding D7.2)
 *
 * It said the old `clampEventLimit` was wrong and why: Rust does NOT silently
 * clamp both ends. `from_query` runs `value.trim().parse::<usize>()` and
 * propagates the parse error as `"limit must be an unsigned integer"`, then
 * refuses `0` with `"limit must be greater than zero"`; only the UPPER bound is
 * clamped (`limit.min(EVENT_PAGE_MAX_LIMIT)`). `handle_agent_job_events` turns
 * either refusal into `400 invalid_event_cursor`. The old function folded both
 * into the default page size, so `?limit=0` and `?limit=abc` answered 200 with
 * 100 rows.
 *
 * Three consequences of following `usize::from_str` exactly, each of which
 * `test/event-feed.test.ts` pins:
 *
 *  - an EMPTY value (`?limit=`) is a parse ERROR in Rust, not an absent limit —
 *    `"".parse::<usize>()` fails. Only an ABSENT `limit` key defaults.
 *  - `usize` is unsigned, so `-1` is a parse error rather than a clamp;
 *  - `1.5`, `1e3` and `0x10` are parse errors too, which `Number.parseInt`
 *    would have accepted as `1`, `1` and `0`. Hence the digits-only guard
 *    rather than `parseInt`.
 *
 * @throws {HttpError} `400 invalid_event_cursor`, with Rust's own message.
 */
export function parseEventLimit(raw: string | null): number {
  // Rust reaches the `limit` arm only when the query carries the key at all.
  if (raw === null) return EVENT_PAGE_DEFAULT_LIMIT;
  const trimmed = raw.trim();
  if (!/^\d+$/.test(trimmed)) {
    throw new HttpError(400, "invalid_event_cursor", "limit must be an unsigned integer");
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (parsed === 0) {
    throw new HttpError(400, "invalid_event_cursor", "limit must be greater than zero");
  }
  return Math.min(parsed, EVENT_PAGE_MAX_LIMIT);
}

/**
 * The total order the feed is paged in: `(occurred_at_unix, id)`
 * (`agent_jobs.rs::agent_job_event_key`).
 *
 * Storage order is not a contract — Rust sorts explicitly before paging, and so
 * does {@link comparePosition}'s caller — because that is what makes a cursor a
 * stable resume point across polls and backends.
 */
export interface EventPosition {
  readonly occurredAtUnix: number;
  readonly id: string;
}

/** `(occurred_at_unix, id)` for one stored row. */
export function eventPosition(event: StoredRunEvent): EventPosition {
  return { occurredAtUnix: event.occurred_at_unix, id: event.id };
}

/** Rust's derived `Ord` on the `(u64, String)` key: numeric, then bytewise. */
export function comparePosition(left: EventPosition, right: EventPosition): number {
  if (left.occurredAtUnix !== right.occurredAtUnix) {
    return left.occurredAtUnix < right.occurredAtUnix ? -1 : 1;
  }
  if (left.id === right.id) return 0;
  return left.id < right.id ? -1 : 1;
}

/**
 * Render a resume cursor as `"<occurred_at_unix>:<event id>"` — Rust
 * `agent_job_event_cursor_token`, the #474 rework.
 *
 * ## Why the bare event id was a defect (cutover finding D7.3)
 *
 * The cursor used to be the bare id, which made resumption depend on that event
 * STILL EXISTING. `runs/do.ts` prunes the oldest row past
 * `MAX_RETAINED_EVENTS`, so a long-lived poll loop's cursor eventually named a
 * pruned event, resolved to nothing, and the feed answered `cursor_reset: true`
 * — handing the loop its WHOLE retained history again on every subsequent poll.
 * A position key is self-describing ("everything ordered at or before here is
 * delivered"), so it keeps working after the event it names is gone.
 */
export function eventCursorToken(event: StoredRunEvent): string {
  return `${event.occurred_at_unix}:${event.id}`;
}

/**
 * Parse a cursor into its position key — Rust `resolve_agent_job_cursor`.
 *
 * Accepts BOTH forms, and the acceptance is load-bearing in both directions:
 *
 *  - the composite token this feed emits, recognised by a leading all-digits
 *    segment before the first `:`. It resolves WITHOUT a lookup, which is
 *    exactly what lets it outlive its own event.
 *  - a bare event id copied out of `data[].id` — resolved BY lookup, so a
 *    caller can page from any event it has actually seen, and so every cursor
 *    minted before this fix keeps working. An id that is not in the set is
 *    `null`, which the caller reports as `cursor_reset`.
 *
 * FerroGate's own event ids are `<run id>-evt-<6 digits>` and a run id is never
 * all digits, so the two forms cannot be confused.
 */
export function resolveEventCursor(
  after: string,
  events: readonly StoredRunEvent[],
): EventPosition | null {
  const separator = after.indexOf(":");
  if (separator > 0) {
    const head = after.slice(0, separator);
    if (/^\d+$/.test(head)) {
      const occurredAtUnix = Number.parseInt(head, 10);
      if (Number.isSafeInteger(occurredAtUnix)) {
        return { occurredAtUnix, id: after.slice(separator + 1) };
      }
    }
  }
  const found = events.find((event) => event.id === after);
  return found === undefined ? null : eventPosition(found);
}
