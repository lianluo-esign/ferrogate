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
  const afterEventId = query.get("after_event_id")?.trim();
  return afterEventId !== undefined && afterEventId !== "" ? afterEventId : null;
}

/** Default / maximum page size for the paged (non-SSE) event feed. */
export const EVENT_PAGE_DEFAULT_LIMIT = 100;
export const EVENT_PAGE_MAX_LIMIT = 500;

/**
 * PORT-TODO(`server/agent_jobs.rs::AgentJobEventCursor::from_query`): the
 * parenthetical below is WRONG about Rust and the divergence is real.
 *
 * Rust does NOT silently clamp. `from_query` returns `Err` for a non-integer
 * `limit` ("limit must be an unsigned integer") and for `limit=0` ("limit must
 * be greater than zero"), and `handle_agent_job_events` turns either into
 * `400 invalid_event_cursor`. Only the UPPER bound is clamped
 * (`limit.min(EVENT_PAGE_MAX_LIMIT)`). This function folds both refusals into
 * the default page size, so `?limit=0` and `?limit=abc` answer 200 with 100
 * rows where Rust answers 400 — a client paginating on a typo'd cursor gets
 * silently wrong pages instead of an error.
 *
 * Second, unrelated divergence in the same feed: Rust's resume token is
 * `"<occurred_at_unix>:<event id>"` (`agent_job_event_cursor_token`, issue
 * #474) precisely so a cursor survives the event it names being pruned by
 * retention. `runs/do.ts::listEvents` emits the BARE event id — the pre-#474
 * form — and falls back to `cursorReset: true` (restart from the oldest
 * retained event) when it cannot find it, so a long-lived poll loop
 * RE-DELIVERS its whole retained history after a retention pass instead of
 * resuming. Neither is a platform limit; both are pure functions of data the
 * Durable Object already stores.
 */
/** Clamp a caller-supplied `limit` (Rust: silently clamped, never rejected). */
export function clampEventLimit(raw: string | null): number {
  if (raw === null || raw.trim() === "") return EVENT_PAGE_DEFAULT_LIMIT;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return EVENT_PAGE_DEFAULT_LIMIT;
  return Math.min(parsed, EVENT_PAGE_MAX_LIMIT);
}
