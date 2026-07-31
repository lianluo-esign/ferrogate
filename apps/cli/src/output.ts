/**
 * Rendering: human tables, `--json`, mutation receipts, and honesty notices.
 *
 * Clean-room port of `ferrogate-control-plane-client::output` plus the
 * rendering half of `ferrogate-cli::ctl::resource_cmd`
 * (inventory-edge-control.md §1.2).
 *
 * Stream discipline (a documented contract): **stdout carries data, stderr
 * carries diagnostics** — request/trace ids, truncation and cursor notices, the
 * unhonored-scope note. A script piping stdout gets only the payload.
 */
import type { JsonValue } from "@ferrogate/core";
import type { OutputFormat } from "./context.js";
import { CliError } from "./errors.js";
import { pageCursorState, pageEnvelope } from "./paging.js";
import { type VerbOutput, receiptTableRows } from "./receipt.js";

/** A two-space-separated, left-aligned table. */
export class Table {
  private constructor(
    readonly headers: readonly string[],
    readonly rows: readonly (readonly string[])[],
  ) {}

  static create(headers: readonly string[], rows: readonly (readonly string[])[]): Table {
    const width = headers.length;
    rows.forEach((row, index) => {
      if (row.length !== width) {
        throw CliError.usage(
          `table row ${index} has ${row.length} columns but the header has ${width}`,
        );
      }
    });
    return new Table(headers, rows);
  }

  render(): string {
    const widths = this.headers.map((header) => header.length);
    for (const row of this.rows) {
      row.forEach((cell, index) => {
        widths[index] = Math.max(widths[index] ?? 0, cell.length);
      });
    }
    const pushRow = (cells: readonly string[]): string => {
      let out = "";
      cells.forEach((cell, index) => {
        if (index > 0) out += "  ";
        out += cell;
        if (index + 1 < cells.length) out += " ".repeat((widths[index] ?? 0) - cell.length);
      });
      return out;
    };
    return [pushRow(this.headers), ...this.rows.map(pushRow)].join("\n");
  }
}

/** Stable pretty JSON. */
export function renderJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function renderScalar(value: JsonValue): string {
  if (typeof value === "string") return value;
  if (value === null) return "-";
  if (typeof value === "boolean" || typeof value === "number") return String(value);
  return JSON.stringify(value);
}

function objectTable(map: Record<string, JsonValue>): string {
  const rows = Object.entries(map).map(([key, value]) => [key, renderScalar(value)]);
  return Table.create(["FIELD", "VALUE"], rows).render();
}

function arrayTable(items: readonly JsonValue[]): string {
  if (items.length === 0) return "(no results)";
  const allObjects = items.every(
    (item) => item !== null && typeof item === "object" && !Array.isArray(item),
  );
  if (allObjects) {
    const columns: string[] = [];
    for (const item of items) {
      for (const key of Object.keys(item as Record<string, JsonValue>)) {
        if (!columns.includes(key)) columns.push(key);
      }
    }
    const headers = columns.map((column) => column.toUpperCase());
    const rows = items.map((item) =>
      columns.map((column) => {
        const value = (item as Record<string, JsonValue>)[column];
        return value === undefined ? "-" : renderScalar(value);
      }),
    );
    return Table.create(headers, rows).render();
  }
  return Table.create(
    ["VALUE"],
    items.map((item) => [renderScalar(item)]),
  ).render();
}

/** Render a response body as a human table. */
export function renderTable(body: JsonValue): string {
  if (body === null) return "(empty)";
  if (Array.isArray(body)) return arrayTable(body);
  if (typeof body === "object") {
    const map = body as Record<string, JsonValue>;
    const itemsKey = Object.keys(map).find((key) => key === "data" && Array.isArray(map[key]));
    if (itemsKey !== undefined) {
      const table = arrayTable(map[itemsKey] as JsonValue[]);
      const metadata = Object.fromEntries(Object.entries(map).filter(([key]) => key !== itemsKey));
      if (Object.keys(metadata).length === 0) return table;
      return `${table}\n\n${objectTable(metadata)}`;
    }
    return objectTable(map);
  }
  return renderScalar(body);
}

/**
 * Render whatever a verb produced.
 *
 * A `VerbOutput` carrying a receipt renders the receipt — the render gate has
 * already made it impossible for a mutating verb to carry a body here.
 */
export function renderOutput(format: OutputFormat, output: VerbOutput): string {
  if (output.receipt !== undefined) {
    if (format === "json") return renderJson(output.receipt);
    const rows = receiptTableRows(output.receipt).map(([field, value]) => [field, value]);
    return Table.create(["FIELD", "VALUE"], rows).render();
  }
  if (output.body !== undefined) {
    return format === "json" ? renderJson(output.body) : renderTable(output.body);
  }
  throw CliError.usage("internal: rendered output carried neither a body nor a receipt");
}

// ---------------------------------------------------------------------------
// Honesty notices
// ---------------------------------------------------------------------------

/**
 * Refuse `--offset` on a cursor-paginated endpoint.
 *
 * The server ignores the offset and returns page ONE. Rendering that as "the
 * page you asked for" with exit 0 is a lie, so the CLI refuses instead and
 * hands back the real continuation when the body disclosed one.
 */
export function cursorOffsetRefusal(
  body: JsonValue,
  offset: number | undefined,
  path: string,
): string | undefined {
  if (offset === undefined || offset === 0) return undefined;
  const state = pageCursorState(body);
  if (state === undefined) return undefined;
  const resume =
    state.kind === "resume"
      ? `This page's continuation is ${state.key}=${state.value}; pass it back with --filter using the cursor parameter ${path} documents`
      : `Page it with --filter and the cursor parameter ${path} documents, or re-run without --offset for the first page`;
  return `--offset ${offset} was ignored by ${path}: it is cursor-paginated, so the rows above are page ONE, not the page you asked for. Refusing rather than returning the wrong page with exit 0. ${resume}`;
}

/**
 * Tell the operator when more rows exist — and never invent a next cursor.
 *
 * A cursor endpoint that reported no continuation either way gets an explicit
 * "may exist" notice rather than silence or a fabricated cursor.
 */
export function truncationNotice(
  body: JsonValue,
  offset: number,
  requestedLimit: number | undefined,
): string | undefined {
  const envelope = pageEnvelope(body);
  if (envelope === undefined) return undefined;
  const returned = envelope.items.length;

  if (envelope.cursor) {
    const state = pageCursorState(body);
    if (state === undefined) return undefined;
    switch (state.kind) {
      case "resume":
        return `note: showing ${returned} rows; this endpoint pages by cursor and reported ${state.key}=${state.value}, so more rows exist — re-run with --filter and the cursor parameter this endpoint documents (--all-pages cannot walk a cursor endpoint)`;
      case "exhausted":
        return undefined;
      case "unknown":
        return `note: showing ${returned} rows from a cursor-paginated endpoint that reported no continuation either way; more rows may exist`;
    }
  }

  if (envelope.total !== undefined) {
    if (offset + returned < envelope.total) {
      return `note: showing ${returned} of ${envelope.total} rows (offset ${offset}); re-run with --all-pages to fetch every row`;
    }
    return undefined;
  }

  const limit = requestedLimit ?? envelope.limit;
  if (limit !== undefined && returned > 0 && returned >= limit) {
    return `note: returned a full page of ${returned} rows and the server reported no total; more rows may exist — re-run with --all-pages to be sure`;
  }
  return undefined;
}

/** The `--sort` honesty note: forwarded verbatim, honored by no operation yet. */
export const SORT_NOT_HONORED_NOTICE =
  "note: --sort is forwarded to the server verbatim, but no Control Plane API operation " +
  "declares a 'sort' query parameter yet — the returned order is the server's default, not " +
  "the one you asked for";
