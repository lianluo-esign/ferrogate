/**
 * RFC 4180 CSV, written by hand because a chargeback export is loaded by a
 * spreadsheet and a `join(",")` is not a CSV writer (#677).
 *
 * ## Why this is not `rows.map((r) => cols.map((c) => r[c]).join(","))`
 *
 * Three characters decide it, and all three occur in real FerroGate data:
 *
 *  - a COMMA, which a caller can put in a metadata tag value
 *    (`metadata: {"note": "eu, prod"}`) and which would otherwise shift every
 *    later column of that row left by one — silently attributing one tenant's
 *    cost to another tenant's column;
 *  - a DOUBLE QUOTE, which has to be doubled inside a quoted field or the
 *    field ends early;
 *  - a NEWLINE, which a tag value may also carry, and which would otherwise
 *    turn one request into two half-rows.
 *
 * A finance export that mis-parses is worse than one that does not exist,
 * because the number it produces still looks like a number.
 *
 * ## `null` is an EMPTY FIELD, and that is load-bearing
 *
 * `cost_usd` is `null` for a request nothing could price (#663) and `0` for a
 * request that genuinely cost nothing. Writing `0` for both would silently
 * under-bill; writing an empty cell keeps the two apart in the one format the
 * customer's own analyst opens. Spreadsheets read an empty numeric cell as
 * blank, not as zero, which is exactly the semantics wanted.
 */

/** The value kinds a cost-record column can hold. */
export type CsvValue = string | number | boolean | null | undefined;

/**
 * `\r\n`, per RFC 4180 §2.1.
 *
 * Not `\n`: a bare LF is accepted by most readers but a CRLF is accepted by
 * ALL of them, including the Excel import path that this file exists to serve.
 */
const RECORD_SEPARATOR = "\r\n";

/** Does this field need quoting? */
function needsQuoting(field: string): boolean {
  return (
    field.includes(",") ||
    field.includes('"') ||
    field.includes("\n") ||
    field.includes("\r") ||
    // Leading/trailing whitespace survives a quoted field and is trimmed by
    // some readers otherwise. An id with a stray space is a join key that
    // stops joining, so preserve it exactly.
    field !== field.trim()
  );
}

/** One field, quoted only when it has to be. */
export function csvField(value: CsvValue): string {
  if (value === null || value === undefined) return "";
  const text = typeof value === "string" ? value : String(value);
  if (!needsQuoting(text)) return text;
  return `"${text.replaceAll('"', '""')}"`;
}

/**
 * Encode a fixed column projection as CSV, header first.
 *
 * The header ships even when there are no rows: a zero-row CSV with no header
 * is not an empty table, it is an unloadable file, and the caller who asked for
 * a window that matched nothing still needs to see the schema they queried.
 */
export function encodeCsv(
  columns: readonly string[],
  rows: readonly Readonly<Record<string, CsvValue>>[],
): string {
  const lines = [columns.map(csvField).join(",")];
  for (const row of rows) {
    lines.push(columns.map((column) => csvField(row[column])).join(","));
  }
  return `${lines.join(RECORD_SEPARATOR)}${RECORD_SEPARATOR}`;
}
