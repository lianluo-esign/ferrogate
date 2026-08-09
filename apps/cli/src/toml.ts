/**
 * A TOML reader/writer for exactly the CLI context-store document.
 *
 * The Rust CLI persists `contexts.toml` via `toml::to_string_pretty` over a
 * `PersistedStore { current: Option<String>, contexts: Vec<Context> }`
 * (`crates/ferrogate-cli/src/ctl/store.rs`). Neither Bun nor Node ships a TOML
 * *writer*, and pulling a general TOML crate-equivalent in would be a large
 * dependency for one closed document — so this module implements the exact
 * subset that document can contain, and REFUSES anything outside it by name
 * rather than mis-parsing it:
 *
 *   - `key = value` pairs whose value is a basic string (`"…"`, with the TOML
 *     escape set), a literal string (`'…'`), a boolean, or an integer;
 *   - `[table]` headers and `[[array.of.tables]]` headers, nested by dotted key;
 *   - `#` comments and blank lines.
 *
 * That is the complete value space of the persisted `Context` struct (strings,
 * one bool, one nested `auth` table), so for THIS document the round trip is
 * faithful and interoperable with the Rust binary's file. Arrays, inline
 * tables, multi-line strings, floats, datetimes and dotted-key assignments are
 * deliberately rejected with a message naming the construct and its line: the
 * store is security-relevant (it names the env var a bearer token lives in), so
 * silently dropping a construct we do not understand is not an option.
 */

/** A parsed TOML value from the supported subset. */
export type TomlValue = string | boolean | number | TomlTable | TomlValue[];

/** A parsed TOML table. */
export interface TomlTable {
  [key: string]: TomlValue;
}

class TomlError extends Error {
  constructor(message: string, line: number) {
    super(`${message} (line ${line})`);
    this.name = "TomlError";
  }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

const BARE_KEY = /^[A-Za-z0-9_-]+$/;

function encodeKey(key: string): string {
  return BARE_KEY.test(key) ? key : encodeString(key);
}

/** A TOML basic string: the escape set TOML 1.0 defines, and nothing else. */
function encodeString(value: string): string {
  let out = '"';
  for (const char of value) {
    const code = char.codePointAt(0) as number;
    switch (char) {
      case '"':
        out += '\\"';
        break;
      case "\\":
        out += "\\\\";
        break;
      case "\b":
        out += "\\b";
        break;
      case "\t":
        out += "\\t";
        break;
      case "\n":
        out += "\\n";
        break;
      case "\f":
        out += "\\f";
        break;
      case "\r":
        out += "\\r";
        break;
      default:
        // Control characters must be escaped; everything else is literal UTF-8.
        out += code < 0x20 || code === 0x7f ? `\\u${code.toString(16).padStart(4, "0")}` : char;
    }
  }
  return `${out}"`;
}

function encodeScalar(value: TomlValue, path: string): string {
  if (typeof value === "string") return encodeString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`refusing to write a non-integer TOML value at ${path}: ${value}`);
    }
    return String(value);
  }
  throw new Error(`refusing to write an unsupported TOML value at ${path}`);
}

function isTable(value: TomlValue): value is TomlTable {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTableArray(value: TomlValue): value is TomlTable[] {
  return Array.isArray(value) && value.every(isTable);
}

/**
 * Emit a table.
 *
 * TOML requires every scalar at a table level to be emitted BEFORE any
 * sub-table or array-of-tables (a scalar written after `[[contexts]]` would
 * belong to that context, not to the root). The Rust side handles this by
 * declaring `current` before `contexts` in `PersistedStore`; this emitter
 * enforces it structurally instead, so key order in the input object cannot
 * produce an invalid document.
 */
function emitTable(table: TomlTable, prefix: readonly string[], lines: string[]): void {
  const scalars: [string, TomlValue][] = [];
  const subTables: [string, TomlTable][] = [];
  const tableArrays: [string, TomlTable[]][] = [];
  for (const [key, value] of Object.entries(table)) {
    if (value === undefined) continue;
    if (isTable(value)) subTables.push([key, value]);
    else if (Array.isArray(value)) {
      if (!isTableArray(value)) {
        throw new Error(
          `refusing to write a non-table array at ${[...prefix, key].join(".")}: the context store has no such field`,
        );
      }
      tableArrays.push([key, value]);
    } else scalars.push([key, value]);
  }

  for (const [key, value] of scalars) {
    lines.push(`${encodeKey(key)} = ${encodeScalar(value, [...prefix, key].join("."))}`);
  }
  for (const [key, value] of subTables) {
    const path = [...prefix, key];
    lines.push("", `[${path.map(encodeKey).join(".")}]`);
    emitTable(value, path, lines);
  }
  for (const [key, entries] of tableArrays) {
    const path = [...prefix, key];
    for (const entry of entries) {
      lines.push("", `[[${path.map(encodeKey).join(".")}]]`);
      emitTable(entry, path, lines);
    }
  }
}

/** Serialize a table to TOML text (trailing newline included). */
export function stringifyToml(table: TomlTable): string {
  const lines: string[] = [];
  emitTable(table, [], lines);
  while (lines[0] === "") lines.shift();
  return `${lines.join("\n")}\n`;
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

interface Cursor {
  readonly text: string;
  index: number;
}

function parseBasicString(cursor: Cursor, line: number): string {
  const { text } = cursor;
  if (text.startsWith('"""', cursor.index)) {
    throw new TomlError("multi-line basic strings are not supported by the context store", line);
  }
  cursor.index += 1; // opening quote
  let out = "";
  for (;;) {
    const char = text[cursor.index];
    if (char === undefined || char === "\n") throw new TomlError("unterminated string", line);
    cursor.index += 1;
    if (char === '"') return out;
    if (char !== "\\") {
      out += char;
      continue;
    }
    const escapeChar = text[cursor.index];
    cursor.index += 1;
    switch (escapeChar) {
      case '"':
        out += '"';
        break;
      case "\\":
        out += "\\";
        break;
      case "b":
        out += "\b";
        break;
      case "t":
        out += "\t";
        break;
      case "n":
        out += "\n";
        break;
      case "f":
        out += "\f";
        break;
      case "r":
        out += "\r";
        break;
      case "u":
      case "U": {
        const width = escapeChar === "u" ? 4 : 8;
        const hex = text.slice(cursor.index, cursor.index + width);
        if (!new RegExp(`^[0-9a-fA-F]{${width}}$`).test(hex)) {
          throw new TomlError(`invalid \\${escapeChar} escape`, line);
        }
        cursor.index += width;
        out += String.fromCodePoint(Number.parseInt(hex, 16));
        break;
      }
      default:
        throw new TomlError(`unknown string escape '\\${escapeChar ?? ""}'`, line);
    }
  }
}

function parseLiteralString(cursor: Cursor, line: number): string {
  const { text } = cursor;
  if (text.startsWith("'''", cursor.index)) {
    throw new TomlError("multi-line literal strings are not supported by the context store", line);
  }
  cursor.index += 1;
  const end = text.indexOf("'", cursor.index);
  const newline = text.indexOf("\n", cursor.index);
  if (end === -1 || (newline !== -1 && newline < end)) {
    throw new TomlError("unterminated literal string", line);
  }
  const value = text.slice(cursor.index, end);
  cursor.index = end + 1;
  return value;
}

function parseValue(cursor: Cursor, line: number): TomlValue {
  const { text } = cursor;
  const char = text[cursor.index];
  if (char === '"') return parseBasicString(cursor, line);
  if (char === "'") return parseLiteralString(cursor, line);
  if (char === "[") {
    throw new TomlError("arrays are not supported by the context store", line);
  }
  if (char === "{") {
    throw new TomlError("inline tables are not supported by the context store", line);
  }
  // A bare token: boolean or integer. Stop at whitespace or a comment.
  let end = cursor.index;
  while (end < text.length && !"\n#".includes(text[end] as string)) end += 1;
  const token = text.slice(cursor.index, end).trim();
  cursor.index = end;
  if (token === "true") return true;
  if (token === "false") return false;
  if (/^[+-]?[0-9](?:[0-9_]*[0-9])?$/.test(token)) return Number(token.replace(/_/g, ""));
  throw new TomlError(
    `unsupported value '${token}': the context store holds only strings, booleans and integers`,
    line,
  );
}

function splitDottedKey(raw: string, line: number): string[] {
  const segments: string[] = [];
  const cursor: Cursor = { text: raw, index: 0 };
  for (;;) {
    while (cursor.text[cursor.index] === " " || cursor.text[cursor.index] === "\t")
      cursor.index += 1;
    const char = cursor.text[cursor.index];
    if (char === undefined) throw new TomlError(`invalid key '${raw}'`, line);
    if (char === '"') segments.push(parseBasicString(cursor, line));
    else if (char === "'") segments.push(parseLiteralString(cursor, line));
    else {
      let end = cursor.index;
      while (end < cursor.text.length && BARE_KEY.test(cursor.text[end] as string)) end += 1;
      if (end === cursor.index) throw new TomlError(`invalid key '${raw}'`, line);
      segments.push(cursor.text.slice(cursor.index, end));
      cursor.index = end;
    }
    while (cursor.text[cursor.index] === " " || cursor.text[cursor.index] === "\t")
      cursor.index += 1;
    if (cursor.index >= cursor.text.length) return segments;
    if (cursor.text[cursor.index] !== ".") throw new TomlError(`invalid key '${raw}'`, line);
    cursor.index += 1;
  }
}

/** Walk (creating as needed) to the table named by `path`, following table arrays. */
function descend(root: TomlTable, path: readonly string[], line: number): TomlTable {
  let current = root;
  for (const segment of path) {
    const next = current[segment];
    if (next === undefined) {
      const created: TomlTable = {};
      current[segment] = created;
      current = created;
    } else if (isTable(next)) {
      current = next;
    } else if (isTableArray(next) && next.length > 0) {
      current = next[next.length - 1] as TomlTable;
    } else {
      throw new TomlError(`cannot redefine '${path.join(".")}' as a table`, line);
    }
  }
  return current;
}

/**
 * Parse the supported TOML subset into a plain object.
 *
 * Throws a `TomlError` naming the line for anything outside the subset.
 */
export function parseToml(text: string): TomlTable {
  const root: TomlTable = {};
  let currentPath: string[] = [];
  const lines = text.split("\n");

  for (let index = 0; index < lines.length; index += 1) {
    const lineNumber = index + 1;
    const raw = lines[index] as string;
    const trimmed = raw.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;

    if (trimmed.startsWith("[[")) {
      const close = trimmed.indexOf("]]");
      if (close === -1) throw new TomlError("unterminated array-of-tables header", lineNumber);
      const path = splitDottedKey(trimmed.slice(2, close), lineNumber);
      const parent = descend(root, path.slice(0, -1), lineNumber);
      const key = path[path.length - 1] as string;
      const existing = parent[key];
      const entry: TomlTable = {};
      if (existing === undefined) parent[key] = [entry];
      else if (isTableArray(existing)) (existing as TomlTable[]).push(entry);
      else
        throw new TomlError(
          `cannot redefine '${path.join(".")}' as an array of tables`,
          lineNumber,
        );
      currentPath = path;
      // Point subsequent key/value lines at the entry just pushed.
      continue;
    }

    if (trimmed.startsWith("[")) {
      const close = trimmed.indexOf("]");
      if (close === -1) throw new TomlError("unterminated table header", lineNumber);
      currentPath = splitDottedKey(trimmed.slice(1, close), lineNumber);
      descend(root, currentPath, lineNumber);
      continue;
    }

    const equals = raw.indexOf("=");
    if (equals === -1) throw new TomlError(`expected 'key = value', got '${trimmed}'`, lineNumber);
    const keyPath = splitDottedKey(raw.slice(0, equals), lineNumber);
    if (keyPath.length > 1) {
      throw new TomlError(
        "dotted-key assignments are not supported by the context store",
        lineNumber,
      );
    }
    const cursor: Cursor = { text: raw, index: equals + 1 };
    while (cursor.text[cursor.index] === " " || cursor.text[cursor.index] === "\t")
      cursor.index += 1;
    const value = parseValue(cursor, lineNumber);
    const rest = cursor.text.slice(cursor.index).trim();
    if (rest !== "" && !rest.startsWith("#")) {
      throw new TomlError(`trailing content after value: '${rest}'`, lineNumber);
    }
    const table = descend(root, currentPath, lineNumber);
    const key = keyPath[0] as string;
    if (Object.hasOwn(table, key)) {
      throw new TomlError(`duplicate key '${key}'`, lineNumber);
    }
    table[key] = value;
  }

  return root;
}
