/**
 * Port of `ferrogate-config`'s `diagnostic.rs` — the structured Caddyfile
 * error (`CaddyfileDiagnostic`).
 *
 * The rendered form is `<file>:<line>:<column> <message>. <suggestion>`, and
 * every constructor puts its complete human diagnosis in `message` (#540). It
 * is a throwable `Error` subclass (idiomatic TS) that still exposes the
 * structured fields the Rust struct carried.
 */

/** The structured fields of a Caddyfile diagnostic. */
export interface CaddyfileDiagnosticData {
  file: string;
  line: number;
  column: number;
  directive: string;
  message: string;
  suggestion: string;
}

/** Structured Caddyfile parse/compat error (file:line:col + message + suggestion). */
export class CaddyfileDiagnostic extends Error implements CaddyfileDiagnosticData {
  override readonly name = "CaddyfileDiagnostic";
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly directive: string;
  readonly suggestion: string;

  constructor(data: CaddyfileDiagnosticData) {
    super(`${data.file}:${data.line}:${data.column} ${data.message}. ${data.suggestion}`);
    this.file = data.file;
    this.line = data.line;
    this.column = data.column;
    this.directive = data.directive;
    this.suggestion = data.suggestion;
  }

  /** `<file>:<line>:<column> <message>. <suggestion>` (Rust `Display`). */
  render(): string {
    return `${this.file}:${this.line}:${this.column} ${this.message}. ${this.suggestion}`;
  }
}
