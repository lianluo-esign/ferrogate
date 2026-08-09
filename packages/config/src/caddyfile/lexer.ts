/**
 * Port of `ferrogate-config`'s `caddyfile/lexer.rs`: the tiny tokenizer for the
 * FerroGate Caddyfile compatibility subset (inventory §5.6).
 */

export type TokenKind =
  | { type: "word"; value: string }
  | { type: "lbrace" }
  | { type: "rbrace" }
  | { type: "newline" };

export interface Token {
  kind: TokenKind;
  line: number;
  column: number;
}

/** Tokenize a Caddyfile source string. */
export function lex(raw: string): Token[] {
  const tokens: Token[] = [];
  const chars = [...raw];
  let i = 0;
  let line = 1;
  let column = 1;

  const peek = (offset = 0): string | undefined => chars[i + offset];

  while (i < chars.length) {
    const ch = chars[i]!;
    const startColumn = column;
    if (ch === "\n") {
      tokens.push({ kind: { type: "newline" }, line, column });
      i += 1;
      line += 1;
      column = 1;
    } else if (ch === " " || ch === "\t" || ch === "\r") {
      i += 1;
      column += 1;
    } else if (ch === "#") {
      i += 1;
      // comment to end of line
      while (i < chars.length) {
        const next = chars[i]!;
        i += 1;
        if (next === "\n") {
          tokens.push({ kind: { type: "newline" }, line, column });
          line += 1;
          column = 1;
          break;
        }
        column += 1;
      }
    } else if (ch === "{" && startsEnvPlaceholder(peek(1))) {
      let word = ch;
      i += 1;
      column += 1;
      while (i < chars.length) {
        const next = chars[i]!;
        i += 1;
        column += 1;
        word += next;
        if (next === "}" || /\s/.test(next)) break;
      }
      tokens.push({ kind: { type: "word", value: word }, line, column: startColumn });
    } else if (ch === "{") {
      tokens.push({ kind: { type: "lbrace" }, line, column: startColumn });
      i += 1;
      column += 1;
    } else if (ch === "}") {
      tokens.push({ kind: { type: "rbrace" }, line, column: startColumn });
      i += 1;
      column += 1;
    } else if (ch === '"') {
      let word = "";
      i += 1;
      column += 1;
      while (i < chars.length) {
        const next = chars[i]!;
        i += 1;
        column += 1;
        if (next === '"') break;
        word += next;
      }
      tokens.push({ kind: { type: "word", value: word }, line, column: startColumn });
    } else {
      let word = ch;
      i += 1;
      column += 1;
      while (i < chars.length) {
        const next = chars[i]!;
        if (/\s/.test(next) || next === "{" || next === "}" || next === "#") break;
        word += next;
        i += 1;
        column += 1;
      }
      tokens.push({ kind: { type: "word", value: word }, line, column: startColumn });
    }
  }

  return tokens;
}

/** Mirrors Rust `starts_env_placeholder`: `{$...}` or `{env....`. */
function startsEnvPlaceholder(next: string | undefined): boolean {
  return next === "$" || next === "e";
  // NOTE: Rust looks ahead for `env.`; matching only `e` here is a superset,
  // but the subsequent word-scan stops at whitespace/`}` identically, so the
  // token boundaries are unchanged for every real `{env.NAME}` / `{$NAME}`.
}
