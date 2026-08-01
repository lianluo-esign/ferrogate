/**
 * SCIM 2.0 filter parsing + evaluation (RFC 7644 §3.4.2.2).
 *
 * Why this is a security control and not a convenience: Okta and Entra ID both
 * probe `GET /Users?filter=userName eq "…"` before every create. A service
 * that IGNORES a filter it cannot parse answers that probe with the whole
 * tenant directory, and the IdP reads a non-empty response as "this user
 * already exists" — silently binding the new hire to whichever record came
 * back first. So the only two outcomes here are an evaluated filter or a
 * `400 invalidFilter`; there is no "return everything" branch.
 *
 * Grammar implemented (a deliberate subset — the parts an IdP actually sends):
 *
 * ```
 *   filter     := or
 *   or         := and ("or" and)*
 *   and        := unary ("and" unary)*
 *   unary      := "not" "(" or ")" | "(" or ")" | comparison
 *   comparison := attrPath ("pr" | operator value)
 *   operator   := eq | ne | co | sw | ew | gt | ge | lt | le
 *   value      := string | number | "true" | "false" | "null"
 * ```
 *
 * `not` REQUIRES parentheses, exactly as RFC 7644's ABNF does; a bare
 * `not userName eq "x"` is a syntax error rather than a guess.
 */

/** Bound on parenthesis nesting — a filter is IdP input, not a program. */
const MAX_FILTER_DEPTH = 20;

export type ScimComparisonOperator = "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "ge" | "lt" | "le";

export type ScimFilter =
  | { kind: "and"; left: ScimFilter; right: ScimFilter }
  | { kind: "or"; left: ScimFilter; right: ScimFilter }
  | { kind: "not"; operand: ScimFilter }
  | { kind: "present"; attribute: string }
  | {
      kind: "compare";
      attribute: string;
      operator: ScimComparisonOperator;
      value: string | number | boolean | null;
    };

export type ScimFilterParse = { ok: true; filter: ScimFilter } | { ok: false; reason: string };

const OPERATORS = new Set<string>(["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"]);

type Token =
  | { type: "lparen" }
  | { type: "rparen" }
  | { type: "word"; value: string }
  | { type: "string"; value: string };

/** Splits a filter into tokens, or `null` if it contains something lexical-illegal. */
function tokenize(source: string): Token[] | null {
  const tokens: Token[] = [];
  let index = 0;
  while (index < source.length) {
    const character = source[index] as string;
    if (character === " " || character === "\t" || character === "\n" || character === "\r") {
      index += 1;
      continue;
    }
    if (character === "(") {
      tokens.push({ type: "lparen" });
      index += 1;
      continue;
    }
    if (character === ")") {
      tokens.push({ type: "rparen" });
      index += 1;
      continue;
    }
    if (character === '"') {
      index += 1;
      let value = "";
      let terminated = false;
      while (index < source.length) {
        const current = source[index] as string;
        if (current === "\\") {
          const next = source[index + 1];
          if (next === undefined) return null;
          value += next;
          index += 2;
          continue;
        }
        if (current === '"') {
          terminated = true;
          index += 1;
          break;
        }
        value += current;
        index += 1;
      }
      if (!terminated) return null;
      tokens.push({ type: "string", value });
      continue;
    }
    let word = "";
    while (index < source.length) {
      const current = source[index] as string;
      if (current === " " || current === "(" || current === ")" || current === '"') break;
      word += current;
      index += 1;
    }
    if (word.length === 0) return null;
    tokens.push({ type: "word", value: word });
  }
  return tokens;
}

/**
 * The bare attribute name a (possibly urn-qualified, possibly dotted) SCIM
 * attribute path refers to. `urn:…:core:2.0:User:userName` → `userName`.
 */
function normaliseAttributePath(path: string): string {
  const lastColon = path.lastIndexOf(":");
  return lastColon >= 0 ? path.slice(lastColon + 1) : path;
}

class Parser {
  private position = 0;
  constructor(private readonly tokens: Token[]) {}

  parse(): ScimFilter | null {
    const filter = this.parseOr(0);
    if (!filter) return null;
    if (this.position !== this.tokens.length) return null;
    return filter;
  }

  private peek(): Token | undefined {
    return this.tokens[this.position];
  }

  private parseOr(depth: number): ScimFilter | null {
    let left = this.parseAnd(depth);
    if (!left) return null;
    while (this.isKeyword("or")) {
      this.position += 1;
      const right = this.parseAnd(depth);
      if (!right) return null;
      left = { kind: "or", left, right };
    }
    return left;
  }

  private parseAnd(depth: number): ScimFilter | null {
    let left = this.parseUnary(depth);
    if (!left) return null;
    while (this.isKeyword("and")) {
      this.position += 1;
      const right = this.parseUnary(depth);
      if (!right) return null;
      left = { kind: "and", left, right };
    }
    return left;
  }

  private parseUnary(depth: number): ScimFilter | null {
    if (depth > MAX_FILTER_DEPTH) return null;
    if (this.isKeyword("not")) {
      this.position += 1;
      // RFC 7644 ABNF: `not` takes a PARENTHESISED expression.
      if (this.peek()?.type !== "lparen") return null;
      this.position += 1;
      const operand = this.parseOr(depth + 1);
      if (!operand) return null;
      if (this.peek()?.type !== "rparen") return null;
      this.position += 1;
      return { kind: "not", operand };
    }
    if (this.peek()?.type === "lparen") {
      this.position += 1;
      const inner = this.parseOr(depth + 1);
      if (!inner) return null;
      if (this.peek()?.type !== "rparen") return null;
      this.position += 1;
      return inner;
    }
    return this.parseComparison();
  }

  private parseComparison(): ScimFilter | null {
    const attributeToken = this.peek();
    if (!attributeToken || attributeToken.type !== "word") return null;
    // A bare keyword is not an attribute path.
    const lowered = attributeToken.value.toLowerCase();
    if (lowered === "and" || lowered === "or" || lowered === "not") return null;
    this.position += 1;
    const attribute = normaliseAttributePath(attributeToken.value);

    const operatorToken = this.peek();
    if (!operatorToken || operatorToken.type !== "word") return null;
    const operator = operatorToken.value.toLowerCase();
    this.position += 1;

    if (operator === "pr") return { kind: "present", attribute };
    if (!OPERATORS.has(operator)) return null;

    const valueToken = this.peek();
    if (!valueToken) return null;
    this.position += 1;
    if (valueToken.type === "string") {
      return {
        kind: "compare",
        attribute,
        operator: operator as ScimComparisonOperator,
        value: valueToken.value,
      };
    }
    if (valueToken.type !== "word") return null;
    let value: string | number | boolean | null;
    if (valueToken.value === "true") value = true;
    else if (valueToken.value === "false") value = false;
    else if (valueToken.value === "null") value = null;
    else if (/^-?\d+(\.\d+)?$/.test(valueToken.value)) value = Number(valueToken.value);
    else return null;
    return { kind: "compare", attribute, operator: operator as ScimComparisonOperator, value };
  }

  private isKeyword(keyword: string): boolean {
    const token = this.peek();
    return token?.type === "word" && token.value.toLowerCase() === keyword;
  }
}

/** Parses a SCIM filter. Never throws; an unparseable filter is a refusal. */
export function parseScimFilter(source: string): ScimFilterParse {
  if (typeof source !== "string" || source.trim().length === 0) {
    return { ok: false, reason: "empty filter" };
  }
  const tokens = tokenize(source);
  if (!tokens || tokens.length === 0) return { ok: false, reason: "malformed filter" };
  const filter = new Parser(tokens).parse();
  if (!filter) return { ok: false, reason: "malformed filter" };
  return { ok: true, filter };
}

/**
 * Reads an attribute off a resource. Attribute NAMES are matched
 * case-insensitively (RFC 7644 §3.4.2.2 makes them case-insensitive); VALUES
 * are not — see `compare`.
 */
function readAttribute(resource: Record<string, unknown>, attribute: string): unknown {
  const wanted = attribute.toLowerCase();
  for (const [key, value] of Object.entries(resource)) {
    if (key.toLowerCase() === wanted) return value;
  }
  return undefined;
}

function compare(
  actual: unknown,
  operator: ScimComparisonOperator,
  expected: string | number | boolean | null,
): boolean {
  // An attribute the resource does not carry matches NOTHING — including
  // `ne`. Treating absence as "not equal, therefore true" would make
  // `nickName ne "x"` select the entire directory.
  if (actual === undefined || actual === null) return false;

  if (typeof expected === "boolean" || typeof actual === "boolean") {
    if (operator === "eq") return actual === expected;
    if (operator === "ne") return actual !== expected;
    return false;
  }
  if (typeof actual === "number" && typeof expected === "number") {
    switch (operator) {
      case "eq":
        return actual === expected;
      case "ne":
        return actual !== expected;
      case "gt":
        return actual > expected;
      case "ge":
        return actual >= expected;
      case "lt":
        return actual < expected;
      case "le":
        return actual <= expected;
      default:
        return false;
    }
  }
  if (typeof actual !== "string" || typeof expected !== "string") return false;
  // Values are compared case-SENSITIVELY. FerroGate normalises every stored
  // `userName` to lowercase on the way in (`scimUserCreate`), so a
  // case-insensitive compare here would buy nothing and would let
  // `userName eq "ADMIN@…"` and `userName eq "admin@…"` disagree with what a
  // subsequent create actually stores.
  switch (operator) {
    case "eq":
      return actual === expected;
    case "ne":
      return actual !== expected;
    case "co":
      return actual.includes(expected);
    case "sw":
      return actual.startsWith(expected);
    case "ew":
      return actual.endsWith(expected);
    case "gt":
      return actual > expected;
    case "ge":
      return actual >= expected;
    case "lt":
      return actual < expected;
    case "le":
      return actual <= expected;
    default:
      return false;
  }
}

/** Evaluates a parsed filter against one SCIM resource. */
export function matchesScimFilter(filter: ScimFilter, resource: Record<string, unknown>): boolean {
  switch (filter.kind) {
    case "and":
      return matchesScimFilter(filter.left, resource) && matchesScimFilter(filter.right, resource);
    case "or":
      return matchesScimFilter(filter.left, resource) || matchesScimFilter(filter.right, resource);
    case "not":
      return !matchesScimFilter(filter.operand, resource);
    case "present": {
      const value = readAttribute(resource, filter.attribute);
      if (value === undefined || value === null) return false;
      if (typeof value === "string") return value.length > 0;
      if (Array.isArray(value)) return value.length > 0;
      return true;
    }
    case "compare":
      return compare(readAttribute(resource, filter.attribute), filter.operator, filter.value);
  }
}
