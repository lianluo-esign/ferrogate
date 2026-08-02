/**
 * SCIM 2.0 filter parsing + evaluation (RFC 7644 §3.4.2.2).
 *
 * Not decoration: Okta and Entra ID both probe `GET /Users?filter=userName eq
 * "..."` before every create, and a service that IGNORES an unparsed filter
 * answers that probe with the whole tenant directory — which the IdP reads as
 * "the user already exists" for whichever record happens to come back first.
 * So an unparseable filter must be a 400 (`invalidFilter`), never a silent
 * full listing.
 */
import { describe, expect, test } from "vitest";
import { matchesScimFilter, parseScimFilter } from "../src/scim/filter.js";

const ALICE = {
  id: "u1",
  userName: "alice@example.com",
  displayName: "Alice Example",
  active: true,
  ferrogateRole: "admin",
};
const BOB = {
  id: "u2",
  userName: "bob@example.com",
  displayName: "Bob",
  active: false,
  ferrogateRole: "viewer",
};

function evaluate(source: string, resource: Record<string, unknown>): boolean {
  const parsed = parseScimFilter(source);
  if (!parsed.ok) throw new Error(`expected ${source} to parse: ${parsed.reason}`);
  return matchesScimFilter(parsed.filter, resource);
}

describe("parseScimFilter", () => {
  test('userName eq "…" — the probe every IdP sends', () => {
    expect(evaluate('userName eq "alice@example.com"', ALICE)).toBe(true);
    expect(evaluate('userName eq "alice@example.com"', BOB)).toBe(false);
  });

  test("attribute names are case-insensitive, values are not", () => {
    expect(evaluate('USERNAME eq "alice@example.com"', ALICE)).toBe(true);
    expect(evaluate('userName eq "ALICE@example.com"', ALICE)).toBe(false);
  });

  test("ne / co / sw / ew", () => {
    expect(evaluate('userName ne "bob@example.com"', ALICE)).toBe(true);
    expect(evaluate('displayName co "Examp"', ALICE)).toBe(true);
    expect(evaluate('userName sw "alice"', ALICE)).toBe(true);
    expect(evaluate('userName ew "example.com"', ALICE)).toBe(true);
    expect(evaluate('userName sw "bob"', ALICE)).toBe(false);
  });

  test("pr (present) is false for absent and for empty", () => {
    expect(evaluate("displayName pr", ALICE)).toBe(true);
    expect(evaluate("nickName pr", ALICE)).toBe(false);
    expect(evaluate("displayName pr", { ...ALICE, displayName: "" })).toBe(false);
  });

  test("boolean equality on active", () => {
    expect(evaluate("active eq true", ALICE)).toBe(true);
    expect(evaluate("active eq false", ALICE)).toBe(false);
    expect(evaluate("active eq false", BOB)).toBe(true);
  });

  test("and binds tighter than or", () => {
    // `A or B and C` === `A or (B and C)`
    expect(evaluate('userName eq "nobody" or userName sw "alice" and active eq true', ALICE)).toBe(
      true,
    );
    expect(evaluate('userName eq "nobody" or userName sw "alice" and active eq false', ALICE)).toBe(
      false,
    );
  });

  test("parentheses override precedence", () => {
    expect(
      evaluate('(userName eq "nobody" or userName sw "alice") and active eq false', ALICE),
    ).toBe(false);
  });

  test("not(...)", () => {
    expect(evaluate('not (userName eq "alice@example.com")', ALICE)).toBe(false);
    expect(evaluate('not (userName eq "alice@example.com")', BOB)).toBe(true);
  });

  test("escaped quotes inside a value", () => {
    expect(evaluate('displayName eq "a\\"b"', { displayName: 'a"b' })).toBe(true);
  });

  test("urn-qualified attribute paths resolve to the bare attribute", () => {
    expect(
      evaluate('urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice@example.com"', ALICE),
    ).toBe(true);
  });

  test("REJECTS an unparseable filter rather than matching everything", () => {
    for (const bad of [
      "",
      "userName",
      "userName eq",
      'userName zz "x"',
      '(userName eq "x"',
      'userName eq "x") and',
      "and",
      'userName eq "unterminated',
      'not userName eq "x"',
    ]) {
      const parsed = parseScimFilter(bad);
      expect(parsed.ok, `expected ${JSON.stringify(bad)} to be rejected`).toBe(false);
    }
  });

  test("an unknown attribute matches nothing (it does not match everything)", () => {
    expect(evaluate('nickName eq "alice"', ALICE)).toBe(false);
    expect(evaluate('nickName ne "alice"', ALICE)).toBe(false);
  });

  test("a deeply nested filter is refused rather than blowing the stack", () => {
    const nested = `${"(".repeat(200)}userName eq "x"${")".repeat(200)}`;
    const parsed = parseScimFilter(nested);
    expect(parsed.ok).toBe(false);
  });
});
