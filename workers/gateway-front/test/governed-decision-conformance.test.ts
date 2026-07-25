// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, Runner B of the #470
// governed-decision conformance suite: drives the SAME committed corpus through
// the real gateway-front Worker in workerd and asserts the §8d directional
// properties -- the shell may abstain or veto, never allow, never meter.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import {
  canonicalJson,
  directionalConformance,
  EMPTY_METERED,
  GOVERNED_DECISION_SCHEMA,
  type GovernedDecisionRecord,
} from "../src/shell";

/**
 * The corpus, inlined by Vite at build time.
 *
 * workerd has no filesystem, so the fixtures cannot be read at runtime the way
 * Runner A reads them. They are the *same files* -- one corpus, committed at the
 * repository root so neither host owns it -- reached by a relative glob rather
 * than copied. A copy would make the suite prove that two copies agree, which is
 * not the property under test.
 */
const CORPUS = import.meta.glob("../../../tests/fixtures/governed-decisions/*.json", {
  eager: true,
  import: "default",
}) as Record<string, Fixture>;

const BASE = "https://gateway-front.test";

interface Fixture {
  id: string;
  schema: number;
  description: string;
  request: {
    endpoint: string;
    headers?: Record<string, string>;
    body?: unknown;
    body_raw?: string;
    body_over_limit?: boolean;
  };
  expect: Partial<GovernedDecisionRecord> & { outcome: string; status: number };
  worker_shell: {
    deny_list?: string[];
    expect: Partial<GovernedDecisionRecord> & { outcome: string; status: number };
  };
}

/** Fills the same serde defaults the Rust side applies, so the two canonical forms line up. */
function materialise(
  partial: Partial<GovernedDecisionRecord> & { outcome: string; status: number },
): GovernedDecisionRecord {
  return {
    schema: partial.schema ?? GOVERNED_DECISION_SCHEMA,
    outcome: partial.outcome as GovernedDecisionRecord["outcome"],
    status: partial.status,
    code: partial.code ?? null,
    metered: { ...EMPTY_METERED, ...(partial.metered ?? {}) },
    durable_writes: partial.durable_writes ?? [],
    audit_events: partial.audit_events ?? [],
  };
}

const fixtures = Object.entries(CORPUS)
  .map(([path, fixture]) => [path.split("/").pop() ?? path, fixture] as const)
  .sort(([left], [right]) => left.localeCompare(right));

/**
 * The shared vocabulary, derived from the corpus rather than duplicated.
 *
 * Runner A already gates that every fixture code is in the Rust
 * `GOVERNED_ERROR_VOCABULARY` and that every reproducible code has a fixture, so
 * this set is a subset of the true vocabulary. Deriving it here keeps the
 * vocabulary single-sourced: a second hand-maintained list in TypeScript would
 * be exactly the kind of drift this suite exists to catch.
 */
const VOCABULARY: ReadonlySet<string> = new Set(
  fixtures.flatMap(([, fixture]) =>
    [fixture.expect.code, fixture.worker_shell.expect.code].filter(
      (code): code is string => typeof code === "string",
    ),
  ),
);

async function askTheShell(fixture: Fixture): Promise<GovernedDecisionRecord> {
  const response = await SELF.fetch(`${BASE}/__conformance/decide`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(fixture),
  });
  expect(response.status).toBe(200);
  return (await response.json()) as GovernedDecisionRecord;
}

describe("the corpus is non-empty and shared", () => {
  it("loads the same fixtures Runner A drives", () => {
    expect(fixtures.length).toBeGreaterThan(30);
    for (const [name, fixture] of fixtures) {
      expect(fixture.schema, `${name}: schema`).toBe(GOVERNED_DECISION_SCHEMA);
      expect(fixture.description.length, `${name}: description`).toBeGreaterThan(30);
    }
  });
});

describe("the veto-only shell is directionally conformant over the whole corpus", () => {
  for (const [name, fixture] of fixtures) {
    it(`${name}: ${fixture.id}`, async () => {
      const actual = await askTheShell(fixture);
      const declared = materialise(fixture.worker_shell.expect);
      const authority = materialise(fixture.expect);

      // 1. The Worker answers what the corpus says it answers, byte for byte.
      expect(canonicalJson(actual), `${name}: shell answer`).toBe(canonicalJson(declared));

      // 2. That answer is directionally legal against the authority's decision:
      //    abstain or veto, never allow, never a metered amount (§8d).
      expect(directionalConformance(authority, actual, VOCABULARY), `${name}: direction`).toBeNull();
    });
  }
});

describe("the shell cannot be talked into authoring a decision", () => {
  it("never allows, never meters and never writes, for any corpus case", async () => {
    for (const [name, fixture] of fixtures) {
      const actual = await askTheShell(fixture);
      expect(["defer", "deny"], `${name}: outcome`).toContain(actual.outcome);
      expect(canonicalJson(actual.metered), `${name}: metered`).toBe(canonicalJson(EMPTY_METERED));
      expect(actual.durable_writes, `${name}: durable_writes`).toEqual([]);
      expect(actual.audit_events, `${name}: audit_events`).toEqual([]);
    }
  });
});

describe("the conformance route is not a production surface", () => {
  it("is 404 unless CONFORMANCE is exactly 1", async () => {
    const response = await worker.fetch(
      new Request(`${BASE}/__conformance/decide`, { method: "POST", body: "{}" }),
      { CONFORMANCE: "0" },
    );
    expect(response.status).toBe(404);
  });
});

describe("the request path itself never admits", () => {
  it("fails closed with 501 rather than answering when no origin is bound", async () => {
    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { authorization: "Bearer secret-1", "content-type": "application/json" },
      body: JSON.stringify({ model: "fast-chat", messages: [] }),
    });
    // A shell that cannot reach the authority must not invent one (#472 binds
    // the container origin).
    expect(response.status).toBe(501);
  });

  it("vetoes a credential-less request before it can reach any origin", async () => {
    const response = await SELF.fetch(`${BASE}/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "fast-chat", messages: [] }),
    });
    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("missing_api_key");
  });
});
