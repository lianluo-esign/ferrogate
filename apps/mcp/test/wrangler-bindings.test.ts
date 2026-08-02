/**
 * The parts of `apps/mcp/wrangler.toml` that NO behavioural test in this suite
 * can see.
 *
 * ## Why this file exists
 *
 * `docs/rewrite/MOUNT-SEAMS.md` §8.5 recorded this app as having **no
 * committed-`wrangler.toml` gate at all**. `vitest.config.ts` names `main`
 * explicitly, which overrides the toml, and nothing under `test/` read the
 * committed file — so two T1 seams (MCP-T6, MCP-T7) had no local proof channel
 * of any kind, and the wave-14 mutation sweep confirmed it: deleting either
 *
 *     [[migrations]]
 *     new_sqlite_classes = ["McpOauthFlowClaim"]
 *     new_sqlite_classes = ["FerroGateMcpSession"]
 *
 * left all 340 MCP tests GREEN.
 *
 * That is not a cosmetic gap. `@cloudflare/vitest-pool-workers` builds a
 * Durable Object namespace from the BINDING alone and never consults the
 * migration list. Cloudflare does consult it, in two different ways:
 *
 *  1. a `[[durable_objects.bindings]]` whose `class_name` was never introduced
 *     by a migration is **rejected at deploy** (`Cannot create binding for
 *     class McpOauthFlowClaim because it is not currently defined`), so the
 *     first real `wrangler deploy` would fail; and — the worse case —
 *  2. a class introduced with `new_classes` instead of `new_sqlite_classes`
 *     **deploys fine** and silently gets the key-value backend instead of the
 *     SQLite one. `McpOauthFlowClaim` is the single-claim OAuth flow arbiter
 *     and `FerroGateMcpSession` holds session state; both assume SQLite
 *     storage. A green suite plus a successful deploy plus the wrong storage
 *     engine is exactly the failure mode this project keeps finding.
 *
 * `TEST_WRANGLER_TOML` is the COMMITTED file, bound verbatim by
 * `vitest.config.ts`. Asserting against a fixture copy would prove nothing.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import * as entry from "../src/worker.js";

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(
      "mcp binding gate: TEST_WRANGLER_TOML is not bound; restore it in apps/mcp/vitest.config.ts",
    );
  }
  return raw;
}

/**
 * The bodies of every `[[<header>]]` array-of-tables stanza, as line lists.
 *
 * Line-oriented on purpose: a TOML table ends at the next header, and a regex
 * that spans headers is the kind of subtlety that makes a config gate quietly
 * match nothing. Comment lines are dropped, so commenting a stanza out reads as
 * deleting it — which is what it is, and what the mutation sweep does.
 */
function stanzas(header: string): string[][] {
  const out: string[][] = [];
  let current: string[] | null = null;
  for (const line of wranglerToml().split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) continue;
    if (/^\[/.test(trimmed)) {
      if (current !== null) out.push(current);
      current = trimmed === `[[${header}]]` ? [] : null;
      continue;
    }
    if (current !== null && trimmed !== "") current.push(trimmed);
  }
  if (current !== null) out.push(current);
  return out;
}

/** `key = "value"` out of a stanza body. */
function value(body: readonly string[], key: string): string | undefined {
  for (const line of body) {
    const match = new RegExp(`^${key}\\s*=\\s*"([^"]*)"`).exec(line);
    if (match !== null) return match[1];
  }
  return undefined;
}

/** Every class named by any migration, split by which storage backend it got. */
function migratedClasses(): { sqlite: string[]; legacy: string[] } {
  const sqlite: string[] = [];
  const legacy: string[] = [];
  for (const body of stanzas("migrations")) {
    for (const line of body) {
      const match = /^(new_sqlite_classes|new_classes)\s*=\s*\[([^\]]*)\]/.exec(line);
      if (match === null) continue;
      const target = match[1] === "new_sqlite_classes" ? sqlite : legacy;
      for (const entryMatch of (match[2] ?? "").matchAll(/"([^"]+)"/g)) {
        target.push(entryMatch[1] as string);
      }
    }
  }
  return { sqlite, legacy };
}

describe("every Durable Object binding is deployable", () => {
  const bindings = stanzas("durable_objects.bindings");

  it("declares at least the two classes this Worker exports", () => {
    // A guard on the gate itself: if the parser ever stopped matching, every
    // assertion below would pass vacuously over an empty list.
    expect(bindings.length).toBeGreaterThanOrEqual(2);
  });

  it("introduces each bound class in a [[migrations]] new_sqlite_classes", () => {
    const { sqlite, legacy } = migratedClasses();
    for (const body of bindings) {
      const className = value(body, "class_name");
      expect(className, `a [[durable_objects.bindings]] has no class_name: ${body.join(" ")}`)
        .toBeDefined();
      expect(legacy, `${className} was introduced with new_classes`).not.toContain(className);
      expect(sqlite, `${className} is bound but no migration introduces it`).toContain(className);
    }
  });

  it("resolves each bound class against the ENTRY module's exports", () => {
    // workerd resolves `class_name` against `main`. This closes the loop from
    // the CONFIG side, so adding a third binding without its `src/worker.ts`
    // re-export fails here rather than at `wrangler dev`.
    for (const body of bindings) {
      const className = value(body, "class_name") as string;
      expect(
        typeof (entry as unknown as Record<string, unknown>)[className],
        `class_name ${className} is not exported by src/worker.ts`,
      ).toBe("function");
    }
  });
});

describe("wave 24 — the S5 entitlement ladder needs no new binding, ASSERTED", () => {
  /**
   * `src/entitlements.ts` (`D1ToolEntitlements`, cluster **S5**) reads the
   * CONTROL database through `env.DB` and NOTHING else. Under
   * `@cloudflare/vitest-pool-workers` that binding comes from
   * `vitest.config.ts`, so every entitlement test would still pass if the
   * committed deploy config stopped declaring it — and the ladder would then
   * fall back to `InMemoryEntitlements` in production, denying nobody. That is
   * the R1 shape again, one level down, and only the committed text can see it.
   */
  it("declares the CONTROL D1 binding the entitlement ladder reads", () => {
    const d1 = stanzas("d1_databases");
    expect(d1.length, "no [[d1_databases]] stanza in the committed config").toBeGreaterThan(0);
    const control = d1.filter((body) => value(body, "binding") === "DB");
    expect(control.length, 'no [[d1_databases]] declares binding = "DB"').toBe(1);
    expect(value(control[0] as string[], "database_name")).toBe("ferrogate-control");
    // The id is a deploy-time PLACEHOLDER by design (CLOUD-VERIFICATION §B).
    // Pinning it stops a real account id from being committed by accident.
    expect(value(control[0] as string[], "database_id")).toBe("PLACEHOLDER_SET_AT_DEPLOY_TIME");
  });

  /**
   * INERTNESS, asserted rather than claimed in a wave note: S5 introduced no
   * Durable Object, so the committed config's bound class set must still be
   * exactly the set `src/worker.ts` exports. A new DO added without its binding
   * (or a binding added without its export) fails here.
   */
  it("binds exactly the Durable Object classes the entry module exports", () => {
    const bound = stanzas("durable_objects.bindings")
      .map((body) => value(body, "class_name"))
      .filter((name): name is string => name !== undefined)
      .sort();
    const exported = Object.entries(entry as unknown as Record<string, unknown>)
      .filter(([name, member]) => name !== "default" && typeof member === "function")
      .map(([name]) => name)
      .sort();
    expect(bound).toEqual(exported);
    expect(bound).toEqual(["FerroGateMcpSession", "McpOauthFlowClaim"]);
  });
});

describe("the entry module the deploy config points at", () => {
  it("names src/worker.ts as main, not the composition root", () => {
    // `src/index.ts` default-exports the Hono app; the Durable Object classes
    // are re-exported only from `src/worker.ts`. Pointing `main` at the former
    // deploys a Worker whose DO namespaces resolve to nothing. vitest cannot
    // see this (it overrides `main`), so the assertion is on the text.
    expect(wranglerToml()).toMatch(/^main = "src\/worker\.ts"$/m);
  });
});

describe("the dev flag that must not reach production", () => {
  /**
   * `FG_DEV_IN_MEMORY_PORTS = "1"` is COMMITTED to the deploy config, because
   * the local `wrangler dev` boot and `e2e/` both need the in-memory port
   * bundle. A deploy that inherits it runs those ports in PRODUCTION.
   *
   * This gate cannot stop that — only the deploy procedure can — so it does the
   * one thing a test can: it pins the fact, so the var cannot be silently
   * renamed out of `docs/rewrite/CLOUD-VERIFICATION.md` §B1's override list
   * while still being read by `src/ports.ts`.
   */
  it("is still spelled exactly as CLOUD-VERIFICATION §B1 overrides it", () => {
    expect(wranglerToml()).toMatch(/^FG_DEV_IN_MEMORY_PORTS = "1"$/m);
  });
});
