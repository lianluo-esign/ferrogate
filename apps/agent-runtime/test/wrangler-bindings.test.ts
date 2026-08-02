/**
 * The parts of `apps/agent-runtime/wrangler.toml` that NO behavioural test in
 * this suite can see.
 *
 * ## Why this file exists
 *
 * `docs/rewrite/MOUNT-SEAMS.md` §9.4 recorded this app as having **no
 * committed-`wrangler.toml` gate at all**, and — unlike `apps/mcp` — this app
 * is also **not covered by `e2e/`**, so several T1 rows had NO local proof
 * channel of any kind. The wave-14 mutation sweep confirmed four of them:
 *
 *  - **AR-T5** deleting `new_sqlite_classes = ["AgentRunState", "WorkerPlane"]`
 *    left all 342 tests GREEN;
 *  - **AR-T6/T7/T8** editing `FG_DEV_IN_MEMORY_PORTS`, `FG_REQUIRE_PRODUCTION_MTLS`
 *    and `CONTAINER_GOVERNED_EGRESS_HOSTS` in the committed file changed
 *    nothing, because `vitest.config.ts` pins all three as explicit miniflare
 *    bindings that win over the toml. The inventory's "Expected RED" for those
 *    three rows was wrong; its §9.4 header ("NO CONFIG GATE EXISTS IN THIS
 *    APP") was right.
 *
 * The migration row is the dangerous one. `@cloudflare/vitest-pool-workers`
 * builds a Durable Object namespace from the BINDING alone and never consults
 * `[[migrations]]`. Cloudflare does, in two ways: a bound `class_name` no
 * migration introduced is **rejected at deploy**, and a class introduced with
 * `new_classes` instead of `new_sqlite_classes` **deploys fine** while getting
 * the key-value backend instead of the SQLite one. `AgentRunState` holds run
 * lifecycle + SSE fan-out state and `WorkerPlane` holds the lease queue; both
 * assume SQLite.
 *
 * The `[vars]` assertions below are deliberately WEAKER — text-drift gates, not
 * behavioural ones. A pinned test binding is the right call for hermetic tests,
 * so the committed value genuinely cannot be exercised here; what a test CAN do
 * is refuse to let the production-critical value drift unnoticed.
 *
 * `TEST_WRANGLER_TOML` is the COMMITTED file, bound verbatim by
 * `vitest.config.ts`. Asserting against a fixture copy would prove nothing.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import * as compositionRoot from "../src/index.js";
import * as entry from "../src/worker.js";

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(
      "agent-runtime binding gate: TEST_WRANGLER_TOML is not bound; restore it in apps/agent-runtime/vitest.config.ts",
    );
  }
  return raw;
}

/** The bodies of every `[[<header>]]` array-of-tables stanza, as line lists. */
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

/**
 * A binding that names `script_name` borrows a class ANOTHER Worker defines,
 * migrates and exports — `RATE_LIMIT` → `apps/gateway`'s
 * `RateLimiterDurableObject` (#666). Every rule below about migrations and
 * entry-module exports therefore applies to the LOCAL bindings only, and the
 * borrowed ones get the opposite rules in their own describe block.
 */
const LOCAL = (body: readonly string[]): boolean => value(body, "script_name") === undefined;

describe("every Durable Object binding is deployable", () => {
  const bindings = stanzas("durable_objects.bindings").filter(LOCAL);

  it("declares at least the two classes this Worker exports", () => {
    // A guard on the gate itself: if the parser ever stopped matching, every
    // assertion below would pass vacuously over an empty list.
    expect(bindings.length).toBeGreaterThanOrEqual(2);
  });

  it("introduces each LOCAL bound class in a [[migrations]] new_sqlite_classes", () => {
    const { sqlite, legacy } = migratedClasses();
    for (const body of bindings) {
      const className = value(body, "class_name");
      expect(
        className,
        `a [[durable_objects.bindings]] has no class_name: ${body.join(" ")}`,
      ).toBeDefined();
      expect(legacy, `${className} was introduced with new_classes`).not.toContain(className);
      expect(sqlite, `${className} is bound but no migration introduces it`).toContain(className);
    }
  });

  it("resolves each LOCAL bound class against the ENTRY module's exports", () => {
    for (const body of bindings) {
      const className = value(body, "class_name") as string;
      expect(
        typeof (entry as unknown as Record<string, unknown>)[className],
        `class_name ${className} is not exported by src/worker.ts`,
      ).toBe("function");
    }
  });

  /**
   * AR-C9 — `src/index.ts:64-65` re-exports `AgentRunState` and `WorkerPlane`
   * a second time, duplicating AR-E2/AR-E3 on `src/worker.ts`. MOUNT-SEAMS
   * carried this row with *Expected RED: none* through every wave, on the
   * stated grounds that it is "genuinely redundant … kept because
   * `vitest.config.ts` can point `main` at either" module.
   *
   * Half of that is wrong, and the source says so. `src/worker.ts`'s own
   * docblock records that `main` CANNOT point at `src/index.ts`: workerd treats
   * every named export of the entry module as a service entrypoint and rejects
   * one that is not a function / handler / class, and `src/index.ts` exports
   * `OWNED_OPERATIONS`, an array. So there is no configuration in which these
   * two lines are the ones workerd resolves `class_name` against.
   *
   * What they still are is a claim — that the two candidate modules agree on
   * which class each name means. That claim was asserted by nothing, so
   * deleting both lines, or pointing either at a different class, was invisible.
   * This asserts IDENTITY, not mere presence: a same-named stub class would
   * satisfy `typeof … === "function"` and still be a different Durable Object.
   */
  it("keeps the composition root's duplicate DO exports IDENTICAL to the entry module's (AR-C9)", () => {
    const names = bindings.map((body) => value(body, "class_name") as string);
    expect(names.length).toBeGreaterThanOrEqual(2);
    for (const className of names) {
      const fromRoot = (compositionRoot as unknown as Record<string, unknown>)[className];
      const fromEntry = (entry as unknown as Record<string, unknown>)[className];
      expect(fromRoot, `src/index.ts no longer re-exports ${className}`).toBeDefined();
      expect(
        fromRoot,
        `src/index.ts's ${className} is a DIFFERENT class than src/worker.ts's`,
      ).toBe(fromEntry);
    }
  });
});

describe("the BORROWED counter namespace (#666)", () => {
  const borrowed = stanzas("durable_objects.bindings").filter((body) => !LOCAL(body));

  it("binds RATE_LIMIT from apps/gateway and nothing else cross-script", () => {
    // Not vacuous, and the count is pinned: a second borrowed namespace is a
    // second deploy-order dependency and deserves its own decision.
    expect(borrowed.length).toBe(1);
    const body = borrowed[0] as string[];
    expect(value(body, "name")).toBe("RATE_LIMIT");
    expect(value(body, "class_name")).toBe("RateLimiterDurableObject");
    expect(value(body, "script_name")).toBe("ferrogate-gateway");
  });

  it("neither migrates nor exports the borrowed class", () => {
    // Both are deploy-time refusals from Cloudflare ("Cannot create binding for
    // class … because it is not currently defined" for the migration side), and
    // an export here would be the start of a SECOND, private namespace — the
    // per-Worker quota multiplier this issue exists to close.
    const { sqlite, legacy } = migratedClasses();
    expect([...sqlite, ...legacy]).not.toContain("RateLimiterDurableObject");
    expect((entry as unknown as Record<string, unknown>).RateLimiterDurableObject).toBeUndefined();
    expect(
      (compositionRoot as unknown as Record<string, unknown>).RateLimiterDurableObject,
    ).toBeUndefined();
  });
});

describe("the runtime contract at the top of the file", () => {
  it("keeps nodejs_compat in compatibility_flags (AR-T2)", () => {
    // Corrected in wave 17. The MOUNT-SEAMS row's *Expected RED* was "whole
    // suite"; measured, commenting the line out left every agent-runtime suite
    // GREEN, because `@cloudflare/vitest-pool-workers` supplies its own runtime
    // flags. The line whose absence stops the deployed Worker starting had no
    // gate at all.
    expect(wranglerToml()).toMatch(/^compatibility_flags\s*=\s*\[[^\]]*"nodejs_compat"/m);
  });

  it("pins a compatibility_date (AR-T2)", () => {
    expect(wranglerToml()).toMatch(/^compatibility_date\s*=\s*"\d{4}-\d{2}-\d{2}"/m);
  });
});

describe("the entry module the deploy config points at", () => {
  it("names src/worker.ts as main, not the composition root", () => {
    // `src/index.ts` default-exports the Hono app; `AgentRunState` and
    // `WorkerPlane` are re-exported from BOTH files today, but `main` pointing
    // at the composition root is still wrong — `src/worker.ts` is the declared
    // entry and the only one this gate resolves `class_name` against.
    expect(wranglerToml()).toMatch(/^main = "src\/worker\.ts"$/m);
  });
});

describe("the production-critical [vars] this suite pins away", () => {
  /**
   * These three are read by `src/ports.ts` and `src/mtls.ts`, but
   * `vitest.config.ts` binds all three explicitly so the suite is hermetic —
   * which means the COMMITTED value is never exercised and can drift freely.
   * Each assertion below states the committed value and why it is that value.
   */
  it("ships CONTAINER_GOVERNED_EGRESS_HOSTS SEALED (#471)", () => {
    // Empty means sealed: `parseGovernedEgressHosts("")` is `[]`, and
    // `inMemoryGovernancePort` grants nothing from an empty list. A committed
    // "*" would grant ALL egress from every container, because the port treats
    // "*" as grant-all.
    expect(wranglerToml()).toMatch(/^CONTAINER_GOVERNED_EGRESS_HOSTS = ""$/m);
  });

  it("still spells the two flags CLOUD-VERIFICATION §B1 must override", () => {
    // Both are committed at their DEV value so `wrangler dev --local` boots.
    // Nothing mechanical stops a deploy inheriting them; this only stops the
    // names drifting out of the override list while the code still reads them.
    expect(wranglerToml()).toMatch(/^FG_DEV_IN_MEMORY_PORTS = "1"$/m);
    expect(wranglerToml()).toMatch(/^FG_REQUIRE_PRODUCTION_MTLS = "0"$/m);
  });
});
