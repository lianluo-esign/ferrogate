/**
 * The `[triggers] crons` stanza — the half of the schedule wiring that lives in
 * `wrangler.toml` and that no behavioural test could see.
 *
 * `test/worker-entry.test.ts` already holds the OTHER half: that `scheduled`
 * rides on the entry module's DEFAULT export, and that invoking it fires a due
 * schedule. What neither it nor any other file could observe is whether
 * Cloudflare is ever told to invoke it: `@cloudflare/vitest-pool-workers` boots
 * the Worker but dispatches no scheduled event of its own, so the trigger is
 * invisible to the suite.
 *
 * The wave-11 mount-mutation sweep proved that gap was real — deleting
 * `[triggers] crons = ["* * * * *"]` from the committed `wrangler.toml` left all
 * 428 tests GREEN, while in production it means `runScheduleTick` is reachable
 * only through `run-now` and no agent schedule ever fires on its own.
 *
 * `TEST_WRANGLER_TOML` is bound by `vitest.config.ts` with `readFileSync`
 * (workerd has no filesystem) and is the DEPLOYED file verbatim, never a
 * fixture copy — an assertion about a copy would prove nothing about a deploy.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import handler from "../src/worker.js";

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    // Loud, never a silent skip: an absent binding means the harness wiring was
    // removed, and a skipped assertion would look green.
    throw new Error(
      "control-plane cron gate: TEST_WRANGLER_TOML is not bound; restore it in apps/control-plane/vitest.config.ts",
    );
  }
  return raw;
}

/** The `crons = [...]` entries of the TOP-LEVEL `[triggers]` table. */
function declaredCrons(): string[] {
  // Line-oriented rather than one big regex: TOML tables end at the next
  // top-level header, and a lookahead for "end of input" is exactly the kind of
  // subtlety that makes a config gate quietly match nothing.
  const lines = wranglerToml().split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === "[triggers]");
  if (start < 0) return [];
  const crons: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\s*\[/.test(line)) break; // the next table: [triggers] is over
    const match = /^\s*crons\s*=\s*\[([^\]]*)\]/.exec(line);
    if (match === null) continue;
    for (const entry of (match[1] ?? "").matchAll(/"([^"]+)"/g)) crons.push(entry[1] as string);
  }
  return crons;
}

describe("the deployed Worker's Cron trigger", () => {
  it("declares a [triggers] crons stanza in the COMMITTED wrangler.toml", () => {
    expect(declaredCrons().length).toBeGreaterThan(0);
  });

  it("ticks at the finest granularity Cron Triggers offer", () => {
    // The schedule engine's smallest unit is a minute, so anything coarser
    // silently delays every schedule this Worker owns.
    expect(declaredCrons()).toContain("* * * * *");
  });

  it("declares only well-formed 5-field cron expressions", () => {
    for (const expression of declaredCrons()) {
      expect(expression.trim().split(/\s+/), `malformed cron "${expression}"`).toHaveLength(5);
    }
  });

  it("has a `scheduled` handler for that trigger to invoke", () => {
    // A trigger with no handler is a Cron firing into nothing; a handler with no
    // trigger never fires at all. Both halves, one assertion set.
    expect(typeof handler.scheduled).toBe("function");
    expect(declaredCrons().length).toBeGreaterThan(0);
  });
});
