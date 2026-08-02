/**
 * The `[triggers] crons` stanza — the half of the Cron wiring that lives in
 * `wrangler.toml` and that NO other test could see.
 *
 * ## Why a config assertion, and why here
 *
 * The scheduled path has two independent halves, and both must hold:
 *
 *  1. a `scheduled` handler on the ENTRY module's DEFAULT export
 *     (`src/worker.ts`) — held by `test/metering/*` and by the wave-11 mutation
 *     that deletes the handler and turns the suite red; and
 *  2. a Cron TRIGGER telling Cloudflare to invoke it.
 *
 * `@cloudflare/vitest-pool-workers` boots the Worker but never dispatches a
 * scheduled event of its own, so half (2) is invisible to every behavioural
 * test in this suite. The wave-11 mount-mutation sweep proved that literally:
 * renaming `[triggers]` to `[disabled_triggers]` in the committed
 * `wrangler.toml` left all 1464 tests GREEN. In production that edit means the
 * billing-outbox sweep (`gatewayScheduled` → `MeteringUsageSink.sweep`, the
 * recovery for a charge whose isolate died between the D1 ledger commit and the
 * Queue publish, issue #150) simply never runs, and nothing reports it.
 *
 * So this file reads the committed file itself. `TEST_WRANGLER_TOML` is bound
 * by `vitest.config.ts` with `readFileSync` because workerd has no filesystem —
 * it is the DEPLOYED config verbatim, not a fixture copy, which is the only way
 * an assertion about it means anything.
 */
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import handler from "../src/worker.js";

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    // Loud, never a silent skip: an absent binding means the harness wiring in
    // `vitest.config.ts` was removed, and a skipped assertion would look green.
    throw new Error(
      "gateway cron gate: TEST_WRANGLER_TOML is not bound; restore it in apps/gateway/vitest.config.ts",
    );
  }
  return raw;
}

/**
 * The `crons = [...]` entries of the top-level `[triggers]` table.
 *
 * Deliberately anchored on the TABLE HEADER rather than just grepping for
 * `crons`: the failure this file exists to catch is the whole stanza being
 * dropped or renamed, and a bare `crons = [...]` line sitting under some other
 * table is not a Cron trigger.
 */
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

  it("declares only well-formed 5-field cron expressions", () => {
    for (const expression of declaredCrons()) {
      expect(expression.trim().split(/\s+/), `malformed cron "${expression}"`).toHaveLength(5);
    }
  });

  it("has a `scheduled` handler for that trigger to invoke", () => {
    // Both halves in one assertion set: a trigger with no handler is a Cron
    // firing into nothing, and a handler with no trigger never fires at all.
    expect(typeof handler.scheduled).toBe("function");
    expect(declaredCrons().length).toBeGreaterThan(0);
  });
});
