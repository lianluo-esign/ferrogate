/**
 * ANTI-UNMOUNT for the control plane's DEPLOY ENTRYPOINT — `src/worker.ts`.
 *
 * ## Why this file exists
 *
 * `test/schedule-wiring.test.ts` proves the tick itself: `scheduled` builds its
 * deps from the real bindings and drives a real fire end to end. What it CANNOT
 * prove is that the platform ever calls it, because it imports
 * `src/schedule/scheduled.js` directly. workerd dispatches a scheduled event
 * ONLY to a handler found on the ENTRY module's DEFAULT export — a named
 * `export { scheduled }` there is silently accepted as a service entrypoint and
 * never invoked — so a Worker can carry a `[triggers] crons` stanza, a correct
 * engine, and a fully green suite while no schedule ever fires on its own.
 * That is `docs/rewrite/parity-audit-storage.md` §4.2 one layer further out.
 *
 * So this file asserts against the object `wrangler.toml`'s `main` resolves to,
 * and drives the tick THROUGH it.
 *
 * MUTATION: drop `scheduled` from the handler in `src/worker.ts` (or revert the
 * file to `export { default } from "./index.js"`) and both cases below go red;
 * every other control-plane suite stays green.
 */
import { SELF, env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { SCHEDULE_COLLECTION, SELF_HOSTED_DISPATCH_COLLECTION } from "../src/schedule/engine.js";
import { scheduledDispatchId } from "../src/schedule/model.js";
import worker from "../src/worker.js";
import { applySchema, rawDocument, resetD1 } from "./d1.js";
import { BASE, arm, jsonRequest, operatorKey } from "./harness.js";

const KEY = operatorKey.secret;

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey] });
});

/** The bindings a cron invocation gets, with the D1 store selected. */
function cronEnv(): never {
  return {
    ...(env as unknown as Record<string, unknown>),
    CONTROL_PLANE_STORE: undefined,
  } as never;
}

const CTX = {
  waitUntil: () => {},
  passThroughOnException: () => {},
  props: {},
} as never;

describe("the deploy entrypoint exports what the platform dispatches to", () => {
  it("carries BOTH handlers — `fetch` and `scheduled` — on the default export", () => {
    // Not a shape assertion for its own sake: a missing `scheduled` here is
    // invisible to every other suite in this app and costs the entire
    // scheduler.
    expect(typeof worker.fetch).toBe("function");
    expect(typeof worker.scheduled).toBe("function");
  });

  it("fires a due schedule when the CRON invokes the entrypoint's handler", async () => {
    const created = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(KEY, "POST", { id: "s_entry", spec_kind: "interval", interval_secs: 60 }),
    );
    expect(created.status).toBe(201);
    const slot = (await rawDocument(SCHEDULE_COLLECTION, "s_entry"))?.next_fire_at_unix as number;

    // THE MOUNT GATE — dispatched exactly the way workerd dispatches a Cron
    // Trigger: through the default export, not through the module that
    // defines the tick.
    await worker.scheduled?.(
      { scheduledTime: slot * 1000, cron: "* * * * *", noRetry: () => {} },
      cronEnv(),
      CTX,
    );

    expect(
      await rawDocument(SELF_HOSTED_DISPATCH_COLLECTION, scheduledDispatchId("s_entry", slot)),
    ).not.toBeNull();
  });
});
