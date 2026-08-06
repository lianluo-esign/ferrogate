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
import { tenantScheduleAlarmMessage } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { SELF_HOSTED_DISPATCH_COLLECTION } from "../src/schedule/engine.js";
import { scheduledDispatchId } from "../src/schedule/model.js";
import worker from "../src/worker.js";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";
import { rawTenantDocument, registerObjectTenants } from "./tenant-object.js";

const KEY = operatorKey.secret;
const TENANT_KEY = "entry-tenant";

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  arm({ store: "d1", staticKeys: [operatorKey], nativeKeys: [tenantKey(TENANT_KEY, "tenant_entry")] });
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
  it("carries ALL handlers — `fetch`, `scheduled` and `queue` — on the default export", () => {
    // Not a shape assertion for its own sake: a missing `scheduled` here is
    // invisible to every other suite in this app and costs every maintenance
    // pass; a missing `queue` costs the entire scheduler, because the tenant
    // alarm wake-ups are dispatched to the ENTRY module's default export only.
    expect(typeof worker.fetch).toBe("function");
    expect(typeof worker.scheduled).toBe("function");
    expect(typeof worker.queue).toBe("function");
  });

  it("fires a due schedule when the QUEUE invokes the entrypoint's handler", async () => {
    // Schedule execution rides the tenant-object alarm queue now, not the
    // Cron: the object's native alarm publishes a tenant wake-up, and workerd
    // dispatches the batch to the ENTRY module's default export `queue`.
    await registerObjectTenants(["tenant_entry"]);
    const created = await SELF.fetch(
      `${BASE}/admin/v1/agent-schedules`,
      jsonRequest(TENANT_KEY, "POST", { id: "s_entry", spec_kind: "interval", interval_secs: 60 }),
    );
    expect(created.status).toBe(201);
    const stored = await SELF.fetch(`${BASE}/admin/v1/agent-schedules/s_entry`, {
      headers: bearer(TENANT_KEY),
    });
    expect(stored.status).toBe(200);
    const slot = ((await stored.json()) as { agent_schedule: { next_fire_at_unix: number } })
      .agent_schedule.next_fire_at_unix;
    expect(typeof slot).toBe("number");

    // THE MOUNT GATE — dispatched exactly the way workerd dispatches a queue
    // batch: through the default export, not through the module that defines
    // the consumer.
    await worker.queue?.(
      {
        messages: [
          { body: tenantScheduleAlarmMessage("tenant_entry", slot), ack: () => {}, retry: () => {} },
        ],
      } as never,
      cronEnv(),
      CTX,
    );

    expect(
      await rawTenantDocument(
        "tenant_entry",
        SELF_HOSTED_DISPATCH_COLLECTION,
        scheduledDispatchId("s_entry", slot),
      ),
    ).not.toBeNull();
  });
});
