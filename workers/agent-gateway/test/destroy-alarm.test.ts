// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-27
// description: Worker-side regression for issue #482 — NO ALARM SURVIVES A DESTROY.
//   `POST /control/destroy` on a run carrying a #426 schedule must leave the Durable
//   Object with no pending alarm, so a run marked `cleaned_up` can never wake itself
//   back up and bill compute. Boots the real Worker in workerd via
//   @cloudflare/vitest-pool-workers + miniflare (no Docker, no Cloudflare account,
//   no network).
//
//   WHAT IS BEING HELD, AND WHY THE EXISTING SUITE DOES NOT HOLD IT.
//   `AgentGateway.destroyRun()` ends in `await this.destroy()` — the SDK primitive
//   (agents@0.0.109, dist/chunk-3IQQY2UH.js:879-896) that DROPs the four `cf_agents_*`
//   tables, calls `ctx.storage.deleteAlarm()`, calls `ctx.storage.deleteAll()` and then
//   `ctx.abort("destroyed")`. Its predecessor called `deleteAll()` alone. Every existing
//   destroy assertion in lifecycle.test.ts survives that regression: `deleteAll()` also
//   clears the synced state, so the follow-up status still answers 404 `not_found`, and
//   the in-flight abort comes from `destroyRun`'s own `#inFlight.abort(...)`, not from
//   the SDK. The alarm is the ONLY observable that separates the two, because this
//   deployment's `compatibility_date = "2025-06-01"` predates 2026-02-24, from which
//   workerd's `delete_all_deletes_alarm` behaviour makes `deleteAll()` clear alarms by
//   itself (the flag pair `delete_all_deletes_alarm` / `delete_all_preserves_alarm` is
//   in the bundled workerd, and vitest.config.ts feeds miniflare the compatibility date
//   READ FROM wrangler.toml, so the harness runs under the deployed gate).
//
//   THE MUTATION THIS FILE EXISTS TO RED: replace `await this.destroy()` in
//   `AgentGateway.destroyRun()` (src/index.ts) with `await this.ctx.storage.deleteAll()`.
//   Two independent things then go wrong, and the alarm read below catches either one:
//     1. the alarm armed by `_scheduleNextAlarm()` is still pending, and
//     2. the `cf_agents_schedules` row is still there, so the Agent constructor's
//        `blockConcurrencyWhile(... this.alarm() ...)` RE-ARMS the alarm on the next
//        wake — which is exactly what the destroyed instance gets when anything
//        re-addresses it.
//
//   NON-VACUITY. The alarm is read through the SAME helper, in the SAME test, for a
//   sibling run that was NOT destroyed; that read must be non-null. So "null" cannot be
//   the harness answering null for everything, and it cannot be re-instantiation
//   dropping alarms on its own.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import wranglerToml from "../wrangler.toml?raw";
import type { AgentGateway } from "../src/index";

const TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";

/**
 * The compatibility date from which Cloudflare's `ctx.storage.deleteAll()` deletes the
 * Durable Object's alarm by itself. Before it, an alarm survives `deleteAll()` — which
 * is what made #482 a live bug rather than a documentation nit.
 */
const DELETE_ALL_DELETES_ALARM_FROM = "2026-02-24";

function authedInit(extra?: RequestInit): RequestInit {
  return {
    ...extra,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${TOKEN}`,
      ...(extra?.headers ?? {}),
    },
  };
}

function post(path: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}${path}`, authedInit({ method: "POST", body: JSON.stringify(body) }));
}

function start(runId: string): Promise<Response> {
  return post("/control/start", {
    sessionId: "sess-482",
    runId,
    workerTemplateId: "tmpl-1",
    frameworkAdapter: "native",
    capabilityEnvelopeId: "env-1",
  });
}

/**
 * Arm one far-future schedule on `instance` through the governed #426 route.
 *
 * An hour out on purpose: the property under test is that the alarm is GONE, and an
 * alarm that could fire mid-test would erase itself and fake a pass.
 */
async function scheduleFarFuture(instance: string, taskId: string): Promise<void> {
  const res = await post("/schedule/create", {
    instance,
    task: { taskId, kind: "once", delaySeconds: 3600, data: { probe: "482" } },
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as { ok: boolean; schedule: { time: number | null } };
  expect(body.ok).toBe(true);
  // The persisted row carries a FUTURE execution time (epoch seconds — the SDK's unit).
  // That is the row `_scheduleNextAlarm()` turns into the DO's single alarm; without it
  // there would be no alarm to lose.
  expect(body.schedule.time).toBeGreaterThan(Math.floor(Date.now() / 1000));
}

/**
 * The alarm ACTUALLY pending on `runRef`, read off the platform rather than inferred
 * from anything the Worker reported.
 *
 * `getAgentByName` addresses instances with a plain `idFromName(name)`, so this reads
 * the same Durable Object the routes drove. Entering the object also runs the Agents SDK
 * constructor's `blockConcurrencyWhile` block — including its `this.alarm()` /
 * `_scheduleNextAlarm()` re-arm — before the callback runs, so a surviving schedule row
 * shows up here as a re-armed alarm.
 */
function pendingAlarm(runRef: string): Promise<number | null> {
  const namespace = env.AGENT_GATEWAY as DurableObjectNamespace<AgentGateway>;
  const stub = namespace.get(namespace.idFromName(runRef));
  return runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
}

describe("#482 a destroyed run leaves no pending alarm", () => {
  it("no alarm survives POST /control/destroy, while an untouched sibling keeps its own", async () => {
    const destroyed = "run-destroy-alarm";
    const sibling = "run-keeps-alarm";
    await start(destroyed);
    await start(sibling);
    await scheduleFarFuture(destroyed, "wake-me");
    await scheduleFarFuture(sibling, "wake-me");

    // PRECONDITION: the schedule really armed the platform alarm. Without this the
    // post-destroy `toBeNull()` would hold for a run that never had an alarm at all.
    const before = await pendingAlarm(destroyed);
    expect(before).not.toBeNull();
    expect(before as number).toBeGreaterThan(Date.now());

    const res = await post("/control/destroy", { runRef: destroyed });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ runRef: destroyed, status: "cleaned_up" });

    // Wake the destroyed name the way a caller (or a firing alarm) would: re-addressing
    // re-instantiates the object, and the SDK constructor re-arms the alarm from any
    // schedule row that outlived the teardown.
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${destroyed}`, authedInit());
    expect(after.status).toBe(404);

    // THE ASSERTION: pinned to `await this.destroy()` in AgentGateway.destroyRun().
    // Swap it for `ctx.storage.deleteAll()` and this reds — the alarm is preserved at
    // this deployment's compatibility date, and the schedule row re-arms it besides.
    expect(await pendingAlarm(destroyed)).toBeNull();

    // NON-VACUITY: same helper, same moment, the run that was NOT destroyed.
    const survivor = await pendingAlarm(sibling);
    expect(survivor).not.toBeNull();
    expect(survivor as number).toBeGreaterThan(Date.now());
  });

  it("the destroyed run's schedule rows are gone too, so a later wake can re-arm nothing", async () => {
    // The second half of the property, on the SQL side: `deleteAll()` clears the
    // key-value data, but `cf_agents_schedules` is a SQL table — only the DROPs inside
    // `destroy()` remove it. A surviving row is a scheduled wake-up waiting for the
    // next time anything touches this name.
    const name = "run-destroy-rows";
    await start(name);
    await scheduleFarFuture(name, "wake-me");
    const listed = await post("/schedule/list", { instance: name });
    expect(await listed.json()).toMatchObject({ ok: true, count: 1 });

    const res = await post("/control/destroy", { runRef: name });
    expect(res.status).toBe(200);

    const after = await post("/schedule/list", { instance: name });
    expect(after.status).toBe(200);
    expect(await after.json()).toMatchObject({ ok: true, count: 0 });
  });

  it("the deployment still predates the compatibility date that would clear alarms for us", () => {
    // A tripwire, not a preference. The mutation argument above rests on `deleteAll()`
    // PRESERVING the alarm here. When this reds, someone moved the deployment past
    // 2026-02-24 (or set the flag): `this.destroy()` is still the right call — the table
    // DROPs and `ctx.abort()` are exclusive to it — but the alarm no longer discriminates
    // it from `deleteAll()`, and the assertion above must be re-derived rather than
    // trusted.
    const compatibilityDate = /^compatibility_date\s*=\s*"([^"]+)"/m.exec(wranglerToml)?.[1];
    expect(compatibilityDate).toBeDefined();
    expect(wranglerToml).not.toContain("delete_all_deletes_alarm");
    expect(compatibilityDate! < DELETE_ALL_DELETES_ALARM_FROM).toBe(true);
  });
});
