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
//   EXACTLY ONE observable then goes wrong, and it is the one the first test reads: the
//   alarm `_scheduleNextAlarm()` armed is still pending, and nothing later clears it —
//   `_scheduleNextAlarm()` (dist/chunk-3IQQY2UH.js:863-875) only ever calls `setAlarm()`,
//   so with zero schedule rows it returns without calling `deleteAlarm()`. The stale alarm
//   fires on a name marked `cleaned_up`, re-instantiates the Durable Object and bills
//   compute.
//
//   WHAT IS *NOT* A SECOND DISCRIMINATOR — and was wrongly written here when this file
//   first landed: a SURVIVING `cf_agents_schedules` ROW. `AgentGateway` is SQLite-backed
//   (`wrangler.toml` `new_sqlite_classes`; `vitest.config.ts` `useSQLite: true`), and on a
//   SQLite-backed Durable Object `deleteAll()` removes the entire contents of the object's
//   private SQLite database — SQL data AND key-value data, atomically. The mutation
//   therefore wipes the schedule rows too, and the Agent constructor's
//   `CREATE TABLE IF NOT EXISTS cf_agents_schedules` (chunk-3IQQY2UH.js:158-168) rebuilds
//   the table empty on the next wake. Nothing re-arms. The table DROPs inside `destroy()`
//   are redundant with its own `deleteAll()` here; the `deleteAlarm()` and the
//   `ctx.abort()` are what the mutation actually loses.
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
 * constructor's `blockConcurrencyWhile(... this.alarm() ...)` block before the callback
 * runs — i.e. this read happens AFTER the SDK's last chance to tidy up. That is the point:
 * the SDK never takes it (`_scheduleNextAlarm()` can only `setAlarm()`), so a non-null read
 * after a destroy is a genuinely stranded alarm and not a timing artefact of the harness.
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
    // re-instantiates the object and runs the SDK constructor's alarm path. That is the
    // last opportunity anything has to notice a stale alarm and delete it, so reading
    // AFTER it is what makes the assertion below about the platform rather than about
    // when the test happened to look.
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${destroyed}`, authedInit());
    expect(after.status).toBe(404);

    // THE ASSERTION: pinned to `await this.destroy()` in AgentGateway.destroyRun().
    // Swap it for `ctx.storage.deleteAll()` and this reds — at this deployment's
    // compatibility date `deleteAll()` preserves the alarm, and nothing afterwards
    // deletes it.
    expect(await pendingAlarm(destroyed)).toBeNull();

    // NON-VACUITY: same helper, same moment, the run that was NOT destroyed.
    const survivor = await pendingAlarm(sibling);
    expect(survivor).not.toBeNull();
    expect(survivor as number).toBeGreaterThan(Date.now());
  });

  it("the destroyed run reports no schedules afterwards (post-condition; it does NOT catch the deleteAll mutation)", async () => {
    // READ THE TITLE LITERALLY. This is a true post-condition of destroy and worth
    // holding, but it is NOT a second guard on `await this.destroy()`, and an earlier
    // version of this comment claimed it was. Under the mutation
    // (`this.destroy()` -> `this.ctx.storage.deleteAll()`) `deleteAll()` wipes the SQL
    // data too, the Agent constructor's `CREATE TABLE IF NOT EXISTS` rebuilds an empty
    // `cf_agents_schedules`, and `/schedule/list` still answers `count: 0` — this test
    // GREENS on the broken implementation. The alarm read in the first test is the only
    // thing separating the two.
    //
    // WHAT IT DOES CATCH: a `destroyRun` that stops tearing storage down at all — drop
    // the teardown call, or let it return the `cleaned_up` envelope without reaching it,
    // and the row is still listed (`count: 1`). It also holds the create -> list -> destroy
    // -> list route pair itself, which is why it is worth its runtime.
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
    // 2026-02-24 (or set the flag): `this.destroy()` is still the right call, because
    // `ctx.abort("destroyed")` remains exclusive to it and is what stops in-flight work
    // and WebSockets — but the alarm stops discriminating the two, so THIS FILE loses its
    // pinned assertion and needs a new one rather than a re-read of the old one.
    const compatibilityDate = /^compatibility_date\s*=\s*"([^"]+)"/m.exec(wranglerToml)?.[1];
    expect(compatibilityDate).toBeDefined();
    expect(wranglerToml).not.toContain("delete_all_deletes_alarm");
    expect(compatibilityDate! < DELETE_ALL_DELETES_ALARM_FROM).toBe(true);
  });
});
