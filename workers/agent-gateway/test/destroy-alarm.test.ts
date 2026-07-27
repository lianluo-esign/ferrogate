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
//   WHAT IS BEING HELD. `AgentGateway.destroyRun()` ends in `await this.destroy()` —
//   the SDK primitive (agents@0.0.109, dist/chunk-3IQQY2UH.js:879-896) that DROPs the
//   four `cf_agents_*` tables, calls `ctx.storage.deleteAlarm()`, calls
//   `ctx.storage.deleteAll()` and then `ctx.abort("destroyed")`. Its predecessor — the
//   code #482 was filed against — called `deleteAll()` alone.
//
//   THE MUTATION THIS FILE EXISTS TO RED: replace `await this.destroy()` in
//   `AgentGateway.destroyRun()` (src/index.ts) with `await this.ctx.storage.deleteAll()`.
//   Ran, not reasoned about (#559 made this Worker's suite terminate; before that no one
//   could run it): `vitest run` over the whole Worker then reports
//   `3 failed | 106 passed`. Two are the tests below. The third is
//   lifecycle.test.ts's "destroy tears the instance down: a following status reports
//   not_found" — so the older claim here, that every existing destroy assertion SURVIVES
//   this regression, was also wrong.
//
//   WHAT THE MUTATION ACTUALLY CHANGES, MEASURED. Three observables move, not one — an
//   earlier version of this header claimed the alarm was the only one, and that is false:
//     * `GET /control/status` answers 200 `{"status":"cleaned_up"}` instead of 404
//       `not_found`;
//     * `POST /schedule/list` answers 400
//       `{"error":"schedule_error","message":"no such table: cf_agents_schedules: SQLITE_ERROR"}`
//       instead of 200 `count: 0`;
//     * the alarm `_scheduleNextAlarm()` armed is STILL PENDING instead of null.
//   The first two are consequences of the same missing thing: without `ctx.abort()` the
//   Durable Object is never evicted, so `this.state` stays live in memory (status answers
//   from it) and the tables `deleteAll()` dropped are never rebuilt (nothing re-runs the
//   constructor's `CREATE TABLE IF NOT EXISTS`). They say the object did not go away.
//   Only the third says the *platform* is still holding a timer against a name marked
//   `cleaned_up`, which is the harm #482 names: the alarm fires, re-instantiates the
//   object and bills compute.
//
//   AND IT IS DURABLE, WHICH IS WHY IT IS THE ONE WORTH PINNING. The stranded alarm is
//   not a stale in-memory value that a real eviction would clear. Mutation M2b below
//   proves it with an eviction the platform performs itself: `deleteAll()`, one macrotask,
//   then `ctx.abort("destroyed")`. Under it the object provably goes away —
//   lifecycle.test.ts's post-destroy status is 404 and the second test below lists
//   `count: 0`, answers only a REBUILT instance can give — and the alarm STILL reads as
//   an epoch-millis timestamp (`expected 1785171499000 to be null`). So `deleteAll()`
//   genuinely leaves the alarm on the platform here, which also confirms the compatibility
//   premise by experiment rather than by documentation.
//   (Deployment `compatibility_date = "2025-06-01"` predates
//   2026-02-24, from which workerd's `delete_all_deletes_alarm` behaviour would clear it;
//   vitest.config.ts feeds miniflare the date READ FROM wrangler.toml, so the harness runs
//   under the deployed gate. The last test below is the tripwire on that.)
//
//   WHAT THIS FILE DOES *NOT* CATCH, and WHY — four mutations, all run over the whole
//   Worker, `npx vitest run` in workers/agent-gateway:
//     M1  `this.destroy()` -> `deleteAll()`                      3 failed | 106 passed
//     M2  `deleteAll()` + same-turn `ctx.abort()`                109 passed
//     M2b `deleteAll()` + `setTimeout(…, 0)` + `ctx.abort()`     1 failed | 108 passed
//     M3  `deleteAlarm()` + `deleteAll()` + `setTimeout` + abort 109 passed
//   M2 is green for a COMMIT-TIMING reason, not because the alarm was cleaned up. At this
//   compatibility date the alarm's survival of `deleteAll()` only becomes visible to a
//   later read once the I/O turn commits; `ctx.abort()` in that same turn breaks the
//   output gate — workerd prints `api/actor-state.c++:1178: broken.outputGateBroken;
//   jsg.Error: destroyed` on every destroy in this suite — and the survival never lands,
//   so the alarm reads `null` for the wrong reason. That last sentence is INFERRED from
//   M2/M2b, not read off workerd's source, which is not vendored here; what is measured is
//   the flip. M2b is the control: the ONLY difference from M2 is one
//   macrotask before the abort, and it flips the alarm back to a timestamp (a microtask,
//   `await Promise.resolve()`, does not — so the boundary is the storage commit, not the
//   microtask queue). M3 then shows what `deleteAlarm()` actually buys: with it in front
//   of the same sequence the alarm is gone regardless of when the abort lands.
//   CONSEQUENCE FOR THIS FILE'S SCOPE: the assertion below pins `destroy()` against the
//   historical `deleteAll()` (M1), and against a `deleteAll()`-plus-eviction teardown
//   whose abort is not same-turn (M2b, where it is the only red in 109). It does NOT
//   separate `deleteAlarm()` from a same-turn `ctx.abort()` (M2), and nobody should read
//   it as doing so — nor should anyone read M2's green as licence to reimplement teardown
//   that way; see `docs/cloudflare-agent-gateway.md` §3a.
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
 * the same Durable Object the routes drove.
 *
 * On a COLD name, entering the object first runs the Agents SDK constructor's
 * `blockConcurrencyWhile(... this.alarm() ...)`, so the read happens after the SDK's last
 * chance to tidy up — and the SDK never takes it (`_scheduleNextAlarm()` can only
 * `setAlarm()`). But do not lean on that here: under the M1 mutation the object was never
 * aborted, so it is still RESIDENT and no constructor runs at all. What rules out a harness
 * timing artefact in that case is M2b in the header — the same `deleteAll()` followed by a
 * real eviction still reads the timestamp back — plus the sibling read below, which shows
 * this helper does not simply answer null (or non-null) for everything.
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

    // Address the destroyed name the way a caller (or a firing alarm) would. On unmutated
    // code the destroy aborted the object, so this re-instantiates it and runs the SDK
    // constructor's alarm path — the last opportunity anything has to notice a stale alarm
    // and delete it, which is what makes the assertion below about the platform rather than
    // about when the test happened to look. (Under the M1 mutation there is no abort, so
    // this hits the still-resident object instead; the header's M2b run is what covers that
    // case.) Its status is asserted a few lines down, AFTER the guard, on purpose: both red
    // under the mutation, and the one that should name the failure is the alarm.
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${destroyed}`, authedInit());

    // THE ASSERTION: pinned to `await this.destroy()` in AgentGateway.destroyRun().
    // Swap it for `ctx.storage.deleteAll()` and this line reds with `AssertionError:
    // expected 1785172324000 to be null` — sample digits from the 2026-07-27 run; the value
    // is `now + delaySeconds: 3600` in millis and differs every run — at this compatibility
    // date `deleteAll()` preserves the alarm and nothing afterwards deletes it. The header's
    // M2b run shows the timestamp also survives a real eviction, so this is not a stale read.
    expect(await pendingAlarm(destroyed)).toBeNull();

    // A SECOND DISCRIMINATOR, not a formality: under the mutation this answers 200
    // `cleaned_up`, because an un-aborted object keeps serving status out of the
    // in-memory `this.state` that `deleteAll()` could not reach.
    expect(after.status).toBe(404);

    // NON-VACUITY: same helper, same moment, the run that was NOT destroyed.
    const survivor = await pendingAlarm(sibling);
    expect(survivor).not.toBeNull();
    expect(survivor as number).toBeGreaterThan(Date.now());
  });

  it("the destroyed run reports no schedules afterwards (post-condition; under the deleteAll mutation it reds on a 400, never on the count)", async () => {
    // READ THE TITLE LITERALLY, and note that it is the SECOND correction to it. This is
    // a true post-condition of destroy, worth holding, and NOT a guard on the alarm.
    //
    // It does red under the mutation (`this.destroy()` -> `this.ctx.storage.deleteAll()`),
    // but the assertion that goes red is `expect(after.status).toBe(200)`, because
    // `/schedule/list` answers 400 `no such table: cf_agents_schedules`. `count` is never
    // reached and never wrong. The earlier comment here predicted the opposite — a green
    // 200 with `count: 0`, from the Agent constructor rebuilding an empty table "on the
    // next wake". Measured, no wake happens in between: without `ctx.abort()` nothing
    // forces an eviction, the same instance is still resident two requests later, so the
    // tables `deleteAll()` dropped stay dropped, the RPC comes back as a `schedule_error`
    // and `scheduleResponse` maps it to 400. That residency is an OBSERVATION about two
    // back-to-back requests in one test, not a platform guarantee — hibernation between
    // them would flip the mutated outcome back to a green 200 `count: 0`, exactly the
    // prediction the measurement replaced. (The header's M2b run is that case made
    // deliberate: force the eviction and this test goes green while the alarm assertion
    // stays red.) Treat this test's red as a symptom of a missing eviction, not as
    // evidence about schedules.
    //
    // WHAT IT IS ACTUALLY FOR: a `destroyRun` that stops tearing storage down at all —
    // drop the teardown call, or let it return the `cleaned_up` envelope without reaching
    // it, and the row is still listed (`count: 1`). It also holds the create -> list ->
    // destroy -> list route pair itself, which is why it is worth its runtime.
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
