// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Worker-side E2E for the #414 agent LIFECYCLE semantics — cancellation
//   that actually stops work, `this.destroy()` as the destroy primitive, the
//   unknown-runRef guard, the start state-machine guards, and the placement dials.
//   Boots the real Worker in workerd via @cloudflare/vitest-pool-workers + miniflare
//   (no Docker, no Cloudflare account, no network).
//
//   THE BAR THESE TESTS HOLD. Before #414's rework, `POST /control/cancel` set
//   `status:"stopped"` and returned — it cancelled nothing, while six places (the
//   Worker, the README, the Rust mapping table, two design notes) claimed it drove
//   Cloudflare's fiber-cancel primitive, and #428's over-budget kill switch routed a
//   money decision through it. So "the status field changed" is NOT what is asserted
//   here: the cancellation tests assert that the workload's POST-AWAIT SIDE EFFECT
//   never happened.
//
//   The pinned SDK (agents@0.0.109) ships NO fiber API — `grep -ri fiber
//   node_modules/agents/` finds nothing — so cancellation is COOPERATIVE: an
//   AbortSignal the workload observes, plus a durable latch that refuses later work.
//   These tests pin exactly that, and nothing stronger.

/// <reference types="@cloudflare/vitest-pool-workers" />
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

import wranglerToml from "../wrangler.toml?raw";
import { addressingCalls, observedAborts, sideEffects } from "./harness/worker";

const TOKEN = "test-control-secret";
const BASE = "https://agent-gateway.test";

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

function start(runId: string, extra?: Record<string, unknown>): Promise<Response> {
  return post("/control/start", {
    sessionId: "sess-1",
    runId,
    workerTemplateId: "tmpl-1",
    frameworkAdapter: "native",
    capabilityEnvelopeId: "env-1",
    ...extra,
  });
}

describe("#414 cancel actually stops in-flight work", () => {
  it("a cancelled run never reaches its workload's post-await side effect", async () => {
    const name = "run-cancel-aborts";
    await start(name);

    // A workload with a real window: it awaits 5s and only THEN records that it
    // ran. Nothing about the status field can fake this.
    const inFlight = post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["5000"],
    });
    // Let the invoke reach its await before cancelling.
    await scheduler.wait(50);

    const cancel = await post("/control/cancel", { runRef: name, reason: "over-budget" });
    expect(cancel.status).toBe(200);
    // `aborted: true` is the honest part of the envelope: in-flight work on this
    // instance was signalled, not merely flagged. The status is still `running`:
    // signalling is not stopping, and only the workload can say which happened —
    // see the defiant-workload test below for why that distinction is the point.
    expect(await cancel.json()).toMatchObject({ runRef: name, status: "running", aborted: true });

    // The invoke unwound EARLY (it did not wait out its 5s) and reports stopped.
    // `invoke`'s abort branch is the ONLY writer of `stopped`.
    const invoked = (await (await inFlight).json()) as { status: string; exitCode: number | null };
    expect(invoked.status).toBe("stopped");
    expect(invoked.exitCode).toBeNull();

    // THE ASSERTION THAT MATTERS: the work never happened.
    expect(sideEffects(name)).not.toContain("probe:sleep");
    // ...and it did not happen because the workload SAW the cancel.
    expect(observedAborts(name)).toContain("Error: ferrogate cancel: over-budget");

    // Only now that the workload has unwound does the run read as stopped.
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await after.json()).toMatchObject({ status: "stopped", cancelRequested: true });
  });

  it("a cancel the workload IGNORES is NOT reported as stopped (the kill must escalate)", async () => {
    // THE BLOCKER THIS FILE EXISTS FOR, second occurrence. `cancel` wrote
    // `status:"stopped"` unconditionally, and the Rust `kill_is_settled` treats
    // `Stopped` as terminal — so for #428's over-budget kill the sequence was
    // always cancel -> "stopped", run_status -> "stopped", escalation skipped.
    // A runaway agent was reported killed and kept spending. The status a
    // defiant workload leaves behind is the whole discriminator, so it is what
    // is asserted here.
    const name = "run-cancel-defiant";
    await start(name);

    const inFlight = post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:defiant",
      args: ["1000"],
    });
    await scheduler.wait(50);

    const cancel = await post("/control/cancel", { runRef: name, reason: "over-budget" });
    expect(cancel.status).toBe(200);
    expect(await cancel.json()).toMatchObject({ runRef: name, status: "running", aborted: true });

    // This is the read the Rust `KillMode::Cancel` makes next. It must NOT say
    // settled, because the run demonstrably is not.
    const status = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await status.json()).toMatchObject({
      runRef: name,
      status: "running",
      cancelRequested: true,
    });

    // Proof the workload really was defiant rather than merely slow: it reached
    // its post-await side effect despite having been signalled.
    const invoked = (await (await inFlight).json()) as { status: string };
    expect(invoked.status).toBe("completed");
    expect(sideEffects(name)).toContain("probe:defiant");
  });

  it("an UNcancelled run of the same workload DOES reach its side effect", async () => {
    // The control for the test above: without a cancel the identical workload
    // completes and records itself. Without this, "no side effect" could just
    // mean the probe never runs.
    const name = "run-cancel-control";
    await start(name);
    const done = await post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["1"],
    });
    expect(await done.json()).toMatchObject({ status: "completed", exitCode: 0 });

    expect(sideEffects(name)).toContain("probe:sleep");
  });

  it("the cancel latch is DURABLE: a later invoke on a cancelled run is REFUSED, not answered", async () => {
    // The in-memory AbortController dies with hibernation/eviction, so the latch
    // that stops the run from starting NEW work has to be persistent state.
    //
    // And the refusal is a refusal: it used to come back as HTTP 200 with an
    // `InvokeResult`, so the Rust `exec_or_attach` recorded lifecycle evidence
    // saying `outcome:"executed"` for work that never ran — only the free-text
    // message said otherwise.
    const name = "run-cancel-latch";
    await start(name);
    await post("/control/cancel", { runRef: name, reason: "operator" });

    const res = await post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["1"],
    });
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string; runRef: string; detail: string };
    expect(body.error).toBe("run_cancelled");
    expect(body.runRef).toBe(name);
    expect(body.detail).toContain("cancelled (operator)");
    expect(body).not.toHaveProperty("exitCode");

    // ...and the refused invoke did no work either.
    expect(sideEffects(name)).not.toContain("probe:sleep");
  });

  it("a second CONCURRENT invoke is refused rather than silently dropping the abort handle", async () => {
    // `this.#inFlight = controller` used to overwrite the previous handle, and DO
    // RPC calls interleave at every await — so a second invoke arriving during the
    // first one's await left the FIRST workload un-cancellable: a later cancel
    // signalled only the second, and the first ran to completion.
    const name = "run-invoke-concurrent";
    await start(name);

    const first = post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["2000"],
    });
    await scheduler.wait(50);

    const second = await post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["1"],
    });
    expect(second.status).toBe(409);
    expect(await second.json()).toMatchObject({ error: "invoke_in_flight", runRef: name });

    // The FIRST workload still owns the handle, so the cancel reaches it.
    const cancel = await post("/control/cancel", { runRef: name, reason: "over-budget" });
    expect(await cancel.json()).toMatchObject({ aborted: true });
    const invoked = (await (await first).json()) as { status: string };
    expect(invoked.status).toBe("stopped");
    expect(sideEffects(name)).not.toContain("probe:sleep");
  });

  it("status reports the cancel latch so an operator can tell cancelled from finished", async () => {
    const name = "run-cancel-visible";
    await start(name);
    await post("/control/cancel", { runRef: name, reason: "budget" });
    const res = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await res.json()).toMatchObject({
      runRef: name,
      status: "stopped",
      cancelRequested: true,
      message: "cancelled: budget",
    });
  });

  it("cancel does NOT flip an already-terminal run, and reports aborted:false", async () => {
    // Item 5: cancel() used to rewrite a `completed` run to `stopped`.
    const name = "run-cancel-terminal";
    await start(name);
    await post("/control/invoke", { runRef: name, workloadRef: "w", args: [] });

    const res = await post("/control/cancel", { runRef: name, reason: "too late" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      runRef: name,
      status: "completed",
      aborted: false,
    });
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await after.json()).toMatchObject({ status: "completed", cancelRequested: false });
  });

  it("cancel with nothing in flight reports aborted:false (it only set the latch)", async () => {
    const name = "run-cancel-idle";
    await start(name);
    const res = await post("/control/cancel", { runRef: name, reason: "operator" });
    expect(await res.json()).toMatchObject({ status: "stopped", aborted: false });
  });
});

describe("#414 destroy calls the SDK destroy() primitive", () => {
  it("destroy tears the instance down: a following status reports not_found", async () => {
    // `this.destroy()` DROPs the agent tables, deletes the alarm and clears
    // storage (its predecessor called ctx.storage.deleteAll(), which leaves the
    // alarm armed — #482). Observable proof: the instance has no run afterwards.
    const name = "run-destroy-1";
    await start(name);
    const destroyed = await post("/control/destroy", { runRef: name });
    expect(destroyed.status).toBe(200);
    expect(await destroyed.json()).toMatchObject({ runRef: name, status: "cleaned_up" });

    const after = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(after.status).toBe(404);
    expect(await after.json()).toMatchObject({ error: "not_found" });
  });

  it("destroy SIGNALS in-flight work before tearing the object down", async () => {
    // What this pins, and why it is not "the work stopped": `destroy()` ends in
    // `ctx.abort("destroyed")`, which stops everything on the instance whatever
    // `destroyRun` did — so a side-effect-absent or a resolved-promptly assertion
    // survives deleting the explicit abort. The discriminator is that the
    // workload OBSERVED an abort, with destroy's own reason, BEFORE the teardown.
    // Deleting `this.#inFlight?.abort(...)` from `destroyRun` empties that ledger.
    const name = "run-destroy-inflight";
    await start(name);
    const inFlight = post("/control/invoke", {
      runRef: name,
      workloadRef: "probe:sleep",
      args: ["5000"],
    });
    await scheduler.wait(50);
    const destroyed = await post("/control/destroy", { runRef: name });
    expect(await destroyed.json()).toMatchObject({ status: "cleaned_up" });
    await inFlight.catch(() => undefined);

    expect(observedAborts(name)).toContain("Error: ferrogate destroy");
    // And it unwound at the signal instead of sleeping out its 5s: the ledger is
    // in module scope, so it survives the aborted object and this is a real read.
    expect(sideEffects(name)).not.toContain("probe:sleep");
  });
});

describe("#414 unknown runRef is refused, not silently created", () => {
  // Before this guard, POST /control/destroy {"runRef":"typo"} returned 200
  // `cleaned_up` and FerroGate recorded lifecycle evidence for a run that never
  // existed — and a token holder could mint unbounded Durable Objects that way.
  const unknown = "run-never-started-xyz";

  it("destroy on an unknown runRef returns 404 not_found", async () => {
    const res = await post("/control/destroy", { runRef: unknown });
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found", runRef: unknown });
  });

  it("cancel on an unknown runRef returns 404 not_found", async () => {
    const res = await post("/control/cancel", { runRef: unknown, reason: "x" });
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found", runRef: unknown });
  });

  it("status on an unknown runRef returns 404 not_found", async () => {
    const res = await SELF.fetch(`${BASE}/control/status?runRef=${unknown}`, authedInit());
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found", runRef: unknown });
  });

  it("invoke on an unknown runRef returns 404 not_found", async () => {
    const res = await post("/control/invoke", { runRef: unknown, workloadRef: "w", args: [] });
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ error: "not_found", runRef: unknown });
  });
});

describe("#414 start state machine", () => {
  it("a second start with a DIFFERENT identity is refused with 409, state unchanged", async () => {
    // Item 5: start() used to re-point sessionId/runId/capabilityEnvelopeId on a
    // live instance, detaching the control plane's evidence from the workload.
    const name = "run-start-rebind";
    await start(name, { props: { model: "model-first" } });
    const res = await post("/control/start", {
      sessionId: "sess-OTHER",
      runId: name,
      workerTemplateId: "tmpl-1",
      frameworkAdapter: "native",
      capabilityEnvelopeId: "env-1",
      props: { model: "model-second" },
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "run_conflict", runRef: name });

    const after = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await after.json()).toMatchObject({ resolvedModel: "model-first" });
  });

  it("an IDENTICAL re-start is idempotent (a safe transport retry)", async () => {
    const name = "run-start-idempotent";
    await start(name, { props: { model: "model-first" } });
    const again = await start(name, { props: { model: "model-second" } });
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ runRef: name, status: "running" });
    // Props are NOT re-resolved by a retry: the run keeps its bound configuration.
    const after = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await after.json()).toMatchObject({ resolvedModel: "model-first" });
  });

  it("a start against a terminal run is refused with 409", async () => {
    const name = "run-start-terminal";
    await start(name);
    await post("/control/invoke", { runRef: name, workloadRef: "w", args: [] });
    const res = await start(name);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "run_conflict" });
  });

  it("a start against a cancelled run is refused with 409", async () => {
    const name = "run-start-cancelled";
    await start(name);
    await post("/control/cancel", { runRef: name, reason: "operator" });
    const res = await start(name);
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "run_conflict" });
  });
});

describe("#414 placement dials are honored or refused, never silently inert", () => {
  it("locationHint is PASSED to the addressing call, not merely echoed back", async () => {
    // `resolvedLocationHint` is copied out of `props` by `start()` on a path that
    // never touches `getAgentByName`, so asserting on it alone pinned nothing:
    // deleting the `{ locationHint }` options argument left this test green and
    // the run reporting a placement it had not requested. The options object the
    // Worker actually passes is recorded by the harness's addressing seam, which
    // is the only place the real argument is visible.
    const name = "run-placement-hint";
    const res = await start(name, { props: { model: "m", locationHint: "weur" } });
    expect(res.status).toBe(200);

    const addressed = addressingCalls.filter((call) => call.name === name);
    expect(addressed.length).toBeGreaterThan(0);
    expect(addressed[0].options).toEqual({ locationHint: "weur" });

    const status = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await status.json()).toMatchObject({ resolvedLocationHint: "weur" });
  });

  it("a start without a locationHint passes no hint (the recorder is not just always right)", async () => {
    // The negative control for the assertion above: a recorder that reported
    // `{ locationHint: "weur" }` for every call would satisfy it too.
    const name = "run-placement-none";
    expect((await start(name)).status).toBe(200);
    const addressed = addressingCalls.filter((call) => call.name === name);
    expect(addressed.length).toBeGreaterThan(0);
    expect(addressed[0].options).toEqual({ locationHint: undefined });
  });

  it("an unknown locationHint is REFUSED (422), not dropped", async () => {
    const res = await start("run-placement-bad", { props: { locationHint: "atlantis" } });
    expect(res.status).toBe(422);
    expect(await res.json()).toMatchObject({ error: "unsupported_location_hint" });
    // No instance was bound.
    const status = await SELF.fetch(`${BASE}/control/status?runRef=run-placement-bad`, authedInit());
    expect(status.status).toBe(404);
  });

  it("jurisdiction is REFUSED (422) rather than recorded and reported as honored", async () => {
    // A jurisdiction changes the Durable Object's IDENTITY
    // (namespace.jurisdiction(j).idFromName(name)), so a run started with one
    // would be invisible to every caller that addresses it without one —
    // including #428's over-budget kill switch. Accepting and echoing it is the
    // "compliance dial that does nothing" failure mode.
    const res = await start("run-placement-eu", { props: { jurisdiction: "eu" } });
    expect(res.status).toBe(422);
    expect(await res.json()).toMatchObject({ error: "jurisdiction_unsupported" });
    const status = await SELF.fetch(`${BASE}/control/status?runRef=run-placement-eu`, authedInit());
    expect(status.status).toBe(404);
  });

  it("routingRetry is recorded and REPORTED as recorded-only", async () => {
    const name = "run-placement-retry";
    await start(name, { props: { routingRetry: 3 } });
    const status = await SELF.fetch(`${BASE}/control/status?runRef=${name}`, authedInit());
    expect(await status.json()).toMatchObject({ recordedRoutingRetry: 3 });
  });
});

describe("#414 the deployment binds the PRODUCTION agent class", () => {
  it("wrangler.toml binds AgentGateway, not the test probe subclass", () => {
    // The suite runs against `ProbeAgentGateway` (see vitest.config.ts) so a
    // cancellable workload exists at all. This asserts the probe never reaches
    // production: what deploys is the class in src/index.ts.
    expect(wranglerToml).toContain('class_name = "AgentGateway"');
    expect(wranglerToml).not.toContain("ProbeAgentGateway");
  });
});
