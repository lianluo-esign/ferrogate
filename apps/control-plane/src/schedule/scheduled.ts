/**
 * The `scheduled` seam for the agent-schedule tick.
 *
 * ## Read this before believing the scheduler runs
 *
 * Everything under `src/schedule/` is reachable from the HTTP surface — create,
 * replace, merge, delete and `run-now` all go through it, and
 * `test/schedule-wiring.test.ts` proves each of those mounts by removal. The
 * TICK is the exception: on Cloudflare a periodic tick is a Cron Trigger, which
 * means a `scheduled` handler on the module `wrangler.toml`'s `main` points at
 * (`src/worker.ts`) plus a `[triggers] crons` stanza. **This slice may not edit
 * either file** (the integrate step owns every composition root), so the two
 * lines below are stated exactly and left for it:
 *
 * ```ts
 * // apps/control-plane/src/worker.ts
 * export { default } from "./index.js";
 * export { scheduled } from "./schedule/scheduled.js";   // <- ADD
 * ```
 *
 * ```toml
 * # apps/control-plane/wrangler.toml
 * [triggers]
 * crons = ["* * * * *"]                                  # <- ADD
 * ```
 *
 * (A Worker's `scheduled` handler and its `fetch` handler may be separate named
 * exports of the entry module; `export default withAliasCanonicalization(app)`
 * stays exactly as it is. `* * * * *` is the finest granularity Cron Triggers
 * offer, which is also the finest granularity a 5-field cron expression can
 * ask for, so nothing is lost — a sub-minute schedule would need a Durable
 * Object alarm instead.)
 *
 * **Until those two lines land, schedules do not fire on their own.** That is
 * stated plainly rather than hidden behind a green suite, because a scheduler
 * whose tick is never invoked is exactly the defect
 * `docs/rewrite/parity-audit-storage.md` §4.2 recorded, one layer further out.
 * `test/schedule-wiring.test.ts` drives {@link scheduled} directly against the
 * real bindings, so the handler itself is proven; what is unproven is only that
 * the platform calls it.
 */

import { resolveDeps } from "../adapters.js";
import type { ControlPlaneBindings } from "../ports.js";
import { type ScheduleTickSummary, runScheduleTick } from "./engine.js";

/** What `scheduled` reports back, so a tail log says something useful. */
export interface ScheduledTickReport extends ScheduleTickSummary {
  readonly at: number;
}

/**
 * One tick of the agent-schedule engine, built from the Worker's bindings.
 *
 * Deps come from `resolveDeps` — the SAME composition root every request uses —
 * rather than from a second, tick-only construction. That is deliberate: a
 * scheduler holding its own store would be able to fire schedules the request
 * path cannot see, and the tenancy lifecycle gate it enforces would be a
 * different gate from the one the admin surface enforces.
 *
 * Errors are swallowed into the report rather than thrown. A `scheduled`
 * handler that throws is retried by the platform, and retrying a tick whose
 * failure is a bad schedule definition would re-run every OTHER due schedule in
 * the batch with it — the fire ledger makes that harmless but not free.
 */
export async function runScheduledTick(
  env: ControlPlaneBindings,
  now: number = Math.floor(Date.now() / 1000),
): Promise<ScheduledTickReport> {
  const deps = resolveDeps(env, { requestId: `cron-${now}` });
  const summary = await runScheduleTick(
    { store: deps.store, lifecycle: deps.lifecycle, nodeId: "control-plane-cron" },
    now,
  );
  return { at: now, ...summary };
}

/**
 * The `ExportedHandler["scheduled"]` shape workerd expects.
 *
 * `waitUntil` is NOT used to background the tick: the platform keeps the
 * invocation alive for the returned promise, and detaching it would let the
 * isolate be evicted mid-batch, leaving fire rows claimed with no dispatch
 * behind them. Awaiting is what makes the claim-then-dispatch order safe.
 */
export const scheduled: ExportedHandlerScheduledHandler<ControlPlaneBindings> = async (
  controller,
  env,
) => {
  await runScheduledTick(env, Math.floor(controller.scheduledTime / 1000));
};
