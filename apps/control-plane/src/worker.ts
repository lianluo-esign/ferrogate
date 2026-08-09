/**
 * The deploy entrypoint — the module `wrangler.toml`'s `main` points at.
 *
 * workerd treats every named export of the entry module as a service
 * entrypoint and rejects any that is not a function / `ExportedHandler` /
 * `WorkerEntrypoint` or `DurableObject` class. `index.ts` exports the
 * anti-drift surface (`MOUNTED_ROUTES`, `MOUNTED_OPERATION_IDS`,
 * `CONTROL_PLANE_ROUTE_MODULES`, `app`) — arrays and objects — so pointing
 * `main` at it fails the Worker at startup. See `apps/gateway/src/worker.ts`
 * for the full write-up and the error text.
 *
 * `fetch` delegates to `withAliasCanonicalization(app)`, the same object
 * `index.ts` builds, so `/control/v1/*` still folds onto `/admin/v1/*` before
 * routing. Nothing is composed in this file.
 *
 * `scheduled` is the agent-schedule TICK (`src/schedule/scheduled.ts`), and the
 * reason this file is an explicit `ExportedHandler` rather than the one-line
 * `export { default }` it used to be: workerd only dispatches a scheduled event
 * to a handler found on the ENTRY module's DEFAULT export, so a named
 * `export { scheduled }` would be silently accepted as a service entrypoint and
 * the Cron trigger would fire against a Worker with no handler — schedules
 * would never fire on their own while the whole suite stayed green. Same
 * lesson, same shape, as `gatewayScheduled` in `apps/gateway/src/worker.ts`.
 */
import app from "./index.js";
import { consumeTenantScheduleAlarmBatch } from "./schedule/alarm-queue.js";
import { scheduled } from "./schedule/scheduled.js";

const handler: ExportedHandler<Parameters<typeof scheduled>[1]> = {
  fetch: (request, env, ctx) => app.fetch(request, env, ctx),
  scheduled: (controller, env, ctx) => scheduled(controller, env, ctx),
  queue: (batch, env) => consumeTenantScheduleAlarmBatch(batch, env),
};

export default handler;
