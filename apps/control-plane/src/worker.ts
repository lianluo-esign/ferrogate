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
 * The default export re-exported here is `withAliasCanonicalization(app)`, the
 * same object `index.ts` builds, so `/control/v1/*` still folds onto
 * `/admin/v1/*` before routing. Nothing is composed in this file.
 */
export { default } from "./index.js";
