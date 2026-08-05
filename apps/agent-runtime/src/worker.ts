/**
 * The deploy entrypoint — the module `wrangler.toml`'s `main` points at.
 *
 * workerd treats every named export of the entry module as a service
 * entrypoint and rejects any that is not a function / `ExportedHandler` /
 * `WorkerEntrypoint` or `DurableObject` class. `index.ts` exports
 * `OWNED_OPERATIONS` (an array), so pointing `main` at it fails the Worker at
 * startup. See `apps/gateway/src/worker.ts` for the full write-up.
 *
 * The two Durable Object classes MUST be re-exported here: this app really
 * does declare `[[durable_objects.bindings]]` for `AGENT_RUN_STATE` and
 * `WORKER_PLANE`, and workerd resolves each `class_name` against the ENTRY
 * module. Dropping either re-export fails the Worker at startup with
 * `Durable Object class ... not found`.
 */
export { default } from "./index.js";
export { AgentRunState } from "./runs/do.js";
export { WorkerPlane } from "./workers/plane.js";

/** The cross-script tenant database class used by the durable test harness. */
export { TenantDataObject } from "@ferrogate/storage/durable-objects";
