/**
 * The deploy entrypoint — the module `wrangler.toml`'s `main` points at.
 *
 * workerd treats every named export of the entry module as a service
 * entrypoint and rejects any that is not a function / `ExportedHandler` /
 * `WorkerEntrypoint` or `DurableObject` class. `index.ts` exports the
 * anti-drift surface (`MCP_ROUTE_MODULES`, `mcpRouter`, `app`, the route
 * modules and their operation-id lists), so pointing `main` at it fails the
 * Worker at startup. See `apps/gateway/src/worker.ts` for the full write-up.
 *
 * When a `FerroGateMcpSession` Durable Object is eventually added (see the
 * DURABLE OBJECTS note in `wrangler.toml`), its class must be re-exported HERE
 * as well — a `[[durable_objects.bindings]]` resolves `class_name` against the
 * entry module, which is this file.
 */
export { default } from "./index.js";
