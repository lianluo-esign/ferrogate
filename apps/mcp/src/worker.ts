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
 * `McpOauthFlowClaim` IS such a class and MUST stay re-exported here: this app
 * declares `[[durable_objects.bindings]] name = "MCP_OAUTH_FLOWS"` and workerd
 * resolves its `class_name` against the ENTRY module. Dropping the re-export
 * fails the Worker at startup with `Durable Object class ... not found`.
 *
 * When a `FerroGateMcpSession` Durable Object is eventually added (see the
 * DURABLE OBJECTS note in `wrangler.toml`), its class must be re-exported HERE
 * as well, for the same reason.
 */
export { default } from "./index.js";
export { McpOauthFlowClaim } from "./oauth-flow.js";
