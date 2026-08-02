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
 * `McpOauthFlowClaim`, `FerroGateMcpSession` and `FerroGateMcpUnifiedSession`
 * ARE such classes and MUST stay re-exported here: this app declares
 * `[[durable_objects.bindings]] name = "MCP_OAUTH_FLOWS"`, `name =
 * "MCP_SESSION"` and `name = "MCP_CLIENT_SESSION"`, and workerd resolves each
 * `class_name` against the ENTRY module. Dropping any re-export fails the
 * Worker at startup with `Durable Object class ... not found` — including under
 * `@cloudflare/vitest-pool-workers`, which is why `test/durable-upstreams.test.ts`
 * and `test/unified-session.test.ts` can assert the namespaces are reachable
 * and go red on a dropped export.
 *
 * The two session classes are DIFFERENT axes and both are needed:
 * `FerroGateMcpSession` is one per `(tenant, UPSTREAM)`;
 * `FerroGateMcpUnifiedSession` is one per `(tenant, CLIENT session)` (#687).
 */
export { default } from "./index.js";
export { McpOauthFlowClaim } from "./oauth-flow.js";
export { FerroGateMcpSession } from "./session.js";
export { FerroGateMcpUnifiedSession } from "./unified.js";
