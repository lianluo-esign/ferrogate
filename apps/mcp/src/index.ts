/**
 * `ferrogate-mcp` Worker — FerroGate's MCP host ingress.
 *
 * Clean-room re-implementation of the Rust `ferrogate-mcp` host and the
 * `/v1/mcp*` surface of `ferrogate-gateway` (`server/mcp_rpc.rs`,
 * `server/mcp_ingress.rs`, `server/mcp_identity.rs`), per
 * `docs/legacy/inventory-edge-control.md` §4 (MCP).
 *
 * The six contract operations this Worker owns
 * (docs/openapi/runtime-api-contract.json):
 *
 * | operation_id               | route                                      | auth                    |
 * |----------------------------|--------------------------------------------|-------------------------|
 * | `mcpJsonRpc`               | `POST /v1/mcp`                             | method_dependent scope  |
 * | `executeMcpTool`           | `POST /v1/mcp/tool/execute`                | bearer, MCP execute     |
 * | `getMcpIdentity`           | `GET /v1/mcp/identity/{server}`            | bearer `tools.read`     |
 * | `revokeMcpIdentity`        | `DELETE /v1/mcp/identity/{server}`         | bearer `tools.execute`  |
 * | `authorizeMcpIdentity`     | `POST /v1/mcp/identity/{server}/authorize` | bearer `tools.execute`  |
 * | `completeMcpIdentityOauth` | `GET /v1/mcp/identity/callback`            | anonymous (state-bound) |
 *
 * ...plus the two SHARED operations ROUTE-MAP.md requires in every Worker,
 * `GET /healthz` and `GET /readyz` (both `anonymous`), which the composition
 * root in `src/routes/index.ts` registers directly.
 *
 * ## Why the JSON-RPC layer is hand-written rather than `@modelcontextprotocol/sdk`
 *
 * The SDK models a stateful MCP *server* (session ids, a resumable event log,
 * `initialize` handshake state). FerroGate's ingress is deliberately the
 * opposite: a STATELESS dual-era gateway that must (a) accept the pinned
 * `2026-07-28` candidate revision, which has no `initialize` handshake and adds
 * the `Mcp-Method` / `Mcp-Name` routing headers the SDK does not model, and (b)
 * fail a request CLOSED when a routing header disagrees with the body — a
 * gateway-specific control with no SDK hook. Wrapping the SDK would mean
 * bypassing it for exactly the behavior this port exists to preserve, so
 * `src/jsonrpc.ts` implements the JSON-RPC 2.0 codec directly and
 * `src/transport.ts` implements both transport directions. The SDK stays a
 * declared dependency for the tenant-hosted MCP-server half (see below).
 *
 * PORT-TODO(inventory-edge-control §9.2): NOT a platform limit and NOT this
 * Worker's work — a SCOPE boundary, recorded so it is not lost. The other half
 * of the Rust crate, `mcp_worker_deploy.rs`, uploads a tenant's own hosted
 * MCP-server Worker (`FerroGateMcp extends McpAgent` at `/mcp` + `/sse` behind
 * `@cloudflare/workers-oauth-provider`). On CF that is a `wrangler deploy` /
 * Workers-for-Platforms call, which is a CONTROL-PLANE capability: it needs an
 * account-scoped API token, and giving this data-plane ingress the ability to
 * deploy Workers would be a serious privilege escalation. It belongs in
 * `apps/control-plane`, never as a runtime route here.
 */
import { identityRouteModule } from "./identity/routes.js";
import { type RouteModule, createMcpApp } from "./routes/index.js";
import { ingressRouteModule } from "./routes/ingress.js";

/**
 * The route modules THIS Worker mounts — the single source of truth for what
 * the deployed MCP ingress serves. `test/contract.test.ts` imports this exact
 * array (never a bespoke copy) and asserts every owned operation id is
 * registered AND reachable over `SELF.fetch`, so a module dropped from this
 * list fails the suite instead of silently un-deploying four routes.
 */
export const MCP_ROUTE_MODULES: readonly RouteModule[] = [
  ingressRouteModule(),
  identityRouteModule(),
];

const { app, router } = createMcpApp({ modules: MCP_ROUTE_MODULES });

/** The registry of what the deployed Worker actually mounted (anti-drift gate). */
export const mcpRouter = router;

export default app;

export { app };

export {
  createMcpApp,
  McpRouter,
  SERVICE_NAME,
  RUNTIME_NAME,
  MCP_PROTOCOL_REVISION,
  PENDING_MODULE_OPERATION_IDS,
  healthReport,
  readinessReport,
} from "./routes/index.js";
export type {
  McpApp,
  McpAppEnv,
  OperationHandler,
  RouteModule,
  HealthReport,
  ReadinessReport,
} from "./routes/index.js";
export { ingressRouteModule, INGRESS_OPERATION_IDS } from "./routes/ingress.js";
export { identityRouteModule, IDENTITY_OPERATION_IDS } from "./identity/routes.js";
export * from "./contract.js";
