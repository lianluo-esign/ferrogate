/**
 * `ferrogate-gateway` Worker — the native TS data plane.
 *
 * Replaces the Rust `ferrogate-gateway` + `ferrogate-runtime` + the Pingora
 * container (eliminated). A Hono streaming proxy for OpenAI-compatible
 * inference, tool/MCP execution, and agent invoke.
 *
 * Routing and auth are **contract-driven**: `src/contract.ts` is the 251
 * operations from `docs/openapi/runtime-api-contract.json`, `src/middleware/
 * auth.ts` is the single guard that enforces each operation's declared
 * `auth.kind` / `auth.scope` / `rbac_action`, and `src/routes/index.ts` mounts
 * the 31 operations this Worker owns.
 *
 * The inference (6 ops) and asset (18 ops) handlers arrive as `RouteModule`s
 * from their own directories and are added to `modules` below; they need no
 * change to the router, the guard, or the contract table.
 */
import { PUBLIC_API_MAJOR } from "@ferrogate/core";
import { type RouteModule, createGatewayApp } from "./routes/index.js";

/**
 * PORT-TODO(ROUTE-MAP §apps/gateway): append the inference and asset route
 * modules here once `src/inference/` and `src/assets/` land (owned by other
 * agents this wave). `PENDING_MODULE_OPERATION_IDS` in `./routes/index.ts`
 * tracks exactly which operation ids are still outstanding, and
 * `test/contract.test.ts` fails if that list and the mounted routes disagree.
 */
const modules: readonly RouteModule[] = [];

const { app } = createGatewayApp({ modules });

app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

export default app;

export { createGatewayApp, GatewayRouter } from "./routes/index.js";
export type { RouteModule, OperationHandler, GatewayApp } from "./routes/index.js";
export type {
  ApiKeyAuthenticatorPort,
  ApiKeyResolution,
  AuthContext,
  GatewayDeps,
  GatewayEnv,
  InternalTransportPort,
  RbacAuthorizerPort,
  TenancyLifecycleGatePort,
} from "./ports.js";
export * from "./contract.js";
