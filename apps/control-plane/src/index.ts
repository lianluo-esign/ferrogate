import { PUBLIC_API_MAJOR } from "@ferrogate/core";
/**
 * `ferrogate-control-plane` Worker — the 197-operation `/admin/v1/**` surface.
 *
 * Replaces `ferrogate-admin` (the naming/stability contract),
 * `ferrogate-auth-service` (server side) and the legacy `d1-proxy` Worker.
 * Everything is table-driven off `docs/openapi/runtime-api-contract.json`:
 * routes, auth kind, required scope and `rbac_action` all come from the same
 * document, so a contract change cannot silently drift from the implementation.
 *
 * Request pipeline, in order — the order is load-bearing:
 *
 * ```
 *   fetch  → alias fold        /control/v1/* → /admin/v1/*   (BEFORE routing)
 *   use    → requestId         x-request-id / x-trace-id
 *   use    → deps              composition root from bindings
 *   use    → cors headers      only when a console origin is configured
 *   use    → cors preflight    OPTIONS /admin/* — only when configured
 *   use    → contractAuth      405 → CSRF → anonymous → bearer+scope
 *                              → lifecycle → rbac_action
 *   route  → 197 handlers      registered from the contract
 *   error  → uniform envelope  { error: { message, type, code, request_id } }
 * ```
 *
 * The preflight sits BEFORE `contractAuth` because a CORS preflight carries no
 * credentials by definition and must not be challenged for one; the auth
 * middleware sits before every handler so no route can be reached unguarded.
 *
 * Still to come on this Worker (they are NOT contract operations, so they are
 * not part of the 197 and do not affect the anti-drift gate):
 * `/v1/admin/*` console identity, `/v1/auth/*` resolve-api-key + authorize, and
 * `/scim/v2/*` provisioning — see `docs/legacy/inventory-edge-control.md` §5.1.
 */
import { Hono } from "hono";
import { resolveDeps } from "./adapters.js";
import {
  CONTROL_PLANE_GROUPS,
  CONTROL_PLANE_OPERATIONS,
  EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
} from "./contract.js";
import { withAliasCanonicalization } from "./middleware/alias.js";
import { contractAuth } from "./middleware/auth.js";
import { adminCorsPreflight, corsResponseHeaders } from "./middleware/cors.js";
import {
  controlPlaneErrorHandler,
  controlPlaneNotFoundHandler,
  requestId,
} from "./middleware/errors.js";
import type { ControlPlaneEnv } from "./ports.js";
import { GROUP_MODULES, type RegisteredRoute, registerRoutes } from "./routes/index.js";
import type { GroupModule } from "./routes/resource.js";

export const app = new Hono<ControlPlaneEnv>();

app.onError(controlPlaneErrorHandler);
app.notFound(controlPlaneNotFoundHandler);

app.use("*", requestId);

/** The composition root, resolved per request from the Worker bindings. */
app.use("*", async (c, next) => {
  c.set("deps", resolveDeps(c.env));
  await next();
});

app.use("*", corsResponseHeaders);
app.use("*", adminCorsPreflight);
app.use("*", contractAuth());

/**
 * THE mount. `MOUNTED_ROUTES` is the value `registerRoutes` returned for THIS
 * app — one entry per `app.on(...)` it actually performed — so it is a record
 * of what the composition root did, not a restatement of the contract.
 *
 * It is exported so the anti-drift gate (`test/wiring.test.ts`) inspects the
 * REAL registry of the app below `export default`. Building a bespoke app in a
 * test and asserting against that is exactly how `apps/gateway` shipped with 24
 * of its 31 operations unreachable while every suite stayed green.
 */
export const MOUNTED_ROUTES: readonly RegisteredRoute[] = registerRoutes(app);

/** Every operation id mounted on the exported app, in mount order. */
export const MOUNTED_OPERATION_IDS: readonly string[] = MOUNTED_ROUTES.map(
  (route) => route.operationId,
);

/**
 * The production module list — the same array the route registry composed the
 * handler table from. Exported for the gate; nothing else should import it.
 */
export const CONTROL_PLANE_ROUTE_MODULES: readonly GroupModule[] = GROUP_MODULES;

/**
 * Liveness / build introspection. `/health` and `/version` are NOT contract
 * operations — the contract's shared probes are `/healthz` and `/readyz`
 * (implemented in every Worker) — so they sit outside the 197 by design.
 */
app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) =>
  c.json({
    api: PUBLIC_API_MAJOR,
    operations: EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
    registered: CONTROL_PLANE_OPERATIONS.length,
    groups: CONTROL_PLANE_GROUPS.length,
  }),
);

/**
 * The default export folds `/control/v1/*` onto `/admin/v1/*` before Hono
 * routes, so both spellings reach exactly one handler with one guard.
 */
export default withAliasCanonicalization(app);
