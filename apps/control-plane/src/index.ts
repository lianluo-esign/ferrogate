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
import { createIdentityRoutes } from "@ferrogate/identity";
import { Hono } from "hono";
import { SERVICE_NAME, resolveDeps } from "./adapters.js";
import {
  CONTROL_PLANE_GROUPS,
  CONTROL_PLANE_OPERATIONS,
  EXPECTED_CONTROL_PLANE_OPERATION_COUNT,
} from "./contract.js";
import { resolveIdentityDeps } from "./identity/adapters.js";
import { type SsoRouteRecord, mountSsoRoutes } from "./identity/routes.js";
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
import { type AdminConsoleSessionRoute, mountAdminConsoleSession } from "./session/index.js";

export const app = new Hono<ControlPlaneEnv>();

app.onError(controlPlaneErrorHandler);
app.notFound(controlPlaneNotFoundHandler);

app.use("*", requestId);

/**
 * The composition root, resolved per request from the Worker bindings.
 *
 * The request id is threaded in because the durable store stamps it onto the
 * `audit_events` row of every mutation it applies — an audit entry nobody can
 * correlate back to a request is evidence of very little. It runs AFTER
 * `requestId`, which is what makes `c.get("requestId")` available here.
 */
app.use("*", async (c, next) => {
  c.set("deps", resolveDeps(c.env, { requestId: c.get("requestId") }));
  await next();
});

app.use("*", corsResponseHeaders);
app.use("*", adminCorsPreflight);
app.use("*", contractAuth());

/**
 * THE ENTERPRISE-IDENTITY MOUNTS (wave 18).
 *
 * Three surfaces that had NO TypeScript at all for seventeen waves — the
 * admin-console session, OIDC + SCIM, and SAML — and that
 * `docs/rewrite/MODULE-OWNERSHIP.md` found precisely because they are not in
 * `docs/openapi/runtime-api-contract.json`. None of their paths is one of the
 * 197, so mounting them cannot move the anti-drift operation count; they mount
 * OUTSIDE `registerRoutes` exactly as `/healthz` and `/version` do.
 *
 * The ORDER is load-bearing:
 *
 *  1. `mountAdminConsoleSession` first, because it installs
 *     `app.use("/v1/admin/*", consoleCsrf)` and Hono applies a `use` to the
 *     handlers registered after it. Mounting it later would leave every
 *     `/v1/admin/*` route below without the cross-site guard;
 *  2. the identity app (`/scim/v2/*` + the OIDC legs + the SCIM-token mint);
 *  3. the SAML legs and the SHARED `sso-config` row.
 *
 * Each returns what it ACTUALLY mounted, so `test/wiring.test.ts` asserts
 * against what the composition root did rather than against a restatement.
 * Deleting any one of these three lines takes a named test RED with a
 * `404 no route for …`, which is the property `docs/rewrite/MOUNT-SEAMS.md`
 * requires of a seam.
 */
export const MOUNTED_SESSION_ROUTES: readonly AdminConsoleSessionRoute[] =
  mountAdminConsoleSession(app);

export const IDENTITY_APP = createIdentityRoutes((c) => resolveIdentityDeps(c));
app.route("/", IDENTITY_APP);

export const MOUNTED_SSO_ROUTES: readonly SsoRouteRecord[] = mountSsoRoutes(app);

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
 * The two SHARED contract probes (`docs/rewrite/ROUTE-MAP.md`: implemented in
 * EVERY Worker; `auth.kind: "anonymous"`, `visibility: "public"` in
 * `docs/openapi/runtime-api-contract.json`).
 *
 * They were missing here — `gateway`, `mcp`, `agent-runtime` and `telemetry`
 * all mount them, and this Worker mounted only the historic `/health`. Nothing
 * in the unit suite could see the hole: it drives named contract operations,
 * and an unmounted anonymous probe is not one of the 197 this app owns. It
 * surfaced on the first real `wrangler dev --local` boot, where `/healthz`
 * answered `404 not_found` — i.e. every uptime check and load-balancer origin
 * probe pointed at the fleet-standard path would have marked this Worker down.
 *
 * Mounted as plain routes rather than through `registerRoutes`, deliberately:
 * folding them into the contract-driven registry would move them inside the
 * operation count the anti-drift test pins. `contractAuth` still runs over them
 * — it is an `app.use("*", …)` — and passes them through because neither path is
 * one of the 197 operations it guards, which is the same treatment `/health`
 * and `/version` have always had. `test/health.test.ts` asserts both answer 200
 * with NO credential, so a future guard change that starts challenging them
 * fails there rather than in an operator's uptime dashboard.
 *
 * `/health` and `/version` are NOT contract operations and stay outside the 197
 * by design.
 */
app.get("/healthz", (c) => c.json({ status: "ok", service: SERVICE_NAME, runtime: "workers" }));
app.get("/readyz", (c) => c.json({ status: "ready", service: SERVICE_NAME, runtime: "workers" }));
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
