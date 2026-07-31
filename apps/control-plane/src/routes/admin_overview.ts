/**
 * Contract group `admin_overview` (9 operations).
 *
 * The un-versioned surface plus the three `/admin/v1` introspection reads:
 *
 * ```
 *   GET  /admin, /admin/, /admin/dashboard   anonymous  → the console HTML
 *   GET  /admin/status, /admin/v1/status     admin.read → AdminStatus
 *   POST /admin/v1/status                    admin.write→ self-hosted worker registration (!)
 *   GET  /admin/v1/overview                  admin.read
 *   GET  /admin/v1/observability             admin.read
 *   GET  /metrics                            admin.read → Prometheus exposition
 * ```
 *
 * Two things here are easy to get wrong and are called out in `ROUTE-MAP.md`:
 *
 *  - **`GET /metrics` is `visibility: internal` but `auth.kind: bearer`.** It is
 *    NOT public and NOT unauthenticated. Rust `handle_metrics` opens with
 *    `authenticate(&state, headers, "admin.read", …)` exactly like every other
 *    admin read, and the guard is applied here by the same table-driven
 *    middleware — this module contributes only the body.
 *  - **`POST /admin/v1/status` is `registerAdminSelfHostedWorker`**, not a
 *    status write. It shares the path with the status read but is a worker-plane
 *    registration; `crates/ferrogate-control-plane-client/src/ops.rs` documents
 *    the collision explicitly ("this shares the status path but is a
 *    worker-agent data-plane registration"). It is routed to the self-hosted
 *    worker collection so the two do not get conflated.
 *
 * The three dashboard paths are the contract's only `anonymous` operations in
 * this app — they serve static HTML and read nothing.
 */
import { z } from "zod";
import {
  crudGroup,
  createHandler,
  json,
  raw,
  resolveSpec,
  type GroupModule,
  type Handler,
} from "./resource.js";
import { SELF_HOSTED_WORKER_SPEC } from "./self_hosted_worker.js";

/**
 * The admin console shell. Rust serves a bundled single-page document
 * (`ADMIN_DASHBOARD_HTML`); the real console is rebuilt separately and is the
 * lowest-priority slice of the rewrite, so this is the honest minimum: a valid
 * document that names the API it fronts.
 *
 * PORT-TODO(inventory-edge-control §4): replace with the rebuilt admin-console
 * bundle (Workers Assets / Pages) once that app is ported.
 */
export const ADMIN_DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FerroGate Control Plane</title>
</head>
<body>
<h1>FerroGate Control Plane</h1>
<p>Control Plane API <code>/admin/v1</code> (legacy alias <code>/control/v1</code>).</p>
<p>See <code>GET /admin/v1/status</code> for runtime status.</p>
</body>
</html>
`;

/** Rust `write_raw_response(…, "text/html; charset=utf-8", ADMIN_DASHBOARD_HTML)`. */
const dashboard: Handler = (c) => raw(c, 200, "text/html; charset=utf-8", ADMIN_DASHBOARD_HTML);

/**
 * `POST /admin/v1/status` — self-hosted worker registration, delegated to the
 * same collection `POST /admin/v1/self-hosted-workers` writes, so the two entry
 * points cannot diverge.
 */
const registerWorker = createHandler(resolveSpec(SELF_HOSTED_WORKER_SPEC));

export const adminOverviewRoutes: GroupModule = crudGroup(
  "admin_overview",
  // Every operation in this group is bespoke; there is no CRUD collection.
  [],
  {
    getAdminDashboard: dashboard,
    getAdminDashboardSlash: dashboard,
    getAdminDashboardAlias: dashboard,

    getAdminStatus: async (c) => json(c, 200, await c.get("deps").runtime.status()),
    getAdminStatusAlias: async (c) => json(c, 200, await c.get("deps").runtime.status()),
    registerAdminSelfHostedWorker: registerWorker,

    getAdminOverview: async (c) => json(c, 200, await c.get("deps").runtime.overview()),
    listAdminObservability: async (c) =>
      json(c, 200, { object: "list", data: await c.get("deps").runtime.observability() }),

    // Rust: `text/plain; version=0.0.4; charset=utf-8`, the Prometheus
    // exposition content type. A JSON envelope here would break every scraper.
    getMetrics: async (c) =>
      raw(
        c,
        200,
        "text/plain; version=0.0.4; charset=utf-8",
        await c.get("deps").runtime.metrics(),
      ),
  },
);

/** Body of a self-hosted worker registration (shared with `self_hosted_worker`). */
export const workerRegistrationSchema = z
  .object({
    id: z.string().trim().min(1).optional(),
    name: z.string().trim().min(1).optional(),
    workspace_id: z.string().trim().min(1).optional(),
  })
  .passthrough();
