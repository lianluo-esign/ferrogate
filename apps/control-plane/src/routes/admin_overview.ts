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
import { type GroupModule, type Handler, crudGroup, json, raw } from "./resource.js";
import { registerSelfHostedWorkerHandler } from "./self_hosted_worker.js";

/**
 * The admin console SIGNPOST — not the console itself.
 *
 * PORT-TODO(P: inventory-edge-control §4) — KEPT, narrowed by #696. The console
 * is no longer unserved: `wrangler.toml` now carries an `[assets]` block that
 * serves `admin-console/`'s build output from THIS Worker, so the SPA lives at
 * `/` and its client-side routes (`/app/**`, `/login`) are answered by the
 * asset router's single-page-application fallback. Same origin is a
 * requirement, not a convenience — `adminCrossSiteRejection` and the `/admin/`-
 * only CORS preflight make a cross-origin console unable to write or even log
 * in; that file's docblock has the argument.
 *
 * What is NOT resolved is these three paths. `/admin`, `/admin/` and
 * `/admin/dashboard` are contract operations (the contract's only `anonymous`
 * ones) with a documented `text/html` response, so they cannot become the SPA
 * without changing the contract, and they are inside `run_worker_first` so the
 * asset router never sees them. They therefore stay a self-contained document —
 * one that now points at `/`, where the console actually is.
 *
 * It deliberately ships **no script tag and no bundle reference**: a shell that
 * loaded a bundle would answer `200` with a blank page whenever the console had
 * not been built into `public/`, and an operator reads a blank page as "the
 * console is broken" rather than "the console is not deployed". `test/auth.test.ts`
 * pins both halves (a real document, and no script).
 *
 * It closes when the contract's dashboard operations are either retired or
 * redefined to serve the SPA.
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
<p>The admin console is served from the site root: <a href="/">/</a>. If that
answers 404, the console has not been built into this Worker's asset directory
&mdash; run <code>scripts/build-admin-console.sh</code> before deploying.</p>
</body>
</html>
`;

/** Rust `write_raw_response(…, "text/html; charset=utf-8", ADMIN_DASHBOARD_HTML)`. */
const dashboard: Handler = (c) => raw(c, 200, "text/html; charset=utf-8", ADMIN_DASHBOARD_HTML);

/**
 * `POST /admin/v1/status` — self-hosted worker registration, delegated to the
 * SAME handler `POST /admin/v1/self-hosted-workers` uses, so the two entry
 * points cannot diverge.
 *
 * It used to be a bare `createHandler` over the shared collection spec, which
 * wrote only the document. That is now a real divergence rather than a cosmetic
 * one: registration mints a transport credential and projects the typed
 * `self_hosted_worker_registrations` row `apps/agent-runtime` authenticates
 * against, so a worker registered through THIS alias would have been visible in
 * the admin listing and able to authenticate nobody.
 */
const registerWorker = registerSelfHostedWorkerHandler;

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
