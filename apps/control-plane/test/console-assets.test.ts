/**
 * The `[assets]` stanza — the admin console served from THIS Worker (#696).
 *
 * ## Why the console has to live on this origin
 *
 * Two guards make a cross-origin admin console unusable in a real browser, and
 * neither is a bug to be relaxed:
 *
 *  1. `adminCrossSiteRejection` (src/middleware/auth.ts) rejects any
 *     state-changing request whose `sec-fetch-site` is `cross-site` or
 *     `same-site` with `403 cross_site_admin_denied`. The browser sets that
 *     header and a page cannot forge it, so a console on another origin is
 *     refused on every POST/PUT/PATCH/DELETE — `POST /v1/admin/login` included,
 *     via `consoleCsrf` (src/session/routes.ts), which imports the SAME rule.
 *  2. the CORS preflight surface (src/middleware/cors.ts) answers
 *     `OPTIONS /admin/{*rest}` and nothing else — the prefix is `/admin/`
 *     verbatim, exactly as Rust wrote it. `POST /v1/admin/login` sends
 *     `content-type: application/json`, so a cross-origin browser preflights
 *     `OPTIONS /v1/admin/login`, which is documented for no operation: the
 *     login is refused before it is ever sent. `deniesTheCrossOriginLogin`
 *     below pins both halves so neither can be "fixed" by widening CORS
 *     without someone deciding to.
 *
 * Same origin dissolves both without widening anything: `sec-fetch-site` is
 * `same-origin`, and a same-origin request is never preflighted.
 *
 * ## What this file actually gates
 *
 * `run_worker_first`. Workers Static Assets are served BEFORE the Worker by
 * default, and with `not_found_handling = "single-page-application"` the
 * `index.html` fallback answers every path no asset matches. Attaching the
 * console WITHOUT `run_worker_first` therefore does not merely add a UI — it
 * takes the API down and hides it: `GET /admin/v1/plans` would answer
 * `200 text/html` with the console shell, and every client would see a
 * successful-looking response it cannot parse.
 *
 * So the list is derived, never restated: `app.routes` is Hono's own table on
 * the instance `src/index.ts` exports, so a surface mounted there and not
 * listed in `wrangler.toml` is RED here. The one addition the table cannot
 * show is `/control/v1/*`, which never reaches Hono under that spelling —
 * `withAliasCanonicalization` rewrites it to `/admin/v1/*` at the fetch
 * boundary, i.e. INSIDE the Worker, which is already too late for the asset
 * router that runs in front of it.
 *
 * ## What this file cannot prove, and why it is still worth having
 *
 * `@cloudflare/vitest-pool-workers` dispatches `SELF.fetch` straight at the
 * Worker entrypoint: the asset router is not in the path at all (probed while
 * writing this — with an `index.html` in `public/`, `GET /` still answered the
 * Worker's `404 no route for GET /`). So no test here can observe an asset
 * being served, and the behavioural half is verified only by a real deploy.
 * The half that CAN be read off the committed file is the half that breaks the
 * API, which is the half worth gating — the same argument `cron-trigger.test.ts`
 * makes for `[triggers]`.
 */
import { SELF, env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { ALIAS_PATH_PREFIX } from "../src/contract.js";
import { app } from "../src/index.js";
import { BASE } from "./harness.js";

// ---------------------------------------------------------------------------
// The committed wrangler.toml
// ---------------------------------------------------------------------------

function wranglerToml(): string {
  const raw = (env as unknown as { TEST_WRANGLER_TOML?: string }).TEST_WRANGLER_TOML;
  if (typeof raw !== "string" || raw.length === 0) {
    throw new Error(
      "control-plane console-assets gate: TEST_WRANGLER_TOML is not bound; restore it in apps/control-plane/vitest.config.ts",
    );
  }
  return raw;
}

/** The lines of the top-level `[assets]` table, or `[]` when there is none. */
function assetsTableLines(): string[] {
  // Line-oriented for the same reason `cron-trigger.test.ts` is: a TOML table
  // ends at the next top-level header, and a regex that has to express "or end
  // of input" is exactly where a config gate silently starts matching nothing.
  const lines = wranglerToml().split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === "[assets]");
  if (start < 0) return [];
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\s*\[/.test(line)) break;
    body.push(line);
  }
  return body;
}

/** A single `key = "value"` string entry of `[assets]`. */
function assetsString(key: string): string | null {
  for (const line of assetsTableLines()) {
    const match = new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`).exec(line);
    if (match !== null) return match[1] as string;
  }
  return null;
}

/**
 * `run_worker_first = [...]`, which wrangler accepts multi-line, so this reads
 * to the closing bracket rather than to the end of the line.
 */
function runWorkerFirst(): string[] {
  const body = assetsTableLines();
  const start = body.findIndex((line) => /^\s*run_worker_first\s*=\s*\[/.test(line));
  if (start < 0) return [];
  const patterns: string[] = [];
  for (const line of body.slice(start)) {
    for (const entry of line.matchAll(/"([^"]+)"/g)) patterns.push(entry[1] as string);
    if (line.includes("]")) break;
  }
  return patterns;
}

// ---------------------------------------------------------------------------
// The paths the Worker must keep
// ---------------------------------------------------------------------------

interface HonoRoute {
  readonly path: string;
  readonly method: string;
}

/**
 * Every path Hono routes on the EXPORTED app, with `:param` segments filled in
 * so each is a concrete URL an asset router would have to classify.
 *
 * `method === "ALL"` entries are the `app.use(...)` middleware chain, not
 * routes; `wiring.test.ts` filters them the same way.
 */
function workerPaths(): string[] {
  const routes = (app as unknown as { routes: readonly HonoRoute[] }).routes;
  const paths = new Set<string>();
  for (const route of routes) {
    if (route.method === "ALL") continue;
    paths.add(route.path.replace(/:[^/]+/g, "probe").replace(/\/\*$/, "/probe"));
  }
  // The alias spelling never appears in `app.routes` — see the docblock.
  paths.add(`${ALIAS_PATH_PREFIX}/plans`);
  return [...paths].sort();
}

/** Cloudflare asset route patterns: an exact path, or a `/*` suffix wildcard. */
function matchesPattern(pattern: string, path: string): boolean {
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -2);
    return path === prefix || path.startsWith(`${prefix}/`);
  }
  return pattern === path;
}

// ---------------------------------------------------------------------------

describe("the admin console's static-asset wiring", () => {
  it("declares an [assets] stanza in the COMMITTED wrangler.toml", () => {
    expect(assetsString("directory")).not.toBeNull();
  });

  it("falls back to the console shell so client-side routes deep-link", () => {
    // Without this, `/app/request-logs` — a react-router path with no file
    // behind it — 404s on reload and on every shared link.
    expect(assetsString("not_found_handling")).toBe("single-page-application");
  });

  it("declares no assets binding, because nothing in src/ would read one", () => {
    // `test/env-var-drift.test.ts` refuses a declared-but-unread binding, and
    // it refused this one: an assets `binding` exists so the Worker can call
    // `env.<NAME>.fetch(request)` itself, which is only needed under
    // `run_worker_first = true`. Here the Worker runs first for the API paths
    // and never for an asset path. If a reader is ever added, the name must not
    // be `ASSETS` — `apps/gateway` binds that to its hosted-artifact R2 bucket.
    expect(assetsString("binding")).toBeNull();
  });

  it("runs the Worker first for EVERY path the Worker routes", () => {
    const patterns = runWorkerFirst();
    const shadowed = workerPaths().filter(
      (path) => !patterns.some((pattern) => matchesPattern(pattern, path)),
    );
    // A shadowed path does not 404 — it answers `200 text/html` with the
    // console shell, so a client sees "up" and cannot parse the body.
    expect(
      shadowed,
      `these routed paths would be answered by the SPA asset fallback instead of the Worker; add them to [assets] run_worker_first in apps/control-plane/wrangler.toml: ${shadowed.join(", ")}`,
    ).toEqual([]);
  });

  it("does not claim a path the Worker does not route", () => {
    // The mirror direction: a stale `run_worker_first` entry for a surface that
    // has been removed sends real console URLs to the Worker's JSON 404 handler
    // instead of to the SPA fallback, which breaks deep links silently.
    const paths = workerPaths();
    const stale = runWorkerFirst().filter(
      (pattern) => !paths.some((path) => matchesPattern(pattern, path)),
    );
    expect(stale, `stale run_worker_first patterns: ${stale.join(", ")}`).toEqual([]);
  });
});

describe("why the console must be same-origin", () => {
  it("denies the cross-origin console login twice over", async () => {
    // (1) the preflight a cross-origin browser sends first. `/v1/admin/login`
    //     is not under the `/admin/` preflight prefix, so it is unroutable:
    //     the browser never sends the POST at all.
    const preflight = await SELF.fetch(`${BASE}/v1/admin/login`, {
      method: "OPTIONS",
      headers: { origin: "https://console.example", "sec-fetch-site": "cross-site" },
    });
    expect(preflight.status).toBe(404);
    expect(preflight.headers.get("access-control-allow-origin")).toBeNull();

    // (2) and had it been sent anyway (a non-browser client forging nothing,
    //     or a future CORS widening), `consoleCsrf` refuses it on the header
    //     the browser controls.
    const post = await SELF.fetch(`${BASE}/v1/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "cross-site" },
      body: JSON.stringify({ email: "operator@example.test", password: "hunter2hunter2" }),
    });
    expect(post.status).toBe(403);
    expect(((await post.json()) as { error: { code: string } }).error.code).toBe(
      "cross_site_admin_denied",
    );
  });

  it("admits the same-origin console login as far as the credential check", async () => {
    // Same request, same body, one header different — and it reaches the
    // surface instead of the guard. 401/503 here is the login REFUSING an
    // unknown account or an unconfigured secret, which is the point: the CSRF
    // ladder is behind it.
    const response = await SELF.fetch(`${BASE}/v1/admin/login`, {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "same-origin" },
      body: JSON.stringify({ email: "operator@example.test", password: "hunter2hunter2" }),
    });
    expect(response.status).not.toBe(403);
  });
});
