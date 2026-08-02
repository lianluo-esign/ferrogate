// Where the console's backend lives — which, since #696, is ONE place: the
// origin the console itself was served from.
//
// ## Why same-origin is a correctness requirement, not a deployment style
//
// The console is served by `apps/control-plane` as Workers Static Assets (see
// that app's `wrangler.toml` `[assets]` block). It has to be, because two
// guards on that Worker make a cross-origin console unusable in a browser:
//
//   1. `adminCrossSiteRejection` (`src/middleware/auth.ts`) answers
//      `403 cross_site_admin_denied` to any state-changing request whose
//      `sec-fetch-site` is `cross-site` or `same-site`. The browser sets that
//      header and a page cannot forge it, so a console on another origin can
//      READ but never write — including `POST /v1/admin/login`, which
//      `consoleCsrf` guards with the same rule.
//   2. the CORS preflight surface (`src/middleware/cors.ts`) answers
//      `OPTIONS /admin/{*rest}` and nothing else. Login is
//      `content-type: application/json`, so a cross-origin browser preflights
//      `OPTIONS /v1/admin/login` — documented for no operation, therefore 404 —
//      and the POST is never sent.
//
// Neither is a bug to relax; they are the CSRF posture of an admin surface.
// Same-origin dissolves both at no cost: `sec-fetch-site: same-origin` passes
// the first, and a same-origin request is never preflighted, so the second is
// not consulted. `src/lib/control-plane-origin.test.ts` holds the property.
//
// ## What replaced the two Rust-era origins
//
// This file used to resolve `VITE_AUTH_BASE_URL` (`:8081`, the
// `ferrogate-auth-service` binary) and `VITE_GATEWAY_ADMIN_BASE_URL` /
// `VITE_ADMIN_API_BASE_URL` (`:8080`, the gateway's own `/admin/v1`). Both
// binaries are deleted; `apps/control-plane` serves BOTH surfaces
// (`/v1/admin/*` and `/admin/v1/*`) from one Worker. Those three variable names
// are therefore no longer read at all — deliberately, rather than being mapped
// onto the new one. A stale `VITE_AUTH_BASE_URL=http://localhost:8081` left in
// somebody's `.env.local` would otherwise keep pointing a working console at a
// service that no longer exists, and the failure mode (a 404 preflight) does
// not name the cause.
//
// ## The one escape hatch
//
// `VITE_CONTROL_PLANE_BASE_URL` overrides the origin for the case same-origin
// cannot cover: pointing a locally-served console at a remote control plane
// while debugging. It is not a supported production topology — a console
// configured that way can read and cannot write, for the reasons above — so it
// exists as one clearly-named variable rather than as a default.
//
// Runtime (`window.__ENV__`) still takes precedence over the Vite build-time
// env, because the same built bundle is deployed across environments: the
// container entrypoint renders `/env-config.js` before nginx starts, and
// `index.html` loads it ahead of the app bundle.
declare global {
  interface Window {
    __ENV__?: {
      VITE_CONTROL_PLANE_BASE_URL?: string;
    };
  }
}

/**
 * The single origin every console request goes to.
 *
 * Deliberately an ABSOLUTE origin rather than the empty string, even in the
 * same-origin case: `buildUrl` and four other call sites compose their URLs
 * with `new URL(path, CONTROL_PLANE_BASE_URL)`, and `new URL("/x", "")` throws.
 * Resolving `window.location.origin` here keeps one shape for both.
 */
export const CONTROL_PLANE_BASE_URL: string =
  window.__ENV__?.VITE_CONTROL_PLANE_BASE_URL ||
  import.meta.env.VITE_CONTROL_PLANE_BASE_URL ||
  window.location.origin;

/**
 * @deprecated Kept as an alias of {@link CONTROL_PLANE_BASE_URL} so the console
 * session client reads at its call site; there is no separate auth service any
 * more. New code should name the control plane.
 */
export const AUTH_BASE_URL: string = CONTROL_PLANE_BASE_URL;

/**
 * @deprecated Alias of {@link CONTROL_PLANE_BASE_URL}. The gateway's own
 * `/admin/v1` surface moved to `apps/control-plane` in the TypeScript rewrite,
 * so this no longer names a different service.
 */
export const GATEWAY_ADMIN_BASE_URL: string = CONTROL_PLANE_BASE_URL;

/** @deprecated Alias of {@link CONTROL_PLANE_BASE_URL}. */
export const ADMIN_API_BASE_URL: string = CONTROL_PLANE_BASE_URL;
