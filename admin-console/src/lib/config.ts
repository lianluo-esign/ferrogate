// Where the console's backends live. The control plane and data plane are
// separate Workers: control-plane routes must stay same-origin with the
// console, while data-plane paths may use the gateway's own origin.
//
// ## Why the control plane stays same-origin
//
// The console is served by `apps/control-plane` as Workers Static Assets (see
// that app's `wrangler.toml` `[assets]` block). The control plane has two
// browser-facing guards that make a cross-origin console unusable:
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
// Same-origin dissolves both: `sec-fetch-site: same-origin` passes the first,
// and a same-origin request is never preflighted, so the second is not
// consulted. `src/lib/control-plane-origin.test.ts` holds the property.
//
// ## What replaced the Rust-era origins
//
// This file used to resolve separate Rust-era auth and gateway-admin origins.
// The TypeScript control plane now serves the admin and session surfaces. The
// gateway still owns data-plane paths such as `/v1/assets` and `/sites`, so
// those paths are selected explicitly below instead of being sent to the
// control plane by accident.
//
// ## The two origins
//
// `VITE_CONTROL_PLANE_BASE_URL` is the control-plane origin. It defaults to
// the origin serving the console so browser mutations remain same-origin.
// `VITE_GATEWAY_BASE_URL` is the data-plane origin. It also defaults to the
// console origin for a reverse-proxy or local integrated setup, and should be
// set explicitly when the gateway is deployed separately.
//
// Runtime (`window.__ENV__`) still takes precedence over the Vite build-time
// env, because the same built bundle is deployed across environments: the
// container entrypoint renders `/env-config.js` before nginx starts, and
// `index.html` loads it ahead of the app bundle.
declare global {
  interface Window {
    __ENV__?: {
      VITE_CONTROL_PLANE_BASE_URL?: string;
      VITE_GATEWAY_BASE_URL?: string;
    };
  }
}

/**
 * Origin for control-plane requests. Deliberately absolute rather than empty:
 * URL composition needs a valid base even in the same-origin case.
 */
export const CONTROL_PLANE_BASE_URL: string =
  window.__ENV__?.VITE_CONTROL_PLANE_BASE_URL ||
  import.meta.env.VITE_CONTROL_PLANE_BASE_URL ||
  window.location.origin;

/** Origin for gateway-owned data-plane requests such as assets and sites. */
export const GATEWAY_BASE_URL: string =
  window.__ENV__?.VITE_GATEWAY_BASE_URL ||
  import.meta.env.VITE_GATEWAY_BASE_URL ||
  window.location.origin;

const CONTROL_PLANE_PATH_PREFIXES = ["/admin/v1", "/control/v1", "/v1/admin", "/scim/v2"] as const;

const CONTROL_PLANE_ROOT_PATHS = new Set([
  "/admin",
  "/admin/",
  "/admin/dashboard",
  "/admin/status",
  "/healthz",
  "/readyz",
  "/health",
  "/version",
  "/metrics",
]);

/** Returns whether a request path is handled by the TypeScript control plane. */
export function isControlPlaneRequestPath(path: string): boolean {
  const pathname = path.split(/[?#]/, 1)[0] ?? path;
  return (
    CONTROL_PLANE_ROOT_PATHS.has(pathname) ||
    CONTROL_PLANE_PATH_PREFIXES.some(
      (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
    )
  );
}

/** Selects the backend origin for a console request path. */
export function baseUrlForRequestPath(
  path: string,
  controlPlaneBaseUrl: string = CONTROL_PLANE_BASE_URL,
  gatewayBaseUrl: string = GATEWAY_BASE_URL,
): string {
  return isControlPlaneRequestPath(path) ? controlPlaneBaseUrl : gatewayBaseUrl;
}

/**
 * @deprecated Kept as an alias of {@link CONTROL_PLANE_BASE_URL} so the console
 * session client reads at its call site; there is no separate auth service any
 * more. New code should name the control plane.
 */
export const AUTH_BASE_URL: string = CONTROL_PLANE_BASE_URL;

/**
 * @deprecated Alias of {@link CONTROL_PLANE_BASE_URL}. The name is retained
 * for old call sites while request-path routing moves data-plane calls to
 * {@link GATEWAY_BASE_URL}.
 */
export const GATEWAY_ADMIN_BASE_URL: string = CONTROL_PLANE_BASE_URL;

/** @deprecated Alias of {@link CONTROL_PLANE_BASE_URL}. */
export const ADMIN_API_BASE_URL: string = CONTROL_PLANE_BASE_URL;
