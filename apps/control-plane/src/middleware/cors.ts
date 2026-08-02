/**
 * `OPTIONS /admin/{*rest}` — the CORS preflight surface.
 *
 * This is a **dynamic surface**, not one of the 254 contract operations. From
 * `dynamic_surfaces` in `docs/openapi/runtime-api-contract.json`:
 *
 * > `OPTIONS /admin/{*rest}` — CORS preflight, exists only when an
 * > admin-console allowed origin is configured.
 *
 * "Exists only when configured" is literal, and load-bearing. Rust
 * (`server/handlers.rs`):
 *
 * ```rust
 * if req.method == http::Method::OPTIONS
 *     && path.starts_with("/admin/")
 *     && cors_allowed_origin().is_some()
 * { write_cors_preflight_response(session).await?; return Ok(true); }
 * ```
 *
 * With no console origin configured the branch is not taken, the request falls
 * through to normal routing, and `OPTIONS` — documented for no operation — is a
 * 405/404. A gateway with no admin console does not answer preflights at all,
 * so a browser cannot use it as a CORS relay. Answering a permissive preflight
 * unconditionally (the naive `hono/cors` mount) would silently widen that.
 *
 * Note the prefix is `/admin/` **with** the trailing slash, exactly as Rust
 * writes it: bare `/admin` is not preflighted.
 *
 * `apply_cors_headers` (the `access-control-allow-origin` + `vary: origin` pair
 * Rust attaches to every locally-handled response) is exported separately and
 * applied to all responses, again only when an origin is configured.
 */
import type { MiddlewareHandler } from "hono";
import type { ControlPlaneDeps, ControlPlaneEnv } from "../ports.js";

/** Rust: the prefix the preflight branch tests. Trailing slash is deliberate. */
export const ADMIN_PREFLIGHT_PREFIX = "/admin/";

/** Rust `write_cors_preflight_response` — the exact header set, verbatim. */
export const PREFLIGHT_ALLOW_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
export const PREFLIGHT_ALLOW_HEADERS = "authorization, content-type, x-api-key";
export const PREFLIGHT_MAX_AGE = "600";

/** Rust `apply_cors_headers`. No-op when no console origin is configured. */
export function applyCorsHeaders(headers: Headers, corsAllowedOrigin: string | null): void {
  if (corsAllowedOrigin === null) return;
  headers.set("access-control-allow-origin", corsAllowedOrigin);
  headers.set("vary", "origin");
}

/**
 * Answer the preflight (204, no body) — and ONLY when a console origin is
 * configured. Mount before `contractAuth`, since a preflight carries no
 * credentials by definition and must not be challenged for one.
 */
export const adminCorsPreflight: MiddlewareHandler<ControlPlaneEnv> = async (c, next) => {
  const deps: ControlPlaneDeps = c.get("deps");
  const path = c.get("canonicalPath") ?? c.req.path;

  if (
    c.req.method === "OPTIONS" &&
    path.startsWith(ADMIN_PREFLIGHT_PREFIX) &&
    deps.corsAllowedOrigin !== null
  ) {
    const headers = new Headers({
      "content-length": "0",
      "access-control-allow-methods": PREFLIGHT_ALLOW_METHODS,
      "access-control-allow-headers": PREFLIGHT_ALLOW_HEADERS,
      "access-control-max-age": PREFLIGHT_MAX_AGE,
    });
    applyCorsHeaders(headers, deps.corsAllowedOrigin);
    return new Response(null, { status: 204, headers });
  }

  await next();
};

/**
 * Attach the CORS response headers to every locally-handled response, mirroring
 * Rust's `apply_cors_headers` inside `write_json_response`/`write_raw_response`.
 */
export const corsResponseHeaders: MiddlewareHandler<ControlPlaneEnv> = async (c, next) => {
  await next();
  const deps: ControlPlaneDeps = c.get("deps");
  applyCorsHeaders(c.res.headers, deps.corsAllowedOrigin);
};
