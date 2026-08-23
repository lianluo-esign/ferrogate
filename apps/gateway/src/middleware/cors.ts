/**
 * Cross-origin support for a separately deployed Admin Console.
 *
 * The console's control-plane calls are same-origin, but its Workers Static
 * Assets build can point data-plane requests at this gateway. CORS is mounted
 * before contract authentication so browser preflights do not carry a bearer
 * credential and do not get challenged for one.
 */
import type { MiddlewareHandler } from "hono";
import type { GatewayEnv } from "../ports.js";
import { classifyError, writeJsonError } from "./errors.js";

/** Rust-compatible response contract plus the headers used by site uploads. */
export const PREFLIGHT_ALLOW_METHODS = "GET, POST, PUT, PATCH, DELETE, OPTIONS";
export const PREFLIGHT_ALLOW_HEADERS =
  "authorization, content-type, x-api-key, x-goog-api-key, x-goog-api-client, x-site-cache-control, x-site-public, x-site-spa-fallback";
export const PREFLIGHT_MAX_AGE = "600";

/**
 * Apply CORS headers only for the configured console origin. `Vary` is set for
 * every configured response so an intermediary cannot reuse an allowed
 * response for a different Origin.
 */
export function applyCorsHeaders(
  headers: Headers,
  allowedOrigin: string | null,
  requestOrigin: string | null,
): void {
  if (allowedOrigin === null) return;
  const vary = (headers.get("vary") ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value !== "");
  if (!vary.some((value) => value === "*" || value.toLowerCase() === "origin")) {
    vary.push("origin");
  }
  headers.set("vary", vary.join(", "));
  if (requestOrigin === allowedOrigin) {
    headers.set("access-control-allow-origin", allowedOrigin);
  }
}

/**
 * The gateway CORS middleware. An unset origin is deliberately inert; a
 * mismatched origin falls through without a CORS header or permissive 204.
 */
export const gatewayCors: MiddlewareHandler<GatewayEnv> = async (c, next) => {
  const allowedOrigin = c.env.GATEWAY_CORS_ALLOWED_ORIGIN?.trim() || null;
  const requestOrigin = c.req.header("Origin") ?? null;

  if (c.req.method === "OPTIONS" && allowedOrigin === requestOrigin) {
    const headers = new Headers({
      "content-length": "0",
      "access-control-allow-methods": PREFLIGHT_ALLOW_METHODS,
      "access-control-allow-headers": PREFLIGHT_ALLOW_HEADERS,
      "access-control-max-age": PREFLIGHT_MAX_AGE,
    });
    applyCorsHeaders(headers, allowedOrigin, requestOrigin);
    return new Response(null, { status: 204, headers });
  }

  try {
    await next();
  } catch (error) {
    // The outer envelope boundary would otherwise catch this after this
    // middleware unwinds, leaving the generated error without CORS headers.
    const { status, code, message, headers } = classifyError(error);
    c.res = writeJsonError(c, status, code, message, headers ?? {});
  }
  applyCorsHeaders(c.res.headers, allowedOrigin, requestOrigin);
};
