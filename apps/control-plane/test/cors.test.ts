/**
 * `OPTIONS /admin/{*rest}` — a surface that EXISTS ONLY WHEN CONFIGURED.
 *
 * From the contract's `dynamic_surfaces`: "CORS preflight exists only when an
 * Admin console allowed origin is configured." That conditional existence is
 * the security property, and it is what these tests hold. A gateway fronting no
 * admin console must not answer preflights at all — otherwise a browser can use
 * it as a CORS relay for the whole admin API.
 *
 * The naive port (mounting `hono/cors` unconditionally, or answering a
 * permissive 204 for every OPTIONS) passes a "preflight works" test and silently
 * widens the surface. So the first assertion here is the NEGATIVE one.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import {
  ADMIN_PREFLIGHT_PREFIX,
  PREFLIGHT_ALLOW_HEADERS,
  PREFLIGHT_ALLOW_METHODS,
  applyCorsHeaders,
} from "../src/middleware/cors.js";
import { BASE, arm, bearer, operatorKey } from "./harness.js";

const CONSOLE_ORIGIN = "https://console.ferrogate.test";

describe("with NO admin-console origin configured", () => {
  it("does not answer an admin preflight at all", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: null });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, { method: "OPTIONS" });
    // The contract documents no OPTIONS operation, so the request falls through
    // to normal routing: 405 for a documented path, never a permissive 204.
    expect(response.status).not.toBe(204);
    expect(response.status).toBe(405);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("attaches no CORS headers to ordinary responses", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: null });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("vary")).toBeNull();
  });
});

describe("with an admin-console origin configured", () => {
  it("answers the preflight with 204 and the Rust header set", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      method: "OPTIONS",
      headers: { origin: CONSOLE_ORIGIN, "access-control-request-method": "POST" },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
    expect(response.headers.get("access-control-allow-methods")).toBe(PREFLIGHT_ALLOW_METHODS);
    expect(response.headers.get("access-control-allow-headers")).toBe(PREFLIGHT_ALLOW_HEADERS);
    expect(response.headers.get("access-control-max-age")).toBe("600");
    expect(response.headers.get("vary")).toBe("origin");
  });

  it("answers the preflight WITHOUT requiring a credential", async () => {
    // A browser preflight never carries Authorization; challenging it would
    // break the console entirely.
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    const response = await SELF.fetch(`${BASE}/admin/v1/guardrail-policies`, { method: "OPTIONS" });
    expect(response.status).toBe(204);
  });

  it("attaches the CORS headers to ordinary responses too", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      headers: bearer(operatorKey.secret),
    });
    expect(response.headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
  });

  it("still refuses a cross-origin mutation from an origin that is NOT the console", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    const response = await SELF.fetch(`${BASE}/admin/v1/plans`, {
      method: "POST",
      headers: {
        ...bearer(operatorKey.secret),
        "content-type": "application/json",
        origin: "https://evil.test",
      },
      body: JSON.stringify({ id: "p_evil" }),
    });
    expect(response.status).toBe(403);
  });

  it("does NOT preflight bare /admin — the Rust prefix carries a trailing slash", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    expect(ADMIN_PREFLIGHT_PREFIX).toBe("/admin/");
    const response = await SELF.fetch(`${BASE}/admin`, { method: "OPTIONS" });
    expect(response.status).not.toBe(204);
  });

  it("does not preflight a non-admin path", async () => {
    arm({ staticKeys: [operatorKey], corsAllowedOrigin: CONSOLE_ORIGIN });
    const response = await SELF.fetch(`${BASE}/metrics`, { method: "OPTIONS" });
    expect(response.status).not.toBe(204);
  });
});

describe("applyCorsHeaders", () => {
  it("is a no-op with no configured origin", () => {
    const headers = new Headers();
    applyCorsHeaders(headers, null);
    expect([...headers.keys()]).toEqual([]);
  });

  it("sets origin + vary when configured", () => {
    const headers = new Headers();
    applyCorsHeaders(headers, CONSOLE_ORIGIN);
    expect(headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
    expect(headers.get("vary")).toBe("origin");
  });
});
