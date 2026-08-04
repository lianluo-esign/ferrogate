import { describe, expect, it } from "vitest";

import {
  PREFLIGHT_ALLOW_HEADERS,
  PREFLIGHT_ALLOW_METHODS,
  PREFLIGHT_MAX_AGE,
  applyCorsHeaders,
} from "../src/middleware/cors.js";
import { createGatewayApp } from "../src/routes/index.js";

const BASE = "https://gateway.test";
const CONSOLE_ORIGIN = "https://console.ferrogate.test";

function request(
  path: string,
  init: RequestInit = {},
  env: Record<string, string> = {},
): Promise<Response> {
  const { app } = createGatewayApp();
  return Promise.resolve(app.request(`${BASE}${path}`, init, env));
}

describe("gateway CORS", () => {
  it("is inert when no console origin is configured", async () => {
    const response = await request("/v1/assets", {
      method: "OPTIONS",
      headers: { Origin: CONSOLE_ORIGIN },
    });
    expect(response.status).not.toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();

    const ordinary = await request("/healthz");
    expect(ordinary.status).toBe(200);
    expect(ordinary.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("answers a matching preflight without requiring a gateway credential", async () => {
    const response = await request(
      "/v1/assets/static_site/site-a/versions/v1",
      {
        method: "OPTIONS",
        headers: {
          Origin: CONSOLE_ORIGIN,
          "Access-Control-Request-Method": "PUT",
          "Access-Control-Request-Headers": "authorization, content-type, x-site-public",
        },
      },
      { GATEWAY_CORS_ALLOWED_ORIGIN: CONSOLE_ORIGIN },
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
    expect(response.headers.get("access-control-allow-methods")).toBe(PREFLIGHT_ALLOW_METHODS);
    expect(response.headers.get("access-control-allow-headers")).toBe(PREFLIGHT_ALLOW_HEADERS);
    expect(response.headers.get("access-control-max-age")).toBe(PREFLIGHT_MAX_AGE);
    expect(response.headers.get("content-length")).toBe("0");
    expect(response.headers.get("vary")).toBe("origin");
  });

  it("adds CORS headers to ordinary gateway responses for the matching origin", async () => {
    const response = await request(
      "/healthz",
      { headers: { Origin: CONSOLE_ORIGIN } },
      { GATEWAY_CORS_ALLOWED_ORIGIN: CONSOLE_ORIGIN },
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
    expect(response.headers.get("vary")).toBe("origin");
  });

  it("adds CORS headers to an authentication refusal", async () => {
    const response = await request(
      "/metrics",
      { headers: { Origin: CONSOLE_ORIGIN } },
      { GATEWAY_CORS_ALLOWED_ORIGIN: CONSOLE_ORIGIN },
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
    expect(response.headers.get("vary")).toBe("origin");
  });

  it("does not grant a mismatched origin a preflight or response header", async () => {
    const response = await request(
      "/healthz",
      { headers: { Origin: "https://evil.test" } },
      { GATEWAY_CORS_ALLOWED_ORIGIN: CONSOLE_ORIGIN },
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();

    const preflight = await request(
      "/v1/assets",
      { method: "OPTIONS", headers: { Origin: "https://evil.test" } },
      { GATEWAY_CORS_ALLOWED_ORIGIN: CONSOLE_ORIGIN },
    );
    expect(preflight.status).not.toBe(204);
  });
});

describe("applyCorsHeaders", () => {
  it("merges Origin into an existing cache variation contract", () => {
    const headers = new Headers({ vary: "authorization, x-api-key" });
    applyCorsHeaders(headers, CONSOLE_ORIGIN, CONSOLE_ORIGIN);
    expect(headers.get("vary")).toBe("authorization, x-api-key, origin");
    expect(headers.get("access-control-allow-origin")).toBe(CONSOLE_ORIGIN);
  });

  it("does nothing when CORS is disabled and withholds access for a mismatch", () => {
    const headers = new Headers();
    applyCorsHeaders(headers, null, CONSOLE_ORIGIN);
    applyCorsHeaders(headers, CONSOLE_ORIGIN, "https://evil.test");
    expect(headers.get("access-control-allow-origin")).toBeNull();
    expect(headers.get("vary")).toBe("origin");
  });
});
