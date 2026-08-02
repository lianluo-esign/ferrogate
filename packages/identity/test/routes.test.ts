/**
 * The MOUNT SEAM: the Hono sub-app a composition root mounts to expose
 * `/scim/v2/*`, `/v1/admin/team/scim-token` and the two OIDC legs.
 *
 * `IDENTITY_ROUTES` is the value `createIdentityRoutes` reports for the app it
 * actually built — one entry per `app.on(...)` it performed — so the coverage
 * assertion below inspects what the factory DID, not a restatement of a wish
 * list. Asserting against a hand-written table is exactly how `apps/gateway`
 * shipped with 24 of 31 operations unreachable while every suite stayed green.
 */
import { describe, expect, test } from "vitest";
import { JwksCache } from "../src/oidc/jwks.js";
import { createIdentityRoutes } from "../src/routes.js";
import type { IdentityDeps } from "../src/routes.js";
import { SCIM_PROVISION_SCOPE } from "../src/scim/auth.js";
import {
  CountingRandom,
  FakeClock,
  MemoryApiKeyAuthenticator,
  MemoryIdentityRepository,
} from "./memory-store.js";

const TENANT = "tenant_a";

function build() {
  const repo = new MemoryIdentityRepository();
  const keys = new MemoryApiKeyAuthenticator();
  const clock = new FakeClock(1_700_000_000);
  const fetchLike = async () => new Response("{}", { status: 200 });
  const deps: IdentityDeps = {
    repository: repo,
    apiKeys: keys,
    secrets: { resolve: async () => "secret" },
    session: {
      currentAdminSession: async () => null,
      issueSession: async () => ({ accessToken: "at", refreshToken: "rt", expiresIn: 900 }),
      provisionGatewayApiKey: async () => "fg_key",
      mintVirtualApiKeySecret: async () => ({
        secret: "s",
        keyPrefix: "p",
        keyHash: "h",
        last4: "1234",
      }),
    },
    clock,
    random: new CountingRandom(),
    fetch: fetchLike,
    jwks: new JwksCache({ fetch: fetchLike, clock }),
  };
  keys.keys.set("scim_a", {
    apiKeyId: "k1",
    scopes: [SCIM_PROVISION_SCOPE],
    tenant: { organizationId: TENANT, projectId: "p", workspaceId: "w" },
  });
  repo.tenants.set(TENANT, { id: TENANT, name: "A" });
  repo.workspaces.set(TENANT, { id: "w", projectId: "p", tenantId: TENANT });
  const app = createIdentityRoutes(() => deps);
  return { app, repo, keys, deps };
}

/** Every SCIM route, as (method, path) — the surface the bearer gate must cover. */
const SCIM_ROUTES: [string, string][] = [
  ["GET", "/scim/v2/Users"],
  ["POST", "/scim/v2/Users"],
  ["GET", "/scim/v2/Users/u1"],
  ["PATCH", "/scim/v2/Users/u1"],
  ["PUT", "/scim/v2/Users/u1"],
  ["DELETE", "/scim/v2/Users/u1"],
  ["GET", "/scim/v2/Groups"],
];

describe("identity route mount", () => {
  test("mounts every SCIM + OIDC route", () => {
    const { app } = build();
    const mounted = new Set(
      (app as unknown as { identityRoutes: { method: string; path: string }[] }).identityRoutes.map(
        (r) => `${r.method} ${r.path}`,
      ),
    );
    expect(mounted).toContain("POST /v1/admin/team/scim-token");
    expect(mounted).toContain("GET /v1/admin/auth/sso/authorize");
    expect(mounted).toContain("GET /v1/admin/auth/sso/callback");
    expect(mounted).toContain("GET /scim/v2/Users");
    expect(mounted).toContain("POST /scim/v2/Users");
    expect(mounted).toContain("GET /scim/v2/Groups");
    expect(mounted).toContain("GET /scim/v2/Users/:id");
    expect(mounted).toContain("PATCH /scim/v2/Users/:id");
    expect(mounted).toContain("PUT /scim/v2/Users/:id");
    expect(mounted).toContain("DELETE /scim/v2/Users/:id");
  });

  test("EVERY SCIM route rejects an anonymous request", async () => {
    const { app } = build();
    for (const [method, path] of SCIM_ROUTES) {
      const response = await app.request(`https://cp.test${path}`, {
        method,
        ...(method === "POST" || method === "PATCH" || method === "PUT"
          ? { body: "{}", headers: { "content-type": "application/json" } }
          : {}),
      });
      expect(response.status, `${method} ${path} must be guarded`).toBe(401);
    }
  });

  test("EVERY SCIM route rejects a key without the scim.provision scope", async () => {
    const { app, keys } = build();
    keys.keys.set("admin_key", {
      apiKeyId: "k2",
      scopes: ["admin.read", "admin.write"],
      tenant: { organizationId: TENANT, projectId: "p", workspaceId: "w" },
    });
    for (const [method, path] of SCIM_ROUTES) {
      const response = await app.request(`https://cp.test${path}`, {
        method,
        headers: { authorization: "Bearer admin_key", "content-type": "application/json" },
        ...(method === "POST" || method === "PATCH" || method === "PUT" ? { body: "{}" } : {}),
      });
      expect(response.status, `${method} ${path} must require scim.provision`).toBe(403);
    }
  });

  test("a scoped token reaches the handler and sees only its tenant", async () => {
    const { app, repo } = build();
    repo.users.set("u_a", {
      id: "u_a",
      email: "a@example.com",
      displayName: "A",
      passwordHash: "!",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: null,
    });
    repo.memberships.push({
      id: "m",
      userId: "u_a",
      tenantId: TENANT,
      role: "member",
      createdAtUnix: 1,
    });
    repo.users.set("u_b", {
      id: "u_b",
      email: "b@example.com",
      displayName: "B",
      passwordHash: "!",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: null,
    });
    repo.memberships.push({
      id: "m2",
      userId: "u_b",
      tenantId: "tenant_b",
      role: "owner",
      createdAtUnix: 1,
    });
    const response = await app.request("https://cp.test/scim/v2/Users", {
      headers: { authorization: "Bearer scim_a" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/scim+json");
    const body = (await response.json()) as { totalResults: number };
    expect(body.totalResults).toBe(1);
  });

  test("the ?filter query parameter reaches the service", async () => {
    const { app, repo } = build();
    repo.users.set("u_a", {
      id: "u_a",
      email: "a@example.com",
      displayName: "A",
      passwordHash: "!",
      superadmin: false,
      createdAtUnix: 1,
      updatedAtUnix: 1,
      lastLoginAtUnix: null,
      disabledAtUnix: null,
    });
    repo.memberships.push({
      id: "m",
      userId: "u_a",
      tenantId: TENANT,
      role: "member",
      createdAtUnix: 1,
    });
    const hit = await app.request(
      `https://cp.test/scim/v2/Users?filter=${encodeURIComponent('userName eq "a@example.com"')}`,
      { headers: { authorization: "Bearer scim_a" } },
    );
    expect(((await hit.json()) as { totalResults: number }).totalResults).toBe(1);
    const miss = await app.request(
      `https://cp.test/scim/v2/Users?filter=${encodeURIComponent('userName eq "nobody@x.test"')}`,
      { headers: { authorization: "Bearer scim_a" } },
    );
    expect(((await miss.json()) as { totalResults: number }).totalResults).toBe(0);
  });

  test("a malformed JSON body is a 400, not a 500", async () => {
    const { app } = build();
    const response = await app.request("https://cp.test/scim/v2/Users", {
      method: "POST",
      headers: { authorization: "Bearer scim_a", "content-type": "application/json" },
      body: "{not json",
    });
    expect(response.status).toBe(400);
  });

  test("the scim-token mint route requires an admin session", async () => {
    const { app } = build();
    const response = await app.request("https://cp.test/v1/admin/team/scim-token", {
      method: "POST",
    });
    expect(response.status).toBe(401);
  });

  test("the OIDC authorize leg is anonymous but 404s an unconfigured tenant", async () => {
    const { app } = build();
    const response = await app.request(
      `https://cp.test/v1/admin/auth/sso/authorize?tenant_id=${TENANT}`,
    );
    expect(response.status).toBe(404);
  });

  test("the OIDC authorize leg refuses a request with no tenant_id", async () => {
    const { app } = build();
    const response = await app.request("https://cp.test/v1/admin/auth/sso/authorize");
    expect(response.status).toBe(422);
  });

  test("the OIDC callback leg refuses a missing code or state", async () => {
    const { app } = build();
    expect((await app.request("https://cp.test/v1/admin/auth/sso/callback")).status).toBe(422);
    expect((await app.request("https://cp.test/v1/admin/auth/sso/callback?code=c")).status).toBe(
      422,
    );
    expect((await app.request("https://cp.test/v1/admin/auth/sso/callback?state=s")).status).toBe(
      422,
    );
  });

  test("an unknown state on the callback leg is a 401", async () => {
    const { app } = build();
    const response = await app.request(
      "https://cp.test/v1/admin/auth/sso/callback?code=c&state=forged",
    );
    expect(response.status).toBe(401);
  });
});
