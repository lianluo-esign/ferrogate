/**
 * SCIM AUTHORIZATION — the property that decides whether a leaked provisioning
 * token is a directory-sync credential or a cross-tenant admin takeover.
 *
 * Clean-room port of `resolve_scim_tenant` (`scim.rs`), issues #161 / #232.
 */
import { beforeEach, describe, expect, test } from "vitest";
import { SCIM_PROVISION_SCOPE, resolveScimTenant } from "../src/scim/auth.js";
import type { ScimDeps } from "../src/scim/service.js";
import {
  CountingRandom,
  FakeClock,
  MemoryApiKeyAuthenticator,
  MemoryIdentityRepository,
} from "./memory-store.js";

const TENANT_A = "tenant_a";
const TENANT_B = "tenant_b";

function deps(): {
  deps: ScimDeps;
  repo: MemoryIdentityRepository;
  keys: MemoryApiKeyAuthenticator;
} {
  const repo = new MemoryIdentityRepository();
  const keys = new MemoryApiKeyAuthenticator();
  return {
    repo,
    keys,
    deps: {
      repository: repo,
      apiKeys: keys,
      clock: new FakeClock(1_700_000_000),
      random: new CountingRandom(),
      session: {
        currentAdminSession: async () => null,
        issueSession: async () => ({ accessToken: "at", refreshToken: "rt", expiresIn: 900 }),
        provisionGatewayApiKey: async () => "fg_key",
        mintVirtualApiKeySecret: async () => ({
          secret: "fg_scim_secret",
          keyPrefix: "fg_scim",
          keyHash: "hash",
          last4: "cret",
        }),
      },
    },
  };
}

describe("resolveScimTenant", () => {
  let context: ReturnType<typeof deps>;
  beforeEach(() => {
    context = deps();
    context.keys.keys.set("scim_a", {
      apiKeyId: "scim_1",
      scopes: [SCIM_PROVISION_SCOPE],
      tenant: { organizationId: TENANT_A, projectId: "proj_a", workspaceId: "ws_a" },
    });
  });

  test("resolves the tenant stamped on the token", async () => {
    const result = await resolveScimTenant(context.deps, "scim_a");
    expect(result).toEqual({ ok: true, tenantId: TENANT_A });
  });

  test("401 with no bearer token", async () => {
    expect(await resolveScimTenant(context.deps, null)).toMatchObject({
      ok: false,
      response: { status: 401 },
    });
    expect(await resolveScimTenant(context.deps, "")).toMatchObject({
      ok: false,
      response: { status: 401 },
    });
  });

  test("401 for a token the directory does not know", async () => {
    expect(await resolveScimTenant(context.deps, "not-a-key")).toMatchObject({
      ok: false,
      response: { status: 401 },
    });
  });

  test("403 for a valid key that lacks the scim.provision scope", async () => {
    context.keys.keys.set("admin_key", {
      apiKeyId: "k2",
      // A full-authority console key — deliberately the MOST privileged key in
      // the system. SCIM is a separate credential class; `admin.write` must not
      // be a way into the provisioning surface.
      scopes: ["admin.read", "admin.write", "assets.read", "assets.write"],
      tenant: { organizationId: TENANT_A, projectId: "proj_a", workspaceId: "ws_a" },
    });
    expect(await resolveScimTenant(context.deps, "admin_key")).toMatchObject({
      ok: false,
      response: { status: 403 },
    });
  });

  test("scope matching is exact — a prefix or superstring does not pass", async () => {
    for (const scope of ["scim", "scim.provisioning", "scim.provision.extra", "SCIM.PROVISION"]) {
      context.keys.keys.set("weird", {
        apiKeyId: "k3",
        scopes: [scope],
        tenant: { organizationId: TENANT_A, projectId: "proj_a", workspaceId: "ws_a" },
      });
      expect(
        await resolveScimTenant(context.deps, "weird"),
        `scope ${scope} must not pass`,
      ).toMatchObject({ ok: false, response: { status: 403 } });
    }
  });

  test("fails closed when the token carries no tenant scope", async () => {
    context.keys.keys.set("untenanted", {
      apiKeyId: "k4",
      scopes: [SCIM_PROVISION_SCOPE],
      tenant: { organizationId: null, projectId: null, workspaceId: null },
    });
    const result = await resolveScimTenant(context.deps, "untenanted");
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.response.status).toBeGreaterThanOrEqual(400);
  });

  test("REFUSES a token whose tenancy is suspended", async () => {
    context.repo.suspendedTenants.add(TENANT_A);
    expect(await resolveScimTenant(context.deps, "scim_a")).toMatchObject({ ok: false });
  });

  test("a tenant-A token NEVER resolves to tenant B", async () => {
    context.keys.keys.set("scim_b", {
      apiKeyId: "scim_2",
      scopes: [SCIM_PROVISION_SCOPE],
      tenant: { organizationId: TENANT_B, projectId: "proj_b", workspaceId: "ws_b" },
    });
    expect(await resolveScimTenant(context.deps, "scim_a")).toEqual({
      ok: true,
      tenantId: TENANT_A,
    });
    expect(await resolveScimTenant(context.deps, "scim_b")).toEqual({
      ok: true,
      tenantId: TENANT_B,
    });
  });
});
