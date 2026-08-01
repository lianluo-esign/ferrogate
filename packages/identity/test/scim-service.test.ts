/**
 * SCIM 2.0 user/group provisioning semantics.
 *
 * Clean-room port of `crates/ferrogate-auth-service/src/scim.rs`
 * (issues #161 / #232 / #492 / #517). The load-bearing property throughout is
 * that EVERY read and EVERY write is fenced to the tenant the provisioning
 * token resolved to — the token is per-tenant, so a global effect from it is a
 * cross-tenant defect even when the caller is otherwise legitimate.
 */
import { beforeEach, describe, expect, test } from "vitest";
import { SCIM_PROVISION_SCOPE } from "../src/scim/auth.js";
import {
  type ScimDeps,
  mintScimToken,
  scimGroupsList,
  scimUserCreate,
  scimUserDelete,
  scimUserGet,
  scimUserPatch,
  scimUsersList,
} from "../src/scim/service.js";
import {
  CountingRandom,
  FakeClock,
  MemoryApiKeyAuthenticator,
  MemoryIdentityRepository,
} from "./memory-store.js";

const TENANT_A = "tenant_a";
const TENANT_B = "tenant_b";

interface Context {
  deps: ScimDeps;
  repo: MemoryIdentityRepository;
  keys: MemoryApiKeyAuthenticator;
  clock: FakeClock;
  session: { user: string; tenant: string; role: string } | null;
}

function context(): Context {
  const repo = new MemoryIdentityRepository();
  const keys = new MemoryApiKeyAuthenticator();
  const clock = new FakeClock(1_700_000_000);
  const state: Context = { repo, keys, clock, session: null, deps: undefined as never };
  state.deps = {
    repository: repo,
    apiKeys: keys,
    clock,
    random: new CountingRandom(),
    session: {
      currentAdminSession: async () => {
        if (!state.session) return null;
        const user = repo.users.get(state.session.user);
        if (!user) return null;
        return {
          user,
          membership: {
            id: "m",
            userId: state.session.user,
            tenantId: state.session.tenant,
            role: state.session.role,
            createdAtUnix: 1,
          },
        };
      },
      issueSession: async () => ({ accessToken: "at", refreshToken: "rt", expiresIn: 900 }),
      provisionGatewayApiKey: async () => "fg_key",
      mintVirtualApiKeySecret: async () => ({
        secret: "fg_scim_plaintext_secret",
        keyPrefix: "fg_scim",
        keyHash: "hash",
        last4: "cret",
      }),
    },
  };
  repo.tenants.set(TENANT_A, { id: TENANT_A, name: "A" });
  repo.tenants.set(TENANT_B, { id: TENANT_B, name: "B" });
  repo.workspaces.set(TENANT_A, { id: "ws_a", projectId: "proj_a", tenantId: TENANT_A });
  repo.workspaces.set(TENANT_B, { id: "ws_b", projectId: "proj_b", tenantId: TENANT_B });
  return state;
}

function seedUser(
  c: Context,
  id: string,
  email: string,
  tenants: { tenantId: string; role: string }[],
  disabledAtUnix: number | null = null,
) {
  c.repo.users.set(id, {
    id,
    email,
    displayName: email,
    passwordHash: "!",
    superadmin: false,
    createdAtUnix: 1,
    updatedAtUnix: 1,
    lastLoginAtUnix: null,
    disabledAtUnix,
  });
  for (const t of tenants) {
    c.repo.memberships.push({
      id: `m_${id}_${t.tenantId}`,
      userId: id,
      tenantId: t.tenantId,
      role: t.role,
      createdAtUnix: 1,
    });
  }
}

describe("SCIM Users — list", () => {
  let c: Context;
  beforeEach(() => {
    c = context();
    seedUser(c, "u_a1", "alice@example.com", [{ tenantId: TENANT_A, role: "admin" }]);
    seedUser(c, "u_a2", "carol@example.com", [{ tenantId: TENANT_A, role: "viewer" }]);
    seedUser(c, "u_b1", "bob@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
  });

  test("lists only THIS tenant's members", async () => {
    const response = await scimUsersList(c.deps, TENANT_A, {});
    expect(response.status).toBe(200);
    const body = response.body as { totalResults: number; Resources: { userName: string }[] };
    expect(body.totalResults).toBe(2);
    expect(body.Resources.map((r) => r.userName).sort()).toEqual([
      "alice@example.com",
      "carol@example.com",
    ]);
    // bob belongs to tenant B and must not be visible to a tenant-A token.
    expect(JSON.stringify(body)).not.toContain("bob@example.com");
  });

  test("emits the SCIM ListResponse envelope", async () => {
    const body = (await scimUsersList(c.deps, TENANT_A, {})).body as Record<string, unknown>;
    expect(body.schemas).toEqual(["urn:ietf:params:scim:api:messages:2.0:ListResponse"]);
    const first = (body.Resources as Record<string, unknown>[])[0];
    expect(first?.schemas).toEqual(["urn:ietf:params:scim:schemas:core:2.0:User"]);
    expect(first?.meta).toEqual({ resourceType: "User" });
  });

  test("applies a userName filter", async () => {
    const response = await scimUsersList(c.deps, TENANT_A, {
      filter: 'userName eq "alice@example.com"',
    });
    const body = response.body as { totalResults: number; Resources: { id: string }[] };
    expect(body.totalResults).toBe(1);
    expect(body.Resources[0]?.id).toBe("u_a1");
  });

  test("a filter naming a user in ANOTHER tenant returns nothing, not that user", async () => {
    const response = await scimUsersList(c.deps, TENANT_A, {
      filter: 'userName eq "bob@example.com"',
    });
    const body = response.body as { totalResults: number };
    expect(body.totalResults).toBe(0);
  });

  test("400 invalidFilter for an unparseable filter (never a full listing)", async () => {
    const response = await scimUsersList(c.deps, TENANT_A, { filter: 'userName zz "x"' });
    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({ scimType: "invalidFilter" });
  });

  test("startIndex/count paginate 1-based, and report the unpaged total", async () => {
    const response = await scimUsersList(c.deps, TENANT_A, { startIndex: 2, count: 1 });
    const body = response.body as {
      totalResults: number;
      itemsPerPage: number;
      startIndex: number;
      Resources: unknown[];
    };
    expect(body.totalResults).toBe(2);
    expect(body.startIndex).toBe(2);
    expect(body.itemsPerPage).toBe(1);
    expect(body.Resources).toHaveLength(1);
  });

  test("resolves a legacy role column to a real tier rather than echoing it", async () => {
    seedUser(c, "u_junk", "junk@example.com", [{ tenantId: TENANT_A, role: "superuser" }]);
    const body = (await scimUsersList(c.deps, TENANT_A, {})).body as {
      Resources: { userName: string; ferrogateRole: string }[];
    };
    const junk = body.Resources.find((r) => r.userName === "junk@example.com");
    expect(junk?.ferrogateRole).toBe("viewer");
  });
});

describe("SCIM Users — get", () => {
  let c: Context;
  beforeEach(() => {
    c = context();
    seedUser(c, "u_a1", "alice@example.com", [{ tenantId: TENANT_A, role: "admin" }]);
    seedUser(c, "u_b1", "bob@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
  });

  test("returns this tenant's member", async () => {
    const response = await scimUserGet(c.deps, TENANT_A, "u_a1");
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ id: "u_a1", userName: "alice@example.com" });
  });

  test("404 for a user that exists but belongs to ANOTHER tenant", async () => {
    const response = await scimUserGet(c.deps, TENANT_A, "u_b1");
    expect(response.status).toBe(404);
    // and the 404 body leaks nothing about the other tenant's user
    expect(JSON.stringify(response.body)).not.toContain("bob@example.com");
  });
});

describe("SCIM Users — create", () => {
  let c: Context;
  beforeEach(() => {
    c = context();
  });

  test("creates a user + membership under the token's tenant", async () => {
    const response = await scimUserCreate(c.deps, TENANT_A, {
      userName: "New.Person@Example.com",
      displayName: "New Person",
    });
    expect(response.status).toBe(201);
    const body = response.body as { id: string; userName: string; ferrogateRole: string };
    expect(body.userName).toBe("new.person@example.com");
    expect(body.ferrogateRole).toBe("member");
    expect(c.repo.memberships).toEqual([
      expect.objectContaining({ tenantId: TENANT_A, role: "member" }),
    ]);
  });

  test("honours the ferrogateRole extension", async () => {
    const response = await scimUserCreate(c.deps, TENANT_A, {
      userName: "a@example.com",
      ferrogateRole: "viewer",
    });
    expect(response.status).toBe(201);
    expect(c.repo.memberships[0]?.role).toBe("viewer");
  });

  test("REFUSES an unknown ferrogateRole rather than storing it", async () => {
    const response = await scimUserCreate(c.deps, TENANT_A, {
      userName: "a@example.com",
      ferrogateRole: "superuser",
    });
    expect(response.status).toBe(422);
    expect(c.repo.memberships).toHaveLength(0);
    expect(c.repo.users.size).toBe(0);
  });

  test("REFUSES a non-email userName", async () => {
    const response = await scimUserCreate(c.deps, TENANT_A, { userName: "not-an-email" });
    expect(response.status).toBe(422);
    expect(c.repo.users.size).toBe(0);
  });

  test("attaches a membership to an existing account WITHOUT touching its other tenants", async () => {
    seedUser(c, "u_b1", "shared@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
    const response = await scimUserCreate(c.deps, TENANT_A, {
      userName: "shared@example.com",
      ferrogateRole: "viewer",
    });
    expect(response.status).toBe(201);
    const tenantB = c.repo.memberships.find((m) => m.tenantId === TENANT_B);
    expect(tenantB?.role).toBe("owner");
    const tenantA = c.repo.memberships.find((m) => m.tenantId === TENANT_A);
    expect(tenantA?.role).toBe("viewer");
  });

  test("never creates a tenant/project/workspace", async () => {
    const before = c.repo.tenants.size;
    await scimUserCreate(c.deps, TENANT_A, { userName: "a@example.com" });
    expect(c.repo.tenants.size).toBe(before);
  });

  test("active:false at create deprovisions in this tenant only", async () => {
    seedUser(c, "u_b1", "shared@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
    const response = await scimUserCreate(c.deps, TENANT_A, {
      userName: "shared@example.com",
      active: false,
    });
    expect(response.status).toBe(201);
    expect((response.body as { active: boolean }).active).toBe(false);
    // Still enabled globally, because tenant B still holds them.
    expect(c.repo.users.get("u_b1")?.disabledAtUnix).toBeNull();
    expect(c.repo.revocations.allRefreshTokens).toHaveLength(0);
  });
});

describe("SCIM Users — deprovisioning (issue #232)", () => {
  let c: Context;
  beforeEach(() => {
    c = context();
  });

  test("DELETE of a multi-tenant user removes ONLY this tenant's membership", async () => {
    seedUser(c, "u_shared", "shared@example.com", [
      { tenantId: TENANT_A, role: "member" },
      { tenantId: TENANT_B, role: "owner" },
    ]);
    const response = await scimUserDelete(c.deps, TENANT_A, "u_shared");
    expect(response.status).toBe(204);
    expect(c.repo.memberships.map((m) => m.tenantId)).toEqual([TENANT_B]);
    // The GLOBAL account is untouched: this is the cross-tenant DoS #232 fixed.
    expect(c.repo.users.get("u_shared")?.disabledAtUnix).toBeNull();
    expect(c.repo.revocations.allRefreshTokens).toHaveLength(0);
    expect(c.repo.revocations.tenantRefreshTokens).toEqual([
      { userId: "u_shared", tenantId: TENANT_A },
    ]);
  });

  test("DELETE also revokes the tenant's console-session GATEWAY KEYS, not just tokens", async () => {
    seedUser(c, "u_shared", "shared@example.com", [
      { tenantId: TENANT_A, role: "member" },
      { tenantId: TENANT_B, role: "owner" },
    ]);
    await scimUserDelete(c.deps, TENANT_A, "u_shared");
    // #517: a deprovisioned user holding a live `admin.write` gateway key is
    // still an admin of the tenant that just removed them.
    expect(c.repo.revocations.sessionKeys).toEqual([{ userId: "u_shared", tenantId: TENANT_A }]);
  });

  test("DELETE of a LAST membership disables the account globally and keeps the row", async () => {
    seedUser(c, "u_only", "only@example.com", [{ tenantId: TENANT_A, role: "member" }]);
    const response = await scimUserDelete(c.deps, TENANT_A, "u_only");
    expect(response.status).toBe(204);
    expect(c.repo.users.get("u_only")?.disabledAtUnix).toBe(c.clock.nowUnix());
    expect(c.repo.revocations.allRefreshTokens).toEqual(["u_only"]);
    // The membership is KEPT so a later PATCH active:true can reactivate.
    expect(c.repo.memberships.map((m) => m.tenantId)).toEqual([TENANT_A]);
  });

  test("404 when the target is not a member of this tenant — and nothing is revoked", async () => {
    seedUser(c, "u_b1", "bob@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
    const response = await scimUserDelete(c.deps, TENANT_A, "u_b1");
    expect(response.status).toBe(404);
    expect(c.repo.memberships).toHaveLength(1);
    expect(c.repo.users.get("u_b1")?.disabledAtUnix).toBeNull();
    expect(c.repo.revocations.tenantRefreshTokens).toHaveLength(0);
    expect(c.repo.revocations.sessionKeys).toHaveLength(0);
    expect(c.repo.revocations.allRefreshTokens).toHaveLength(0);
  });

  test("PATCH active:false is equally tenant-scoped", async () => {
    seedUser(c, "u_shared", "shared@example.com", [
      { tenantId: TENANT_A, role: "member" },
      { tenantId: TENANT_B, role: "owner" },
    ]);
    const response = await scimUserPatch(c.deps, TENANT_A, "u_shared", { active: false });
    expect(response.status).toBe(200);
    expect((response.body as { active: boolean }).active).toBe(false);
    expect(c.repo.users.get("u_shared")?.disabledAtUnix).toBeNull();
    expect(c.repo.memberships.map((m) => m.tenantId)).toEqual([TENANT_B]);
  });

  test("PATCH understands the standards-shaped Operations body", async () => {
    seedUser(c, "u_only", "only@example.com", [{ tenantId: TENANT_A, role: "member" }]);
    const response = await scimUserPatch(c.deps, TENANT_A, "u_only", {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "active", value: false }],
    });
    expect(response.status).toBe(200);
    expect(c.repo.users.get("u_only")?.disabledAtUnix).toBe(c.clock.nowUnix());
  });

  test("PATCH active:true reactivates", async () => {
    seedUser(c, "u_only", "only@example.com", [{ tenantId: TENANT_A, role: "member" }], 42);
    const response = await scimUserPatch(c.deps, TENANT_A, "u_only", { active: true });
    expect(response.status).toBe(200);
    expect(c.repo.users.get("u_only")?.disabledAtUnix).toBeNull();
    expect((response.body as { active: boolean }).active).toBe(true);
  });

  test("PATCH on ANOTHER tenant's user is a 404 with no side effect", async () => {
    seedUser(c, "u_b1", "bob@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
    const response = await scimUserPatch(c.deps, TENANT_A, "u_b1", { active: false });
    expect(response.status).toBe(404);
    expect(c.repo.users.get("u_b1")?.disabledAtUnix).toBeNull();
    expect(c.repo.memberships).toHaveLength(1);
    expect(c.repo.revocations.tenantRefreshTokens).toHaveLength(0);
  });

  test("422 when the PATCH body carries no determinable active value", async () => {
    seedUser(c, "u_only", "only@example.com", [{ tenantId: TENANT_A, role: "member" }]);
    const response = await scimUserPatch(c.deps, TENANT_A, "u_only", {
      Operations: [{ op: "replace", path: "displayName", value: "x" }],
    });
    expect(response.status).toBe(422);
    expect(c.repo.users.get("u_only")?.disabledAtUnix).toBeNull();
  });
});

describe("SCIM Groups", () => {
  test("lists this tenant's in-use tiers as resolved groups", async () => {
    const c = context();
    seedUser(c, "u1", "a@example.com", [{ tenantId: TENANT_A, role: "admin" }]);
    seedUser(c, "u2", "b@example.com", [{ tenantId: TENANT_A, role: "superuser" }]);
    seedUser(c, "u3", "c@example.com", [{ tenantId: TENANT_A, role: "admin" }]);
    seedUser(c, "u4", "d@example.com", [{ tenantId: TENANT_B, role: "owner" }]);
    const body = (await scimGroupsList(c.deps, TENANT_A, {})).body as {
      totalResults: number;
      Resources: { id: string; displayName: string }[];
    };
    // `superuser` is not a tier: it resolves to viewer, and tenant B's `owner`
    // is not visible here at all.
    expect(body.Resources.map((r) => r.id)).toEqual(["admin", "viewer"]);
    expect(body.totalResults).toBe(2);
  });

  test("400 invalidFilter on an unparseable group filter", async () => {
    const c = context();
    const response = await scimGroupsList(c.deps, TENANT_A, { filter: "((" });
    expect(response.status).toBe(400);
  });
});

describe("mintScimToken", () => {
  let c: Context;
  beforeEach(() => {
    c = context();
    seedUser(c, "u_owner", "owner@example.com", [{ tenantId: TENANT_A, role: "owner" }]);
  });

  test("only a tenant owner may mint", async () => {
    c.session = { user: "u_owner", tenant: TENANT_A, role: "admin" };
    expect((await mintScimToken(c.deps, "session")).status).toBe(403);
    c.session = { user: "u_owner", tenant: TENANT_A, role: "member" };
    expect((await mintScimToken(c.deps, "session")).status).toBe(403);
    c.session = { user: "u_owner", tenant: TENANT_A, role: "owner" };
    expect((await mintScimToken(c.deps, "session")).status).toBe(201);
  });

  test("401 without a session", async () => {
    c.session = null;
    expect((await mintScimToken(c.deps, "session")).status).toBe(401);
  });

  test("mints a key carrying ONLY scim.provision, scoped to the caller's tenant", async () => {
    c.session = { user: "u_owner", tenant: TENANT_A, role: "owner" };
    const response = await mintScimToken(c.deps, "session");
    expect(response.status).toBe(201);
    expect(response.body).toEqual({ token: "fg_scim_plaintext_secret" });
    expect(c.repo.apiKeys).toHaveLength(1);
    const key = c.repo.apiKeys[0];
    expect(key?.scopes).toEqual([SCIM_PROVISION_SCOPE]);
    expect(key?.tenantId).toBe(TENANT_A);
    // The plaintext secret is never persisted — only its hash.
    expect(JSON.stringify(key)).not.toContain("fg_scim_plaintext_secret");
  });

  test("a suspended tenancy cannot mint a new long-lived credential", async () => {
    c.session = { user: "u_owner", tenant: TENANT_A, role: "owner" };
    c.repo.suspendedTenants.add(TENANT_A);
    const response = await mintScimToken(c.deps, "session");
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(c.repo.apiKeys).toHaveLength(0);
  });
});
