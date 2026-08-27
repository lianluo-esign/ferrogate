/**
 * `D1AdminConsoleSessionStore.listTenantOwnerEmails` — the batched owner-or-oldest
 * email projection that `tenant-accounts` hangs on its list rows so operators read
 * a human, not a `tenant-…` opaque id.
 *
 * The contract pinned here:
 *
 *  1. an empty `tenantIds` returns an empty map WITHOUT touching the database
 *     (the fail-safe the enrich hook relies on when there is nothing to enrich);
 *  2. the `owner`-role membership wins even when a NON-owner membership is older —
 *     "representative" means owner-first, oldest-only-as-fallback;
 *  3. with no owner, the OLDEST membership by `created_at_unix, id` supplies the
 *     email (the founding member), the same load-bearing tiebreak login uses;
 *  4. a tenant with no membership at all is simply ABSENT from the map (caller
 *     leaves that row's email null) — never a null/empty entry;
 *  5. many tenants resolve in one call.
 *
 * (Ownership is resolved fail-closed via `membershipRoleFromStored`, so a
 * legacy/hostile `"Owner"` could never win — but the `role` CHECK on
 * `admin_user_tenant_memberships` refuses to STORE a non-canonical role in the
 * first place, so that guard is exercised where it lives: `membership_role`'s
 * own unit tests.)
 */
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { AdminMembershipRow, AdminUserRow } from "../src/session/store.js";
import { D1AdminConsoleSessionStore } from "../src/session/store.js";
import { applySchema, db, resetD1 } from "./d1.js";

function user(overrides: Partial<AdminUserRow> = {}): AdminUserRow {
  return {
    id: "user-1",
    email: "person@acme.test",
    passwordHash: "pbkdf2$100000$aa$bb",
    displayName: "Person",
    superadmin: false,
    createdAtUnix: 1000,
    updatedAtUnix: 1000,
    lastLoginAtUnix: null,
    disabledAtUnix: null,
    ...overrides,
  };
}

function membership(overrides: Partial<AdminMembershipRow> = {}): AdminMembershipRow {
  return {
    id: "mem-1",
    userId: "user-1",
    tenantId: "tenant-a",
    role: "admin",
    createdAtUnix: 1000,
    ...overrides,
  };
}

describe("listTenantOwnerEmails", () => {
  beforeAll(applySchema);
  beforeEach(resetD1);

  it("returns an empty map for an empty id list (no DB read)", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    const result = await store.listTenantOwnerEmails([]);
    expect(result.size).toBe(0);
  });

  it("prefers the owner even when a non-owner membership is older", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user({ id: "admin-user", email: "admin@acme.test" }));
    await store.upsertUser(user({ id: "owner-user", email: "owner@acme.test" }));
    // The admin bound FIRST (older); the owner bound later. Owner still wins.
    await store.upsertMembership(
      membership({ id: "m-admin", userId: "admin-user", tenantId: "tenant-a", role: "admin", createdAtUnix: 1000 }),
    );
    await store.upsertMembership(
      membership({ id: "m-owner", userId: "owner-user", tenantId: "tenant-a", role: "owner", createdAtUnix: 2000 }),
    );

    const result = await store.listTenantOwnerEmails(["tenant-a"]);
    expect(result.get("tenant-a")).toBe("owner@acme.test");
  });

  it("falls back to the OLDEST membership when there is no owner", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user({ id: "early-user", email: "early@acme.test" }));
    await store.upsertUser(user({ id: "late-user", email: "late@acme.test" }));
    await store.upsertMembership(
      membership({ id: "m-late", userId: "late-user", tenantId: "tenant-a", role: "member", createdAtUnix: 2000 }),
    );
    await store.upsertMembership(
      membership({ id: "m-early", userId: "early-user", tenantId: "tenant-a", role: "admin", createdAtUnix: 1000 }),
    );

    const result = await store.listTenantOwnerEmails(["tenant-a"]);
    expect(result.get("tenant-a")).toBe("early@acme.test");
  });

  it("omits tenants that have no membership", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user({ id: "u", email: "u@acme.test" }));
    await store.upsertMembership(membership({ id: "m", userId: "u", tenantId: "tenant-a" }));

    const result = await store.listTenantOwnerEmails(["tenant-a", "tenant-empty"]);
    expect(result.get("tenant-a")).toBe("u@acme.test");
    expect(result.has("tenant-empty")).toBe(false);
  });

  it("resolves many tenants in one call", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user({ id: "ua", email: "a@acme.test" }));
    await store.upsertUser(user({ id: "ub", email: "b@acme.test" }));
    await store.upsertMembership(
      membership({ id: "ma", userId: "ua", tenantId: "tenant-a", role: "owner", createdAtUnix: 1000 }),
    );
    await store.upsertMembership(
      membership({ id: "mb", userId: "ub", tenantId: "tenant-b", role: "owner", createdAtUnix: 1000 }),
    );

    const result = await store.listTenantOwnerEmails(["tenant-a", "tenant-b", "tenant-a"]);
    expect(result.get("tenant-a")).toBe("a@acme.test");
    expect(result.get("tenant-b")).toBe("b@acme.test");
    expect(result.size).toBe(2);
  });
});
