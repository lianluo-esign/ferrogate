/**
 * `D1AdminConsoleSessionStore.bootstrapLoginByEmail` — the ONE-round-trip JOIN
 * that folds `getUserByEmail` + `listMembershipsByUser` for the <1s login path.
 *
 * The end-to-end login/refresh suite (`console-session.test.ts`) already drives
 * this method through the routes; what is pinned HERE in isolation is the one
 * genuinely new behaviour the merge introduces — a single `LEFT JOIN` that must:
 *
 *  1. return `null` for an unknown email (indistinguishable from wrong password);
 *  2. return the user with an EMPTY membership list when they have none (the
 *     `LEFT JOIN`'s all-NULL `m_*` row must be dropped, not decoded);
 *  3. return memberships OLDEST FIRST by `created_at_unix, id` — the same
 *     load-bearing order `listMembershipsByUser` guaranteed, so `memberships[0]`
 *     (the tenant login stamps) is stable even when insertion order and
 *     `created_at` disagree.
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

describe("bootstrapLoginByEmail", () => {
  beforeAll(applySchema);
  beforeEach(resetD1);

  it("returns null for an unknown email", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    expect(await store.bootstrapLoginByEmail("nobody@acme.test")).toBeNull();
  });

  it("returns the user with an EMPTY membership list when they have none", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user());

    const result = await store.bootstrapLoginByEmail("person@acme.test");
    expect(result).not.toBeNull();
    expect(result?.user.id).toBe("user-1");
    expect(result?.user.passwordHash).toBe("pbkdf2$100000$aa$bb");
    expect(result?.memberships).toEqual([]);
  });

  it("returns memberships OLDEST FIRST even when insertion order disagrees with created_at", async () => {
    const store = new D1AdminConsoleSessionStore(db());
    await store.upsertUser(user());
    // Insert the NEWER membership first, the OLDER one second: a naive read in
    // insertion order would put tenant-b at [0] and login would stamp the wrong
    // tenant/tier.
    await store.upsertMembership(
      membership({ id: "mem-b", tenantId: "tenant-b", role: "member", createdAtUnix: 2000 }),
    );
    await store.upsertMembership(
      membership({ id: "mem-a", tenantId: "tenant-a", role: "owner", createdAtUnix: 1000 }),
    );

    const result = await store.bootstrapLoginByEmail("person@acme.test");
    expect(result?.memberships.map((m) => m.tenantId)).toEqual(["tenant-a", "tenant-b"]);
    // `memberships[0]` — the tenant login stamps — is the oldest.
    expect(result?.memberships[0]?.tenantId).toBe("tenant-a");
    expect(result?.memberships[0]?.role).toBe("owner");
  });
});
