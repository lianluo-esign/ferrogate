/**
 * Phase B (#66, login leg): the KV PROJECTION of the login bootstrap that lets
 * `POST /v1/admin/login` resolve its first control read from a replicated KV read
 * instead of a cross-region RPC to the single-region control object.
 *
 * This file pins the PURE layer — {@link KvAdminIdentityProjection} over a fake KV,
 * no `workerd`, no real binding — where the fail-closed guarantees the slice must
 * hold are asserted directly at the seam:
 *
 *  (a) ROUND TRIP — a written bootstrap (password hash + memberships and all)
 *      reads back byte-for-field identical, and the stored value is EXACTLY the
 *      bootstrap columns, nothing wider;
 *  (b) A CORRUPT ENTRY IS A MISS — absent / unparseable / shape-invalid bytes all
 *      return `null`, and one malformed membership fails the WHOLE value;
 *  (c) THE TTL BACKSTOP — every write carries an `expirationTtl` clamped up to the
 *      KV 60s floor, so an entry a delete missed still self-expires;
 *  (d) DELETE — drops the entry the login populate seeded.
 */
import { describe, expect, test } from "vitest";
import {
  type AdminIdentityProjection,
  DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS,
  IDENTITY_PROJECTION_PREFIX,
  type IdentityDirectoryKv,
  KV_MIN_EXPIRATION_TTL_SECONDS,
  KvAdminIdentityProjection,
  adminIdentityProjectionKey,
  normalizeIdentityEmail,
} from "../src/session/identity-projection.js";
import type {
  AdminLoginBootstrap,
  AdminMembershipRow,
  AdminUserRow,
} from "../src/session/store.js";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

interface PutCall {
  readonly key: string;
  readonly value: string;
  readonly expirationTtl?: number;
}

/** An in-memory KV that records every put, so the TTL floor is observable. */
class FakeKv implements IdentityDirectoryKv {
  readonly store = new Map<string, string>();
  readonly puts: PutCall[] = [];
  readonly deletes: string[] = [];

  async get(key: string, _type: "text"): Promise<string | null> {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
    this.puts.push({ key, value, expirationTtl: options?.expirationTtl });
    this.store.set(key, value);
  }
  async delete(key: string): Promise<void> {
    this.deletes.push(key);
    this.store.delete(key);
  }
}

/** The single put a write recorded — fails loudly if there is not exactly one. */
function onlyPut(kv: FakeKv): PutCall {
  expect(kv.puts).toHaveLength(1);
  const [put] = kv.puts;
  if (put === undefined) throw new Error("no put recorded");
  return put;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EMAIL = "Alice@Example.com";

function user(overrides: Partial<AdminUserRow> = {}): AdminUserRow {
  return {
    id: "usr_1",
    email: "alice@example.com",
    passwordHash: "argon2id$v=19$m=65536,t=3,p=1$abc$def",
    displayName: "Alice",
    superadmin: false,
    createdAtUnix: 1_700_000_000,
    updatedAtUnix: 1_700_000_500,
    lastLoginAtUnix: 1_700_000_900,
    disabledAtUnix: null,
    ...overrides,
  };
}

function membership(overrides: Partial<AdminMembershipRow> = {}): AdminMembershipRow {
  return {
    id: "mem_1",
    userId: "usr_1",
    tenantId: "tenant_a",
    role: "owner",
    createdAtUnix: 1_700_000_100,
    ...overrides,
  };
}

function bootstrap(overrides: Partial<AdminLoginBootstrap> = {}): AdminLoginBootstrap {
  return {
    user: user(),
    memberships: [membership()],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

describe("adminIdentityProjectionKey", () => {
  test("normalizes case and surrounding whitespace so writer and reader agree", () => {
    expect(normalizeIdentityEmail("  Alice@Example.com  ")).toBe("alice@example.com");
    expect(adminIdentityProjectionKey("  Alice@Example.com  ")).toBe(
      `${IDENTITY_PROJECTION_PREFIX}alice@example.com`,
    );
  });
});

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

describe("KvAdminIdentityProjection round trip", () => {
  test("a written bootstrap reads back identical, password hash and memberships included", async () => {
    const kv = new FakeKv();
    const projection: AdminIdentityProjection = new KvAdminIdentityProjection(kv);
    const value = bootstrap({
      memberships: [
        membership({ id: "mem_1", tenantId: "tenant_a", role: "owner" }),
        membership({
          id: "mem_2",
          tenantId: "tenant_b",
          role: "viewer",
          createdAtUnix: 1_700_000_200,
        }),
      ],
    });

    await projection.write(EMAIL, value);
    const read = await projection.read(EMAIL);

    expect(read).toEqual(value);
    // The password hash makes the trip — that is the whole point of caching it.
    expect(read?.user.passwordHash).toBe(value.user.passwordHash);
    // Membership order (oldest-first; login takes [0]) is preserved.
    expect(read?.memberships.map((m) => m.tenantId)).toEqual(["tenant_a", "tenant_b"]);
  });

  test("read normalizes the email so a differently-cased login hits the same entry", async () => {
    const kv = new FakeKv();
    const projection = new KvAdminIdentityProjection(kv);
    await projection.write("alice@example.com", bootstrap());
    expect(await projection.read("ALICE@EXAMPLE.COM")).not.toBeNull();
  });

  test("the stored value is EXACTLY the bootstrap columns, nothing wider", async () => {
    const kv = new FakeKv();
    const projection = new KvAdminIdentityProjection(kv);
    await projection.write(EMAIL, bootstrap());

    const stored = JSON.parse(onlyPut(kv).value);
    expect(Object.keys(stored).sort()).toEqual(["memberships", "user"]);
    expect(Object.keys(stored.user).sort()).toEqual([
      "createdAtUnix",
      "disabledAtUnix",
      "displayName",
      "email",
      "id",
      "lastLoginAtUnix",
      "passwordHash",
      "superadmin",
      "updatedAtUnix",
    ]);
    expect(Object.keys(stored.memberships[0]).sort()).toEqual([
      "createdAtUnix",
      "id",
      "role",
      "tenantId",
      "userId",
    ]);
  });

  test("a user with no memberships round-trips with an empty array", async () => {
    const kv = new FakeKv();
    const projection = new KvAdminIdentityProjection(kv);
    await projection.write(EMAIL, bootstrap({ memberships: [] }));
    const read = await projection.read(EMAIL);
    expect(read?.memberships).toEqual([]);
  });

  test("a disabled user (disabledAtUnix set) round-trips — the gate runs on the reader", async () => {
    const kv = new FakeKv();
    const projection = new KvAdminIdentityProjection(kv);
    const value = bootstrap({ user: user({ disabledAtUnix: 1_700_001_000 }) });
    await projection.write(EMAIL, value);
    expect((await projection.read(EMAIL))?.user.disabledAtUnix).toBe(1_700_001_000);
  });
});

// ---------------------------------------------------------------------------
// A corrupt entry is a MISS
// ---------------------------------------------------------------------------

describe("KvAdminIdentityProjection: a corrupt entry is a miss", () => {
  test("an absent key reads null", async () => {
    const projection = new KvAdminIdentityProjection(new FakeKv());
    expect(await projection.read("nobody@example.com")).toBeNull();
  });

  test("unparseable bytes read null (never throw)", async () => {
    const kv = new FakeKv();
    kv.store.set(adminIdentityProjectionKey(EMAIL), "{ not json");
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("valid JSON of the wrong shape reads null", async () => {
    const kv = new FakeKv();
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify({ hello: "world" }));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("a missing password hash reads null — the cache cannot serve an unauthable user", async () => {
    const kv = new FakeKv();
    const { passwordHash: _dropped, ...userNoHash } = bootstrap().user;
    const raw = { user: userNoHash, memberships: [membership()] };
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify(raw));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("a wrong-typed superadmin reads null", async () => {
    const kv = new FakeKv();
    const raw = JSON.parse(JSON.stringify(bootstrap()));
    raw.user.superadmin = "yes";
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify(raw));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("one malformed membership fails the WHOLE value — login must not resolve a truncated tier", async () => {
    const kv = new FakeKv();
    // The second member is corrupt (no `role`); the first is well-formed.
    const { role: _dropped, ...secondNoRole } = membership({ id: "mem_2" });
    const raw = { user: user(), memberships: [membership({ id: "mem_1" }), secondNoRole] };
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify(raw));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("memberships that is not an array reads null", async () => {
    const kv = new FakeKv();
    const raw = JSON.parse(JSON.stringify(bootstrap()));
    raw.memberships = { "0": membership() };
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify(raw));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });

  test("a non-null non-number disabledAtUnix reads null", async () => {
    const kv = new FakeKv();
    const raw = JSON.parse(JSON.stringify(bootstrap()));
    raw.user.disabledAtUnix = "later";
    kv.store.set(adminIdentityProjectionKey(EMAIL), JSON.stringify(raw));
    expect(await new KvAdminIdentityProjection(kv).read(EMAIL)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// TTL backstop
// ---------------------------------------------------------------------------

describe("KvAdminIdentityProjection: the TTL backstop", () => {
  test("the default TTL is clamped up to the KV 60s floor", async () => {
    const kv = new FakeKv();
    await new KvAdminIdentityProjection(kv).write(EMAIL, bootstrap());
    expect(DEFAULT_IDENTITY_PROJECTION_TTL_SECONDS).toBeLessThan(KV_MIN_EXPIRATION_TTL_SECONDS);
    expect(onlyPut(kv).expirationTtl).toBe(KV_MIN_EXPIRATION_TTL_SECONDS);
  });

  test("a sub-floor requested TTL is clamped up to the floor", async () => {
    const kv = new FakeKv();
    await new KvAdminIdentityProjection(kv, { ttlSeconds: 5 }).write(EMAIL, bootstrap());
    expect(onlyPut(kv).expirationTtl).toBe(KV_MIN_EXPIRATION_TTL_SECONDS);
  });

  test("an above-floor TTL is honored (floored to a whole second)", async () => {
    const kv = new FakeKv();
    await new KvAdminIdentityProjection(kv, { ttlSeconds: 120.9 }).write(EMAIL, bootstrap());
    expect(onlyPut(kv).expirationTtl).toBe(120);
  });

  test("a non-finite TTL falls back to the default, then clamps to the floor", async () => {
    const kv = new FakeKv();
    await new KvAdminIdentityProjection(kv, { ttlSeconds: Number.NaN }).write(EMAIL, bootstrap());
    expect(onlyPut(kv).expirationTtl).toBe(KV_MIN_EXPIRATION_TTL_SECONDS);
  });

  test("every write is keyed by the normalized email", async () => {
    const kv = new FakeKv();
    await new KvAdminIdentityProjection(kv).write("  Alice@Example.com ", bootstrap());
    expect(onlyPut(kv).key).toBe(`${IDENTITY_PROJECTION_PREFIX}alice@example.com`);
  });
});

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

describe("KvAdminIdentityProjection: delete", () => {
  test("delete drops the entry a populate seeded, keyed by normalized email", async () => {
    const kv = new FakeKv();
    const projection = new KvAdminIdentityProjection(kv);
    await projection.write(EMAIL, bootstrap());
    expect(await projection.read(EMAIL)).not.toBeNull();

    await projection.delete("ALICE@EXAMPLE.COM");
    expect(kv.deletes).toEqual([`${IDENTITY_PROJECTION_PREFIX}alice@example.com`]);
    expect(await projection.read(EMAIL)).toBeNull();
  });

  test("deleting an absent entry is a no-op that does not throw", async () => {
    const kv = new FakeKv();
    await expect(
      new KvAdminIdentityProjection(kv).delete("nobody@example.com"),
    ).resolves.toBeUndefined();
  });
});
