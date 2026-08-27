/**
 * The `tenant-accounts` READ path projects the tenant OWNER's email
 * (`CollectionSpec.enrichList`, wired in `routes/tenant_hierarchy.ts`), driven
 * through the EXPORTED Worker against a REAL D1 binding.
 *
 * The account document holds only an opaque `tenant-…` id; an operator needs the
 * HUMAN, which lives one seam over in `admin_users` ⋈
 * `admin_user_tenant_memberships`. What is pinned here is the WIRE contract Polaris
 * reads, through the real pipeline (a hook that nothing MOUNTS is dead in
 * production while every unit test stays green — this repo has shipped that
 * before, hence `SELF`):
 *
 *  1. the LIST hangs `email` on every account that has a resolvable owner;
 *  2. the SINGLE read (the tenant-detail H1's source) hangs it too — a field on
 *     the list can never be missing from the detail read of the same resource;
 *  3. an account with NO membership simply carries no `email` (never null/empty);
 *  4. FAIL-SAFE: with no control database (memory store) the read still succeeds,
 *     unchanged — enrichment never fails an otherwise-good read.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";

const OPERATOR = operatorKey.secret;

interface AccountRow {
  readonly id: string;
  readonly tenant_id?: string | null;
  readonly email?: string | null;
  readonly [field: string]: unknown;
}

interface ListEnvelope {
  readonly object: "list";
  readonly data: readonly AccountRow[];
}

/** Insert an `admin_users` row directly — no seed helper exists for identity. */
async function seedAdminUser(id: string, email: string, createdAtUnix: number): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO admin_users
         (id, email, password_hash, display_name, superadmin, created_at_unix, updated_at_unix)
       VALUES (?, ?, 'pbkdf2$0$aa$bb', ?, 0, ?, ?)`,
    )
    .bind(id, email, email, createdAtUnix, createdAtUnix)
    .run();
}

/** Insert an `admin_user_tenant_memberships` row directly. */
async function seedMembership(
  id: string,
  userId: string,
  tenantId: string,
  role: string,
  createdAtUnix: number,
): Promise<void> {
  await db()
    .prepare(
      `INSERT INTO admin_user_tenant_memberships (id, user_id, tenant_id, role, created_at_unix)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(id, userId, tenantId, role, createdAtUnix)
    .run();
}

beforeAll(async () => {
  await applySchema();
});

describe("tenant-accounts read path projects the owner email (D1)", () => {
  beforeEach(async () => {
    await resetD1();
    arm({ store: "d1", staticKeys: [operatorKey], lifecycle: {} });
    // Two accounts, created through the real POST route (which writes both the
    // document and the typed `tenants` row the list reads): one with an owner,
    // one with no membership at all.
    for (const [id, name] of [
      ["tenant-owned", "Owned"],
      ["tenant-orphan", "Orphan"],
    ]) {
      const created = await SELF.fetch(
        `${BASE}/admin/v1/tenant-accounts`,
        jsonRequest(OPERATOR, "POST", { id, tenant_id: id, name }),
      );
      expect(created.status).toBe(201);
    }
    // tenant-owned: an older admin plus a later owner — the owner must win even
    // over the older binding, through the real pipeline.
    await seedAdminUser("u-admin", "admin@acme.test", 1000);
    await seedAdminUser("u-owner", "owner@acme.test", 2000);
    await seedMembership("m-admin", "u-admin", "tenant-owned", "admin", 1000);
    await seedMembership("m-owner", "u-owner", "tenant-owned", "owner", 2000);
  });

  it("hangs the owner email on every account in the LIST", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      headers: bearer(OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListEnvelope;
    const byId = new Map(body.data.map((row) => [row.id, row]));
    expect(byId.get("tenant-owned")?.email).toBe("owner@acme.test");
    // No membership ⇒ no email field, never a null/empty string.
    expect(byId.get("tenant-orphan")).toBeDefined();
    expect("email" in (byId.get("tenant-orphan") as AccountRow)).toBe(false);
  });

  it("hangs the owner email on the SINGLE read (tenant-detail H1 source)", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/tenant-owned`, {
      headers: bearer(OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tenant_account: AccountRow };
    expect(body.tenant_account.email).toBe("owner@acme.test");
  });

  it("omits email on the single read of an account with no membership", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts/tenant-orphan`, {
      headers: bearer(OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { tenant_account: AccountRow };
    expect("email" in body.tenant_account).toBe(false);
  });
});

describe("tenant-accounts read path is fail-safe without a control database (memory)", () => {
  beforeEach(() => {
    arm({
      store: "memory",
      staticKeys: [operatorKey],
      lifecycle: {},
      seed: { "tenant-accounts": [{ id: "tenant-mem", tenant_id: "tenant-mem", name: "Mem" }] },
    });
  });

  it("still lists the account, just without an email", async () => {
    const response = await SELF.fetch(`${BASE}/admin/v1/tenant-accounts`, {
      headers: bearer(OPERATOR),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as ListEnvelope;
    const row = body.data.find((r) => r.id === "tenant-mem");
    expect(row).toBeDefined();
    expect("email" in (row as AccountRow)).toBe(false);
  });
});
