/**
 * The WRITE half of the virtual-key credential — the MOUNT GATE.
 *
 * Every native-credential authenticator in this repo (`src/store/api_keys.ts`'s
 * `D1NativeApiKeyAuthenticator`, and the equivalents in `apps/gateway` and
 * `apps/mcp`) resolves a presented secret in two hops: `api_key_directory` in
 * the CONTROL database maps `key_hash` → tenancy, then that tenant's own
 * `api_keys` row supplies `scopes_json` and the budget.
 *
 * **Nothing wrote either row.** `POST /admin/v1/virtual-keys` minted a secret,
 * hashed it, and stored the result as a `control_plane_resources` document — a
 * table no authenticator reads. A freshly minted key therefore answered
 * `401 invalid_api_key` everywhere, and `disable` / `revoke` / `rotate` changed
 * nothing any credential check could observe.
 *
 * These tests do not inspect rows and call it proof. They **use the credential**:
 * mint a key through the deployed admin API over `SELF`, then present it as the
 * `Authorization: Bearer` of a real request to the same deployed Worker. The
 * whole two-hop resolver runs, against two REAL D1 databases, exactly as it
 * would in production. Raw-SQL row reads appear only to pin the ordering rule
 * and the rotation delete, which behaviour alone cannot distinguish.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { API_KEY_DIRECTORY_TABLE } from "../src/store/api_keys.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";
import {
  TENANT_A,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
  tenantDbA,
  tenantDbB,
} from "./tenant-db.js";

const OPERATOR = operatorKey.secret;

interface MintedKey {
  readonly secret: string;
  readonly id: string;
}

/** `POST /admin/v1/virtual-keys` as the platform operator. */
async function mint(id: string, extra: Record<string, unknown> = {}): Promise<MintedKey> {
  const res = await SELF.fetch(
    `${BASE}/admin/v1/virtual-keys`,
    jsonRequest(OPERATOR, "POST", {
      id,
      name: `key ${id}`,
      tenant_id: TENANT_A,
      project_id: "proj-1",
      workspace_id: "ws-1",
      scopes: ["admin.read"],
      ...extra,
    }),
  );
  expect(res.status).toBe(201);
  const body = (await res.json()) as { secret: string; virtual_key: { id: string } };
  expect(typeof body.secret).toBe("string");
  return { secret: body.secret, id: body.virtual_key.id };
}

/**
 * Present a credential to the DEPLOYED Worker on a real `admin.read` operation.
 *
 * `GET /admin/v1/virtual-keys` is the probe because it is an ordinary bearer
 * operation with no special-casing — the answer is decided by the same auth
 * ladder every other route runs.
 */
async function presentedStatus(secret: string): Promise<number> {
  const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys`, { headers: bearer(secret) });
  return res.status;
}

async function directoryRows(id: string): Promise<Record<string, unknown>[]> {
  const rows = await db()
    .prepare(`SELECT * FROM ${API_KEY_DIRECTORY_TABLE} WHERE id = ?`)
    .bind(id)
    .all<Record<string, unknown>>();
  return rows.results;
}

async function tenantKeyRow(id: string): Promise<Record<string, unknown> | null> {
  return await tenantDbA()
    .prepare("SELECT * FROM api_keys WHERE id = ?")
    .bind(id)
    .first<Record<string, unknown>>();
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    // No `tenant_role_bindings` rows exist, so the durable authorizer defers to
    // this declarative map — the posture `rbac-d1.test.ts` documents.
    rbac: { [TENANT_A]: ["*"] },
  });
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
});

describe("MOUNT: a minted virtual key actually authenticates", () => {
  it("the secret returned by POST is accepted on the very next request", async () => {
    const key = await mint("vk1");
    // Before this projection existed, this was 401 on every deployment: the
    // credential the admin API had just handed the operator resolved nowhere.
    expect(await presentedStatus(key.secret)).toBe(200);
  });

  it("a secret the admin API never minted is still refused", async () => {
    // The control. Without it, "not 401" would prove nothing about the mount —
    // it could just as easily mean the guard stopped challenging anybody.
    await mint("vk1");
    expect(await presentedStatus("fg_deadbeefdeadbeefdeadbeefdeadbeef")).toBe(401);
  });

  it("writes BOTH halves of the dual write, and only for the owning tenant", async () => {
    const key = await mint("vk1");

    const directory = await directoryRows(key.id);
    expect(directory).toHaveLength(1);
    expect(directory[0]?.["tenant_id"]).toBe(TENANT_A);
    expect(directory[0]?.["enabled"]).toBe(1);
    expect(directory[0]?.["revoked_at_unix"]).toBeNull();

    const tenantRow = await tenantKeyRow(key.id);
    expect(tenantRow).not.toBeNull();
    expect(tenantRow?.["key_hash"]).toBe(directory[0]?.["key_hash"]);
    expect(tenantRow?.["scopes_json"]).toBe(JSON.stringify(["admin.read"]));

    // The authority row is physically isolated: tenant B's database must not
    // have acquired it. A single shared database would pass a row-count
    // assertion against a router that ignored its argument.
    const leaked = await tenantDbB()
      .prepare("SELECT id FROM api_keys WHERE id = ?")
      .bind(key.id)
      .first();
    expect(leaked).toBeNull();
  });
});

describe("MOUNT: the lifecycle actions reach the credential, not just the document", () => {
  it("revoke stops the key authenticating — 401, never 403", async () => {
    const key = await mint("vk1");
    expect(await presentedStatus(key.secret)).toBe(200);

    const revoked = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/revoke`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });
    expect(revoked.status).toBe(200);

    // The 401-vs-403 invariant: a revoked key is indistinguishable from a typo,
    // because a 403 would confirm the presented secret is a real credential.
    expect(await presentedStatus(key.secret)).toBe(401);
    expect((await directoryRows(key.id))[0]?.["revoked_at_unix"]).not.toBeNull();
  });

  it("DELETE is a revocation and it bites too", async () => {
    const key = await mint("vk1");
    const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(res.status).toBe(200);
    expect(await presentedStatus(key.secret)).toBe(401);
  });

  it("disable then enable is a round trip the credential follows", async () => {
    const key = await mint("vk1");

    const disabled = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/disable`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });
    expect(disabled.status).toBe(200);
    expect(await presentedStatus(key.secret)).toBe(401);
    expect((await directoryRows(key.id))[0]?.["enabled"]).toBe(0);

    const enabled = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/enable`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });
    expect(enabled.status).toBe(200);
    // Issue #514 finding 5 in miniature: a reversible switch must actually
    // reverse, or an operator who disables a key has destroyed it.
    expect(await presentedStatus(key.secret)).toBe(200);
  });
});

describe("rotation retires the OLD secret", () => {
  it("the previous secret stops working and the new one starts", async () => {
    const key = await mint("vk1");
    expect(await presentedStatus(key.secret)).toBe(200);

    const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/rotate`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });
    expect(res.status).toBe(200);
    const rotated = (await res.json()) as { secret: string };
    expect(rotated.secret).not.toBe(key.secret);

    // The whole point of rotating is that a leaked credential stops working.
    expect(await presentedStatus(key.secret)).toBe(401);
    expect(await presentedStatus(rotated.secret)).toBe(200);
  });

  it("leaves exactly ONE directory row — the old key_hash is deleted, not orphaned", async () => {
    const key = await mint("vk1");
    const before = await directoryRows(key.id);
    expect(before).toHaveLength(1);

    await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/rotate`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });

    // `api_key_directory`'s PRIMARY KEY is `key_hash`, so an upsert-only
    // rotation would INSERT a second row and leave the old hash resolving
    // forever. One row, and it is not the old one.
    const after = await directoryRows(key.id);
    expect(after).toHaveLength(1);
    expect(after[0]?.["key_hash"]).not.toBe(before[0]?.["key_hash"]);
  });
});
