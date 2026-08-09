/**
 * Zero-D1 S6 (#882): the WRITE-THROUGH half of the `api_key_directory` KV
 * projection, exercised through the DEPLOYED admin API over `SELF`.
 *
 * The gateway reads this projection AHEAD of the control-object RPC on the auth
 * hot path (`packages/storage/key-directory-projection.ts`,
 * `apps/gateway/src/keys/resolver.ts`). This suite is its writer's proof: mint /
 * revoke / disable / enable / rotate a key through the real admin routes, then
 * read the SAME `KEY_DIRECTORY` KV namespace the data plane would, and assert the
 * routing row moves in lockstep with the credential's lifecycle.
 *
 * The projection is a cache of the ROUTING hop only — every one of these actions
 * is ALSO proved to reach the credential itself in `virtual-key-credential.test.ts`.
 * Here we pin only the KV mirror, keyed exactly as `keyDirectoryProjectionKey`
 * derives it from the presented secret's `sha256:` hash.
 */
import { SELF, env } from "cloudflare:test";
import { keyDirectoryProjectionKey } from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey } from "./harness.js";
import {
  TENANT_A,
  applyTenantSchema,
  registerTenantDatabases,
  resetTenantD1,
} from "./tenant-db.js";

const OPERATOR = operatorKey.secret;

function kv(): KVNamespace {
  const namespace = (env as { KEY_DIRECTORY?: KVNamespace }).KEY_DIRECTORY;
  if (namespace === undefined) {
    throw new Error(
      "no KV binding `KEY_DIRECTORY` — add [[kv_namespaces]] to apps/control-plane/wrangler.toml",
    );
  }
  return namespace;
}

/** The `sha256:`-tagged hash the control plane keys the directory by. */
async function hashSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  const hex = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}

/** The projected routing row for a secret, or `null` when KV holds none. */
async function projectionFor(secret: string): Promise<Record<string, unknown> | null> {
  const raw = await kv().get(keyDirectoryProjectionKey(await hashSecret(secret)), "text");
  return raw === null ? null : (JSON.parse(raw) as Record<string, unknown>);
}

interface MintedKey {
  readonly secret: string;
  readonly id: string;
}

async function mint(id: string): Promise<MintedKey> {
  const res = await SELF.fetch(
    `${BASE}/admin/v1/virtual-keys`,
    jsonRequest(OPERATOR, "POST", {
      id,
      name: `key ${id}`,
      tenant_id: TENANT_A,
      project_id: "proj-1",
      workspace_id: "ws-1",
      scopes: ["admin.read"],
    }),
  );
  expect(res.status).toBe(201);
  const body = (await res.json()) as { secret: string; virtual_key: { id: string } };
  return { secret: body.secret, id: body.virtual_key.id };
}

async function act(id: string, action: string): Promise<void> {
  const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${id}/${action}`, {
    method: "POST",
    headers: bearer(OPERATOR),
  });
  expect(res.status).toBe(200);
}

beforeAll(async () => {
  await applySchema();
  await applyTenantSchema();
});

beforeEach(async () => {
  arm({ store: "d1", staticKeys: [operatorKey], rbac: { [TENANT_A]: ["*"] } });
  await resetD1();
  await resetTenantD1();
  await registerTenantDatabases();
});

describe("write-through: mint publishes a positive routing row", () => {
  it("a freshly minted key has its routing row in KV, for the owning tenant only", async () => {
    const key = await mint("vk1");
    const row = await projectionFor(key.secret);
    expect(row).not.toBeNull();
    expect(row?.id).toBe(key.id);
    expect(row?.tenant_id).toBe(TENANT_A);
    expect(row?.enabled).toBe(1);
    // POSITIVE row: not revoked, not expired.
    expect(row?.revoked_at_unix).toBeNull();
  });

  it("a secret the admin API never minted has NO routing row (positive only)", async () => {
    await mint("vk1");
    expect(await projectionFor("fg_never_minted_secret")).toBeNull();
  });
});

describe("write-through: tighten DELETEs the routing row within the lifecycle", () => {
  it("revoke removes the KV routing row", async () => {
    const key = await mint("vk1");
    expect(await projectionFor(key.secret)).not.toBeNull();

    await act(key.id, "revoke");
    // Delete-on-revoke: the gateway stops resolving this key from KV promptly,
    // rather than waiting out the TTL. HOP 2 would deny it regardless.
    expect(await projectionFor(key.secret)).toBeNull();
  });

  it("DELETE removes the KV routing row too", async () => {
    const key = await mint("vk1");
    const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}`, {
      method: "DELETE",
      headers: bearer(OPERATOR),
    });
    expect(res.status).toBe(200);
    expect(await projectionFor(key.secret)).toBeNull();
  });

  it("disable clears the routing row, and enable republishes it", async () => {
    const key = await mint("vk1");

    await act(key.id, "disable");
    expect(await projectionFor(key.secret)).toBeNull();

    await act(key.id, "enable");
    const row = await projectionFor(key.secret);
    expect(row).not.toBeNull();
    expect(row?.enabled).toBe(1);
  });
});

describe("write-through: rotation publishes the NEW secret's routing row", () => {
  it("the new secret is published to KV (the old hash self-expires under TTL)", async () => {
    const key = await mint("vk1");

    const res = await SELF.fetch(`${BASE}/admin/v1/virtual-keys/${key.id}/rotate`, {
      method: "POST",
      headers: bearer(OPERATOR),
    });
    expect(res.status).toBe(200);
    const rotated = (await res.json()) as { secret: string };
    expect(rotated.secret).not.toBe(key.secret);

    // The NEW secret's routing row is published for the same key id. The rotate
    // is a `tighten` for the D1 legs (the old key_hash is retired first), but its
    // row is LIVE, so KV is upserted for the new hash.
    const newRow = await projectionFor(rotated.secret);
    expect(newRow?.id).toBe(key.id);
    expect(newRow?.tenant_id).toBe(TENANT_A);
    // The OLD hash's KV entry is not addressable by this writer (it holds only
    // the new hash), so it self-expires under `expirationTtl`. It cannot
    // authenticate meanwhile: the gateway's HOP 2 reads the rotated tenant row
    // and denies the old secret — a stale ROUTING row resolves nothing on its own.
  });
});
