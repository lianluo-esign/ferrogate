/**
 * The WRITE half of `admin_api_key`, driven end-to-end through the exported
 * Worker against a REAL D1 binding.
 *
 * ## Why this file exists, and why `api-keys-d1.test.ts` did not catch it
 *
 * `api-keys-d1.test.ts` proves the READER: it seeds `static_api_keys` with raw
 * SQL and shows `D1ApiKeyAuthenticator` resolves what is in the table. That is
 * the right shape for a reader test, and it is exactly why it could not see
 * this — it never once used the admin API to create a credential.
 *
 * The wave-15 control-plane certification found the write half missing on both
 * verbs at once:
 *
 * > `POST` / `DELETE /admin/v1/api-keys` **neither creates nor revokes a
 * > credential.**
 *
 * All six operations wrote a `control_plane_resources` DOCUMENT and nothing
 * else, and the schema deliberately refuses a client-supplied `secret` while
 * nothing minted one — so the collection had no path to a working credential at
 * all, and `DELETE` answered `200 {"deleted": true}` over a row no
 * authenticator had ever consulted.
 *
 * ## The rule every case here obeys
 *
 * **Provision ONLY through the admin API; assert the EFFECT.** Every world
 * below arms exactly one declarative operator key (the one making the admin
 * calls) and no other credential, so a `200` from a minted secret can only mean
 * a `static_api_keys` row exists, and a `401` after a `DELETE` can only mean it
 * is gone. Nothing here asserts the admin call's own status code as evidence.
 */
import { SELF } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { hashApiKeySecret } from "../src/store/api_keys.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

/** `GET /admin/v1/status` — an `admin.read` operation behind the auth chain. */
function status(secret: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/status`, { headers: bearer(secret) });
}

/**
 * An `admin.write` operation, for proving what a minted key may and may not do.
 *
 * The probe must be an operation where a minimal body is VALID, so a refusal
 * can only be the scope gate — one that 400s on the body would make "not 403"
 * unreadable as "authorized".
 *
 * It was `POST /admin/v1/roles` until #791, which made every write in the
 * `rbac` group operator-only. The keys minted below are TENANT-scoped, so that
 * probe now answers `403 rbac_write_operator_only` for a reason that has
 * nothing to do with this file's subject (the scope clamp), and the case that
 * asserted `201` went red. Changed deliberately rather than weakened:
 * `POST /admin/v1/agent-workflows` is a plain `crudGroup` collection
 * (`routes/admin_agent_workflow.ts:43`) whose fields are all optional and which
 * a tenant-scoped `admin.write` key is entitled to — so `403` here still means
 * "the minted credential lacks `admin.write`", which is the only thing these
 * cases are allowed to be reading.
 */
function write(secret: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/agent-workflows`,
    jsonRequest(secret, "POST", { id: `wf_${crypto.randomUUID()}`, name: "probe" }),
  );
}

interface CreatedKey {
  readonly secret: string;
  readonly id: string;
  readonly body: Record<string, unknown>;
}

/** `POST /admin/v1/api-keys` as `asSecret`, returning the minted plaintext. */
async function createKey(
  asSecret: string,
  body: Record<string, unknown> = {},
): Promise<CreatedKey> {
  const response = await SELF.fetch(
    `${BASE}/admin/v1/api-keys`,
    jsonRequest(asSecret, "POST", body),
  );
  expect(response.status, await response.clone().text()).toBe(201);
  const payload = (await response.json()) as {
    secret: string;
    api_key: Record<string, unknown>;
  };
  // Asserted here so no case below can pass vacuously on an unminted secret:
  // `expect(text).not.toContain(undefined)` is not an assertion.
  expect(typeof payload.secret).toBe("string");
  expect(payload.secret.length).toBeGreaterThan(16);
  return { secret: payload.secret, id: String(payload.api_key.id), body: payload.api_key };
}

function deleteKey(asSecret: string, id: string): Promise<Response> {
  return SELF.fetch(`${BASE}/admin/v1/api-keys/${id}`, {
    method: "DELETE",
    headers: bearer(asSecret),
  });
}

async function staticRow(id: string): Promise<{
  key_hash: string;
  tenant_id: string | null;
  platform_operator: number;
  scopes_json: string | null;
  enabled: number;
} | null> {
  return await db()
    .prepare(
      `SELECT key_hash, tenant_id, platform_operator, scopes_json, enabled
         FROM static_api_keys WHERE id = ?`,
    )
    .bind(id)
    .first();
}

async function clearKeyTables(): Promise<void> {
  await db().batch([db().prepare("DELETE FROM static_api_keys")]);
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await clearKeyTables();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [
      tenantKey("k-tenant", "t-1"),
      // Deliberately WRITE-only: the minter whose ceiling is narrower than the
      // mint it asks for.
      { ...tenantKey("k-narrow", "t-1"), id: "key_narrow", scopes: ["admin.write"] },
    ],
  });
});

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

describe("POST /admin/v1/api-keys creates a credential that authenticates", () => {
  it("the minted secret authenticates on the very next request", async () => {
    const created = await createKey(operatorKey.secret, { name: "ci-runner" });

    expect(created.secret).not.toBe("");
    const response = await status(created.secret);
    expect(response.status, await response.clone().text()).toBe(200);
  });

  it("returns the plaintext EXACTLY once — never on a read of the same key", async () => {
    const created = await createKey(operatorKey.secret, { name: "ci-runner" });

    const read = await SELF.fetch(`${BASE}/admin/v1/api-keys/${created.id}`, {
      headers: bearer(operatorKey.secret),
    });
    expect(read.status).toBe(200);
    expect(await read.text()).not.toContain(created.secret);
  });

  it("stores only the sha256 digest — the plaintext is nowhere in the table", async () => {
    const created = await createKey(operatorKey.secret);

    const row = await staticRow(created.id);
    expect(row?.key_hash).toBe(await hashApiKeySecret(created.secret));
    expect(row?.key_hash).not.toContain(created.secret);
  });

  it("honours the scopes the operator asked for: admin.read yes, admin.write no", async () => {
    const created = await createKey(operatorKey.secret, { scopes: ["admin.read"] });

    expect((await status(created.secret)).status).toBe(200);
    expect((await write(created.secret)).status).toBe(403);
  });

  it("an expired-on-arrival key does not authenticate", async () => {
    const created = await createKey(operatorKey.secret, { expires_at: 1 });

    expect((await status(created.secret)).status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Revocation — the second half of the named defect
// ---------------------------------------------------------------------------

describe("DELETE /admin/v1/api-keys/{id} revokes the credential", () => {
  it("the secret stops authenticating on the very next request", async () => {
    const created = await createKey(operatorKey.secret);
    expect((await status(created.secret)).status).toBe(200);

    const revoked = await deleteKey(operatorKey.secret, created.id);
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ deleted: true });

    // The claim the 200 makes, tested.
    expect((await status(created.secret)).status).toBe(401);
  });

  it("leaves no static_api_keys row behind for the authenticator to find", async () => {
    const created = await createKey(operatorKey.secret);
    expect(await staticRow(created.id)).not.toBeNull();

    await deleteKey(operatorKey.secret, created.id);

    expect(await staticRow(created.id)).toBeNull();
  });

  it("revokes only the named key — the operator's other keys keep working", async () => {
    const keep = await createKey(operatorKey.secret, { name: "keep" });
    const drop = await createKey(operatorKey.secret, { name: "drop" });

    await deleteKey(operatorKey.secret, drop.id);

    expect((await status(keep.secret)).status).toBe(200);
    expect((await status(drop.secret)).status).toBe(401);
  });

  it("a PATCH that disables the key takes effect on the very next request", async () => {
    const created = await createKey(operatorKey.secret);
    expect((await status(created.secret)).status).toBe(200);

    const patched = await SELF.fetch(
      `${BASE}/admin/v1/api-keys/${created.id}`,
      jsonRequest(operatorKey.secret, "PATCH", { enabled: false }),
    );
    expect(patched.status).toBe(200);

    // A DISABLED static row is 403, not 401 — the taxonomy `api-keys-d1.test.ts`
    // pins does not move because the row was written by the admin API.
    expect((await status(created.secret)).status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// The credential this surface must never mint
// ---------------------------------------------------------------------------

describe("a minted key can never exceed the caller that minted it", () => {
  it("is never a platform operator, even when the body asks for one", async () => {
    const created = await createKey(operatorKey.secret, {
      platform_operator: true,
      scopes: ["*"],
    });

    expect((await staticRow(created.id))?.platform_operator).toBe(0);
  });

  it("a tenant-scoped caller mints a key fenced to its OWN tenant", async () => {
    const created = await createKey("k-tenant", { name: "tenant-minted", tenant_id: "t-2" });

    expect((await staticRow(created.id))?.tenant_id).toBe("t-1");
  });

  it("a tenant-scoped caller cannot mint a WIDER scope set than it holds", async () => {
    // `k-tenant` holds `admin.read` + `admin.write` and asks for the wildcard.
    const created = await createKey("k-tenant", { scopes: ["*"] });

    const granted = JSON.parse((await staticRow(created.id))?.scopes_json ?? "null");
    expect(granted).not.toContain("*");
    // Still a usable credential — clamped, not emptied.
    expect((await status(created.secret)).status).toBe(200);
  });

  it("drops a NAMED scope the minter does not itself hold", async () => {
    // `k-narrow` holds `admin.write` and nothing else, and asks for a key that
    // can also read. The clamp keeps what it holds and drops what it does not.
    const created = await createKey("k-narrow", { scopes: ["admin.read", "admin.write"] });

    const granted = JSON.parse((await staticRow(created.id))?.scopes_json ?? "null");
    expect(granted).toEqual(["admin.write"]);

    // Both directions, so the case cannot pass by minting nothing at all.
    expect((await status(created.secret)).status).toBe(403);
    expect((await write(created.secret)).status).toBe(201);
  });

  it("a tenant-scoped caller cannot revoke ANOTHER tenant's key", async () => {
    const operatorMinted = await createKey(operatorKey.secret, {
      name: "platform",
      tenant_id: "t-2",
    });
    expect((await status(operatorMinted.secret)).status).toBe(200);

    const refused = await deleteKey("k-tenant", operatorMinted.id);
    expect(refused.status).toBe(404);

    // The refusal did not take the credential down with it.
    expect((await status(operatorMinted.secret)).status).toBe(200);
    expect(await staticRow(operatorMinted.id)).not.toBeNull();
  });
});
