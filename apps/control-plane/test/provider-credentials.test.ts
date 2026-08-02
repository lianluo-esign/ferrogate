/**
 * The BYOK registration surface (issue #682), driven end-to-end through the
 * exported Worker against a REAL D1 binding.
 *
 * The rule this file obeys, borrowed from `api-keys-write-half.test.ts`:
 * **provision ONLY through the admin API; assert the EFFECT.** Nothing below
 * inserts a row by hand, so a `200` can only mean the handler wrote one, and
 * the cross-tenant assertions can only pass because the fence is real rather
 * than because a fixture agreed with the test.
 *
 * Three properties are asserted, and each fails independently:
 *
 *  1. register → list → rotate → revoke works with NO deploy in the loop;
 *  2. the stored row is CIPHERTEXT, and no response ever carries the key;
 *  3. tenant B cannot read, rotate or revoke tenant A's alias — even when it
 *     knows the exact alias name.
 */
import { SELF } from "cloudflare:test";
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, tenantKey } from "./harness.js";

/**
 * A TEST master key — 32 bytes of `0x2a`, base64. Deterministic and public on
 * purpose: it must never be mistaken for a deployment key, and a `crypto`-minted
 * one would make a failure non-reproducible.
 */
const TEST_MASTER_KEY = btoa("*".repeat(32));

const ACME = "tenant_acme";
const RIVAL = "tenant_rival";
const ACME_KEY = "acme-admin-secret";
const RIVAL_KEY = "rival-admin-secret";

const CREDENTIALS = `${BASE}/admin/v1/provider-credentials`;

function armWorld(): void {
  arm({
    store: "d1",
    nativeKeys: [tenantKey(ACME_KEY, ACME), tenantKey(RIVAL_KEY, RIVAL)],
  });
  (env as unknown as Record<string, string>).FERROGATE_BYOK_MASTER_KEY = TEST_MASTER_KEY;
}

function put(secret: string, alias: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${CREDENTIALS}/${alias}`, jsonRequest(secret, "PUT", body));
}

function list(secret: string): Promise<Response> {
  return SELF.fetch(CREDENTIALS, { headers: bearer(secret) });
}

function revoke(secret: string, alias: string): Promise<Response> {
  return SELF.fetch(`${CREDENTIALS}/${alias}`, {
    method: "DELETE",
    headers: bearer(secret),
  });
}

async function rows(): Promise<
  { tenant_id: string; alias: string; ciphertext: string; last4: string }[]
> {
  const result = await db()
    .prepare("SELECT tenant_id, alias, ciphertext, last4 FROM tenant_provider_credentials")
    .all<{ tenant_id: string; alias: string; ciphertext: string; last4: string }>();
  return result.results ?? [];
}

beforeAll(async () => {
  await applySchema();
});

beforeEach(async () => {
  await resetD1();
  await db().prepare("DELETE FROM tenant_provider_credentials").run();
  armWorld();
});

describe("register and rotate, with no deploy", () => {
  it("registers an alias and lists it back REDACTED", async () => {
    const created = await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    expect(created.status).toBe(200);

    const listed = await list(ACME_KEY);
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { data: Record<string, unknown>[] };
    expect(body.data).toHaveLength(1);
    expect(body.data[0]?.alias).toBe("openai-enterprise");
    expect(body.data[0]?.provider).toBe("openai-main");
    expect(body.data[0]?.last4).toBe("0001");
  });

  it("NEVER puts the credential in a response body", async () => {
    const created = await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    expect(await created.clone().text()).not.toContain("sk-acme-negotiated-0001");
    expect(await (await list(ACME_KEY)).text()).not.toContain("sk-acme-negotiated-0001");
  });

  it("stores CIPHERTEXT, not the key", async () => {
    await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    const stored = await rows();
    expect(stored).toHaveLength(1);
    // The strongest cheap statement: the plaintext is absent from the column
    // that holds the credential, and from the whole row.
    expect(JSON.stringify(stored)).not.toContain("sk-acme-negotiated-0001");
    expect(stored[0]?.ciphertext.length).toBeGreaterThan(0);
  });

  it("rotates in ONE request, replacing the material under the same alias", async () => {
    await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    const before = (await rows())[0]?.ciphertext;

    const rotated = await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-rotated-9999",
    });
    expect(rotated.status).toBe(200);

    const after = await rows();
    // Still ONE row — a rotation replaces, it does not accumulate.
    expect(after).toHaveLength(1);
    expect(after[0]?.ciphertext).not.toBe(before);
    expect(after[0]?.last4).toBe("9999");
  });

  it("revokes, and a second revoke is a 404 rather than a false success", async () => {
    await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    expect((await revoke(ACME_KEY, "openai-enterprise")).status).toBe(200);
    expect((await revoke(ACME_KEY, "openai-enterprise")).status).toBe(404);
  });

  it("refuses an alias outside the grammar rather than storing it", async () => {
    const response = await put(ACME_KEY, "Openai%2FEnterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
    expect(response.status).toBe(400);
    expect(await rows()).toHaveLength(0);
  });
});

describe("THE FENCE: one tenant cannot touch another's alias", () => {
  beforeEach(async () => {
    await put(ACME_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-acme-negotiated-0001",
    });
  });

  it("cannot see it in a listing", async () => {
    const listed = await list(RIVAL_KEY);
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { data: unknown[] };
    // Not even the alias NAME or the provider — that pair is the commercial
    // information an enterprise BYOK customer is protecting.
    expect(body.data).toEqual([]);
  });

  it("cannot revoke it", async () => {
    expect((await revoke(RIVAL_KEY, "openai-enterprise")).status).toBe(404);
    // …and ACME's row is untouched and still live.
    const stored = await rows();
    expect(stored).toHaveLength(1);
    expect(stored[0]?.tenant_id).toBe(ACME);
    expect((await list(ACME_KEY)).status).toBe(200);
  });

  it("cannot overwrite it — a same-named PUT creates a SEPARATE row", async () => {
    const response = await put(RIVAL_KEY, "openai-enterprise", {
      provider: "openai-main",
      value: "sk-rival-key-7777",
    });
    expect(response.status).toBe(200);

    const stored = await rows();
    expect(stored).toHaveLength(2);
    const acme = stored.find((row) => row.tenant_id === ACME);
    const rival = stored.find((row) => row.tenant_id === RIVAL);
    // ACME's material is unchanged — the rival's write went to its own
    // partition, and could not clobber a credential it does not own.
    expect(acme?.last4).toBe("0001");
    expect(rival?.last4).toBe("7777");
    expect(acme?.ciphertext).not.toBe(rival?.ciphertext);
  });
});
