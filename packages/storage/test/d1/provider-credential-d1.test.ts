/**
 * The per-tenant BYOK alias table against REAL D1 (issue #682).
 *
 * The claim that needs a real database is the SQL fence itself: `tenant_id = ?`
 * on every statement, against a schema whose PRIMARY KEY leads with `tenant_id`.
 * An in-memory fake keyed by `${tenant} ${alias}` proves only that the fake was
 * written to agree — it cannot be wrong, so it cannot catch a store that fetched
 * every row and filtered afterwards, nor one whose predicate a later refactor
 * widened to `LIKE`.
 *
 * Three separate properties are asserted, because they fail independently:
 *
 *  1. a tenant cannot READ another tenant's alias (confidentiality);
 *  2. a tenant cannot REVOKE another tenant's alias (availability — the crypto
 *     fence does not cover this at all, since destroying access needs no
 *     ability to decrypt);
 *  3. a tenant cannot ENUMERATE another tenant's aliases — the listing leaks
 *     `provider` and `alias` in plaintext, which is exactly the commercial
 *     information an enterprise BYOK customer is protecting.
 */
import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, test } from "vitest";
import {
  D1TenantProviderCredentialStore,
  LOOKUP_TENANT_PROVIDER_CREDENTIAL_SQL,
  credentialLast4,
} from "../../src/index.js";
import { TENANT_A, TENANT_B, setupDatabases } from "./harness.js";

const NOW = 1_784_073_600;

let store: D1TenantProviderCredentialStore;

beforeAll(async () => {
  await setupDatabases();
  store = new D1TenantProviderCredentialStore(env.CONTROL_DB);
});

beforeEach(async () => {
  await env.CONTROL_DB.prepare("DELETE FROM tenant_provider_credentials").run();
});

async function seed(
  tenantId: string,
  alias: string,
  provider = "openai",
  ciphertext = `sealed-for-${tenantId}`,
): Promise<void> {
  await store.upsert(
    {
      tenantId,
      alias,
      provider,
      keyVersion: 1,
      iv: "aXYtYmFzZTY0",
      ciphertext,
      last4: "abcd",
    },
    NOW,
  );
}

describe("D1TenantProviderCredentialStore", () => {
  test("resolves this tenant's alias", async () => {
    await seed(TENANT_A, "openai-enterprise");
    const found = await store.lookup(TENANT_A, "openai-enterprise");
    expect(found?.ciphertext).toBe(`sealed-for-${TENANT_A}`);
    expect(found?.provider).toBe("openai");
  });

  test("FENCE 1: another tenant's identical alias resolves to null", async () => {
    await seed(TENANT_A, "openai-enterprise");
    expect(await store.lookup(TENANT_B, "openai-enterprise")).toBeNull();
  });

  test("FENCE 1: two tenants may own the SAME alias name independently", async () => {
    await seed(TENANT_A, "openai-enterprise", "openai", "sealed-a");
    await seed(TENANT_B, "openai-enterprise", "openai", "sealed-b");
    expect((await store.lookup(TENANT_A, "openai-enterprise"))?.ciphertext).toBe(
      "sealed-a",
    );
    expect((await store.lookup(TENANT_B, "openai-enterprise"))?.ciphertext).toBe(
      "sealed-b",
    );
  });

  test("FENCE 2: a tenant cannot revoke another tenant's alias", async () => {
    await seed(TENANT_A, "openai-enterprise");

    expect(await store.revoke(TENANT_B, "openai-enterprise", NOW + 1)).toBe(false);
    // …and tenant A's credential is still live and unchanged.
    expect(await store.lookup(TENANT_A, "openai-enterprise")).not.toBeNull();

    expect(await store.revoke(TENANT_A, "openai-enterprise", NOW + 1)).toBe(true);
    expect(await store.lookup(TENANT_A, "openai-enterprise")).toBeNull();
  });

  test("FENCE 3: a listing shows only this tenant, and never key material", async () => {
    await seed(TENANT_A, "openai-enterprise", "openai");
    await seed(TENANT_A, "anthropic-negotiated", "anthropic");
    await seed(TENANT_B, "azure-eu", "azure");

    const listed = await store.list(TENANT_A);
    expect(listed.map((row) => row.alias)).toEqual([
      "anthropic-negotiated",
      "openai-enterprise",
    ]);
    for (const row of listed) {
      // The summary TYPE has no ciphertext field; assert the runtime object
      // agrees, so a future `SELECT *` regression is caught rather than merely
      // being untyped.
      expect(row).not.toHaveProperty("ciphertext");
      expect(row).not.toHaveProperty("iv");
    }
  });

  test("the tenant predicate is in the SQL, not applied afterwards", () => {
    // Pinning the statement itself: a store that fetched every tenant's rows and
    // filtered in JS would satisfy every assertion above on a two-tenant fixture
    // while shipping every tenant's alias metadata into the isolate.
    //
    // The WHOLE clause, not `toContain("tenant_id = ?")`: a substring check
    // survives `(tenant_id = ? OR 1 = 1)`, which is exactly the shape a
    // "temporarily relax this for the migration" edit takes.
    expect(LOOKUP_TENANT_PROVIDER_CREDENTIAL_SQL).toContain(
      "WHERE tenant_id = ? AND alias = ? AND revoked_at_unix IS NULL",
    );
  });
});

describe("rotation", () => {
  test("rotating replaces the material, preserves created_at, and needs no deploy", async () => {
    await seed(TENANT_A, "openai-enterprise", "openai", "sealed-old");
    const before = await store.lookup(TENANT_A, "openai-enterprise");

    await store.upsert(
      {
        tenantId: TENANT_A,
        alias: "openai-enterprise",
        provider: "openai",
        keyVersion: 1,
        iv: "bmV3LWl2LWI2NA",
        ciphertext: "sealed-new",
        last4: "wxyz",
      },
      NOW + 86_400,
    );

    const after = await store.lookup(TENANT_A, "openai-enterprise");
    expect(after?.ciphertext).toBe("sealed-new");
    expect(after?.last4).toBe("wxyz");
    // The audit trail must still say when the alias was first registered.
    expect(after?.createdAtUnix).toBe(before?.createdAtUnix);
    expect(after?.rotatedAtUnix).toBe(NOW + 86_400);
  });

  test("a rotation revives a revoked alias rather than burning the name", async () => {
    await seed(TENANT_A, "openai-enterprise");
    expect(await store.revoke(TENANT_A, "openai-enterprise", NOW + 1)).toBe(true);
    expect(await store.lookup(TENANT_A, "openai-enterprise")).toBeNull();

    await seed(TENANT_A, "openai-enterprise", "openai", "sealed-again");
    expect((await store.lookup(TENANT_A, "openai-enterprise"))?.ciphertext).toBe(
      "sealed-again",
    );
  });

  test("revoking twice reports the second call as a no-op", async () => {
    await seed(TENANT_A, "openai-enterprise");
    expect(await store.revoke(TENANT_A, "openai-enterprise", NOW + 1)).toBe(true);
    expect(await store.revoke(TENANT_A, "openai-enterprise", NOW + 2)).toBe(false);
  });
});

describe("credentialLast4", () => {
  test("shows the tail of a real key and masks a short one entirely", () => {
    expect(credentialLast4("sk-proj-abcdefgh1234")).toBe("1234");
    // For a 6-character value "the last 4" is most of it, so nothing is shown.
    expect(credentialLast4("abc123")).toBe("");
  });
});
