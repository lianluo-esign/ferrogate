/**
 * Zero-D1 S6 (#882): the gateway's HOP-1 READ-AHEAD over the `api_key_directory`
 * KV projection, against REAL `workerd` objects AND a real KV namespace.
 *
 * Nothing here is mocked except the one control-object OUTAGE case D1 cannot
 * stage. The directory hop reads `api_key_directory` from the real `CONTROL_DATA`
 * object; the KV projection is the real `KEY_DIRECTORY` binding; the second hop
 * routes to a real per-tenant `TenantDataObject`. The point is to prove the four
 * invariants end to end, with the SAME `D1TwoHopApiKeyDirectory` + `D1ApiKeyResolver`
 * the composition root wires in production:
 *
 *   (a) POSITIVE ONLY — an unknown key is never written to KV;
 *   (b) a control-object OUTAGE is `unavailable` (→503) even with KV bound;
 *   (c) a KV-served routing row STILL runs HOP 2 and the taxonomy is preserved;
 *   (d) revocation propagates within the TTL (delete-on-revoke → re-auth denies).
 *
 * The in-isolate cache is disabled (`ttlSeconds: 0`) throughout, so every assertion
 * is about the KV read-ahead and the authoritative RPC directly, never a memoized
 * answer.
 */
import { env } from "cloudflare:test";
import {
  type ApiKeyDirectoryProjection,
  type ApiKeyDirectoryRow,
  D1TwoHopApiKeyDirectory,
  KvApiKeyDirectoryProjection,
  keyDirectoryProjectionKey,
} from "@ferrogate/storage";
import { beforeEach, describe, expect, test } from "vitest";
import {
  ApiKeyResolutionCache,
  D1ApiKeyResolver,
  hashVirtualApiKeySecret,
} from "../../src/keys/index.js";
import { controlDb, resetApiKeysTable, seedApiKey, tenantDb, tenantRouter, testSecret } from "./seed.js";

const NOW = 1_800_000_000;

function keyDirectoryKv(): KVNamespace {
  const kv = (env as { KEY_DIRECTORY?: KVNamespace }).KEY_DIRECTORY;
  if (kv === undefined) {
    throw new Error(
      "WIRING TODO — no KEY_DIRECTORY KV bound.\n" +
        "  The HOP-1 read-ahead reads the api_key_directory projection from it;\n" +
        "  declare [[kv_namespaces]] KEY_DIRECTORY in apps/gateway/wrangler.toml.",
    );
  }
  return kv;
}

function projection(): KvApiKeyDirectoryProjection {
  return new KvApiKeyDirectoryProjection(keyDirectoryKv());
}

/** A resolver whose directory reads the real KV projection ahead of the RPC. */
function resolver(proj?: ApiKeyDirectoryProjection): D1ApiKeyResolver {
  return new D1ApiKeyResolver({
    directory: new D1TwoHopApiKeyDirectory(controlDb(), tenantRouter(), {
      now: () => NOW,
      projection: proj ?? projection(),
    }),
    // The KV read-ahead is what this file exercises; the in-isolate cache would
    // memoize the very first answer and hide it, so it is OFF here.
    cache: new ApiKeyResolutionCache({ ttlSeconds: 0 }),
  });
}

async function clearProjection(): Promise<void> {
  const kv = keyDirectoryKv();
  const { keys } = await kv.list({ prefix: "akd:v1:" });
  for (const entry of keys) await kv.delete(entry.name);
}

function positiveRow(id: string, tenantId: string): ApiKeyDirectoryRow {
  return {
    id,
    tenant_id: tenantId,
    project_id: `${tenantId}_project`,
    workspace_id: `${tenantId}_workspace`,
    enabled: 1,
    expires_at_unix: null,
    revoked_at_unix: null,
  };
}

beforeEach(async () => {
  await resetApiKeysTable();
  await clearProjection();
});

describe("(c) a KV HIT serves HOP 1, then still runs HOP 2 and the full taxonomy", () => {
  test("resolves from KV even when the control-object directory row is GONE", async () => {
    const secret = testSecret("kv-hit");
    const hash = await hashVirtualApiKeySecret(secret);
    await seedApiKey({ id: "k1", secret, tenantId: "tenant_a", scopes: ["chat.completions"] });

    // Warm KV, then DELETE the control-object directory row: an RPC would now
    // MISS, so a `resolved` answer can only have come from the KV routing row.
    await projection().write(hash, positiveRow("k1", "tenant_a"));
    await controlDb().prepare("DELETE FROM api_key_directory WHERE id = ?").bind("k1").run();

    const result = await resolver().authenticate(secret);
    expect(result.outcome).toBe("resolved");
    if (result.outcome === "resolved") {
      expect(result.auth.tenancy.tenantId).toBe("tenant_a");
    }
  });

  test("a KV-served row whose tenant row is REVOKED still denies (HOP 2 authorizes)", async () => {
    const secret = testSecret("kv-hit-revoked");
    const hash = await hashVirtualApiKeySecret(secret);
    await seedApiKey({ id: "k2", secret, tenantId: "tenant_a", revokedAtUnix: NOW - 1 });
    await projection().write(hash, positiveRow("k2", "tenant_a"));

    // The KV row is a live-looking POSITIVE routing row, but HOP 2 reads the
    // revoked tenant row — the retirement collapses onto the unknown-key 401.
    const result = await resolver().authenticate(secret);
    expect(result.outcome).toBe("key_suspended");
  });

  test("a KV-served valid key with a zero budget is still 429 (taxonomy preserved)", async () => {
    const secret = testSecret("kv-hit-budget");
    const hash = await hashVirtualApiKeySecret(secret);
    await seedApiKey({ id: "k3", secret, tenantId: "tenant_a", monthlyTokenBudget: 0 });
    await projection().write(hash, positiveRow("k3", "tenant_a"));

    expect((await resolver().authenticate(secret)).outcome).toBe("token_budget_exhausted");
  });
});

describe("cache-miss fallthrough populates KV — positive only", () => {
  test("a KV MISS resolves via the RPC and POPULATES the routing row", async () => {
    const secret = testSecret("miss-populate");
    const hash = await hashVirtualApiKeySecret(secret);
    await seedApiKey({ id: "m1", secret, tenantId: "tenant_a", scopes: ["chat.completions"] });

    expect(await projection().read(hash)).toBeNull(); // cold

    const result = await resolver().authenticate(secret);
    expect(result.outcome).toBe("resolved");

    const cached = await projection().read(hash);
    expect(cached?.id).toBe("m1");
    expect(cached?.tenant_id).toBe("tenant_a");
  });

  test("(a) an UNKNOWN key is refused and is NEVER written to KV", async () => {
    const secret = testSecret("never-minted");
    const hash = await hashVirtualApiKeySecret(secret);

    const result = await resolver().authenticate(secret);
    expect(result.outcome).toBe("unknown");
    expect(await projection().read(hash)).toBeNull(); // a miss is never seeded
  });
});

describe("(b) a control-object OUTAGE is 503 even with KV bound", () => {
  test("a KV miss + a throwing control object is `unavailable`, never masked", async () => {
    const throwing = {
      prepare() {
        return {
          bind() {
            return {
              async first() {
                throw new Error("control object unreachable");
              },
            };
          },
        };
      },
    } as unknown as D1Database;

    // KV is bound and empty for this hash: the miss must reach the RPC, and the
    // RPC failure must surface as `unavailable`, not be rewritten into a miss.
    const directory = new D1TwoHopApiKeyDirectory(throwing, tenantRouter(), {
      projection: projection(),
    });
    const twoHop = await directory.resolve("sha256:deadbeef");
    expect(twoHop.kind).toBe("unavailable");
  });
});

describe("(d) revocation propagates within the TTL", () => {
  test("delete-on-revoke → the next auth misses KV, hits the RPC, and denies", async () => {
    const secret = testSecret("revoke-prop");
    const hash = await hashVirtualApiKeySecret(secret);
    await seedApiKey({ id: "d1", secret, tenantId: "tenant_a", scopes: ["chat.completions"] });

    // Warm KV through a real resolve.
    expect((await resolver().authenticate(secret)).outcome).toBe("resolved");
    expect(await projection().read(hash)).not.toBeNull();

    // What the control plane's `tighten` does: DELETE the KV routing row, then
    // mark the directory + tenant rows revoked.
    await projection().delete(hash);
    await controlDb()
      .prepare("UPDATE api_key_directory SET revoked_at_unix = ? WHERE id = ?")
      .bind(NOW - 1, "d1")
      .run();
    await (await tenantDb("tenant_a"))
      .prepare("UPDATE api_keys SET revoked_at_unix = ? WHERE id = ?")
      .bind(NOW - 1, "d1")
      .run();

    // KV miss → RPC → the now-revoked directory row → the unknown-key 401.
    expect((await resolver().authenticate(secret)).outcome).toBe("key_suspended");
  });
});

describe("cross-tenant safety", () => {
  test("a KV routing row resolves HOP 2 against its OWN tenant only", async () => {
    const secret = testSecret("cross-tenant");
    const hash = await hashVirtualApiKeySecret(secret);
    // The authoritative row lives in tenant_a; tenant_b never holds this hash.
    await seedApiKey({ id: "c1", secret, tenantId: "tenant_a", scopes: ["chat.completions"] });
    await projection().write(hash, positiveRow("c1", "tenant_a"));

    const result = await resolver().authenticate(secret);
    expect(result.outcome).toBe("resolved");
    if (result.outcome === "resolved") {
      expect(result.auth.tenancy.tenantId).toBe("tenant_a");
    }
  });
});
