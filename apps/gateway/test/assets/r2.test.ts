/**
 * THE R2 MOUNT — asset bytes really land in the bucket `wrangler.toml` declares.
 *
 * `test/assets/routes.test.ts` drives the 18 operations with a SUBSTITUTED
 * object store, because that is what lets it cover the refusal taxonomy. What
 * it cannot see is whether the deployed composition root ever dereferences
 * `env.ASSETS` — and that is the exact defect this repo has shipped twice: a
 * module fully implemented, fully tested, and never mounted, with every suite
 * green. `wrangler.toml` even carried a "nothing dereferences `env.ASSETS` yet"
 * note while the binding sat there looking live.
 *
 * So every request in this file goes through `SELF.fetch`, i.e. the
 * `export default app` that `src/worker.ts` re-exports and `wrangler deploy`
 * ships, and every assertion is read back out of the REAL local R2 bucket
 * `@cloudflare/vitest-pool-workers` provisions from `[[r2_buckets]] ASSETS`.
 * Nothing here is substituted. Reverting `src/index.ts` to `assetRouteModule()`
 * turns this file red and nothing else in the suite.
 *
 * Local only: miniflare's R2 is a local filesystem-backed bucket. No account
 * resource is touched.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, test } from "vitest";

import {
  assetDepsFromEnv,
  sigV4PresignerFromEnv,
} from "../../src/assets/index.js";
import { GATEWAY_ROUTE_MODULES } from "../../src/index.js";
import { ASSET_OPERATION_IDS } from "../../src/routes/index.js";

const bindings = env as unknown as Record<string, unknown>;

function assetsBucket(): R2Bucket {
  const bucket = bindings.ASSETS as R2Bucket | undefined;
  if (bucket === undefined) {
    // Loud, never a silent skip: `[[r2_buckets]] binding = "ASSETS"` is
    // declared, so an absent binding means the declaration was removed and this
    // suite is about to prove something other than what it claims.
    throw new Error("asset tests expect the `ASSETS` R2 binding (apps/gateway/wrangler.toml).");
  }
  return bucket;
}

const BASE = "https://gw.test";
const RW = { authorization: "Bearer fg_r2_rw" } as const;

beforeAll(() => {
  bindings.GATEWAY_NATIVE_API_KEYS = JSON.stringify([
    {
      key: "fg_r2_rw",
      id: "key_r2",
      tenant_id: "tenant_r2",
      scopes: ["assets.read", "assets.write"],
    },
  ]);
  bindings.ASSET_ENTITLEMENTS = JSON.stringify({
    tenant_r2: { asset_hosting_enabled: true },
  });
});

afterEach(async () => {
  const listed = await assetsBucket().list();
  if (listed.objects.length > 0) {
    await assetsBucket().delete(listed.objects.map((object) => object.key));
  }
});

async function push(name: string, version: string, body: string): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/assets/skill/${name}/${version}`, {
    method: "PUT",
    headers: { ...RW, "content-type": "application/octet-stream" },
    body,
  });
}

describe("the deployed Worker writes asset bytes to the R2 binding", () => {
  test("a push through SELF puts an object in env.ASSETS", async () => {
    // Zero objects first, so "an object exists" cannot be inherited.
    expect((await assetsBucket().list()).objects).toHaveLength(0);

    const response = await push("probe", "1.0.0", "hello r2");
    expect(response.status).toBe(200);

    const listed = await assetsBucket().list();
    expect(listed.objects).toHaveLength(1);
    // The tenant is in the key, which is what keeps two tenants' objects from
    // ever colliding in one bucket (`src/assets/keys.ts`).
    expect(listed.objects[0]?.key).toContain("tenant_r2");

    const stored = await assetsBucket().get(listed.objects[0]?.key ?? "");
    expect(await stored?.text()).toBe("hello r2");
  });

  test("a pull through SELF reads those same bytes back out of R2", async () => {
    await push("roundtrip", "2.1.0", "durable bytes");

    const pulled = await SELF.fetch(`${BASE}/v1/assets/skill/roundtrip/2.1.0`, { headers: RW });
    expect(pulled.status).toBe(200);
    expect(new TextDecoder().decode(await pulled.arrayBuffer())).toBe("durable bytes");

    // …and the read really went to the BUCKET, not to an in-isolate copy:
    // removing the object underneath the gateway must break the pull. (It is
    // the CONTENT DIGEST that fails first if the bytes are altered rather than
    // removed — the service verifies what it read — so the object is deleted,
    // which is the unambiguous probe.)
    const key = (await assetsBucket().list()).objects[0]?.key ?? "";
    await assetsBucket().delete(key);
    const missing = await SELF.fetch(`${BASE}/v1/assets/skill/roundtrip/2.1.0`, { headers: RW });
    expect(missing.status).not.toBe(200);
  });

  test("a delete through SELF removes the object from the bucket", async () => {
    await push("removable", "1.0.0", "bytes");
    expect((await assetsBucket().list()).objects).toHaveLength(1);

    const deleted = await SELF.fetch(`${BASE}/v1/assets/skill/removable/1.0.0`, {
      method: "DELETE",
      headers: RW,
    });
    expect(deleted.status).toBe(200);
    expect((await assetsBucket().list()).objects).toHaveLength(0);
  });

  test("a WITHHELD push is stored in R2 but unreadable — #366, through the real bucket", async () => {
    // The supply-chain gate does not refuse an EICAR push; it stores it and
    // WITHHOLDS it (202), so the read path is what has to be closed. Proving
    // that against the real bucket matters: the bytes provably exist in R2 and
    // the gateway still answers 404, which is the isolation property — unproven
    // is indistinguishable from absent.
    const eicar = `X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`;
    const response = await push("malware", "1.0.0", eicar);
    expect(response.status).toBe(202);
    expect((await assetsBucket().list()).objects).toHaveLength(1);

    const pulled = await SELF.fetch(`${BASE}/v1/assets/skill/malware/1.0.0`, { headers: RW });
    expect(pulled.status).toBe(404);
  });
});

describe("the presign family without S3 credentials", () => {
  test("no presigner is built from a partial credential set", () => {
    // Half-configuring must never mint a URL the bucket will reject.
    expect(sigV4PresignerFromEnv({})).toBeNull();
    expect(
      sigV4PresignerFromEnv({
        ASSET_S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
        ASSET_S3_BUCKET: "b",
        ASSET_S3_ACCESS_KEY_ID: "id",
        // secret missing
      }),
    ).toBeNull();
    expect(
      sigV4PresignerFromEnv({
        ASSET_S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
        ASSET_S3_BUCKET: "b",
        ASSET_S3_ACCESS_KEY_ID: "id",
        ASSET_S3_SECRET_ACCESS_KEY: "   ",
      }),
    ).toBeNull();
  });

  test("the full set builds one, and presigning is enabled only WITH a bucket", () => {
    const credentials = {
      ASSET_S3_ENDPOINT: "https://acct.r2.cloudflarestorage.com",
      ASSET_S3_BUCKET: "b",
      ASSET_S3_ACCESS_KEY_ID: "id",
      ASSET_S3_SECRET_ACCESS_KEY: "secret",
    };
    expect(sigV4PresignerFromEnv(credentials)).not.toBeNull();

    // Credentials but no bucket binding: a presigned upload would stage bytes
    // the commit step could never find, so the flag stays off.
    expect(assetDepsFromEnv({ ...credentials }).limits).toBeUndefined();
    // Bucket but no credentials: nothing can be signed at all.
    expect(assetDepsFromEnv({ ASSETS: assetsBucket() }).limits).toBeUndefined();
    // Both: on.
    expect(assetDepsFromEnv({ ...credentials, ASSETS: assetsBucket() }).limits).toEqual({
      presignEnabled: true,
    });
  });

  test("the deployed env presigns nothing until an operator binds credentials", async () => {
    // `wrangler.toml` ships `ASSET_S3_*` empty, which is the Rust unconfigured
    // posture: `503 asset_bucket_unavailable`, never bytes through the Worker.
    const response = await SELF.fetch(`${BASE}/v1/assets/presign/upload/skill/x/1.0.0`, {
      method: "POST",
      headers: { ...RW, "content-type": "application/json" },
      body: JSON.stringify({ size_bytes: 1024, sha256: "a".repeat(64) }),
    });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "asset_bucket_unavailable",
    );
  });
});

describe("composition root — the asset module is wired to the bindings", () => {
  test("GATEWAY_ROUTE_MODULES mounts all 18 asset operations", () => {
    const mounted = new Set(GATEWAY_ROUTE_MODULES.flatMap((module) => module.operationIds));
    for (const operationId of ASSET_OPERATION_IDS) {
      expect(mounted.has(operationId), `${operationId} is not mounted`).toBe(true);
    }
  });

  test("env.ASSETS is the store, not the in-isolate fallback", () => {
    // The structural companion to the round-trip above: it names the exact
    // binding, so removing `depsFromEnv: assetDepsFromEnv` from `src/index.ts`
    // is caught even if somebody later makes the fallback store durable.
    expect(assetDepsFromEnv(bindings).objects).toBe(bindings.ASSETS);
  });
});
