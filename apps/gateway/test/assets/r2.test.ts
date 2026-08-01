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
  assetRouteModule,
  sigV4PresignerFromEnv,
} from "../../src/assets/index.js";
import { GATEWAY_ROUTE_MODULES } from "../../src/index.js";
import { ASSET_OPERATION_IDS, createGatewayApp } from "../../src/routes/index.js";

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
    // the commit step could never find, so the flag stays off — AND the inline
    // family is off too, because the store it would fall back to is an
    // isolate-local Map (see `AssetLimits.objectStoreEnabled`).
    expect(assetDepsFromEnv({ ...credentials }).limits).toEqual({
      objectStoreEnabled: false,
    });
    // Bucket but no credentials: nothing can be SIGNED, but the bucket really
    // holds bytes, so the inline family stays on.
    expect(assetDepsFromEnv({ ASSETS: assetsBucket() }).limits).toEqual({
      objectStoreEnabled: true,
    });
    // Both: on.
    expect(assetDepsFromEnv({ ...credentials, ASSETS: assetsBucket() }).limits).toEqual({
      objectStoreEnabled: true,
      presignEnabled: true,
    });
    // The developer escape hatch, and ONLY for the exact string "1".
    expect(assetDepsFromEnv({ FG_DEV_IN_MEMORY_PORTS: "1" }).limits).toEqual({
      objectStoreEnabled: true,
    });
    for (const value of ["0", "true", "yes", "", " 1 "]) {
      expect(
        assetDepsFromEnv({ FG_DEV_IN_MEMORY_PORTS: value }).limits,
        `FG_DEV_IN_MEMORY_PORTS=${JSON.stringify(value)} must not open the in-memory store`,
      ).toEqual({ objectStoreEnabled: false });
    }
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

/**
 * THE UNCONFIGURED-BUCKET POSTURE — what a deployment does with NO `ASSETS`.
 *
 * This is not hypothetical. `docs/rewrite/CLOUD-VERIFICATION.md` §B2 offers
 * exactly this as a resolution for the single authorised live deploy: "delete
 * the `[[r2_buckets]]` stanza for this one verification", on the stated
 * expectation that "the 18 asset ops answer `503 asset_bucket_unavailable`".
 *
 * Before this file, only FOUR of them did — the presign family, gated on
 * `presignEnabled`. The inline push fell back to `InMemoryAssetObjectStore`
 * and answered **200**, while its metadata row went to D1 and survived; every
 * later pull then reported the object "missing from the object bucket". A
 * durable pointer to bytes that never existed anywhere is strictly worse than
 * a refusal, and no test held the difference, because every suite either binds
 * the real bucket or substitutes a working store.
 *
 * These tests run the app the composition root builds (`assetRouteModule({
 * depsFromEnv: assetDepsFromEnv })`, verbatim from `src/index.ts`) against an
 * env with no `ASSETS`, which is the ONE thing `SELF.fetch` cannot express —
 * `wrangler.toml` declares the binding, so the deployed app always has it.
 */
describe("no ASSETS binding ⇒ 503, never a 200 whose bytes evaporate", () => {
  const ENV = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify([
      {
        key: "fg_nobucket",
        id: "key_nobucket",
        tenant_id: "tenant_nb",
        scopes: ["assets.read", "assets.write"],
      },
    ]),
    ASSET_ENTITLEMENTS: JSON.stringify({ tenant_nb: { asset_hosting_enabled: true } }),
  };

  function call(
    path: string,
    init: RequestInit,
    overrides: Record<string, unknown> = {},
  ): Promise<Response> {
    const { app } = createGatewayApp({
      modules: [assetRouteModule({ depsFromEnv: assetDepsFromEnv })],
    });
    return Promise.resolve(
      app.request(
        `${BASE}${path}`,
        {
          ...init,
          headers: new Headers({
            authorization: "Bearer fg_nobucket",
            ...(init.headers as Record<string, string> | undefined),
          }),
        },
        { ...ENV, ...overrides },
      ),
    );
  }

  test("the inline PUSH refuses with asset_bucket_unavailable", async () => {
    const response = await call("/v1/assets/skill/nb/1.0.0", {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: "bytes that must not be accepted",
    });
    expect(response.status).toBe(503);
    const body = (await response.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe("asset_bucket_unavailable");
    expect(body.error.message).toContain("ASSETS");
  });

  test("and it wrote NO metadata row — the refusal is before any durable effect", async () => {
    await call("/v1/assets/skill/nb_row/1.0.0", {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: "bytes",
    });
    // Same env, so the same (in-memory) metadata store: a row created by the
    // push above would be listed here. Nothing may be.
    const listed = await call("/v1/assets/skill", { method: "GET" });
    expect(listed.status).toBe(200);
    expect(await listed.json()).toEqual({ object: "list", data: [] });
  });

  test("content screening still runs FIRST — a config error cannot skip a security gate", async () => {
    // EICAR under `BuiltinEicarScreener` is quarantined rather than refused
    // (see `assets/ports.ts`), so what this pins is the ORDER: were the bucket
    // check placed at the top of `putAsset`, an infected push would be answered
    // by the missing bucket instead of by the scanner, and a deployment whose
    // R2 binding lapsed would stop screening entirely.
    const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const response = await call("/v1/assets/skill/nb_eicar/1.0.0", {
      method: "PUT",
      headers: { "content-type": "application/octet-stream" },
      body: eicar,
    });
    expect(response.status).toBe(503);
    // The scanner ran (the quarantine verdict is not a refusal), and the bucket
    // check is what refused — proven by the code, which only it produces.
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "asset_bucket_unavailable",
    );
  });

  test("FG_DEV_IN_MEMORY_PORTS=1 restores the local-dev in-memory store", async () => {
    // The escape hatch a developer running `wrangler dev` with no bindings
    // needs, and the var `CLOUD-VERIFICATION.md` §B1 already requires be set to
    // "0" for the live deploy. It is opt-IN: nothing above set it.
    const response = await call(
      "/v1/assets/skill/nb_dev/1.0.0",
      {
        method: "PUT",
        headers: { "content-type": "application/octet-stream" },
        body: "bytes",
      },
      { FG_DEV_IN_MEMORY_PORTS: "1" },
    );
    expect(response.status).toBe(200);
  });

  test("CONTROL: a BOUND bucket in the same shape is accepted", async () => {
    // Without this arm the 503s above would prove only that this bespoke app
    // refuses everything.
    const response = await call(
      "/v1/assets/skill/nb_bound/1.0.0",
      {
        method: "PUT",
        headers: { "content-type": "application/octet-stream" },
        body: "bytes",
      },
      { ASSETS: assetsBucket() },
    );
    expect(response.status).toBe(200);
  });
});
