/**
 * R2 bucket provisioning (slice S1) — ported from
 * `crates/ferrogate-cloudflare/src/r2.rs`.
 *
 * No Worker binding can create an R2 bucket: provisioning is an account-
 * MANAGEMENT operation, so this cannot collapse into `env.ASSETS`. Three
 * behaviours here are load-bearing and each one was a defect in the Rust tree
 * before it was a rule:
 *
 *  1. **Injective tenant → bucket derivation.** The bucket IS the per-tenant
 *     isolation boundary. Two tenants that derive one name read and overwrite
 *     each other's objects, and slice S2 would then scope a "per-tenant"
 *     credential to a SHARED bucket. All of the collision resistance lives in
 *     the 128-bit digest; the readable slug carries none.
 *  2. **Idempotent create is narrowed to two documented codes**, not "any 409".
 *     `AlreadyExists` is reported to the caller as *provisioned*, so absorbing
 *     a bucket-mid-deletion or jurisdiction 409 would claim a bucket exists
 *     that does not.
 *  3. **The list walks the cursor.** Without it, "absent" means "not on page 1"
 *     — which is exactly how a live probe once passed vacuously after a delete.
 *
 * The expected digests below were computed with `sha256sum` OUTSIDE this
 * codebase, so they are golden values rather than a restatement of the
 * implementation. The empty-tenant digest `8785c455…` also appears verbatim in
 * the Rust module docs, which independently confirms the canonicalisation
 * (`"{domain}:{len}:{tenant}"`) is byte-for-byte the ported one.
 */
import { describe, expect, test } from "vitest";
import { CloudflareClient, EnvTokenResolver } from "../src/client.js";
import {
  R2_BUCKET_ALREADY_EXISTS_CODES,
  R2_BUCKET_NAME_MAX_LEN,
  R2_BUCKET_NAME_MIN_LEN,
  R2Client,
  r2BucketNameForTenant,
} from "../src/r2.js";
import { RecordingClock, ScriptedTransport, errorResponse, okResponse } from "./support.js";

function r2(transport: ScriptedTransport, accountId = "acct_123") {
  return new R2Client(
    new CloudflareClient({
      config: { accountId, tokenReference: "inline-token" },
      resolver: new EnvTokenResolver({}),
      transport,
      clock: new RecordingClock(),
    }),
  );
}

describe("r2BucketNameForTenant — the isolation boundary", () => {
  test("matches independently computed SHA-256 golden values", async () => {
    expect(await r2BucketNameForTenant("acme")).toBe(
      "ferrogate-acme-59964e920c573f29c9825cf9b5deb225",
    );
    expect(await r2BucketNameForTenant("tenant_42")).toBe(
      "ferrogate-tenant-42-41a045180a257eab4e1b1b7d7c8b2264",
    );
  });

  test("a tenant id with no alphanumerics drops the slug AND its hyphen", async () => {
    // The Rust module docs pin `""` → `ferrogate-8785c455…`.
    expect(await r2BucketNameForTenant("")).toBe("ferrogate-8785c4553f8630e6c14fd8e22a998d48");
    expect(await r2BucketNameForTenant("!!!")).toBe("ferrogate-b50a9d2c39c93759f4166aae463e7e99");
  });

  test("INJECTIVE: two tenants that share a slug do NOT share a bucket", async () => {
    // Both slugify to `acme-corp`; only the digest separates them. This is the
    // exact family the pre-#490 derivation collapsed.
    const a = await r2BucketNameForTenant("Acme Corp");
    const b = await r2BucketNameForTenant("acme-corp");
    expect(a).toBe("ferrogate-acme-corp-864fe3c8bbda9a19f89540a9983d1e47");
    expect(b).toBe("ferrogate-acme-corp-6c5168be66140109a08d41abe83a997c");
    expect(a).not.toBe(b);
  });

  test("INJECTIVE: truncation cannot be crafted into an alias", async () => {
    const long = "a-very-long-tenant-identifier-that-exceeds-the-slug-cap-substantially";
    const alsoLong = `${long}-and-then-some-more`;
    const first = await r2BucketNameForTenant(long);
    const second = await r2BucketNameForTenant(alsoLong);
    // Identical 20-char slugs, different digests.
    expect(first.slice(0, 30)).toBe(second.slice(0, 30));
    expect(first).not.toBe(second);
  });

  test("the derivation is deterministic across calls", async () => {
    expect(await r2BucketNameForTenant("acme")).toBe(await r2BucketNameForTenant("acme"));
  });

  test("every derived name satisfies R2's hard constraints", async () => {
    const tenants = [
      "",
      "a",
      "!!!",
      "Acme Corp",
      "tenant_42",
      "ÜNICODE-Tenant-Ω",
      "a-very-long-tenant-identifier-that-exceeds-the-slug-cap-substantially",
      "----",
      "9",
    ];
    for (const tenant of tenants) {
      const name = await r2BucketNameForTenant(tenant);
      expect(name).toMatch(/^[a-z0-9-]+$/);
      expect(name.startsWith("-")).toBe(false);
      expect(name.endsWith("-")).toBe(false);
      expect(name).not.toContain("--");
      expect(name.length).toBeGreaterThanOrEqual(R2_BUCKET_NAME_MIN_LEN);
      expect(name.length).toBeLessThanOrEqual(R2_BUCKET_NAME_MAX_LEN);
      expect(name.startsWith("ferrogate-")).toBe(true);
    }
  });

  test("the longest possible name is exactly R2's 63-char maximum", async () => {
    const name = await r2BucketNameForTenant(
      "a-very-long-tenant-identifier-that-exceeds-the-slug-cap-substantially",
    );
    expect(name.length).toBe(63);
    expect(R2_BUCKET_NAME_MAX_LEN).toBe(63);
  });

  test("the shortest possible name is prefix + digest = 42", async () => {
    expect((await r2BucketNameForTenant("")).length).toBe(42);
  });

  test("no legacy-name helper is exported (issue #496)", async () => {
    const module = (await import("../src/r2.js")) as Record<string, unknown>;
    for (const key of Object.keys(module)) {
      expect(key.toLowerCase()).not.toContain("legacy");
    }
  });
});

describe("createBucket — idempotency narrowed to documented codes", () => {
  test("a fresh create returns the descriptor", async () => {
    const transport = new ScriptedTransport([
      okResponse({ name: "b1", location: "enam", storage_class: "Standard" }),
    ]);
    const outcome = await r2(transport).createBucket({ name: "b1" });
    expect(outcome.kind).toBe("created");
    expect(outcome.kind === "created" && outcome.bucket.name).toBe("b1");
    expect(transport.requests[0]?.method).toBe("POST");
    expect(transport.requests[0]?.url).toContain("/accounts/acct_123/r2/buckets");
  });

  test("locationHint and storageClass serialize in camelCase, and are omitted when unset", async () => {
    const transport = new ScriptedTransport([okResponse({ name: "b" }), okResponse({ name: "b" })]);
    const client = r2(transport);
    await client.createBucket({ name: "b", locationHint: "weur", storageClass: "InfrequentAccess" });
    expect(JSON.parse(transport.requests[0]?.body ?? "{}")).toEqual({
      name: "b",
      locationHint: "weur",
      storageClass: "InfrequentAccess",
    });
    await client.createBucket({ name: "b" });
    expect(JSON.parse(transport.requests[1]?.body ?? "{}")).toEqual({ name: "b" });
  });

  test("code 10004 under a 409 is absorbed as AlreadyExists", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 10004, message: "already exists, and you own it" }]),
    ]);
    expect((await r2(transport).createBucket({ name: "b" })).kind).toBe("already_exists");
  });

  test("code 10073 (S3 BucketConflict) is absorbed too", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 10073, message: "BucketConflict" }]),
    ]);
    expect((await r2(transport).createBucket({ name: "b" })).kind).toBe("already_exists");
  });

  test("STATUS-AGNOSTIC: code 10004 under a 200 is absorbed as well", async () => {
    // Cloudflare really does answer the duplicate create with success:false +
    // 10004 under HTTP 200; the CODE is the idempotency signal, not the status.
    const transport = new ScriptedTransport([
      errorResponse(200, [{ code: 10004, message: "already exists, and you own it" }]),
    ]);
    expect((await r2(transport).createBucket({ name: "b" })).kind).toBe("already_exists");
  });

  test("a BARE 409 is an ERROR — never a phantom 'provisioned' bucket", async () => {
    const transport = new ScriptedTransport([errorResponse(409, [])]);
    await expect(r2(transport).createBucket({ name: "b" })).rejects.toMatchObject({
      kind: "api",
      status: 409,
    });
  });

  test("a 409 with some OTHER code is an error", async () => {
    // e.g. a bucket mid-deletion, a jurisdiction conflict, a name held elsewhere.
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 10086, message: "bucket is being deleted" }]),
    ]);
    await expect(r2(transport).createBucket({ name: "b" })).rejects.toMatchObject({ kind: "api" });
  });

  test("an already-exists code does NOT rescue an auth failure", async () => {
    // 401 classifies as Unauthorized before the already-exists check can see it.
    const transport = new ScriptedTransport([
      errorResponse(401, [{ code: 10004, message: "already exists" }]),
    ]);
    await expect(r2(transport).createBucket({ name: "b" })).rejects.toMatchObject({
      kind: "unauthorized",
    });
  });

  test("the already-exists code set is exactly [10004, 10073]", () => {
    expect([...R2_BUCKET_ALREADY_EXISTS_CODES]).toEqual([10004, 10073]);
  });
});

describe("listBuckets — the cursor walk", () => {
  test("walks every page and concatenates in order", async () => {
    const transport = new ScriptedTransport([
      okResponse({ buckets: [{ name: "a" }] }, { cursor: "c1" }),
      okResponse({ buckets: [{ name: "b" }] }, { cursor: "c2" }),
      okResponse({ buckets: [{ name: "c" }] }, { cursor: "" }),
    ]);
    const buckets = await r2(transport).listBuckets();
    expect(buckets.map((b) => b.name)).toEqual(["a", "b", "c"]);
    expect(transport.callCount).toBe(3);
  });

  test("requests per_page=1000 and echoes the cursor back", async () => {
    const transport = new ScriptedTransport([
      okResponse({ buckets: [{ name: "a" }] }, { cursor: "c1" }),
      okResponse({ buckets: [] }),
    ]);
    await r2(transport).listBuckets();
    expect(transport.requests[0]?.url).toContain("per_page=1000");
    expect(transport.requests[0]?.url).not.toContain("cursor=");
    expect(transport.requests[1]?.url).toContain("cursor=c1");
  });

  test("percent-encodes an opaque cursor carrying +, / and =", async () => {
    const transport = new ScriptedTransport([
      okResponse({ buckets: [{ name: "a" }] }, { cursor: "a+b/c=" }),
      okResponse({ buckets: [] }),
    ]);
    await r2(transport).listBuckets();
    expect(transport.requests[1]?.url).toContain("cursor=a%2Bb%2Fc%3D");
  });

  test("stops on an absent cursor", async () => {
    const transport = new ScriptedTransport([okResponse({ buckets: [{ name: "a" }] })]);
    expect((await r2(transport).listBuckets()).length).toBe(1);
    expect(transport.callCount).toBe(1);
  });

  test("stops on an EMPTY page even if a cursor is still offered", async () => {
    const transport = new ScriptedTransport([okResponse({ buckets: [] }, { cursor: "c1" })]);
    expect(await r2(transport).listBuckets()).toEqual([]);
    expect(transport.callCount).toBe(1);
  });

  test("stops on a REPEATED cursor instead of spinning forever", async () => {
    // A server-side no-progress bug. Without this guard the walk never returns.
    const transport = new ScriptedTransport([
      okResponse({ buckets: [{ name: "a" }] }, { cursor: "same" }),
      okResponse({ buckets: [{ name: "b" }] }, { cursor: "same" }),
    ]);
    const buckets = await r2(transport).listBuckets();
    expect(buckets.map((b) => b.name)).toEqual(["a", "b"]);
    expect(transport.callCount).toBe(2);
  });
});

describe("deleteBucket", () => {
  test("issues a DELETE on the named bucket", async () => {
    const transport = new ScriptedTransport([okResponse(null)]);
    await r2(transport).deleteBucket("ferrogate-acme-abc");
    expect(transport.requests[0]?.method).toBe("DELETE");
    expect(transport.requests[0]?.url).toContain("/r2/buckets/ferrogate-acme-abc");
  });

  test("a path-escaping name is refused BEFORE any request", async () => {
    const transport = new ScriptedTransport([]);
    for (const name of ["", "../other", "Upper", "has_underscore", "a/b", "a?x=1"]) {
      await expect(r2(transport).deleteBucket(name)).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    expect(transport.callCount).toBe(0);
  });
});

describe("ensureTenantBucket", () => {
  test("creates the derived bucket and reports created: true", async () => {
    const transport = new ScriptedTransport([okResponse({ name: "x" })]);
    const provision = await r2(transport).ensureTenantBucket("acme");
    expect(provision.name).toBe("ferrogate-acme-59964e920c573f29c9825cf9b5deb225");
    expect(provision.created).toBe(true);
    expect(provision.s3Endpoint).toBe("https://acct_123.r2.cloudflarestorage.com");
    expect(JSON.parse(transport.requests[0]?.body ?? "{}").name).toBe(provision.name);
  });

  test("is idempotent: an existing bucket reports created: false, not an error", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 10004, message: "already exists" }]),
    ]);
    const provision = await r2(transport).ensureTenantBucket("acme");
    expect(provision.created).toBe(false);
    expect(provision.name).toBe("ferrogate-acme-59964e920c573f29c9825cf9b5deb225");
  });

  test("a tenant id naming no identity is refused BEFORE any request", async () => {
    // The derivation itself is deliberately infallible, but minting real
    // storage — and, via S2, a real credential — for an empty tenant id would
    // hide a caller bug behind a success.
    const transport = new ScriptedTransport([]);
    for (const tenant of ["", "   ", "!!!", "---"]) {
      await expect(r2(transport).ensureTenantBucket(tenant)).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    expect(transport.callCount).toBe(0);
  });

  test("a tenant id with at least one alphanumeric is accepted", async () => {
    const transport = new ScriptedTransport([okResponse({ name: "x" })]);
    await expect(r2(transport).ensureTenantBucket("-a-")).resolves.toBeDefined();
  });
});
