/**
 * Minting bucket-scoped R2 S3 credentials (slice S2) — ported from
 * `crates/ferrogate-cloudflare/src/r2_token.rs`.
 *
 * There is no "create R2 token" endpoint: the R2 dashboard is a UI over the
 * generic ACCOUNT-owned API token API, and the S3 credential is *derived* from
 * the created token. Four facts here are expensive to re-derive and are pinned:
 *
 *  - account-owned `POST /accounts/{id}/tokens`, NOT `POST /user/tokens`, so
 *    the credential survives the creating user;
 *  - the resource-scope key
 *    `com.cloudflare.edge.r2.bucket.{account}_{jurisdiction}_{bucket}`;
 *  - the two Bucket Item permission-group ids — the WRITE one is published only
 *    in the R2 Data Catalog docs, not the authentication docs, which is what
 *    made it the single most expensive constant in the crate to rediscover;
 *  - `secretAccessKey = hex(sha256(token.value))`, over the plaintext value
 *    Cloudflare returns EXACTLY ONCE.
 *
 * The expected secret below is a `sha256sum` golden value computed outside this
 * codebase.
 *
 * Two safety properties are asserted rather than assumed: the mint is NEVER
 * retried (a retried mint creates a second credential whose secret is lost),
 * and a response missing `value` is a hard error — never a silent partial
 * success that would hand back an unusable credential pair.
 */
import { describe, expect, test } from "vitest";
import { CloudflareClient, EnvTokenResolver } from "../src/client.js";
import {
  R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID,
  R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
  R2_DEFAULT_JURISDICTION,
  R2TokenClient,
  r2BucketResourceScope,
} from "../src/r2-token.js";
import { RecordingClock, ScriptedTransport, errorResponse, okResponse } from "./support.js";

const TOKEN_VALUE = "v1.0-plaintext-token-value";
const TOKEN_VALUE_SHA256 = "bf63000c4ed942fa0f469bf6b62ad6b0c10c81eb5d9bccd5baea3e9d04b46563";

function tokens(transport: ScriptedTransport, clock = new RecordingClock()) {
  return new R2TokenClient(
    new CloudflareClient({
      config: { accountId: "acct_123", tokenReference: "inline-token" },
      resolver: new EnvTokenResolver({}),
      transport,
      clock,
    }),
  );
}

describe("constants", () => {
  test("the two Bucket Item permission-group ids, verbatim", () => {
    expect(R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID).toBe("6a018a9f2fc74eb6b293b0c548f38b39");
    expect(R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID).toBe("2efd5506f9c8494dacb1fa10a3e7d5b6");
    expect(R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID).not.toBe(
      R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID,
    );
  });

  test("the default jurisdiction is `default`", () => {
    expect(R2_DEFAULT_JURISDICTION).toBe("default");
  });

  test("the resource-scope key is underscore-delimited in account_jurisdiction_bucket order", () => {
    expect(r2BucketResourceScope("acct_123", "default", "ferrogate-acme-abc")).toBe(
      "com.cloudflare.edge.r2.bucket.acct_123_default_ferrogate-acme-abc",
    );
    expect(r2BucketResourceScope("a", "eu", "b")).toBe("com.cloudflare.edge.r2.bucket.a_eu_b");
  });
});

describe("createScopedToken", () => {
  test("posts to the ACCOUNT tokens endpoint, not /user/tokens", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1", value: TOKEN_VALUE })]);
    await tokens(transport).createScopedToken({
      tokenName: "ferrogate-r2-b",
      bucket: "b",
      jurisdiction: "default",
      access: "read-write",
    });
    expect(transport.requests[0]?.method).toBe("POST");
    expect(transport.requests[0]?.url).toBe(
      "https://api.cloudflare.com/client/v4/accounts/acct_123/tokens",
    );
    expect(transport.requests[0]?.url).not.toContain("/user/tokens");
  });

  test("sends ONE allow policy scoped to exactly one bucket resource", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1", value: TOKEN_VALUE })]);
    await tokens(transport).createScopedToken({
      tokenName: "ferrogate-r2-b",
      bucket: "ferrogate-acme-abc",
      jurisdiction: "default",
      access: "read-write",
    });
    const body = JSON.parse(transport.requests[0]?.body ?? "{}");
    expect(body.name).toBe("ferrogate-r2-b");
    expect(body.policies).toHaveLength(1);
    expect(body.policies[0].effect).toBe("allow");
    expect(body.policies[0].resources).toEqual({
      "com.cloudflare.edge.r2.bucket.acct_123_default_ferrogate-acme-abc": "*",
    });
    expect(body.policies[0].permission_groups).toEqual([
      { id: R2_BUCKET_ITEM_WRITE_PERMISSION_GROUP_ID },
    ]);
  });

  test("read-only attaches the READ permission group", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1", value: TOKEN_VALUE })]);
    await tokens(transport).createScopedToken({
      tokenName: "n",
      bucket: "b",
      jurisdiction: "default",
      access: "read-only",
    });
    const body = JSON.parse(transport.requests[0]?.body ?? "{}");
    expect(body.policies[0].permission_groups).toEqual([
      { id: R2_BUCKET_ITEM_READ_PERMISSION_GROUP_ID },
    ]);
  });

  test("derives the S3 credential: id → accessKeyId, hex(sha256(value)) → secret", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1", value: TOKEN_VALUE })]);
    const token = await tokens(transport).createScopedToken({
      tokenName: "n",
      bucket: "b",
      jurisdiction: "default",
      access: "read-write",
    });
    expect(token.tokenId).toBe("tok1");
    expect(token.accessKeyId).toBe("tok1");
    expect(token.secretAccessKey).toBe(TOKEN_VALUE_SHA256);
    expect(token.secretAccessKey).toMatch(/^[0-9a-f]{64}$/);
  });

  test("a response omitting `value` is a HARD error, not a partial success", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1" })]);
    await expect(
      tokens(transport).createScopedToken({
        tokenName: "n",
        bucket: "b",
        jurisdiction: "default",
        access: "read-write",
      }),
    ).rejects.toMatchObject({ kind: "decode" });
  });

  test("NEVER RETRIED: a 500 fails once — a retried mint loses a live secret", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([
      errorResponse(500, []),
      okResponse({ id: "tok2", value: TOKEN_VALUE }),
    ]);
    await expect(
      tokens(transport, clock).createScopedToken({
        tokenName: "n",
        bucket: "b",
        jurisdiction: "default",
        access: "read-write",
      }),
    ).rejects.toMatchObject({ kind: "api", status: 500 });
    expect(transport.callCount).toBe(1);
    expect(clock.slept).toEqual([]);
  });

  test("NEVER RETRIED on a 429 either", async () => {
    const clock = new RecordingClock();
    const transport = new ScriptedTransport([errorResponse(429, [], 1_000), okResponse({})]);
    await expect(
      tokens(transport, clock).createScopedToken({
        tokenName: "n",
        bucket: "b",
        jurisdiction: "default",
        access: "read-write",
      }),
    ).rejects.toMatchObject({ kind: "rate_limited" });
    expect(transport.callCount).toBe(1);
  });

  test("input is validated BEFORE any request is issued", async () => {
    const transport = new ScriptedTransport([]);
    const client = tokens(transport);
    const base = {
      tokenName: "n",
      bucket: "b",
      jurisdiction: "default",
      access: "read-write",
    } as const;

    // The `_` separator must not be smuggled into the resource id, or the
    // account/jurisdiction/bucket split becomes ambiguous.
    for (const bucket of ["", "has_underscore", "UPPER", "a b", "../x"]) {
      await expect(client.createScopedToken({ ...base, bucket })).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    for (const jurisdiction of ["", "EU", "eu-west", "de_fault", "1"]) {
      await expect(client.createScopedToken({ ...base, jurisdiction })).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    for (const tokenName of ["", "   "]) {
      await expect(client.createScopedToken({ ...base, tokenName })).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    expect(transport.callCount).toBe(0);
  });

  test("the minted secret never appears in a stringified token", async () => {
    const transport = new ScriptedTransport([okResponse({ id: "tok1", value: TOKEN_VALUE })]);
    const token = await tokens(transport).createScopedToken({
      tokenName: "n",
      bucket: "b",
      jurisdiction: "default",
      access: "read-write",
    });
    expect(String(token)).not.toContain(TOKEN_VALUE_SHA256);
    expect(JSON.stringify(token)).not.toContain(TOKEN_VALUE_SHA256);
    // …but it is still reachable as a field, for the caller that must store it.
    expect(token.secretAccessKey).toBe(TOKEN_VALUE_SHA256);
  });
});

describe("revokeToken", () => {
  test("issues a DELETE on the account token", async () => {
    const transport = new ScriptedTransport([okResponse(null)]);
    await tokens(transport).revokeToken("abc123");
    expect(transport.requests[0]?.method).toBe("DELETE");
    expect(transport.requests[0]?.url).toBe(
      "https://api.cloudflare.com/client/v4/accounts/acct_123/tokens/abc123",
    );
  });

  test("a path-escaping token id is refused BEFORE any request", async () => {
    const transport = new ScriptedTransport([]);
    for (const id of ["", "../x", "a-b", "a/b", "a b"]) {
      await expect(tokens(transport).revokeToken(id)).rejects.toThrowError(
        /cloudflare config error/,
      );
    }
    expect(transport.callCount).toBe(0);
  });
});

describe("ensureTenantCredentials", () => {
  test("ensures the bucket, then mints a credential scoped to THAT bucket", async () => {
    const transport = new ScriptedTransport([
      okResponse({ name: "ignored" }), // create bucket
      okResponse({ id: "tok1", value: TOKEN_VALUE }), // mint token
    ]);
    const provision = await tokens(transport).ensureTenantCredentials("acme");

    const derived = "ferrogate-acme-59964e920c573f29c9825cf9b5deb225";
    expect(provision.bucket.name).toBe(derived);
    expect(provision.bucket.created).toBe(true);
    expect(provision.token.secretAccessKey).toBe(TOKEN_VALUE_SHA256);

    const body = JSON.parse(transport.requests[1]?.body ?? "{}");
    expect(body.name).toBe(`ferrogate-r2-${derived}`);
    expect(Object.keys(body.policies[0].resources)).toEqual([
      `com.cloudflare.edge.r2.bucket.acct_123_default_${derived}`,
    ]);
  });

  test("an existing bucket still mints — tokens are not create-if-absent", async () => {
    const transport = new ScriptedTransport([
      errorResponse(409, [{ code: 10004, message: "already exists" }]),
      okResponse({ id: "tok9", value: TOKEN_VALUE }),
    ]);
    const provision = await tokens(transport).ensureTenantCredentials("acme");
    expect(provision.bucket.created).toBe(false);
    expect(provision.token.tokenId).toBe("tok9");
  });

  test("a bucket failure short-circuits before any token is minted", async () => {
    const transport = new ScriptedTransport([errorResponse(409, [])]);
    await expect(tokens(transport).ensureTenantCredentials("acme")).rejects.toMatchObject({
      kind: "api",
    });
    expect(transport.callCount).toBe(1);
  });

  test("an invalid tenant id is refused before ANY request", async () => {
    const transport = new ScriptedTransport([]);
    await expect(tokens(transport).ensureTenantCredentials("!!!")).rejects.toThrowError(
      /cloudflare config error/,
    );
    expect(transport.callCount).toBe(0);
  });
});
